/**
 * The API router.
 *
 * A pure function of (request, dependencies) -> response. Request handling order
 * is deliberate and uniform for every route:
 *
 *   1. payload size ceiling (before any parsing)
 *   2. authentication
 *   3. rate limiting, keyed per principal
 *   4. route resolution
 *   5. per-route authorization
 *   6. handler
 *
 * Authorization is table-driven (`ROUTES`), so a new route cannot accidentally
 * ship without a permission: an unmatched route is a 404, and a matched route
 * always carries a required permission.
 */

import {
  displayHandle,
  levelRange,
  newAuditId,
  resolveConfig,
  validateConfigPatch,
  verifyBundle,
  verifyChain,
  type DeepPartial,
  type DetectionConfig,
  type IncidentStatus,
  type TalkinEvent,
} from '@talkinshield/core';

import { loadConfig, type AnalysisDeps } from '../app/analysis-service.ts';
import { ingestEvents, type IngestDeps } from '../app/ingest-service.ts';
import {
  applyModeration,
  availableActions,
  MODERATION_ACTIONS,
  type ModerationActionKind,
  type ModerationDeps,
} from '../app/moderation-service.ts';
import { buildOverview } from '../app/overview-service.ts';
import type { AppEnv } from '../config/env.ts';
import type { AuditStore, Clock, Logger, RateLimiter } from '../ports.ts';
import { authenticate, authorize, permissionsFor, type Permission, type Principal } from './auth.ts';
import {
  badRequest,
  error,
  internalError,
  notFound,
  ok,
  payloadTooLarge,
  tooManyRequests,
  type ApiRequest,
  type ApiResponse,
} from './types.ts';

export interface RouterDeps extends AnalysisDeps, IngestDeps, ModerationDeps {
  env: AppEnv;
  audit: AuditStore;
  rateLimiter: RateLimiter;
  logger: Logger;
  clock: Clock;
}

interface RouteDef {
  method: string;
  /** Path template, e.g. `/users/{userId}`. */
  pattern: string;
  permission: Permission;
  handler: (ctx: RouteContext) => Promise<ApiResponse>;
}

interface RouteContext {
  request: ApiRequest;
  principal: Principal;
  deps: RouterDeps;
  nowMs: number;
}

export async function handleRequest(request: ApiRequest, deps: RouterDeps): Promise<ApiResponse> {
  const nowMs = deps.clock.now();
  const log = deps.logger.child({ requestId: request.requestId, routeKey: request.routeKey });

  try {
    // --- 1. Payload ceiling ---------------------------------------------
    if (request.rawBodyLength > deps.env.limits.maxRequestBytes) {
      return payloadTooLarge(
        `Request body exceeds the ${deps.env.limits.maxRequestBytes}-byte limit.`,
      );
    }

    // --- 2. Authentication ----------------------------------------------
    const auth = authenticate(request, deps.env.auth, nowMs);
    if (!auth.ok) {
      await audit(deps, {
        actorId: 'anonymous',
        action: `AUTH_${auth.code}`,
        target: request.routeKey,
        reason: auth.message,
        outcome: 'DENIED',
        nowMs,
        ...(request.sourceIp !== undefined ? { sourceIp: request.sourceIp } : {}),
      });
      deps.metrics.count('AuthFailure', 1, { code: auth.code });
      // The specific code is returned so a legitimate client can distinguish
      // "refresh your token" (TOKEN_EXPIRED) from "you may not call this API"
      // (CLIENT_NOT_ALLOWED). The message never reveals anything beyond the
      // claim that failed, and the full context is in the audit log.
      return error(auth.status, auth.code, auth.message);
    }
    const { principal } = auth;

    // --- 3. Rate limiting ------------------------------------------------
    const isIngest = request.routeKey === 'POST /events';
    const limit = isIngest ? deps.env.limits.ingestRatePerMinute : deps.env.limits.apiRatePerMinute;
    const budget = await deps.rateLimiter.consume(
      `${isIngest ? 'ingest' : 'api'}:${principal.subject}`,
      limit,
      60,
      nowMs,
    );
    if (!budget.allowed) {
      deps.metrics.count('RateLimited', 1, { route: request.routeKey });
      return tooManyRequests(budget.retryAfterSeconds);
    }

    // --- 4. Route resolution ---------------------------------------------
    const route = matchRoute(request);
    if (route === undefined) {
      return notFound(`No route matches ${request.method} ${request.path}.`);
    }

    // --- 5. Authorization ------------------------------------------------
    const decision = authorize(principal, route.def.permission, deps.env.auth);
    if (!decision.ok) {
      await audit(deps, {
        actorId: principal.subject,
        action: 'AUTHZ_DENIED',
        target: `${request.method} ${route.def.pattern}`,
        reason: decision.message,
        outcome: 'DENIED',
        nowMs,
        detail: { requiredPermission: route.def.permission, roles: principal.roles.join(',') },
        ...(request.sourceIp !== undefined ? { sourceIp: request.sourceIp } : {}),
      });
      deps.metrics.count('AuthorizationDenied', 1, { permission: route.def.permission });
      return error(403, decision.code, decision.message);
    }

    // --- 6. Handler -------------------------------------------------------
    const response = await route.def.handler({
      request: { ...request, pathParams: route.params },
      principal,
      deps,
      nowMs,
    });

    const remaining = String(budget.remaining);
    return { ...response, headers: { ...response.headers, 'x-ratelimit-remaining': remaining } };
  } catch (err: unknown) {
    // Internal details are logged, never returned.
    log.error('Unhandled error while handling request.', {
      error: err instanceof Error ? err.message : String(err),
      stack: err instanceof Error ? err.stack : undefined,
    });
    deps.metrics.count('UnhandledError');
    return internalError(request.requestId);
  }
}

// --- Route table -----------------------------------------------------------

const ROUTES: RouteDef[] = [
  // Ingestion
  { method: 'POST', pattern: '/events', permission: 'telemetry:ingest', handler: postEvents },

  // Live events & overview
  { method: 'GET', pattern: '/overview', permission: 'events:read', handler: getOverview },
  { method: 'GET', pattern: '/events', permission: 'events:read', handler: listEvents },
  { method: 'GET', pattern: '/signals', permission: 'events:read', handler: listSignals },

  // Users
  { method: 'GET', pattern: '/users', permission: 'users:read', handler: listUsers },
  { method: 'GET', pattern: '/users/{userId}', permission: 'users:read', handler: getUser },

  // Incidents
  { method: 'GET', pattern: '/incidents', permission: 'incidents:read', handler: listIncidents },
  { method: 'GET', pattern: '/incidents/{incidentId}', permission: 'incidents:read', handler: getIncident },
  {
    method: 'PATCH',
    pattern: '/incidents/{incidentId}',
    permission: 'incidents:write',
    handler: patchIncident,
  },

  // Evidence. `{key+}` is greedy: evidence keys contain `/` separators.
  { method: 'GET', pattern: '/evidence/{key+}', permission: 'evidence:read', handler: getEvidence },
  {
    method: 'POST',
    pattern: '/evidence/verify',
    permission: 'evidence:read',
    handler: verifyEvidence,
  },

  // Moderation
  { method: 'POST', pattern: '/moderation', permission: 'moderation:local', handler: postModeration },
  {
    method: 'GET',
    pattern: '/moderation/actions',
    permission: 'incidents:read',
    handler: listModerationActions,
  },
  {
    method: 'GET',
    pattern: '/moderation/affordances',
    permission: 'incidents:read',
    handler: getAffordances,
  },

  // Rules & settings
  { method: 'GET', pattern: '/rules', permission: 'rules:read', handler: getRules },
  { method: 'PUT', pattern: '/rules', permission: 'rules:write', handler: putRules },
  { method: 'GET', pattern: '/settings', permission: 'settings:read', handler: getSettings },

  // Logs
  { method: 'GET', pattern: '/logs', permission: 'logs:read', handler: listLogs },

  // Introspection
  { method: 'GET', pattern: '/me', permission: 'events:read', handler: getMe },
];

interface MatchedRoute {
  def: RouteDef;
  params: Record<string, string>;
}

export function matchRoute(request: ApiRequest): MatchedRoute | undefined {
  const segments = request.path.split('/').filter((s) => s.length > 0);

  // Exact-arity patterns are tried before greedy ones, so `/evidence/verify`
  // is never swallowed by `/evidence/{key+}`.
  const ordered = [...ROUTES].sort(
    (a, b) => Number(a.pattern.includes('+}')) - Number(b.pattern.includes('+}')),
  );

  for (const def of ordered) {
    if (def.method !== request.method) continue;
    const patternSegments = def.pattern.split('/').filter((s) => s.length > 0);
    const greedy = patternSegments[patternSegments.length - 1]?.endsWith('+}') === true;

    if (greedy) {
      // A greedy trailing parameter absorbs all remaining segments.
      if (segments.length < patternSegments.length) continue;
    } else if (patternSegments.length !== segments.length) {
      continue;
    }

    const params: Record<string, string> = {};
    let matched = true;
    for (let i = 0; i < patternSegments.length; i += 1) {
      const p = patternSegments[i] as string;
      const isLast = i === patternSegments.length - 1;

      if (p.startsWith('{') && p.endsWith('+}')) {
        if (!isLast) {
          matched = false;
          break;
        }
        params[p.slice(1, -2)] = segments
          .slice(i)
          .map((s) => decodeURIComponent(s))
          .join('/');
        break;
      }

      const s = segments[i] as string;
      if (p.startsWith('{') && p.endsWith('}')) {
        params[p.slice(1, -1)] = decodeURIComponent(s);
      } else if (p !== s) {
        matched = false;
        break;
      }
    }
    if (matched) return { def, params };
  }
  return undefined;
}

/** Exposed for documentation generation and tests. */
export function routeTable(): ReadonlyArray<{ method: string; pattern: string; permission: Permission }> {
  return ROUTES.map((r) => ({ method: r.method, pattern: r.pattern, permission: r.permission }));
}

// --- Handlers --------------------------------------------------------------

async function postEvents({ request, deps, principal }: RouteContext): Promise<ApiResponse> {
  const result = await ingestEvents(request.body, `submitter:${principal.subject}`, deps);
  if ('error' in result) return badRequest(result.error);

  const status = result.accepted > 0 ? 202 : 200;
  return {
    statusCode: status,
    body: {
      accepted: result.accepted,
      duplicates: result.duplicates,
      rejected: result.rejected,
      warnings: result.warnings,
    },
    headers: { 'content-type': 'application/json', 'cache-control': 'no-store' },
  };
}

async function getOverview({ deps, nowMs }: RouteContext): Promise<ApiResponse> {
  const { config } = await loadConfig(deps.rules);
  const overview = await buildOverview(deps, config, nowMs);
  return ok(overview);
}

async function listEvents({ request, deps }: RouteContext): Promise<ApiResponse> {
  const limit = clampLimit(request.query.limit, 50, 200);
  const userId = request.query.userId;
  const roomId = request.query.roomId;

  const events = userId
    ? await deps.events.getByUser(userId, limit)
    : roomId
      ? await deps.events.getByRoom(roomId, limit)
      : await deps.events.listRecent(limit);

  return ok({
    events: events.map((e) => redactEventForDisplay(e, deps)),
    count: events.length,
  });
}

async function listSignals({ request, deps }: RouteContext): Promise<ApiResponse> {
  const limit = clampLimit(request.query.limit, 50, 200);
  const signals = await deps.signals.listRecent(limit);
  return ok({ signals, count: signals.length });
}

async function listUsers({ request, deps }: RouteContext): Promise<ApiResponse> {
  const limit = clampLimit(request.query.limit, 25, 100);
  const users = await deps.userState.listHighRisk(limit);
  return ok({
    users: users.map((u) => ({
      ...u,
      handle: displayHandle(u.userId, deps.env.displayHandleSalt),
    })),
    count: users.length,
  });
}

async function getUser({ request, deps, nowMs }: RouteContext): Promise<ApiResponse> {
  const userId = request.pathParams.userId;
  if (userId === undefined || userId.length === 0) return badRequest('userId is required.');

  const { config } = await loadConfig(deps.rules);
  const [state, assessment, events, signals, actions, openIncidents] = await Promise.all([
    deps.userState.get(userId),
    deps.userState.getAssessment(userId),
    deps.events.getByUser(userId, 50),
    deps.signals.getByUser(userId, 50),
    deps.actions.listByUser(userId, 50),
    deps.incidents.countOpenByUser(userId),
  ]);

  if (state === undefined && events.length === 0) return notFound('No telemetry for this account.');

  const capabilities = deps.platform.capabilities();
  const messageEvents = events.filter((e) => e.eventType === 'message' || e.eventType === 'voice');
  const windowMs = config.spam.windowMs;
  const recentCount = messageEvents.filter((e) => nowMs - e.receivedAtMs <= windowMs).length;

  return ok({
    userId,
    handle: displayHandle(userId, deps.env.displayHandleSalt),
    roomId: events[events.length - 1]?.roomId,
    riskScore: assessment?.score ?? 0,
    riskLevel: assessment?.level ?? 'LOW',
    riskRange: assessment ? levelRange(assessment.level, config.risk) : '0-24',
    contributions: assessment?.contributions ?? [],
    messageFrequency: {
      windowSeconds: Math.round(windowMs / 1000),
      count: recentCount,
      perMinute: Math.round((recentCount / windowMs) * 60_000 * 10) / 10,
    },
    abuseDetections: signals.filter((s) => s.category === 'ABUSE' || s.category === 'THREAT'),
    recentEvents: events.slice(-25).map((e) => redactEventForDisplay(e, deps)),
    moderationHistory: actions,
    openIncidents,
    priorViolations: state?.priorViolations ?? 0,
    evasionCount: state?.evasionCount ?? 0,
    /**
     * Client information limited to what the platform legitimately provides.
     * There is deliberately no device id, IP address, location or hardware
     * detail here — TalkinShield does not collect any of it.
     */
    clientInfo: {
      declaredVersion: events[events.length - 1]?.clientVersion ?? null,
      declaredPlatform: events[events.length - 1]?.platform ?? null,
      attestationAvailable: capabilities.clientAttestation,
      note: capabilities.clientAttestation
        ? 'Signed attestation available from the platform integration.'
        : 'Official client attestation is not available; client findings are behavioural indicators only.',
    },
    unavailableData: unavailableDataNotes(capabilities),
  });
}

async function listIncidents({ request, deps }: RouteContext): Promise<ApiResponse> {
  const limit = clampLimit(request.query.limit, 25, 100);
  const status = request.query.status as IncidentStatus | undefined;
  const incidents = await deps.incidents.list({
    limit,
    ...(status !== undefined ? { status } : {}),
    ...(request.query.userId !== undefined ? { userId: request.query.userId } : {}),
    ...(request.query.roomId !== undefined ? { roomId: request.query.roomId } : {}),
  });
  return ok({ incidents, count: incidents.length });
}

async function getIncident({ request, deps }: RouteContext): Promise<ApiResponse> {
  const id = request.pathParams.incidentId;
  if (id === undefined) return badRequest('incidentId is required.');
  const incident = await deps.incidents.get(id);
  if (incident === undefined) return notFound('Incident not found.');
  return ok({ incident });
}

async function patchIncident({ request, deps, principal, nowMs }: RouteContext): Promise<ApiResponse> {
  const id = request.pathParams.incidentId;
  if (id === undefined) return badRequest('incidentId is required.');

  const body = asObject(request.body);
  if (body === undefined) return badRequest('A JSON object body is required.');

  const status = body.status;
  const validStatuses: IncidentStatus[] = [
    'OPEN',
    'ACKNOWLEDGED',
    'ACTIONED',
    'DISMISSED_FALSE_POSITIVE',
    'CLOSED',
  ];
  if (typeof status !== 'string' || !validStatuses.includes(status as IncidentStatus)) {
    return badRequest(`status must be one of: ${validStatuses.join(', ')}.`);
  }

  const note = typeof body.reviewNote === 'string' ? body.reviewNote.trim() : '';
  if (note.length < 8) {
    return badRequest(
      'reviewNote of at least 8 characters is required: status changes must be explainable in the audit trail.',
    );
  }

  const updated = await deps.incidents.updateStatus(
    id,
    status as IncidentStatus,
    principal.subject,
    note,
    nowMs,
  );
  if (updated === undefined) return notFound('Incident not found.');

  await audit(deps, {
    actorId: principal.subject,
    action: 'INCIDENT_STATUS_CHANGED',
    target: id,
    reason: note,
    outcome: 'SUCCESS',
    nowMs,
    detail: { newStatus: status, moderator: principal.username },
  });

  // A false-positive dismissal is the operator's feedback signal for tuning.
  if (status === 'DISMISSED_FALSE_POSITIVE') {
    deps.metrics.count('FalsePositiveReported', 1, {
      topSignal: updated.detectedBehaviors[0] ?? 'unknown',
    });
    await deps.publisher.publish('FalsePositiveReported', {
      incidentId: id,
      userId: updated.userId,
      detectedBehaviors: updated.detectedBehaviors,
      reviewNote: note,
    });
  }

  return ok({ incident: updated });
}

async function getEvidence({ request, deps, principal, nowMs }: RouteContext): Promise<ApiResponse> {
  const key = request.pathParams.key;
  if (key === undefined || key.length === 0) return badRequest('An evidence key is required.');

  // Path traversal guard: keys are opaque and must match the generated shape.
  if (!/^evidence\/\d{4}\/\d{2}\/\d{2}\/[0-9a-f]{4}\/[A-Za-z0-9-]+\/\d{4}\.json$/u.test(key)) {
    return badRequest('Malformed evidence key.');
  }

  const bundle = await deps.evidence.get(key);
  if (bundle === undefined) return notFound('Evidence bundle not found.');

  const verification = verifyBundle(bundle);

  await audit(deps, {
    actorId: principal.subject,
    action: 'EVIDENCE_ACCESSED',
    target: key,
    reason: 'Moderator opened an evidence bundle for review.',
    outcome: 'SUCCESS',
    nowMs,
    detail: { integrityValid: verification.valid },
  });

  return ok({ bundle, verification });
}

async function verifyEvidence({ request, deps }: RouteContext): Promise<ApiResponse> {
  const body = asObject(request.body);
  const incidentId = body?.incidentId;
  if (typeof incidentId !== 'string' || incidentId.length === 0) {
    return badRequest('incidentId is required.');
  }

  const keys = await deps.evidence.listByIncident(incidentId);
  const bundles = [];
  for (const key of keys) {
    const bundle = await deps.evidence.get(key);
    if (bundle !== undefined) bundles.push(bundle);
  }

  if (bundles.length === 0) return notFound('No evidence bundles for this incident.');

  return ok({
    incidentId,
    bundleCount: bundles.length,
    missing: keys.length - bundles.length,
    chain: verifyChain(bundles),
    bundles: bundles.map((b) => ({
      key: b.key,
      sequence: b.sequence,
      contentHash: b.contentHash,
      verification: verifyBundle(b),
    })),
  });
}

async function postModeration({ request, deps, principal }: RouteContext): Promise<ApiResponse> {
  const body = asObject(request.body);
  if (body === undefined) return badRequest('A JSON object body is required.');

  const kind = body.action;
  if (typeof kind !== 'string' || !MODERATION_ACTIONS.includes(kind as ModerationActionKind)) {
    return badRequest(`action must be one of: ${MODERATION_ACTIONS.join(', ')}.`);
  }
  const targetUserId = body.targetUserId;
  if (typeof targetUserId !== 'string' || !/^[A-Za-z0-9_.:@-]{1,128}$/u.test(targetUserId)) {
    return badRequest('A valid targetUserId is required.');
  }
  const reason = body.reason;
  if (typeof reason !== 'string') return badRequest('reason is required.');

  // Platform-scoped actions need the stronger permission.
  const capabilities = deps.platform.capabilities();
  const wantsPlatform =
    (kind === 'MUTE' && capabilities.remoteMute) ||
    (kind === 'BLOCK' && capabilities.remoteBlock) ||
    kind === 'REPORT';
  if (wantsPlatform) {
    const decision = authorize(principal, 'moderation:platform', deps.env.auth);
    if (!decision.ok) return error(403, decision.code, decision.message);
  }

  const result = await applyModeration(
    {
      kind: kind as ModerationActionKind,
      targetUserId,
      reason,
      ...(typeof body.roomId === 'string' ? { roomId: body.roomId } : {}),
      ...(typeof body.incidentId === 'string' ? { incidentId: body.incidentId } : {}),
      ...(typeof body.durationSeconds === 'number' ? { durationSeconds: body.durationSeconds } : {}),
    },
    principal,
    deps,
  );

  if ('rejected' in result) return badRequest(result.rejected);

  return ok({
    applied: result.applied,
    scope: result.scope,
    message: result.message,
    platformActionUnavailable: result.platformActionUnavailable,
    action: result.action,
  });
}

async function listModerationActions({ request, deps }: RouteContext): Promise<ApiResponse> {
  const limit = clampLimit(request.query.limit, 50, 200);
  const actions = request.query.userId
    ? await deps.actions.listByUser(request.query.userId, limit)
    : await deps.actions.listRecent(limit);
  return ok({ actions, count: actions.length });
}

async function getAffordances({ deps }: RouteContext): Promise<ApiResponse> {
  const capabilities = deps.platform.capabilities();
  return ok({
    affordances: availableActions(deps),
    capabilities,
    unavailableData: unavailableDataNotes(capabilities),
    integration: deps.platform.name,
  });
}

async function getRules({ deps }: RouteContext): Promise<ApiResponse> {
  const stored = await deps.rules.getPatch();
  const effective = resolveConfig(stored?.patch as DeepPartial<DetectionConfig> | undefined);
  return ok({
    effective,
    overrides: stored?.patch ?? {},
    version: stored?.version ?? 'default',
  });
}

async function putRules({ request, deps, principal, nowMs }: RouteContext): Promise<ApiResponse> {
  const body = asObject(request.body);
  if (body === undefined) return badRequest('A JSON object body is required.');

  const patch = body.overrides;
  if (patch === undefined || typeof patch !== 'object' || Array.isArray(patch)) {
    return badRequest('overrides must be an object.');
  }

  const problems = validateConfigPatch(patch as DeepPartial<DetectionConfig>);
  if (problems.length > 0) {
    return badRequest('The supplied detection rules are not valid.', { problems });
  }

  const version = `v${nowMs}`;
  await deps.rules.savePatch(patch as DeepPartial<DetectionConfig>, version, principal.subject);

  await audit(deps, {
    actorId: principal.subject,
    action: 'DETECTION_RULES_UPDATED',
    target: 'detection-config',
    reason: typeof body.reason === 'string' && body.reason.trim().length > 0
      ? body.reason.trim()
      : 'Detection rules updated from the admin dashboard.',
    outcome: 'SUCCESS',
    nowMs,
    detail: { version, keys: Object.keys(patch as object).join(',') },
  });

  const effective = resolveConfig(patch as DeepPartial<DetectionConfig>);
  return ok({ version, effective });
}

async function getSettings({ deps }: RouteContext): Promise<ApiResponse> {
  const { config, version } = await loadConfig(deps.rules);
  const capabilities = deps.platform.capabilities();
  // Only non-sensitive configuration is exposed. No ARNs, ids or secret names.
  return ok({
    stage: deps.env.stage,
    region: deps.env.region,
    integration: { name: deps.platform.name, adapter: deps.env.talkin.adapter, capabilities },
    ai: {
      bedrockEnabled: deps.classifier.enabled,
      modelId: deps.classifier.enabled ? deps.env.bedrock.modelId : null,
      note: deps.classifier.enabled
        ? 'AI classification is advisory. It cannot by itself trigger a durable penalty.'
        : 'AI classification is disabled; detection is fully deterministic.',
    },
    voice: {
      transcribeEnabled: deps.env.transcribe.enabled,
      note: deps.env.transcribe.enabled
        ? 'Transcription is enabled for audio this deployment is authorized and consented to process.'
        : 'Transcription is disabled. No call audio is received or processed.',
    },
    retentionDays: config.retention,
    riskThresholds: config.risk.thresholds,
    alerting: { minLevel: config.alert.minLevel },
    configVersion: version,
    unavailableData: unavailableDataNotes(capabilities),
  });
}

async function listLogs({ request, deps }: RouteContext): Promise<ApiResponse> {
  const limit = clampLimit(request.query.limit, 100, 500);
  const entries = await deps.audit.list({
    limit,
    ...(request.query.actorId !== undefined ? { actorId: request.query.actorId } : {}),
    ...(request.query.sinceMs !== undefined ? { sinceMs: Number(request.query.sinceMs) } : {}),
  });
  return ok({ entries, count: entries.length });
}

async function getMe({ principal, deps }: RouteContext): Promise<ApiResponse> {
  return ok({
    subject: principal.subject,
    username: principal.username,
    roles: principal.roles,
    groups: principal.groups,
    mfaPresent: principal.mfaPresent,
    permissions: permissionsFor(principal),
    mfaRequiredForDestructive: deps.env.auth.requireMfaForDestructive,
  });
}

// --- Shared helpers --------------------------------------------------------

/**
 * The honest inventory of what this deployment cannot see.
 * Rendered by the dashboard so an operator is never left guessing whether a
 * blank panel means "clean" or "never looked".
 */
export function unavailableDataNotes(
  capabilities: ReturnType<ModerationDeps['platform']['capabilities']>,
): Array<{ field: string; status: string; reason: string }> {
  const notes: Array<{ field: string; status: string; reason: string }> = [];

  if (!capabilities.messageContent) {
    notes.push({
      field: 'Message content',
      status: 'UNAVAILABLE',
      reason: 'This deployment is not authorized to process message text.',
    });
  }
  if (!capabilities.voiceAudio) {
    notes.push({
      field: 'Voice audio / transcripts',
      status: 'UNAVAILABLE',
      reason: 'No approved, consented audio integration is configured.',
    });
  }
  if (!capabilities.hiddenPresenceEvents) {
    notes.push({
      field: 'Hidden / ghost-mode presence',
      status: 'UNAVAILABLE',
      reason:
        'The platform integration does not expose hidden presence events. Insufficient authorized telemetry.',
    });
  }
  if (!capabilities.clientAttestation) {
    notes.push({
      field: 'Client attestation',
      status: 'UNAVAILABLE',
      reason: 'The platform provides no signed official-build proof.',
    });
  }
  if (!capabilities.moderationEvents) {
    notes.push({
      field: 'Platform moderation events',
      status: 'UNAVAILABLE',
      reason: 'Moderation evasion cannot be assessed without platform moderation events.',
    });
  }
  if (!capabilities.remoteMute) {
    notes.push({
      field: 'Official mute API',
      status: 'UNAVAILABLE',
      reason: 'MUTE applies locally to the protected user only.',
    });
  }
  if (!capabilities.remoteBlock) {
    notes.push({
      field: 'Official block API',
      status: 'UNAVAILABLE',
      reason: 'BLOCK applies locally to the protected user only.',
    });
  }

  // Always-excluded categories, stated so their absence is never ambiguous.
  notes.push(
    {
      field: 'Location / GPS',
      status: 'OUT_OF_SCOPE',
      reason: 'TalkinShield never collects location data.',
    },
    {
      field: 'Device identifiers & files',
      status: 'OUT_OF_SCOPE',
      reason: 'No device fingerprinting or filesystem access is performed.',
    },
    {
      field: 'Credentials & tokens',
      status: 'OUT_OF_SCOPE',
      reason: 'Never collected; redacted if encountered in content.',
    },
    {
      field: 'Camera / microphone control',
      status: 'OUT_OF_SCOPE',
      reason: 'TalkinShield cannot and does not control any participant device.',
    },
    {
      field: 'Network traffic',
      status: 'OUT_OF_SCOPE',
      reason: 'Only application events delivered to the API are observed.',
    },
  );

  return notes;
}

function redactEventForDisplay(event: TalkinEvent, deps: RouterDeps): Record<string, unknown> {
  const capabilities = deps.platform.capabilities();
  const out: Record<string, unknown> = { ...event };
  if (!capabilities.messageContent) {
    delete out.message;
    out.messageUnavailable = 'Not authorized to display message content.';
  }
  return out;
}

function clampLimit(raw: string | undefined, fallback: number, max: number): number {
  if (raw === undefined) return fallback;
  const parsed = Number(raw);
  if (!Number.isFinite(parsed) || parsed <= 0) return fallback;
  return Math.min(Math.floor(parsed), max);
}

function asObject(body: unknown): Record<string, unknown> | undefined {
  if (body === null || body === undefined) return undefined;
  if (typeof body !== 'object' || Array.isArray(body)) return undefined;
  return body as Record<string, unknown>;
}

async function audit(
  deps: RouterDeps,
  entry: {
    actorId: string;
    action: string;
    target: string;
    reason: string;
    outcome: 'SUCCESS' | 'FAILURE' | 'DENIED';
    nowMs: number;
    detail?: Record<string, string | number | boolean>;
    sourceIp?: string;
  },
): Promise<void> {
  try {
    await deps.audit.append({
      auditId: newAuditId(),
      atMs: entry.nowMs,
      actorId: entry.actorId,
      actorKind: entry.actorId === 'system' ? 'SYSTEM' : 'MODERATOR',
      action: entry.action,
      target: entry.target,
      reason: entry.reason,
      outcome: entry.outcome,
      ...(entry.detail ? { detail: entry.detail } : {}),
      ...(entry.sourceIp !== undefined ? { sourceIp: entry.sourceIp } : {}),
      ttlEpochSeconds: Math.floor(
        (entry.nowMs + deps.env.retentionDays.audit * 86_400_000) / 1000,
      ),
    });
  } catch (err: unknown) {
    // An audit failure must be loud but must not mask the original outcome.
    deps.logger.error('Failed to append audit entry.', {
      action: entry.action,
      error: err instanceof Error ? err.message : String(err),
    });
    deps.metrics.count('AuditWriteFailure');
  }
}
