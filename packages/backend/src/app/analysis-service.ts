/**
 * Analysis service: runs the detection pipeline for one event and performs the
 * resulting automated actions.
 *
 * This is where pure decisions meet side effects. The decision itself comes from
 * `@talkinshield/core`; everything here is persistence, eventing and the
 * narrowly-scoped platform calls the policy authorized.
 */

import {
  analyzeEvent,
  buildEvidenceBundle,
  buildIncident,
  buildLexicon,
  carryForward,
  decideAlert,
  emptyState,
  mergeIntoIncident,
  recordAction,
  resolveConfig,
  type AnalyzeResult,
  type CompiledLexicon,
  type DeepPartial,
  type DetectionConfig,
  type Incident,
  type TalkinEvent,
} from '@talkinshield/core';

import type {
  ActionStore,
  AuditStore,
  Clock,
  EventPublisher,
  EventStore,
  EvidenceStore,
  IncidentStore,
  Logger,
  Metrics,
  Notifier,
  RateLimiter,
  RetentionDays,
  RulesStore,
  SignalStore,
  TalkinPlatformAdapter,
  TextClassifier,
  UserStateStore,
} from '../ports.ts';
import { newAuditId } from '@talkinshield/core';

export interface AnalysisDeps {
  events: EventStore;
  userState: UserStateStore;
  signals: SignalStore;
  incidents: IncidentStore;
  actions: ActionStore;
  audit: AuditStore;
  evidence: EvidenceStore;
  rules: RulesStore;
  rateLimiter: RateLimiter;
  classifier: TextClassifier;
  platform: TalkinPlatformAdapter;
  publisher: EventPublisher;
  notifier: Notifier;
  logger: Logger;
  metrics: Metrics;
  clock: Clock;
  retentionDays: RetentionDays;
}

export interface AnalysisOutcome {
  result: AnalyzeResult;
  incident?: Incident;
  /** True when a new incident was opened; false when folded into an existing one. */
  incidentIsNew?: boolean;
  evidenceKey?: string;
  /** True when an alert was actually dispatched. */
  alerted: boolean;
  /**
   * True when alert conditions were met but the alert was deduplicated.
   * Distinguished from `alerted: false` so "no alert raised" is never confused
   * with "alert raised but suppressed as a repeat".
   */
  alertSuppressed?: boolean;
  /** Platform actions attempted, and whether they were possible. */
  platformActions: Array<{ action: string; ok: boolean; reason: string }>;
}

function existingActionCount(previous: Incident | undefined): number {
  return previous?.actionsTaken.length ?? 0;
}

/** Config + compiled lexicon cache, refreshed when the operator edits rules. */
interface ConfigCache {
  version: string;
  config: DetectionConfig;
  lexicon: CompiledLexicon;
}

let configCache: ConfigCache | undefined;

export async function loadConfig(rules: RulesStore): Promise<ConfigCache> {
  const stored = await rules.getPatch();
  const version = stored?.version ?? 'default';
  if (configCache?.version === version) return configCache;

  const config = resolveConfig(stored?.patch as DeepPartial<DetectionConfig> | undefined);
  const next: ConfigCache = {
    version,
    config,
    lexicon: buildLexicon(config.abuse, version),
  };
  configCache = next;
  return next;
}

/** Test hook: clears the module-level config cache. */
export function resetConfigCache(): void {
  configCache = undefined;
}

export async function analyzeAndRespond(
  event: TalkinEvent,
  deps: AnalysisDeps,
): Promise<AnalysisOutcome> {
  const nowMs = deps.clock.now();
  const { config, lexicon } = await loadConfig(deps.rules);
  const capabilities = deps.platform.capabilities();
  const log = deps.logger.child({ userId: event.userId, eventId: event.eventId });

  // --- Gather authorized context -----------------------------------------
  const [state, restrictions, attestation, malformed, rpm] = await Promise.all([
    deps.userState.get(event.userId),
    capabilities.moderationEvents
      ? deps.platform.getRestrictions(event.userId, event.roomId).catch((err: unknown) => {
          log.warn('Failed to read platform restrictions; evasion detection degraded.', {
            error: errorMessage(err),
          });
          return [] as const;
        })
      : Promise.resolve([] as const),
    capabilities.clientAttestation
      ? deps.platform.verifyClient(event.userId, event.clientVersion).catch(() => undefined)
      : Promise.resolve(undefined),
    deps.rateLimiter.countMalformed(`user:${event.userId}`, config.client.malformedWindowMs / 1000, nowMs),
    deps.rateLimiter.observedRequestsPerMinute(`user:${event.userId}`, nowMs),
  ]);

  // --- Optional AI classification ----------------------------------------
  let bedrock: Awaited<ReturnType<TextClassifier['classify']>>;
  if (
    deps.classifier.enabled &&
    capabilities.messageContent &&
    typeof event.message === 'string' &&
    event.message.length > 0
  ) {
    try {
      bedrock = await deps.classifier.classify(event.message, {
        isTranscript: event.messageIsTranscript === true,
      });
    } catch (err: unknown) {
      // An AI failure must never block moderation; rules still apply.
      log.warn('AI classification failed; continuing with deterministic rules only.', {
        error: errorMessage(err),
      });
      deps.metrics.count('ClassifierFailure');
    }
  }

  // --- Decide -------------------------------------------------------------
  const result = analyzeEvent({
    event,
    state: state ?? emptyState(event.userId),
    config,
    capabilities,
    nowMs,
    lexicon,
    restrictions,
    malformedRequestCount: malformed,
    observedRequestsPerMinute: rpm,
    ...(attestation ? { attestation } : {}),
    ...(bedrock ? { bedrock } : {}),
  });

  // --- Persist ------------------------------------------------------------
  const signalTtl = epochSeconds(nowMs + deps.retentionDays.signals * 86_400_000);
  await Promise.all([
    persistState(deps, result, nowMs),
    result.signals.length > 0
      ? deps.signals.putMany(event.userId, result.signals, signalTtl)
      : Promise.resolve(),
    deps.userState.recordAssessment(result.assessment),
  ]);

  deps.metrics.gauge('RiskScore', result.assessment.score, { level: result.assessment.level });
  for (const signal of result.signals) {
    deps.metrics.count('Signal', 1, { code: signal.code });
  }

  const outcome: AnalysisOutcome = { result, alerted: false, platformActions: [] };

  // --- Automated response -------------------------------------------------
  const plan = result.plan;

  if (plan.automated.includes('INCREASE_MONITORING')) {
    await deps.actions.put(
      recordAction({
        actionType: 'MONITORING_INCREASED',
        actorKind: 'SYSTEM',
        actorId: 'system',
        targetUserId: event.userId,
        roomId: event.roomId,
        reason: `Risk level ${result.assessment.level}: monitoring increased. ${plan.rationale}`,
        scope: 'INTERNAL',
        succeeded: true,
        riskScoreAtAction: result.assessment.score,
        nowMs,
      }),
    );
  }

  if (plan.automated.includes('CREATE_INCIDENT')) {
    const relatedEvents = await collectIncidentEvents(deps, event, result);
    const incidentInput = {
      assessment: result.assessment,
      signals: result.signals,
      plan,
      config,
      ...(result.abuse ? { abuse: result.abuse } : {}),
      events: relatedEvents,
      messageContentAuthorized: capabilities.messageContent,
      nowMs,
    };

    // Reuse an open incident for the same account rather than opening a new one
    // for every event in an ongoing episode.
    const reusable = await deps.incidents.findReusable(
      event.userId,
      event.roomId,
      nowMs - config.incident.dedupeWindowMs,
    );

    let incident: Incident;
    let isNewIncident: boolean;
    let newBehaviors: string[] = [];

    if (reusable !== undefined) {
      const merged = mergeIntoIncident(reusable, incidentInput);
      incident = merged.incident;
      newBehaviors = merged.newBehaviors;
      isNewIncident = false;

      incident.actionsTaken.push(
        recordAction({
          actionType: 'INCIDENT_STATUS_CHANGED',
          actorKind: 'SYSTEM',
          actorId: 'system',
          targetUserId: event.userId,
          roomId: event.roomId,
          reason:
            `Ongoing activity folded into this incident. ${plan.rationale}` +
            (newBehaviors.length > 0 ? ` New behaviours: ${newBehaviors.join(', ')}.` : ''),
          scope: 'INTERNAL',
          succeeded: true,
          incidentId: incident.incidentId,
          riskScoreAtAction: result.assessment.score,
          nowMs,
        }),
      );
    } else {
      incident = buildIncident(incidentInput);
      isNewIncident = true;
      newBehaviors = [...incident.detectedBehaviors];

      incident.actionsTaken.push(
        recordAction({
          actionType: 'INCIDENT_CREATED',
          actorKind: 'SYSTEM',
          actorId: 'system',
          targetUserId: event.userId,
          roomId: event.roomId,
          reason: plan.rationale,
          scope: 'INTERNAL',
          succeeded: true,
          incidentId: incident.incidentId,
          riskScoreAtAction: result.assessment.score,
          nowMs,
        }),
      );
    }

    outcome.incidentIsNew = isNewIncident;

    // --- Evidence --------------------------------------------------------
    // A repeat pass that revealed nothing new is already covered by the
    // existing bundle, so we do not write a redundant one.
    const wantEvidence =
      plan.automated.includes('PRESERVE_EVIDENCE') &&
      incident.evidenceKeys.length < config.incident.maxEvidenceBundles &&
      (isNewIncident ||
        !config.incident.evidenceOnNewBehaviorOnly ||
        newBehaviors.length > 0);

    if (wantEvidence) {
      try {
        const head = await deps.evidence.getChainHead();
        const bundle = buildEvidenceBundle({
          incident,
          assessment: result.assessment,
          signals: result.signals,
          capabilities,
          messages: relatedEvents.map((e) => ({
            eventId: e.eventId,
            atMs: e.receivedAtMs,
            ...(e.message !== undefined ? { text: e.message } : {}),
            isTranscript: e.messageIsTranscript === true,
          })),
          excerptMaxChars: config.abuse.excerptMaxChars,
          nowMs,
          ...(head ? { previous: head } : {}),
        });

        const stored = await deps.evidence.put(bundle);
        await deps.evidence.setChainHead(bundle.contentHash, bundle.sequence);
        incident.evidenceKeys.push(stored.key);
        outcome.evidenceKey = stored.key;

        incident.actionsTaken.push(
          recordAction({
            actionType: 'EVIDENCE_SAVED',
            actorKind: 'SYSTEM',
            actorId: 'system',
            targetUserId: event.userId,
            reason: `Evidence preserved automatically for ${result.assessment.level} risk incident.`,
            scope: 'INTERNAL',
            succeeded: true,
            incidentId: incident.incidentId,
            nowMs,
          }),
        );
      } catch (err: unknown) {
        log.error('Evidence preservation failed.', { error: errorMessage(err) });
        deps.metrics.count('EvidenceWriteFailure');
        incident.actionsTaken.push(
          recordAction({
            actionType: 'EVIDENCE_SAVED',
            actorKind: 'SYSTEM',
            actorId: 'system',
            targetUserId: event.userId,
            reason: 'Automatic evidence preservation was attempted for this incident.',
            scope: 'INTERNAL',
            succeeded: false,
            failureReason: errorMessage(err),
            incidentId: incident.incidentId,
            nowMs,
          }),
        );
      }
    }

    // --- Temporary platform restriction ----------------------------------
    // Applied at most once per incident window. Re-issuing it on every event of
    // an ongoing episode would hammer the platform API and extend the
    // restriction indefinitely by accident.
    const alreadyRestricted = incident.actionsTaken.some(
      (a) => a.actionType === 'PLATFORM_TEMP_BLOCK' && a.succeeded,
    );

    if (plan.automated.includes('PLATFORM_TEMPORARY_BLOCK') && !alreadyRestricted) {
      const platformResult = await deps.platform.block({
        userId: event.userId,
        roomId: event.roomId,
        durationSeconds: 900,
        reason: `Automated temporary restriction pending moderator review. ${plan.rationale}`,
      });

      const ok = platformResult.ok;
      outcome.platformActions.push({
        action: 'PLATFORM_TEMP_BLOCK',
        ok,
        reason: ok ? 'Applied via official moderation API.' : platformResult.reason,
      });

      incident.actionsTaken.push(
        recordAction({
          actionType: 'PLATFORM_TEMP_BLOCK',
          actorKind: 'SYSTEM',
          actorId: 'system',
          targetUserId: event.userId,
          roomId: event.roomId,
          reason: `Temporary 15-minute restriction via official API. ${plan.rationale}`,
          scope: 'PLATFORM_API',
          succeeded: ok,
          ...(ok ? {} : { failureReason: platformResult.reason }),
          incidentId: incident.incidentId,
          riskScoreAtAction: result.assessment.score,
          nowMs,
        }),
      );
    }

    await deps.incidents.put(incident);
    // Only newly-recorded actions are appended to the action store, so merging
    // does not re-insert the whole history each pass.
    for (const action of incident.actionsTaken.slice(existingActionCount(reusable))) {
      await deps.actions.put(action);
    }
    outcome.incident = incident;

    await deps.audit.append({
      auditId: newAuditId(),
      atMs: nowMs,
      actorId: 'system',
      actorKind: 'SYSTEM',
      action: isNewIncident ? 'INCIDENT_CREATED' : 'INCIDENT_UPDATED',
      target: incident.incidentId,
      reason: plan.rationale,
      outcome: 'SUCCESS',
      detail: {
        userId: event.userId,
        riskScore: result.assessment.score,
        riskLevel: result.assessment.level,
        signalCount: result.signals.length,
        newBehaviors: newBehaviors.join(',') || 'none',
      },
    });
  }

  // --- Alerting -----------------------------------------------------------
  const alertDecision = decideAlert({
    assessment: result.assessment,
    signals: result.signals,
    ...(result.abuse ? { abuse: result.abuse } : {}),
    config: config.alert,
  });

  if (alertDecision.shouldAlert) {
    const sent = await deps.notifier.send({
      subject: `TalkinShield ${result.assessment.level}: ${alertDecision.reasons.join(', ')}`,
      body: [
        alertDecision.summary,
        '',
        `Room: ${event.roomId}`,
        `Risk: ${result.assessment.score}/100 (${result.assessment.level})`,
        outcome.incident ? `Incident: ${outcome.incident.incidentId}` : 'Incident: not created',
        '',
        'Detection reasons:',
        ...result.signals.map((s) => `  - [${s.code}] ${s.reason}`),
        '',
        plan.rationale,
      ].join('\n'),
      level: result.assessment.level,
      dedupeKey: alertDecision.dedupeKey,
    });
    outcome.alerted = sent.sent;
    if (sent.suppressed === true) outcome.alertSuppressed = true;
    if (sent.sent) deps.metrics.count('AlertSent', 1, { level: result.assessment.level });
    else deps.metrics.count('AlertSuppressed', 1, { level: result.assessment.level });
  }

  // --- Publish for downstream consumers ----------------------------------
  const detail: Record<string, unknown> = {
    userId: event.userId,
    roomId: event.roomId,
    eventId: event.eventId,
    riskScore: result.assessment.score,
    riskLevel: result.assessment.level,
    signals: result.signals.map((s) => ({ code: s.code, confidence: s.confidence, reason: s.reason })),
    recommended: plan.recommended,
    automated: plan.automated,
    telemetryNotes: result.telemetryNotes,
  };
  if (outcome.incident) detail.incidentId = outcome.incident.incidentId;
  if (result.selfHarmConcern) detail.selfHarmConcern = true;

  await deps.publisher.publish('RiskAssessed', detail);

  // A wellbeing concern is routed separately and never as enforcement.
  if (result.selfHarmConcern) {
    await deps.publisher.publish('WellbeingConcern', {
      userId: event.userId,
      roomId: event.roomId,
      note:
        'Message content indicated possible risk to the sender. Routed for a wellbeing response, not moderation.',
    });
  }

  return outcome;
}

/** Persist user state with one optimistic-concurrency retry. */
async function persistState(deps: AnalysisDeps, result: AnalyzeResult, nowMs: number): Promise<void> {
  const version = await deps.userState.getVersion(result.nextState.userId);
  const written = await deps.userState.put(result.nextState, version);
  if (written) return;

  // Conflict: another event for this user was processed concurrently. Re-read
  // and merge rather than overwrite, so neither update is lost.
  const latest = await deps.userState.get(result.nextState.userId);
  if (latest === undefined) {
    await deps.userState.put(result.nextState, undefined);
    return;
  }

  const merged = {
    ...latest,
    recent: dedupeWindow([...latest.recent, ...result.nextState.recent]).slice(-200),
    abusiveFingerprints: [
      ...new Set([...latest.abusiveFingerprints, ...result.nextState.abusiveFingerprints]),
    ].slice(-50),
    priorViolations: Math.max(latest.priorViolations, result.nextState.priorViolations),
    evasionCount: Math.max(latest.evasionCount, result.nextState.evasionCount),
    carriedRisk: Math.max(latest.carriedRisk, carryForward(result.assessment)),
    lastViolationAtMs: Math.max(latest.lastViolationAtMs ?? 0, result.nextState.lastViolationAtMs ?? 0) || nowMs,
  };

  const latestVersion = await deps.userState.getVersion(result.nextState.userId);
  const ok = await deps.userState.put(merged, latestVersion);
  if (!ok) {
    deps.logger.warn('User state write lost a second optimistic-concurrency race; skipping.', {
      userId: result.nextState.userId,
    });
    deps.metrics.count('UserStateConflict');
  }
}

function dedupeWindow<T extends { eventId: string; atMs: number }>(entries: readonly T[]): T[] {
  const seen = new Map<string, T>();
  for (const entry of entries) seen.set(entry.eventId, entry);
  return [...seen.values()].sort((a, b) => a.atMs - b.atMs);
}

/** The events referenced by the signals, for incident excerpts and evidence. */
async function collectIncidentEvents(
  deps: AnalysisDeps,
  event: TalkinEvent,
  result: AnalyzeResult,
): Promise<TalkinEvent[]> {
  const ids = [...new Set(result.signals.flatMap((s) => s.evidenceEventIds))].filter(
    (id) => id !== event.eventId,
  );
  if (ids.length === 0) return [event];

  try {
    const fetched = await deps.events.getByIds(ids.slice(0, 20));
    return [...fetched, event].sort((a, b) => a.receivedAtMs - b.receivedAtMs);
  } catch {
    // Evidence is better with context, but an incident must still be created.
    return [event];
  }
}

function epochSeconds(ms: number): number {
  return Math.floor(ms / 1000);
}

export function errorMessage(err: unknown): string {
  if (err instanceof Error) return err.message;
  return String(err);
}
