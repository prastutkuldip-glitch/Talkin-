/**
 * Incident construction and alert decisions.
 *
 * An incident is the durable, reviewable record of a decision. It carries every
 * field required by the brief's evidence specification, plus the explicit
 * authorization context.
 */

import type { AlertConfig, DetectionConfig } from '../config/detection-config.ts';
import type { AbuseClassification, DetectionSignal, SignalCode } from '../types/detection.ts';
import type { TalkinEvent } from '../types/events.ts';
import type {
  ActionRecord,
  ActionType,
  Incident,
  MessageExcerpt,
  ResponsePlan,
  RiskAssessment,
  RiskLevel,
} from '../types/risk.ts';
import { newActionId, newIncidentId } from '../util/ids.ts';
import { redactIdentifiers, truncate } from '../util/text.ts';
import { noisyOr } from '../util/stats.ts';

export interface BuildIncidentInput {
  assessment: RiskAssessment;
  signals: readonly DetectionSignal[];
  plan: ResponsePlan;
  config: DetectionConfig;
  abuse?: AbuseClassification;
  /** Events whose text should be excerpted into the incident. */
  events: readonly TalkinEvent[];
  /** False when message content may not be stored. */
  messageContentAuthorized: boolean;
  nowMs: number;
}

export function buildIncident(input: BuildIncidentInput): Incident {
  const { assessment, signals, plan, config, nowMs } = input;

  const detectedBehaviors = [...new Set(signals.map((s) => s.code))];
  const detectionReasons = signals.map((s) => `[${s.code}] ${s.reason}`);

  const relevantMessages: MessageExcerpt[] = input.messageContentAuthorized
    ? input.events
        .filter((e) => typeof e.message === 'string' && e.message.length > 0)
        .slice(-20)
        .map((e) => {
          const { text, redacted } = redactIdentifiers(e.message as string);
          return {
            eventId: e.eventId,
            atMs: e.receivedAtMs,
            text: truncate(text, config.abuse.excerptMaxChars),
            isTranscript: e.messageIsTranscript === true,
            redacted,
          };
        })
    : [];

  const modelVersions = [
    ...new Set([
      assessment.engineVersion,
      ...signals.map((s) => s.detector),
      ...(input.abuse ? input.abuse.modelVersion.split(';') : []),
    ]),
  ].filter((v) => v.length > 0);

  // Aggregate confidence: independent agreeing detectors raise it, but it is
  // capped well below certainty.
  const confidence = Math.min(
    noisyOr(signals.map((s) => s.confidence)),
    0.99,
  );

  const latest = input.events[input.events.length - 1];

  const incident: Incident = {
    incidentId: newIncidentId(nowMs),
    userId: assessment.userId,
    ...(assessment.roomId !== undefined ? { roomId: assessment.roomId } : {}),
    createdAtMs: nowMs,
    updatedAtMs: nowMs,
    status: 'OPEN',
    riskScore: assessment.score,
    riskLevel: assessment.level,
    detectedBehaviors,
    detectionReasons,
    relevantMessages,
    authorizedMetadata: buildAuthorizedMetadata(latest, assessment, plan),
    actionsTaken: [],
    confidence,
    modelVersions,
    evidenceKeys: [],
  };

  return incident;
}

/**
 * Metadata placed on an incident.
 *
 * Deliberately narrow: platform, declared client version, room, counts and
 * engine state. No IP address, no device identifier, no location, no account
 * personal data — none of which TalkinShield collects.
 */
function buildAuthorizedMetadata(
  event: TalkinEvent | undefined,
  assessment: RiskAssessment,
  plan: ResponsePlan,
): Record<string, string | number | boolean> {
  const out: Record<string, string | number | boolean> = {
    riskLevel: assessment.level,
    riskScore: assessment.score,
    peakConfidence: assessment.peakConfidence,
    deterministicOnly: assessment.deterministicOnly,
    signalCount: assessment.contributions.length,
    platformActionUnavailable: plan.platformActionUnavailable,
  };

  if (event) {
    out.platform = event.platform;
    out.eventType = event.eventType;
    if (event.clientVersion !== undefined) out.declaredClientVersion = event.clientVersion;
    if (event.messageIsTranscript === true) out.sourceIsTranscript = true;
    // Operator-supplied metadata was already sanitized at ingestion.
    for (const [k, v] of Object.entries(event.metadata)) {
      out[`meta.${k}`] = v;
    }
  }

  return out;
}

export interface MergeIncidentResult {
  incident: Incident;
  /** Signal codes seen on this pass that the incident did not already have. */
  newBehaviors: SignalCode[];
  /** True when the incident's risk score increased. */
  escalated: boolean;
}

/**
 * Fold a new detection pass into an existing open incident.
 *
 * Ongoing behaviour from the same account belongs on one incident: the risk
 * score rises to the new peak, new behaviours and reasons are appended, and the
 * message excerpts grow (bounded). Nothing is ever removed — an incident only
 * accumulates, so the record of what was detected stays complete.
 */
export function mergeIntoIncident(
  existing: Incident,
  input: BuildIncidentInput,
): MergeIncidentResult {
  const incident: Incident = structuredClone(existing);
  const { assessment, signals, config, nowMs } = input;

  const known = new Set(incident.detectedBehaviors);
  const newBehaviors = [...new Set(signals.map((s) => s.code))].filter((code) => !known.has(code));

  for (const code of newBehaviors) incident.detectedBehaviors.push(code);

  // Append only reasons we have not already recorded, so the list stays useful.
  const knownReasons = new Set(incident.detectionReasons);
  for (const signal of signals) {
    const line = `[${signal.code}] ${signal.reason}`;
    if (!knownReasons.has(line)) {
      incident.detectionReasons.push(line);
      knownReasons.add(line);
    }
  }

  const escalated = assessment.score > incident.riskScore;
  if (escalated) {
    incident.riskScore = assessment.score;
    incident.riskLevel = assessment.level;
  }

  incident.confidence = Math.max(
    incident.confidence,
    Math.min(noisyOr(signals.map((s) => s.confidence)), 0.99),
  );

  if (input.messageContentAuthorized) {
    const seen = new Set(incident.relevantMessages.map((m) => m.eventId));
    for (const event of input.events) {
      if (seen.has(event.eventId)) continue;
      if (typeof event.message !== 'string' || event.message.length === 0) continue;
      const { text, redacted } = redactIdentifiers(event.message);
      incident.relevantMessages.push({
        eventId: event.eventId,
        atMs: event.receivedAtMs,
        text: truncate(text, config.abuse.excerptMaxChars),
        isTranscript: event.messageIsTranscript === true,
        redacted,
      });
      seen.add(event.eventId);
    }
    // Keep the most recent excerpts only — data minimization.
    if (incident.relevantMessages.length > 20) {
      incident.relevantMessages = incident.relevantMessages.slice(-20);
    }
  }

  for (const version of [
    assessment.engineVersion,
    ...signals.map((s) => s.detector),
    ...(input.abuse ? input.abuse.modelVersion.split(';') : []),
  ]) {
    if (version.length > 0 && !incident.modelVersions.includes(version)) {
      incident.modelVersions.push(version);
    }
  }

  incident.updatedAtMs = nowMs;
  // Continued activity on a reviewed incident reopens it for attention.
  if (incident.status === 'ACKNOWLEDGED' && escalated) incident.status = 'OPEN';

  return { incident, newBehaviors, escalated };
}

export interface RecordActionInput {
  actionType: ActionType;
  actorKind: 'SYSTEM' | 'MODERATOR';
  actorId: string;
  targetUserId: string;
  roomId?: string;
  reason: string;
  scope: 'LOCAL_TO_REQUESTER' | 'PLATFORM_API' | 'INTERNAL';
  succeeded: boolean;
  failureReason?: string;
  incidentId?: string;
  riskScoreAtAction?: number;
  nowMs: number;
}

/**
 * Build an action record. `reason` is mandatory and validated non-empty — every
 * automated action must be explainable.
 */
export function recordAction(input: RecordActionInput): ActionRecord {
  if (input.reason.trim().length === 0) {
    throw new Error('recordAction requires a non-empty reason: every action must be explainable.');
  }
  return {
    actionId: newActionId(),
    actionType: input.actionType,
    actorKind: input.actorKind,
    actorId: input.actorId,
    targetUserId: input.targetUserId,
    ...(input.roomId !== undefined ? { roomId: input.roomId } : {}),
    atMs: input.nowMs,
    reason: input.reason,
    scope: input.scope,
    succeeded: input.succeeded,
    ...(input.failureReason !== undefined ? { failureReason: input.failureReason } : {}),
    ...(input.incidentId !== undefined ? { incidentId: input.incidentId } : {}),
    ...(input.riskScoreAtAction !== undefined ? { riskScoreAtAction: input.riskScoreAtAction } : {}),
  };
}

// --- Alerting --------------------------------------------------------------

export const ALERT_REASONS = [
  'CRITICAL_RISK',
  'SEVERE_ABUSE',
  'THREAT_DETECTED',
  'MASS_SPAM',
  'REPEATED_EVASION',
  'SUSPICIOUS_CLIENT',
] as const;
export type AlertReason = (typeof ALERT_REASONS)[number];

export interface AlertDecision {
  shouldAlert: boolean;
  reasons: AlertReason[];
  /** Dedupe key: suppresses repeat alerts for the same user+reason set. */
  dedupeKey: string;
  summary: string;
}

const LEVEL_ORDER: Record<RiskLevel, number> = { LOW: 0, MEDIUM: 1, HIGH: 2, CRITICAL: 3 };

export function decideAlert(args: {
  assessment: RiskAssessment;
  signals: readonly DetectionSignal[];
  abuse?: AbuseClassification;
  config: AlertConfig;
}): AlertDecision {
  const { assessment, signals, abuse, config } = args;
  const reasons: AlertReason[] = [];

  if (LEVEL_ORDER[assessment.level] >= LEVEL_ORDER[config.minLevel]) {
    if (assessment.level === 'CRITICAL') reasons.push('CRITICAL_RISK');
  }

  const codes = new Set<SignalCode>(signals.map((s) => s.code));

  if (config.alertOnThreat && (codes.has('THREAT_LANGUAGE') || abuse?.classification === 'THREAT')) {
    reasons.push('THREAT_DETECTED');
  }
  if (config.alertOnSevereAbuse && (codes.has('ABUSE_SEVERE') || abuse?.classification === 'SEVERE_ABUSE')) {
    reasons.push('SEVERE_ABUSE');
  }
  if (
    config.alertOnMassSpam &&
    (codes.has('COORDINATED_IDENTICAL_CONTENT') ||
      codes.has('BOT_SUSTAINED_RATE') ||
      (codes.has('SPAM_IDENTICAL_REPEAT') &&
        signals.some((s) => s.code === 'SPAM_IDENTICAL_REPEAT' && s.severity === 'SEVERE')))
  ) {
    reasons.push('MASS_SPAM');
  }
  if (
    config.alertOnRepeatedEvasion &&
    (codes.has('EVASION_POST_MODERATION_ACTIVITY') || codes.has('EVASION_REJOIN_CYCLING'))
  ) {
    reasons.push('REPEATED_EVASION');
  }
  if (
    config.alertOnSuspiciousClient &&
    (codes.has('CLIENT_ATTESTATION_FAILED') ||
      codes.has('CLIENT_IMPOSSIBLE_SEQUENCE') ||
      codes.has('CLIENT_ABNORMAL_REQUEST_RATE'))
  ) {
    reasons.push('SUSPICIOUS_CLIENT');
  }

  const unique = [...new Set(reasons)].sort(
    (a, b) => ALERT_REASON_SEVERITY[b] - ALERT_REASON_SEVERITY[a],
  );
  const minLevelMet = LEVEL_ORDER[assessment.level] >= LEVEL_ORDER[config.minLevel];

  // An alert fires when the configured level is met, or when a specific
  // always-alert condition (threat, severe abuse) is present regardless.
  const alwaysAlert = unique.includes('THREAT_DETECTED') || unique.includes('SEVERE_ABUSE');
  const shouldAlert = unique.length > 0 && (minLevelMet || alwaysAlert);

  /**
   * Dedupe on the account, risk level and *most severe* reason only.
   *
   * Keying on the full reason set would re-alert every time a secondary reason
   * appeared or disappeared — an oscillating set would page on-call repeatedly
   * for one ongoing episode. Keying on the top reason plus level means a
   * genuine escalation (spam -> threat, HIGH -> CRITICAL) still alerts, while
   * churn within the same severity is suppressed.
   */
  const topReason = unique[0] ?? 'NONE';

  return {
    shouldAlert,
    reasons: unique,
    dedupeKey: `${assessment.userId}:${assessment.level}:${topReason}`,
    summary: shouldAlert
      ? `${assessment.level} risk (${assessment.score}/100) for user ${assessment.userId}: ${unique.join(', ')}.`
      : 'No alert conditions met.',
  };
}

/** Higher wins when choosing the dedupe key's representative reason. */
const ALERT_REASON_SEVERITY: Record<AlertReason, number> = {
  THREAT_DETECTED: 5,
  SEVERE_ABUSE: 4,
  CRITICAL_RISK: 3,
  REPEATED_EVASION: 2,
  SUSPICIOUS_CLIENT: 1,
  MASS_SPAM: 0,
};
