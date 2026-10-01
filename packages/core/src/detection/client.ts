/**
 * Suspicious / modified client detection — passive analysis only.
 *
 * AUTHORIZATION BOUNDARY (enforced by construction):
 *   This detector reads *only* telemetry the platform already delivers to us —
 *   declared client version, declared platform, the shape and ordering of
 *   requests we received, and our own count of malformed requests. It performs
 *   no probing, fingerprinting callbacks, exploitation, or any outbound contact
 *   with the suspected client. There is deliberately no code path here that
 *   sends anything anywhere.
 *
 * A finding means "this traffic is inconsistent with the official client" — it
 * is an input to moderator judgement, never proof, and never an automatic ban.
 */

import type { ClientConfig } from '../config/detection-config.ts';
import type { ClientRiskAssessment, DetectionSignal, SignalCode } from '../types/detection.ts';
import type { TalkinEvent, WindowEntry } from '../types/events.ts';
import { clamp, round, saturate } from '../util/stats.ts';

export const CLIENT_DETECTOR = 'client-integrity@1.1.0';

export interface ClientInput {
  event: TalkinEvent;
  window: readonly WindowEntry[];
  config: ClientConfig;
  nowMs: number;
  /** Count of malformed requests attributed to this user by the API layer. */
  malformedRequestCount?: number;
  /** Observed requests per minute for this user, measured at the edge. */
  observedRequestsPerMinute?: number;
  /**
   * Result of official platform client attestation, when the integration
   * provides it. `undefined` means the capability is not available — absence is
   * never treated as failure.
   */
  attestation?: { verified: boolean; detail?: string };
  /** Whether the platform integration grants attestation at all. */
  attestationAvailable?: boolean;
}

export function assessClient(input: ClientInput): ClientRiskAssessment {
  const { event, config, nowMs } = input;
  const signals: DetectionSignal[] = [];
  const indicators: string[] = [];

  const telemetryCount = input.window.length + 1;

  // Not enough signal to make any claim — say so rather than guess.
  if (telemetryCount < config.minTelemetryEvents && input.attestation === undefined) {
    return {
      clientRisk: 0,
      indicators: [],
      confidence: 0,
      signals: [],
      insufficientTelemetry: true,
      note: `Insufficient authorized telemetry: ${telemetryCount} event(s) observed, ${config.minTelemetryEvents} required before a client-integrity judgement is made.`,
    };
  }

  const add = (
    code: SignalCode,
    severity: DetectionSignal['severity'],
    confidence: number,
    reason: string,
    details?: Record<string, string | number | boolean>,
  ): void => {
    indicators.push(code);
    signals.push({
      code,
      category: 'CLIENT',
      severity,
      confidence: round(clamp(confidence, 0, 1), 4),
      reason,
      evidenceEventIds: [event.eventId],
      detector: CLIENT_DETECTOR,
      observedAtMs: nowMs,
      ...(details ? { details } : {}),
    });
  };

  // --- Version plausibility ---------------------------------------------
  const versionRe = new RegExp(config.versionPattern, 'u');
  if (event.clientVersion === undefined || event.clientVersion.length === 0) {
    if (config.knownVersions.length > 0) {
      add(
        'CLIENT_UNKNOWN_VERSION',
        'LOW',
        0.45,
        'Event arrived with no client version while this deployment expects official builds to declare one.',
      );
    }
  } else if (!versionRe.test(event.clientVersion)) {
    add(
      'CLIENT_UNKNOWN_VERSION',
      'MEDIUM',
      0.75,
      `Declared client version "${sanitizeVersion(event.clientVersion)}" does not match the expected official version format.`,
      { declaredVersion: sanitizeVersion(event.clientVersion) },
    );
  } else if (
    config.knownVersions.length > 0 &&
    !config.knownVersions.includes(event.clientVersion)
  ) {
    add(
      'CLIENT_UNKNOWN_VERSION',
      'LOW',
      0.55,
      `Declared client version "${sanitizeVersion(event.clientVersion)}" is not in the configured list of known official releases.`,
      { declaredVersion: sanitizeVersion(event.clientVersion) },
    );
  }

  // --- Version flapping --------------------------------------------------
  const flapWindow = input.window.filter((e) => nowMs - e.atMs <= config.versionFlapWindowMs);
  const versions = new Set(
    [...flapWindow.map((e) => e.clientVersion), event.clientVersion].filter(
      (v): v is string => typeof v === 'string' && v.length > 0,
    ),
  );
  if (versions.size >= config.versionFlapCount) {
    add(
      'CLIENT_VERSION_FLAPPING',
      'MEDIUM',
      0.7 + 0.2 * saturate(versions.size, config.versionFlapCount, config.versionFlapCount * 2),
      `${versions.size} different client versions declared by the same account within ${Math.round(config.versionFlapWindowMs / 60_000)} minutes — a genuine client does not change version mid-session.`,
      { distinctVersions: versions.size },
    );
  }

  // --- Platform consistency ---------------------------------------------
  const platforms = new Set(
    [...flapWindow.map((e) => e.platform), event.platform].filter(
      (p): p is NonNullable<typeof p> => p !== undefined && p !== 'unknown',
    ),
  );
  if (platforms.size > 1) {
    add(
      'CLIENT_PLATFORM_MISMATCH',
      'MEDIUM',
      0.65,
      `Account reported ${platforms.size} different platforms (${[...platforms].join(', ')}) within the same short window.`,
      { distinctPlatforms: platforms.size },
    );
  } else if (event.platform === 'unknown' && config.knownVersions.length > 0) {
    add(
      'CLIENT_PLATFORM_MISMATCH',
      'LOW',
      0.4,
      'Event declared an unrecognised platform value.',
    );
  }

  // --- Impossible event sequences ---------------------------------------
  const sequenceFinding = findImpossibleSequence(event, input.window);
  if (sequenceFinding) {
    add('CLIENT_IMPOSSIBLE_SEQUENCE', 'HIGH', 0.85, sequenceFinding.reason, sequenceFinding.details);
  }

  // --- Malformed requests ------------------------------------------------
  const malformed = input.malformedRequestCount ?? 0;
  if (malformed >= config.malformedCount) {
    add(
      'CLIENT_MALFORMED_REQUESTS',
      'MEDIUM',
      0.7 + 0.2 * saturate(malformed, config.malformedCount, config.malformedCount * 4),
      `${malformed} malformed or schema-invalid requests from this account within ${Math.round(config.malformedWindowMs / 60_000)} minutes — the official client does not emit invalid payloads.`,
      { malformedCount: malformed },
    );
  }

  // --- Abnormal request rate --------------------------------------------
  const rpm = input.observedRequestsPerMinute ?? 0;
  if (rpm > config.abnormalRequestsPerMinute) {
    add(
      'CLIENT_ABNORMAL_REQUEST_RATE',
      'HIGH',
      0.75,
      `${Math.round(rpm)} API requests per minute, above the configured ceiling of ${config.abnormalRequestsPerMinute} — consistent with an automated or modified client.`,
      { requestsPerMinute: Math.round(rpm), ceiling: config.abnormalRequestsPerMinute },
    );
  }

  // --- Official attestation ---------------------------------------------
  if (input.attestation !== undefined && !input.attestation.verified) {
    add(
      'CLIENT_ATTESTATION_FAILED',
      'HIGH',
      0.9,
      `Official platform client attestation failed${input.attestation.detail ? `: ${input.attestation.detail}` : '.'}`,
    );
  }

  // --- Score -------------------------------------------------------------
  let clientRisk = 0;
  for (const s of signals) {
    const weight = config.indicatorWeights[s.code] ?? 10;
    clientRisk += weight * s.confidence;
  }
  clientRisk = Math.round(clamp(clientRisk, 0, 100));

  // Confidence reflects how much telemetry backed the judgement, and whether
  // authoritative attestation was available.
  const telemetryConfidence = saturate(telemetryCount, config.minTelemetryEvents, config.minTelemetryEvents * 8);
  const attestationBoost = input.attestation !== undefined ? 0.35 : 0;
  const confidence = round(clamp(0.25 + 0.5 * telemetryConfidence + attestationBoost, 0, 1), 4);

  const assessment: ClientRiskAssessment = {
    clientRisk,
    indicators,
    confidence,
    signals,
  };

  if (input.attestationAvailable === false) {
    assessment.note =
      'Official client attestation is not available from this integration; findings are based on behavioural telemetry only and are indicative, not conclusive.';
  }

  return assessment;
}

interface SequenceFinding {
  reason: string;
  details: Record<string, string | number | boolean>;
}

/**
 * Event orderings the official client cannot produce.
 *
 * Kept narrow on purpose: out-of-order delivery is normal in distributed
 * systems, so only orderings that cannot be explained by transport reordering
 * are reported.
 */
function findImpossibleSequence(
  event: TalkinEvent,
  window: readonly WindowEntry[],
): SequenceFinding | undefined {
  const sameRoom = window
    .filter((e) => e.roomId === event.roomId)
    .sort((a, b) => a.atMs - b.atMs);

  const lastLifecycle = [...sameRoom].reverse().find((e) => e.eventType === 'join' || e.eventType === 'leave');

  // Speaking or messaging in a room the account has explicitly left, with a
  // margin well beyond plausible transport reordering.
  if (
    (event.eventType === 'message' || event.eventType === 'voice') &&
    lastLifecycle?.eventType === 'leave'
  ) {
    const gap = event.receivedAtMs - lastLifecycle.atMs;
    if (gap > 5_000) {
      return {
        reason: `A ${event.eventType} event was received ${Math.round(gap / 1000)}s after this account left room ${event.roomId}, with no intervening join. The official client cannot send into a room it has left.`,
        details: { gapSeconds: Math.round(gap / 1000), roomId: event.roomId },
      };
    }
  }

  // Duplicate join without an intervening leave, sustained over time.
  if (event.eventType === 'join' && lastLifecycle?.eventType === 'join') {
    const gap = event.receivedAtMs - lastLifecycle.atMs;
    if (gap > 10_000) {
      return {
        reason: `Two join events for room ${event.roomId} ${Math.round(gap / 1000)}s apart with no leave in between — inconsistent with official client lifecycle.`,
        details: { gapSeconds: Math.round(gap / 1000), roomId: event.roomId },
      };
    }
  }

  // Concurrent presence in multiple rooms is impossible for a voice client.
  const activeRooms = new Set<string>();
  for (const e of window) {
    if (event.receivedAtMs - e.atMs > 30_000) continue;
    if (e.eventType === 'voice') activeRooms.add(e.roomId);
  }
  if (event.eventType === 'voice') activeRooms.add(event.roomId);
  if (activeRooms.size > 1) {
    return {
      reason: `Voice activity in ${activeRooms.size} rooms simultaneously (${[...activeRooms].join(', ')}) — a single official client can only occupy one voice room at a time.`,
      details: { concurrentRooms: activeRooms.size },
    };
  }

  return undefined;
}

/** Bound and strip a client-declared version before it reaches a log or UI. */
function sanitizeVersion(version: string): string {
  return version.replace(/[^\w.+-]/gu, '').slice(0, 32);
}
