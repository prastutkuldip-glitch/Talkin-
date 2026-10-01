/**
 * Hidden / "ghost mode" activity correlation.
 *
 * STRICT AUTHORIZATION BOUNDARY — read this before changing anything here:
 *
 *   This module correlates hidden-presence events that the Talkin platform
 *   *already delivers to us* under the `hiddenPresenceEvents` capability. That
 *   is its only input.
 *
 *   It does NOT, and must never:
 *     - probe or enumerate private APIs to discover concealed users
 *     - bypass or test access controls
 *     - infer hidden identities from timing side channels against users the
 *       platform has chosen not to disclose
 *     - touch another participant's device
 *
 *   When the capability is absent the correct, required behaviour is to report
 *   "Insufficient authorized telemetry." — never to approximate the answer by
 *   other means. There is intentionally no fallback inference path.
 */

import type { GhostConfig } from '../config/detection-config.ts';
import type { DetectionSignal } from '../types/detection.ts';
import type { EventType } from '../types/events.ts';
import { clamp, round, saturate } from '../util/stats.ts';
import { unavailable, authorizedEmpty, authorized, type TelemetryValue } from '../types/telemetry.ts';

export const GHOST_DETECTOR = 'ghost-correlator@1.0.0';

/**
 * A presence record the platform has marked as hidden/invisible. Supplied by
 * the official integration only.
 */
export interface HiddenPresenceRecord {
  /** Account identifier as disclosed by the platform. */
  userId: string;
  roomId: string;
  /** Epoch ms. */
  atMs: number;
  kind: 'HIDDEN_JOIN' | 'HIDDEN_LEAVE' | 'HIDDEN_PRESENT';
  /** Platform's own label for the concealment mode, if provided. */
  mode?: string;
}

/** An observable event used to corroborate hidden presence. */
export interface CorrelatableEvent {
  eventId: string;
  userId: string;
  roomId: string;
  atMs: number;
  eventType: EventType;
}

export interface GhostInput {
  roomId: string;
  config: GhostConfig;
  nowMs: number;
  /** Whether the integration grants hidden-presence events. */
  hiddenPresenceAvailable: boolean;
  /** Hidden presence records delivered by the platform for this room. */
  hiddenPresence: readonly HiddenPresenceRecord[];
  /** Authorized observable events in the same room/window. */
  observedEvents: readonly CorrelatableEvent[];
}

export interface GhostCorrelation {
  userId: string;
  roomId: string;
  /** Observable events that line up with the hidden presence window. */
  correlatedEventIds: string[];
  firstSeenAtMs: number;
  lastSeenAtMs: number;
  mode?: string;
}

export interface GhostResult {
  /**
   * `AUTHORIZED` with findings, `AUTHORIZED_EMPTY` when we were able to look
   * and found nothing, `UNAVAILABLE` when the capability is missing.
   */
  status: TelemetryValue<GhostCorrelation[]>;
  signals: DetectionSignal[];
  /** Exact string the dashboard renders. */
  displayMessage: string;
}

export const INSUFFICIENT_TELEMETRY_MESSAGE = 'Insufficient authorized telemetry.';
export const HIDDEN_ACTIVITY_MESSAGE = 'Potential hidden activity detected';

export function correlateHiddenActivity(input: GhostInput): GhostResult {
  // --- Capability gate: no capability, no claim --------------------------
  if (!input.hiddenPresenceAvailable) {
    return {
      status: unavailable<GhostCorrelation[]>(
        'The connected Talkin integration does not expose hidden/ghost-mode presence events. ' +
          'TalkinShield will not attempt to discover concealed users by any other means.',
      ),
      signals: [],
      displayMessage: INSUFFICIENT_TELEMETRY_MESSAGE,
    };
  }

  if (input.hiddenPresence.length === 0) {
    return {
      status: authorizedEmpty<GhostCorrelation[]>(
        'Hidden-presence telemetry is available and was queried; no hidden presence was reported for this room and window.',
      ),
      signals: [],
      displayMessage: 'No hidden activity reported.',
    };
  }

  const { config } = input;
  const byUser = new Map<string, HiddenPresenceRecord[]>();
  for (const record of input.hiddenPresence) {
    if (record.roomId !== input.roomId) continue;
    const list = byUser.get(record.userId);
    if (list) list.push(record);
    else byUser.set(record.userId, [record]);
  }

  const correlations: GhostCorrelation[] = [];
  const signals: DetectionSignal[] = [];

  for (const [userId, records] of byUser) {
    records.sort((a, b) => a.atMs - b.atMs);
    const first = records[0];
    const last = records[records.length - 1];
    if (!first || !last) continue;

    // Build the concealment interval, tolerating clock skew between the
    // platform's presence feed and our event stream.
    const windowStart = first.atMs - config.correlationToleranceMs;
    const windowEnd =
      (last.kind === 'HIDDEN_LEAVE' ? last.atMs : input.nowMs) + config.correlationToleranceMs;

    const correlated = input.observedEvents.filter(
      (e) =>
        e.roomId === input.roomId &&
        e.userId === userId &&
        e.atMs >= windowStart &&
        e.atMs <= windowEnd,
    );

    if (correlated.length < config.minCorrelatedEvents) continue;

    const correlation: GhostCorrelation = {
      userId,
      roomId: input.roomId,
      correlatedEventIds: correlated.map((e) => e.eventId),
      firstSeenAtMs: first.atMs,
      lastSeenAtMs: last.atMs,
    };
    if (first.mode !== undefined) correlation.mode = first.mode;
    correlations.push(correlation);

    const kinds = [...new Set(correlated.map((e) => e.eventType))].join(', ');
    signals.push({
      code: 'GHOST_HIDDEN_PRESENCE_CORRELATED',
      category: 'GHOST',
      severity: 'LOW',
      confidence: round(
        clamp(
          0.5 + 0.4 * saturate(correlated.length, config.minCorrelatedEvents, config.minCorrelatedEvents * 5),
          0,
          0.95,
        ),
        4,
      ),
      reason: `Platform reported hidden presence for this account in room ${input.roomId}, and ${correlated.length} authorized event(s) (${kinds}) occurred during that concealment window. Correlation is based solely on platform-disclosed presence data.`,
      evidenceEventIds: correlated.map((e) => e.eventId).slice(0, 20),
      detector: GHOST_DETECTOR,
      observedAtMs: input.nowMs,
      details: {
        roomId: input.roomId,
        correlatedEventCount: correlated.length,
        concealmentMode: first.mode ?? 'unspecified',
      },
    });
  }

  if (correlations.length === 0) {
    return {
      status: authorizedEmpty<GhostCorrelation[]>(
        'Hidden presence was reported, but too few corroborating authorized events to correlate.',
      ),
      signals: [],
      displayMessage: 'No hidden activity reported.',
    };
  }

  return {
    status: authorized(correlations),
    signals,
    displayMessage: HIDDEN_ACTIVITY_MESSAGE,
  };
}
