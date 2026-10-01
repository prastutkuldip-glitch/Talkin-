/**
 * Moderation-evasion detection.
 *
 * Correlates platform-reported moderation events (mutes, kicks, bans) with
 * subsequent authorized activity from the same account. Detects the two most
 * common evasion shapes: continuing to act after a restriction, and
 * leave/rejoin cycling to reset room-scoped state.
 *
 * Scope note: this detects evasion *by the same account identifier*. Linking
 * separate accounts to one person is an identity inference we deliberately do
 * not perform — see `coordination.ts`, which reports behavioural similarity
 * between accounts without asserting they are the same human.
 */

import type { EvasionConfig } from '../config/detection-config.ts';
import type { DetectionSignal } from '../types/detection.ts';
import type { TalkinEvent, WindowEntry } from '../types/events.ts';
import { clamp, round, saturate } from '../util/stats.ts';

export const EVASION_DETECTOR = 'evasion-detector@1.0.0';

export interface ModerationRestriction {
  /** Epoch ms the platform applied the restriction. */
  appliedAtMs: number;
  kind: 'MUTE' | 'KICK' | 'BAN' | 'SUSPEND' | 'UNKNOWN';
  roomId?: string;
  /** Epoch ms the restriction expires, when the platform reports it. */
  expiresAtMs?: number;
}

export interface EvasionInput {
  event: TalkinEvent;
  window: readonly WindowEntry[];
  config: EvasionConfig;
  nowMs: number;
  /**
   * Restrictions reported by the platform integration. Empty when the
   * `moderationEvents` capability is not granted — in which case no evasion
   * claim is made at all.
   */
  restrictions: readonly ModerationRestriction[];
  /** Whether the integration delivers platform moderation events. */
  moderationEventsAvailable: boolean;
}

export interface EvasionResult {
  signals: DetectionSignal[];
  /** Set when the capability needed to judge evasion is missing. */
  insufficientTelemetry: boolean;
  note?: string;
}

export function detectEvasion(input: EvasionInput): EvasionResult {
  const { event, config, nowMs } = input;

  if (!input.moderationEventsAvailable) {
    return {
      signals: [],
      insufficientTelemetry: true,
      note:
        'Insufficient authorized telemetry: this integration does not deliver platform moderation events, ' +
        'so moderation evasion cannot be assessed.',
    };
  }

  const signals: DetectionSignal[] = [];

  // --- Activity after a restriction --------------------------------------
  const isActivity = event.eventType === 'message' || event.eventType === 'voice';
  if (isActivity) {
    for (const restriction of input.restrictions) {
      // Only restrictions that were still in force when the event arrived.
      const stillActive =
        restriction.expiresAtMs === undefined || event.receivedAtMs < restriction.expiresAtMs;
      const withinWindow = event.receivedAtMs - restriction.appliedAtMs <= config.postModerationWindowMs;
      const sameScope = restriction.roomId === undefined || restriction.roomId === event.roomId;

      if (
        stillActive &&
        withinWindow &&
        sameScope &&
        event.receivedAtMs > restriction.appliedAtMs
      ) {
        const seconds = Math.round((event.receivedAtMs - restriction.appliedAtMs) / 1000);
        signals.push({
          code: 'EVASION_POST_MODERATION_ACTIVITY',
          category: 'EVASION',
          severity: 'HIGH',
          confidence: 0.85,
          reason: `Account produced a ${event.eventType} event ${seconds}s after a platform ${restriction.kind} was applied${restriction.roomId ? ` in room ${restriction.roomId}` : ''}, while that restriction was still in force.`,
          evidenceEventIds: [event.eventId],
          detector: EVASION_DETECTOR,
          observedAtMs: nowMs,
          details: {
            restrictionKind: restriction.kind,
            secondsAfterRestriction: seconds,
            roomId: event.roomId,
          },
        });
        break;
      }
    }
  }

  // --- Rejoin cycling ----------------------------------------------------
  const recent = input.window.filter((e) => nowMs - e.atMs <= config.rejoinWindowMs);
  const joins = recent.filter((e) => e.eventType === 'join' && e.roomId === event.roomId).length +
    (event.eventType === 'join' && event.roomId ? 1 : 0);
  const leaves = recent.filter((e) => e.eventType === 'leave' && e.roomId === event.roomId).length;
  const cycles = Math.min(joins, leaves);

  if (cycles >= config.rejoinCount) {
    signals.push({
      code: 'EVASION_REJOIN_CYCLING',
      category: 'EVASION',
      severity: 'MEDIUM',
      confidence: round(
        clamp(0.65 + 0.25 * saturate(cycles, config.rejoinCount, config.rejoinCount * 3), 0, 1),
        4,
      ),
      reason: `${cycles} leave/rejoin cycles in room ${event.roomId} within ${Math.round(config.rejoinWindowMs / 60_000)} minutes — a pattern used to reset room-scoped moderation state.`,
      evidenceEventIds: [event.eventId, ...recent.slice(-10).map((e) => e.eventId)],
      detector: EVASION_DETECTOR,
      observedAtMs: nowMs,
      details: { cycles, roomId: event.roomId },
    });
  }

  return { signals, insufficientTelemetry: false };
}
