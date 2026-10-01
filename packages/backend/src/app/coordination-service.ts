/**
 * Room-level coordination sweep.
 *
 * Cross-account correlation cannot be computed from a single event, so it cannot
 * live in the per-event pipeline. This service aggregates recent activity for a
 * room and runs the coordination detector over it. It is invoked on a schedule
 * (see `lambda/coordination.ts`).
 *
 * Boundary note: the aggregate is built only from room-scoped event telemetry we
 * already hold. No device identifier, IP address, or any cross-account personal
 * data is used, and a finding asserts correlated *behaviour* — never that the
 * accounts belong to one person.
 */

import {
  aggregateParticipants,
  detectCoordination,
  type DetectionSignal,
  type SpamConfig,
} from '@talkinshield/core';

import type {
  Clock,
  EventPublisher,
  EventStore,
  Logger,
  Metrics,
  SignalStore,
} from '../ports.ts';

export interface CoordinationDeps {
  events: EventStore;
  signals: SignalStore;
  publisher: EventPublisher;
  logger: Logger;
  metrics: Metrics;
  clock: Clock;
  retentionDays: { signals: number };
}

export interface CoordinationSweepResult {
  roomId: string;
  participantsExamined: number;
  findings: Array<{ userIds: string[]; signals: DetectionSignal[] }>;
}

export async function sweepRoom(
  roomId: string,
  config: SpamConfig,
  windowMs: number,
  deps: CoordinationDeps,
): Promise<CoordinationSweepResult> {
  const nowMs = deps.clock.now();
  const since = nowMs - windowMs;

  const events = (await deps.events.getByRoom(roomId, 500)).filter((e) => e.receivedAtMs >= since);

  const participants = aggregateParticipants(events);
  const findings = detectCoordination({ roomId, participants, config, nowMs });

  const ttl = Math.floor((nowMs + deps.retentionDays.signals * 86_400_000) / 1000);

  for (const finding of findings) {
    // A coordination signal is attributed to every participating account, so it
    // appears on each user's detail page with the same explanation.
    for (const userId of finding.userIds) {
      await deps.signals.putMany(userId, finding.signals, ttl);
    }
    await deps.publisher.publish('CoordinationDetected', {
      roomId,
      userIds: finding.userIds,
      codes: finding.signals.map((s) => s.code),
      reason: finding.signals[0]?.reason ?? '',
      accountCount: finding.userIds.length,
    });
    deps.metrics.count('CoordinationFinding', 1, { code: finding.signals[0]?.code ?? 'unknown' });
  }

  if (findings.length > 0) {
    deps.logger.info('Coordination sweep produced findings.', {
      roomId,
      findings: findings.length,
      participants: participants.length,
    });
  }

  return { roomId, participantsExamined: participants.length, findings };
}

/** Rooms with recent activity, derived from the most recent events. */
export async function activeRooms(deps: CoordinationDeps, limit = 200): Promise<string[]> {
  const recent = await deps.events.listRecent(limit);
  return [...new Set(recent.map((e) => e.roomId))];
}
