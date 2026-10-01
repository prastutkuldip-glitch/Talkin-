/**
 * Cross-account coordination detection (brigading / botnet behaviour).
 *
 * Reports that several accounts are behaving identically. It deliberately does
 * NOT assert that those accounts belong to one person: that is an identity
 * inference requiring data we neither have nor should collect. The output is a
 * behavioural correlation for a moderator to interpret.
 *
 * Operates on room-scoped aggregates, never on device identifiers, IP
 * addresses, or any cross-account personal data.
 */

import type { SpamConfig } from '../config/detection-config.ts';
import type { DetectionSignal } from '../types/detection.ts';
import { clamp, coefficientOfVariation, deltas, round, saturate } from '../util/stats.ts';
import { fingerprint } from '../util/text.ts';

export const COORDINATION_DETECTOR = 'coordination-detector@1.0.0';

/** One account's recent contribution within a single room. */
export interface RoomParticipantSample {
  userId: string;
  /** Normalized message fingerprints, newest last. */
  fingerprints: readonly string[];
  /** Epoch ms of join events within the window. */
  joinTimesMs: readonly number[];
  /** Epoch ms of message events within the window. */
  messageTimesMs: readonly number[];
}

export interface CoordinationInput {
  roomId: string;
  participants: readonly RoomParticipantSample[];
  config: SpamConfig;
  nowMs: number;
  /** Minimum distinct accounts before a coordination claim is made. */
  minAccounts?: number;
}

export interface CoordinationFinding {
  userIds: string[];
  signals: DetectionSignal[];
}

/**
 * Fold a room's events into one sample per account.
 *
 * Lives here rather than in a service because it is pure, and because both the
 * scheduled production sweep and the local scenario verifier must aggregate
 * identically — otherwise the verifier would not be testing the real behaviour.
 */
export function aggregateParticipants(
  events: ReadonlyArray<{
    userId: string;
    eventType: string;
    receivedAtMs: number;
    message?: string;
  }>,
): RoomParticipantSample[] {
  interface Accumulator {
    userId: string;
    fingerprints: string[];
    joinTimesMs: number[];
    messageTimesMs: number[];
  }

  const byUser = new Map<string, Accumulator>();

  for (const event of events) {
    let sample = byUser.get(event.userId);
    if (sample === undefined) {
      sample = { userId: event.userId, fingerprints: [], joinTimesMs: [], messageTimesMs: [] };
      byUser.set(event.userId, sample);
    }
    if (event.eventType === 'join') sample.joinTimesMs.push(event.receivedAtMs);
    if (event.eventType === 'message' || event.eventType === 'voice') {
      sample.messageTimesMs.push(event.receivedAtMs);
      if (typeof event.message === 'string' && event.message.length > 0) {
        sample.fingerprints.push(fingerprint(event.message));
      }
    }
  }

  return [...byUser.values()];
}

export function detectCoordination(input: CoordinationInput): CoordinationFinding[] {
  const minAccounts = input.minAccounts ?? 3;
  const findings: CoordinationFinding[] = [];

  if (input.participants.length < minAccounts) return findings;

  // --- Identical content across distinct accounts -------------------------
  const byFingerprint = new Map<string, Set<string>>();
  for (const p of input.participants) {
    for (const fp of p.fingerprints) {
      // Short, common phrases ("gg", "same", "gg all well played") are
      // independently produced by different people all the time. Only content
      // long enough to be improbable as a coincidence counts as coordination.
      if (fp.length < input.config.coordinationMinContentLength) continue;
      let set = byFingerprint.get(fp);
      if (!set) {
        set = new Set<string>();
        byFingerprint.set(fp, set);
      }
      set.add(p.userId);
    }
  }

  for (const [fp, users] of byFingerprint) {
    if (users.size < minAccounts) continue;
    const userIds = [...users].sort();
    findings.push({
      userIds,
      signals: [
        {
          code: 'COORDINATED_IDENTICAL_CONTENT',
          category: 'COORDINATION',
          severity: users.size >= minAccounts * 2 ? 'HIGH' : 'MEDIUM',
          confidence: round(
            clamp(0.6 + 0.3 * saturate(users.size, minAccounts, minAccounts * 3), 0, 0.95),
            4,
          ),
          reason: `${users.size} separate accounts posted byte-identical content in room ${input.roomId} within the detection window. Reported as correlated behaviour only — no inference is made that these accounts share an operator.`,
          evidenceEventIds: [],
          detector: COORDINATION_DETECTOR,
          observedAtMs: input.nowMs,
          details: {
            accountCount: users.size,
            roomId: input.roomId,
            contentLength: fp.length,
          },
        },
      ],
    });
  }

  // --- Synchronised joins -------------------------------------------------
  const joinTimes: Array<{ userId: string; atMs: number }> = [];
  for (const p of input.participants) {
    for (const t of p.joinTimesMs) joinTimes.push({ userId: p.userId, atMs: t });
  }
  joinTimes.sort((a, b) => a.atMs - b.atMs);

  // Sliding 10s cluster of joins from distinct accounts.
  const CLUSTER_MS = 10_000;
  for (let i = 0; i < joinTimes.length; i += 1) {
    const start = joinTimes[i];
    if (!start) continue;
    const cluster = joinTimes.filter((j) => j.atMs >= start.atMs && j.atMs - start.atMs <= CLUSTER_MS);
    const distinct = new Set(cluster.map((c) => c.userId));
    if (distinct.size < Math.max(minAccounts, 4)) continue;

    const gaps = deltas(cluster.map((c) => c.atMs));
    const cv = coefficientOfVariation(gaps);
    // Evenly spaced joins indicate scripted entry, not a crowd arriving.
    const scripted = gaps.length >= 3 && cv < 0.25;

    findings.push({
      userIds: [...distinct].sort(),
      signals: [
        {
          code: 'COORDINATED_SYNCHRONIZED_JOINS',
          category: 'COORDINATION',
          severity: scripted ? 'HIGH' : 'MEDIUM',
          confidence: round(clamp(scripted ? 0.8 : 0.55, 0, 1), 4),
          reason: `${distinct.size} accounts joined room ${input.roomId} within ${CLUSTER_MS / 1000}s${scripted ? ` at near-uniform intervals (${round(cv * 100, 1)}% variation), indicating scripted entry` : ''}.`,
          evidenceEventIds: [],
          detector: COORDINATION_DETECTOR,
          observedAtMs: input.nowMs,
          details: {
            accountCount: distinct.size,
            roomId: input.roomId,
            clusterSeconds: CLUSTER_MS / 1000,
            intervalVariation: round(cv, 4),
          },
        },
      ],
    });
    break; // One synchronised-join finding per room per pass is enough.
  }

  return findings;
}
