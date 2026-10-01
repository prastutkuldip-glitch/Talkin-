/**
 * Deterministic identifier and hashing helpers.
 *
 * Uses `node:crypto` only. This module is imported by the backend and the
 * evidence chain; the frontend imports types only and never pulls this in.
 */

import { createHash, randomUUID } from 'node:crypto';

export function sha256Hex(input: string | Uint8Array): string {
  return createHash('sha256').update(input).digest('hex');
}

/** Stable JSON stringify with sorted keys — required for reproducible hashes. */
export function canonicalJson(value: unknown): string {
  return JSON.stringify(sortValue(value));
}

function sortValue(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortValue);
  if (value === null || typeof value !== 'object') return value;
  const entries = Object.entries(value as Record<string, unknown>)
    .filter(([, v]) => v !== undefined)
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  const out: Record<string, unknown> = {};
  for (const [k, v] of entries) out[k] = sortValue(v);
  return out;
}

export function hashObject(value: unknown): string {
  return sha256Hex(canonicalJson(value));
}

/**
 * Deterministic event id derived from the identifying fields of a payload.
 * Re-delivering the same event (webhook retry, at-least-once queue) therefore
 * produces the same id and is deduplicated rather than double-counted.
 */
export function deriveEventId(parts: {
  userId: string;
  roomId: string;
  timestamp: string;
  eventType: string;
  message?: string;
}): string {
  return sha256Hex(
    canonicalJson({
      userId: parts.userId,
      roomId: parts.roomId,
      timestamp: parts.timestamp,
      eventType: parts.eventType,
      message: parts.message ?? '',
    }),
  ).slice(0, 32);
}

export function newIncidentId(nowMs: number): string {
  const d = new Date(nowMs);
  const stamp = [
    d.getUTCFullYear(),
    String(d.getUTCMonth() + 1).padStart(2, '0'),
    String(d.getUTCDate()).padStart(2, '0'),
  ].join('');
  return `INC-${stamp}-${randomUUID().slice(0, 8).toUpperCase()}`;
}

export function newActionId(): string {
  return `ACT-${randomUUID()}`;
}

export function newAuditId(): string {
  return `AUD-${randomUUID()}`;
}

/**
 * Short, non-reversible display handle for a user id, so operators can discuss
 * a case without the raw platform identifier being splashed across screens.
 * Deterministic for a given (userId, salt) pair.
 */
export function displayHandle(userId: string, salt: string): string {
  return sha256Hex(`${salt}:${userId}`).slice(0, 6).toUpperCase();
}
