/**
 * Canonical event shapes accepted by the TalkinShield ingestion API.
 *
 * Everything here describes telemetry the operator is *authorized* to receive
 * from the Talkin platform (first-party server-side integration, official
 * moderation webhooks, or the operator's own client SDK). Nothing in this
 * module implies the ability to observe traffic the operator cannot lawfully
 * access.
 */

export const EVENT_TYPES = ['message', 'voice', 'join', 'leave', 'moderation'] as const;
export type EventType = (typeof EVENT_TYPES)[number];

export const PLATFORMS = ['ios', 'android', 'web', 'desktop', 'unknown'] as const;
export type Platform = (typeof PLATFORMS)[number];

/** Raw, untrusted payload as it arrives on the wire. */
export interface RawTalkinEvent {
  userId?: unknown;
  roomId?: unknown;
  timestamp?: unknown;
  eventType?: unknown;
  message?: unknown;
  clientVersion?: unknown;
  platform?: unknown;
  metadata?: unknown;
  eventId?: unknown;
}

/**
 * A validated, normalized event. Produced only by `validateEvent`; the rest of
 * the system may assume every field has already been checked and sanitized.
 */
export interface TalkinEvent {
  /** Server-assigned, deterministic for a given payload (dedupe-friendly). */
  eventId: string;
  /** Pseudonymous account identifier supplied by the platform. */
  userId: string;
  roomId: string;
  /** ISO-8601 UTC. */
  timestamp: string;
  /** Epoch milliseconds, derived from `timestamp`. */
  receivedAtMs: number;
  eventType: EventType;
  /** Present for `message` events, and for `voice` events after transcription. */
  message?: string;
  /** True when `message` holds a machine transcript rather than typed text. */
  messageIsTranscript?: boolean;
  clientVersion?: string;
  platform: Platform;
  /** Operator-supplied, sanitized key/value metadata. */
  metadata: Record<string, string | number | boolean>;
}

/** A moderation event reported *by the platform* (not an action we took). */
export interface PlatformModerationEvent extends TalkinEvent {
  eventType: 'moderation';
}

/**
 * Per-user rolling state used by the stateful detectors. Persisted in DynamoDB
 * and reconstructed per analysis pass; deliberately bounded in size so it can
 * never grow without limit.
 */
export interface UserWindowState {
  userId: string;
  /** Most recent events, newest last, capped at `maxWindowEvents`. */
  recent: WindowEntry[];
  /**
   * Fingerprints of messages previously classified as abusive, newest last and
   * bounded by `MAX_ABUSIVE_FINGERPRINTS`.
   *
   * Required for the abuse-repetition layer: "has this account been abusive
   * before, recently?" cannot be answered from a single event. Only
   * fingerprints are kept, never the message text.
   */
  abusiveFingerprints: string[];
  /** Count of confirmed prior violations (decayed by the risk engine). */
  priorViolations: number;
  /** Count of detected moderation-evasion episodes. */
  evasionCount: number;
  /** Epoch ms of the last recorded violation, if any. */
  lastViolationAtMs?: number;
  /** Rolling risk carried between analysis passes (0-100). */
  carriedRisk: number;
}

/** Compact record of a single past event, retained only for detection windows. */
export interface WindowEntry {
  eventId: string;
  atMs: number;
  eventType: EventType;
  roomId: string;
  /** Normalized-text fingerprint; the raw message is not kept in the window. */
  fingerprint?: string;
  /** Number of @mentions in the message. */
  mentions?: number;
  clientVersion?: string;
  platform?: Platform;
}

/** Hard cap on retained abusive fingerprints per account. */
export const MAX_ABUSIVE_FINGERPRINTS = 50;

export function isEventType(value: unknown): value is EventType {
  return typeof value === 'string' && (EVENT_TYPES as readonly string[]).includes(value);
}

export function isPlatform(value: unknown): value is Platform {
  return typeof value === 'string' && (PLATFORMS as readonly string[]).includes(value);
}
