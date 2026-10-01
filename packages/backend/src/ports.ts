/**
 * Ports (interfaces) for everything the backend needs from the outside world.
 *
 * All application logic depends on these interfaces only. AWS SDK usage is
 * confined to `adapters/aws/*`, and `adapters/memory/*` provides in-memory
 * implementations used by the test suite and local development. That boundary is
 * what allows the API — including authentication, authorization, rate limiting
 * and moderation flows — to be tested exhaustively without AWS.
 */

import type {
  ActionRecord,
  DetectionConfig,
  DetectionSignal,
  DeepPartial,
  EvidenceBundle,
  HiddenPresenceRecord,
  Incident,
  IncidentStatus,
  IntegrationCapabilities,
  ModerationRestriction,
  RiskAssessment,
  TalkinEvent,
  UserWindowState,
} from '@talkinshield/core';

// --- Persistence -----------------------------------------------------------

export interface EventStore {
  /**
   * Persist an event. Returns false when the event id already exists, which
   * makes ingestion idempotent under at-least-once delivery.
   */
  put(event: TalkinEvent, ttlEpochSeconds: number): Promise<boolean>;
  getByUser(userId: string, limit: number): Promise<TalkinEvent[]>;
  getByRoom(roomId: string, limit: number): Promise<TalkinEvent[]>;
  listRecent(limit: number): Promise<TalkinEvent[]>;
  getByIds(eventIds: readonly string[]): Promise<TalkinEvent[]>;
}

export interface UserStateStore {
  get(userId: string): Promise<UserWindowState | undefined>;
  /**
   * Conditional write on an optimistic-concurrency version. Returns false on
   * conflict so the caller can retry rather than silently lose an update.
   */
  put(state: UserWindowState, expectedVersion: number | undefined): Promise<boolean>;
  getVersion(userId: string): Promise<number | undefined>;
  listHighRisk(limit: number): Promise<UserRiskSummary[]>;
  /** Record the latest assessment for dashboard queries. */
  recordAssessment(assessment: RiskAssessment): Promise<void>;
  getAssessment(userId: string): Promise<RiskAssessment | undefined>;
}

export interface UserRiskSummary {
  userId: string;
  riskScore: number;
  riskLevel: string;
  lastSeenAtMs: number;
  roomId?: string;
  openIncidents: number;
}

export interface SignalStore {
  putMany(userId: string, signals: readonly DetectionSignal[], ttlEpochSeconds: number): Promise<void>;
  getByUser(userId: string, limit: number): Promise<DetectionSignal[]>;
  listRecent(limit: number): Promise<Array<DetectionSignal & { userId: string }>>;
}

export interface IncidentStore extends OpenIncidentLookup {
  put(incident: Incident): Promise<void>;
  get(incidentId: string): Promise<Incident | undefined>;
  list(filter: IncidentFilter): Promise<Incident[]>;
  updateStatus(
    incidentId: string,
    status: IncidentStatus,
    reviewedBy: string,
    reviewNote: string,
    nowMs: number,
  ): Promise<Incident | undefined>;
  appendAction(incidentId: string, action: ActionRecord): Promise<void>;
  appendEvidenceKey(incidentId: string, key: string): Promise<void>;
  countOpenByUser(userId: string): Promise<number>;
}

export interface IncidentFilter {
  status?: IncidentStatus;
  userId?: string;
  roomId?: string;
  sinceMs?: number;
  limit: number;
}

/** Most recent reusable incident for an account, for deduplication. */
export interface OpenIncidentLookup {
  findReusable(userId: string, roomId: string | undefined, sinceMs: number): Promise<Incident | undefined>;
}

export interface ActionStore {
  put(action: ActionRecord): Promise<void>;
  listByUser(userId: string, limit: number): Promise<ActionRecord[]>;
  listRecent(limit: number): Promise<ActionRecord[]>;
}

/**
 * Append-only audit log. Implementations must not expose an update or delete
 * operation — the only permitted mutation is appending a new entry.
 */
export interface AuditStore {
  append(entry: AuditEntry): Promise<void>;
  list(filter: { sinceMs?: number; actorId?: string; limit: number }): Promise<AuditEntry[]>;
}

export interface AuditEntry {
  auditId: string;
  atMs: number;
  /** Cognito subject, or `system`. */
  actorId: string;
  actorKind: 'SYSTEM' | 'MODERATOR';
  action: string;
  /** What the action applied to (user id, incident id, config key). */
  target: string;
  /** Mandatory, non-empty. */
  reason: string;
  outcome: 'SUCCESS' | 'FAILURE' | 'DENIED';
  /** Non-sensitive detail. Never request bodies or tokens. */
  detail?: Record<string, string | number | boolean>;
  sourceIp?: string;
  ttlEpochSeconds?: number;
}

export interface RulesStore {
  /** Current operator config patch, merged over defaults by the caller. */
  getPatch(): Promise<{ patch: DeepPartial<DetectionConfig>; version: string } | undefined>;
  savePatch(patch: DeepPartial<DetectionConfig>, version: string, actorId: string): Promise<void>;
}

export interface EvidenceStore {
  /**
   * Write a bundle. Implementations must use server-side encryption and must
   * not permit overwriting an existing key.
   */
  put(bundle: EvidenceBundle): Promise<{ key: string; versionId?: string }>;
  get(key: string): Promise<EvidenceBundle | undefined>;
  listByIncident(incidentId: string): Promise<string[]>;
  /** Head of the hash chain, for linking the next bundle. */
  getChainHead(): Promise<{ contentHash: string; sequence: number } | undefined>;
  setChainHead(contentHash: string, sequence: number): Promise<void>;
  /** Delete under a retention policy only. Records an audit entry. */
  deleteForRetention(key: string): Promise<boolean>;
}

// --- Rate limiting ---------------------------------------------------------

export interface RateLimiter {
  /**
   * Consume one unit from `key`'s budget.
   * Returns allowed=false with retryAfterSeconds when the budget is exhausted.
   */
  consume(
    key: string,
    limit: number,
    windowSeconds: number,
    nowMs: number,
  ): Promise<{ allowed: boolean; remaining: number; retryAfterSeconds: number }>;
  /** Count of malformed requests recorded for a subject, for client scoring. */
  countMalformed(key: string, windowSeconds: number, nowMs: number): Promise<number>;
  recordMalformed(key: string, nowMs: number): Promise<void>;
  /** Observed request rate for a subject, used by the client detector. */
  observedRequestsPerMinute(key: string, nowMs: number): Promise<number>;
}

// --- AI classification -----------------------------------------------------

export interface TextClassifier {
  /** Returns undefined when disabled or unavailable — never throws upward. */
  classify(text: string, context: { isTranscript: boolean }): Promise<
    | {
        classification: 'SAFE' | 'ABUSIVE' | 'SEVERE_ABUSE' | 'THREAT' | 'UNCERTAIN';
        confidence: number;
        reason: string;
        modelVersion: string;
      }
    | undefined
  >;
  readonly enabled: boolean;
}

// --- Transcription ---------------------------------------------------------

export interface Transcriber {
  readonly enabled: boolean;
  /**
   * Start transcription for audio the operator is authorized to process.
   * Implementations must refuse when `consentRecorded` is false.
   */
  startJob(input: {
    audioUri: string;
    userId: string;
    roomId: string;
    consentRecorded: boolean;
  }): Promise<{ jobName: string } | { refused: string }>;
}

// --- Eventing & alerting ---------------------------------------------------

export interface EventPublisher {
  publish(detailType: string, detail: Record<string, unknown>): Promise<void>;
  publishMany(entries: ReadonlyArray<{ detailType: string; detail: Record<string, unknown> }>): Promise<void>;
}

export interface Notifier {
  send(alert: {
    subject: string;
    body: string;
    level: string;
    dedupeKey: string;
  }): Promise<{ sent: boolean; suppressed?: boolean }>;
}

// --- Platform integration --------------------------------------------------

/**
 * The official Talkin integration.
 *
 * Every method that affects another account returns an explicit
 * `unsupported` result when the capability is not granted. There is no code
 * path that attempts the action by unofficial means.
 */
export interface TalkinPlatformAdapter {
  readonly name: string;
  capabilities(): IntegrationCapabilities;

  /** Restrictions the platform reports as in force for an account. */
  getRestrictions(userId: string, roomId?: string): Promise<readonly ModerationRestriction[]>;

  /** Hidden-presence records, only when `hiddenPresenceEvents` is granted. */
  getHiddenPresence(roomId: string, sinceMs: number): Promise<readonly HiddenPresenceRecord[]>;

  /** Official client attestation, only when `clientAttestation` is granted. */
  verifyClient(
    userId: string,
    clientVersion: string | undefined,
  ): Promise<{ verified: boolean; detail?: string } | undefined>;

  /** Server-side mute via the official API. */
  mute(input: {
    userId: string;
    roomId: string;
    durationSeconds: number;
    reason: string;
  }): Promise<PlatformActionResult>;

  /** Reversible server-side block via the official API. */
  block(input: {
    userId: string;
    roomId?: string;
    durationSeconds: number;
    reason: string;
  }): Promise<PlatformActionResult>;

  /** Submit a report through the official reporting channel. */
  report(input: {
    userId: string;
    roomId?: string;
    reason: string;
    evidenceKeys: readonly string[];
  }): Promise<PlatformActionResult>;
}

export type PlatformActionResult =
  | { ok: true; reference?: string }
  | { ok: false; unsupported: true; reason: string }
  | { ok: false; unsupported: false; reason: string };

// --- Retention -------------------------------------------------------------

/**
 * Retention windows in days, shared by every service that writes TTL-bearing
 * records. Declared once so the services cannot disagree about the shape.
 */
export interface RetentionDays {
  rawEvents: number;
  signals: number;
}

// --- Observability ---------------------------------------------------------

export interface Logger {
  debug(message: string, fields?: Record<string, unknown>): void;
  info(message: string, fields?: Record<string, unknown>): void;
  warn(message: string, fields?: Record<string, unknown>): void;
  error(message: string, fields?: Record<string, unknown>): void;
  child(fields: Record<string, unknown>): Logger;
}

export interface Metrics {
  count(name: string, value?: number, dimensions?: Record<string, string>): void;
  gauge(name: string, value: number, dimensions?: Record<string, string>): void;
}

export interface Clock {
  now(): number;
}

// --- Secrets ---------------------------------------------------------------

export interface SecretProvider {
  /** Returns undefined when the secret is not configured. */
  get(name: string): Promise<string | undefined>;
}
