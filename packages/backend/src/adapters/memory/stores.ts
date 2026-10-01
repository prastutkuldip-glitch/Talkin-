/**
 * In-memory adapter implementations.
 *
 * Used by the automated test suite and by local development (`VITE_USE_MOCK_API`
 * / `TALKIN_ADAPTER=mock`). They implement the same contracts as the AWS
 * adapters, including the behaviours that matter for correctness: idempotent
 * writes, optimistic concurrency, and an append-only audit log.
 */

import { verifyBundle, type ActionRecord, type DeepPartial, type DetectionConfig, type DetectionSignal, type EvidenceBundle, type Incident, type IncidentStatus, type RiskAssessment, type TalkinEvent, type UserWindowState } from '@talkinshield/core';

import type {
  ActionStore,
  AuditEntry,
  AuditStore,
  Clock,
  EventPublisher,
  EventStore,
  EvidenceStore,
  IncidentFilter,
  IncidentStore,
  Logger,
  Metrics,
  Notifier,
  RateLimiter,
  RulesStore,
  SecretProvider,
  SignalStore,
  TextClassifier,
  Transcriber,
  UserRiskSummary,
  UserStateStore,
} from '../../ports.ts';

export class MemoryEventStore implements EventStore {
  private readonly byId = new Map<string, TalkinEvent>();
  /** Recorded TTLs, so retention behaviour can be asserted in tests. */
  readonly expiry = new Map<string, number>();

  async put(event: TalkinEvent, ttlEpochSeconds: number): Promise<boolean> {
    if (this.byId.has(event.eventId)) return false;
    this.byId.set(event.eventId, event);
    this.expiry.set(event.eventId, ttlEpochSeconds);
    return true;
  }

  async getByUser(userId: string, limit: number): Promise<TalkinEvent[]> {
    return this.sorted()
      .filter((e) => e.userId === userId)
      .slice(-limit);
  }

  async getByRoom(roomId: string, limit: number): Promise<TalkinEvent[]> {
    return this.sorted()
      .filter((e) => e.roomId === roomId)
      .slice(-limit);
  }

  async listRecent(limit: number): Promise<TalkinEvent[]> {
    return this.sorted().slice(-limit).reverse();
  }

  async getByIds(eventIds: readonly string[]): Promise<TalkinEvent[]> {
    return eventIds
      .map((id) => this.byId.get(id))
      .filter((e): e is TalkinEvent => e !== undefined)
      .sort((a, b) => a.receivedAtMs - b.receivedAtMs);
  }

  private sorted(): TalkinEvent[] {
    return [...this.byId.values()].sort((a, b) => a.receivedAtMs - b.receivedAtMs);
  }

  get size(): number {
    return this.byId.size;
  }
}

export class MemoryUserStateStore implements UserStateStore {
  private readonly states = new Map<string, { state: UserWindowState; version: number }>();
  private readonly assessments = new Map<string, RiskAssessment>();
  private readonly incidentCounts = new Map<string, number>();

  async get(userId: string): Promise<UserWindowState | undefined> {
    const entry = this.states.get(userId);
    return entry ? structuredClone(entry.state) : undefined;
  }

  async getVersion(userId: string): Promise<number | undefined> {
    return this.states.get(userId)?.version;
  }

  async put(state: UserWindowState, expectedVersion: number | undefined): Promise<boolean> {
    const existing = this.states.get(state.userId);
    if (existing === undefined) {
      if (expectedVersion !== undefined) return false;
      this.states.set(state.userId, { state: structuredClone(state), version: 1 });
      return true;
    }
    if (existing.version !== expectedVersion) return false;
    this.states.set(state.userId, {
      state: structuredClone(state),
      version: existing.version + 1,
    });
    return true;
  }

  async recordAssessment(assessment: RiskAssessment): Promise<void> {
    this.assessments.set(assessment.userId, structuredClone(assessment));
  }

  async getAssessment(userId: string): Promise<RiskAssessment | undefined> {
    const found = this.assessments.get(userId);
    return found ? structuredClone(found) : undefined;
  }

  async listHighRisk(limit: number): Promise<UserRiskSummary[]> {
    return [...this.assessments.values()]
      .sort((a, b) => b.score - a.score)
      .slice(0, limit)
      .map((a) => ({
        userId: a.userId,
        riskScore: a.score,
        riskLevel: a.level,
        lastSeenAtMs: a.assessedAtMs,
        ...(a.roomId !== undefined ? { roomId: a.roomId } : {}),
        openIncidents: this.incidentCounts.get(a.userId) ?? 0,
      }));
  }

  setOpenIncidentCount(userId: string, count: number): void {
    this.incidentCounts.set(userId, count);
  }
}

export class MemorySignalStore implements SignalStore {
  private readonly all: Array<DetectionSignal & { userId: string }> = [];
  readonly expiry = new Map<string, number>();

  async putMany(
    userId: string,
    signals: readonly DetectionSignal[],
    ttlEpochSeconds: number,
  ): Promise<void> {
    for (const signal of signals) {
      this.all.push({ ...signal, userId });
      this.expiry.set(`${userId}#${signal.code}#${signal.observedAtMs}`, ttlEpochSeconds);
    }
  }

  async getByUser(userId: string, limit: number): Promise<DetectionSignal[]> {
    return this.all
      .filter((s) => s.userId === userId)
      .slice(-limit)
      .reverse();
  }

  async listRecent(limit: number): Promise<Array<DetectionSignal & { userId: string }>> {
    return this.all.slice(-limit).reverse();
  }
}

export class MemoryIncidentStore implements IncidentStore {
  private readonly byId = new Map<string, Incident>();

  async put(incident: Incident): Promise<void> {
    this.byId.set(incident.incidentId, structuredClone(incident));
  }

  async get(incidentId: string): Promise<Incident | undefined> {
    const found = this.byId.get(incidentId);
    return found ? structuredClone(found) : undefined;
  }

  async list(filter: IncidentFilter): Promise<Incident[]> {
    return [...this.byId.values()]
      .filter((i) => filter.status === undefined || i.status === filter.status)
      .filter((i) => filter.userId === undefined || i.userId === filter.userId)
      .filter((i) => filter.roomId === undefined || i.roomId === filter.roomId)
      .filter((i) => filter.sinceMs === undefined || i.createdAtMs >= filter.sinceMs)
      .sort((a, b) => b.createdAtMs - a.createdAtMs)
      .slice(0, filter.limit)
      .map((i) => structuredClone(i));
  }

  async updateStatus(
    incidentId: string,
    status: IncidentStatus,
    reviewedBy: string,
    reviewNote: string,
    nowMs: number,
  ): Promise<Incident | undefined> {
    const incident = this.byId.get(incidentId);
    if (incident === undefined) return undefined;
    incident.status = status;
    incident.reviewedBy = reviewedBy;
    incident.reviewNote = reviewNote;
    incident.updatedAtMs = nowMs;
    return structuredClone(incident);
  }

  async appendAction(incidentId: string, action: ActionRecord): Promise<void> {
    const incident = this.byId.get(incidentId);
    if (incident === undefined) return;
    incident.actionsTaken.push(action);
  }

  async appendEvidenceKey(incidentId: string, key: string): Promise<void> {
    const incident = this.byId.get(incidentId);
    if (incident === undefined) return;
    if (!incident.evidenceKeys.includes(key)) incident.evidenceKeys.push(key);
  }

  async countOpenByUser(userId: string): Promise<number> {
    return [...this.byId.values()].filter((i) => i.userId === userId && i.status === 'OPEN').length;
  }

  async findReusable(
    userId: string,
    roomId: string | undefined,
    sinceMs: number,
  ): Promise<Incident | undefined> {
    const candidates = [...this.byId.values()]
      .filter((i) => i.userId === userId)
      .filter((i) => i.status === 'OPEN' || i.status === 'ACKNOWLEDGED')
      .filter((i) => i.updatedAtMs >= sinceMs)
      .filter((i) => roomId === undefined || i.roomId === undefined || i.roomId === roomId)
      .sort((a, b) => b.updatedAtMs - a.updatedAtMs);
    const found = candidates[0];
    return found ? structuredClone(found) : undefined;
  }
}

export class MemoryActionStore implements ActionStore {
  readonly all: ActionRecord[] = [];

  async put(action: ActionRecord): Promise<void> {
    this.all.push(action);
  }

  async listByUser(userId: string, limit: number): Promise<ActionRecord[]> {
    return this.all
      .filter((a) => a.targetUserId === userId)
      .slice(-limit)
      .reverse();
  }

  async listRecent(limit: number): Promise<ActionRecord[]> {
    return this.all.slice(-limit).reverse();
  }
}

/** Append-only by construction: there is no update or delete method. */
export class MemoryAuditStore implements AuditStore {
  private readonly entries: AuditEntry[] = [];

  async append(entry: AuditEntry): Promise<void> {
    this.entries.push(Object.freeze({ ...entry }));
  }

  async list(filter: { sinceMs?: number; actorId?: string; limit: number }): Promise<AuditEntry[]> {
    return this.entries
      .filter((e) => filter.sinceMs === undefined || e.atMs >= filter.sinceMs)
      .filter((e) => filter.actorId === undefined || e.actorId === filter.actorId)
      .slice(-filter.limit)
      .reverse();
  }

  /** Test helper. */
  get snapshot(): readonly AuditEntry[] {
    return this.entries;
  }
}

export class MemoryRulesStore implements RulesStore {
  private current: { patch: DeepPartial<DetectionConfig>; version: string } | undefined;

  async getPatch(): Promise<{ patch: DeepPartial<DetectionConfig>; version: string } | undefined> {
    return this.current ? structuredClone(this.current) : undefined;
  }

  async savePatch(patch: DeepPartial<DetectionConfig>, version: string): Promise<void> {
    this.current = { patch: structuredClone(patch), version };
  }
}

export class MemoryEvidenceStore implements EvidenceStore {
  private readonly objects = new Map<string, EvidenceBundle>();
  private head: { contentHash: string; sequence: number } | undefined;
  /** Mirrors S3 Object Lock: writes are immutable. */
  readonly overwriteAttempts: string[] = [];

  async put(bundle: EvidenceBundle): Promise<{ key: string; versionId?: string }> {
    if (this.objects.has(bundle.key)) {
      this.overwriteAttempts.push(bundle.key);
      throw new Error(
        `Refusing to overwrite existing evidence object ${bundle.key}: evidence storage is write-once.`,
      );
    }
    this.objects.set(bundle.key, structuredClone(bundle));
    return { key: bundle.key, versionId: `v-${this.objects.size}` };
  }

  async get(key: string): Promise<EvidenceBundle | undefined> {
    const found = this.objects.get(key);
    return found ? structuredClone(found) : undefined;
  }

  async listByIncident(incidentId: string): Promise<string[]> {
    return [...this.objects.values()]
      .filter((b) => b.body.incidentId === incidentId)
      .sort((a, b) => a.sequence - b.sequence)
      .map((b) => b.key);
  }

  async getChainHead(): Promise<{ contentHash: string; sequence: number } | undefined> {
    return this.head ? { ...this.head } : undefined;
  }

  async setChainHead(contentHash: string, sequence: number): Promise<void> {
    this.head = { contentHash, sequence };
  }

  async deleteForRetention(key: string): Promise<boolean> {
    return this.objects.delete(key);
  }

  /** Test helper: verify every stored bundle. */
  verifyAll(): { valid: boolean; problems: string[] } {
    const problems: string[] = [];
    for (const bundle of this.objects.values()) {
      const result = verifyBundle(bundle);
      if (!result.valid) problems.push(`${bundle.key}: ${result.problems.join(' ')}`);
    }
    return { valid: problems.length === 0, problems };
  }

  get size(): number {
    return this.objects.size;
  }
}

/** Fixed-window counter, mirroring the DynamoDB implementation's semantics. */
export class MemoryRateLimiter implements RateLimiter {
  private readonly counters = new Map<string, { windowStart: number; count: number }>();
  private readonly malformed = new Map<string, number[]>();
  private readonly requests = new Map<string, number[]>();

  async consume(
    key: string,
    limit: number,
    windowSeconds: number,
    nowMs: number,
  ): Promise<{ allowed: boolean; remaining: number; retryAfterSeconds: number }> {
    const windowMs = windowSeconds * 1000;
    const windowStart = Math.floor(nowMs / windowMs) * windowMs;
    const entry = this.counters.get(key);

    const timestamps = this.requests.get(key) ?? [];
    timestamps.push(nowMs);
    this.requests.set(
      key,
      timestamps.filter((t) => nowMs - t <= 60_000),
    );

    if (entry === undefined || entry.windowStart !== windowStart) {
      this.counters.set(key, { windowStart, count: 1 });
      return { allowed: true, remaining: limit - 1, retryAfterSeconds: 0 };
    }

    if (entry.count >= limit) {
      const retryAfterSeconds = Math.max(1, Math.ceil((windowStart + windowMs - nowMs) / 1000));
      return { allowed: false, remaining: 0, retryAfterSeconds };
    }

    entry.count += 1;
    return { allowed: true, remaining: limit - entry.count, retryAfterSeconds: 0 };
  }

  async recordMalformed(key: string, nowMs: number): Promise<void> {
    const list = this.malformed.get(key) ?? [];
    list.push(nowMs);
    this.malformed.set(key, list);
  }

  async countMalformed(key: string, windowSeconds: number, nowMs: number): Promise<number> {
    const list = this.malformed.get(key) ?? [];
    return list.filter((t) => nowMs - t <= windowSeconds * 1000).length;
  }

  async observedRequestsPerMinute(key: string, nowMs: number): Promise<number> {
    const list = this.requests.get(key) ?? [];
    return list.filter((t) => nowMs - t <= 60_000).length;
  }
}

export class MemoryEventPublisher implements EventPublisher {
  readonly published: Array<{ detailType: string; detail: Record<string, unknown> }> = [];

  async publish(detailType: string, detail: Record<string, unknown>): Promise<void> {
    this.published.push({ detailType, detail });
  }

  async publishMany(
    entries: ReadonlyArray<{ detailType: string; detail: Record<string, unknown> }>,
  ): Promise<void> {
    this.published.push(...entries);
  }
}

export class MemoryNotifier implements Notifier {
  readonly sent: Array<{ subject: string; body: string; level: string; dedupeKey: string }> = [];
  private readonly recentKeys = new Map<string, number>();
  private readonly clock: Clock;
  private readonly dedupeWindowMs: number;

  constructor(clock: Clock, dedupeWindowMs = 5 * 60 * 1000) {
    this.clock = clock;
    this.dedupeWindowMs = dedupeWindowMs;
  }

  async send(alert: {
    subject: string;
    body: string;
    level: string;
    dedupeKey: string;
  }): Promise<{ sent: boolean; suppressed?: boolean }> {
    const now = this.clock.now();
    const last = this.recentKeys.get(alert.dedupeKey);
    if (last !== undefined && now - last < this.dedupeWindowMs) {
      return { sent: false, suppressed: true };
    }
    this.recentKeys.set(alert.dedupeKey, now);
    this.sent.push(alert);
    return { sent: true };
  }
}

/** Disabled classifier: the default, fully deterministic configuration. */
export class DisabledClassifier implements TextClassifier {
  readonly enabled = false;
  async classify(): Promise<undefined> {
    return undefined;
  }
}

export interface ScriptedVerdict {
  classification: 'SAFE' | 'ABUSIVE' | 'SEVERE_ABUSE' | 'THREAT' | 'UNCERTAIN';
  confidence: number;
  reason: string;
  modelVersion: string;
}

/** Scriptable classifier for tests. */
export class ScriptedClassifier implements TextClassifier {
  readonly enabled = true;
  private readonly verdict: ScriptedVerdict | undefined;
  private readonly shouldThrow: boolean;

  constructor(verdict: ScriptedVerdict | undefined, shouldThrow = false) {
    this.verdict = verdict;
    this.shouldThrow = shouldThrow;
  }

  async classify(): Promise<
    | {
        classification: 'SAFE' | 'ABUSIVE' | 'SEVERE_ABUSE' | 'THREAT' | 'UNCERTAIN';
        confidence: number;
        reason: string;
        modelVersion: string;
      }
    | undefined
  > {
    if (this.shouldThrow) throw new Error('simulated Bedrock failure');
    return this.verdict;
  }
}

export class DisabledTranscriber implements Transcriber {
  readonly enabled = false;
  async startJob(): Promise<{ refused: string }> {
    return {
      refused:
        'Transcription is disabled. No approved, consented audio integration is configured for this deployment.',
    };
  }
}

export class MemorySecretProvider implements SecretProvider {
  private readonly secrets: Record<string, string>;
  constructor(secrets: Record<string, string> = {}) {
    this.secrets = secrets;
  }
  async get(name: string): Promise<string | undefined> {
    return this.secrets[name];
  }
}

export class TestClock implements Clock {
  private current: number;
  constructor(current: number) {
    this.current = current;
  }
  now(): number {
    return this.current;
  }
  advance(ms: number): void {
    this.current += ms;
  }
  set(ms: number): void {
    this.current = ms;
  }
}

export class CollectingLogger implements Logger {
  readonly lines: Array<{ level: string; message: string; fields?: Record<string, unknown> }> = [];
  private readonly context: Record<string, unknown>;

  constructor(context: Record<string, unknown> = {}) {
    this.context = context;
  }

  debug(message: string, fields?: Record<string, unknown>): void {
    this.record('debug', message, fields);
  }
  info(message: string, fields?: Record<string, unknown>): void {
    this.record('info', message, fields);
  }
  warn(message: string, fields?: Record<string, unknown>): void {
    this.record('warn', message, fields);
  }
  error(message: string, fields?: Record<string, unknown>): void {
    this.record('error', message, fields);
  }
  child(fields: Record<string, unknown>): Logger {
    const child = new CollectingLogger({ ...this.context, ...fields });
    // Share the buffer so assertions can inspect everything in one place.
    Object.defineProperty(child, 'lines', { value: this.lines });
    return child;
  }
  private record(level: string, message: string, fields?: Record<string, unknown>): void {
    this.lines.push({ level, message, ...(fields ? { fields: { ...this.context, ...fields } } : {}) });
  }
}

export class CollectingMetrics implements Metrics {
  readonly counts: Array<{ name: string; value: number; dimensions?: Record<string, string> }> = [];
  readonly gauges: Array<{ name: string; value: number; dimensions?: Record<string, string> }> = [];

  count(name: string, value = 1, dimensions?: Record<string, string>): void {
    this.counts.push({ name, value, ...(dimensions ? { dimensions } : {}) });
  }
  gauge(name: string, value: number, dimensions?: Record<string, string>): void {
    this.gauges.push({ name, value, ...(dimensions ? { dimensions } : {}) });
  }
  total(name: string): number {
    return this.counts.filter((c) => c.name === name).reduce((sum, c) => sum + c.value, 0);
  }
}
