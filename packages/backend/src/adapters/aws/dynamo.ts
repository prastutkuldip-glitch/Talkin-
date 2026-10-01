/**
 * DynamoDB adapters.
 *
 * Table design (see docs/ARCHITECTURE.md for the full schema):
 *   events      PK=userId,  SK=receivedAtMs#eventId   GSI1: roomId / receivedAtMs
 *                                                     GSI2: eventId (point lookup)
 *   user-state  PK=userId
 *   signals     PK=userId,  SK=observedAtMs#code      GSI1: observedAtDay / observedAtMs
 *   incidents   PK=incidentId                         GSI1: status / createdAtMs
 *                                                     GSI2: userId / updatedAtMs
 *   actions     PK=targetUserId, SK=atMs#actionId     GSI1: atMsDay / atMs
 *   audit       PK=auditId                            GSI1: atMsDay / atMs
 *                                                     GSI2: actorId / atMs
 *   rules       PK=configKey (single item)
 *   ratelimit   PK=bucketKey (TTL-expired counters)
 *
 * All tables use on-demand capacity, SSE-KMS with a customer-managed key, and
 * point-in-time recovery. TTL attributes expire raw events, signals and audit
 * entries according to the configured retention policy.
 */

import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import {
  DynamoDBDocumentClient,
  DeleteCommand,
  GetCommand,
  PutCommand,
  QueryCommand,
  ScanCommand,
  UpdateCommand,
} from '@aws-sdk/lib-dynamodb';

import type {
  ActionRecord,
  DeepPartial,
  DetectionConfig,
  DetectionSignal,
  Incident,
  IncidentStatus,
  RiskAssessment,
  TalkinEvent,
  UserWindowState,
} from '@talkinshield/core';

import type {
  ActionStore,
  AuditEntry,
  AuditStore,
  EventStore,
  IncidentFilter,
  IncidentStore,
  RateLimiter,
  RulesStore,
  SignalStore,
  UserRiskSummary,
  UserStateStore,
} from '../../ports.ts';

export interface DynamoTables {
  events: string;
  userState: string;
  incidents: string;
  signals: string;
  actions: string;
  rules: string;
  audit: string;
  rateLimit: string;
}

export function createDocumentClient(region: string): DynamoDBDocumentClient {
  return DynamoDBDocumentClient.from(new DynamoDBClient({ region }), {
    marshallOptions: { removeUndefinedValues: true, convertClassInstanceToMap: false },
  });
}

const dayKey = (ms: number): string => new Date(ms).toISOString().slice(0, 10);
const pad = (n: number): string => String(n).padStart(16, '0');

// --- Events ----------------------------------------------------------------

export class DynamoEventStore implements EventStore {
  private readonly doc: DynamoDBDocumentClient;
  private readonly table: string;

  constructor(doc: DynamoDBDocumentClient, table: string) {
    this.doc = doc;
    this.table = table;
  }

  async put(event: TalkinEvent, ttlEpochSeconds: number): Promise<boolean> {
    try {
      await this.doc.send(
        new PutCommand({
          TableName: this.table,
          Item: {
            userId: event.userId,
            sk: `${pad(event.receivedAtMs)}#${event.eventId}`,
            eventId: event.eventId,
            roomId: event.roomId,
            receivedAtMs: event.receivedAtMs,
            expiresAt: ttlEpochSeconds,
            payload: event,
          },
          // Idempotency: a redelivered event is rejected rather than re-counted.
          ConditionExpression: 'attribute_not_exists(sk)',
        }),
      );
      return true;
    } catch (err: unknown) {
      if (isConditionalCheckFailure(err)) return false;
      throw err;
    }
  }

  async getByUser(userId: string, limit: number): Promise<TalkinEvent[]> {
    const result = await this.doc.send(
      new QueryCommand({
        TableName: this.table,
        KeyConditionExpression: 'userId = :u',
        ExpressionAttributeValues: { ':u': userId },
        Limit: limit,
        ScanIndexForward: false,
      }),
    );
    return unwrap(result.Items).reverse();
  }

  async getByRoom(roomId: string, limit: number): Promise<TalkinEvent[]> {
    const result = await this.doc.send(
      new QueryCommand({
        TableName: this.table,
        IndexName: 'byRoom',
        KeyConditionExpression: 'roomId = :r',
        ExpressionAttributeValues: { ':r': roomId },
        Limit: limit,
        ScanIndexForward: false,
      }),
    );
    return unwrap(result.Items).reverse();
  }

  async listRecent(limit: number): Promise<TalkinEvent[]> {
    // Recent-across-all-users is a dashboard read; `byRoom` is partitioned, so
    // this uses a bounded scan. Acceptable because the events table is TTL-bounded
    // and this endpoint is rate limited and paginated.
    const result = await this.doc.send(
      new ScanCommand({ TableName: this.table, Limit: Math.min(limit * 4, 400) }),
    );
    return unwrap(result.Items)
      .sort((a, b) => b.receivedAtMs - a.receivedAtMs)
      .slice(0, limit);
  }

  async getByIds(eventIds: readonly string[]): Promise<TalkinEvent[]> {
    const found: TalkinEvent[] = [];
    for (const eventId of eventIds.slice(0, 50)) {
      const result = await this.doc.send(
        new QueryCommand({
          TableName: this.table,
          IndexName: 'byEventId',
          KeyConditionExpression: 'eventId = :e',
          ExpressionAttributeValues: { ':e': eventId },
          Limit: 1,
        }),
      );
      found.push(...unwrap(result.Items));
    }
    return found.sort((a, b) => a.receivedAtMs - b.receivedAtMs);
  }
}

function unwrap(items: Record<string, unknown>[] | undefined): TalkinEvent[] {
  if (!items) return [];
  return items
    .map((item) => item.payload as TalkinEvent | undefined)
    .filter((e): e is TalkinEvent => e !== undefined);
}

// --- User state ------------------------------------------------------------

export class DynamoUserStateStore implements UserStateStore {
  private readonly doc: DynamoDBDocumentClient;
  private readonly table: string;

  constructor(doc: DynamoDBDocumentClient, table: string) {
    this.doc = doc;
    this.table = table;
  }

  async get(userId: string): Promise<UserWindowState | undefined> {
    const result = await this.doc.send(
      new GetCommand({ TableName: this.table, Key: { userId }, ConsistentRead: true }),
    );
    return result.Item?.state as UserWindowState | undefined;
  }

  async getVersion(userId: string): Promise<number | undefined> {
    const result = await this.doc.send(
      new GetCommand({
        TableName: this.table,
        Key: { userId },
        ProjectionExpression: 'version',
        ConsistentRead: true,
      }),
    );
    return result.Item?.version as number | undefined;
  }

  /** Optimistic concurrency on `version`, so concurrent events cannot clobber. */
  async put(state: UserWindowState, expectedVersion: number | undefined): Promise<boolean> {
    try {
      await this.doc.send(
        new PutCommand({
          TableName: this.table,
          Item: { userId: state.userId, state, version: (expectedVersion ?? 0) + 1 },
          ...(expectedVersion === undefined
            ? { ConditionExpression: 'attribute_not_exists(userId)' }
            : {
                ConditionExpression: 'version = :v',
                ExpressionAttributeValues: { ':v': expectedVersion },
              }),
        }),
      );
      return true;
    } catch (err: unknown) {
      if (isConditionalCheckFailure(err)) return false;
      throw err;
    }
  }

  async recordAssessment(assessment: RiskAssessment): Promise<void> {
    await this.doc.send(
      new UpdateCommand({
        TableName: this.table,
        Key: { userId: assessment.userId },
        UpdateExpression:
          'SET assessment = :a, riskScore = :s, riskLevel = :l, lastSeenAtMs = :t, riskBucket = :b',
        ExpressionAttributeValues: {
          ':a': assessment,
          ':s': assessment.score,
          ':l': assessment.level,
          ':t': assessment.assessedAtMs,
          // Constant partition key for the risk GSI, so high-risk users can be
          // queried by score instead of scanned.
          ':b': 'ALL',
        },
      }),
    );
  }

  async getAssessment(userId: string): Promise<RiskAssessment | undefined> {
    const result = await this.doc.send(
      new GetCommand({ TableName: this.table, Key: { userId }, ProjectionExpression: 'assessment' }),
    );
    return result.Item?.assessment as RiskAssessment | undefined;
  }

  async listHighRisk(limit: number): Promise<UserRiskSummary[]> {
    const result = await this.doc.send(
      new QueryCommand({
        TableName: this.table,
        IndexName: 'byRisk',
        KeyConditionExpression: 'riskBucket = :b',
        ExpressionAttributeValues: { ':b': 'ALL' },
        Limit: limit,
        ScanIndexForward: false,
      }),
    );
    return (result.Items ?? []).map((item) => ({
      userId: String(item.userId),
      riskScore: Number(item.riskScore ?? 0),
      riskLevel: String(item.riskLevel ?? 'LOW'),
      lastSeenAtMs: Number(item.lastSeenAtMs ?? 0),
      ...(typeof item.roomId === 'string' ? { roomId: item.roomId } : {}),
      openIncidents: Number(item.openIncidents ?? 0),
    }));
  }
}

// --- Signals ---------------------------------------------------------------

export class DynamoSignalStore implements SignalStore {
  private readonly doc: DynamoDBDocumentClient;
  private readonly table: string;

  constructor(doc: DynamoDBDocumentClient, table: string) {
    this.doc = doc;
    this.table = table;
  }

  async putMany(
    userId: string,
    signals: readonly DetectionSignal[],
    ttlEpochSeconds: number,
  ): Promise<void> {
    for (const signal of signals) {
      await this.doc.send(
        new PutCommand({
          TableName: this.table,
          Item: {
            userId,
            sk: `${pad(signal.observedAtMs)}#${signal.code}`,
            day: dayKey(signal.observedAtMs),
            observedAtMs: signal.observedAtMs,
            expiresAt: ttlEpochSeconds,
            signal,
          },
        }),
      );
    }
  }

  async getByUser(userId: string, limit: number): Promise<DetectionSignal[]> {
    const result = await this.doc.send(
      new QueryCommand({
        TableName: this.table,
        KeyConditionExpression: 'userId = :u',
        ExpressionAttributeValues: { ':u': userId },
        Limit: limit,
        ScanIndexForward: false,
      }),
    );
    return (result.Items ?? [])
      .map((i) => i.signal as DetectionSignal | undefined)
      .filter((s): s is DetectionSignal => s !== undefined);
  }

  async listRecent(limit: number): Promise<Array<DetectionSignal & { userId: string }>> {
    // Queried by day partition, newest first — no scan.
    const today = dayKey(Date.now());
    const yesterday = dayKey(Date.now() - 86_400_000);
    const out: Array<DetectionSignal & { userId: string }> = [];

    for (const day of [today, yesterday]) {
      if (out.length >= limit) break;
      const result = await this.doc.send(
        new QueryCommand({
          TableName: this.table,
          IndexName: 'byDay',
          KeyConditionExpression: '#d = :d',
          ExpressionAttributeNames: { '#d': 'day' },
          ExpressionAttributeValues: { ':d': day },
          Limit: limit - out.length,
          ScanIndexForward: false,
        }),
      );
      for (const item of result.Items ?? []) {
        const signal = item.signal as DetectionSignal | undefined;
        if (signal) out.push({ ...signal, userId: String(item.userId) });
      }
    }
    return out;
  }
}

// --- Incidents -------------------------------------------------------------

export class DynamoIncidentStore implements IncidentStore {
  private readonly doc: DynamoDBDocumentClient;
  private readonly table: string;

  constructor(doc: DynamoDBDocumentClient, table: string) {
    this.doc = doc;
    this.table = table;
  }

  async put(incident: Incident): Promise<void> {
    await this.doc.send(
      new PutCommand({
        TableName: this.table,
        Item: {
          incidentId: incident.incidentId,
          userId: incident.userId,
          status: incident.status,
          createdAtMs: incident.createdAtMs,
          updatedAtMs: incident.updatedAtMs,
          incident,
        },
      }),
    );
  }

  async get(incidentId: string): Promise<Incident | undefined> {
    const result = await this.doc.send(
      new GetCommand({ TableName: this.table, Key: { incidentId } }),
    );
    return result.Item?.incident as Incident | undefined;
  }

  async list(filter: IncidentFilter): Promise<Incident[]> {
    if (filter.userId !== undefined) {
      const result = await this.doc.send(
        new QueryCommand({
          TableName: this.table,
          IndexName: 'byUser',
          KeyConditionExpression: 'userId = :u',
          ExpressionAttributeValues: { ':u': filter.userId },
          Limit: filter.limit,
          ScanIndexForward: false,
        }),
      );
      return this.extract(result.Items, filter);
    }

    if (filter.status !== undefined) {
      const result = await this.doc.send(
        new QueryCommand({
          TableName: this.table,
          IndexName: 'byStatus',
          KeyConditionExpression: '#s = :s',
          ExpressionAttributeNames: { '#s': 'status' },
          ExpressionAttributeValues: { ':s': filter.status },
          Limit: filter.limit,
          ScanIndexForward: false,
        }),
      );
      return this.extract(result.Items, filter);
    }

    // Unfiltered recency listing uses the status index across all statuses.
    const collected: Incident[] = [];
    const statuses: IncidentStatus[] = ['OPEN', 'ACKNOWLEDGED', 'ACTIONED', 'CLOSED', 'DISMISSED_FALSE_POSITIVE'];
    for (const status of statuses) {
      const result = await this.doc.send(
        new QueryCommand({
          TableName: this.table,
          IndexName: 'byStatus',
          KeyConditionExpression: '#s = :s',
          ExpressionAttributeNames: { '#s': 'status' },
          ExpressionAttributeValues: { ':s': status },
          Limit: filter.limit,
          ScanIndexForward: false,
        }),
      );
      collected.push(...this.extract(result.Items, filter));
    }
    return collected.sort((a, b) => b.createdAtMs - a.createdAtMs).slice(0, filter.limit);
  }

  private extract(items: Record<string, unknown>[] | undefined, filter: IncidentFilter): Incident[] {
    return (items ?? [])
      .map((i) => i.incident as Incident | undefined)
      .filter((i): i is Incident => i !== undefined)
      .filter((i) => filter.roomId === undefined || i.roomId === filter.roomId)
      .filter((i) => filter.sinceMs === undefined || i.createdAtMs >= filter.sinceMs);
  }

  async updateStatus(
    incidentId: string,
    status: IncidentStatus,
    reviewedBy: string,
    reviewNote: string,
    nowMs: number,
  ): Promise<Incident | undefined> {
    const existing = await this.get(incidentId);
    if (existing === undefined) return undefined;

    existing.status = status;
    existing.reviewedBy = reviewedBy;
    existing.reviewNote = reviewNote;
    existing.updatedAtMs = nowMs;
    await this.put(existing);
    return existing;
  }

  async appendAction(incidentId: string, action: ActionRecord): Promise<void> {
    const existing = await this.get(incidentId);
    if (existing === undefined) return;
    existing.actionsTaken.push(action);
    existing.updatedAtMs = action.atMs;
    await this.put(existing);
  }

  async appendEvidenceKey(incidentId: string, key: string): Promise<void> {
    const existing = await this.get(incidentId);
    if (existing === undefined) return;
    if (!existing.evidenceKeys.includes(key)) existing.evidenceKeys.push(key);
    await this.put(existing);
  }

  async countOpenByUser(userId: string): Promise<number> {
    const result = await this.doc.send(
      new QueryCommand({
        TableName: this.table,
        IndexName: 'byUser',
        KeyConditionExpression: 'userId = :u',
        FilterExpression: '#s = :open',
        ExpressionAttributeNames: { '#s': 'status' },
        ExpressionAttributeValues: { ':u': userId, ':open': 'OPEN' },
        Select: 'COUNT',
      }),
    );
    return result.Count ?? 0;
  }

  async findReusable(
    userId: string,
    roomId: string | undefined,
    sinceMs: number,
  ): Promise<Incident | undefined> {
    const result = await this.doc.send(
      new QueryCommand({
        TableName: this.table,
        IndexName: 'byUser',
        KeyConditionExpression: 'userId = :u AND updatedAtMs >= :since',
        ExpressionAttributeValues: { ':u': userId, ':since': sinceMs },
        Limit: 10,
        ScanIndexForward: false,
      }),
    );
    return (result.Items ?? [])
      .map((i) => i.incident as Incident | undefined)
      .filter((i): i is Incident => i !== undefined)
      .filter((i) => i.status === 'OPEN' || i.status === 'ACKNOWLEDGED')
      .find((i) => roomId === undefined || i.roomId === undefined || i.roomId === roomId);
  }
}

// --- Actions ---------------------------------------------------------------

export class DynamoActionStore implements ActionStore {
  private readonly doc: DynamoDBDocumentClient;
  private readonly table: string;

  constructor(doc: DynamoDBDocumentClient, table: string) {
    this.doc = doc;
    this.table = table;
  }

  async put(action: ActionRecord): Promise<void> {
    await this.doc.send(
      new PutCommand({
        TableName: this.table,
        Item: {
          targetUserId: action.targetUserId,
          sk: `${pad(action.atMs)}#${action.actionId}`,
          day: dayKey(action.atMs),
          atMs: action.atMs,
          action,
        },
      }),
    );
  }

  async listByUser(userId: string, limit: number): Promise<ActionRecord[]> {
    const result = await this.doc.send(
      new QueryCommand({
        TableName: this.table,
        KeyConditionExpression: 'targetUserId = :u',
        ExpressionAttributeValues: { ':u': userId },
        Limit: limit,
        ScanIndexForward: false,
      }),
    );
    return (result.Items ?? [])
      .map((i) => i.action as ActionRecord | undefined)
      .filter((a): a is ActionRecord => a !== undefined);
  }

  async listRecent(limit: number): Promise<ActionRecord[]> {
    const out: ActionRecord[] = [];
    for (const day of [dayKey(Date.now()), dayKey(Date.now() - 86_400_000)]) {
      if (out.length >= limit) break;
      const result = await this.doc.send(
        new QueryCommand({
          TableName: this.table,
          IndexName: 'byDay',
          KeyConditionExpression: '#d = :d',
          ExpressionAttributeNames: { '#d': 'day' },
          ExpressionAttributeValues: { ':d': day },
          Limit: limit - out.length,
          ScanIndexForward: false,
        }),
      );
      for (const item of result.Items ?? []) {
        const action = item.action as ActionRecord | undefined;
        if (action) out.push(action);
      }
    }
    return out;
  }
}

// --- Audit (append-only) ---------------------------------------------------

/**
 * The IAM policy for the application role grants only `dynamodb:PutItem` and
 * `Query` on this table — no `UpdateItem`, no `DeleteItem`. Combined with the
 * absence of a mutate method here, audit history cannot be rewritten by the
 * application even if this code were changed.
 */
export class DynamoAuditStore implements AuditStore {
  private readonly doc: DynamoDBDocumentClient;
  private readonly table: string;

  constructor(doc: DynamoDBDocumentClient, table: string) {
    this.doc = doc;
    this.table = table;
  }

  async append(entry: AuditEntry): Promise<void> {
    await this.doc.send(
      new PutCommand({
        TableName: this.table,
        Item: {
          auditId: entry.auditId,
          day: dayKey(entry.atMs),
          atMs: entry.atMs,
          actorId: entry.actorId,
          ...(entry.ttlEpochSeconds !== undefined ? { expiresAt: entry.ttlEpochSeconds } : {}),
          entry,
        },
        ConditionExpression: 'attribute_not_exists(auditId)',
      }),
    );
  }

  async list(filter: { sinceMs?: number; actorId?: string; limit: number }): Promise<AuditEntry[]> {
    if (filter.actorId !== undefined) {
      const result = await this.doc.send(
        new QueryCommand({
          TableName: this.table,
          IndexName: 'byActor',
          KeyConditionExpression: 'actorId = :a',
          ExpressionAttributeValues: { ':a': filter.actorId },
          Limit: filter.limit,
          ScanIndexForward: false,
        }),
      );
      return extractAudit(result.Items, filter.sinceMs);
    }

    const out: AuditEntry[] = [];
    for (let back = 0; back < 7 && out.length < filter.limit; back += 1) {
      const result = await this.doc.send(
        new QueryCommand({
          TableName: this.table,
          IndexName: 'byDay',
          KeyConditionExpression: '#d = :d',
          ExpressionAttributeNames: { '#d': 'day' },
          ExpressionAttributeValues: { ':d': dayKey(Date.now() - back * 86_400_000) },
          Limit: filter.limit - out.length,
          ScanIndexForward: false,
        }),
      );
      out.push(...extractAudit(result.Items, filter.sinceMs));
    }
    return out.slice(0, filter.limit);
  }
}

function extractAudit(
  items: Record<string, unknown>[] | undefined,
  sinceMs: number | undefined,
): AuditEntry[] {
  return (items ?? [])
    .map((i) => i.entry as AuditEntry | undefined)
    .filter((e): e is AuditEntry => e !== undefined)
    .filter((e) => sinceMs === undefined || e.atMs >= sinceMs);
}

// --- Rules -----------------------------------------------------------------

export class DynamoRulesStore implements RulesStore {
  private readonly doc: DynamoDBDocumentClient;
  private readonly table: string;
  private static readonly KEY = 'detection-config';

  constructor(doc: DynamoDBDocumentClient, table: string) {
    this.doc = doc;
    this.table = table;
  }

  async getPatch(): Promise<{ patch: DeepPartial<DetectionConfig>; version: string } | undefined> {
    const result = await this.doc.send(
      new GetCommand({ TableName: this.table, Key: { configKey: DynamoRulesStore.KEY } }),
    );
    if (result.Item === undefined) return undefined;
    return {
      patch: (result.Item.patch ?? {}) as DeepPartial<DetectionConfig>,
      version: String(result.Item.version ?? 'default'),
    };
  }

  async savePatch(
    patch: DeepPartial<DetectionConfig>,
    version: string,
    actorId: string,
  ): Promise<void> {
    await this.doc.send(
      new PutCommand({
        TableName: this.table,
        Item: {
          configKey: DynamoRulesStore.KEY,
          patch,
          version,
          updatedBy: actorId,
          updatedAtMs: Date.now(),
        },
      }),
    );
    // Previous versions are retained for audit, keyed by version.
    await this.doc.send(
      new PutCommand({
        TableName: this.table,
        Item: {
          configKey: `history#${version}`,
          patch,
          version,
          updatedBy: actorId,
          updatedAtMs: Date.now(),
        },
      }),
    );
  }
}

// --- Rate limiting ---------------------------------------------------------

/**
 * Fixed-window counters with an atomic increment.
 *
 * A fixed window is used rather than a token bucket because the atomic
 * `ADD`-with-condition is a single round trip and the window boundary is
 * derivable from the clock, so no read-modify-write race exists.
 */
export class DynamoRateLimiter implements RateLimiter {
  private readonly doc: DynamoDBDocumentClient;
  private readonly table: string;

  constructor(doc: DynamoDBDocumentClient, table: string) {
    this.doc = doc;
    this.table = table;
  }

  async consume(
    key: string,
    limit: number,
    windowSeconds: number,
    nowMs: number,
  ): Promise<{ allowed: boolean; remaining: number; retryAfterSeconds: number }> {
    const windowMs = windowSeconds * 1000;
    const windowStart = Math.floor(nowMs / windowMs) * windowMs;
    const bucketKey = `rate#${key}#${windowStart}`;

    const result = await this.doc.send(
      new UpdateCommand({
        TableName: this.table,
        Key: { bucketKey },
        UpdateExpression: 'ADD hits :one SET expiresAt = if_not_exists(expiresAt, :ttl)',
        ExpressionAttributeValues: {
          ':one': 1,
          ':ttl': Math.floor((windowStart + windowMs * 2) / 1000),
        },
        ReturnValues: 'UPDATED_NEW',
      }),
    );

    const hits = Number(result.Attributes?.hits ?? 1);
    if (hits > limit) {
      return {
        allowed: false,
        remaining: 0,
        retryAfterSeconds: Math.max(1, Math.ceil((windowStart + windowMs - nowMs) / 1000)),
      };
    }
    return { allowed: true, remaining: Math.max(0, limit - hits), retryAfterSeconds: 0 };
  }

  async recordMalformed(key: string, nowMs: number): Promise<void> {
    const bucket = Math.floor(nowMs / 60_000) * 60_000;
    await this.doc.send(
      new UpdateCommand({
        TableName: this.table,
        Key: { bucketKey: `malformed#${key}#${bucket}` },
        UpdateExpression: 'ADD hits :one SET expiresAt = if_not_exists(expiresAt, :ttl)',
        ExpressionAttributeValues: { ':one': 1, ':ttl': Math.floor(bucket / 1000) + 3600 },
      }),
    );
  }

  async countMalformed(key: string, windowSeconds: number, nowMs: number): Promise<number> {
    const buckets = Math.ceil(windowSeconds / 60);
    let total = 0;
    for (let i = 0; i < Math.min(buckets, 60); i += 1) {
      const bucket = Math.floor((nowMs - i * 60_000) / 60_000) * 60_000;
      const result = await this.doc.send(
        new GetCommand({ TableName: this.table, Key: { bucketKey: `malformed#${key}#${bucket}` } }),
      );
      total += Number(result.Item?.hits ?? 0);
    }
    return total;
  }

  async observedRequestsPerMinute(key: string, nowMs: number): Promise<number> {
    const bucket = Math.floor(nowMs / 60_000) * 60_000;
    const result = await this.doc.send(
      new GetCommand({ TableName: this.table, Key: { bucketKey: `rate#api:${key}#${bucket}` } }),
    );
    const ingest = await this.doc.send(
      new GetCommand({ TableName: this.table, Key: { bucketKey: `rate#ingest:${key}#${bucket}` } }),
    );
    return Number(result.Item?.hits ?? 0) + Number(ingest.Item?.hits ?? 0);
  }

  /** Used by the retention job to clear expired counters eagerly. */
  async drop(bucketKey: string): Promise<void> {
    await this.doc.send(new DeleteCommand({ TableName: this.table, Key: { bucketKey } }));
  }
}

function isConditionalCheckFailure(err: unknown): boolean {
  return (
    typeof err === 'object' &&
    err !== null &&
    'name' in err &&
    (err as { name: string }).name === 'ConditionalCheckFailedException'
  );
}
