import {
  NO_CAPABILITIES,
  type IntegrationCapabilities,
} from '@talkinshield/core';

import {
  CollectingLogger,
  CollectingMetrics,
  DisabledClassifier,
  MemoryActionStore,
  MemoryAuditStore,
  MemoryEventPublisher,
  MemoryEventStore,
  MemoryEvidenceStore,
  MemoryIncidentStore,
  MemoryNotifier,
  MemoryRateLimiter,
  MemoryRulesStore,
  MemorySignalStore,
  MemoryUserStateStore,
  TestClock,
} from '../src/adapters/memory/stores.ts';
import {
  MockTalkinAdapter,
  NoopTalkinAdapter,
  emptyMockState,
  type MockState,
} from '../src/adapters/platform/talkin-adapter.ts';
import { resetConfigCache } from '../src/app/analysis-service.ts';
import { loadEnv, type AppEnv } from '../src/config/env.ts';
import type { RouterDeps } from '../src/http/router.ts';
import type { ApiRequest } from '../src/http/types.ts';
import type { TextClassifier } from '../src/ports.ts';

export const T0 = Date.parse('2026-03-01T12:00:00.000Z');

export const FULL_CAPS: IntegrationCapabilities = {
  messageContent: true,
  moderationEvents: true,
  voiceAudio: true,
  hiddenPresenceEvents: true,
  clientAttestation: true,
  remoteMute: true,
  remoteBlock: true,
};

export const CONTENT_ONLY_CAPS: IntegrationCapabilities = {
  ...NO_CAPABILITIES,
  messageContent: true,
};

const BASE_ENV: Record<string, string> = {
  STAGE: 'dev',
  AWS_REGION: 'us-east-1',
  COGNITO_USER_POOL_ID: 'us-east-1_TESTPOOL',
  COGNITO_CLIENT_ID: 'test-client-id',
  MODERATOR_GROUPS: 'moderators,admins',
  ADMIN_GROUPS: 'admins',
  SERVICE_GROUPS: 'telemetry-ingest',
  EVIDENCE_BUCKET: 'test-bucket',
  TALKIN_ADAPTER: 'mock',
  TALKIN_CAP_MESSAGE_CONTENT: 'true',
  TALKIN_CAP_MODERATION_EVENTS: 'true',
  API_RATE_LIMIT_PER_MINUTE: '120',
  INGEST_RATE_LIMIT_PER_MINUTE: '600',
  DISPLAY_HANDLE_SALT: 'test-salt',
};

export function testEnv(overrides: Record<string, string> = {}): AppEnv {
  const { env, problems } = loadEnv({ ...BASE_ENV, ...overrides });
  if (env === undefined) throw new Error(`test env invalid: ${problems.join('; ')}`);
  return env;
}

export interface Harness {
  deps: RouterDeps;
  clock: TestClock;
  env: AppEnv;
  events: MemoryEventStore;
  userState: MemoryUserStateStore;
  signals: MemorySignalStore;
  incidents: MemoryIncidentStore;
  actions: MemoryActionStore;
  audit: MemoryAuditStore;
  evidence: MemoryEvidenceStore;
  rules: MemoryRulesStore;
  publisher: MemoryEventPublisher;
  notifier: MemoryNotifier;
  logger: CollectingLogger;
  metrics: CollectingMetrics;
  rateLimiter: MemoryRateLimiter;
  mockState: MockState;
}

export function harness(
  options: {
    capabilities?: IntegrationCapabilities;
    classifier?: TextClassifier;
    env?: Record<string, string>;
    useNoopPlatform?: boolean;
    mockState?: MockState;
  } = {},
): Harness {
  resetConfigCache();

  const clock = new TestClock(T0);
  const env = testEnv(options.env);
  const capabilities = options.capabilities ?? CONTENT_ONLY_CAPS;
  const mockState = options.mockState ?? emptyMockState();

  const platform = options.useNoopPlatform
    ? new NoopTalkinAdapter()
    : new MockTalkinAdapter(capabilities, clock, mockState, env.stage);

  const events = new MemoryEventStore();
  const userState = new MemoryUserStateStore();
  const signals = new MemorySignalStore();
  const incidents = new MemoryIncidentStore();
  const actions = new MemoryActionStore();
  const audit = new MemoryAuditStore();
  const evidence = new MemoryEvidenceStore();
  const rules = new MemoryRulesStore();
  const publisher = new MemoryEventPublisher();
  const notifier = new MemoryNotifier(clock);
  const logger = new CollectingLogger();
  const metrics = new CollectingMetrics();
  const rateLimiter = new MemoryRateLimiter();

  const deps: RouterDeps = {
    env,
    events,
    userState,
    signals,
    incidents,
    actions,
    audit,
    evidence,
    rules,
    rateLimiter,
    classifier: options.classifier ?? new DisabledClassifier(),
    platform,
    publisher,
    notifier,
    logger,
    metrics,
    clock,
    limits: {
      maxBatchSize: env.limits.ingestMaxBatchSize,
      maxMessageLength: env.limits.ingestMaxMessageLength,
    },
    retentionDays: {
      signals: env.retentionDays.signals,
      rawEvents: env.retentionDays.rawEvents,
    },
  };

  return {
    deps,
    clock,
    env,
    events,
    userState,
    signals,
    incidents,
    actions,
    audit,
    evidence,
    rules,
    publisher,
    notifier,
    logger,
    metrics,
    rateLimiter,
    mockState,
  };
}

// --- Request builders ------------------------------------------------------

export interface ClaimOptions {
  sub?: string;
  username?: string;
  groups?: string[];
  clientId?: string;
  tokenUse?: string;
  issuer?: string;
  expSeconds?: number;
  amr?: string[];
}

export function claims(options: ClaimOptions = {}): Record<string, unknown> {
  const out: Record<string, unknown> = {
    sub: options.sub ?? 'mod-subject-1',
    'cognito:username': options.username ?? 'alice',
    'cognito:groups': options.groups ?? ['moderators'],
    client_id: options.clientId ?? 'test-client-id',
    token_use: options.tokenUse ?? 'access',
    iss: options.issuer ?? 'https://cognito-idp.us-east-1.amazonaws.com/us-east-1_TESTPOOL',
    exp: options.expSeconds ?? Math.floor(T0 / 1000) + 3600,
  };
  if (options.amr !== undefined) out.amr = options.amr;
  return out;
}

export const ADMIN_CLAIMS = claims({ sub: 'admin-1', username: 'root', groups: ['admins'], amr: ['pwd', 'mfa'] });
export const MODERATOR_CLAIMS = claims({ sub: 'mod-1', username: 'alice', groups: ['moderators'], amr: ['pwd', 'mfa'] });
export const VIEWER_CLAIMS = claims({ sub: 'view-1', username: 'bob', groups: ['viewers'] });
export const SERVICE_CLAIMS = claims({ sub: 'svc-1', username: 'ingestor', groups: ['telemetry-ingest'] });

export function request(
  method: string,
  path: string,
  options: {
    body?: unknown;
    query?: Record<string, string>;
    claims?: Record<string, unknown>;
    sourceIp?: string;
    rawBodyLength?: number;
  } = {},
): ApiRequest {
  const body = options.body;
  const serialized = body === undefined ? '' : JSON.stringify(body);
  return {
    method,
    routeKey: `${method} ${path}`,
    path,
    pathParams: {},
    query: options.query ?? {},
    headers: { 'content-type': 'application/json' },
    body,
    rawBodyLength: options.rawBodyLength ?? serialized.length,
    requestId: `req-${Math.random().toString(36).slice(2, 10)}`,
    ...(options.sourceIp !== undefined ? { sourceIp: options.sourceIp } : {}),
    ...(options.claims !== undefined ? { claims: options.claims } : {}),
  };
}

export function event(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    userId: 'user-A',
    roomId: 'ABC123',
    timestamp: new Date(T0).toISOString(),
    eventType: 'message',
    message: 'hello everyone',
    clientVersion: '4.2.1',
    platform: 'ios',
    metadata: {},
    ...overrides,
  };
}

export function bodyOf<T = Record<string, unknown>>(response: { body: unknown }): T {
  return response.body as T;
}

export function errorCode(response: { body: unknown }): string | undefined {
  const body = response.body as { error?: { code?: string } } | undefined;
  return body?.error?.code;
}
