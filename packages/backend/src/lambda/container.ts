/**
 * Dependency wiring for Lambda.
 *
 * Built once per container (cold start) and reused, so client construction and
 * secret fetches are amortised. Everything is assembled from `AppEnv`; the
 * handlers never read `process.env` directly.
 */

import { S3Client } from '@aws-sdk/client-s3';

import {
  BedrockClassifier,
  createBedrockClient,
} from '../adapters/aws/bedrock.ts';
import {
  createDocumentClient,
  DynamoActionStore,
  DynamoAuditStore,
  DynamoEventStore,
  DynamoIncidentStore,
  DynamoRateLimiter,
  DynamoRulesStore,
  DynamoSignalStore,
  DynamoUserStateStore,
} from '../adapters/aws/dynamo.ts';
import {
  createEventBridgeClient,
  createSecretsClient,
  createSnsClient,
  createTranscribeClient,
  EmfMetrics,
  EventBridgePublisher,
  JsonLogger,
  SecretsManagerProvider,
  SnsNotifier,
  TranscribeAdapter,
} from '../adapters/aws/misc.ts';
import { S3EvidenceStore } from '../adapters/aws/s3-evidence.ts';
import { DisabledClassifier, DisabledTranscriber } from '../adapters/memory/stores.ts';
import {
  HttpTalkinAdapter,
  MockTalkinAdapter,
  NoopTalkinAdapter,
} from '../adapters/platform/talkin-adapter.ts';
import { loadEnvOrThrow, type AppEnv } from '../config/env.ts';
import type { RouterDeps } from '../http/router.ts';
import type { Clock, TalkinPlatformAdapter, Transcriber } from '../ports.ts';

export interface Container extends RouterDeps {
  transcriber: Transcriber;
}

let cached: Container | undefined;

const systemClock: Clock = { now: () => Date.now() };

export function container(): Container {
  if (cached !== undefined) return cached;
  cached = build(loadEnvOrThrow());
  return cached;
}

export function build(env: AppEnv): Container {
  const logger = new JsonLogger(env.logLevel, { stage: env.stage, service: 'talkinshield' });
  const metrics = new EmfMetrics('TalkinShield', { Stage: env.stage });

  const doc = createDocumentClient(env.region);
  const secrets = new SecretsManagerProvider(createSecretsClient(env.region), logger);

  const platform = buildPlatformAdapter(env, secrets, logger);

  const classifier = env.bedrock.enabled
    ? new BedrockClassifier(
        createBedrockClient(env.bedrock.region),
        {
          enabled: true,
          modelId: env.bedrock.modelId,
          maxTokens: env.bedrock.maxTokens,
          timeoutMs: env.bedrock.timeoutMs,
          classifierVersion: env.bedrock.classifierVersion,
        },
        logger,
        metrics,
      )
    : new DisabledClassifier();

  const transcriber: Transcriber = env.transcribe.enabled
    ? new TranscribeAdapter(
        createTranscribeClient(env.region),
        {
          enabled: true,
          languageCode: env.transcribe.languageCode,
          ...(env.transcribe.outputBucket !== undefined
            ? { outputBucket: env.transcribe.outputBucket }
            : {}),
          ...(env.transcribe.vocabularyName !== undefined
            ? { vocabularyName: env.transcribe.vocabularyName }
            : {}),
        },
        logger,
      )
    : new DisabledTranscriber();

  return {
    env,
    logger,
    metrics,
    clock: systemClock,
    platform,
    classifier,
    transcriber,
    events: new DynamoEventStore(doc, env.tables.events),
    userState: new DynamoUserStateStore(doc, env.tables.userState),
    signals: new DynamoSignalStore(doc, env.tables.signals),
    incidents: new DynamoIncidentStore(doc, env.tables.incidents),
    actions: new DynamoActionStore(doc, env.tables.actions),
    audit: new DynamoAuditStore(doc, env.tables.audit),
    rules: new DynamoRulesStore(doc, env.tables.rules),
    rateLimiter: new DynamoRateLimiter(doc, env.tables.rateLimit),
    evidence: new S3EvidenceStore(
      new S3Client({ region: env.region }),
      {
        bucket: env.evidence.bucket,
        objectLockDays: env.evidence.objectLockDays,
        ...(env.evidence.kmsKeyId !== undefined ? { kmsKeyId: env.evidence.kmsKeyId } : {}),
      },
      logger,
    ),
    publisher: new EventBridgePublisher(
      createEventBridgeClient(env.region),
      env.eventBus.name,
      env.eventBus.source,
      logger,
    ),
    notifier: new SnsNotifier(createSnsClient(env.region), env.alert.snsTopicArn, logger),
    limits: {
      maxBatchSize: env.limits.ingestMaxBatchSize,
      maxMessageLength: env.limits.ingestMaxMessageLength,
    },
    retentionDays: {
      signals: env.retentionDays.signals,
      rawEvents: env.retentionDays.rawEvents,
    },
  };
}

function buildPlatformAdapter(
  env: AppEnv,
  secrets: SecretsManagerProvider,
  logger: JsonLogger,
): TalkinPlatformAdapter {
  switch (env.talkin.adapter) {
    case 'http': {
      if (env.talkin.baseUrl === undefined || env.talkin.secretName === undefined) {
        // Fail safe rather than fail open: with no credentials we behave as if
        // there is no integration at all.
        logger.error(
          'TALKIN_ADAPTER=http but base URL or secret name is missing; falling back to no integration.',
        );
        return new NoopTalkinAdapter();
      }
      return new HttpTalkinAdapter(
        {
          baseUrl: env.talkin.baseUrl,
          secretName: env.talkin.secretName,
          timeoutMs: env.talkin.timeoutMs,
          capabilities: env.talkin.capabilities,
        },
        secrets,
        logger,
      );
    }
    case 'mock':
      return new MockTalkinAdapter(env.talkin.capabilities, systemClock, undefined, env.stage);
    case 'noop':
    default:
      return new NoopTalkinAdapter();
  }
}

/** Test seam: drop the cached container. */
export function resetContainer(): void {
  cached = undefined;
}
