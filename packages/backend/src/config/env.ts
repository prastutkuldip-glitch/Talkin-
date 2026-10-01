/**
 * Environment configuration.
 *
 * Every value is read from the environment — nothing is hard-coded, and no
 * secret is ever read from source. Sensitive material (Talkin API credentials,
 * webhook URLs) is fetched at runtime from Secrets Manager by name; only the
 * *name* appears in the environment.
 *
 * `loadEnv` fails fast with a combined list of problems rather than discovering
 * a missing variable halfway through a request.
 */

import type { AuthConfig } from '../http/auth.ts';
import type { IntegrationCapabilities } from '@talkinshield/core';

export interface AppEnv {
  stage: string;
  logLevel: 'debug' | 'info' | 'warn' | 'error';
  region: string;

  auth: AuthConfig;

  tables: {
    events: string;
    userState: string;
    incidents: string;
    signals: string;
    actions: string;
    rules: string;
    audit: string;
    rateLimit: string;
  };

  evidence: {
    bucket: string;
    objectLockDays: number;
    kmsKeyId?: string;
  };

  eventBus: { name: string; source: string };

  bedrock: {
    enabled: boolean;
    region: string;
    modelId: string;
    maxTokens: number;
    timeoutMs: number;
    classifierVersion: string;
  };

  transcribe: {
    enabled: boolean;
    languageCode: string;
    outputBucket?: string;
    vocabularyName?: string;
  };

  talkin: {
    adapter: 'noop' | 'mock' | 'http';
    baseUrl?: string;
    secretName?: string;
    timeoutMs: number;
    capabilities: IntegrationCapabilities;
  };

  limits: {
    ingestRatePerMinute: number;
    ingestMaxBatchSize: number;
    ingestMaxMessageLength: number;
    apiRatePerMinute: number;
    /** Hard ceiling on raw request bytes, enforced before JSON parsing. */
    maxRequestBytes: number;
  };

  retentionDays: {
    rawEvents: number;
    signals: number;
    incidents: number;
    evidence: number;
    audit: number;
  };

  alert: {
    snsTopicArn?: string;
    webhookSecretName?: string;
    minLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  };

  /** Salt for deriving display handles. Loaded from Secrets Manager in prod. */
  displayHandleSalt: string;
}

export interface LoadResult {
  env?: AppEnv;
  problems: string[];
}

export function loadEnv(source: Record<string, string | undefined> = process.env): LoadResult {
  const problems: string[] = [];

  const required = (key: string): string => {
    const value = source[key];
    if (value === undefined || value.trim().length === 0) {
      problems.push(`${key} is required but not set.`);
      return '';
    }
    return value.trim();
  };

  const optional = (key: string, fallback = ''): string => (source[key] ?? fallback).trim();

  const int = (key: string, fallback: number, min = 0, max = Number.MAX_SAFE_INTEGER): number => {
    const raw = source[key];
    if (raw === undefined || raw.trim().length === 0) return fallback;
    const parsed = Number(raw);
    if (!Number.isFinite(parsed) || !Number.isInteger(parsed)) {
      problems.push(`${key} must be an integer.`);
      return fallback;
    }
    if (parsed < min || parsed > max) {
      problems.push(`${key} must be between ${min} and ${max}.`);
      return fallback;
    }
    return parsed;
  };

  const bool = (key: string, fallback = false): boolean => {
    const raw = source[key];
    if (raw === undefined || raw.trim().length === 0) return fallback;
    const normalized = raw.trim().toLowerCase();
    if (['true', '1', 'yes', 'on'].includes(normalized)) return true;
    if (['false', '0', 'no', 'off'].includes(normalized)) return false;
    problems.push(`${key} must be a boolean (true/false).`);
    return fallback;
  };

  const list = (key: string, fallback: string[] = []): string[] => {
    const raw = source[key];
    if (raw === undefined || raw.trim().length === 0) return fallback;
    return raw
      .split(',')
      .map((v) => v.trim())
      .filter((v) => v.length > 0);
  };

  const stage = optional('STAGE', 'dev');
  const isProd = stage === 'prod';
  const region = optional('AWS_REGION', 'us-east-1');

  const logLevelRaw = optional('LOG_LEVEL', 'info');
  const logLevel = (['debug', 'info', 'warn', 'error'] as const).includes(
    logLevelRaw as 'debug' | 'info' | 'warn' | 'error',
  )
    ? (logLevelRaw as 'debug' | 'info' | 'warn' | 'error')
    : 'info';

  const adapterRaw = optional('TALKIN_ADAPTER', 'noop');
  const adapter = (['noop', 'mock', 'http'] as const).includes(adapterRaw as 'noop' | 'mock' | 'http')
    ? (adapterRaw as 'noop' | 'mock' | 'http')
    : ((): 'noop' => {
        problems.push('TALKIN_ADAPTER must be one of: noop, mock, http.');
        return 'noop';
      })();

  // Production must not run against the mock platform adapter.
  if (isProd && adapter === 'mock') {
    problems.push(
      'TALKIN_ADAPTER=mock is not permitted when STAGE=prod — the mock adapter fabricates platform responses.',
    );
  }

  const capabilities: IntegrationCapabilities = {
    messageContent: bool('TALKIN_CAP_MESSAGE_CONTENT', false),
    moderationEvents: bool('TALKIN_CAP_MODERATION_EVENTS', false),
    voiceAudio: bool('TALKIN_CAP_VOICE_AUDIO', false),
    hiddenPresenceEvents: bool('TALKIN_CAP_HIDDEN_PRESENCE', false),
    clientAttestation: bool('TALKIN_CAP_CLIENT_ATTESTATION', false),
    remoteMute: bool('TALKIN_CAP_REMOTE_MUTE', false),
    remoteBlock: bool('TALKIN_CAP_REMOTE_BLOCK', false),
  };

  // Declaring a platform-acting capability without an API endpoint is a
  // configuration error: the system would advertise an ability it cannot use.
  const httpRequired = capabilities.remoteMute || capabilities.remoteBlock;
  if (adapter === 'http' && optional('TALKIN_API_BASE_URL').length === 0) {
    problems.push('TALKIN_API_BASE_URL is required when TALKIN_ADAPTER=http.');
  }
  if (httpRequired && adapter === 'noop') {
    problems.push(
      'TALKIN_CAP_REMOTE_MUTE / TALKIN_CAP_REMOTE_BLOCK are enabled but TALKIN_ADAPTER=noop, so no official API is configured to perform them.',
    );
  }

  const transcribeEnabled = bool('TRANSCRIBE_ENABLED', false);
  if (transcribeEnabled && !capabilities.voiceAudio) {
    problems.push(
      'TRANSCRIBE_ENABLED=true requires TALKIN_CAP_VOICE_AUDIO=true — transcription must not be enabled without an authorized audio integration.',
    );
  }

  const bedrockEnabled = bool('BEDROCK_ENABLED', false);

  const env: AppEnv = {
    stage,
    logLevel,
    region,
    auth: {
      userPoolId: isProd ? required('COGNITO_USER_POOL_ID') : optional('COGNITO_USER_POOL_ID'),
      allowedClientIds: list('COGNITO_CLIENT_ID'),
      region,
      moderatorGroups: list('MODERATOR_GROUPS', ['moderators', 'admins']),
      adminGroups: list('ADMIN_GROUPS', ['admins']),
      serviceGroups: list('SERVICE_GROUPS', ['telemetry-ingest']),
      requireMfaForDestructive: bool('REQUIRE_MFA_FOR_DESTRUCTIVE', isProd),
    },
    tables: {
      events: optional('TABLE_EVENTS', 'talkinshield-events'),
      userState: optional('TABLE_USER_STATE', 'talkinshield-user-state'),
      incidents: optional('TABLE_INCIDENTS', 'talkinshield-incidents'),
      signals: optional('TABLE_SIGNALS', 'talkinshield-signals'),
      actions: optional('TABLE_ACTIONS', 'talkinshield-actions'),
      rules: optional('TABLE_RULES', 'talkinshield-rules'),
      audit: optional('TABLE_AUDIT', 'talkinshield-audit'),
      rateLimit: optional('TABLE_RATELIMIT', 'talkinshield-ratelimit'),
    },
    evidence: {
      bucket: isProd ? required('EVIDENCE_BUCKET') : optional('EVIDENCE_BUCKET'),
      objectLockDays: int('EVIDENCE_OBJECT_LOCK_DAYS', 30, 1, 36500),
      ...(optional('KMS_KEY_ID').length > 0 ? { kmsKeyId: optional('KMS_KEY_ID') } : {}),
    },
    eventBus: {
      name: optional('EVENT_BUS_NAME', 'talkinshield-bus'),
      source: optional('EVENT_SOURCE', 'talkinshield.detection'),
    },
    bedrock: {
      enabled: bedrockEnabled,
      region: optional('BEDROCK_REGION', region),
      modelId: optional('BEDROCK_MODEL_ID', 'anthropic.claude-3-5-haiku-20241022-v1:0'),
      maxTokens: int('BEDROCK_MAX_TOKENS', 512, 64, 4096),
      timeoutMs: int('BEDROCK_TIMEOUT_MS', 4000, 500, 30_000),
      classifierVersion: optional('BEDROCK_CLASSIFIER_VERSION', '1.0.0'),
    },
    transcribe: {
      enabled: transcribeEnabled,
      languageCode: optional('TRANSCRIBE_LANGUAGE_CODE', 'en-US'),
      ...(optional('TRANSCRIBE_OUTPUT_BUCKET').length > 0
        ? { outputBucket: optional('TRANSCRIBE_OUTPUT_BUCKET') }
        : {}),
      ...(optional('TRANSCRIBE_VOCABULARY_NAME').length > 0
        ? { vocabularyName: optional('TRANSCRIBE_VOCABULARY_NAME') }
        : {}),
    },
    talkin: {
      adapter,
      ...(optional('TALKIN_API_BASE_URL').length > 0
        ? { baseUrl: optional('TALKIN_API_BASE_URL') }
        : {}),
      ...(optional('TALKIN_API_SECRET_NAME').length > 0
        ? { secretName: optional('TALKIN_API_SECRET_NAME') }
        : {}),
      timeoutMs: int('TALKIN_API_TIMEOUT_MS', 5000, 500, 30_000),
      capabilities,
    },
    limits: {
      ingestRatePerMinute: int('INGEST_RATE_LIMIT_PER_MINUTE', 600, 1, 1_000_000),
      ingestMaxBatchSize: int('INGEST_MAX_BATCH_SIZE', 50, 1, 500),
      ingestMaxMessageLength: int('INGEST_MAX_MESSAGE_LENGTH', 4000, 1, 100_000),
      apiRatePerMinute: int('API_RATE_LIMIT_PER_MINUTE', 120, 1, 1_000_000),
      maxRequestBytes: int('MAX_REQUEST_BYTES', 262_144, 1024, 10_485_760),
    },
    retentionDays: {
      rawEvents: int('RETENTION_RAW_EVENTS_DAYS', 30, 1, 3650),
      signals: int('RETENTION_SIGNALS_DAYS', 90, 1, 3650),
      incidents: int('RETENTION_INCIDENTS_DAYS', 365, 1, 3650),
      evidence: int('RETENTION_EVIDENCE_DAYS', 365, 1, 3650),
      audit: int('RETENTION_AUDIT_DAYS', 730, 1, 3650),
    },
    alert: {
      ...(optional('ALERT_SNS_TOPIC_ARN').length > 0
        ? { snsTopicArn: optional('ALERT_SNS_TOPIC_ARN') }
        : {}),
      ...(optional('ALERT_WEBHOOK_SECRET_NAME').length > 0
        ? { webhookSecretName: optional('ALERT_WEBHOOK_SECRET_NAME') }
        : {}),
      minLevel: (['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'] as const).includes(
        optional('ALERT_MIN_LEVEL', 'HIGH') as 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL',
      )
        ? (optional('ALERT_MIN_LEVEL', 'HIGH') as 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL')
        : 'HIGH',
    },
    displayHandleSalt: optional('DISPLAY_HANDLE_SALT', 'talkinshield-dev-salt'),
  };

  if (isProd && env.displayHandleSalt === 'talkinshield-dev-salt') {
    problems.push('DISPLAY_HANDLE_SALT must be set to a real secret value when STAGE=prod.');
  }

  // Evidence retention must not be shorter than incident retention, otherwise
  // an incident would outlive the evidence that justifies it.
  if (env.retentionDays.evidence < env.retentionDays.incidents) {
    problems.push(
      'RETENTION_EVIDENCE_DAYS must be greater than or equal to RETENTION_INCIDENTS_DAYS, otherwise incidents would outlive their supporting evidence.',
    );
  }

  if (problems.length > 0) return { problems };
  return { env, problems: [] };
}

/** Throwing variant for Lambda cold start. */
export function loadEnvOrThrow(source: Record<string, string | undefined> = process.env): AppEnv {
  const { env, problems } = loadEnv(source);
  if (env === undefined) {
    throw new Error(`Invalid TalkinShield configuration:\n  - ${problems.join('\n  - ')}`);
  }
  return env;
}
