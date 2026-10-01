/**
 * Remaining AWS adapters: EventBridge, SNS, Secrets Manager, Transcribe,
 * structured logging and CloudWatch EMF metrics.
 */

import { EventBridgeClient, PutEventsCommand } from '@aws-sdk/client-eventbridge';
import { PublishCommand, SNSClient } from '@aws-sdk/client-sns';
import { GetSecretValueCommand, SecretsManagerClient } from '@aws-sdk/client-secrets-manager';
import { StartTranscriptionJobCommand, TranscribeClient } from '@aws-sdk/client-transcribe';

import type {
  EventPublisher,
  Logger,
  Metrics,
  Notifier,
  SecretProvider,
  Transcriber,
} from '../../ports.ts';

// --- EventBridge -----------------------------------------------------------

export class EventBridgePublisher implements EventPublisher {
  private readonly client: EventBridgeClient;
  private readonly busName: string;
  private readonly source: string;
  private readonly logger: Logger;

  constructor(client: EventBridgeClient, busName: string, source: string, logger: Logger) {
    this.client = client;
    this.busName = busName;
    this.source = source;
    this.logger = logger;
  }

  async publish(detailType: string, detail: Record<string, unknown>): Promise<void> {
    await this.publishMany([{ detailType, detail }]);
  }

  async publishMany(
    entries: ReadonlyArray<{ detailType: string; detail: Record<string, unknown> }>,
  ): Promise<void> {
    // PutEvents accepts at most 10 entries per call.
    for (let i = 0; i < entries.length; i += 10) {
      const chunk = entries.slice(i, i + 10);
      const result = await this.client.send(
        new PutEventsCommand({
          Entries: chunk.map((e) => ({
            EventBusName: this.busName,
            Source: this.source,
            DetailType: e.detailType,
            Detail: JSON.stringify(e.detail),
          })),
        }),
      );
      if ((result.FailedEntryCount ?? 0) > 0) {
        // Publishing is best-effort for notification fan-out; the authoritative
        // record is already persisted, so a failure is logged, not fatal.
        this.logger.error('Some events failed to publish to EventBridge.', {
          failed: result.FailedEntryCount,
          attempted: chunk.length,
        });
      }
    }
  }
}

// --- SNS notifier ----------------------------------------------------------

export class SnsNotifier implements Notifier {
  private readonly client: SNSClient;
  private readonly topicArn: string | undefined;
  private readonly logger: Logger;
  private readonly dedupeWindowMs: number;
  private readonly recent = new Map<string, number>();

  constructor(
    client: SNSClient,
    topicArn: string | undefined,
    logger: Logger,
    dedupeWindowMs = 5 * 60 * 1000,
  ) {
    this.client = client;
    this.topicArn = topicArn;
    this.logger = logger;
    this.dedupeWindowMs = dedupeWindowMs;
  }

  async send(alert: {
    subject: string;
    body: string;
    level: string;
    dedupeKey: string;
  }): Promise<{ sent: boolean; suppressed?: boolean }> {
    if (this.topicArn === undefined) {
      this.logger.warn('Alert raised but no SNS topic is configured; alert not delivered.', {
        level: alert.level,
      });
      return { sent: false };
    }

    const now = Date.now();
    // Lambda containers are reused, so this suppresses the common case cheaply.
    // Cross-container duplicates are tolerable for alerting.
    const last = this.recent.get(alert.dedupeKey);
    if (last !== undefined && now - last < this.dedupeWindowMs) {
      return { sent: false, suppressed: true };
    }
    this.recent.set(alert.dedupeKey, now);
    if (this.recent.size > 500) {
      for (const [key, at] of this.recent) {
        if (now - at > this.dedupeWindowMs) this.recent.delete(key);
      }
    }

    await this.client.send(
      new PublishCommand({
        TopicArn: this.topicArn,
        // SNS subjects are limited to 100 characters.
        Subject: alert.subject.slice(0, 100),
        Message: alert.body,
        MessageAttributes: {
          level: { DataType: 'String', StringValue: alert.level },
        },
      }),
    );
    return { sent: true };
  }
}

// --- Secrets Manager -------------------------------------------------------

export class SecretsManagerProvider implements SecretProvider {
  private readonly client: SecretsManagerClient;
  private readonly logger: Logger;
  /** Cached for the container lifetime; secrets rotate far slower than this. */
  private readonly cache = new Map<string, string>();

  constructor(client: SecretsManagerClient, logger: Logger) {
    this.client = client;
    this.logger = logger;
  }

  async get(name: string): Promise<string | undefined> {
    const cached = this.cache.get(name);
    if (cached !== undefined) return cached;

    try {
      const result = await this.client.send(new GetSecretValueCommand({ SecretId: name }));
      const value = result.SecretString;
      if (value === undefined) return undefined;
      this.cache.set(name, value);
      return value;
    } catch (err: unknown) {
      // Never log the secret name's value or the error body verbatim.
      this.logger.error('Failed to retrieve a secret.', {
        secretName: name,
        errorName: err instanceof Error ? err.name : 'unknown',
      });
      return undefined;
    }
  }
}

// --- Transcribe ------------------------------------------------------------

export interface TranscribeConfig {
  enabled: boolean;
  languageCode: string;
  outputBucket?: string;
  vocabularyName?: string;
}

/**
 * Amazon Transcribe adapter.
 *
 * Refuses to start a job unless the caller asserts a recorded consent/lawful
 * basis for this specific audio. That check lives here rather than at the call
 * site so that no future code path can start a transcription job without it.
 */
export class TranscribeAdapter implements Transcriber {
  readonly enabled: boolean;
  private readonly client: TranscribeClient;
  private readonly config: TranscribeConfig;
  private readonly logger: Logger;

  constructor(client: TranscribeClient, config: TranscribeConfig, logger: Logger) {
    this.client = client;
    this.config = config;
    this.logger = logger;
    this.enabled = config.enabled;
  }

  async startJob(input: {
    audioUri: string;
    userId: string;
    roomId: string;
    consentRecorded: boolean;
  }): Promise<{ jobName: string } | { refused: string }> {
    if (!this.enabled) {
      return {
        refused:
          'Transcription is disabled for this deployment. No call audio is received or processed.',
      };
    }

    if (!input.consentRecorded) {
      this.logger.warn('Transcription refused: no recorded consent for this audio.', {
        roomId: input.roomId,
      });
      return {
        refused:
          'Transcription refused: no recorded lawful basis or participant consent for this audio. ' +
          'TalkinShield will not process call audio without one.',
      };
    }

    if (this.config.outputBucket === undefined) {
      return { refused: 'Transcription is enabled but no output bucket is configured.' };
    }

    // Job names must be unique and may not contain arbitrary characters.
    const jobName = `talkinshield-${input.roomId.replace(/[^A-Za-z0-9-]/gu, '')}-${Date.now()}`;

    await this.client.send(
      new StartTranscriptionJobCommand({
        TranscriptionJobName: jobName,
        LanguageCode: this.config.languageCode as 'en-US',
        Media: { MediaFileUri: input.audioUri },
        OutputBucketName: this.config.outputBucket,
        ...(this.config.vocabularyName !== undefined
          ? { Settings: { VocabularyName: this.config.vocabularyName } }
          : {}),
        // Content redaction removes PII from the transcript before it reaches us.
        ContentRedaction: {
          RedactionType: 'PII',
          RedactionOutput: 'redacted',
        },
      }),
    );

    return { jobName };
  }
}

// --- Logging ---------------------------------------------------------------

const LEVELS = { debug: 10, info: 20, warn: 30, error: 40 } as const;
export type LogLevel = keyof typeof LEVELS;

/**
 * Structured JSON logger for CloudWatch Logs Insights.
 *
 * Never logs message content, tokens, or raw request bodies. Callers pass
 * identifiers and counts; the detectors already produce human-readable reasons
 * that are safe to record.
 */
export class JsonLogger implements Logger {
  private readonly minLevel: number;
  private readonly context: Record<string, unknown>;

  constructor(level: LogLevel = 'info', context: Record<string, unknown> = {}) {
    this.minLevel = LEVELS[level];
    this.context = context;
  }

  debug(message: string, fields?: Record<string, unknown>): void {
    this.write('debug', message, fields);
  }
  info(message: string, fields?: Record<string, unknown>): void {
    this.write('info', message, fields);
  }
  warn(message: string, fields?: Record<string, unknown>): void {
    this.write('warn', message, fields);
  }
  error(message: string, fields?: Record<string, unknown>): void {
    this.write('error', message, fields);
  }

  child(fields: Record<string, unknown>): Logger {
    const levelName = (Object.keys(LEVELS) as LogLevel[]).find(
      (k) => LEVELS[k] === this.minLevel,
    );
    return new JsonLogger(levelName ?? 'info', { ...this.context, ...fields });
  }

  private write(level: LogLevel, message: string, fields?: Record<string, unknown>): void {
    if (LEVELS[level] < this.minLevel) return;
    const line = JSON.stringify({
      level,
      message,
      timestamp: new Date().toISOString(),
      ...this.context,
      ...fields,
    });
    if (level === 'error') process.stderr.write(`${line}\n`);
    else process.stdout.write(`${line}\n`);
  }
}

/**
 * CloudWatch metrics via the Embedded Metric Format.
 *
 * EMF avoids a synchronous PutMetricData call per metric: the log line itself is
 * the metric, so there is no added latency or failure mode on the request path.
 */
export class EmfMetrics implements Metrics {
  private readonly namespace: string;
  private readonly defaults: Record<string, string>;

  constructor(namespace = 'TalkinShield', defaults: Record<string, string> = {}) {
    this.namespace = namespace;
    this.defaults = defaults;
  }

  count(name: string, value = 1, dimensions?: Record<string, string>): void {
    this.emit(name, value, 'Count', dimensions);
  }

  gauge(name: string, value: number, dimensions?: Record<string, string>): void {
    this.emit(name, value, 'None', dimensions);
  }

  private emit(
    name: string,
    value: number,
    unit: string,
    dimensions?: Record<string, string>,
  ): void {
    const allDimensions = { ...this.defaults, ...dimensions };
    const dimensionKeys = Object.keys(allDimensions);
    process.stdout.write(
      `${JSON.stringify({
        _aws: {
          Timestamp: Date.now(),
          CloudWatchMetrics: [
            {
              Namespace: this.namespace,
              Dimensions: dimensionKeys.length > 0 ? [dimensionKeys] : [[]],
              Metrics: [{ Name: name, Unit: unit }],
            },
          ],
        },
        ...allDimensions,
        [name]: value,
      })}\n`,
    );
  }
}

// --- Client factories ------------------------------------------------------

export const createEventBridgeClient = (region: string): EventBridgeClient =>
  new EventBridgeClient({ region });
export const createSnsClient = (region: string): SNSClient => new SNSClient({ region });
export const createSecretsClient = (region: string): SecretsManagerClient =>
  new SecretsManagerClient({ region });
export const createTranscribeClient = (region: string): TranscribeClient =>
  new TranscribeClient({ region });
