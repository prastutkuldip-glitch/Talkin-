/**
 * Event ingestion.
 *
 * Validates and sanitizes every event, deduplicates, persists, and fans the
 * accepted events out to the analysis pipeline via EventBridge.
 *
 * Rejected events are counted against the submitting subject so that repeated
 * malformed payloads become a client-integrity signal — one of the few places
 * where a failed request is itself useful telemetry.
 */

import {
  DEFAULT_LIMITS,
  validateBatch,
  type TalkinEvent,
  type ValidationIssue,
} from '@talkinshield/core';

import type {
  AuditStore,
  Clock,
  EventPublisher,
  EventStore,
  Logger,
  Metrics,
  RateLimiter,
  RetentionDays,
  TalkinPlatformAdapter,
} from '../ports.ts';

export interface IngestDeps {
  events: EventStore;
  publisher: EventPublisher;
  rateLimiter: RateLimiter;
  platform: TalkinPlatformAdapter;
  audit: AuditStore;
  logger: Logger;
  metrics: Metrics;
  clock: Clock;
  limits: {
    maxBatchSize: number;
    maxMessageLength: number;
  };
  retentionDays: RetentionDays;
}

export interface IngestResult {
  accepted: number;
  duplicates: number;
  rejected: Array<{ index: number; issues: ValidationIssue[] }>;
  warnings: Array<{ index: number; warnings: ValidationIssue[] }>;
  eventIds: string[];
}

export type IngestOutcome = IngestResult | { error: string };

export async function ingestEvents(
  payload: unknown,
  submitterKey: string,
  deps: IngestDeps,
): Promise<IngestOutcome> {
  const nowMs = deps.clock.now();
  const capabilities = deps.platform.capabilities();

  const events = extractEvents(payload);
  if ('error' in events) {
    await deps.rateLimiter.recordMalformed(submitterKey, nowMs);
    deps.metrics.count('IngestMalformed');
    return events;
  }

  const validation = validateBatch(events.list, {
    nowMs,
    maxBatchSize: deps.limits.maxBatchSize,
    limits: { ...DEFAULT_LIMITS, maxMessageLength: deps.limits.maxMessageLength },
    messageContentAuthorized: capabilities.messageContent,
  });

  if ('error' in validation) {
    await deps.rateLimiter.recordMalformed(submitterKey, nowMs);
    deps.metrics.count('IngestMalformed');
    return validation;
  }

  // Each rejected event counts once toward the malformed-request signal.
  for (let i = 0; i < validation.rejected.length; i += 1) {
    await deps.rateLimiter.recordMalformed(submitterKey, nowMs);
  }
  if (validation.rejected.length > 0) {
    deps.metrics.count('IngestRejected', validation.rejected.length);
  }

  const ttl = Math.floor((nowMs + deps.retentionDays.rawEvents * 86_400_000) / 1000);
  const stored: TalkinEvent[] = [];
  let duplicates = 0;

  for (const event of validation.accepted) {
    try {
      const written = await deps.events.put(event, ttl);
      if (written) stored.push(event);
      else duplicates += 1;
    } catch (err: unknown) {
      deps.logger.error('Failed to persist an accepted event.', {
        eventId: event.eventId,
        error: err instanceof Error ? err.message : String(err),
      });
      deps.metrics.count('IngestPersistFailure');
      throw err;
    }
  }

  // Fan out for analysis. Only newly-stored events are analysed, so a retried
  // delivery cannot inflate a user's risk score.
  if (stored.length > 0) {
    await deps.publisher.publishMany(
      stored.map((event) => ({
        detailType: 'EventIngested',
        detail: {
          eventId: event.eventId,
          userId: event.userId,
          roomId: event.roomId,
          eventType: event.eventType,
          timestamp: event.timestamp,
        },
      })),
    );
  }

  deps.metrics.count('IngestAccepted', stored.length);
  deps.metrics.count('IngestDuplicate', duplicates);

  return {
    accepted: stored.length,
    duplicates,
    rejected: validation.rejected,
    warnings: validation.warnings,
    eventIds: stored.map((e) => e.eventId),
  };
}

/**
 * Accept either a single event object or `{ events: [...] }`.
 * Anything else is a malformed request.
 */
function extractEvents(payload: unknown): { list: unknown[] } | { error: string } {
  if (payload === null || payload === undefined) {
    return { error: 'Request body is required.' };
  }
  if (Array.isArray(payload)) {
    return { error: 'Send a single event object, or an object of the form { "events": [ ... ] }.' };
  }
  if (typeof payload !== 'object') {
    return { error: 'Request body must be a JSON object.' };
  }

  const record = payload as Record<string, unknown>;
  if (Array.isArray(record.events)) return { list: record.events };
  if (record.events !== undefined) {
    return { error: '"events" must be an array.' };
  }
  // A bare single event.
  return { list: [payload] };
}
