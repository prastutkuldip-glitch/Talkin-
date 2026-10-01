/**
 * Analysis Lambda: consumes `EventIngested` from EventBridge and runs the
 * detection pipeline.
 *
 * Ingestion and analysis are separated so that a slow AI call or platform API
 * can never delay or fail the ingestion request. Analysis is idempotent at the
 * event level because the event id is deterministic and already deduplicated at
 * write time.
 */

import type { Context, EventBridgeEvent, SQSEvent, SQSBatchResponse } from 'aws-lambda';

import { analyzeAndRespond } from '../app/analysis-service.ts';
import { container } from './container.ts';

interface EventIngestedDetail {
  eventId?: unknown;
  userId?: unknown;
}

/** EventBridge direct target. */
export async function handler(
  event: EventBridgeEvent<'EventIngested', EventIngestedDetail>,
  _context: Context,
): Promise<void> {
  const deps = container();
  const eventId = typeof event.detail?.eventId === 'string' ? event.detail.eventId : undefined;

  if (eventId === undefined) {
    deps.logger.warn('EventIngested detail had no eventId; nothing to analyse.');
    return;
  }

  const [stored] = await deps.events.getByIds([eventId]);
  if (stored === undefined) {
    // The event was expired by TTL or never persisted. Not an error.
    deps.logger.warn('Event referenced by EventIngested is no longer available.', { eventId });
    deps.metrics.count('AnalyzeEventMissing');
    return;
  }

  await analyzeAndRespond(stored, deps);
}

/**
 * SQS target, for deployments that buffer analysis behind a queue.
 * Partial batch failure is reported so only the failed messages are retried.
 */
export async function sqsHandler(event: SQSEvent, _context: Context): Promise<SQSBatchResponse> {
  const deps = container();
  const failures: Array<{ itemIdentifier: string }> = [];

  for (const record of event.Records) {
    try {
      const parsed = JSON.parse(record.body) as { detail?: EventIngestedDetail };
      const eventId =
        typeof parsed.detail?.eventId === 'string' ? parsed.detail.eventId : undefined;
      if (eventId === undefined) continue;

      const [stored] = await deps.events.getByIds([eventId]);
      if (stored === undefined) continue;

      await analyzeAndRespond(stored, deps);
    } catch (err: unknown) {
      deps.logger.error('Analysis failed for an SQS record; will be retried.', {
        messageId: record.messageId,
        error: err instanceof Error ? err.message : String(err),
      });
      deps.metrics.count('AnalyzeFailure');
      failures.push({ itemIdentifier: record.messageId });
    }
  }

  return { batchItemFailures: failures };
}
