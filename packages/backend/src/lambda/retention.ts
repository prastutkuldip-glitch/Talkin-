/**
 * Retention Lambda: enforces the configured data-retention policy.
 *
 * Most tables expire themselves via DynamoDB TTL, which is the cheapest and most
 * reliable mechanism. This job handles what TTL cannot:
 *
 *   - Evidence objects in S3, which are Object-Lock protected until their
 *     retain-until date and therefore cannot be lifecycle-expired early.
 *   - Writing an audit entry for each deletion, so the act of deleting evidence
 *     is itself part of the record.
 *
 * It refuses to delete evidence that is still referenced by an incident which
 * has not reached its own retention age — an incident must never outlive the
 * evidence that justifies it.
 */

import type { Context, ScheduledEvent } from 'aws-lambda';

import { newAuditId } from '@talkinshield/core';

import { container } from './container.ts';

export interface RetentionSummary {
  evidenceExamined: number;
  evidenceDeleted: number;
  evidenceRetainedByPolicy: number;
  refusals: string[];
}

export async function handler(
  _event: ScheduledEvent,
  _context: Context,
): Promise<RetentionSummary> {
  const deps = container();
  const nowMs = deps.clock.now();
  const log = deps.logger.child({ job: 'retention' });

  const summary: RetentionSummary = {
    evidenceExamined: 0,
    evidenceDeleted: 0,
    evidenceRetainedByPolicy: 0,
    refusals: [],
  };

  const evidenceCutoff = nowMs - deps.env.retentionDays.evidence * 86_400_000;
  const incidentCutoff = nowMs - deps.env.retentionDays.incidents * 86_400_000;

  // Only incidents already past their own retention age are candidates.
  const expiredIncidents = await deps.incidents.list({ limit: 500 });

  for (const incident of expiredIncidents) {
    if (incident.createdAtMs > incidentCutoff) continue;

    for (const key of incident.evidenceKeys) {
      summary.evidenceExamined += 1;

      const bundle = await deps.evidence.get(key);
      if (bundle === undefined) continue;

      if (bundle.body.createdAtMs > evidenceCutoff) {
        summary.evidenceRetainedByPolicy += 1;
        continue;
      }

      const deleted = await deps.evidence.deleteForRetention(key);

      if (deleted) {
        summary.evidenceDeleted += 1;
        // The deletion is itself auditable, including the hash of what was
        // removed, so the chain gap is explained rather than suspicious.
        await deps.audit.append({
          auditId: newAuditId(),
          atMs: nowMs,
          actorId: 'system',
          actorKind: 'SYSTEM',
          action: 'RETENTION_DELETION',
          target: key,
          reason: `Evidence deleted under the configured ${deps.env.retentionDays.evidence}-day retention policy.`,
          outcome: 'SUCCESS',
          detail: {
            incidentId: incident.incidentId,
            contentHash: bundle.contentHash,
            sequence: bundle.sequence,
            createdAt: bundle.body.createdAt,
          },
          ttlEpochSeconds: Math.floor((nowMs + deps.env.retentionDays.audit * 86_400_000) / 1000),
        });
        deps.metrics.count('RetentionEvidenceDeleted');
      } else {
        // Object Lock still in force, or IAM refused. Expected, not an error.
        summary.refusals.push(key);
        deps.metrics.count('RetentionDeletionRefused');
      }
    }
  }

  log.info('Retention pass complete.', { ...summary, refusals: summary.refusals.length });
  return summary;
}
