/**
 * Alert Lambda: consumes high-severity detection events from EventBridge and
 * dispatches operator notifications.
 *
 * Kept separate from the analysis path so that a notification outage (SNS
 * throttle, webhook down) cannot fail or slow detection. Alerting is a fan-out
 * concern; the authoritative record is already persisted by the time this runs.
 */

import type { Context, EventBridgeEvent } from 'aws-lambda';

import { newAuditId } from '@talkinshield/core';

import { container } from './container.ts';

interface RiskAssessedDetail {
  userId?: unknown;
  roomId?: unknown;
  riskLevel?: unknown;
  riskScore?: unknown;
  incidentId?: unknown;
  signals?: unknown;
  telemetryNotes?: unknown;
}

const LEVEL_ORDER: Record<string, number> = { LOW: 0, MEDIUM: 1, HIGH: 2, CRITICAL: 3 };

export async function handler(
  event: EventBridgeEvent<string, RiskAssessedDetail>,
  _context: Context,
): Promise<void> {
  const deps = container();
  const detail = event.detail ?? {};

  const userId = typeof detail.userId === 'string' ? detail.userId : undefined;
  const level = typeof detail.riskLevel === 'string' ? detail.riskLevel : 'LOW';
  const score = typeof detail.riskScore === 'number' ? detail.riskScore : 0;

  if (userId === undefined) {
    deps.logger.warn('Alert event had no userId; ignoring.', { detailType: event['detail-type'] });
    return;
  }

  // A wellbeing concern is routed to the support channel, never as enforcement.
  if (event['detail-type'] === 'WellbeingConcern') {
    await deps.notifier.send({
      subject: 'TalkinShield: wellbeing concern detected',
      body: [
        'A message indicated possible risk to the sender rather than abuse of another participant.',
        '',
        `Room: ${typeof detail.roomId === 'string' ? detail.roomId : 'unknown'}`,
        '',
        'This is routed for a wellbeing response. No moderation action has been taken, and none',
        'should be taken on the basis of this signal alone.',
      ].join('\n'),
      level: 'WELLBEING',
      dedupeKey: `wellbeing:${userId}`,
    });
    return;
  }

  if ((LEVEL_ORDER[level] ?? 0) < (LEVEL_ORDER[deps.env.alert.minLevel] ?? 2)) {
    return;
  }

  const signals = Array.isArray(detail.signals)
    ? detail.signals
        .filter((s): s is { code?: unknown; reason?: unknown } => typeof s === 'object' && s !== null)
        .map((s) => `  - [${String(s.code)}] ${String(s.reason)}`)
    : [];

  const notes = Array.isArray(detail.telemetryNotes)
    ? detail.telemetryNotes.filter((n): n is string => typeof n === 'string')
    : [];

  const nowMs = deps.clock.now();

  const result = await deps.notifier.send({
    subject: `TalkinShield ${level}: risk ${score}/100`,
    body: [
      `Risk level ${level} (${score}/100).`,
      `Room: ${typeof detail.roomId === 'string' ? detail.roomId : 'unknown'}`,
      typeof detail.incidentId === 'string'
        ? `Incident: ${detail.incidentId}`
        : 'Incident: not created',
      '',
      'Detection reasons:',
      ...(signals.length > 0 ? signals : ['  (none recorded)']),
      ...(notes.length > 0 ? ['', 'Telemetry limitations that applied to this assessment:', ...notes.map((n) => `  - ${n}`)] : []),
      '',
      'Recommended actions are available in the TalkinShield console. No durable penalty has been',
      'applied automatically beyond any temporary, reversible restriction noted on the incident.',
    ].join('\n'),
    level,
    dedupeKey: `alert:${userId}:${level}`,
  });

  await deps.audit.append({
    auditId: newAuditId(),
    atMs: nowMs,
    actorId: 'system',
    actorKind: 'SYSTEM',
    action: 'ALERT_DISPATCHED',
    target: userId,
    reason: `Risk level ${level} met the configured alert threshold of ${deps.env.alert.minLevel}.`,
    outcome: result.sent ? 'SUCCESS' : 'FAILURE',
    detail: {
      riskLevel: level,
      riskScore: score,
      suppressed: result.suppressed === true,
      ...(typeof detail.incidentId === 'string' ? { incidentId: detail.incidentId } : {}),
    },
    ttlEpochSeconds: Math.floor((nowMs + deps.env.retentionDays.audit * 86_400_000) / 1000),
  });
}
