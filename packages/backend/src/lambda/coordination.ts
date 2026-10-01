/**
 * Coordination sweep Lambda (scheduled).
 *
 * Runs the cross-account coordination detector over each recently active room.
 * Scheduled rather than per-event because the detection is inherently
 * aggregate: "are several accounts behaving identically?" has no answer when
 * looking at one event.
 */

import type { Context, ScheduledEvent } from 'aws-lambda';

import { loadConfig } from '../app/analysis-service.ts';
import { activeRooms, sweepRoom } from '../app/coordination-service.ts';
import { container } from './container.ts';

export interface SweepSummary {
  roomsSwept: number;
  findings: number;
  accountsImplicated: number;
}

export async function handler(
  _event: ScheduledEvent,
  _context: Context,
): Promise<SweepSummary> {
  const deps = container();
  const { config } = await loadConfig(deps.rules);
  const log = deps.logger.child({ job: 'coordination-sweep' });

  const rooms = await activeRooms(deps);
  const summary: SweepSummary = { roomsSwept: 0, findings: 0, accountsImplicated: 0 };
  const implicated = new Set<string>();

  for (const roomId of rooms) {
    try {
      const result = await sweepRoom(roomId, config.spam, config.spam.sustainedWindowMs, deps);
      summary.roomsSwept += 1;
      summary.findings += result.findings.length;
      for (const finding of result.findings) {
        for (const userId of finding.userIds) implicated.add(userId);
      }
    } catch (err: unknown) {
      // One bad room must not abort the sweep.
      log.error('Coordination sweep failed for a room.', {
        roomId,
        error: err instanceof Error ? err.message : String(err),
      });
      deps.metrics.count('CoordinationSweepFailure');
    }
  }

  summary.accountsImplicated = implicated.size;
  log.info('Coordination sweep complete.', { ...summary });
  return summary;
}
