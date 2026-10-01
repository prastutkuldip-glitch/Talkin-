/**
 * Overview aggregation for the dashboard landing page.
 *
 * Deliberately computed from stored signals/incidents rather than recomputed
 * detection, so the Overview is a cheap read and always consistent with what the
 * Incidents and Users pages show.
 */

import { levelRange, type DetectionConfig, type RiskLevel } from '@talkinshield/core';

import type {
  ActionStore,
  IncidentStore,
  Logger,
  SignalStore,
  UserStateStore,
} from '../ports.ts';

export interface OverviewDeps {
  incidents: IncidentStore;
  signals: SignalStore;
  userState: UserStateStore;
  actions: ActionStore;
  logger: Logger;
}

export interface Overview {
  generatedAtMs: number;
  activeIncidents: number;
  highRiskUsers: number;
  spamEvents: number;
  abuseEvents: number;
  blockedEvents: number;
  recentIncidents: Array<{
    incidentId: string;
    userId: string;
    roomId?: string;
    riskScore: number;
    riskLevel: RiskLevel;
    status: string;
    createdAtMs: number;
    topBehaviors: string[];
  }>;
  riskDistribution: Array<{ level: RiskLevel; range: string; count: number }>;
  topSignals: Array<{ code: string; count: number }>;
}

export async function buildOverview(
  deps: OverviewDeps,
  config: DetectionConfig,
  nowMs: number,
): Promise<Overview> {
  const [openIncidents, recentIncidents, recentSignals, users, recentActions] = await Promise.all([
    deps.incidents.list({ status: 'OPEN', limit: 500 }),
    deps.incidents.list({ limit: 10 }),
    deps.signals.listRecent(1000),
    deps.userState.listHighRisk(500),
    deps.actions.listRecent(500),
  ]);

  const spamEvents = recentSignals.filter(
    (s) => s.category === 'SPAM' || s.category === 'FREQUENCY' || s.category === 'COORDINATION',
  ).length;
  const abuseEvents = recentSignals.filter(
    (s) => s.category === 'ABUSE' || s.category === 'THREAT',
  ).length;

  // "Blocked" counts only actions that actually took effect.
  const blockedEvents = recentActions.filter(
    (a) =>
      a.succeeded &&
      (a.actionType === 'PLATFORM_BLOCK' ||
        a.actionType === 'PLATFORM_TEMP_BLOCK' ||
        a.actionType === 'LOCAL_BLOCK'),
  ).length;

  const distribution = new Map<RiskLevel, number>([
    ['LOW', 0],
    ['MEDIUM', 0],
    ['HIGH', 0],
    ['CRITICAL', 0],
  ]);
  for (const user of users) {
    const level = user.riskLevel as RiskLevel;
    distribution.set(level, (distribution.get(level) ?? 0) + 1);
  }

  const signalCounts = new Map<string, number>();
  for (const signal of recentSignals) {
    signalCounts.set(signal.code, (signalCounts.get(signal.code) ?? 0) + 1);
  }

  return {
    generatedAtMs: nowMs,
    activeIncidents: openIncidents.length,
    highRiskUsers: users.filter((u) => u.riskLevel === 'HIGH' || u.riskLevel === 'CRITICAL').length,
    spamEvents,
    abuseEvents,
    blockedEvents,
    recentIncidents: recentIncidents.map((i) => ({
      incidentId: i.incidentId,
      userId: i.userId,
      ...(i.roomId !== undefined ? { roomId: i.roomId } : {}),
      riskScore: i.riskScore,
      riskLevel: i.riskLevel,
      status: i.status,
      createdAtMs: i.createdAtMs,
      topBehaviors: i.detectedBehaviors.slice(0, 4),
    })),
    riskDistribution: (['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'] as const).map((level) => ({
      level,
      range: levelRange(level, config.risk),
      count: distribution.get(level) ?? 0,
    })),
    topSignals: [...signalCounts.entries()]
      .map(([code, count]) => ({ code, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 8),
  };
}
