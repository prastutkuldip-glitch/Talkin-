/**
 * Configurable risk engine.
 *
 * Converts a set of detection signals plus prior history into a 0-100 score and
 * a risk level. Every number used is operator-configurable from the admin
 * dashboard (`RiskConfig`).
 *
 * Safety properties encoded here:
 *   - Confidence scaling: a weight is only applied in full at high confidence.
 *     A tentative finding contributes proportionally less, so a single weak
 *     prediction cannot escalate a user.
 *   - Per-signal cap: no single signal can dominate the score.
 *   - Deduplication: repeated signals of the same code within one pass count
 *     once at their strongest, so a noisy detector cannot inflate a score.
 *   - `deterministicOnly` records whether any AI-derived signal contributed, so
 *     downstream policy can refuse to auto-act on AI-only escalation.
 *   - History decays exponentially: a user is not punished forever for one bad
 *     evening.
 */

import type { RiskConfig } from '../config/detection-config.ts';
import type { DetectionSignal } from '../types/detection.ts';
import type { RiskAssessment, RiskContribution, RiskLevel } from '../types/risk.ts';
import { clamp, decay, round } from '../util/stats.ts';

export const RISK_ENGINE_VERSION = 'risk-engine@1.1.0';

/** Detectors whose output is partly or wholly AI-derived. */
const AI_ASSISTED_DETECTORS = ['abuse-classifier'];

export interface RiskInput {
  userId: string;
  roomId?: string;
  signals: readonly DetectionSignal[];
  config: RiskConfig;
  nowMs: number;
  /** Count of prior confirmed violations for this account. */
  priorViolations?: number;
  /** Count of detected evasion episodes. */
  evasionCount?: number;
  /** Risk carried from the previous assessment (0-100). */
  carriedRisk?: number;
  /** Epoch ms of the previous assessment, used to decay carried risk. */
  lastAssessedAtMs?: number;
  /** True when at least one contributing signal involved an AI verdict. */
  aiContributed?: boolean;
}

export function assessRisk(input: RiskInput): RiskAssessment {
  const { config, nowMs } = input;

  // --- Deduplicate: strongest instance of each signal code wins -----------
  const strongest = new Map<string, DetectionSignal>();
  for (const signal of input.signals) {
    const existing = strongest.get(signal.code);
    if (!existing || signal.confidence > existing.confidence) {
      strongest.set(signal.code, signal);
    }
  }

  const contributions: RiskContribution[] = [];
  let signalTotal = 0;
  let peakConfidence = 0;
  let aiInvolved = input.aiContributed === true;

  for (const signal of strongest.values()) {
    const weight = config.weights[signal.code] ?? 0;
    if (weight <= 0) continue;

    const scaled = applyConfidenceScaling(weight, signal.confidence, config);
    const applied = Math.min(scaled, config.maxSingleContribution);

    contributions.push({
      code: signal.code,
      weight,
      applied: round(applied, 2),
      confidence: signal.confidence,
      reason: signal.reason,
    });

    signalTotal += applied;
    if (signal.confidence > peakConfidence) peakConfidence = signal.confidence;
    if (AI_ASSISTED_DETECTORS.some((d) => signal.detector.startsWith(d))) aiInvolved = true;
  }

  // --- Repeat-violation bonus --------------------------------------------
  const priorViolations = input.priorViolations ?? 0;
  const evasionCount = input.evasionCount ?? 0;
  // Prior violations and prior successful evasion both count as history: an
  // account that has previously worked around moderation is a higher risk than
  // one with the same number of violations and no evasion.
  const historyUnits = priorViolations + evasionCount;

  let repeatBonus = 0;
  if (historyUnits > 0 && contributions.length > 0) {
    // Only applied when there is a current finding — history alone never
    // raises a user's score in isolation.
    repeatBonus = Math.min(historyUnits * config.repeatViolationWeight, config.maxRepeatBonus);
    const parts = [
      priorViolations > 0 ? `${priorViolations} prior confirmed violation(s)` : '',
      evasionCount > 0 ? `${evasionCount} prior moderation-evasion episode(s)` : '',
    ].filter((p) => p.length > 0);
    contributions.push({
      code: evasionCount > 0 ? 'EVASION_POST_MODERATION_ACTIVITY' : 'ABUSE_REPEATED',
      weight: config.repeatViolationWeight,
      applied: round(repeatBonus, 2),
      confidence: 1,
      reason: `${parts.join(' and ')} on this account (capped contribution of ${config.maxRepeatBonus}).`,
    });
  }

  // --- Decayed history --------------------------------------------------
  let historyComponent = 0;
  if (input.carriedRisk !== undefined && input.carriedRisk > 0) {
    const elapsed = input.lastAssessedAtMs !== undefined ? nowMs - input.lastAssessedAtMs : 0;
    historyComponent = clamp(
      decay(input.carriedRisk, Math.max(0, elapsed), config.historyHalfLifeMs),
      0,
      config.maxHistoryComponent,
    );
  }

  const raw = signalTotal + repeatBonus + historyComponent;
  const score = Math.round(clamp(raw, 0, 100));

  return {
    userId: input.userId,
    ...(input.roomId !== undefined ? { roomId: input.roomId } : {}),
    score,
    level: levelFor(score, config),
    contributions: contributions.sort((a, b) => b.applied - a.applied),
    historyComponent: round(historyComponent, 2),
    peakConfidence: round(peakConfidence, 4),
    deterministicOnly: !aiInvolved,
    assessedAtMs: nowMs,
    engineVersion: RISK_ENGINE_VERSION,
  };
}

/**
 * Scale a weight by confidence.
 *
 * At or above the scaling floor the full weight applies; below it the weight is
 * reduced proportionally. This keeps high-confidence deterministic findings at
 * their configured strength while damping speculative ones.
 */
function applyConfidenceScaling(weight: number, confidence: number, config: RiskConfig): number {
  const floor = clamp(config.confidenceScalingFloor, 0.01, 1);
  if (confidence >= floor) return weight;
  return weight * (confidence / floor);
}

export function levelFor(score: number, config: RiskConfig): RiskLevel {
  const t = config.thresholds;
  if (score >= t.CRITICAL) return 'CRITICAL';
  if (score >= t.HIGH) return 'HIGH';
  if (score >= t.MEDIUM) return 'MEDIUM';
  return 'LOW';
}

/** Human-readable range label, e.g. "50-74" — used by the dashboard legend. */
export function levelRange(level: RiskLevel, config: RiskConfig): string {
  const t = config.thresholds;
  switch (level) {
    case 'LOW':
      return `${t.LOW}-${t.MEDIUM - 1}`;
    case 'MEDIUM':
      return `${t.MEDIUM}-${t.HIGH - 1}`;
    case 'HIGH':
      return `${t.HIGH}-${t.CRITICAL - 1}`;
    case 'CRITICAL':
      return `${t.CRITICAL}-100`;
    default:
      return '';
  }
}

/**
 * Carried risk for the next pass. Deliberately a fraction of the current score
 * so that risk fades rather than ratchets upward across passes.
 */
export function carryForward(assessment: RiskAssessment): number {
  return round(assessment.score * 0.4, 2);
}
