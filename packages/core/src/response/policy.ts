/**
 * Automated response policy.
 *
 * Maps a risk assessment onto (a) actions the system performs itself and
 * (b) actions it merely *recommends* to a human moderator.
 *
 * HARD CONSTRAINTS encoded in this module:
 *
 *   1. No durable penalty is ever applied on the strength of a single AI
 *      prediction. A platform-side block requires BOTH high confidence AND at
 *      least one deterministic (non-AI) contributing signal.
 *   2. Mute / block / report against another account are *recommendations*.
 *      They are surfaced as buttons and only executed when a moderator presses
 *      them, or — at CRITICAL — as a reversible temporary restriction.
 *   3. If the platform grants no moderation API, the system never pretends
 *      otherwise. It falls back to protections scoped to the requesting user
 *      (local mute, block, ignore, report, evidence capture) and reports the
 *      platform action as unavailable.
 *   4. Every automated action returns a record with a mandatory reason, so the
 *      audit trail can always explain why something happened.
 */

import type { DetectionConfig } from '../config/detection-config.ts';
import type { RecommendedAction } from '../types/detection.ts';
import type {
  IntegrationCapabilities,
} from '../types/telemetry.ts';
import type { ResponseAction, ResponsePlan, RiskAssessment } from '../types/risk.ts';

export const POLICY_VERSION = 'response-policy@1.1.0';

export interface PolicyInput {
  assessment: RiskAssessment;
  config: DetectionConfig;
  capabilities: IntegrationCapabilities;
  /** Highest abuse classification seen this pass, when any. */
  abuseClassification?: 'SAFE' | 'ABUSIVE' | 'SEVERE_ABUSE' | 'THREAT' | 'UNCERTAIN';
  /** True when the abuse layer flagged the decision for human review. */
  requiresHumanReview?: boolean;
}

export function planResponse(input: PolicyInput): ResponsePlan {
  const { assessment, config, capabilities } = input;
  const automated: ResponseAction[] = ['LOG'];
  const recommended: RecommendedAction[] = [];
  const notes: string[] = [];
  let platformActionUnavailable = false;

  const level = assessment.level;

  if (level === 'MEDIUM' || level === 'HIGH' || level === 'CRITICAL') {
    automated.push('INCREASE_MONITORING');
  }

  if (level === 'HIGH' || level === 'CRITICAL') {
    automated.push('RECOMMEND_MUTE', 'RECOMMEND_BLOCK', 'RECOMMEND_REPORT');
    recommended.push('MUTE', 'BLOCK', 'REPORT');
  }

  if (level === 'CRITICAL') {
    automated.push('CREATE_INCIDENT', 'PRESERVE_EVIDENCE', 'NOTIFY_MODERATOR');

    // Gate on the two-key rule: confident AND corroborated by deterministic logic.
    const confident = assessment.peakConfidence >= config.risk.criticalAutoActionMinConfidence;
    const corroborated = assessment.deterministicOnly || hasDeterministicContribution(assessment);

    if (!confident) {
      notes.push(
        `No automated platform restriction applied: peak signal confidence ${assessment.peakConfidence.toFixed(2)} is below the required ${config.risk.criticalAutoActionMinConfidence} for automated action.`,
      );
    } else if (!corroborated) {
      notes.push(
        'No automated platform restriction applied: the escalation rests on AI classification without a corroborating deterministic signal. Queued for moderator decision instead.',
      );
    } else if (input.requiresHumanReview === true) {
      notes.push(
        'No automated platform restriction applied: the abuse classifier flagged this decision for human review.',
      );
    } else if (!capabilities.remoteBlock) {
      platformActionUnavailable = true;
      notes.push(
        'A temporary platform restriction is warranted, but the connected Talkin integration grants no official block API. ' +
          'Falling back to protections scoped to the requesting user: local mute, local block, ignore, report and evidence capture. ' +
          'TalkinShield will not attempt to restrict another account by any unofficial means.',
      );
    } else {
      // Temporary and reversible by design — never a permanent ban from a
      // single automated decision.
      automated.push('PLATFORM_TEMPORARY_BLOCK');
      notes.push(
        'Applied a temporary, reversible platform restriction via the official moderation API pending moderator review. A permanent penalty requires explicit human confirmation.',
      );
    }
  }

  // Threats always reach a human, regardless of the numeric score.
  if (input.abuseClassification === 'THREAT') {
    pushUnique(automated, 'NOTIFY_MODERATOR');
    pushUnique(automated, 'CREATE_INCIDENT');
    pushUnique(automated, 'PRESERVE_EVIDENCE');
    pushUnique(recommended, 'REPORT');
    notes.push('Threat language detected: escalated to a moderator irrespective of aggregate score.');
  }

  if (recommended.length === 0) {
    recommended.push(level === 'MEDIUM' ? 'WARN' : 'NONE');
  }

  // Local-only protections are always available to the protected user, because
  // they require no authority over anyone else's account.
  if (!capabilities.remoteMute && (level === 'HIGH' || level === 'CRITICAL')) {
    notes.push(
      'No official platform mute API is configured; MUTE is offered as a local mute for the protected user only.',
    );
  }

  return {
    level,
    automated: dedupe(automated),
    recommended: dedupe(recommended),
    platformActionUnavailable,
    rationale: buildRationale(assessment, notes),
  };
}

function hasDeterministicContribution(assessment: RiskAssessment): boolean {
  // Any contribution from a non-abuse detector counts as deterministic
  // corroboration: spam, frequency, client-integrity and evasion detectors are
  // all rule-based.
  return assessment.contributions.some(
    (c) =>
      c.code.startsWith('SPAM_') ||
      c.code.startsWith('BOT_') ||
      c.code.startsWith('CLIENT_') ||
      c.code.startsWith('EVASION_') ||
      c.code.startsWith('COORDINATED_'),
  );
}

function buildRationale(assessment: RiskAssessment, notes: readonly string[]): string {
  const top = assessment.contributions.slice(0, 3).map((c) => `${c.code} (+${c.applied})`);
  const base = `Risk ${assessment.score}/100 (${assessment.level}).${
    top.length > 0 ? ` Principal contributors: ${top.join(', ')}.` : ''
  }`;
  return notes.length > 0 ? `${base} ${notes.join(' ')}` : base;
}

function pushUnique<T>(list: T[], value: T): void {
  if (!list.includes(value)) list.push(value);
}

function dedupe<T>(list: readonly T[]): T[] {
  return [...new Set(list)];
}

/**
 * Which moderator buttons should be enabled, and with what scope.
 *
 * The dashboard renders exactly this: a label plus an honest description of
 * what the button will actually do given current authorization.
 */
export interface ActionAffordance {
  action: RecommendedAction | 'SAVE_EVIDENCE';
  enabled: boolean;
  scope: 'LOCAL_TO_REQUESTER' | 'PLATFORM_API' | 'INTERNAL';
  label: string;
  description: string;
}

export function actionAffordances(capabilities: IntegrationCapabilities): ActionAffordance[] {
  return [
    {
      action: 'MUTE',
      enabled: true,
      scope: capabilities.remoteMute ? 'PLATFORM_API' : 'LOCAL_TO_REQUESTER',
      label: 'MUTE',
      description: capabilities.remoteMute
        ? 'Mutes the account in this room via the official Talkin moderation API.'
        : 'Mutes this account locally for the protected user only. No official platform mute API is configured, so other participants are unaffected.',
    },
    {
      action: 'BLOCK',
      enabled: true,
      scope: capabilities.remoteBlock ? 'PLATFORM_API' : 'LOCAL_TO_REQUESTER',
      label: 'BLOCK',
      description: capabilities.remoteBlock
        ? 'Applies a reversible platform-side block via the official Talkin moderation API.'
        : 'Blocks this account locally for the protected user only. No official platform block API is configured.',
    },
    {
      action: 'REPORT',
      enabled: true,
      scope: 'PLATFORM_API',
      label: 'REPORT',
      description:
        'Submits a report with the attached evidence bundle through the official reporting channel.',
    },
    {
      action: 'SAVE_EVIDENCE',
      enabled: true,
      scope: 'INTERNAL',
      label: 'SAVE EVIDENCE',
      description:
        'Writes an immutable, hash-chained evidence bundle to encrypted storage for later review.',
    },
  ];
}
