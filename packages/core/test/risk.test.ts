import test from 'node:test';
import assert from 'node:assert/strict';

import { DEFAULT_CONFIG, resolveConfig, validateConfigPatch } from '../src/config/detection-config.ts';
import { assessRisk, carryForward, levelFor, levelRange } from '../src/risk/engine.ts';
import { actionAffordances, planResponse } from '../src/response/policy.ts';
import type { DetectionSignal, SignalCode } from '../src/types/detection.ts';
import { FULL_CAPS, MINIMAL_CAPS, T0 } from './helpers.ts';

const riskCfg = DEFAULT_CONFIG.risk;

function sig(
  code: SignalCode,
  confidence = 1,
  detector = 'spam-detector@1.2.0',
): DetectionSignal {
  return {
    code,
    category: 'SPAM',
    severity: 'MEDIUM',
    confidence,
    reason: `test signal ${code}`,
    evidenceEventIds: ['e1'],
    detector,
    observedAtMs: T0,
  };
}

// --- Level banding (exact ranges from the brief) ---------------------------

test('risk: level bands match the specified ranges', () => {
  assert.equal(levelFor(0, riskCfg), 'LOW');
  assert.equal(levelFor(24, riskCfg), 'LOW');
  assert.equal(levelFor(25, riskCfg), 'MEDIUM');
  assert.equal(levelFor(49, riskCfg), 'MEDIUM');
  assert.equal(levelFor(50, riskCfg), 'HIGH');
  assert.equal(levelFor(74, riskCfg), 'HIGH');
  assert.equal(levelFor(75, riskCfg), 'CRITICAL');
  assert.equal(levelFor(100, riskCfg), 'CRITICAL');
});

test('risk: level ranges render as the documented labels', () => {
  assert.equal(levelRange('LOW', riskCfg), '0-24');
  assert.equal(levelRange('MEDIUM', riskCfg), '25-49');
  assert.equal(levelRange('HIGH', riskCfg), '50-74');
  assert.equal(levelRange('CRITICAL', riskCfg), '75-100');
});

// --- Weighting ------------------------------------------------------------

test('risk: default weights match the brief\'s weighting table', () => {
  assert.equal(riskCfg.weights.SPAM_IDENTICAL_REPEAT, 20);
  assert.equal(riskCfg.weights.ABUSE_SEVERE, 30);
  assert.equal(riskCfg.weights.THREAT_LANGUAGE, 40);
  assert.equal(riskCfg.weights.CLIENT_ABNORMAL_REQUEST_RATE, 20);
  assert.equal(riskCfg.weights.SPAM_HIGH_FREQUENCY, 20);
  assert.equal(riskCfg.repeatViolationWeight, 25);
  assert.equal(riskCfg.weights.EVASION_POST_MODERATION_ACTIVITY, 25);
});

test('risk: signals accumulate into a score', () => {
  const a = assessRisk({
    userId: 'u1',
    signals: [sig('SPAM_IDENTICAL_REPEAT'), sig('SPAM_HIGH_FREQUENCY')],
    config: riskCfg,
    nowMs: T0,
  });
  assert.equal(a.score, 40);
  assert.equal(a.level, 'MEDIUM');
  assert.equal(a.contributions.length, 2);
});

test('risk: the worked example from the brief reaches HIGH/CRITICAL', () => {
  // Spam + severe abuse + suspicious client + extreme frequency.
  const a = assessRisk({
    userId: '8F29A1',
    roomId: 'ABC123',
    signals: [
      sig('SPAM_IDENTICAL_REPEAT'),
      sig('ABUSE_SEVERE', 1, 'abuse-classifier@1.3.0'),
      sig('CLIENT_ABNORMAL_REQUEST_RATE'),
      sig('SPAM_HIGH_FREQUENCY'),
    ],
    config: riskCfg,
    nowMs: T0,
  });
  assert.ok(a.score >= 75, `expected CRITICAL-range score, got ${a.score}`);
  assert.equal(a.level, 'CRITICAL');
});

test('risk: score is clamped to 100', () => {
  const a = assessRisk({
    userId: 'u1',
    signals: [
      sig('THREAT_LANGUAGE'),
      sig('ABUSE_SEVERE'),
      sig('SPAM_IDENTICAL_REPEAT'),
      sig('EVASION_POST_MODERATION_ACTIVITY'),
      sig('COORDINATED_IDENTICAL_CONTENT'),
      sig('BOT_UNIFORM_TIMING'),
    ],
    config: riskCfg,
    nowMs: T0,
  });
  assert.equal(a.score, 100);
});

test('risk: duplicate signal codes count once, at their strongest', () => {
  const a = assessRisk({
    userId: 'u1',
    signals: [
      sig('SPAM_IDENTICAL_REPEAT', 0.6),
      sig('SPAM_IDENTICAL_REPEAT', 1),
      sig('SPAM_IDENTICAL_REPEAT', 0.8),
    ],
    config: riskCfg,
    nowMs: T0,
  });
  assert.equal(a.contributions.length, 1);
  assert.equal(a.score, 20);
  assert.equal(a.contributions[0]?.confidence, 1);
});

test('risk: low confidence contributes proportionally less', () => {
  const confident = assessRisk({
    userId: 'u1',
    signals: [sig('THREAT_LANGUAGE', 1)],
    config: riskCfg,
    nowMs: T0,
  });
  const tentative = assessRisk({
    userId: 'u1',
    signals: [sig('THREAT_LANGUAGE', 0.2)],
    config: riskCfg,
    nowMs: T0,
  });
  assert.ok(
    tentative.score < confident.score,
    `low-confidence signal must score lower (${tentative.score} vs ${confident.score})`,
  );
  assert.equal(tentative.score, 16); // 40 * (0.2 / 0.5)
});

test('risk: no single signal can exceed maxSingleContribution', () => {
  const cfg = { ...riskCfg, weights: { ...riskCfg.weights, THREAT_LANGUAGE: 95 } };
  const a = assessRisk({ userId: 'u1', signals: [sig('THREAT_LANGUAGE')], config: cfg, nowMs: T0 });
  assert.equal(a.score, cfg.maxSingleContribution);
});

test('risk: history alone never raises a score without a current finding', () => {
  const a = assessRisk({
    userId: 'u1',
    signals: [],
    config: riskCfg,
    nowMs: T0,
    priorViolations: 10,
  });
  assert.equal(a.score, 0);
  assert.equal(a.level, 'LOW');
});

test('risk: repeat-violation bonus is capped', () => {
  const a = assessRisk({
    userId: 'u1',
    signals: [sig('SPAM_IDENTICAL_REPEAT')],
    config: riskCfg,
    nowMs: T0,
    priorViolations: 50,
  });
  assert.equal(a.score, 20 + riskCfg.maxRepeatBonus);
});

test('risk: carried history decays over time', () => {
  const recent = assessRisk({
    userId: 'u1',
    signals: [sig('SPAM_BURST')],
    config: riskCfg,
    nowMs: T0,
    carriedRisk: 80,
    lastAssessedAtMs: T0,
  });
  const stale = assessRisk({
    userId: 'u1',
    signals: [sig('SPAM_BURST')],
    config: riskCfg,
    nowMs: T0 + 7 * 24 * 60 * 60 * 1000,
    carriedRisk: 80,
    lastAssessedAtMs: T0,
  });
  assert.ok(recent.historyComponent > stale.historyComponent);
  assert.ok(stale.historyComponent < 1, `a week later history should be near zero, got ${stale.historyComponent}`);
});

test('risk: carryForward dampens rather than ratchets', () => {
  const a = assessRisk({ userId: 'u1', signals: [sig('THREAT_LANGUAGE')], config: riskCfg, nowMs: T0 });
  assert.ok(carryForward(a) < a.score);
});

test('risk: deterministicOnly is false when an AI verdict contributed', () => {
  const withAi = assessRisk({
    userId: 'u1',
    signals: [sig('ABUSE_SEVERE', 1, 'abuse-classifier@1.3.0')],
    config: riskCfg,
    nowMs: T0,
    aiContributed: true,
  });
  const withoutAi = assessRisk({
    userId: 'u1',
    signals: [sig('SPAM_BURST')],
    config: riskCfg,
    nowMs: T0,
  });
  assert.equal(withAi.deterministicOnly, false);
  assert.equal(withoutAi.deterministicOnly, true);
});

test('risk: unknown or zero-weight signals do not affect the score', () => {
  const cfg = { ...riskCfg, weights: { ...riskCfg.weights, SPAM_SUSPICIOUS_CHARACTERS: 0 } };
  const a = assessRisk({
    userId: 'u1',
    signals: [sig('SPAM_SUSPICIOUS_CHARACTERS')],
    config: cfg,
    nowMs: T0,
  });
  assert.equal(a.score, 0);
  assert.equal(a.contributions.length, 0);
});

test('risk: contributions are ordered by impact and carry their reasons', () => {
  const a = assessRisk({
    userId: 'u1',
    signals: [sig('SPAM_SUSPICIOUS_CHARACTERS'), sig('THREAT_LANGUAGE'), sig('SPAM_BURST')],
    config: riskCfg,
    nowMs: T0,
  });
  const applied = a.contributions.map((c) => c.applied);
  assert.deepEqual(applied, [...applied].sort((x, y) => y - x));
  for (const c of a.contributions) assert.ok(c.reason.length > 0);
});

// --- Configurability ------------------------------------------------------

test('config: operator overrides merge over defaults without losing other keys', () => {
  const merged = resolveConfig({
    risk: { weights: { THREAT_LANGUAGE: 55 } },
    spam: { burstCount: 3 },
  });
  assert.equal(merged.risk.weights.THREAT_LANGUAGE, 55);
  assert.equal(merged.risk.weights.ABUSE_SEVERE, 30, 'untouched weights must survive the merge');
  assert.equal(merged.spam.burstCount, 3);
  assert.equal(merged.spam.burstWindowMs, DEFAULT_CONFIG.spam.burstWindowMs);
});

test('config: invalid patches are rejected with explanations', () => {
  assert.deepEqual(validateConfigPatch({}), []);

  const badWeight = validateConfigPatch({ risk: { weights: { THREAT_LANGUAGE: 500 } } });
  assert.equal(badWeight.length, 1);
  assert.match(badWeight[0] as string, /between 0 and 100/);

  const badThresholds = validateConfigPatch({ risk: { thresholds: { HIGH: 10, MEDIUM: 40 } } });
  assert.ok(badThresholds.some((p) => /strictly increasing/.test(p)));

  const badSpam = validateConfigPatch({ spam: { burstCount: 0 } });
  assert.ok(badSpam.some((p) => /greater than 0/.test(p)));

  const unsafeConfidence = validateConfigPatch({ abuse: { autoActionMinConfidence: 0.1 } });
  assert.ok(unsafeConfidence.some((p) => /low-confidence predictions/.test(p)));

  const badRetention = validateConfigPatch({ retention: { evidenceDays: 99999 } });
  assert.ok(badRetention.some((p) => /between 1 and 3650 days/.test(p)));
});

test('config: custom thresholds change the resulting level', () => {
  const cfg = resolveConfig({ risk: { thresholds: { LOW: 0, MEDIUM: 10, HIGH: 20, CRITICAL: 30 } } });
  assert.equal(levelFor(25, cfg.risk), 'HIGH');
  assert.equal(levelFor(35, cfg.risk), 'CRITICAL');
});

// --- Response policy ------------------------------------------------------

test('policy: LOW only logs', () => {
  const a = assessRisk({ userId: 'u1', signals: [], config: riskCfg, nowMs: T0 });
  const plan = planResponse({ assessment: a, config: DEFAULT_CONFIG, capabilities: FULL_CAPS });
  assert.deepEqual(plan.automated, ['LOG']);
});

test('policy: MEDIUM increases monitoring', () => {
  const a = assessRisk({
    userId: 'u1',
    signals: [sig('SPAM_IDENTICAL_REPEAT'), sig('SPAM_MENTION_FLOOD')],
    config: riskCfg,
    nowMs: T0,
  });
  assert.equal(a.level, 'MEDIUM');
  const plan = planResponse({ assessment: a, config: DEFAULT_CONFIG, capabilities: FULL_CAPS });
  assert.ok(plan.automated.includes('INCREASE_MONITORING'));
  assert.ok(!plan.automated.includes('PLATFORM_TEMPORARY_BLOCK'));
});

test('policy: HIGH recommends mute/block/report but acts on none of them', () => {
  const a = assessRisk({
    userId: 'u1',
    signals: [sig('SPAM_IDENTICAL_REPEAT'), sig('SPAM_HIGH_FREQUENCY'), sig('BOT_UNIFORM_TIMING')],
    config: riskCfg,
    nowMs: T0,
  });
  assert.equal(a.level, 'HIGH');
  const plan = planResponse({ assessment: a, config: DEFAULT_CONFIG, capabilities: FULL_CAPS });
  assert.deepEqual(plan.recommended, ['MUTE', 'BLOCK', 'REPORT']);
  assert.ok(!plan.automated.includes('PLATFORM_TEMPORARY_BLOCK'));
});

test('policy: CRITICAL creates an incident, preserves evidence and notifies', () => {
  const a = assessRisk({
    userId: 'u1',
    signals: [sig('THREAT_LANGUAGE'), sig('ABUSE_SEVERE'), sig('SPAM_BURST')],
    config: riskCfg,
    nowMs: T0,
  });
  assert.equal(a.level, 'CRITICAL');
  const plan = planResponse({ assessment: a, config: DEFAULT_CONFIG, capabilities: FULL_CAPS });
  assert.ok(plan.automated.includes('CREATE_INCIDENT'));
  assert.ok(plan.automated.includes('PRESERVE_EVIDENCE'));
  assert.ok(plan.automated.includes('NOTIFY_MODERATOR'));
  assert.ok(plan.automated.includes('PLATFORM_TEMPORARY_BLOCK'));
  assert.match(plan.rationale, /temporary, reversible/);
});

test('policy: CRITICAL will NOT auto-block without a platform API', () => {
  const a = assessRisk({
    userId: 'u1',
    signals: [sig('THREAT_LANGUAGE'), sig('ABUSE_SEVERE'), sig('SPAM_BURST')],
    config: riskCfg,
    nowMs: T0,
  });
  const plan = planResponse({ assessment: a, config: DEFAULT_CONFIG, capabilities: MINIMAL_CAPS });
  assert.ok(!plan.automated.includes('PLATFORM_TEMPORARY_BLOCK'));
  assert.equal(plan.platformActionUnavailable, true);
  assert.match(plan.rationale, /local mute, local block, ignore, report and evidence capture/);
  assert.match(plan.rationale, /will not attempt to restrict another account/);
});

test('policy: CRITICAL will NOT auto-block on low confidence', () => {
  const a = assessRisk({
    userId: 'u1',
    signals: [
      sig('THREAT_LANGUAGE', 0.55),
      sig('ABUSE_SEVERE', 0.55),
      sig('SPAM_BURST', 0.55),
      sig('BOT_UNIFORM_TIMING', 0.55),
      sig('EVASION_REJOIN_CYCLING', 0.55),
    ],
    config: riskCfg,
    nowMs: T0,
  });
  assert.equal(a.level, 'CRITICAL');
  const plan = planResponse({ assessment: a, config: DEFAULT_CONFIG, capabilities: FULL_CAPS });
  assert.ok(!plan.automated.includes('PLATFORM_TEMPORARY_BLOCK'));
  assert.match(plan.rationale, /below the required/);
});

test('policy: CRITICAL will NOT auto-block on AI-only escalation', () => {
  const a = assessRisk({
    userId: 'u1',
    signals: [
      sig('ABUSE_SEVERE', 0.95, 'abuse-classifier@1.3.0'),
      sig('THREAT_LANGUAGE', 0.95, 'abuse-classifier@1.3.0'),
      sig('ABUSE_REPEATED', 0.95, 'abuse-classifier@1.3.0'),
    ],
    config: riskCfg,
    nowMs: T0,
    aiContributed: true,
  });
  assert.equal(a.level, 'CRITICAL');
  const plan = planResponse({ assessment: a, config: DEFAULT_CONFIG, capabilities: FULL_CAPS });
  assert.ok(!plan.automated.includes('PLATFORM_TEMPORARY_BLOCK'));
  assert.match(plan.rationale, /without a corroborating deterministic signal/);
});

test('policy: human-review flag blocks automated platform action', () => {
  const a = assessRisk({
    userId: 'u1',
    signals: [sig('THREAT_LANGUAGE'), sig('ABUSE_SEVERE'), sig('SPAM_BURST')],
    config: riskCfg,
    nowMs: T0,
  });
  const plan = planResponse({
    assessment: a,
    config: DEFAULT_CONFIG,
    capabilities: FULL_CAPS,
    requiresHumanReview: true,
  });
  assert.ok(!plan.automated.includes('PLATFORM_TEMPORARY_BLOCK'));
  assert.match(plan.rationale, /flagged this decision for human review/);
});

test('policy: a threat escalates to a human even at a low aggregate score', () => {
  const a = assessRisk({
    userId: 'u1',
    signals: [sig('THREAT_LANGUAGE', 0.3)],
    config: riskCfg,
    nowMs: T0,
  });
  assert.notEqual(a.level, 'CRITICAL');
  const plan = planResponse({
    assessment: a,
    config: DEFAULT_CONFIG,
    capabilities: FULL_CAPS,
    abuseClassification: 'THREAT',
  });
  assert.ok(plan.automated.includes('NOTIFY_MODERATOR'));
  assert.ok(plan.automated.includes('CREATE_INCIDENT'));
  assert.ok(plan.recommended.includes('REPORT'));
});

test('policy: affordances describe their true scope honestly', () => {
  const withApi = actionAffordances(FULL_CAPS);
  const withoutApi = actionAffordances(MINIMAL_CAPS);

  const muteWith = withApi.find((a) => a.action === 'MUTE');
  const muteWithout = withoutApi.find((a) => a.action === 'MUTE');
  assert.equal(muteWith?.scope, 'PLATFORM_API');
  assert.equal(muteWithout?.scope, 'LOCAL_TO_REQUESTER');
  assert.match(muteWithout?.description ?? '', /local/i);
  assert.match(muteWithout?.description ?? '', /other participants are unaffected/);

  // Local protections are always offered, because they need no authority
  // over anyone else's account.
  for (const a of withoutApi) assert.equal(a.enabled, true);
});
