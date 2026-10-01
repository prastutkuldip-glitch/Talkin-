import test from 'node:test';
import assert from 'node:assert/strict';

import { DEFAULT_CONFIG } from '../src/config/detection-config.ts';
import { buildLexicon, classifyAbuse } from '../src/detection/abuse/classifier.ts';
import type { BedrockVerdict } from '../src/detection/abuse/classifier.ts';
import { T0, evt, hasCode } from './helpers.ts';

const cfg = DEFAULT_CONFIG.abuse;
const lexicon = buildLexicon(cfg, '1.0.0');

function classify(message: string, extra: Partial<Parameters<typeof classifyAbuse>[0]> = {}) {
  return classifyAbuse({
    event: evt({ message, receivedAtMs: T0 }),
    config: cfg,
    nowMs: T0,
    lexicon,
    ...extra,
  });
}

// --- The specified output contract ----------------------------------------

test('abuse: returns the contracted shape', () => {
  const { classification } = classify('hello everyone, nice to be here');
  assert.ok(['SAFE', 'ABUSIVE', 'SEVERE_ABUSE', 'THREAT', 'UNCERTAIN'].includes(classification.classification));
  assert.equal(typeof classification.confidence, 'number');
  assert.ok(classification.confidence >= 0 && classification.confidence <= 1);
  assert.equal(typeof classification.reason, 'string');
  assert.ok(classification.reason.length > 0);
  assert.ok(['NONE', 'WARN', 'MUTE', 'BLOCK', 'REPORT'].includes(classification.recommendedAction));
  assert.ok(classification.modelVersion.length > 0);
});

test('abuse: benign message is SAFE with no action', () => {
  const { classification, signals } = classify('Good game everyone, that was really fun!');
  assert.equal(classification.classification, 'SAFE');
  assert.equal(classification.recommendedAction, 'NONE');
  assert.deepEqual(signals, []);
});

// --- Threats --------------------------------------------------------------

test('abuse: direct violent threat is classified THREAT and reported', () => {
  const { classification, signals } = classify('i am going to kill you when i find you');
  assert.equal(classification.classification, 'THREAT');
  assert.equal(classification.recommendedAction, 'REPORT');
  assert.ok(classification.confidence >= 0.8);
  assert.ok(hasCode(signals, 'THREAT_LANGUAGE'));
});

test('abuse: location-based intimidation is a THREAT', () => {
  const { classification } = classify('i know where you live btw');
  assert.equal(classification.classification, 'THREAT');
});

test('abuse: doxxing threat is a THREAT', () => {
  const { classification } = classify("i will leak your address if you don't stop");
  assert.equal(classification.classification, 'THREAT');
});

test('abuse: swatting threat is a THREAT', () => {
  const { classification } = classify('im gonna send the cops to your house');
  assert.equal(classification.classification, 'THREAT');
});

test('abuse: threat detection survives letter-spacing evasion', () => {
  const { classification, signals } = classify('i w i l l k i l l y o u');
  assert.equal(classification.classification, 'THREAT');
  assert.ok(hasCode(signals, 'EVASION_FILTER_OBFUSCATION') || classification.confidence > 0.8);
});

// --- Severe abuse ---------------------------------------------------------

test('abuse: telling someone to kill themselves is SEVERE_ABUSE', () => {
  const { classification, signals } = classify('just kys already nobody wants you here');
  assert.equal(classification.classification, 'SEVERE_ABUSE');
  assert.ok(hasCode(signals, 'ABUSE_SEVERE'));
  assert.ok(['BLOCK', 'REPORT'].includes(classification.recommendedAction));
});

test('abuse: dehumanising eliminationist phrasing is SEVERE_ABUSE', () => {
  const { classification } = classify('all of them should be exterminated honestly');
  assert.equal(classification.classification, 'SEVERE_ABUSE');
});

// --- Targeted profanity ---------------------------------------------------

test('abuse: profanity directed at a participant is ABUSIVE', () => {
  const { classification, signals } = classify('you are such a fucking idiot bitch');
  assert.equal(classification.classification, 'ABUSIVE');
  assert.ok(hasCode(signals, 'ABUSE_LANGUAGE'));
  assert.ok(hasCode(signals, 'ABUSE_TARGETED_HARASSMENT'));
});

test('abuse: undirected profanity is only UNCERTAIN, never auto-penalised', () => {
  const { classification } = classify('ah shit, i missed the shot');
  assert.equal(classification.classification, 'UNCERTAIN');
  assert.equal(classification.recommendedAction, 'WARN');
  assert.ok(classification.requiresHumanReview);
});

test('abuse: obfuscated profanity still matches after normalization', () => {
  const { classification } = classify('you are a f\u200Bucking a$$hole');
  assert.notEqual(classification.classification, 'SAFE');
});

test('abuse: obfuscation attempt raises an evasion signal', () => {
  const { signals } = classify('you fu\u200Bcking bi\u200Btch');
  assert.ok(hasCode(signals, 'EVASION_FILTER_OBFUSCATION'));
});

// --- FALSE POSITIVE GUARDS ------------------------------------------------

test('false positive: quoted abuse when reporting another user is not penalised', () => {
  const { classification, mitigations } = classify(
    'mods he called me a fucking idiot and said he would kill me, please help',
  );
  assert.equal(classification.classification, 'SAFE');
  assert.ok(mitigations.length > 0);
});

test('false positive: explicitly negated intent is not a threat', () => {
  const { classification } = classify('i would never hurt you, i promise');
  assert.equal(classification.classification, 'SAFE');
});

test('false positive: in-game violence is not treated as a real threat', () => {
  const { classification } = classify('im gonna destroy you in the next round haha');
  assert.notEqual(classification.classification, 'THREAT');
  assert.ok(classification.requiresHumanReview || classification.classification === 'SAFE');
});

test('false positive: self-directed frustration is not abuse of others', () => {
  const { classification, selfHarmConcern } = classify('ugh im so stupid, i keep missing');
  assert.equal(classification.classification, 'SAFE');
  assert.equal(selfHarmConcern, false);
});

test('false positive: reported speech is downgraded, not enforced', () => {
  const { classification } = classify('someone told me to kys in the last room');
  assert.notEqual(classification.classification, 'SEVERE_ABUSE');
});

test('false positive: operator allow-list suppresses a community term', () => {
  const custom = { ...cfg, allowTerms: ['bastard'] };
  const customLexicon = buildLexicon(custom, '1.0.1');
  const { classification } = classifyAbuse({
    event: evt({ message: 'you magnificent bastard, well played', receivedAtMs: T0 }),
    config: custom,
    nowMs: T0,
    lexicon: customLexicon,
  });
  assert.equal(classification.classification, 'SAFE');
});

test('false positive: empty or whitespace message is SAFE, not an error', () => {
  assert.equal(classify('   ').classification.classification, 'SAFE');
  const noText = classifyAbuse({
    event: evt({ message: undefined, receivedAtMs: T0 }),
    config: cfg,
    nowMs: T0,
    lexicon,
  });
  assert.equal(noText.classification.classification, 'SAFE');
  assert.match(noText.classification.reason, /No message content/);
});

// --- Self-harm routing ----------------------------------------------------

test('self-harm language is detected as a wellbeing concern, not enforcement', () => {
  const { classification, selfHarmConcern } = classify('i dont want to live anymore');
  assert.equal(selfHarmConcern, true);
  // Must never become a punishment.
  assert.ok(['SAFE', 'UNCERTAIN'].includes(classification.classification));
  assert.notEqual(classification.recommendedAction, 'BLOCK');
});

// --- AI arbitration -------------------------------------------------------

test('AI alone cannot produce an enforceable verdict', () => {
  const bedrock: BedrockVerdict = {
    classification: 'SEVERE_ABUSE',
    confidence: 0.99,
    reason: 'model asserts severe abuse',
    modelVersion: 'test-model@1',
  };
  const { classification } = classify('this message contains nothing matchable at all', { bedrock });

  // No deterministic rule fired, so the result is downgraded and flagged.
  assert.equal(classification.classification, 'UNCERTAIN');
  assert.ok(classification.requiresHumanReview);
  assert.ok(classification.confidence <= 0.7);
  assert.notEqual(classification.recommendedAction, 'BLOCK');
});

test('AI cannot override a deterministic threat finding', () => {
  const bedrock: BedrockVerdict = {
    classification: 'SAFE',
    confidence: 0.95,
    reason: 'model believes this is harmless',
    modelVersion: 'test-model@1',
  };
  const { classification } = classify('i will kill you tomorrow', { bedrock });
  assert.equal(classification.classification, 'THREAT');
  assert.ok(classification.requiresHumanReview, 'disagreement on a severe finding must be reviewed');
  assert.match(classification.reason, /deterministic rules take precedence/);
});

test('AI agreement with rules raises confidence above either alone', () => {
  const solo = classify('you are a fucking idiot you bitch');
  const withAi = classify('you are a fucking idiot you bitch', {
    bedrock: {
      classification: 'ABUSIVE',
      confidence: 0.8,
      reason: 'model agrees: directed insult',
      modelVersion: 'test-model@1',
    },
  });
  assert.equal(withAi.classification.classification, 'ABUSIVE');
  assert.ok(
    withAi.classification.confidence > solo.classification.confidence,
    `expected corroboration to raise confidence (${solo.classification.confidence} -> ${withAi.classification.confidence})`,
  );
});

test('material disagreement between layers yields UNCERTAIN', () => {
  const { classification } = classify('ah shit i lost again', {
    bedrock: {
      classification: 'THREAT',
      confidence: 0.9,
      reason: 'model claims threat',
      modelVersion: 'test-model@1',
    },
  });
  assert.equal(classification.classification, 'UNCERTAIN');
  assert.ok(classification.requiresHumanReview);
});

test('every decision records a reason and the versions consulted', () => {
  const { classification } = classify('you are a fucking idiot', {
    bedrock: {
      classification: 'ABUSIVE',
      confidence: 0.7,
      reason: 'model agrees',
      modelVersion: 'bedrock-test@2.0',
    },
  });
  assert.ok(classification.reason.length > 20);
  assert.match(classification.modelVersion, /abuse-classifier@/);
  assert.match(classification.modelVersion, /bedrock-test@2\.0/);
  assert.ok(classification.sources.length >= 2);
  for (const source of classification.sources) {
    assert.ok(source.reason.length > 0, 'each contributing layer must record its own reason');
    assert.ok(source.version.length > 0);
  }
});

// --- Repetition -----------------------------------------------------------

test('abuse: repeated abusive content raises a repetition signal', () => {
  const { signals } = classify('you are a bitch', {
    priorAbusiveFingerprints: ['youareabitch', 'youareabitch', 'youareabitch'],
  });
  assert.ok(hasCode(signals, 'ABUSE_REPEATED'));
});

// --- Configurability ------------------------------------------------------

test('abuse: operator-supplied severe terms are honoured', () => {
  const custom = { ...cfg, extraTerms: { mild: [], severe: ['glorptastic'], threat: [] } };
  const customLexicon = buildLexicon(custom, '2.0.0');
  const { classification } = classifyAbuse({
    event: evt({ message: 'you are so glorptastic', receivedAtMs: T0 }),
    config: custom,
    nowMs: T0,
    lexicon: customLexicon,
  });
  assert.equal(classification.classification, 'SEVERE_ABUSE');
});

test('abuse: confidence below the configured floor forces human review', () => {
  const strict = { ...cfg, autoActionMinConfidence: 0.99 };
  const strictLexicon = buildLexicon(strict, '1.0.0');
  const { classification } = classifyAbuse({
    event: evt({ message: 'you are a fucking idiot', receivedAtMs: T0 }),
    config: strict,
    nowMs: T0,
    lexicon: strictLexicon,
  });
  assert.ok(classification.requiresHumanReview);
  assert.equal(classification.recommendedAction, 'WARN');
});

test('abuse: transcripts are marked as such on the signal', () => {
  const { signals } = classifyAbuse({
    event: evt({
      message: 'you are a fucking idiot',
      messageIsTranscript: true,
      eventType: 'voice',
      receivedAtMs: T0,
    }),
    config: cfg,
    nowMs: T0,
    lexicon,
  });
  const s = signals.find((x) => x.code === 'ABUSE_LANGUAGE');
  assert.ok(s);
  assert.equal(s.details?.transcript, true);
});
