import test from 'node:test';
import assert from 'node:assert/strict';

import { DEFAULT_CONFIG } from '../src/config/detection-config.ts';
import { buildLexicon } from '../src/detection/abuse/classifier.ts';
import {
  applyShield,
  clearLocalMute,
  DEFAULT_SHIELD_CONFIG,
  emptySpeakerState,
  type ShieldInput,
  type SpeakerState,
  type Utterance,
} from '../src/shield/personal-shield.ts';
import { T0 } from './helpers.ts';

const abuseConfig = DEFAULT_CONFIG.abuse;
const lexicon = buildLexicon(abuseConfig, '1.0.0');

function utter(transcript: string, atMs: number, speakerId = 'spk-1'): Utterance {
  return { speakerId, roomId: 'ABC123', atMs, transcript };
}

function run(
  utterance: Utterance,
  state: SpeakerState | undefined,
  currentlyMuted: Map<string, number> = new Map(),
  extra: Partial<ShieldInput> = {},
) {
  return applyShield({
    utterance,
    state,
    currentlyMuted,
    config: DEFAULT_SHIELD_CONFIG,
    abuseConfig,
    nowMs: utterance.atMs,
    lexicon,
    ...extra,
  });
}

// --- The core promise: abuse gets silenced FOR THE USER --------------------

test('shield: severe abuse (telling someone to kill themselves) mutes immediately', () => {
  const decision = run(utter('kys you worthless piece of shit', T0), undefined);
  assert.equal(decision.action, 'LOCAL_MUTE');
  assert.ok(decision.locallyMutedSpeakerIds.includes('spk-1'));
  assert.match(decision.message, /muted for you/);
  assert.match(decision.message, /changes only your own audio/);
});

test('shield: a single directed insult soft-mutes first, then mutes on repeat', () => {
  // Directed profanity lands around 0.68 confidence — ABUSIVE, not SEVERE —
  // so the first one softens the speaker and warns, rather than hard-muting.
  const first = run(utter('you fucking bitch', T0), undefined);
  assert.equal(first.action, 'LOCAL_SOFT_MUTE');
  assert.match(first.message, /one more and they are muted/);

  const second = run(utter('you absolute bitch', T0 + 4000), first.nextState);
  assert.equal(second.action, 'LOCAL_MUTE');
  assert.ok(second.locallyMutedSpeakerIds.includes('spk-1'));
});

test('shield: a credible threat mutes immediately', () => {
  const decision = run(utter('i am going to kill you when i find you', T0), undefined);
  assert.equal(decision.action, 'LOCAL_MUTE');
  assert.ok(decision.locallyMutedSpeakerIds.includes('spk-1'));
});

test('shield: repeat offenders are muted after the configured number of offenses', () => {
  // Two directed insults within the window → local mute.
  const first = run(utter('you fucking prick', T0), undefined);
  assert.ok(['LOCAL_SOFT_MUTE', 'LOCAL_MUTE'].includes(first.action));

  const second = run(utter('you absolute bitch', T0 + 5000), first.nextState);
  assert.equal(second.action, 'LOCAL_MUTE');
  assert.ok(second.locallyMutedSpeakerIds.includes('spk-1'));
});

test('shield: a muted speaker stays muted on subsequent clean utterances until expiry', () => {
  const muted = run(utter('kys you worthless piece of shit', T0), undefined);
  assert.equal(muted.action, 'LOCAL_MUTE');

  // They say something harmless next — still muted, because the window holds.
  const next = run(utter('okay fine whatever', T0 + 1000, 'spk-1'), muted.nextState);
  assert.equal(next.action, 'LOCAL_MUTE');
  assert.ok(next.locallyMutedSpeakerIds.includes('spk-1'));
});

test('shield: mute expires after the configured duration', () => {
  const muted = run(utter('kys you worthless piece of shit', T0), undefined);
  assert.ok(muted.nextState.mutedUntilMs !== undefined);

  const later = T0 + DEFAULT_SHIELD_CONFIG.localMuteDurationMs + 1000;
  const afterExpiry = run(utter('normal comment now', later, 'spk-1'), muted.nextState);
  assert.equal(afterExpiry.action, 'NONE');
  assert.ok(!afterExpiry.locallyMutedSpeakerIds.includes('spk-1'));
});

// --- Evidence --------------------------------------------------------------

test('shield: captures redacted evidence for each offense', () => {
  const decision = run(
    utter('you are a fucking idiot, dm me at victim@example.com', T0),
    undefined,
  );
  assert.ok(decision.evidence);
  assert.equal(decision.evidence.isTranscript, true);
  assert.equal(decision.evidence.speakerId, 'spk-1');
  assert.ok(!decision.evidence.excerpt.includes('victim@example.com'), 'PII must be redacted');
  assert.match(decision.evidence.excerpt, /\[redacted-email\]/);
  assert.ok(decision.evidence.reason.length > 0);
});

// --- False-positive safety -------------------------------------------------

test('shield: ordinary conversation is never muted', () => {
  const decision = run(utter('hey everyone, good game, that was fun', T0), undefined);
  assert.equal(decision.action, 'NONE');
  assert.deepEqual(decision.locallyMutedSpeakerIds, []);
  assert.equal(decision.evidence, undefined);
});

test('shield: undirected frustration is not treated as abuse of the user', () => {
  const decision = run(utter('ah shit i missed the shot again', T0), undefined);
  assert.ok(['NONE', 'FLAG'].includes(decision.action));
  assert.ok(!decision.locallyMutedSpeakerIds.includes('spk-1'));
});

test('shield: low-confidence findings are flagged, not muted', () => {
  const decision = run(utter('that was a stupid play honestly', T0), undefined);
  assert.ok(['NONE', 'FLAG'].includes(decision.action));
});

// --- User control ----------------------------------------------------------

test('shield: a user-initiated block is permanent until the user lifts it', () => {
  const decision = run(utter('hello', T0), undefined, new Map(), { userBlocked: true });
  assert.equal(decision.action, 'LOCAL_BLOCK');
  assert.ok(decision.locallyMutedSpeakerIds.includes('spk-1'));
  assert.match(decision.message, /nothing was done to their device/);
});

test('shield: the user can clear a mute or block themselves', () => {
  // Use a severe utterance so a hard mute is set in one step.
  const muted = run(utter('kys you worthless trash', T0), undefined);
  assert.ok(muted.nextState.mutedUntilMs !== undefined || muted.nextState.blockedLocally);

  const cleared = clearLocalMute(muted.nextState);
  assert.equal(cleared.blockedLocally, false);
  assert.equal(cleared.mutedUntilMs, undefined);
});

// --- The boundary: nothing leaves the user's own client --------------------

test('shield: the decision only ever names speakers to drop from the LOCAL mix', () => {
  const decision = run(utter('i will hurt you', T0), undefined);
  // The entire effect is a list of speaker ids for the local client to drop.
  // There is no field that could carry a command to another party.
  const keys = Object.keys(decision);
  assert.ok(keys.includes('locallyMutedSpeakerIds'));
  assert.ok(!keys.some((k) => /remote|send|command|target.*device|signal|jam/i.test(k)));

  // And the muted set is just ids — strings — not instructions.
  for (const id of decision.locallyMutedSpeakerIds) {
    assert.equal(typeof id, 'string');
  }
});

test('shield: multiple abusers accumulate independently in the local mute set', () => {
  // Both severe, so each is hard-muted on their first utterance.
  const a = run(utter('kys you worthless trash', T0, 'abuser-A'), undefined, new Map());
  assert.equal(a.action, 'LOCAL_MUTE');
  const muted = new Map(a.locallyMutedSpeakerIds.map((id) => [id, a.nextState.mutedUntilMs ?? 0]));

  const b = run(utter('i will kill you', T0 + 1000, 'abuser-B'), undefined, muted);

  assert.ok(b.locallyMutedSpeakerIds.includes('abuser-A'));
  assert.ok(b.locallyMutedSpeakerIds.includes('abuser-B'));
});

test('shield: a clean speaker is never added to the mute set', () => {
  const muted = new Map<string, number>([['abuser-A', Number.POSITIVE_INFINITY]]);
  const decision = run(utter('nice shot, well played', T0, 'friendly-C'), undefined, muted);
  assert.ok(!decision.locallyMutedSpeakerIds.includes('friendly-C'));
  // The already-muted abuser is preserved.
  assert.ok(decision.locallyMutedSpeakerIds.includes('abuser-A'));
});

test('shield: starts from empty state cleanly', () => {
  const state = emptySpeakerState('spk-9');
  assert.equal(state.offenses.length, 0);
  assert.equal(state.blockedLocally, false);
  const decision = run(utter('you stupid prick', T0, 'spk-9'), state);
  assert.ok(decision.action !== 'NONE');
});
