import test from 'node:test';
import assert from 'node:assert/strict';

import { DEFAULT_CONFIG } from '../src/config/detection-config.ts';
import { appendToWindow, detectSpam, pruneWindow } from '../src/detection/spam.ts';
import { T0, entry, evt, hasCode, window } from './helpers.ts';

const cfg = DEFAULT_CONFIG.spam;

test('spam: the brief\'s example — 10 messages in 5 seconds is flagged as a burst', () => {
  // 9 prior messages spread across 5s, plus the current one.
  const prior = window(9, 500, T0 - 100, 'hello there friends');
  const signals = detectSpam({
    event: evt({ message: 'hello again everyone', receivedAtMs: T0 }),
    window: prior,
    config: cfg,
    nowMs: T0,
  });

  assert.ok(hasCode(signals, 'SPAM_BURST'), `expected SPAM_BURST, got ${JSON.stringify(signals.map((s) => s.code))}`);
  const burst = signals.find((s) => s.code === 'SPAM_BURST');
  assert.ok(burst);
  assert.ok(burst.confidence >= 0.6);
  assert.match(burst.reason, /messages sent within 5s/);
});

test('spam: the brief\'s example — many identical messages is SEVERE', () => {
  const text = 'FREE CRYPTO CLICK HERE NOW';
  // 50 identical messages, comfortably above the severe threshold.
  const prior = window(49, 1000, T0 - 1000, text);
  const signals = detectSpam({
    event: evt({ message: text, receivedAtMs: T0 }),
    window: prior,
    config: cfg,
    nowMs: T0,
  });

  const repeat = signals.find((s) => s.code === 'SPAM_IDENTICAL_REPEAT');
  assert.ok(repeat, 'expected SPAM_IDENTICAL_REPEAT');
  assert.equal(repeat.severity, 'SEVERE');
  assert.ok(repeat.confidence >= 0.9, `confidence was ${repeat.confidence}`);
  assert.match(repeat.reason, /sent 50 times/);
});

test('spam: identical detection survives punctuation and case mutation', () => {
  const prior = [
    entry(T0 - 4000, 'Buy cheap followers right now!!!'),
    entry(T0 - 3000, 'buy cheap followers right now'),
    entry(T0 - 2000, 'BUY CHEAP FOLLOWERS RIGHT NOW...'),
    entry(T0 - 1000, 'Buy   cheap  followers right now!'),
  ];
  const signals = detectSpam({
    event: evt({ message: 'buy cheap followers right now!!!!', receivedAtMs: T0 }),
    window: prior,
    config: cfg,
    nowMs: T0,
  });
  assert.ok(hasCode(signals, 'SPAM_IDENTICAL_REPEAT'));
});

test('spam: short repeated phrases are tolerated (false-positive guard)', () => {
  // "lol" four times in a conversation is normal, not spam.
  const prior = [entry(T0 - 9000, 'lol'), entry(T0 - 6000, 'lol'), entry(T0 - 3000, 'lol')];
  const signals = detectSpam({
    event: evt({ message: 'lol', receivedAtMs: T0 }),
    window: prior,
    config: cfg,
    nowMs: T0,
  });
  assert.ok(
    !hasCode(signals, 'SPAM_IDENTICAL_REPEAT'),
    `short phrases must not trip the repeat threshold: ${JSON.stringify(signals.map((s) => s.code))}`,
  );
});

test('spam: short phrases ARE flagged once repetition becomes absurd', () => {
  const prior = Array.from({ length: 14 }, (_, i) => entry(T0 - (15 - i) * 1000, 'lol'));
  const signals = detectSpam({
    event: evt({ message: 'lol', receivedAtMs: T0 }),
    window: prior,
    config: cfg,
    nowMs: T0,
  });
  const repeat = signals.find((s) => s.code === 'SPAM_IDENTICAL_REPEAT');
  assert.ok(repeat, 'fifteen identical short messages is spam');
  assert.equal(repeat.details?.shortMessage, true);
  assert.match(repeat.reason, /adjusted upward because the message is short/);
});

test('spam: near-duplicate template with varied digits is detected', () => {
  const prior = [
    entry(T0 - 5000, 'win a prize now visit site number 1111'),
    entry(T0 - 4000, 'win a prize now visit site number 2222'),
    entry(T0 - 3000, 'win a prize now visit site number 3333'),
    entry(T0 - 2000, 'win a prize now visit site number 4444'),
  ];
  const signals = detectSpam({
    event: evt({ message: 'win a prize now visit site number 5555', receivedAtMs: T0 }),
    window: prior,
    config: cfg,
    nowMs: T0,
  });
  assert.ok(
    hasCode(signals, 'SPAM_NEAR_DUPLICATE'),
    `got ${JSON.stringify(signals.map((s) => s.code))}`,
  );
});

test('spam: uniform machine-like timing is detected', () => {
  // Exactly 2000ms apart — no human types with this regularity.
  const prior = window(10, 2000, T0 - 2000, 'status update');
  const signals = detectSpam({
    event: evt({ message: 'status update', receivedAtMs: T0 }),
    window: prior,
    config: cfg,
    nowMs: T0,
  });

  const timing = signals.find((s) => s.code === 'BOT_UNIFORM_TIMING');
  assert.ok(timing, `expected BOT_UNIFORM_TIMING, got ${JSON.stringify(signals.map((s) => s.code))}`);
  assert.match(timing.reason, /machine-like/);
  assert.equal(timing.details?.meanIntervalMs, 2000);
});

test('spam: irregular human timing is NOT flagged as bot-like', () => {
  const gaps = [1200, 8400, 2300, 15000, 3100, 6700, 1900];
  let at = T0 - gaps.reduce((a, b) => a + b, 0);
  const prior = [];
  for (const gap of gaps) {
    prior.push(entry(at, `message ${at}`));
    at += gap;
  }

  const signals = detectSpam({
    event: evt({ message: 'another thought', receivedAtMs: T0 }),
    window: prior,
    config: cfg,
    nowMs: T0,
  });
  assert.ok(!hasCode(signals, 'BOT_UNIFORM_TIMING'));
});

test('spam: mention flood in a single message', () => {
  const signals = detectSpam({
    event: evt({
      message: '@a1 @b2 @c3 @d4 @e5 @f6 @g7 @h8 check this out',
      receivedAtMs: T0,
    }),
    window: [],
    config: cfg,
    nowMs: T0,
  });
  const flood = signals.find((s) => s.code === 'SPAM_MENTION_FLOOD');
  assert.ok(flood);
  assert.match(flood.reason, /mentioned 8 users/);
});

test('spam: zero-width characters inserted inside words are flagged', () => {
  const signals = detectSpam({
    event: evt({ message: 'this is a te\u200Bst of fil\u200Bter eva\u200Bsion', receivedAtMs: T0 }),
    window: [],
    config: cfg,
    nowMs: T0,
  });
  const chars = signals.find((s) => s.code === 'SPAM_SUSPICIOUS_CHARACTERS');
  assert.ok(chars);
  assert.equal(chars.severity, 'HIGH');
  assert.match(chars.reason, /zero-width characters inserted inside words/);
});

test('spam: mixed-script homoglyph text is flagged', () => {
  // "paypal" using Cyrillic а and о.
  const signals = detectSpam({
    event: evt({ message: 'login to pаypаl now', receivedAtMs: T0 }),
    window: [],
    config: cfg,
    nowMs: T0,
  });
  assert.ok(hasCode(signals, 'SPAM_SUSPICIOUS_CHARACTERS'));
});

test('spam: ordinary enthusiastic message produces no signals (false-positive guard)', () => {
  const signals = detectSpam({
    event: evt({ message: 'That was an amazing round!! GG everyone :)', receivedAtMs: T0 }),
    window: window(3, 25_000, T0 - 25_000, 'chatting normally'),
    config: cfg,
    nowMs: T0,
  });
  assert.deepEqual(signals, [], `unexpected signals: ${JSON.stringify(signals.map((s) => s.code))}`);
});

test('spam: a quiet conversation never trips frequency thresholds', () => {
  const prior = window(8, 45_000, T0 - 45_000, 'varied chat content here');
  const signals = detectSpam({
    event: evt({ message: 'completely different sentence', receivedAtMs: T0 }),
    window: prior,
    config: cfg,
    nowMs: T0,
  });
  assert.ok(!hasCode(signals, 'SPAM_HIGH_FREQUENCY'));
  assert.ok(!hasCode(signals, 'SPAM_BURST'));
});

test('spam: thresholds are configurable and actually honoured', () => {
  const strict = { ...cfg, burstCount: 3, burstWindowMs: 5000 };
  const prior = window(2, 1000, T0 - 1000, 'a');
  const relaxed = detectSpam({
    event: evt({ message: 'b', receivedAtMs: T0 }),
    window: prior,
    config: cfg,
    nowMs: T0,
  });
  const tightened = detectSpam({
    event: evt({ message: 'b', receivedAtMs: T0 }),
    window: prior,
    config: strict,
    nowMs: T0,
  });
  assert.ok(!hasCode(relaxed, 'SPAM_BURST'));
  assert.ok(hasCode(tightened, 'SPAM_BURST'));
});

test('window: appendToWindow caps growth at maxWindowEvents', () => {
  const small = { ...cfg, maxWindowEvents: 5 };
  let w = window(10, 1000, T0, 'x');
  for (let i = 0; i < 10; i += 1) {
    w = appendToWindow(w, evt({ message: `m${i}`, receivedAtMs: T0 + i * 1000 }), small);
  }
  assert.equal(w.length, 5);
  // Retained entries must be the newest ones.
  assert.ok(w.every((e) => e.atMs >= T0));
});

test('window: pruneWindow drops entries beyond the detection horizon', () => {
  const old = entry(T0 - DEFAULT_CONFIG.spam.sustainedWindowMs - 60_000, 'ancient');
  const fresh = entry(T0 - 1000, 'recent');
  const pruned = pruneWindow([old, fresh], cfg, T0);
  assert.equal(pruned.length, 1);
  assert.equal(pruned[0]?.fingerprint, fresh.fingerprint);
});

test('spam: voice transcripts participate in frequency analysis', () => {
  const prior = window(9, 400, T0 - 100, 'repeated transcript line', { eventType: 'voice' });
  const signals = detectSpam({
    event: evt({ eventType: 'voice', message: 'repeated transcript line', messageIsTranscript: true, receivedAtMs: T0 }),
    window: prior,
    config: cfg,
    nowMs: T0,
  });
  assert.ok(hasCode(signals, 'SPAM_BURST'));
});

test('spam: join/leave events are excluded from message-rate analysis', () => {
  const prior = window(20, 200, T0 - 200, undefined, { eventType: 'join' });
  const signals = detectSpam({
    event: evt({ eventType: 'join', message: undefined, receivedAtMs: T0 }),
    window: prior,
    config: cfg,
    nowMs: T0,
  });
  assert.ok(!hasCode(signals, 'SPAM_BURST'));
  assert.ok(!hasCode(signals, 'SPAM_HIGH_FREQUENCY'));
});
