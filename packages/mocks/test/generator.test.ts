import test from 'node:test';
import assert from 'node:assert/strict';

import { validateEvent } from '@talkinshield/core';

import {
  allScenarios,
  createRandom,
  ghostCorrelationEvents,
  hiddenPresenceFixture,
  mixedStream,
} from '../src/generator.ts';

test('generator: every scenario produces events that pass ingestion validation', () => {
  for (const scenario of allScenarios()) {
    assert.ok(scenario.events.length > 0, `${scenario.name} produced no events`);
    for (const [i, raw] of scenario.events.entries()) {
      const result = validateEvent(raw, {
        nowMs: Date.parse(raw.timestamp),
        messageContentAuthorized: true,
      });
      assert.ok(
        result.ok,
        `${scenario.name}[${i}] failed validation: ${result.ok ? '' : JSON.stringify(result.issues)}`,
      );
    }
  }
});

test('generator: output is deterministic for a given seed', () => {
  const a = JSON.stringify(allScenarios({ seed: 42 }));
  const b = JSON.stringify(allScenarios({ seed: 42 }));
  const c = JSON.stringify(allScenarios({ seed: 43 }));
  assert.equal(a, b, 'the same seed must produce the same stream');
  assert.notEqual(a, c, 'a different seed must produce a different stream');
});

test('generator: the PRNG is uniform enough to be useful', () => {
  const rand = createRandom(7);
  const values = Array.from({ length: 2000 }, () => rand());
  assert.ok(values.every((v) => v >= 0 && v < 1));
  const mean = values.reduce((a, b) => a + b, 0) / values.length;
  assert.ok(mean > 0.45 && mean < 0.55, `mean was ${mean}`);
});

test('generator: scenarios declare their expectations', () => {
  for (const scenario of allScenarios()) {
    assert.ok(scenario.description.length > 20, `${scenario.name} needs a real description`);
    if (scenario.expectClean) {
      assert.deepEqual(scenario.expectedSignals, [], `${scenario.name} is clean but lists signals`);
    } else {
      assert.ok(scenario.expectedSignals.length > 0, `${scenario.name} lists no expected signals`);
    }
  }
});

test('generator: at least two scenarios are false-positive guards', () => {
  const clean = allScenarios().filter((s) => s.expectClean);
  assert.ok(clean.length >= 2, 'the fixture set must include clean traffic');
});

test('generator: the mixed stream is chronologically ordered', () => {
  const events = mixedStream();
  for (let i = 1; i < events.length; i += 1) {
    const prev = Date.parse(events[i - 1]?.timestamp ?? '');
    const cur = Date.parse(events[i]?.timestamp ?? '');
    assert.ok(cur >= prev, `stream out of order at index ${i}`);
  }
});

test('generator: ghost fixtures line up with correlatable events', () => {
  const presence = hiddenPresenceFixture();
  const events = ghostCorrelationEvents();
  assert.ok(presence.length > 0);
  assert.ok(events.length >= 2, 'need enough events to exceed minCorrelatedEvents');

  const userIds = new Set(presence.map((p) => p.userId));
  for (const event of events) {
    assert.ok(userIds.has(event.userId), 'correlatable events must belong to a hidden user');
    assert.equal(event.roomId, presence[0]?.roomId);
  }
});

test('generator: no scenario contains real-looking personal data', () => {
  const serialized = JSON.stringify(allScenarios());
  // Fixtures must be obviously synthetic — no plausible real contact details.
  assert.ok(!/\b[\w.+-]+@(?!example\.)[\w-]+\.[a-z]{2,}\b/u.test(serialized), 'contains an email');
  assert.ok(!/\b(?:\+?\d[\d\s().-]{9,}\d)\b/u.test(serialized), 'contains a phone-like number');
  assert.ok(!/\b(?:\d{1,3}\.){3}\d{1,3}\b/u.test(serialized), 'contains an IP address');
});
