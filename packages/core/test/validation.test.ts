import test from 'node:test';
import assert from 'node:assert/strict';

import { DEFAULT_LIMITS, validateBatch, validateEvent } from '../src/validation/event-validator.ts';
import { T0 } from './helpers.ts';

const NOW = T0;
const base = {
  userId: 'user-A',
  roomId: 'ABC123',
  timestamp: new Date(NOW).toISOString(),
  eventType: 'message',
  message: 'hello world',
  clientVersion: '4.2.1',
  platform: 'ios',
  metadata: { region: 'eu-west-1', speakers: 3, muted: false },
};

function v(input: unknown) {
  return validateEvent(input, { nowMs: NOW });
}

function issueCodes(result: ReturnType<typeof validateEvent>): string[] {
  return result.ok ? [] : result.issues.map((i) => i.code).sort();
}

// --- Happy path -----------------------------------------------------------

test('validation: accepts a well-formed event and normalizes it', () => {
  const result = v(base);
  assert.ok(result.ok);
  assert.equal(result.event.userId, 'user-A');
  assert.equal(result.event.eventType, 'message');
  assert.equal(result.event.platform, 'ios');
  assert.equal(result.event.receivedAtMs, NOW);
  assert.equal(result.event.timestamp, new Date(NOW).toISOString());
  assert.deepEqual(result.event.metadata, { region: 'eu-west-1', speakers: 3, muted: false });
  assert.ok(result.event.eventId.length > 0);
});

test('validation: event ids are deterministic for identical payloads', () => {
  const a = v(base);
  const b = v({ ...base });
  assert.ok(a.ok && b.ok);
  assert.equal(a.event.eventId, b.event.eventId, 'retried deliveries must dedupe to one id');
});

test('validation: differing content produces differing ids', () => {
  const a = v(base);
  const b = v({ ...base, message: 'something else' });
  assert.ok(a.ok && b.ok);
  assert.notEqual(a.event.eventId, b.event.eventId);
});

// --- MALFORMED REQUESTS ---------------------------------------------------

test('malformed: non-object payloads are rejected', () => {
  for (const bad of [null, 'string', 42, true, [], undefined]) {
    const result = v(bad);
    assert.ok(!result.ok, `expected rejection for ${JSON.stringify(bad)}`);
  }
});

test('malformed: missing required fields are reported per-field', () => {
  const result = v({ message: 'orphan' });
  assert.ok(!result.ok);
  const fields = result.issues.map((i) => i.field).sort();
  assert.deepEqual(fields, ['eventType', 'roomId', 'timestamp', 'userId']);
});

test('malformed: unknown fields are rejected rather than ignored', () => {
  const result = v({ ...base, isAdmin: true, __proto__: {} });
  assert.ok(!result.ok);
  assert.ok(issueCodes(result).includes('UNKNOWN_FIELD'));
});

test('malformed: invalid eventType is rejected', () => {
  assert.ok(issueCodes(v({ ...base, eventType: 'delete_everything' })).includes('INVALID_ENUM'));
  assert.ok(issueCodes(v({ ...base, eventType: 42 })).includes('INVALID_ENUM'));
});

test('malformed: bad timestamps are rejected', () => {
  assert.ok(issueCodes(v({ ...base, timestamp: 'not-a-date' })).includes('INVALID_FORMAT'));
  assert.ok(issueCodes(v({ ...base, timestamp: 12345 })).includes('MISSING'));
  const future = new Date(NOW + 60 * 60 * 1000).toISOString();
  assert.ok(issueCodes(v({ ...base, timestamp: future })).includes('FUTURE_TIMESTAMP'));
  const ancient = new Date(NOW - 400 * 24 * 60 * 60 * 1000).toISOString();
  assert.ok(issueCodes(v({ ...base, timestamp: ancient })).includes('TOO_OLD'));
});

test('malformed: oversized message is rejected', () => {
  const huge = 'x'.repeat(DEFAULT_LIMITS.maxMessageLength + 1);
  assert.ok(issueCodes(v({ ...base, message: huge })).includes('TOO_LONG'));
});

test('malformed: ids with unsafe characters are rejected', () => {
  for (const bad of ['user A', 'user/../etc', '<script>', "u'; DROP TABLE--", 'user\u0000']) {
    const result = v({ ...base, userId: bad });
    assert.ok(!result.ok, `expected rejection of userId ${JSON.stringify(bad)}`);
    assert.ok(issueCodes(result).includes('INVALID_CHARACTERS'));
  }
});

test('malformed: prototype-polluting metadata keys are rejected', () => {
  const result = validateEvent(
    { ...base, metadata: JSON.parse('{"__proto__": "x"}') },
    { nowMs: NOW },
  );
  // Either rejected outright, or dropped — never carried through.
  if (result.ok) {
    assert.ok(!Object.hasOwn(result.event.metadata, '__proto__'));
    assert.equal(({} as Record<string, unknown>).polluted, undefined);
  } else {
    assert.ok(issueCodes(result).includes('FORBIDDEN_KEY'));
  }
});

test('malformed: nested metadata objects are rejected', () => {
  const result = v({ ...base, metadata: { nested: { a: 1 } } });
  assert.ok(!result.ok);
  assert.ok(issueCodes(result).includes('INVALID_VALUE_TYPE'));
});

test('malformed: metadata arrays and non-finite numbers are rejected', () => {
  assert.ok(!v({ ...base, metadata: [1, 2, 3] }).ok);
  assert.ok(issueCodes(v({ ...base, metadata: { n: Number.POSITIVE_INFINITY } })).includes('INVALID_NUMBER'));
});

test('malformed: too many metadata keys is rejected', () => {
  const metadata: Record<string, number> = {};
  for (let i = 0; i < DEFAULT_LIMITS.maxMetadataKeys + 5; i += 1) metadata[`k${i}`] = i;
  assert.ok(issueCodes(v({ ...base, metadata })).includes('TOO_MANY_KEYS'));
});

test('malformed: error messages never echo raw attacker input', () => {
  const result = v({ ...base, 'evil<script>alert(1)</script>': true });
  assert.ok(!result.ok);
  for (const issue of result.issues) {
    assert.ok(!issue.message.includes('<script>'), `message leaked markup: ${issue.message}`);
    assert.ok(!issue.message.includes('alert(1)'));
  }
});

// --- Sanitization ---------------------------------------------------------

test('sanitization: invisible characters are stripped from stored text', () => {
  const result = v({ ...base, message: 'he\u200Bllo\uFEFF world' });
  assert.ok(result.ok);
  assert.equal(result.event.message, 'hello world');
});

test('sanitization: whitespace is collapsed and trimmed', () => {
  const result = v({ ...base, message: '  spaced    out\n\ttext  ' });
  assert.ok(result.ok);
  assert.equal(result.event.message, 'spaced out text');
});

test('sanitization: unrecognised platform becomes a warning, not a silent default', () => {
  const result = v({ ...base, platform: 'nintendo-fridge' });
  assert.ok(result.ok);
  assert.equal(result.event.platform, 'unknown');
  assert.ok(result.warnings.some((w) => w.code === 'UNRECOGNISED_PLATFORM'));
});

// --- Authorization-aware content handling ---------------------------------

test('authorization: message text is dropped when content is not authorized', () => {
  const result = validateEvent(base, { nowMs: NOW, messageContentAuthorized: false });
  assert.ok(result.ok);
  assert.equal(result.event.message, undefined);
  const warning = result.warnings.find((w) => w.code === 'CONTENT_NOT_AUTHORIZED');
  assert.ok(warning, 'the drop must be reported, not silent');
  assert.match(warning.message, /not authorized/);
});

test('authorization: a message event with no text warns that detectors are skipped', () => {
  const { message, ...withoutMessage } = base;
  void message;
  const result = v(withoutMessage);
  assert.ok(result.ok);
  assert.ok(result.warnings.some((w) => w.code === 'EMPTY_MESSAGE_EVENT'));
});

// --- Batches --------------------------------------------------------------

test('batch: partial failure accepts the good events and reports the bad ones', () => {
  const result = validateBatch([base, { userId: 'x' }, { ...base, message: 'second' }], {
    nowMs: NOW,
    maxBatchSize: 50,
  });
  assert.ok(!('error' in result));
  assert.equal(result.accepted.length, 2);
  assert.equal(result.rejected.length, 1);
  assert.equal(result.rejected[0]?.index, 1);
});

test('batch: duplicates within one batch are discarded', () => {
  const result = validateBatch([base, { ...base }], { nowMs: NOW, maxBatchSize: 50 });
  assert.ok(!('error' in result));
  assert.equal(result.accepted.length, 1);
  assert.equal(result.rejected[0]?.issues[0]?.code, 'DUPLICATE_IN_BATCH');
});

test('batch: oversized and empty batches are refused', () => {
  const tooMany = Array.from({ length: 51 }, (_, i) => ({ ...base, message: `m${i}` }));
  const over = validateBatch(tooMany, { nowMs: NOW, maxBatchSize: 50 });
  assert.ok('error' in over);
  assert.match(over.error, /at most 50/);

  const empty = validateBatch([], { nowMs: NOW, maxBatchSize: 50 });
  assert.ok('error' in empty);

  const notArray = validateBatch('nope' as unknown as unknown[], { nowMs: NOW, maxBatchSize: 50 });
  assert.ok('error' in notArray);
});
