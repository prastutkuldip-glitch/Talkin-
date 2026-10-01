import test from 'node:test';
import assert from 'node:assert/strict';

import { DEFAULT_CONFIG } from '../src/config/detection-config.ts';
import { assessClient } from '../src/detection/client.ts';
import { detectCoordination } from '../src/detection/coordination.ts';
import { detectEvasion } from '../src/detection/evasion.ts';
import {
  correlateHiddenActivity,
  HIDDEN_ACTIVITY_MESSAGE,
  INSUFFICIENT_TELEMETRY_MESSAGE,
} from '../src/detection/ghost.ts';
import { fingerprint } from '../src/util/text.ts';
import { T0, entry, evt, hasCode, window } from './helpers.ts';

const clientCfg = { ...DEFAULT_CONFIG.client, knownVersions: ['4.2.1', '4.3.0'] };
const ghostCfg = DEFAULT_CONFIG.ghost;
const evasionCfg = DEFAULT_CONFIG.evasion;

// --- SUSPICIOUS CLIENT DETECTION -----------------------------------------

test('client: returns the contracted shape', () => {
  const result = assessClient({
    event: evt({ receivedAtMs: T0 }),
    window: window(10, 2000, T0 - 2000),
    config: clientCfg,
    nowMs: T0,
  });
  assert.equal(typeof result.clientRisk, 'number');
  assert.ok(result.clientRisk >= 0 && result.clientRisk <= 100);
  assert.ok(Array.isArray(result.indicators));
  assert.ok(result.confidence >= 0 && result.confidence <= 1);
});

test('client: reports insufficient telemetry rather than guessing', () => {
  const result = assessClient({
    event: evt({ receivedAtMs: T0 }),
    window: [],
    config: clientCfg,
    nowMs: T0,
  });
  assert.equal(result.insufficientTelemetry, true);
  assert.equal(result.clientRisk, 0);
  assert.equal(result.confidence, 0);
  assert.match(result.note ?? '', /Insufficient authorized telemetry/);
});

test('client: an official version on a full window is clean', () => {
  const result = assessClient({
    event: evt({ clientVersion: '4.2.1', platform: 'ios', receivedAtMs: T0 }),
    window: window(20, 5000, T0 - 5000, 'chat', { clientVersion: '4.2.1', platform: 'ios' }),
    config: clientCfg,
    nowMs: T0,
  });
  assert.equal(result.clientRisk, 0);
  assert.deepEqual(result.indicators, []);
});

test('client: malformed version string is flagged', () => {
  const result = assessClient({
    event: evt({ clientVersion: 'totally-custom-build', receivedAtMs: T0 }),
    window: window(10, 2000, T0 - 2000, 'x', { clientVersion: 'totally-custom-build' }),
    config: clientCfg,
    nowMs: T0,
  });
  assert.ok(result.indicators.includes('CLIENT_UNKNOWN_VERSION'));
  assert.ok(result.clientRisk > 0);
});

test('client: an unlisted but well-formed version is a weaker signal', () => {
  const strong = assessClient({
    event: evt({ clientVersion: 'hacked!!', receivedAtMs: T0 }),
    window: window(10, 2000, T0 - 2000),
    config: clientCfg,
    nowMs: T0,
  });
  const weak = assessClient({
    event: evt({ clientVersion: '9.9.9', receivedAtMs: T0 }),
    window: window(10, 2000, T0 - 2000),
    config: clientCfg,
    nowMs: T0,
  });
  assert.ok(weak.clientRisk < strong.clientRisk);
});

test('client: version flapping within a session is flagged', () => {
  const w = [
    entry(T0 - 300_000, 'a', { clientVersion: '4.2.1' }),
    entry(T0 - 200_000, 'b', { clientVersion: '4.3.0' }),
    entry(T0 - 100_000, 'c', { clientVersion: '4.2.1' }),
    ...window(8, 2000, T0 - 10_000, 'd', { clientVersion: '5.0.0' }),
  ];
  const result = assessClient({
    event: evt({ clientVersion: '5.0.0', receivedAtMs: T0 }),
    window: w,
    config: clientCfg,
    nowMs: T0,
  });
  assert.ok(result.indicators.includes('CLIENT_VERSION_FLAPPING'));
});

test('client: platform mismatch within one session is flagged', () => {
  const w = [
    ...window(5, 2000, T0 - 20_000, 'a', { platform: 'ios' }),
    ...window(5, 2000, T0 - 5000, 'b', { platform: 'android' }),
  ];
  const result = assessClient({
    event: evt({ platform: 'android', receivedAtMs: T0 }),
    window: w,
    config: clientCfg,
    nowMs: T0,
  });
  assert.ok(result.indicators.includes('CLIENT_PLATFORM_MISMATCH'));
});

test('client: messaging a room after leaving it is an impossible sequence', () => {
  const w = [
    ...window(8, 3000, T0 - 60_000, 'chatting'),
    entry(T0 - 30_000, undefined, { eventType: 'leave' }),
  ];
  const result = assessClient({
    event: evt({ eventType: 'message', message: 'still here', receivedAtMs: T0 }),
    window: w,
    config: clientCfg,
    nowMs: T0,
  });
  assert.ok(result.indicators.includes('CLIENT_IMPOSSIBLE_SEQUENCE'));
  const signal = result.signals.find((s) => s.code === 'CLIENT_IMPOSSIBLE_SEQUENCE');
  assert.match(signal?.reason ?? '', /after this account left room/);
});

test('client: brief out-of-order delivery is tolerated, not flagged', () => {
  const w = [
    ...window(8, 3000, T0 - 60_000, 'chatting'),
    entry(T0 - 1000, undefined, { eventType: 'leave' }),
  ];
  const result = assessClient({
    event: evt({ eventType: 'message', message: 'race condition', receivedAtMs: T0 }),
    window: w,
    config: clientCfg,
    nowMs: T0,
  });
  assert.ok(
    !result.indicators.includes('CLIENT_IMPOSSIBLE_SEQUENCE'),
    'normal transport reordering must not be reported as a modified client',
  );
});

test('client: simultaneous voice in two rooms is an impossible sequence', () => {
  const w = [
    ...window(6, 2000, T0 - 20_000, 'talking', { eventType: 'voice', roomId: 'ROOM-1' }),
    ...window(4, 2000, T0 - 8000, 'talking', { eventType: 'voice', roomId: 'ROOM-2' }),
  ];
  const result = assessClient({
    event: evt({ eventType: 'voice', roomId: 'ROOM-2', receivedAtMs: T0 }),
    window: w,
    config: clientCfg,
    nowMs: T0,
  });
  assert.ok(result.indicators.includes('CLIENT_IMPOSSIBLE_SEQUENCE'));
});

test('client: repeated malformed requests are flagged', () => {
  const result = assessClient({
    event: evt({ receivedAtMs: T0 }),
    window: window(10, 2000, T0 - 2000),
    config: clientCfg,
    nowMs: T0,
    malformedRequestCount: 25,
  });
  assert.ok(result.indicators.includes('CLIENT_MALFORMED_REQUESTS'));
});

test('client: abnormal request rate is flagged', () => {
  const result = assessClient({
    event: evt({ receivedAtMs: T0 }),
    window: window(10, 2000, T0 - 2000),
    config: clientCfg,
    nowMs: T0,
    observedRequestsPerMinute: 1200,
  });
  assert.ok(result.indicators.includes('CLIENT_ABNORMAL_REQUEST_RATE'));
});

test('client: failed official attestation is the strongest indicator', () => {
  const result = assessClient({
    event: evt({ receivedAtMs: T0 }),
    window: window(10, 2000, T0 - 2000),
    config: clientCfg,
    nowMs: T0,
    attestation: { verified: false, detail: 'signature mismatch' },
    attestationAvailable: true,
  });
  assert.ok(result.indicators.includes('CLIENT_ATTESTATION_FAILED'));
  assert.ok(result.confidence > 0.5, 'attestation should raise confidence');
});

test('client: absent attestation is never treated as failure', () => {
  const result = assessClient({
    event: evt({ clientVersion: '4.2.1', receivedAtMs: T0 }),
    window: window(10, 2000, T0 - 2000, 'x', { clientVersion: '4.2.1', platform: 'ios' }),
    config: clientCfg,
    nowMs: T0,
    attestationAvailable: false,
  });
  assert.ok(!result.indicators.includes('CLIENT_ATTESTATION_FAILED'));
  assert.match(result.note ?? '', /indicative, not conclusive/);
});

test('client: declared version is sanitized before appearing in a reason', () => {
  const result = assessClient({
    event: evt({ clientVersion: '<script>alert(1)</script>', receivedAtMs: T0 }),
    window: window(10, 2000, T0 - 2000),
    config: clientCfg,
    nowMs: T0,
  });
  const reason = result.signals.map((s) => s.reason).join(' ');
  assert.ok(!reason.includes('<script>'), reason);
});

// --- GHOST / HIDDEN ACTIVITY ---------------------------------------------

test('ghost: without the capability, reports exactly "Insufficient authorized telemetry."', () => {
  const result = correlateHiddenActivity({
    roomId: 'ABC123',
    config: ghostCfg,
    nowMs: T0,
    hiddenPresenceAvailable: false,
    hiddenPresence: [],
    observedEvents: [],
  });
  assert.equal(result.displayMessage, INSUFFICIENT_TELEMETRY_MESSAGE);
  assert.equal(result.status.availability, 'UNAVAILABLE');
  assert.deepEqual(result.signals, []);
  assert.match(result.status.note ?? '', /will not attempt to discover concealed users/);
});

test('ghost: capability present but nothing reported is distinguished from unavailable', () => {
  const result = correlateHiddenActivity({
    roomId: 'ABC123',
    config: ghostCfg,
    nowMs: T0,
    hiddenPresenceAvailable: true,
    hiddenPresence: [],
    observedEvents: [],
  });
  assert.equal(result.status.availability, 'AUTHORIZED_EMPTY');
  assert.notEqual(result.displayMessage, INSUFFICIENT_TELEMETRY_MESSAGE);
});

test('ghost: platform-disclosed hidden presence is correlated with authorized events', () => {
  const result = correlateHiddenActivity({
    roomId: 'ABC123',
    config: ghostCfg,
    nowMs: T0,
    hiddenPresenceAvailable: true,
    hiddenPresence: [
      { userId: 'ghost-1', roomId: 'ABC123', atMs: T0 - 60_000, kind: 'HIDDEN_JOIN', mode: 'invisible' },
    ],
    observedEvents: [
      { eventId: 'g1', userId: 'ghost-1', roomId: 'ABC123', atMs: T0 - 50_000, eventType: 'message' },
      { eventId: 'g2', userId: 'ghost-1', roomId: 'ABC123', atMs: T0 - 40_000, eventType: 'message' },
      { eventId: 'g3', userId: 'ghost-1', roomId: 'ABC123', atMs: T0 - 30_000, eventType: 'voice' },
    ],
  });

  assert.equal(result.displayMessage, HIDDEN_ACTIVITY_MESSAGE);
  assert.equal(result.status.availability, 'AUTHORIZED');
  assert.equal(result.status.value?.length, 1);
  assert.equal(result.status.value?.[0]?.correlatedEventIds.length, 3);
  assert.ok(hasCode(result.signals, 'GHOST_HIDDEN_PRESENCE_CORRELATED'));
  assert.match(result.signals[0]?.reason ?? '', /solely on platform-disclosed presence data/);
});

test('ghost: too few corroborating events produces no claim', () => {
  const result = correlateHiddenActivity({
    roomId: 'ABC123',
    config: ghostCfg,
    nowMs: T0,
    hiddenPresenceAvailable: true,
    hiddenPresence: [{ userId: 'ghost-1', roomId: 'ABC123', atMs: T0 - 60_000, kind: 'HIDDEN_JOIN' }],
    observedEvents: [
      { eventId: 'g1', userId: 'ghost-1', roomId: 'ABC123', atMs: T0 - 50_000, eventType: 'message' },
    ],
  });
  assert.deepEqual(result.signals, []);
  assert.equal(result.status.availability, 'AUTHORIZED_EMPTY');
});

test('ghost: events from other rooms or users are not correlated', () => {
  const result = correlateHiddenActivity({
    roomId: 'ABC123',
    config: ghostCfg,
    nowMs: T0,
    hiddenPresenceAvailable: true,
    hiddenPresence: [{ userId: 'ghost-1', roomId: 'ABC123', atMs: T0 - 60_000, kind: 'HIDDEN_JOIN' }],
    observedEvents: [
      { eventId: 'x1', userId: 'other-user', roomId: 'ABC123', atMs: T0 - 50_000, eventType: 'message' },
      { eventId: 'x2', userId: 'ghost-1', roomId: 'OTHER', atMs: T0 - 40_000, eventType: 'message' },
    ],
  });
  assert.deepEqual(result.signals, []);
});

test('ghost: events outside the concealment window are excluded', () => {
  const result = correlateHiddenActivity({
    roomId: 'ABC123',
    config: ghostCfg,
    nowMs: T0,
    hiddenPresenceAvailable: true,
    hiddenPresence: [
      { userId: 'ghost-1', roomId: 'ABC123', atMs: T0 - 60_000, kind: 'HIDDEN_JOIN' },
      { userId: 'ghost-1', roomId: 'ABC123', atMs: T0 - 50_000, kind: 'HIDDEN_LEAVE' },
    ],
    observedEvents: [
      // After HIDDEN_LEAVE + tolerance — no longer concealed.
      { eventId: 'g1', userId: 'ghost-1', roomId: 'ABC123', atMs: T0 - 20_000, eventType: 'message' },
      { eventId: 'g2', userId: 'ghost-1', roomId: 'ABC123', atMs: T0 - 10_000, eventType: 'message' },
    ],
  });
  assert.deepEqual(result.signals, []);
});

// --- EVASION --------------------------------------------------------------

test('evasion: without moderation events, reports insufficient telemetry', () => {
  const result = detectEvasion({
    event: evt({ receivedAtMs: T0 }),
    window: [],
    config: evasionCfg,
    nowMs: T0,
    restrictions: [],
    moderationEventsAvailable: false,
  });
  assert.equal(result.insufficientTelemetry, true);
  assert.deepEqual(result.signals, []);
  assert.match(result.note ?? '', /Insufficient authorized telemetry/);
});

test('evasion: speaking while an active platform mute is in force is detected', () => {
  const result = detectEvasion({
    event: evt({ eventType: 'message', message: 'still talking', receivedAtMs: T0 }),
    window: [],
    config: evasionCfg,
    nowMs: T0,
    restrictions: [{ appliedAtMs: T0 - 30_000, kind: 'MUTE', roomId: 'ABC123' }],
    moderationEventsAvailable: true,
  });
  assert.ok(hasCode(result.signals, 'EVASION_POST_MODERATION_ACTIVITY'));
  assert.match(result.signals[0]?.reason ?? '', /30s after a platform MUTE/);
});

test('evasion: activity after a restriction expired is not evasion', () => {
  const result = detectEvasion({
    event: evt({ receivedAtMs: T0 }),
    window: [],
    config: evasionCfg,
    nowMs: T0,
    restrictions: [{ appliedAtMs: T0 - 60_000, kind: 'MUTE', expiresAtMs: T0 - 30_000 }],
    moderationEventsAvailable: true,
  });
  assert.ok(!hasCode(result.signals, 'EVASION_POST_MODERATION_ACTIVITY'));
});

test('evasion: a restriction in a different room is not evasion', () => {
  const result = detectEvasion({
    event: evt({ roomId: 'ROOM-X', receivedAtMs: T0 }),
    window: [],
    config: evasionCfg,
    nowMs: T0,
    restrictions: [{ appliedAtMs: T0 - 30_000, kind: 'MUTE', roomId: 'ROOM-Y' }],
    moderationEventsAvailable: true,
  });
  assert.ok(!hasCode(result.signals, 'EVASION_POST_MODERATION_ACTIVITY'));
});

test('evasion: rejoin cycling is detected', () => {
  const w = [];
  for (let i = 0; i < 6; i += 1) {
    w.push(entry(T0 - (i * 2 + 2) * 10_000, undefined, { eventType: 'join' }));
    w.push(entry(T0 - (i * 2 + 1) * 10_000, undefined, { eventType: 'leave' }));
  }
  const result = detectEvasion({
    event: evt({ eventType: 'join', receivedAtMs: T0 }),
    window: w,
    config: evasionCfg,
    nowMs: T0,
    restrictions: [],
    moderationEventsAvailable: true,
  });
  assert.ok(hasCode(result.signals, 'EVASION_REJOIN_CYCLING'));
});

// --- COORDINATION ---------------------------------------------------------

test('coordination: identical content across accounts is reported without identity inference', () => {
  const text = 'join our giveaway at this totally legitimate address';
  const fp = fingerprint(text);
  const findings = detectCoordination({
    roomId: 'ABC123',
    config: DEFAULT_CONFIG.spam,
    nowMs: T0,
    participants: [
      { userId: 'u1', fingerprints: [fp], joinTimesMs: [], messageTimesMs: [T0] },
      { userId: 'u2', fingerprints: [fp], joinTimesMs: [], messageTimesMs: [T0] },
      { userId: 'u3', fingerprints: [fp], joinTimesMs: [], messageTimesMs: [T0] },
      { userId: 'u4', fingerprints: [fp], joinTimesMs: [], messageTimesMs: [T0] },
    ],
  });
  const finding = findings.find((f) => f.signals[0]?.code === 'COORDINATED_IDENTICAL_CONTENT');
  assert.ok(finding);
  assert.equal(finding.userIds.length, 4);
  assert.match(finding.signals[0]?.reason ?? '', /no inference is made that these accounts share an operator/);
});

test('coordination: trivial short messages do not create findings', () => {
  const fp = fingerprint('lol');
  const findings = detectCoordination({
    roomId: 'ABC123',
    config: DEFAULT_CONFIG.spam,
    nowMs: T0,
    participants: Array.from({ length: 8 }, (_, i) => ({
      userId: `u${i}`,
      fingerprints: [fp],
      joinTimesMs: [],
      messageTimesMs: [T0],
    })),
  });
  assert.ok(!findings.some((f) => f.signals[0]?.code === 'COORDINATED_IDENTICAL_CONTENT'));
});

test('coordination: scripted synchronized joins are detected', () => {
  const findings = detectCoordination({
    roomId: 'ABC123',
    config: DEFAULT_CONFIG.spam,
    nowMs: T0,
    participants: Array.from({ length: 6 }, (_, i) => ({
      userId: `bot${i}`,
      fingerprints: [],
      joinTimesMs: [T0 - 9000 + i * 1000], // exactly 1s apart
      messageTimesMs: [],
    })),
  });
  const finding = findings.find((f) => f.signals[0]?.code === 'COORDINATED_SYNCHRONIZED_JOINS');
  assert.ok(finding);
  assert.match(finding.signals[0]?.reason ?? '', /scripted entry/);
});

test('coordination: too few accounts produces no finding', () => {
  const findings = detectCoordination({
    roomId: 'ABC123',
    config: DEFAULT_CONFIG.spam,
    nowMs: T0,
    participants: [
      { userId: 'u1', fingerprints: ['sameexactcontent'], joinTimesMs: [], messageTimesMs: [] },
      { userId: 'u2', fingerprints: ['sameexactcontent'], joinTimesMs: [], messageTimesMs: [] },
    ],
  });
  assert.deepEqual(findings, []);
});
