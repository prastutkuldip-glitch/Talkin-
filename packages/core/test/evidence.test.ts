import test from 'node:test';
import assert from 'node:assert/strict';

import { DEFAULT_CONFIG } from '../src/config/detection-config.ts';
import {
  buildEvidenceBundle,
  evidenceKey,
  GENESIS_HASH,
  verifyBundle,
  verifyChain,
  type EvidenceBundle,
} from '../src/evidence/record.ts';
import { buildIncident, recordAction } from '../src/pipeline/incident.ts';
import { assessRisk } from '../src/risk/engine.ts';
import { planResponse } from '../src/response/policy.ts';
import type { DetectionSignal } from '../src/types/detection.ts';
import { NO_CAPABILITIES } from '../src/types/telemetry.ts';
import { hashObject } from '../src/util/ids.ts';
import { FULL_CAPS, MINIMAL_CAPS, T0, evt } from './helpers.ts';

const signals: DetectionSignal[] = [
  {
    code: 'THREAT_LANGUAGE',
    category: 'THREAT',
    severity: 'SEVERE',
    confidence: 0.92,
    reason: 'Threat pattern matched: actor, intent verb and target all present.',
    evidenceEventIds: ['e1'],
    detector: 'abuse-classifier@1.3.0',
    observedAtMs: T0,
  },
  {
    code: 'SPAM_IDENTICAL_REPEAT',
    category: 'SPAM',
    severity: 'SEVERE',
    confidence: 0.95,
    reason: 'The same message content was sent 50 times.',
    evidenceEventIds: ['e1', 'e2'],
    detector: 'spam-detector@1.2.0',
    observedAtMs: T0,
  },
];

function makeBundle(capabilities = FULL_CAPS, previous?: { contentHash: string; sequence: number }) {
  const assessment = assessRisk({
    userId: '8F29A1',
    roomId: 'ABC123',
    signals,
    config: DEFAULT_CONFIG.risk,
    nowMs: T0,
  });
  const plan = planResponse({ assessment, config: DEFAULT_CONFIG, capabilities });
  const events = [
    evt({ eventId: 'e1', message: 'i will kill you', receivedAtMs: T0 - 2000 }),
    evt({ eventId: 'e2', message: 'i will kill you', receivedAtMs: T0 - 1000 }),
  ];
  const incident = buildIncident({
    assessment,
    signals,
    plan,
    config: DEFAULT_CONFIG,
    events,
    messageContentAuthorized: capabilities.messageContent,
    nowMs: T0,
  });
  incident.actionsTaken.push(
    recordAction({
      actionType: 'EVIDENCE_SAVED',
      actorKind: 'SYSTEM',
      actorId: 'system',
      targetUserId: incident.userId,
      reason: 'CRITICAL risk: evidence preserved automatically.',
      scope: 'INTERNAL',
      succeeded: true,
      nowMs: T0,
    }),
  );

  return buildEvidenceBundle({
    incident,
    assessment,
    signals,
    capabilities,
    messages: events.map((e) => ({ eventId: e.eventId, atMs: e.receivedAtMs, text: e.message })),
    excerptMaxChars: DEFAULT_CONFIG.abuse.excerptMaxChars,
    nowMs: T0,
    ...(previous ? { previous } : {}),
  });
}

// --- Required fields ------------------------------------------------------

test('evidence: bundle carries every field required by the specification', () => {
  const bundle = makeBundle();
  const b = bundle.body;
  assert.ok(b.incidentId.startsWith('INC-'));
  assert.equal(b.userId, '8F29A1');
  assert.equal(b.roomId, 'ABC123');
  assert.ok(b.createdAt.endsWith('Z'));
  assert.ok(b.detectedBehaviors.includes('THREAT_LANGUAGE'));
  assert.ok(b.detectionReasons.length >= 2);
  assert.equal(typeof b.riskScore, 'number');
  assert.ok(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'].includes(b.riskLevel));
  assert.ok(b.relevantMessages.length > 0);
  assert.ok(b.actionsTaken.length > 0);
  assert.ok(b.confidence > 0 && b.confidence <= 1);
  assert.ok(b.modelVersions.some((v) => v.includes('risk-engine')));
  assert.ok(b.modelVersions.some((v) => v.includes('abuse-classifier')));
});

test('evidence: every detection reason is retained verbatim and attributed', () => {
  const bundle = makeBundle();
  for (const s of bundle.body.signals) {
    assert.ok(s.reason.length > 0);
    assert.match(s.detector, /@\d+\.\d+\.\d+/);
    assert.ok(s.observedAt.endsWith('Z'));
  }
});

test('evidence: actions always record a reason', () => {
  const bundle = makeBundle();
  for (const a of bundle.body.actionsTaken) {
    assert.ok(a.reason.trim().length > 0, 'an action without a reason is not auditable');
  }
});

test('evidence: an action cannot be recorded without a reason', () => {
  assert.throws(
    () =>
      recordAction({
        actionType: 'PLATFORM_MUTE',
        actorKind: 'MODERATOR',
        actorId: 'mod-1',
        targetUserId: 'u1',
        reason: '   ',
        scope: 'PLATFORM_API',
        succeeded: true,
        nowMs: T0,
      }),
    /non-empty reason/,
  );
});

// --- Integrity ------------------------------------------------------------

test('integrity: a freshly built bundle verifies', () => {
  const result = verifyBundle(makeBundle());
  assert.equal(result.valid, true, result.problems.join('; '));
});

test('integrity: modifying the body is detected', () => {
  const bundle = makeBundle();
  bundle.body.riskScore = 1;
  const result = verifyBundle(bundle);
  assert.equal(result.valid, false);
  assert.match(result.problems.join(' '), /modified since it was written/);
});

test('integrity: rewriting a message excerpt is detected', () => {
  const bundle = makeBundle();
  const first = bundle.body.relevantMessages[0];
  assert.ok(first);
  first.text = 'something harmless';
  assert.equal(verifyBundle(bundle).valid, false);
});

test('integrity: deleting a detection reason is detected', () => {
  const bundle = makeBundle();
  bundle.body.detectionReasons.pop();
  assert.equal(verifyBundle(bundle).valid, false);
});

test('integrity: tampering with the chain hash is detected', () => {
  const bundle = makeBundle();
  bundle.chainHash = 'f'.repeat(64);
  const result = verifyBundle(bundle);
  assert.equal(result.valid, false);
  assert.match(result.problems.join(' '), /Chain hash does not match/);
});

test('integrity: hashing is canonical — key order does not change the hash', () => {
  // Reproducible hashes require a canonical encoding, otherwise a bundle
  // re-serialized with different key order would appear tampered with.
  assert.equal(
    hashObject({ a: 1, b: { c: 2, d: [3, 4] } }),
    hashObject({ b: { d: [3, 4], c: 2 }, a: 1 }),
  );
  // ...but a genuine value change must change the hash.
  assert.notEqual(hashObject({ a: 1 }), hashObject({ a: 2 }));
  // Array order is significant, since message ordering is meaningful.
  assert.notEqual(hashObject({ a: [1, 2] }), hashObject({ a: [2, 1] }));
});

// --- Chain ----------------------------------------------------------------

test('chain: a valid multi-bundle chain verifies', () => {
  const first = makeBundle();
  const second = makeBundle(FULL_CAPS, { contentHash: first.contentHash, sequence: first.sequence });
  assert.equal(first.previousHash, GENESIS_HASH);
  assert.equal(first.sequence, 1);
  assert.equal(second.sequence, 2);
  assert.equal(second.previousHash, first.contentHash);

  const result = verifyChain([first, second]);
  assert.equal(result.valid, true, result.problems.join('; '));
});

test('chain: deleting a middle bundle is detected', () => {
  const b1 = makeBundle();
  const b2 = makeBundle(FULL_CAPS, { contentHash: b1.contentHash, sequence: b1.sequence });
  const b3 = makeBundle(FULL_CAPS, { contentHash: b2.contentHash, sequence: b2.sequence });

  const result = verifyChain([b1, b3]);
  assert.equal(result.valid, false);
  const joined = result.problems.join(' ');
  assert.ok(/Sequence gap/.test(joined) || /Broken chain/.test(joined), joined);
});

test('chain: reordering bundles is detected', () => {
  const b1 = makeBundle();
  const b2 = makeBundle(FULL_CAPS, { contentHash: b1.contentHash, sequence: b1.sequence });
  const swapped: EvidenceBundle[] = [
    { ...b2, sequence: 1 },
    { ...b1, sequence: 2 },
  ];
  assert.equal(verifyChain(swapped).valid, false);
});

test('chain: substituting a bundle with a valid-looking forgery is detected', () => {
  const b1 = makeBundle();
  const forged = makeBundle(MINIMAL_CAPS); // self-consistent, but wrong link
  const result = verifyChain([b1, { ...forged, sequence: 2, previousHash: GENESIS_HASH }]);
  assert.equal(result.valid, false);
  assert.match(result.problems.join(' '), /Broken chain/);
});

// --- Privacy / authorization record ---------------------------------------

test('privacy: identifiers in message text are redacted before storage', () => {
  const assessment = assessRisk({ userId: 'u1', signals, config: DEFAULT_CONFIG.risk, nowMs: T0 });
  const plan = planResponse({ assessment, config: DEFAULT_CONFIG, capabilities: FULL_CAPS });
  const events = [
    evt({
      eventId: 'e9',
      message: 'contact me at victim@example.com or +1 (555) 123-4567, ip 192.168.1.44',
      receivedAtMs: T0,
    }),
  ];
  const incident = buildIncident({
    assessment,
    signals,
    plan,
    config: DEFAULT_CONFIG,
    events,
    messageContentAuthorized: true,
    nowMs: T0,
  });

  const text = incident.relevantMessages[0]?.text ?? '';
  assert.ok(!text.includes('victim@example.com'), text);
  assert.ok(!text.includes('555'), text);
  assert.ok(!text.includes('192.168.1.44'), text);
  assert.match(text, /\[redacted-email\]/);
  assert.equal(incident.relevantMessages[0]?.redacted, true);
});

test('privacy: excerpts are truncated to the configured limit', () => {
  const assessment = assessRisk({ userId: 'u1', signals, config: DEFAULT_CONFIG.risk, nowMs: T0 });
  const plan = planResponse({ assessment, config: DEFAULT_CONFIG, capabilities: FULL_CAPS });
  const incident = buildIncident({
    assessment,
    signals,
    plan,
    config: { ...DEFAULT_CONFIG, abuse: { ...DEFAULT_CONFIG.abuse, excerptMaxChars: 20 } },
    events: [evt({ message: 'x'.repeat(500), receivedAtMs: T0 })],
    messageContentAuthorized: true,
    nowMs: T0,
  });
  assert.ok((incident.relevantMessages[0]?.text.length ?? 0) <= 20);
});

test('privacy: no message content is stored when content is not authorized', () => {
  // NO_CAPABILITIES denies message content outright.
  const bundle = makeBundle(NO_CAPABILITIES);
  assert.deepEqual(bundle.body.relevantMessages, []);
  const notCollected = bundle.body.authorization.notCollected.map((n) => n.field);
  assert.ok(notCollected.includes('messageText'));
  const entry = bundle.body.authorization.notCollected.find((n) => n.field === 'messageText');
  assert.match(entry?.reason ?? '', /not authorized/);
});

test('authorization record: states what was and was not collected', () => {
  const bundle = makeBundle(MINIMAL_CAPS);
  const auth = bundle.body.authorization;
  assert.ok(auth.collected.includes('riskAssessment'));

  const fields = auth.notCollected.map((n) => n.field);
  assert.ok(fields.includes('voiceAudio/voiceTranscript'));
  assert.ok(fields.includes('hiddenPresenceEvents'));
  assert.ok(fields.includes('clientAttestation'));
  // Categories never collected under any configuration.
  assert.ok(fields.includes('deviceLocation'));
  assert.ok(fields.includes('deviceIdentifiers'));
  assert.ok(fields.includes('credentials/tokens'));
  assert.ok(fields.includes('networkTraffic'));

  for (const entry of auth.notCollected) {
    assert.ok(entry.reason.length > 0, `${entry.field} must explain why it was not collected`);
  }
});

test('authorization record: the capability snapshot is inside the hashed body', () => {
  const bundle = makeBundle(MINIMAL_CAPS);
  assert.equal(bundle.body.authorization.capabilities.remoteBlock, false);
  // Changing it must break the hash — the boundary is part of the record.
  bundle.body.authorization.capabilities.remoteBlock = true;
  assert.equal(verifyBundle(bundle).valid, false);
});

// --- Keys -----------------------------------------------------------------

test('evidence keys are date-partitioned and sequenced', () => {
  const key = evidenceKey('user-A', 'INC-20260301-ABCD1234', T0, 7);
  assert.match(key, /^evidence\/2026\/03\/01\/[0-9a-f]{4}\/INC-20260301-ABCD1234\/0007\.json$/);
});

test('evidence keys do not embed the raw user id', () => {
  const key = evidenceKey('sensitive-user-name', 'INC-X', T0, 1);
  assert.ok(!key.includes('sensitive-user-name'));
});
