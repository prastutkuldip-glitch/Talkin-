import test from 'node:test';
import assert from 'node:assert/strict';

import { NO_CAPABILITIES } from '@talkinshield/core';

import { handleRequest } from '../src/http/router.ts';
import { applyModeration } from '../src/app/moderation-service.ts';
import { authenticate } from '../src/http/auth.ts';
import {
  ADMIN_CLAIMS,
  CONTENT_ONLY_CAPS,
  FULL_CAPS,
  MODERATOR_CLAIMS,
  T0,
  VIEWER_CLAIMS,
  bodyOf,
  harness,
  request,
  testEnv,
} from './harness.ts';

function principal(claims: Record<string, unknown>) {
  const result = authenticate(request('GET', '/x', { claims }), testEnv().auth, T0);
  if (!result.ok) throw new Error('test principal failed authentication');
  return result.principal;
}

const MOD = () => principal(MODERATOR_CLAIMS);

// --- Platform API available ------------------------------------------------

test('moderation: MUTE uses the official API when the capability is granted', async () => {
  const h = harness({ capabilities: FULL_CAPS });
  const result = await applyModeration(
    { kind: 'MUTE', targetUserId: 'user-A', roomId: 'ABC123', reason: 'repeated targeted abuse in voice' },
    MOD(),
    h.deps,
  );

  assert.ok(!('rejected' in result));
  assert.equal(result.applied, true);
  assert.equal(result.scope, 'PLATFORM_API');
  assert.equal(result.platformActionUnavailable, false);
  assert.equal(result.action.actionType, 'PLATFORM_MUTE');
  assert.match(result.message, /official Talkin moderation API/);
  assert.match(result.message, /reversible/);
  assert.equal(h.mockState.muted.length, 1);
  assert.equal(h.mockState.muted[0]?.userId, 'user-A');
});

test('moderation: BLOCK via the official API is time-bounded', async () => {
  const h = harness({ capabilities: FULL_CAPS });
  const result = await applyModeration(
    { kind: 'BLOCK', targetUserId: 'user-A', reason: 'credible threat against a participant', durationSeconds: 3600 },
    MOD(),
    h.deps,
  );
  assert.ok(!('rejected' in result));
  assert.equal(result.scope, 'PLATFORM_API');
  assert.equal(h.mockState.blocked.length, 1);
  assert.equal(h.mockState.blocked[0]?.until, T0 + 3_600_000);
});

test('moderation: block duration is capped at 24 hours', async () => {
  const h = harness({ capabilities: FULL_CAPS });
  await applyModeration(
    { kind: 'BLOCK', targetUserId: 'user-A', reason: 'severe abuse repeated', durationSeconds: 999_999_999 },
    MOD(),
    h.deps,
  );
  assert.equal(h.mockState.blocked[0]?.until, T0 + 24 * 60 * 60 * 1000);
});

// --- THE CRITICAL BOUNDARY: no platform API -------------------------------

test('boundary: MUTE without a platform API degrades to a local mute and says so', async () => {
  const h = harness({ capabilities: CONTENT_ONLY_CAPS });
  const result = await applyModeration(
    { kind: 'MUTE', targetUserId: 'user-A', roomId: 'ABC123', reason: 'shouting over everyone' },
    MOD(),
    h.deps,
  );

  assert.ok(!('rejected' in result));
  assert.equal(result.applied, true);
  assert.equal(result.scope, 'LOCAL_TO_REQUESTER');
  assert.equal(result.platformActionUnavailable, true);
  assert.equal(result.action.actionType, 'LOCAL_MUTE');
  assert.match(result.message, /locally for the protected user only/);
  assert.match(result.message, /other participants still hear this account/);
  assert.match(result.message, /will not attempt to mute another user's microphone/);

  // Nothing was sent to the platform.
  assert.equal(h.mockState.muted.length, 0);
});

test('boundary: BLOCK without a platform API degrades to a local block', async () => {
  const h = harness({ capabilities: CONTENT_ONLY_CAPS });
  const result = await applyModeration(
    { kind: 'BLOCK', targetUserId: 'user-A', reason: 'persistent harassment of a participant' },
    MOD(),
    h.deps,
  );
  assert.ok(!('rejected' in result));
  assert.equal(result.scope, 'LOCAL_TO_REQUESTER');
  assert.equal(result.action.actionType, 'LOCAL_BLOCK');
  assert.match(result.message, /not restricted platform-wide/);
  assert.equal(h.mockState.blocked.length, 0);
});

test('boundary: with no integration at all, every platform action reports unsupported', async () => {
  const h = harness({ useNoopPlatform: true });
  assert.deepEqual(h.deps.platform.capabilities(), NO_CAPABILITIES);

  const mute = await h.deps.platform.mute({
    userId: 'user-A',
    roomId: 'ABC123',
    durationSeconds: 60,
    reason: 'test',
  });
  assert.equal(mute.ok, false);
  assert.ok(!mute.ok && mute.unsupported);
  assert.match(mute.reason, /will not attempt this action by any other means/);
  assert.match(mute.reason, /local mute, block, ignore, report, evidence capture/);
});

test('boundary: hidden presence is never returned without the capability', async () => {
  const h = harness({ capabilities: CONTENT_ONLY_CAPS });
  // Even with data present in the mock fixture, the capability gate wins.
  h.mockState.hiddenPresence.push({
    userId: 'ghost-1',
    roomId: 'ABC123',
    atMs: T0 - 1000,
    kind: 'HIDDEN_JOIN',
  });
  const presence = await h.deps.platform.getHiddenPresence('ABC123', 0);
  assert.deepEqual(presence, []);
});

test('boundary: client attestation returns undefined, not false, when unavailable', async () => {
  const h = harness({ capabilities: CONTENT_ONLY_CAPS });
  const result = await h.deps.platform.verifyClient('user-A', '4.2.1');
  assert.equal(result, undefined, 'absence of attestation must not be reported as failure');
});

test('boundary: restrictions are empty without the moderation-events capability', async () => {
  const h = harness({ capabilities: { ...NO_CAPABILITIES, messageContent: true } });
  h.mockState.restrictions.set('user-A', [{ appliedAtMs: T0 - 1000, kind: 'MUTE' }]);
  assert.deepEqual(await h.deps.platform.getRestrictions('user-A'), []);
});

// --- Local-only actions ----------------------------------------------------

test('moderation: IGNORE is always local and never touches the platform', async () => {
  const h = harness({ capabilities: FULL_CAPS });
  const result = await applyModeration(
    { kind: 'IGNORE', targetUserId: 'user-A', reason: 'user prefers not to hear this account' },
    MOD(),
    h.deps,
  );
  assert.ok(!('rejected' in result));
  assert.equal(result.scope, 'LOCAL_TO_REQUESTER');
  assert.equal(result.action.actionType, 'LOCAL_IGNORE');
  assert.match(result.message, /affects no one else/);
  assert.equal(h.mockState.muted.length, 0);
  assert.equal(h.mockState.blocked.length, 0);
});

test('moderation: REPORT attaches the incident evidence keys', async () => {
  const h = harness({ capabilities: FULL_CAPS });
  await h.incidents.put({
    incidentId: 'INC-TEST-1',
    userId: 'user-A',
    createdAtMs: T0,
    updatedAtMs: T0,
    status: 'OPEN',
    riskScore: 80,
    riskLevel: 'CRITICAL',
    detectedBehaviors: ['THREAT_LANGUAGE'],
    detectionReasons: ['threat detected'],
    relevantMessages: [],
    authorizedMetadata: {},
    actionsTaken: [],
    confidence: 0.9,
    modelVersions: ['risk-engine@1.1.0'],
    evidenceKeys: ['evidence/2026/03/01/abcd/INC-TEST-1/0001.json'],
  });

  const result = await applyModeration(
    {
      kind: 'REPORT',
      targetUserId: 'user-A',
      reason: 'threat of violence against another participant',
      incidentId: 'INC-TEST-1',
    },
    MOD(),
    h.deps,
  );
  assert.ok(!('rejected' in result));
  assert.equal(result.applied, true);
  assert.equal(h.mockState.reports.length, 1);
  assert.deepEqual(h.mockState.reports[0]?.evidenceKeys, [
    'evidence/2026/03/01/abcd/INC-TEST-1/0001.json',
  ]);
});

// --- Reason enforcement ----------------------------------------------------

test('moderation: an action without a meaningful reason is rejected', async () => {
  const h = harness({ capabilities: FULL_CAPS });
  for (const reason of ['', '   ', 'bad']) {
    const result = await applyModeration(
      { kind: 'MUTE', targetUserId: 'user-A', reason },
      MOD(),
      h.deps,
    );
    assert.ok('rejected' in result, `reason ${JSON.stringify(reason)} should be rejected`);
    assert.match(result.rejected, /must be explainable in the audit trail/);
  }
  assert.equal(h.mockState.muted.length, 0);
});

test('moderation: the reason records who acted', async () => {
  const h = harness({ capabilities: FULL_CAPS });
  const result = await applyModeration(
    { kind: 'MUTE', targetUserId: 'user-A', roomId: 'R1', reason: 'spamming identical links' },
    MOD(),
    h.deps,
  );
  assert.ok(!('rejected' in result));
  assert.match(result.action.reason, /actioned by alice/);
});

// --- Audit -----------------------------------------------------------------

test('moderation: every action writes an audit entry', async () => {
  const h = harness({ capabilities: FULL_CAPS });
  await applyModeration(
    { kind: 'MUTE', targetUserId: 'user-A', roomId: 'R1', reason: 'disrupting the room repeatedly' },
    MOD(),
    h.deps,
  );

  const entry = h.audit.snapshot.find((e) => e.action === 'MODERATION_MUTE');
  assert.ok(entry);
  assert.equal(entry.actorId, 'mod-1');
  assert.equal(entry.actorKind, 'MODERATOR');
  assert.equal(entry.target, 'user-A');
  assert.equal(entry.outcome, 'SUCCESS');
  assert.equal(entry.detail?.scope, 'PLATFORM_API');
  assert.match(entry.reason, /disrupting the room/);
});

test('moderation: a failed platform action is still audited and recorded', async () => {
  const h = harness({ capabilities: FULL_CAPS });
  h.deps.platform.mute = async () => ({ ok: false, unsupported: false, reason: 'platform returned HTTP 503.' });

  const result = await applyModeration(
    { kind: 'MUTE', targetUserId: 'user-A', roomId: 'R1', reason: 'spam flood in progress' },
    MOD(),
    h.deps,
  );
  assert.ok(!('rejected' in result));
  assert.equal(result.applied, false);
  assert.equal(result.action.succeeded, false);
  assert.equal(result.action.failureReason, 'platform returned HTTP 503.');

  const entry = h.audit.snapshot.find((e) => e.action === 'MODERATION_MUTE');
  assert.equal(entry?.outcome, 'FAILURE');
});

test('moderation: a thrown platform error is contained and recorded', async () => {
  const h = harness({ capabilities: FULL_CAPS });
  h.deps.platform.mute = async () => {
    throw new Error('connection reset');
  };

  const result = await applyModeration(
    { kind: 'MUTE', targetUserId: 'user-A', roomId: 'R1', reason: 'persistent abuse of a participant' },
    MOD(),
    h.deps,
  );
  assert.ok(!('rejected' in result));
  assert.equal(result.applied, false);
  assert.match(result.message, /connection reset/);
  assert.equal(result.action.succeeded, false);
});

test('moderation: actions are published for downstream consumers', async () => {
  const h = harness({ capabilities: FULL_CAPS });
  await applyModeration(
    { kind: 'BLOCK', targetUserId: 'user-A', reason: 'severe abuse confirmed by review' },
    MOD(),
    h.deps,
  );
  const published = h.publisher.published.find((p) => p.detailType === 'ModerationActionTaken');
  assert.ok(published);
  assert.equal(published.detail.kind, 'BLOCK');
  assert.equal(published.detail.scope, 'PLATFORM_API');
});

// --- Through the API -------------------------------------------------------

test('API: moderation requires a valid action and target', async () => {
  const h = harness({ capabilities: FULL_CAPS });

  const badAction = await handleRequest(
    request('POST', '/moderation', {
      claims: MODERATOR_CLAIMS,
      body: { action: 'DELETE_ACCOUNT', targetUserId: 'user-A', reason: 'because i can' },
    }),
    h.deps,
  );
  assert.equal(badAction.statusCode, 400);

  const badTarget = await handleRequest(
    request('POST', '/moderation', {
      claims: MODERATOR_CLAIMS,
      body: { action: 'MUTE', targetUserId: '../../etc/passwd', reason: 'path traversal attempt' },
    }),
    h.deps,
  );
  assert.equal(badTarget.statusCode, 400);
});

test('API: the response states the true scope of the action', async () => {
  const h = harness({ capabilities: CONTENT_ONLY_CAPS });
  const response = await handleRequest(
    request('POST', '/moderation', {
      claims: MODERATOR_CLAIMS,
      body: { action: 'MUTE', targetUserId: 'user-A', reason: 'repeatedly spamming the room' },
    }),
    h.deps,
  );
  assert.equal(response.statusCode, 200);
  const body = bodyOf<{ scope: string; platformActionUnavailable: boolean; message: string }>(response);
  assert.equal(body.scope, 'LOCAL_TO_REQUESTER');
  assert.equal(body.platformActionUnavailable, true);
  assert.match(body.message, /local/i);
});

test('API: affordances describe each button honestly', async () => {
  const withApi = harness({ capabilities: FULL_CAPS });
  const withoutApi = harness({ capabilities: CONTENT_ONLY_CAPS });

  const a = bodyOf<{ affordances: Array<{ action: string; scope: string; description: string }> }>(
    await handleRequest(request('GET', '/moderation/affordances', { claims: MODERATOR_CLAIMS }), withApi.deps),
  );
  const b = bodyOf<{
    affordances: Array<{ action: string; scope: string; description: string }>;
    unavailableData: Array<{ field: string; status: string }>;
  }>(
    await handleRequest(
      request('GET', '/moderation/affordances', { claims: MODERATOR_CLAIMS }),
      withoutApi.deps,
    ),
  );

  assert.equal(a.affordances.find((x) => x.action === 'MUTE')?.scope, 'PLATFORM_API');
  assert.equal(b.affordances.find((x) => x.action === 'MUTE')?.scope, 'LOCAL_TO_REQUESTER');

  // The unavailable-data inventory must list the out-of-scope categories.
  const fields = b.unavailableData.map((u) => u.field);
  assert.ok(fields.includes('Location / GPS'));
  assert.ok(fields.includes('Camera / microphone control'));
  assert.ok(fields.includes('Credentials & tokens'));
  for (const field of b.unavailableData) {
    assert.ok(['UNAVAILABLE', 'OUT_OF_SCOPE'].includes(field.status));
  }
});

// --- Incident review -------------------------------------------------------

test('API: a false-positive dismissal requires a note and emits a tuning signal', async () => {
  const h = harness({ capabilities: FULL_CAPS });
  await h.incidents.put({
    incidentId: 'INC-FP-1',
    userId: 'user-B',
    createdAtMs: T0,
    updatedAtMs: T0,
    status: 'OPEN',
    riskScore: 60,
    riskLevel: 'HIGH',
    detectedBehaviors: ['SPAM_NEAR_DUPLICATE'],
    detectionReasons: ['near duplicates detected'],
    relevantMessages: [],
    authorizedMetadata: {},
    actionsTaken: [],
    confidence: 0.6,
    modelVersions: ['risk-engine@1.1.0'],
    evidenceKeys: [],
  });

  const noNote = await handleRequest(
    request('PATCH', '/incidents/INC-FP-1', {
      claims: MODERATOR_CLAIMS,
      body: { status: 'DISMISSED_FALSE_POSITIVE' },
    }),
    h.deps,
  );
  assert.equal(noNote.statusCode, 400);

  const dismissed = await handleRequest(
    request('PATCH', '/incidents/INC-FP-1', {
      claims: MODERATOR_CLAIMS,
      body: {
        status: 'DISMISSED_FALSE_POSITIVE',
        reviewNote: 'Legitimate quiz host repeating the same question; not spam.',
      },
    }),
    h.deps,
  );
  assert.equal(dismissed.statusCode, 200);

  assert.equal(h.metrics.total('FalsePositiveReported'), 1);
  assert.ok(h.publisher.published.some((p) => p.detailType === 'FalsePositiveReported'));

  const audited = h.audit.snapshot.find((e) => e.action === 'INCIDENT_STATUS_CHANGED');
  assert.ok(audited);
  assert.match(audited.reason, /Legitimate quiz host/);
});

test('API: an unknown incident status is rejected', async () => {
  const h = harness();
  const response = await handleRequest(
    request('PATCH', '/incidents/INC-X', {
      claims: MODERATOR_CLAIMS,
      body: { status: 'DELETED_FOREVER', reviewNote: 'trying something odd' },
    }),
    h.deps,
  );
  assert.equal(response.statusCode, 400);
});

test('API: a viewer cannot change incident status', async () => {
  const h = harness();
  const response = await handleRequest(
    request('PATCH', '/incidents/INC-X', {
      claims: VIEWER_CLAIMS,
      body: { status: 'CLOSED', reviewNote: 'looks fine to me honestly' },
    }),
    h.deps,
  );
  assert.equal(response.statusCode, 403);
});

test('API: an admin may also moderate', async () => {
  const h = harness({ capabilities: FULL_CAPS });
  const response = await handleRequest(
    request('POST', '/moderation', {
      claims: ADMIN_CLAIMS,
      body: { action: 'MUTE', targetUserId: 'user-A', roomId: 'R1', reason: 'clear policy violation' },
    }),
    h.deps,
  );
  assert.equal(response.statusCode, 200);
});
