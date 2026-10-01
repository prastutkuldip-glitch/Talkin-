import test from 'node:test';
import assert from 'node:assert/strict';

import type { RoomRole } from '@talkinshield/core';

import {
  performVoiceRoomAction,
  voiceRoomAffordances,
  type VoiceRoomDeps,
} from '../src/app/voice-room-service.ts';
import { authenticate } from '../src/http/auth.ts';
import { CONTENT_ONLY_CAPS, FULL_CAPS, MODERATOR_CLAIMS, T0, harness, request, testEnv } from './harness.ts';

function principal() {
  const r = authenticate(request('GET', '/x', { claims: MODERATOR_CLAIMS }), testEnv().auth, T0);
  if (!r.ok) throw new Error('auth failed');
  return r.principal;
}

function deps(
  h: ReturnType<typeof harness>,
  role: RoomRole,
  targetIsOperator = false,
): VoiceRoomDeps {
  return {
    platform: h.deps.platform,
    actions: h.deps.actions,
    audit: h.deps.audit,
    publisher: h.deps.publisher,
    logger: h.deps.logger,
    clock: h.deps.clock,
    resolveRoomRole: async () => role,
    resolveTargetIsOperator: async () => targetIsOperator,
  };
}

const REASON = 'repeatedly shouting slurs over everyone in the room';

// --- HOST / OWNER -----------------------------------------------------------

test('owner can mute a speaker room-wide via the official API', async () => {
  const h = harness({ capabilities: FULL_CAPS });
  const result = await performVoiceRoomAction(
    { action: 'ROOM_MUTE', roomId: 'ABC123', targetSpeakerId: 'spk-1', reason: REASON },
    principal(),
    deps(h, 'OWNER'),
  );
  assert.ok(!('rejected' in result));
  assert.equal(result.applied, true);
  assert.equal(result.scope, 'ROOM_WIDE');
  assert.match(result.message, /official platform API/);
  assert.match(result.message, /stopped relaying this speaker/);
  assert.equal(h.mockState.muted.length, 1);
  assert.equal(h.mockState.muted[0]?.userId, 'spk-1');
});

test('owner can remove (kick) a speaker from the room', async () => {
  const h = harness({ capabilities: FULL_CAPS });
  const result = await performVoiceRoomAction(
    { action: 'ROOM_KICK', roomId: 'ABC123', targetSpeakerId: 'spk-1', reason: REASON },
    principal(),
    deps(h, 'OWNER'),
  );
  assert.ok(!('rejected' in result));
  assert.equal(result.scope, 'ROOM_WIDE');
  assert.equal(h.mockState.blocked.length, 1);
});

// --- MODERATOR --------------------------------------------------------------

test('moderator can mute a normal speaker room-wide', async () => {
  const h = harness({ capabilities: FULL_CAPS });
  const result = await performVoiceRoomAction(
    { action: 'ROOM_MUTE', roomId: 'ABC123', targetSpeakerId: 'spk-1', reason: REASON },
    principal(),
    deps(h, 'MODERATOR'),
  );
  assert.ok(!('rejected' in result));
  assert.equal(result.applied, true);
  assert.equal(result.scope, 'ROOM_WIDE');
});

test('moderator CANNOT room-mute another operator; offered local mute', async () => {
  const h = harness({ capabilities: FULL_CAPS });
  const result = await performVoiceRoomAction(
    { action: 'ROOM_MUTE', roomId: 'ABC123', targetSpeakerId: 'other-mod', reason: REASON },
    principal(),
    deps(h, 'MODERATOR', /* targetIsOperator */ true),
  );
  assert.ok(!('rejected' in result));
  assert.equal(result.applied, false);
  assert.equal(result.scope, 'LOCAL_TO_REQUESTER');
  assert.match(result.message, /Only the room owner/);
  // Nothing was muted platform-wide.
  assert.equal(h.mockState.muted.length, 0);
});

// --- NORMAL PARTICIPANT -----------------------------------------------------

test('participant CANNOT room-mute; the request is refused and nothing hits the platform', async () => {
  const h = harness({ capabilities: FULL_CAPS });
  const result = await performVoiceRoomAction(
    { action: 'ROOM_MUTE', roomId: 'ABC123', targetSpeakerId: 'spk-1', reason: REASON },
    principal(),
    deps(h, 'PARTICIPANT'),
  );
  assert.ok(!('rejected' in result));
  assert.equal(result.applied, false);
  assert.match(result.message, /requires host or moderator authority/);
  assert.match(result.message, /mute this speaker for yourself/);
  // The anti-forgery guarantee: the platform was never called.
  assert.equal(h.mockState.muted.length, 0);
  assert.equal(h.mockState.blocked.length, 0);

  // The refusal is audited as DENIED.
  assert.ok(h.audit.snapshot.some((e) => e.action === 'VOICE_ROOM_MUTE' && e.outcome === 'DENIED'));
});

test('participant CAN mute a speaker locally, for themselves only', async () => {
  const h = harness({ capabilities: FULL_CAPS });
  const result = await performVoiceRoomAction(
    { action: 'LOCAL_MUTE', roomId: 'ABC123', targetSpeakerId: 'spk-1', reason: REASON },
    principal(),
    deps(h, 'PARTICIPANT'),
  );
  assert.ok(!('rejected' in result));
  assert.equal(result.applied, true);
  assert.equal(result.scope, 'LOCAL_TO_REQUESTER');
  assert.equal(result.locallySilencedSpeakerId, 'spk-1');
  assert.match(result.message, /your own audio only/);
  // Local action never touches the platform.
  assert.equal(h.mockState.muted.length, 0);
});

test('participant can block a speaker locally', async () => {
  const h = harness({ capabilities: FULL_CAPS });
  const result = await performVoiceRoomAction(
    { action: 'LOCAL_BLOCK', roomId: 'ABC123', targetSpeakerId: 'spk-1', reason: REASON },
    principal(),
    deps(h, 'PARTICIPANT'),
  );
  assert.ok(!('rejected' in result));
  assert.equal(result.scope, 'LOCAL_TO_REQUESTER');
});

// --- No platform API --------------------------------------------------------

test('operator with no platform API cannot room-mute; falls back to local, platform untouched', async () => {
  const h = harness({ capabilities: CONTENT_ONLY_CAPS });
  const result = await performVoiceRoomAction(
    { action: 'ROOM_MUTE', roomId: 'ABC123', targetSpeakerId: 'spk-1', reason: REASON },
    principal(),
    deps(h, 'OWNER'),
  );
  assert.ok(!('rejected' in result));
  assert.equal(result.applied, false);
  assert.match(result.message, /no official platform/i);
  assert.match(result.message, /will not attempt to silence the speaker for the room by any unofficial means/);
  assert.equal(h.mockState.muted.length, 0);
});

// --- Affordances per role ---------------------------------------------------

test('affordances: a participant is not offered any room-wide button', async () => {
  const h = harness({ capabilities: FULL_CAPS });
  const { role, affordances } = await voiceRoomAffordances('ABC123', principal(), deps(h, 'PARTICIPANT'));
  assert.equal(role, 'PARTICIPANT');
  const actions = affordances.map((a) => a.action);
  assert.ok(!actions.includes('ROOM_MUTE'));
  assert.ok(!actions.includes('ROOM_KICK'));
  assert.ok(actions.includes('LOCAL_MUTE'));
});

test('affordances: an operator is offered room-wide buttons, enabled when the API exists', async () => {
  const h = harness({ capabilities: FULL_CAPS });
  const { affordances } = await voiceRoomAffordances('ABC123', principal(), deps(h, 'OWNER'));
  const roomMute = affordances.find((a) => a.action === 'ROOM_MUTE');
  assert.ok(roomMute);
  assert.equal(roomMute.enabled, true);
  assert.equal(roomMute.scope, 'ROOM_WIDE');
});

test('affordances: an operator with no API sees the room-wide button disabled', async () => {
  const h = harness({ capabilities: CONTENT_ONLY_CAPS });
  const { affordances } = await voiceRoomAffordances('ABC123', principal(), deps(h, 'MODERATOR'));
  const roomMute = affordances.find((a) => a.action === 'ROOM_MUTE');
  assert.ok(roomMute);
  assert.equal(roomMute.enabled, false);
});

// --- Reason enforcement -----------------------------------------------------

test('an action without a real reason is rejected', async () => {
  const h = harness({ capabilities: FULL_CAPS });
  const result = await performVoiceRoomAction(
    { action: 'ROOM_MUTE', roomId: 'ABC123', targetSpeakerId: 'spk-1', reason: 'x' },
    principal(),
    deps(h, 'OWNER'),
  );
  assert.ok('rejected' in result);
  assert.equal(h.mockState.muted.length, 0);
});

// --- Every room-wide success is auditable -----------------------------------

test('a room-wide mute is audited with the role and room', async () => {
  const h = harness({ capabilities: FULL_CAPS });
  await performVoiceRoomAction(
    { action: 'ROOM_MUTE', roomId: 'ABC123', targetSpeakerId: 'spk-1', reason: REASON },
    principal(),
    deps(h, 'OWNER'),
  );
  const entry = h.audit.snapshot.find((e) => e.action === 'VOICE_ROOM_MUTE' && e.outcome === 'SUCCESS');
  assert.ok(entry);
  assert.equal(entry.detail?.role, 'OWNER');
  assert.equal(entry.detail?.roomId, 'ABC123');
});
