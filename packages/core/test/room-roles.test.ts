import test from 'node:test';
import assert from 'node:assert/strict';

import {
  authorizeRoomAction,
  roomAffordances,
  type RoomContext,
} from '../src/shield/room-roles.ts';
import type { IntegrationCapabilities } from '../src/types/telemetry.ts';

const WITH_API: IntegrationCapabilities = {
  messageContent: true,
  moderationEvents: true,
  voiceAudio: true,
  hiddenPresenceEvents: false,
  clientAttestation: false,
  remoteMute: true,
  remoteBlock: true,
};

const NO_API: IntegrationCapabilities = { ...WITH_API, remoteMute: false, remoteBlock: false };

function ctx(overrides: Partial<RoomContext> = {}): RoomContext {
  return {
    roomId: 'ABC123',
    requesterRole: 'PARTICIPANT',
    requesterId: 'me',
    targetSpeakerId: 'spk-1',
    capabilities: WITH_API,
    ...overrides,
  };
}

// --- Local actions: anyone, always -----------------------------------------

test('local mute is allowed for a normal participant', () => {
  const r = authorizeRoomAction('LOCAL_MUTE', ctx({ requesterRole: 'PARTICIPANT' }));
  assert.ok(r.allowed);
  assert.equal(r.scope, 'LOCAL_TO_REQUESTER');
  assert.equal(r.viaPlatformApi, false);
  assert.match(r.reason, /your own audio only/);
});

test('local block is allowed for everyone and needs no room authority', () => {
  for (const role of ['OWNER', 'MODERATOR', 'PARTICIPANT'] as const) {
    const r = authorizeRoomAction('LOCAL_BLOCK', ctx({ requesterRole: role }));
    assert.ok(r.allowed);
    assert.equal(r.scope, 'LOCAL_TO_REQUESTER');
  }
});

// --- Room-wide: the authority line -----------------------------------------

test('a normal participant CANNOT room-mute; offered a local mute instead', () => {
  const r = authorizeRoomAction('ROOM_MUTE', ctx({ requesterRole: 'PARTICIPANT' }));
  assert.ok(!r.allowed);
  assert.equal(r.fallbackScope, 'LOCAL_TO_REQUESTER');
  assert.match(r.reason, /requires host or moderator authority/);
  assert.match(r.reason, /mute this speaker for yourself/);
});

test('a normal participant CANNOT kick', () => {
  const r = authorizeRoomAction('ROOM_KICK', ctx({ requesterRole: 'PARTICIPANT' }));
  assert.ok(!r.allowed);
});

test('a moderator CAN room-mute via the official API', () => {
  const r = authorizeRoomAction('ROOM_MUTE', ctx({ requesterRole: 'MODERATOR' }));
  assert.ok(r.allowed);
  assert.equal(r.scope, 'ROOM_WIDE');
  assert.equal(r.viaPlatformApi, true);
  assert.match(r.reason, /official platform API/);
  assert.match(r.reason, /nothing is done to their device/);
});

test('an owner CAN room-mute and kick', () => {
  assert.ok(authorizeRoomAction('ROOM_MUTE', ctx({ requesterRole: 'OWNER' })).allowed);
  assert.ok(authorizeRoomAction('ROOM_KICK', ctx({ requesterRole: 'OWNER' })).allowed);
});

// --- Room-wide without an official API --------------------------------------

test('an operator with no platform API cannot room-mute; falls back to local', () => {
  const r = authorizeRoomAction('ROOM_MUTE', ctx({ requesterRole: 'MODERATOR', capabilities: NO_API }));
  assert.ok(!r.allowed);
  assert.equal(r.fallbackScope, 'LOCAL_TO_REQUESTER');
  assert.match(r.reason, /no official platform/i);
  assert.match(r.reason, /will not attempt to silence the speaker for the room by any unofficial means/);
});

// --- Operator-vs-operator guard --------------------------------------------

test('a moderator cannot room-mute another operator; only the owner can', () => {
  const modVsMod = authorizeRoomAction(
    'ROOM_MUTE',
    ctx({ requesterRole: 'MODERATOR', targetIsOperator: true }),
  );
  assert.ok(!modVsMod.allowed);
  assert.match(modVsMod.reason, /Only the room owner/);

  const ownerVsMod = authorizeRoomAction(
    'ROOM_MUTE',
    ctx({ requesterRole: 'OWNER', targetIsOperator: true }),
  );
  assert.ok(ownerVsMod.allowed);
});

// --- Affordances: the UI never offers an authority the user lacks ----------

test('a participant is NOT shown any room-wide button', () => {
  const buttons = roomAffordances(ctx({ requesterRole: 'PARTICIPANT' }));
  const actions = buttons.map((b) => b.action);
  assert.ok(!actions.includes('ROOM_MUTE'));
  assert.ok(!actions.includes('ROOM_KICK'));
  // But they always get local protection and report.
  assert.ok(actions.includes('LOCAL_MUTE'));
  assert.ok(actions.includes('LOCAL_BLOCK'));
  assert.ok(actions.includes('REPORT'));
});

test('an operator IS shown room-wide buttons, enabled when the API exists', () => {
  const withApi = roomAffordances(ctx({ requesterRole: 'MODERATOR', capabilities: WITH_API }));
  const roomMute = withApi.find((b) => b.action === 'ROOM_MUTE');
  assert.ok(roomMute);
  assert.equal(roomMute.enabled, true);
  assert.equal(roomMute.scope, 'ROOM_WIDE');
  assert.match(roomMute.description, /nothing is done to their device/i);
});

test('an operator with no API sees the room-wide button DISABLED, not a false promise', () => {
  const noApi = roomAffordances(ctx({ requesterRole: 'OWNER', capabilities: NO_API }));
  const roomMute = noApi.find((b) => b.action === 'ROOM_MUTE');
  assert.ok(roomMute);
  assert.equal(roomMute.enabled, false);
  assert.match(roomMute.description, /Unavailable: no official platform mute API/);
});

test('every room-wide authorization is explicitly via the official platform API', () => {
  // There is no allowed room-wide path that bypasses the platform.
  for (const role of ['OWNER', 'MODERATOR'] as const) {
    const r = authorizeRoomAction('ROOM_MUTE', ctx({ requesterRole: role }));
    if (r.allowed && r.scope === 'ROOM_WIDE') {
      assert.equal(r.viaPlatformApi, true);
    }
  }
});
