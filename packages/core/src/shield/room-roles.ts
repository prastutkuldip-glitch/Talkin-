/**
 * Room-level roles and what each role is allowed to do to a voice participant.
 *
 * This is the single source of truth for the one-click mute question:
 *
 *   "Can THIS user silence THAT speaker, and for whom?"
 *
 * The answer depends entirely on the requester's authority over the room, and
 * on whether an official platform moderation API exists. It never depends on
 * what the UI shows or what a client claims — a normal user who forges a
 * room-wide request is rejected here, in pure logic that the backend calls
 * before touching the platform.
 *
 * The design keeps the honest line from the rest of the system intact:
 *
 *   - Room-wide silencing (everyone stops hearing the speaker) is only ever a
 *     HOST/MODERATOR action through the official API. It is the platform muting
 *     one of its own participants on the authority of a room operator.
 *   - A normal participant gets LOCAL silencing only — the speaker is dropped
 *     from the requester's own mix. Nobody else is affected and no other device
 *     is touched.
 *   - Nothing here, under any role, disables or jams a microphone. "Mute" means
 *     either "the platform stops relaying this speaker to the room" (official,
 *     authorized) or "my client stops playing this speaker to me" (local). The
 *     speaker's own equipment is never reached.
 */

import type { IntegrationCapabilities } from '../types/telemetry.ts';

export const ROOM_ROLES = ['OWNER', 'MODERATOR', 'PARTICIPANT'] as const;
export type RoomRole = (typeof ROOM_ROLES)[number];

/** The scope at which a silence takes effect. */
export const SILENCE_SCOPES = ['ROOM_WIDE', 'LOCAL_TO_REQUESTER', 'NONE'] as const;
export type SilenceScope = (typeof SILENCE_SCOPES)[number];

/** What a requester asked to do to a speaker. */
export const ROOM_ACTIONS = [
  /** Stop the speaker reaching everyone in the room (platform mute). */
  'ROOM_MUTE',
  /** Remove the speaker from the room entirely (platform kick). */
  'ROOM_KICK',
  /** Stop the speaker reaching only the requester (local mute). */
  'LOCAL_MUTE',
  /** Permanently ignore the speaker for the requester (local block). */
  'LOCAL_BLOCK',
  /** Submit a report with evidence. */
  'REPORT',
] as const;
export type RoomAction = (typeof ROOM_ACTIONS)[number];

export interface RoomContext {
  roomId: string;
  /** The requester's role in THIS room, as the platform reports it. */
  requesterRole: RoomRole;
  requesterId: string;
  targetSpeakerId: string;
  /** Capabilities granted by the connected platform integration. */
  capabilities: IntegrationCapabilities;
  /**
   * True when the target is also an operator. An operator may not room-mute a
   * peer operator unless the requester is the OWNER — this prevents mod wars.
   */
  targetIsOperator?: boolean;
}

export type RoomAuthorization =
  | {
      allowed: true;
      scope: SilenceScope;
      /** Whether this must go through the official platform API. */
      viaPlatformApi: boolean;
      reason: string;
    }
  | {
      allowed: false;
      /** What the requester is offered instead (always something local). */
      fallbackScope: SilenceScope;
      reason: string;
    };

const isOperator = (role: RoomRole): boolean => role === 'OWNER' || role === 'MODERATOR';

/**
 * The core decision. Pure, deterministic, and the only place the room-wide /
 * local distinction is made.
 */
export function authorizeRoomAction(action: RoomAction, ctx: RoomContext): RoomAuthorization {
  switch (action) {
    case 'LOCAL_MUTE':
    case 'LOCAL_BLOCK':
      // Anyone may silence a speaker for themselves. This is control over the
      // requester's own audio output and needs no room authority at all.
      return {
        allowed: true,
        scope: 'LOCAL_TO_REQUESTER',
        viaPlatformApi: false,
        reason:
          'Local protection: the speaker is removed from your own audio only. No one else is affected and the speaker\'s device is untouched.',
      };

    case 'REPORT':
      return {
        allowed: true,
        scope: 'NONE',
        viaPlatformApi: true,
        reason: 'A report with evidence is submitted through the official reporting channel.',
      };

    case 'ROOM_MUTE':
    case 'ROOM_KICK': {
      // Room-wide silencing is an operator action, through the official API.
      if (!isOperator(ctx.requesterRole)) {
        return {
          allowed: false,
          fallbackScope: 'LOCAL_TO_REQUESTER',
          reason:
            'Room-wide mute requires host or moderator authority over this room, which you do not have. ' +
            'You can mute this speaker for yourself instead — they will stop reaching you, and the abuse can be reported for an operator to act on room-wide.',
        };
      }

      const capabilityGranted =
        action === 'ROOM_MUTE' ? ctx.capabilities.remoteMute : ctx.capabilities.remoteBlock;

      if (!capabilityGranted) {
        return {
          allowed: false,
          fallbackScope: 'LOCAL_TO_REQUESTER',
          reason:
            `You have the authority for a room-wide ${action === 'ROOM_MUTE' ? 'mute' : 'kick'}, but no official platform ` +
            'moderation API is configured, so TalkinShield cannot perform it. It will not attempt to silence the speaker ' +
            'for the room by any unofficial means. A local mute is available in the meantime.',
        };
      }

      // A moderator cannot room-mute another operator; only the owner can.
      if (ctx.targetIsOperator === true && ctx.requesterRole !== 'OWNER') {
        return {
          allowed: false,
          fallbackScope: 'LOCAL_TO_REQUESTER',
          reason:
            'The target is also a room operator. Only the room owner can mute or remove another operator. ' +
            'You can still mute them for yourself.',
        };
      }

      return {
        allowed: true,
        scope: 'ROOM_WIDE',
        viaPlatformApi: true,
        reason:
          `Room-wide ${action === 'ROOM_MUTE' ? 'mute' : 'removal'} via the official platform API, on your authority as ` +
          `${ctx.requesterRole.toLowerCase()}. The platform stops relaying this speaker to the room; nothing is done to their device.`,
      };
    }

    default:
      return {
        allowed: false,
        fallbackScope: 'NONE',
        reason: 'Unknown action.',
      };
  }
}

/** The actions a role may even attempt, for building the UI. */
export interface RoomAffordance {
  action: RoomAction;
  label: string;
  /** The scope this will take effect at, given the current room + capabilities. */
  scope: SilenceScope;
  enabled: boolean;
  /** Honest, user-facing description. */
  description: string;
}

/**
 * Build the set of buttons a requester should see. A normal participant simply
 * never receives a room-wide button — it is not rendered, not merely disabled —
 * so the UI cannot imply an authority the user does not hold.
 */
export function roomAffordances(ctx: Omit<RoomContext, 'targetSpeakerId'> & { targetSpeakerId?: string }): RoomAffordance[] {
  const base: RoomAffordance[] = [
    {
      action: 'LOCAL_MUTE',
      label: 'Mute for me',
      scope: 'LOCAL_TO_REQUESTER',
      enabled: true,
      description: 'Stop hearing this speaker. Only your audio changes.',
    },
    {
      action: 'LOCAL_BLOCK',
      label: 'Block for me',
      scope: 'LOCAL_TO_REQUESTER',
      enabled: true,
      description: 'Permanently ignore this speaker for yourself until you undo it.',
    },
    {
      action: 'REPORT',
      label: 'Report',
      scope: 'NONE',
      enabled: true,
      description: 'Send a report with the captured evidence through the official channel.',
    },
  ];

  // Operators additionally get the room-wide controls — but only when an
  // official API backs them. Without the API the button would be a lie.
  if (isOperator(ctx.requesterRole)) {
    base.unshift(
      {
        action: 'ROOM_MUTE',
        label: 'Mute for everyone',
        scope: ctx.capabilities.remoteMute ? 'ROOM_WIDE' : 'LOCAL_TO_REQUESTER',
        enabled: ctx.capabilities.remoteMute,
        description: ctx.capabilities.remoteMute
          ? 'The platform stops relaying this speaker to the room, on your authority. Nothing is done to their device.'
          : 'Unavailable: no official platform mute API is configured for this deployment.',
      },
      {
        action: 'ROOM_KICK',
        label: 'Remove from room',
        scope: ctx.capabilities.remoteBlock ? 'ROOM_WIDE' : 'LOCAL_TO_REQUESTER',
        enabled: ctx.capabilities.remoteBlock,
        description: ctx.capabilities.remoteBlock
          ? 'Remove this speaker from the room via the official platform API, on your authority.'
          : 'Unavailable: no official platform moderation API is configured for this deployment.',
      },
    );
  }

  return base;
}
