/**
 * Voice-room actions, routed by the requester's role in the room.
 *
 * This is the one-click "silence this speaker" entry point, and it is where the
 * authority line is enforced for voice rooms:
 *
 *   - OWNER / MODERATOR → room-wide mute or kick through the official platform
 *     API. Everyone stops hearing the speaker because the platform stops
 *     relaying them, on the operator's authority.
 *   - PARTICIPANT → local silencing only. The speaker is dropped from the
 *     requester's own mix. A room-wide request from a participant is rejected
 *     here (and the UI never offers it), and they are given the local option
 *     plus report-with-evidence instead.
 *
 * The role itself is taken from the platform's view of the room, never from a
 * client-supplied claim — see `resolveRoomRole`. A forged room-wide request
 * therefore fails authorization even if a tampered client sent it.
 *
 * Nothing here reaches the target's device or microphone. "Room mute" is the
 * platform declining to relay a participant; "local mute" is the requester's
 * client declining to play them. Neither touches the speaker's equipment.
 */

import {
  authorizeRoomAction,
  newAuditId,
  recordAction,
  roomAffordances,
  type ActionRecord,
  type RoomAction,
  type RoomAffordance,
  type RoomRole,
} from '@talkinshield/core';

import type { Principal } from '../http/auth.ts';
import type {
  ActionStore,
  AuditStore,
  Clock,
  EventPublisher,
  Logger,
  TalkinPlatformAdapter,
} from '../ports.ts';
import { errorMessage } from './analysis-service.ts';

export interface VoiceRoomDeps {
  platform: TalkinPlatformAdapter;
  actions: ActionStore;
  audit: AuditStore;
  publisher: EventPublisher;
  logger: Logger;
  clock: Clock;
  /**
   * Resolves the requester's role in a room from the platform's own view.
   * Supplied by the adapter layer; defaults to PARTICIPANT (least privilege)
   * when the platform cannot confirm an operator role.
   */
  resolveRoomRole: (roomId: string, userId: string) => Promise<RoomRole>;
  /** Whether the target is also a room operator, for the mod-vs-mod guard. */
  resolveTargetIsOperator?: (roomId: string, targetUserId: string) => Promise<boolean>;
}

export interface VoiceRoomRequest {
  action: RoomAction;
  roomId: string;
  targetSpeakerId: string;
  reason: string;
  /** Seconds, for room/local mute. Capped by the service. */
  durationSeconds?: number;
}

export interface VoiceRoomOutcome {
  applied: boolean;
  scope: 'ROOM_WIDE' | 'LOCAL_TO_REQUESTER' | 'NONE';
  /** Plain-language result for the requester. */
  message: string;
  /** The requester's resolved role, echoed so the UI can reflect it. */
  role: RoomRole;
  /** For LOCAL scope: the speaker id the requester's client should drop. */
  locallySilencedSpeakerId?: string;
  action: ActionRecord;
}

const MAX_DURATION_SECONDS = 24 * 60 * 60;
const MIN_REASON_LENGTH = 8;

export async function performVoiceRoomAction(
  request: VoiceRoomRequest,
  principal: Principal,
  deps: VoiceRoomDeps,
): Promise<VoiceRoomOutcome | { rejected: string }> {
  const reason = request.reason.trim();
  if (reason.length < MIN_REASON_LENGTH) {
    return {
      rejected: `A reason of at least ${MIN_REASON_LENGTH} characters is required: every action must be explainable in the audit trail.`,
    };
  }

  const nowMs = deps.clock.now();
  const capabilities = deps.platform.capabilities();
  const duration = Math.min(request.durationSeconds ?? 900, MAX_DURATION_SECONDS);

  // Role comes from the platform, not the request. This is the anti-forgery
  // control: a participant cannot elevate themselves by sending a room-wide
  // action, because their resolved role is still PARTICIPANT.
  const requesterRole = await deps.resolveRoomRole(request.roomId, principal.subject);
  const targetIsOperator =
    deps.resolveTargetIsOperator !== undefined
      ? await deps.resolveTargetIsOperator(request.roomId, request.targetSpeakerId)
      : false;

  const decision = authorizeRoomAction(request.action, {
    roomId: request.roomId,
    requesterRole,
    requesterId: principal.subject,
    targetSpeakerId: request.targetSpeakerId,
    capabilities,
    targetIsOperator,
  });

  const attributed = `${reason} (by ${principal.username}, role ${requesterRole})`;

  // --- Not allowed: record the refusal and hand back the local fallback ---
  if (!decision.allowed) {
    const action = recordAction({
      actionType: request.action === 'ROOM_KICK' ? 'PLATFORM_BLOCK' : 'PLATFORM_MUTE',
      actorKind: 'MODERATOR',
      actorId: principal.subject,
      targetUserId: request.targetSpeakerId,
      roomId: request.roomId,
      reason: `Refused: ${decision.reason}`,
      scope: 'INTERNAL',
      succeeded: false,
      failureReason: decision.reason,
      nowMs,
    });
    await deps.actions.put(action);
    await audit(deps, principal, request, 'DENIED', decision.reason, requesterRole, nowMs);

    return {
      applied: false,
      scope: decision.fallbackScope === 'ROOM_WIDE' ? 'NONE' : decision.fallbackScope,
      message: decision.reason,
      role: requesterRole,
      action,
    };
  }

  // --- Local scope: nothing leaves the requester's own client -------------
  if (decision.scope === 'LOCAL_TO_REQUESTER') {
    const action = recordAction({
      actionType: request.action === 'LOCAL_BLOCK' ? 'LOCAL_BLOCK' : 'LOCAL_MUTE',
      actorKind: 'MODERATOR',
      actorId: principal.subject,
      targetUserId: request.targetSpeakerId,
      roomId: request.roomId,
      reason: attributed,
      scope: 'LOCAL_TO_REQUESTER',
      succeeded: true,
      nowMs,
    });
    await deps.actions.put(action);
    await deps.publisher.publish('LocalSilenceApplied', {
      roomId: request.roomId,
      requesterId: principal.subject,
      speakerId: request.targetSpeakerId,
      action: request.action,
    });
    await audit(deps, principal, request, 'SUCCESS', decision.reason, requesterRole, nowMs);

    return {
      applied: true,
      scope: 'LOCAL_TO_REQUESTER',
      message: decision.reason,
      role: requesterRole,
      locallySilencedSpeakerId: request.targetSpeakerId,
      action,
    };
  }

  // --- Report ------------------------------------------------------------
  if (request.action === 'REPORT') {
    try {
      const result = await deps.platform.report({
        userId: request.targetSpeakerId,
        roomId: request.roomId,
        reason: attributed,
        evidenceKeys: [],
      });
      const action = recordAction({
        actionType: 'REPORT_SUBMITTED',
        actorKind: 'MODERATOR',
        actorId: principal.subject,
        targetUserId: request.targetSpeakerId,
        roomId: request.roomId,
        reason: attributed,
        scope: 'PLATFORM_API',
        succeeded: result.ok,
        ...(result.ok ? {} : { failureReason: result.reason }),
        nowMs,
      });
      await deps.actions.put(action);
      await audit(deps, principal, request, result.ok ? 'SUCCESS' : 'FAILURE', decision.reason, requesterRole, nowMs);
      return {
        applied: result.ok,
        scope: 'NONE',
        message: result.ok
          ? 'Report submitted through the official reporting channel.'
          : `Report could not be submitted: ${result.reason}`,
        role: requesterRole,
        action,
      };
    } catch (err: unknown) {
      return handleThrow(deps, request, principal, requesterRole, nowMs, errorMessage(err));
    }
  }

  // --- Room-wide via the official platform API ----------------------------
  try {
    const result =
      request.action === 'ROOM_KICK'
        ? await deps.platform.block({
            userId: request.targetSpeakerId,
            roomId: request.roomId,
            durationSeconds: duration,
            reason: attributed,
          })
        : await deps.platform.mute({
            userId: request.targetSpeakerId,
            roomId: request.roomId,
            durationSeconds: duration,
            reason: attributed,
          });

    const action = recordAction({
      actionType: request.action === 'ROOM_KICK' ? 'PLATFORM_BLOCK' : 'PLATFORM_MUTE',
      actorKind: 'MODERATOR',
      actorId: principal.subject,
      targetUserId: request.targetSpeakerId,
      roomId: request.roomId,
      reason: attributed,
      scope: 'PLATFORM_API',
      succeeded: result.ok,
      ...(result.ok ? {} : { failureReason: result.reason }),
      riskScoreAtAction: 0,
      nowMs,
    });
    await deps.actions.put(action);
    await deps.publisher.publish('RoomWideActionApplied', {
      roomId: request.roomId,
      operatorId: principal.subject,
      role: requesterRole,
      speakerId: request.targetSpeakerId,
      action: request.action,
      applied: result.ok,
    });
    await audit(deps, principal, request, result.ok ? 'SUCCESS' : 'FAILURE', decision.reason, requesterRole, nowMs);

    return {
      applied: result.ok,
      scope: result.ok ? 'ROOM_WIDE' : 'NONE',
      message: result.ok
        ? `${request.action === 'ROOM_KICK' ? 'Removed from the room' : 'Muted room-wide'} via the official platform API. The platform has stopped relaying this speaker to the room.`
        : `The official API rejected the action: ${result.reason}`,
      role: requesterRole,
      action,
    };
  } catch (err: unknown) {
    return handleThrow(deps, request, principal, requesterRole, nowMs, errorMessage(err));
  }
}

/** The buttons to show a requester, given their resolved role. */
export async function voiceRoomAffordances(
  roomId: string,
  principal: Principal,
  deps: VoiceRoomDeps,
): Promise<{ role: RoomRole; affordances: RoomAffordance[] }> {
  const requesterRole = await deps.resolveRoomRole(roomId, principal.subject);
  return {
    role: requesterRole,
    affordances: roomAffordances({
      roomId,
      requesterRole,
      requesterId: principal.subject,
      capabilities: deps.platform.capabilities(),
    }),
  };
}

async function handleThrow(
  deps: VoiceRoomDeps,
  request: VoiceRoomRequest,
  principal: Principal,
  role: RoomRole,
  nowMs: number,
  message: string,
): Promise<VoiceRoomOutcome> {
  deps.logger.error('Voice-room platform call failed.', { action: request.action, roomId: request.roomId });
  const action = recordAction({
    actionType: request.action === 'ROOM_KICK' ? 'PLATFORM_BLOCK' : 'PLATFORM_MUTE',
    actorKind: 'MODERATOR',
    actorId: principal.subject,
    targetUserId: request.targetSpeakerId,
    roomId: request.roomId,
    reason: `${request.action} attempted`,
    scope: 'PLATFORM_API',
    succeeded: false,
    failureReason: message,
    nowMs,
  });
  await deps.actions.put(action);
  await audit(deps, principal, request, 'FAILURE', message, role, nowMs);
  return {
    applied: false,
    scope: 'NONE',
    message: `The platform call failed: ${message}`,
    role,
    action,
  };
}

async function audit(
  deps: VoiceRoomDeps,
  principal: Principal,
  request: VoiceRoomRequest,
  outcome: 'SUCCESS' | 'FAILURE' | 'DENIED',
  reason: string,
  role: RoomRole,
  nowMs: number,
): Promise<void> {
  try {
    await deps.audit.append({
      auditId: newAuditId(),
      atMs: nowMs,
      actorId: principal.subject,
      actorKind: 'MODERATOR',
      action: `VOICE_${request.action}`,
      target: request.targetSpeakerId,
      reason,
      outcome,
      detail: {
        roomId: request.roomId,
        role,
        requestedAction: request.action,
        moderator: principal.username,
      },
    });
  } catch (err: unknown) {
    deps.logger.error('Failed to append voice-room audit entry.', { error: errorMessage(err) });
  }
}
