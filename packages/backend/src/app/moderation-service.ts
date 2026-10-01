/**
 * Moderation actions taken by a human moderator.
 *
 * The authorization boundary is enforced here, in one place:
 *
 *   - MUTE / BLOCK go through the official platform API when, and only when,
 *     `capabilities.remoteMute` / `capabilities.remoteBlock` are granted.
 *   - Otherwise the action is recorded as `LOCAL_TO_REQUESTER`: a local mute,
 *     block or ignore that affects what the protected user receives and nothing
 *     else. The response says so explicitly, so a moderator is never misled
 *     into believing a platform-wide action occurred.
 *   - There is no fallback that tries to reach another participant's client,
 *     device or microphone. That capability does not exist in this codebase.
 *
 * Every action, successful or not, produces an `ActionRecord` with a mandatory
 * reason and an `AuditEntry`.
 */

import {
  actionAffordances,
  newAuditId,
  recordAction,
  type ActionRecord,
  type ActionType,
  type IntegrationCapabilities,
} from '@talkinshield/core';

import type {
  ActionStore,
  AuditStore,
  Clock,
  EventPublisher,
  IncidentStore,
  Logger,
  TalkinPlatformAdapter,
  UserStateStore,
} from '../ports.ts';
import type { Principal } from '../http/auth.ts';
import { errorMessage } from './analysis-service.ts';

export const MODERATION_ACTIONS = ['MUTE', 'BLOCK', 'IGNORE', 'REPORT', 'SAVE_EVIDENCE'] as const;
export type ModerationActionKind = (typeof MODERATION_ACTIONS)[number];

export interface ModerationDeps {
  platform: TalkinPlatformAdapter;
  actions: ActionStore;
  audit: AuditStore;
  incidents: IncidentStore;
  userState: UserStateStore;
  publisher: EventPublisher;
  logger: Logger;
  clock: Clock;
}

export interface ModerationRequest {
  kind: ModerationActionKind;
  targetUserId: string;
  roomId?: string;
  reason: string;
  incidentId?: string;
  /** Seconds, for mute/block. Capped by the service. */
  durationSeconds?: number;
}

export interface ModerationOutcome {
  applied: boolean;
  /** Where the action actually took effect. */
  scope: 'LOCAL_TO_REQUESTER' | 'PLATFORM_API' | 'INTERNAL';
  action: ActionRecord;
  /** Plain-language description of what happened, shown to the moderator. */
  message: string;
  /** True when a platform-wide action was requested but is not available. */
  platformActionUnavailable: boolean;
}

const MAX_DURATION_SECONDS = 24 * 60 * 60;
const MIN_REASON_LENGTH = 8;

export async function applyModeration(
  request: ModerationRequest,
  principal: Principal,
  deps: ModerationDeps,
): Promise<ModerationOutcome | { rejected: string }> {
  const reason = request.reason.trim();
  if (reason.length < MIN_REASON_LENGTH) {
    return {
      rejected: `A reason of at least ${MIN_REASON_LENGTH} characters is required: every moderation action must be explainable in the audit trail.`,
    };
  }

  const nowMs = deps.clock.now();
  const capabilities = deps.platform.capabilities();
  const duration = Math.min(request.durationSeconds ?? 900, MAX_DURATION_SECONDS);

  const attributedReason = `${reason} (actioned by ${principal.username})`;

  let outcome: ModerationOutcome;

  switch (request.kind) {
    case 'MUTE':
      outcome = await applyMuteOrBlock('MUTE', request, attributedReason, duration, capabilities, deps, nowMs, principal);
      break;
    case 'BLOCK':
      outcome = await applyMuteOrBlock('BLOCK', request, attributedReason, duration, capabilities, deps, nowMs, principal);
      break;
    case 'IGNORE':
      outcome = localOnly(
        'LOCAL_IGNORE',
        request,
        attributedReason,
        deps,
        nowMs,
        principal,
        'Account is now ignored for the protected user. This is a local preference and affects no one else.',
      );
      break;
    case 'REPORT':
      outcome = await submitReport(request, attributedReason, deps, nowMs, principal);
      break;
    case 'SAVE_EVIDENCE':
      outcome = localOnly(
        'EVIDENCE_SAVED',
        request,
        attributedReason,
        deps,
        nowMs,
        principal,
        'Evidence bundle requested. See the Evidence page for the stored, hash-chained record.',
      );
      break;
    default:
      return { rejected: `Unsupported moderation action.` };
  }

  await deps.actions.put(outcome.action);
  if (request.incidentId !== undefined) {
    await deps.incidents.appendAction(request.incidentId, outcome.action);
  }

  await deps.audit.append({
    auditId: newAuditId(),
    atMs: nowMs,
    actorId: principal.subject,
    actorKind: 'MODERATOR',
    action: `MODERATION_${request.kind}`,
    target: request.targetUserId,
    reason,
    outcome: outcome.applied ? 'SUCCESS' : 'FAILURE',
    detail: {
      scope: outcome.scope,
      platformActionUnavailable: outcome.platformActionUnavailable,
      ...(request.roomId !== undefined ? { roomId: request.roomId } : {}),
      ...(request.incidentId !== undefined ? { incidentId: request.incidentId } : {}),
      moderator: principal.username,
    },
  });

  await deps.publisher.publish('ModerationActionTaken', {
    actionId: outcome.action.actionId,
    kind: request.kind,
    scope: outcome.scope,
    targetUserId: request.targetUserId,
    applied: outcome.applied,
    actorId: principal.subject,
  });

  return outcome;
}

async function applyMuteOrBlock(
  kind: 'MUTE' | 'BLOCK',
  request: ModerationRequest,
  reason: string,
  durationSeconds: number,
  capabilities: IntegrationCapabilities,
  deps: ModerationDeps,
  nowMs: number,
  principal: Principal,
): Promise<ModerationOutcome> {
  const capabilityGranted = kind === 'MUTE' ? capabilities.remoteMute : capabilities.remoteBlock;

  if (!capabilityGranted) {
    // Degrade to a local-only protection and say so plainly.
    const localType: ActionType = kind === 'MUTE' ? 'LOCAL_MUTE' : 'LOCAL_BLOCK';
    const message =
      kind === 'MUTE'
        ? 'Muted locally for the protected user only. No official Talkin mute API is configured, so other participants still hear this account. TalkinShield will not attempt to mute another user\'s microphone by any other means.'
        : 'Blocked locally for the protected user only. No official Talkin block API is configured, so this account is not restricted platform-wide.';

    return {
      applied: true,
      scope: 'LOCAL_TO_REQUESTER',
      platformActionUnavailable: true,
      message,
      action: recordAction({
        actionType: localType,
        actorKind: 'MODERATOR',
        actorId: principal.subject,
        targetUserId: request.targetUserId,
        ...(request.roomId !== undefined ? { roomId: request.roomId } : {}),
        reason: `${reason} — applied locally because no official platform ${kind.toLowerCase()} API is available.`,
        scope: 'LOCAL_TO_REQUESTER',
        succeeded: true,
        ...(request.incidentId !== undefined ? { incidentId: request.incidentId } : {}),
        nowMs,
      }),
    };
  }

  // Platform API path.
  try {
    const result =
      kind === 'MUTE'
        ? await deps.platform.mute({
            userId: request.targetUserId,
            roomId: request.roomId ?? '',
            durationSeconds,
            reason,
          })
        : await deps.platform.block({
            userId: request.targetUserId,
            ...(request.roomId !== undefined ? { roomId: request.roomId } : {}),
            durationSeconds,
            reason,
          });

    if (result.ok) {
      return {
        applied: true,
        scope: 'PLATFORM_API',
        platformActionUnavailable: false,
        message: `${kind === 'MUTE' ? 'Muted' : 'Blocked'} via the official Talkin moderation API for ${durationSeconds}s. This restriction is reversible.`,
        action: recordAction({
          actionType: kind === 'MUTE' ? 'PLATFORM_MUTE' : 'PLATFORM_BLOCK',
          actorKind: 'MODERATOR',
          actorId: principal.subject,
          targetUserId: request.targetUserId,
          ...(request.roomId !== undefined ? { roomId: request.roomId } : {}),
          reason,
          scope: 'PLATFORM_API',
          succeeded: true,
          ...(request.incidentId !== undefined ? { incidentId: request.incidentId } : {}),
          nowMs,
        }),
      };
    }

    return {
      applied: false,
      scope: 'PLATFORM_API',
      platformActionUnavailable: result.unsupported,
      message: `The official API rejected the ${kind.toLowerCase()}: ${result.reason}`,
      action: recordAction({
        actionType: kind === 'MUTE' ? 'PLATFORM_MUTE' : 'PLATFORM_BLOCK',
        actorKind: 'MODERATOR',
        actorId: principal.subject,
        targetUserId: request.targetUserId,
        ...(request.roomId !== undefined ? { roomId: request.roomId } : {}),
        reason,
        scope: 'PLATFORM_API',
        succeeded: false,
        failureReason: result.reason,
        ...(request.incidentId !== undefined ? { incidentId: request.incidentId } : {}),
        nowMs,
      }),
    };
  } catch (err: unknown) {
    deps.logger.error('Platform moderation call failed.', { error: errorMessage(err), kind });
    return {
      applied: false,
      scope: 'PLATFORM_API',
      platformActionUnavailable: false,
      message: `The official API call failed: ${errorMessage(err)}`,
      action: recordAction({
        actionType: kind === 'MUTE' ? 'PLATFORM_MUTE' : 'PLATFORM_BLOCK',
        actorKind: 'MODERATOR',
        actorId: principal.subject,
        targetUserId: request.targetUserId,
        ...(request.roomId !== undefined ? { roomId: request.roomId } : {}),
        reason,
        scope: 'PLATFORM_API',
        succeeded: false,
        failureReason: errorMessage(err),
        nowMs,
      }),
    };
  }
}

async function submitReport(
  request: ModerationRequest,
  reason: string,
  deps: ModerationDeps,
  nowMs: number,
  principal: Principal,
): Promise<ModerationOutcome> {
  const evidenceKeys = request.incidentId
    ? ((await deps.incidents.get(request.incidentId))?.evidenceKeys ?? [])
    : [];

  try {
    const result = await deps.platform.report({
      userId: request.targetUserId,
      ...(request.roomId !== undefined ? { roomId: request.roomId } : {}),
      reason,
      evidenceKeys,
    });

    return {
      applied: result.ok,
      scope: 'PLATFORM_API',
      platformActionUnavailable: !result.ok && result.unsupported,
      message: result.ok
        ? `Report submitted through the official reporting channel with ${evidenceKeys.length} evidence bundle(s) attached.`
        : `Report could not be submitted: ${result.reason}`,
      action: recordAction({
        actionType: 'REPORT_SUBMITTED',
        actorKind: 'MODERATOR',
        actorId: principal.subject,
        targetUserId: request.targetUserId,
        ...(request.roomId !== undefined ? { roomId: request.roomId } : {}),
        reason,
        scope: 'PLATFORM_API',
        succeeded: result.ok,
        ...(result.ok ? {} : { failureReason: result.reason }),
        ...(request.incidentId !== undefined ? { incidentId: request.incidentId } : {}),
        nowMs,
      }),
    };
  } catch (err: unknown) {
    return {
      applied: false,
      scope: 'PLATFORM_API',
      platformActionUnavailable: false,
      message: `Report submission failed: ${errorMessage(err)}`,
      action: recordAction({
        actionType: 'REPORT_SUBMITTED',
        actorKind: 'MODERATOR',
        actorId: principal.subject,
        targetUserId: request.targetUserId,
        reason,
        scope: 'PLATFORM_API',
        succeeded: false,
        failureReason: errorMessage(err),
        nowMs,
      }),
    };
  }
}

function localOnly(
  actionType: ActionType,
  request: ModerationRequest,
  reason: string,
  _deps: ModerationDeps,
  nowMs: number,
  principal: Principal,
  message: string,
): ModerationOutcome {
  return {
    applied: true,
    scope: actionType === 'EVIDENCE_SAVED' ? 'INTERNAL' : 'LOCAL_TO_REQUESTER',
    platformActionUnavailable: false,
    message,
    action: recordAction({
      actionType,
      actorKind: 'MODERATOR',
      actorId: principal.subject,
      targetUserId: request.targetUserId,
      ...(request.roomId !== undefined ? { roomId: request.roomId } : {}),
      reason,
      scope: actionType === 'EVIDENCE_SAVED' ? 'INTERNAL' : 'LOCAL_TO_REQUESTER',
      succeeded: true,
      ...(request.incidentId !== undefined ? { incidentId: request.incidentId } : {}),
      nowMs,
    }),
  };
}

/** What the dashboard should render for the action buttons. */
export function availableActions(deps: Pick<ModerationDeps, 'platform'>) {
  return actionAffordances(deps.platform.capabilities());
}
