/** Risk scoring, response policy and incident/evidence record shapes. */

import type { DetectionSignal, RecommendedAction, SignalCode } from './detection.ts';

export const RISK_LEVELS = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'] as const;
export type RiskLevel = (typeof RISK_LEVELS)[number];

export interface RiskContribution {
  code: SignalCode;
  /** Configured weight before confidence scaling. */
  weight: number;
  /** Weight actually applied after confidence scaling and caps. */
  applied: number;
  confidence: number;
  reason: string;
}

export interface RiskAssessment {
  userId: string;
  roomId?: string;
  /** 0..100, clamped. */
  score: number;
  level: RiskLevel;
  contributions: RiskContribution[];
  /** Carried-over risk from prior analysis passes, after decay. */
  historyComponent: number;
  /** Highest single-signal confidence, used to gate automated actions. */
  peakConfidence: number;
  /** True when every contribution came from deterministic (non-AI) logic. */
  deterministicOnly: boolean;
  assessedAtMs: number;
  engineVersion: string;
}

export const RESPONSE_ACTIONS = [
  'LOG',
  'INCREASE_MONITORING',
  'RECOMMEND_MUTE',
  'RECOMMEND_BLOCK',
  'RECOMMEND_REPORT',
  'PLATFORM_TEMPORARY_BLOCK',
  'CREATE_INCIDENT',
  'PRESERVE_EVIDENCE',
  'NOTIFY_MODERATOR',
] as const;
export type ResponseAction = (typeof RESPONSE_ACTIONS)[number];

export interface ResponsePlan {
  level: RiskLevel;
  /** Automated steps the system will perform itself. */
  automated: ResponseAction[];
  /** Actions surfaced to the moderator as buttons; never auto-executed. */
  recommended: RecommendedAction[];
  /**
   * True when the plan would have included a platform-side block but the
   * integration does not grant that capability.
   */
  platformActionUnavailable: boolean;
  rationale: string;
}

// --- Incidents -------------------------------------------------------------

export const INCIDENT_STATUSES = [
  'OPEN',
  'ACKNOWLEDGED',
  'ACTIONED',
  'DISMISSED_FALSE_POSITIVE',
  'CLOSED',
] as const;
export type IncidentStatus = (typeof INCIDENT_STATUSES)[number];

export interface Incident {
  incidentId: string;
  userId: string;
  roomId?: string;
  createdAtMs: number;
  updatedAtMs: number;
  status: IncidentStatus;
  riskScore: number;
  riskLevel: RiskLevel;
  /** Signal codes that triggered the incident. */
  detectedBehaviors: SignalCode[];
  /** Full human-readable reasons, one per contributing signal. */
  detectionReasons: string[];
  /** Redacted excerpts of the relevant messages, if content is authorized. */
  relevantMessages: MessageExcerpt[];
  /** Non-sensitive, authorized metadata only. */
  authorizedMetadata: Record<string, string | number | boolean>;
  actionsTaken: ActionRecord[];
  /** Aggregate confidence 0..1. */
  confidence: number;
  /** `engine@version` plus any AI model versions consulted. */
  modelVersions: string[];
  evidenceKeys: string[];
  /** Set when a moderator marks the incident a false positive. */
  reviewNote?: string;
  reviewedBy?: string;
}

export interface MessageExcerpt {
  eventId: string;
  atMs: number
  /** Truncated and redacted text. Empty when content is not authorized. */
  text: string;
  isTranscript: boolean;
  redacted: boolean;
}

export const ACTION_TYPES = [
  'LOCAL_MUTE',
  'LOCAL_BLOCK',
  'LOCAL_IGNORE',
  'REPORT_SUBMITTED',
  'EVIDENCE_SAVED',
  'PLATFORM_MUTE',
  'PLATFORM_BLOCK',
  'PLATFORM_TEMP_BLOCK',
  'WARNING_ISSUED',
  'MONITORING_INCREASED',
  'INCIDENT_CREATED',
  'INCIDENT_STATUS_CHANGED',
  'MODERATOR_NOTIFIED',
  'RETENTION_DELETION',
] as const;
export type ActionType = (typeof ACTION_TYPES)[number];

export const ACTOR_KINDS = ['SYSTEM', 'MODERATOR'] as const;
export type ActorKind = (typeof ACTOR_KINDS)[number];

export interface ActionRecord {
  actionId: string;
  actionType: ActionType;
  actorKind: ActorKind;
  /** Cognito subject of the moderator, or `system` for automated actions. */
  actorId: string;
  targetUserId: string;
  roomId?: string;
  atMs: number;
  /** Why this action was taken — mandatory, never empty. */
  reason: string;
  /** Scope makes the authorization boundary explicit on every action. */
  scope: 'LOCAL_TO_REQUESTER' | 'PLATFORM_API' | 'INTERNAL';
  succeeded: boolean;
  failureReason?: string;
  incidentId?: string;
  riskScoreAtAction?: number;
}

export interface SignalBundle {
  userId: string;
  roomId?: string;
  signals: DetectionSignal[];
}
