/** Response shapes returned by the TalkinShield API. */

export type RiskLevel = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export interface Overview {
  generatedAtMs: number;
  activeIncidents: number;
  highRiskUsers: number;
  spamEvents: number;
  abuseEvents: number;
  blockedEvents: number;
  recentIncidents: Array<{
    incidentId: string;
    userId: string;
    roomId?: string;
    riskScore: number;
    riskLevel: RiskLevel;
    status: string;
    createdAtMs: number;
    topBehaviors: string[];
  }>;
  riskDistribution: Array<{ level: RiskLevel; range: string; count: number }>;
  topSignals: Array<{ code: string; count: number }>;
}

export interface EventRow {
  eventId: string;
  userId: string;
  roomId: string;
  timestamp: string;
  receivedAtMs: number;
  eventType: string;
  message?: string;
  messageUnavailable?: string;
  messageIsTranscript?: boolean;
  clientVersion?: string;
  platform: string;
  metadata: Record<string, string | number | boolean>;
}

export interface SignalRow {
  code: string;
  category: string;
  severity: string;
  confidence: number;
  reason: string;
  detector: string;
  observedAtMs: number;
  evidenceEventIds: string[];
  userId: string;
  details?: Record<string, string | number | boolean>;
}

export interface UserSummary {
  userId: string;
  handle: string;
  riskScore: number;
  riskLevel: RiskLevel;
  lastSeenAtMs: number;
  roomId?: string;
  openIncidents: number;
}

export interface UnavailableField {
  field: string;
  status: 'UNAVAILABLE' | 'OUT_OF_SCOPE' | 'NOT_AUTHORIZED';
  reason: string;
}

export interface UserDetail {
  userId: string;
  handle: string;
  roomId?: string;
  riskScore: number;
  riskLevel: RiskLevel;
  riskRange: string;
  contributions: Array<{
    code: string;
    weight: number;
    applied: number;
    confidence: number;
    reason: string;
  }>;
  messageFrequency: { windowSeconds: number; count: number; perMinute: number };
  abuseDetections: SignalRow[];
  recentEvents: EventRow[];
  moderationHistory: ActionRow[];
  openIncidents: number;
  priorViolations: number;
  evasionCount: number;
  clientInfo: {
    declaredVersion: string | null;
    declaredPlatform: string | null;
    attestationAvailable: boolean;
    note: string;
  };
  unavailableData: UnavailableField[];
}

export interface Incident {
  incidentId: string;
  userId: string;
  roomId?: string;
  createdAtMs: number;
  updatedAtMs: number;
  status: string;
  riskScore: number;
  riskLevel: RiskLevel;
  detectedBehaviors: string[];
  detectionReasons: string[];
  relevantMessages: Array<{
    eventId: string;
    atMs: number;
    text: string;
    isTranscript: boolean;
    redacted: boolean;
  }>;
  authorizedMetadata: Record<string, string | number | boolean>;
  actionsTaken: ActionRow[];
  confidence: number;
  modelVersions: string[];
  evidenceKeys: string[];
  reviewNote?: string;
  reviewedBy?: string;
}

export interface ActionRow {
  actionId: string;
  actionType: string;
  actorKind: 'SYSTEM' | 'MODERATOR';
  actorId: string;
  targetUserId: string;
  roomId?: string;
  atMs: number;
  reason: string;
  scope: 'LOCAL_TO_REQUESTER' | 'PLATFORM_API' | 'INTERNAL';
  succeeded: boolean;
  failureReason?: string;
  incidentId?: string;
  riskScoreAtAction?: number;
}

export interface Affordance {
  action: string;
  enabled: boolean;
  scope: 'LOCAL_TO_REQUESTER' | 'PLATFORM_API' | 'INTERNAL';
  label: string;
  description: string;
}

export interface Capabilities {
  messageContent: boolean;
  moderationEvents: boolean;
  voiceAudio: boolean;
  hiddenPresenceEvents: boolean;
  clientAttestation: boolean;
  remoteMute: boolean;
  remoteBlock: boolean;
}

export interface AffordanceResponse {
  affordances: Affordance[];
  capabilities: Capabilities;
  unavailableData: UnavailableField[];
  integration: string;
}

export interface AuditRow {
  auditId: string;
  atMs: number;
  actorId: string;
  actorKind: 'SYSTEM' | 'MODERATOR';
  action: string;
  target: string;
  reason: string;
  outcome: 'SUCCESS' | 'FAILURE' | 'DENIED';
  detail?: Record<string, string | number | boolean>;
  sourceIp?: string;
}

export interface EvidenceBundleView {
  key: string;
  sequence: number;
  contentHash: string;
  previousHash: string;
  chainHash: string;
  body: {
    schemaVersion: string;
    incidentId: string;
    userId: string;
    roomId?: string;
    createdAt: string;
    detectedBehaviors: string[];
    detectionReasons: string[];
    riskScore: number;
    riskLevel: string;
    confidence: number;
    modelVersions: string[];
    relevantMessages: Array<{ eventId: string; text: string; redacted: boolean; isTranscript: boolean }>;
    authorizedMetadata: Record<string, string | number | boolean>;
    actionsTaken: ActionRow[];
    signals: Array<{ code: string; reason: string; detector: string; confidence: number }>;
    authorization: {
      capabilities: Capabilities;
      collected: string[];
      notCollected: Array<{ field: string; reason: string }>;
      note: string;
    };
  };
}

export interface VerificationResult {
  valid: boolean;
  problems: string[];
}

export interface RulesResponse {
  effective: DetectionConfigView;
  overrides: Record<string, unknown>;
  version: string;
}

export interface DetectionConfigView {
  spam: Record<string, number>;
  abuse: Record<string, unknown>;
  client: Record<string, unknown>;
  evasion: Record<string, number>;
  ghost: Record<string, number>;
  risk: {
    weights: Record<string, number>;
    thresholds: { LOW: number; MEDIUM: number; HIGH: number; CRITICAL: number };
    repeatViolationWeight: number;
    maxRepeatBonus: number;
    confidenceScalingFloor: number;
    maxSingleContribution: number;
    criticalAutoActionMinConfidence: number;
    historyHalfLifeMs: number;
    maxHistoryComponent: number;
  };
  incident: Record<string, unknown>;
  retention: Record<string, number>;
  alert: Record<string, unknown>;
  configVersion: string;
}

export interface SettingsResponse {
  stage: string;
  region: string;
  integration: { name: string; adapter: string; capabilities: Capabilities };
  ai: { bedrockEnabled: boolean; modelId: string | null; note: string };
  voice: { transcribeEnabled: boolean; note: string };
  retentionDays: Record<string, number>;
  riskThresholds: { LOW: number; MEDIUM: number; HIGH: number; CRITICAL: number };
  alerting: { minLevel: string };
  configVersion: string;
  unavailableData: UnavailableField[];
}

export interface Me {
  subject: string;
  username: string;
  roles: string[];
  groups: string[];
  mfaPresent: boolean;
  permissions: string[];
  mfaRequiredForDestructive: boolean;
}

export interface ModerationResult {
  applied: boolean;
  scope: string;
  message: string;
  platformActionUnavailable: boolean;
  action: ActionRow;
}
