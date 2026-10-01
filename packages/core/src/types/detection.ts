/**
 * Detection signals: the single currency every detector emits and the risk
 * engine consumes.
 *
 * Every signal carries a human-readable `reason` and a `detector` version
 * string. These are persisted with each automated decision so that any
 * moderation outcome can be explained and audited after the fact.
 */

export const SIGNAL_CATEGORIES = [
  'SPAM',
  'FREQUENCY',
  'ABUSE',
  'THREAT',
  'CLIENT',
  'EVASION',
  'GHOST',
  'COORDINATION',
] as const;
export type SignalCategory = (typeof SIGNAL_CATEGORIES)[number];

export const SIGNAL_CODES = [
  // Spam & frequency
  'SPAM_IDENTICAL_REPEAT',
  'SPAM_NEAR_DUPLICATE',
  'SPAM_HIGH_FREQUENCY',
  'SPAM_BURST',
  'SPAM_MENTION_FLOOD',
  'SPAM_SUSPICIOUS_CHARACTERS',
  'SPAM_LINK_FLOOD',
  'BOT_UNIFORM_TIMING',
  'BOT_SUSTAINED_RATE',
  // Coordination
  'COORDINATED_IDENTICAL_CONTENT',
  'COORDINATED_SYNCHRONIZED_JOINS',
  // Abuse
  'ABUSE_LANGUAGE',
  'ABUSE_SEVERE',
  'ABUSE_REPEATED',
  'ABUSE_TARGETED_HARASSMENT',
  'THREAT_LANGUAGE',
  // Client integrity
  'CLIENT_UNKNOWN_VERSION',
  'CLIENT_VERSION_FLAPPING',
  'CLIENT_IMPOSSIBLE_SEQUENCE',
  'CLIENT_MALFORMED_REQUESTS',
  'CLIENT_ABNORMAL_REQUEST_RATE',
  'CLIENT_PLATFORM_MISMATCH',
  'CLIENT_ATTESTATION_FAILED',
  // Evasion
  'EVASION_POST_MODERATION_ACTIVITY',
  'EVASION_REJOIN_CYCLING',
  'EVASION_FILTER_OBFUSCATION',
  // Ghost / hidden presence
  'GHOST_HIDDEN_PRESENCE_CORRELATED',
] as const;
export type SignalCode = (typeof SIGNAL_CODES)[number];

export const SEVERITIES = ['INFO', 'LOW', 'MEDIUM', 'HIGH', 'SEVERE'] as const;
export type Severity = (typeof SEVERITIES)[number];

export interface DetectionSignal {
  code: SignalCode;
  category: SignalCategory;
  severity: Severity;
  /** Detector's own confidence in this finding, 0..1. */
  confidence: number;
  /** Operator-facing explanation. Persisted verbatim for audit. */
  reason: string;
  /** Event ids supporting the finding; used to assemble evidence. */
  evidenceEventIds: string[];
  /** `name@semver` of the detector that produced this signal. */
  detector: string;
  /** Epoch ms when the signal was produced. */
  observedAtMs: number;
  /** Structured, non-sensitive detail for the dashboard (counts, windows). */
  details?: Record<string, string | number | boolean>;
}

export const CATEGORY_OF_CODE: Record<SignalCode, SignalCategory> = {
  SPAM_IDENTICAL_REPEAT: 'SPAM',
  SPAM_NEAR_DUPLICATE: 'SPAM',
  SPAM_HIGH_FREQUENCY: 'FREQUENCY',
  SPAM_BURST: 'FREQUENCY',
  SPAM_MENTION_FLOOD: 'SPAM',
  SPAM_SUSPICIOUS_CHARACTERS: 'SPAM',
  SPAM_LINK_FLOOD: 'SPAM',
  BOT_UNIFORM_TIMING: 'FREQUENCY',
  BOT_SUSTAINED_RATE: 'FREQUENCY',
  COORDINATED_IDENTICAL_CONTENT: 'COORDINATION',
  COORDINATED_SYNCHRONIZED_JOINS: 'COORDINATION',
  ABUSE_LANGUAGE: 'ABUSE',
  ABUSE_SEVERE: 'ABUSE',
  ABUSE_REPEATED: 'ABUSE',
  ABUSE_TARGETED_HARASSMENT: 'ABUSE',
  THREAT_LANGUAGE: 'THREAT',
  CLIENT_UNKNOWN_VERSION: 'CLIENT',
  CLIENT_VERSION_FLAPPING: 'CLIENT',
  CLIENT_IMPOSSIBLE_SEQUENCE: 'CLIENT',
  CLIENT_MALFORMED_REQUESTS: 'CLIENT',
  CLIENT_ABNORMAL_REQUEST_RATE: 'CLIENT',
  CLIENT_PLATFORM_MISMATCH: 'CLIENT',
  CLIENT_ATTESTATION_FAILED: 'CLIENT',
  EVASION_POST_MODERATION_ACTIVITY: 'EVASION',
  EVASION_REJOIN_CYCLING: 'EVASION',
  EVASION_FILTER_OBFUSCATION: 'EVASION',
  GHOST_HIDDEN_PRESENCE_CORRELATED: 'GHOST',
};

// --- Abuse classification (contract specified by the product brief) --------

export const CLASSIFICATIONS = [
  'SAFE',
  'ABUSIVE',
  'SEVERE_ABUSE',
  'THREAT',
  'UNCERTAIN',
] as const;
export type Classification = (typeof CLASSIFICATIONS)[number];

export const RECOMMENDED_ACTIONS = ['NONE', 'WARN', 'MUTE', 'BLOCK', 'REPORT'] as const;
export type RecommendedAction = (typeof RECOMMENDED_ACTIONS)[number];

export interface AbuseClassification {
  classification: Classification;
  /** 0..1 */
  confidence: number;
  reason: string;
  recommendedAction: RecommendedAction;
  /** Which layers contributed, for transparency and tuning. */
  sources: ClassificationSource[];
  /** Model or ruleset identifier recorded on the decision. */
  modelVersion: string;
  /** True when a human should confirm before any durable penalty. */
  requiresHumanReview: boolean;
}

export interface ClassificationSource {
  layer: 'rules' | 'lexicon' | 'rate' | 'bedrock';
  classification: Classification;
  confidence: number;
  reason: string;
  version: string;
}

// --- Client integrity (contract specified by the product brief) ------------

export interface ClientRiskAssessment {
  /** 0..100 */
  clientRisk: number;
  indicators: string[];
  /** 0..1 — how much telemetry backed this assessment. */
  confidence: number;
  signals: DetectionSignal[];
  /** Set when there was not enough telemetry to judge. */
  insufficientTelemetry?: boolean;
  note?: string;
}
