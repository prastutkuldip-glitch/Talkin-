/**
 * Every threshold and weight in the system lives here. Nothing is hard-coded
 * inside a detector.
 *
 * The defaults are deliberately conservative: they are tuned to avoid
 * penalising ordinary enthusiastic conversation. Operators override them from
 * the Detection Rules / Settings pages, and overrides are persisted in
 * DynamoDB and merged over these defaults by `resolveConfig`.
 */

import type { RiskLevel, SignalCode } from '../types/index.ts';

export interface SpamConfig {
  /** Sliding window for frequency analysis, ms. */
  windowMs: number;
  /** Messages within `windowMs` above this count => high-frequency signal. */
  highFrequencyCount: number;
  /** Short burst window, ms (brief flood detection). */
  burstWindowMs: number;
  /** Messages within `burstWindowMs` above this count => burst signal. */
  burstCount: number;
  /** Identical normalized messages above this count => repeat signal. */
  identicalRepeatCount: number;
  /** Identical count at/above which the repeat signal is treated as SEVERE. */
  identicalSevereCount: number;
  /**
   * Fingerprints at or below this length are treated as "short" and require
   * proportionally more repeats before being called spam.
   *
   * Short phrases legitimately recur in conversation — "lol", "gg", "same",
   * "wp" — so applying the normal repeat threshold to them produces constant
   * false positives. A long message repeated four times is suspicious; "lol"
   * repeated four times is a conversation.
   */
  identicalShortMessageLength: number;
  /** Multiplier applied to the repeat thresholds for short messages. */
  identicalShortRepeatMultiplier: number;
  /**
   * Minimum content length before identical text across *different accounts* is
   * treated as coordination.
   *
   * Several people independently typing "gg all, well played" in the same room
   * is normal. Several people posting the same 30-character sentence is not.
   */
  coordinationMinContentLength: number;
  /** Near-duplicate similarity threshold, 0..1 (trigram Jaccard). */
  nearDuplicateSimilarity: number;
  /** Near-duplicate messages above this count => near-duplicate signal. */
  nearDuplicateCount: number;
  /** Minimum fingerprint length before similarity matching is attempted. */
  nearDuplicateMinLength: number;
  /** @mentions in a single message above this => mention flood. */
  mentionsPerMessage: number;
  /** Total @mentions in window above this => mention flood. */
  mentionsPerWindow: number;
  /** Distinct links in window above this => link flood. */
  linksPerWindow: number;
  /** Minimum samples before timing analysis is attempted. */
  timingMinSamples: number;
  /**
   * Coefficient of variation below this => machine-like regularity.
   * Humans typically produce CV well above 0.35 between messages.
   */
  timingMaxCoefficientOfVariation: number;
  /** Ignore timing analysis when mean gap exceeds this (slow chat is normal). */
  timingMaxMeanGapMs: number;
  /** Sustained-rate window, ms. */
  sustainedWindowMs: number;
  /** Messages per sustained window above this => sustained automated rate. */
  sustainedCount: number;
  /** Max events retained per user detection window. */
  maxWindowEvents: number;
}

export interface AbuseConfig {
  /** Repeated abusive messages in window above this => repeated-abuse signal. */
  repeatWindowMs: number;
  repeatCount: number;
  /** Minimum rule confidence required to emit an ABUSE signal at all. */
  minConfidence: number;
  /**
   * When deterministic rules and the AI classifier disagree by at least this
   * much, the result is downgraded to UNCERTAIN and flagged for human review.
   */
  disagreementThreshold: number;
  /** Confidence floor below which no automated penalty may be recommended. */
  autoActionMinConfidence: number;
  /** Operator-supplied additional terms, by tier. */
  extraTerms: { mild: string[]; severe: string[]; threat: string[] };
  /** Terms the operator has explicitly allow-listed (community in-jokes etc). */
  allowTerms: string[];
  /** Max characters of message text retained in evidence excerpts. */
  excerptMaxChars: number;
}

export interface ClientConfig {
  /** Client versions recognised as official builds. */
  knownVersions: string[];
  /** Semver-ish pattern an official version must match. */
  versionPattern: string;
  /** Distinct client versions per user in window above this => flapping. */
  versionFlapWindowMs: number;
  versionFlapCount: number;
  /** Requests per minute above this => abnormal request rate. */
  abnormalRequestsPerMinute: number;
  /** Malformed requests in window above this => malformed-request signal. */
  malformedWindowMs: number;
  malformedCount: number;
  /** Minimum telemetry events before a client judgement is made at all. */
  minTelemetryEvents: number;
  /** Weight of each indicator toward the 0..100 clientRisk score. */
  indicatorWeights: Record<string, number>;
}

export interface EvasionConfig {
  /** Activity within this window after a platform mute/ban => evasion. */
  postModerationWindowMs: number;
  /** Rejoin cycles in window above this => rejoin cycling. */
  rejoinWindowMs: number;
  rejoinCount: number;
}

export interface GhostConfig {
  /** Max clock skew tolerated when correlating hidden presence, ms. */
  correlationToleranceMs: number;
  /** Minimum correlated events before reporting hidden activity. */
  minCorrelatedEvents: number;
}

export interface RiskConfig {
  /** Weight added per signal code. Fully operator-configurable. */
  weights: Record<SignalCode, number>;
  /** Level boundaries: lower bound of each level. */
  thresholds: { LOW: number; MEDIUM: number; HIGH: number; CRITICAL: number };
  /** Added per prior confirmed violation, up to `maxRepeatBonus`. */
  repeatViolationWeight: number;
  maxRepeatBonus: number;
  /** Carried risk halves every `historyHalfLifeMs`. */
  historyHalfLifeMs: number;
  /** Max contribution from carried history. */
  maxHistoryComponent: number;
  /**
   * Signals below this confidence contribute proportionally less rather than
   * their full weight, so a single weak guess cannot escalate a user.
   */
  confidenceScalingFloor: number;
  /** A single signal may never contribute more than this many points. */
  maxSingleContribution: number;
  /**
   * CRITICAL automated platform actions require at least this confidence AND
   * at least one deterministic signal. Prevents AI-only escalation.
   */
  criticalAutoActionMinConfidence: number;
}

export interface RetentionConfig {
  rawEventsDays: number;
  signalsDays: number;
  incidentsDays: number;
  evidenceDays: number;
  auditDays: number;
}

export interface AlertConfig {
  minLevel: RiskLevel;
  alertOnSevereAbuse: boolean;
  alertOnThreat: boolean;
  alertOnMassSpam: boolean;
  alertOnRepeatedEvasion: boolean;
  alertOnSuspiciousClient: boolean;
  /** Suppress duplicate alerts for the same user within this window, ms. */
  dedupeWindowMs: number;
}

export interface IncidentConfig {
  /**
   * Reuse an existing OPEN incident for the same user/room within this window
   * instead of opening a new one.
   *
   * Without this, a sustained flood opens one incident per event: a 20-message
   * spam burst becomes 17 near-identical incidents, burying the moderator and
   * writing redundant evidence. Ongoing behaviour belongs on one incident.
   */
  dedupeWindowMs: number;
  /** Ceiling on evidence bundles attached to a single incident. */
  maxEvidenceBundles: number;
  /**
   * Only write an additional evidence bundle when the incident gains a
   * previously-unseen signal code. Repeat occurrences of the same behaviour are
   * already covered by the existing bundle.
   */
  evidenceOnNewBehaviorOnly: boolean;
}

export interface DetectionConfig {
  spam: SpamConfig;
  abuse: AbuseConfig;
  client: ClientConfig;
  evasion: EvasionConfig;
  ghost: GhostConfig;
  risk: RiskConfig;
  incident: IncidentConfig;
  retention: RetentionConfig;
  alert: AlertConfig;
  /** Bumped whenever an operator edits config; recorded on every decision. */
  configVersion: string;
}

const SECOND = 1000;
const MINUTE = 60 * SECOND;
const HOUR = 60 * MINUTE;
const DAY = 24 * HOUR;

export const DEFAULT_CONFIG: DetectionConfig = {
  spam: {
    windowMs: 30 * SECOND,
    highFrequencyCount: 15,
    burstWindowMs: 5 * SECOND,
    // The brief's example: 10 messages in 5 seconds is suspicious.
    burstCount: 10,
    identicalRepeatCount: 4,
    // The brief's example: 50 identical messages is high risk.
    identicalSevereCount: 15,
    identicalShortMessageLength: 16,
    identicalShortRepeatMultiplier: 3,
    coordinationMinContentLength: 24,
    /**
     * Trigram-Jaccard threshold for "same template, small mutation".
     *
     * Tuned empirically against fingerprint pairs: legitimate paraphrases
     * ("good morning everyone" / "...everybody") peak around 0.68, while long
     * templated spam reaches ~0.81. 0.78 sits above the legitimate band with
     * margin. Short templates that score below this are deliberately left to
     * the identical-repeat and frequency detectors rather than risking false
     * positives on ordinary conversation, because the two distributions
     * overlap below ~0.7 and cannot be separated by similarity alone.
     */
    nearDuplicateSimilarity: 0.78,
    nearDuplicateCount: 5,
    /** Fingerprints shorter than this are too noisy for similarity matching. */
    nearDuplicateMinLength: 16,
    mentionsPerMessage: 6,
    mentionsPerWindow: 15,
    linksPerWindow: 6,
    timingMinSamples: 6,
    timingMaxCoefficientOfVariation: 0.18,
    timingMaxMeanGapMs: 20 * SECOND,
    sustainedWindowMs: 5 * MINUTE,
    sustainedCount: 120,
    maxWindowEvents: 200,
  },
  abuse: {
    repeatWindowMs: 10 * MINUTE,
    repeatCount: 3,
    minConfidence: 0.5,
    disagreementThreshold: 0.45,
    autoActionMinConfidence: 0.7,
    extraTerms: { mild: [], severe: [], threat: [] },
    allowTerms: [],
    excerptMaxChars: 280,
  },
  client: {
    knownVersions: [],
    versionPattern: '^\\d+\\.\\d+\\.\\d+(?:[-+][0-9A-Za-z.-]+)?$',
    versionFlapWindowMs: 10 * MINUTE,
    versionFlapCount: 3,
    abnormalRequestsPerMinute: 240,
    malformedWindowMs: 5 * MINUTE,
    malformedCount: 5,
    minTelemetryEvents: 5,
    indicatorWeights: {
      CLIENT_UNKNOWN_VERSION: 18,
      CLIENT_VERSION_FLAPPING: 22,
      CLIENT_IMPOSSIBLE_SEQUENCE: 28,
      CLIENT_MALFORMED_REQUESTS: 20,
      CLIENT_ABNORMAL_REQUEST_RATE: 22,
      CLIENT_PLATFORM_MISMATCH: 20,
      CLIENT_ATTESTATION_FAILED: 35,
    },
  },
  evasion: {
    postModerationWindowMs: 10 * MINUTE,
    rejoinWindowMs: 5 * MINUTE,
    rejoinCount: 5,
  },
  ghost: {
    correlationToleranceMs: 3 * SECOND,
    minCorrelatedEvents: 2,
  },
  risk: {
    // Defaults mirror the weighting table in the product brief.
    weights: {
      SPAM_IDENTICAL_REPEAT: 20,
      SPAM_NEAR_DUPLICATE: 14,
      SPAM_HIGH_FREQUENCY: 20,
      SPAM_BURST: 20,
      SPAM_MENTION_FLOOD: 15,
      SPAM_SUSPICIOUS_CHARACTERS: 10,
      SPAM_LINK_FLOOD: 15,
      BOT_UNIFORM_TIMING: 20,
      BOT_SUSTAINED_RATE: 20,
      COORDINATED_IDENTICAL_CONTENT: 25,
      COORDINATED_SYNCHRONIZED_JOINS: 18,
      ABUSE_LANGUAGE: 15,
      ABUSE_SEVERE: 30,
      ABUSE_REPEATED: 25,
      ABUSE_TARGETED_HARASSMENT: 25,
      THREAT_LANGUAGE: 40,
      CLIENT_UNKNOWN_VERSION: 10,
      CLIENT_VERSION_FLAPPING: 15,
      CLIENT_IMPOSSIBLE_SEQUENCE: 20,
      CLIENT_MALFORMED_REQUESTS: 15,
      CLIENT_ABNORMAL_REQUEST_RATE: 20,
      CLIENT_PLATFORM_MISMATCH: 15,
      CLIENT_ATTESTATION_FAILED: 20,
      EVASION_POST_MODERATION_ACTIVITY: 25,
      EVASION_REJOIN_CYCLING: 20,
      EVASION_FILTER_OBFUSCATION: 15,
      GHOST_HIDDEN_PRESENCE_CORRELATED: 10,
    },
    thresholds: { LOW: 0, MEDIUM: 25, HIGH: 50, CRITICAL: 75 },
    repeatViolationWeight: 25,
    maxRepeatBonus: 25,
    historyHalfLifeMs: 24 * HOUR,
    maxHistoryComponent: 20,
    confidenceScalingFloor: 0.5,
    maxSingleContribution: 40,
    criticalAutoActionMinConfidence: 0.8,
  },
  incident: {
    dedupeWindowMs: 30 * MINUTE,
    maxEvidenceBundles: 10,
    evidenceOnNewBehaviorOnly: true,
  },
  retention: {
    rawEventsDays: 30,
    signalsDays: 90,
    incidentsDays: 365,
    evidenceDays: 365,
    auditDays: 730,
  },
  alert: {
    minLevel: 'HIGH',
    alertOnSevereAbuse: true,
    alertOnThreat: true,
    alertOnMassSpam: true,
    alertOnRepeatedEvasion: true,
    alertOnSuspiciousClient: true,
    dedupeWindowMs: 5 * MINUTE,
  },
  configVersion: '1.0.0',
};

export type DeepPartial<T> = {
  [K in keyof T]?: T[K] extends object ? (T[K] extends unknown[] ? T[K] : DeepPartial<T[K]>) : T[K];
};

/** Merge operator overrides over the defaults. Arrays replace, objects merge. */
export function resolveConfig(overrides?: DeepPartial<DetectionConfig>): DetectionConfig {
  if (!overrides) return DEFAULT_CONFIG;
  return mergeDeep(DEFAULT_CONFIG, overrides) as DetectionConfig;
}

function mergeDeep(base: unknown, override: unknown): unknown {
  if (override === undefined || override === null) return base;
  if (Array.isArray(override)) return override.slice();
  if (typeof override !== 'object' || typeof base !== 'object' || base === null) return override;

  const out: Record<string, unknown> = { ...(base as Record<string, unknown>) };
  for (const [key, value] of Object.entries(override as Record<string, unknown>)) {
    out[key] = mergeDeep((base as Record<string, unknown>)[key], value);
  }
  return out;
}

/**
 * Validate an operator-supplied config patch before it is persisted.
 * Returns a list of problems; empty means acceptable.
 */
export function validateConfigPatch(patch: DeepPartial<DetectionConfig>): string[] {
  const problems: string[] = [];

  const weights = patch.risk?.weights as Record<string, unknown> | undefined;
  if (weights) {
    for (const [code, value] of Object.entries(weights)) {
      if (typeof value !== 'number' || !Number.isFinite(value)) {
        problems.push(`risk.weights.${code} must be a finite number`);
      } else if (value < 0 || value > 100) {
        problems.push(`risk.weights.${code} must be between 0 and 100`);
      }
    }
  }

  const t = patch.risk?.thresholds;
  if (t) {
    const merged = { ...DEFAULT_CONFIG.risk.thresholds, ...t };
    if (!(merged.LOW < merged.MEDIUM && merged.MEDIUM < merged.HIGH && merged.HIGH < merged.CRITICAL)) {
      problems.push('risk.thresholds must be strictly increasing: LOW < MEDIUM < HIGH < CRITICAL');
    }
    if (merged.LOW !== 0) problems.push('risk.thresholds.LOW must be 0');
    if (merged.CRITICAL > 100) problems.push('risk.thresholds.CRITICAL must be <= 100');
  }

  for (const [key, value] of Object.entries(patch.spam ?? {})) {
    if (typeof value === 'number' && value <= 0) {
      problems.push(`spam.${key} must be greater than 0`);
    }
  }

  const minConf = patch.abuse?.autoActionMinConfidence;
  if (typeof minConf === 'number' && (minConf < 0.5 || minConf > 1)) {
    problems.push(
      'abuse.autoActionMinConfidence must be between 0.5 and 1 — lowering it further would let ' +
        'low-confidence predictions drive penalties',
    );
  }

  for (const [key, value] of Object.entries(patch.retention ?? {})) {
    if (typeof value === 'number' && (value < 1 || value > 3650)) {
      problems.push(`retention.${key} must be between 1 and 3650 days`);
    }
  }

  return problems;
}

export const TIME = { SECOND, MINUTE, HOUR, DAY };
