/**
 * Layered abusive-language classification.
 *
 * Four layers, combined by an explicit arbitration policy:
 *
 *   1. `rules`   — structural threat / severe-abuse patterns (deterministic)
 *   2. `lexicon` — tiered term matching after obfuscation folding
 *   3. `rate`    — repetition of abusive content over time
 *   4. `bedrock` — optional AI classification, supplied by the caller
 *
 * ARBITRATION PRINCIPLES (these are the product's safety requirements, encoded):
 *
 *   - AI output is never authoritative. A Bedrock verdict can raise or lower
 *     confidence and can *surface* abuse the rules missed, but it cannot by
 *     itself justify a durable penalty: `requiresHumanReview` is set whenever
 *     the AI is the sole or dominant basis.
 *   - Deterministic THREAT detections win over a SAFE AI verdict.
 *   - Material disagreement between layers yields UNCERTAIN, not a guess.
 *   - Mitigating context (quotation, reported speech, negated intent,
 *     self-directed language, gaming banter) downgrades findings before any
 *     signal is emitted.
 *   - Self-harm language is routed to a wellbeing outcome, never enforcement.
 */

import type { AbuseConfig } from '../../config/detection-config.ts';
import type {
  AbuseClassification,
  Classification,
  ClassificationSource,
  DetectionSignal,
  RecommendedAction,
  Severity,
} from '../../types/detection.ts';
import type { TalkinEvent, WindowEntry } from '../../types/events.ts';
import { clamp, noisyOr, round } from '../../util/stats.ts';
import { collapseLetterSpacing, normalizeForMatch, analyzeCharacters } from '../../util/text.ts';
import { compileLexicon, matchAll, type CompiledLexicon } from './lexicon.ts';

export const ABUSE_DETECTOR = 'abuse-classifier@1.3.0';
export const RULES_VERSION = 'rules@1.3.0';

/** Severity order used for arbitration. */
const RANK: Record<Classification, number> = {
  SAFE: 0,
  UNCERTAIN: 1,
  ABUSIVE: 2,
  SEVERE_ABUSE: 3,
  THREAT: 4,
};

export interface BedrockVerdict {
  classification: Classification;
  confidence: number;
  reason: string;
  modelVersion: string;
}

export interface AbuseInput {
  event: TalkinEvent;
  config: AbuseConfig;
  nowMs: number;
  /** Prior window entries, used for the repetition layer. */
  window?: readonly WindowEntry[];
  /** Fingerprints of previously confirmed-abusive messages from this user. */
  priorAbusiveFingerprints?: readonly string[];
  /** Optional AI verdict. Omitted when Bedrock is disabled or unavailable. */
  bedrock?: BedrockVerdict;
  /** Pre-compiled lexicon; compiled on demand when absent. */
  lexicon?: CompiledLexicon;
}

export interface AbuseResult {
  classification: AbuseClassification;
  signals: DetectionSignal[];
  /** True when the message indicates risk to the *sender*, not to others. */
  selfHarmConcern: boolean;
  /** Mitigating contexts that were applied. */
  mitigations: string[];
}

export function buildLexicon(config: AbuseConfig, version: string): CompiledLexicon {
  return compileLexicon({
    mild: config.extraTerms.mild,
    severe: config.extraTerms.severe,
    threat: config.extraTerms.threat,
    allow: config.allowTerms,
    version: `lexicon@${version}`,
  });
}

export function classifyAbuse(input: AbuseInput): AbuseResult {
  const { event, config, nowMs } = input;
  const lexicon = input.lexicon ?? buildLexicon(config, '1.0.0');

  const text = event.message;
  if (text === undefined || text.trim().length === 0) {
    return {
      classification: safeResult(
        'No message content was available to analyse.',
        [],
        `${ABUSE_DETECTOR};${RULES_VERSION}`,
      ),
      signals: [],
      selfHarmConcern: false,
      mitigations: [],
    };
  }

  const normalized = normalizeForMatch(text);
  // "k i l l  y o u" collapses to "killyou"; matched with boundary-relaxed
  // patterns because collapsing necessarily destroys word boundaries.
  const collapsed = collapseLetterSpacing(normalized);
  const haystacks = collapsed ? [normalized, collapsed] : [normalized];

  /** Match a tier against normal text strictly, and collapsed text densely. */
  const matchTier = (tier: 'mild' | 'severe' | 'threat'): string[] => {
    const hits = matchAll(lexicon[tier], normalized);
    if (collapsed !== undefined) hits.push(...matchAll(lexicon.dense[tier], collapsed));
    return unique(hits);
  };

  // --- Mitigating context ------------------------------------------------
  const mitigations: string[] = [];
  for (const { name, re } of lexicon.mitigating) {
    if (haystacks.some((h) => re.test(h))) mitigations.push(name);
  }

  const selfHarmConcern = haystacks.some((h) => lexicon.selfHarm.test(h));

  // --- Allow-list --------------------------------------------------------
  const allowed = lexicon.allow ? haystacks.flatMap((h) => matchAll(lexicon.allow as RegExp, h)) : [];

  const sources: ClassificationSource[] = [];

  // --- Layer 1: structural rules ----------------------------------------
  const threatHits = matchTier('threat');
  const severeHits = matchTier('severe');

  const negated = mitigations.includes('negated-intent');
  const quoted = mitigations.includes('quotation') || mitigations.includes('reported-speech');
  const gaming = mitigations.includes('gaming-context');
  const reporting = mitigations.includes('reporting-abuse');
  const selfDirected = mitigations.includes('self-directed');

  if (threatHits.length > 0) {
    // A threat phrase inside quoted/reported speech, explicitly negated, or
    // clearly framed as in-game banter is downgraded rather than enforced.
    let classification: Classification = 'THREAT';
    let confidence = 0.9;
    let reason = `Threat pattern matched (${threatHits.length} construction${threatHits.length === 1 ? '' : 's'}): actor, intent verb and target all present.`;

    if (negated) {
      classification = 'SAFE';
      confidence = 0.6;
      reason = 'Threat-shaped phrasing was explicitly negated ("never", "not going to") — not treated as a threat.';
    } else if (reporting) {
      classification = 'SAFE';
      confidence = 0.55;
      reason = 'Threat-shaped phrasing appears inside a report *about* abuse rather than as a threat.';
    } else if (quoted) {
      classification = 'UNCERTAIN';
      confidence = 0.5;
      reason = 'Threat phrasing appears as quoted or reported speech — requires human review to attribute.';
    } else if (gaming) {
      classification = 'UNCERTAIN';
      confidence = 0.45;
      reason = 'Violent verb used in an apparent in-game context — requires human review.';
    }

    sources.push({
      layer: 'rules',
      classification,
      confidence,
      reason,
      version: RULES_VERSION,
    });
  }

  if (severeHits.length > 0) {
    let classification: Classification = 'SEVERE_ABUSE';
    let confidence = 0.85;
    let reason = `Severe-abuse construction matched (${severeHits.length} pattern${severeHits.length === 1 ? '' : 's'}).`;

    if (selfDirected && !hasOtherTarget(normalized)) {
      classification = 'SAFE';
      confidence = 0.6;
      reason = 'Hostile language appears self-directed; routed to wellbeing rather than enforcement.';
    } else if (reporting || quoted) {
      classification = 'UNCERTAIN';
      confidence = 0.5;
      reason = 'Severe-abuse phrasing appears quoted or reported — requires human review to attribute.';
    }

    sources.push({
      layer: 'rules',
      classification,
      confidence,
      reason,
      version: RULES_VERSION,
    });
  }

  // --- Layer 2: lexicon -------------------------------------------------
  const mildHits = matchTier('mild').filter(
    (hit) => !allowed.some((a) => a.includes(hit) || hit.includes(a)),
  );

  if (mildHits.length > 0) {
    const targeted = isTargeted(normalized, event);
    // Profanity alone is weak; profanity aimed at a participant is stronger.
    let confidence = targeted ? 0.68 : 0.42;
    let classification: Classification = targeted ? 'ABUSIVE' : 'UNCERTAIN';
    let reason = targeted
      ? `Profanity directed at a participant (${mildHits.length} term${mildHits.length === 1 ? '' : 's'} matched, second-person target present).`
      : `Profanity present but not directed at a participant (${mildHits.length} term${mildHits.length === 1 ? '' : 's'} matched) — weak signal only.`;

    if (quoted || reporting || selfDirected) {
      classification = 'SAFE';
      confidence = 0.5;
      reason = 'Profanity appears in quoted, reported or self-directed context — not treated as abuse of another participant.';
    } else if (mildHits.length >= 4 && targeted) {
      confidence = 0.8;
      reason = `Sustained profanity directed at a participant (${mildHits.length} distinct terms).`;
    }

    sources.push({
      layer: 'lexicon',
      classification,
      confidence,
      reason,
      version: lexicon.version,
    });
  }

  // --- Layer 2b: deliberate filter obfuscation ---------------------------
  const anomalies = analyzeCharacters(text);
  const obfuscated =
    (anomalies.invisibleInsideWord || anomalies.mixedScriptWords > 0 || anomalies.letterSpaced) &&
    (mildHits.length > 0 || severeHits.length > 0 || threatHits.length > 0);

  // --- Layer 3: repetition ----------------------------------------------
  const priorFingerprints = input.priorAbusiveFingerprints ?? [];
  const recentAbusive = priorFingerprints.length;
  if (recentAbusive + 1 >= config.repeatCount && (mildHits.length > 0 || severeHits.length > 0)) {
    sources.push({
      layer: 'rate',
      classification: 'ABUSIVE',
      confidence: 0.75,
      reason: `${recentAbusive + 1} abusive messages from this user within the repeat window (threshold ${config.repeatCount}).`,
      version: RULES_VERSION,
    });
  }

  // --- Layer 4: Bedrock --------------------------------------------------
  if (input.bedrock) {
    sources.push({
      layer: 'bedrock',
      classification: input.bedrock.classification,
      confidence: clamp(input.bedrock.confidence, 0, 1),
      reason: input.bedrock.reason,
      version: input.bedrock.modelVersion,
    });
  }

  const classification = arbitrate(sources, config, mitigations);
  const signals = toSignals({
    classification,
    config,
    event,
    nowMs,
    threatHits: threatHits.length,
    severeHits: severeHits.length,
    mildHits: mildHits.length,
    repeated: recentAbusive + 1 >= config.repeatCount,
    obfuscated,
    targeted: isTargeted(normalized, event),
  });

  return { classification, signals, selfHarmConcern, mitigations };
}

/**
 * Combine layer verdicts into a single decision.
 *
 * The rule is: take the most severe *deterministic* verdict as the floor, let
 * the AI raise severity only with corroboration or an explicit human-review
 * flag, and collapse genuine disagreement to UNCERTAIN.
 */
function arbitrate(
  sources: readonly ClassificationSource[],
  config: AbuseConfig,
  mitigations: readonly string[],
): AbuseClassification {
  const modelVersions = unique([ABUSE_DETECTOR, ...sources.map((s) => s.version)]);

  if (sources.length === 0) {
    return safeResult('No abuse indicators matched.', [], modelVersions.join(';'));
  }

  const deterministic = sources.filter((s) => s.layer !== 'bedrock');
  const ai = sources.find((s) => s.layer === 'bedrock');

  const topDeterministic = deterministic.reduce<ClassificationSource | undefined>(
    (best, cur) => (best === undefined || RANK[cur.classification] > RANK[best.classification] ? cur : best),
    undefined,
  );

  let classification: Classification;
  let confidence: number;
  let reason: string;
  let requiresHumanReview = false;

  if (topDeterministic && ai) {
    const gap = Math.abs(RANK[topDeterministic.classification] - RANK[ai.classification]);
    const agree = topDeterministic.classification === ai.classification;

    if (agree) {
      classification = topDeterministic.classification;
      // Independent agreement genuinely increases confidence.
      confidence = noisyOr([topDeterministic.confidence, ai.confidence]);
      reason = `${topDeterministic.reason} AI classifier agreed: ${ai.reason}`;
    } else if (RANK[topDeterministic.classification] >= RANK.SEVERE_ABUSE) {
      // Deterministic severe/threat findings are not overridden by the model.
      classification = topDeterministic.classification;
      confidence = topDeterministic.confidence;
      reason = `${topDeterministic.reason} (AI classifier returned ${ai.classification}; deterministic rules take precedence for severe findings.)`;
      requiresHumanReview = ai.classification === 'SAFE';
    } else if (gap >= 2 || normalizedGap(topDeterministic, ai) >= config.disagreementThreshold) {
      classification = 'UNCERTAIN';
      confidence = 0.5;
      reason = `Detection layers disagreed (rules: ${topDeterministic.classification}, AI: ${ai.classification}). Escalated for human review rather than acted on automatically.`;
      requiresHumanReview = true;
    } else if (RANK[ai.classification] > RANK[topDeterministic.classification]) {
      // The model is more severe than the rules: accept, but require review
      // because the AI is now the dominant basis for the decision.
      classification = ai.classification;
      confidence = Math.min(ai.confidence, 0.75);
      reason = `AI classifier flagged ${ai.classification}: ${ai.reason} Deterministic rules only reached ${topDeterministic.classification}, so this requires human confirmation.`;
      requiresHumanReview = true;
    } else {
      classification = topDeterministic.classification;
      confidence = topDeterministic.confidence;
      reason = topDeterministic.reason;
    }
  } else if (topDeterministic) {
    classification = topDeterministic.classification;
    confidence = topDeterministic.confidence;
    reason = topDeterministic.reason;
  } else if (ai) {
    // AI-only finding. Never authoritative: capped confidence and always
    // flagged for review.
    classification = ai.classification === 'SAFE' ? 'SAFE' : 'UNCERTAIN';
    confidence = Math.min(ai.confidence, 0.7);
    reason =
      ai.classification === 'SAFE'
        ? `AI classifier found no abuse: ${ai.reason}`
        : `AI classifier flagged ${ai.classification} with no corroborating deterministic rule: ${ai.reason} Recorded as UNCERTAIN pending human review.`;
    requiresHumanReview = ai.classification !== 'SAFE';
  } else {
    return safeResult('No abuse indicators matched.', sources, modelVersions.join(';'));
  }

  // Confidence below the configured floor can never drive an automated penalty.
  if (confidence < config.autoActionMinConfidence && classification !== 'SAFE') {
    requiresHumanReview = true;
  }

  if (mitigations.length > 0 && classification !== 'SAFE') {
    reason += ` Mitigating context considered: ${mitigations.join(', ')}.`;
  }

  return {
    classification,
    confidence: round(clamp(confidence, 0, 1), 4),
    reason,
    recommendedAction: recommend(classification, confidence, config),
    sources: [...sources],
    modelVersion: modelVersions.join(';'),
    requiresHumanReview,
  };
}

function normalizedGap(a: ClassificationSource, b: ClassificationSource): number {
  return Math.abs(RANK[a.classification] - RANK[b.classification]) / 4 + Math.abs(a.confidence - b.confidence) / 2;
}

function recommend(
  classification: Classification,
  confidence: number,
  config: AbuseConfig,
): RecommendedAction {
  // Low-confidence findings never recommend more than a warning.
  const confident = confidence >= config.autoActionMinConfidence;
  switch (classification) {
    case 'THREAT':
      return 'REPORT';
    case 'SEVERE_ABUSE':
      return confident ? 'BLOCK' : 'REPORT';
    case 'ABUSIVE':
      return confident ? 'MUTE' : 'WARN';
    case 'UNCERTAIN':
      return 'WARN';
    case 'SAFE':
      return 'NONE';
    default:
      return 'NONE';
  }
}

function safeResult(
  reason: string,
  sources: readonly ClassificationSource[],
  modelVersion: string,
): AbuseClassification {
  return {
    classification: 'SAFE',
    confidence: 0.9,
    reason,
    recommendedAction: 'NONE',
    sources: [...sources],
    modelVersion,
    requiresHumanReview: false,
  };
}

function toSignals(args: {
  classification: AbuseClassification;
  config: AbuseConfig;
  event: TalkinEvent;
  nowMs: number;
  threatHits: number;
  severeHits: number;
  mildHits: number;
  repeated: boolean;
  obfuscated: boolean;
  targeted: boolean;
}): DetectionSignal[] {
  const { classification, config, event, nowMs } = args;
  if (classification.classification === 'SAFE') return [];

  /**
   * Emission floor.
   *
   * A weak, undirected finding — "ah shit, I missed the shot" lands at ~0.42 —
   * must not surface as an abuse detection at all. Showing it would fill the
   * dashboard with noise that no moderator would act on, and erode trust in the
   * signals that matter. THREAT and SEVERE_ABUSE bypass the floor: those are
   * always worth a human's attention even when tentative.
   */
  const serious =
    classification.classification === 'THREAT' || classification.classification === 'SEVERE_ABUSE';
  if (!serious && classification.confidence < config.minConfidence) return [];

  const out: DetectionSignal[] = [];
  const base = {
    evidenceEventIds: [event.eventId],
    detector: ABUSE_DETECTOR,
    observedAtMs: nowMs,
  };

  const severityFor = (c: Classification): Severity => {
    if (c === 'THREAT') return 'SEVERE';
    if (c === 'SEVERE_ABUSE') return 'SEVERE';
    if (c === 'ABUSIVE') return 'MEDIUM';
    return 'LOW';
  };

  if (classification.classification === 'THREAT') {
    out.push({
      ...base,
      code: 'THREAT_LANGUAGE',
      category: 'THREAT',
      severity: 'SEVERE',
      confidence: classification.confidence,
      reason: classification.reason,
      details: { threatPatternsMatched: args.threatHits, transcript: event.messageIsTranscript === true },
    });
  } else if (classification.classification === 'SEVERE_ABUSE') {
    out.push({
      ...base,
      code: 'ABUSE_SEVERE',
      category: 'ABUSE',
      severity: 'SEVERE',
      confidence: classification.confidence,
      reason: classification.reason,
      details: { severePatternsMatched: args.severeHits, transcript: event.messageIsTranscript === true },
    });
  } else if (classification.classification === 'ABUSIVE' || classification.classification === 'UNCERTAIN') {
    out.push({
      ...base,
      code: 'ABUSE_LANGUAGE',
      category: 'ABUSE',
      severity: severityFor(classification.classification),
      confidence: classification.confidence,
      reason: classification.reason,
      details: { termsMatched: args.mildHits, targeted: args.targeted, transcript: event.messageIsTranscript === true },
    });
  }

  if (args.targeted && RANK[classification.classification] >= RANK.ABUSIVE) {
    out.push({
      ...base,
      code: 'ABUSE_TARGETED_HARASSMENT',
      category: 'ABUSE',
      severity: 'HIGH',
      confidence: Math.min(classification.confidence, 0.85),
      reason: 'Abusive content was directed at a specific participant (direct address or @mention present).',
    });
  }

  if (args.repeated) {
    out.push({
      ...base,
      code: 'ABUSE_REPEATED',
      category: 'ABUSE',
      severity: 'HIGH',
      confidence: 0.8,
      reason: 'Abusive content repeated across multiple messages within the configured repeat window.',
    });
  }

  if (args.obfuscated) {
    out.push({
      ...base,
      code: 'EVASION_FILTER_OBFUSCATION',
      category: 'EVASION',
      severity: 'MEDIUM',
      confidence: 0.8,
      reason:
        'Abusive content was obfuscated with invisible characters, mixed scripts or letter spacing — an apparent attempt to evade content filtering.',
    });
  }

  return out;
}

/** Second-person address or an explicit @mention indicates a target. */
function isTargeted(normalized: string, event: TalkinEvent): boolean {
  if (/(?:^|\s)@[a-z0-9_.-]{2,}/u.test(normalized)) return true;
  return /\b(?:you|u|ur|your|yall|y'all)\b/u.test(normalized) && event.eventType !== 'join';
}

function hasOtherTarget(normalized: string): boolean {
  return /\b(?:you|u|him|her|them|they|@\w+)\b/u.test(normalized);
}

function unique<T>(values: readonly T[]): T[] {
  return [...new Set(values)];
}
