/**
 * Spam, flood and automation-pattern detection.
 *
 * Operates purely on a bounded per-user sliding window plus the event under
 * analysis. Every threshold comes from `SpamConfig`; nothing here is tuned
 * in-line. All findings are deterministic and reproducible — given the same
 * window and config, the same signals are always produced.
 */

import type { SpamConfig } from '../config/detection-config.ts';
import type { DetectionSignal, Severity } from '../types/detection.ts';
import type { TalkinEvent, WindowEntry } from '../types/events.ts';
import {
  analyzeCharacters,
  countMentions,
  extractUrls,
  fingerprint,
  similarity,
} from '../util/text.ts';
import { clamp, coefficientOfVariation, deltas, mean, round, saturate } from '../util/stats.ts';

export const SPAM_DETECTOR = 'spam-detector@1.2.0';

export interface SpamInput {
  event: TalkinEvent;
  /** Prior window entries for this user, any order. */
  window: readonly WindowEntry[];
  config: SpamConfig;
  nowMs: number;
}

export function detectSpam(input: SpamInput): DetectionSignal[] {
  const { event, config, nowMs } = input;
  const signals: DetectionSignal[] = [];

  // Only content-bearing events participate in spam analysis.
  const history = [...input.window]
    .filter((e) => e.eventType === 'message' || e.eventType === 'voice')
    .sort((a, b) => a.atMs - b.atMs);

  const currentEntry: WindowEntry = {
    eventId: event.eventId,
    atMs: event.receivedAtMs,
    eventType: event.eventType,
    roomId: event.roomId,
    ...(event.message !== undefined ? { fingerprint: fingerprint(event.message) } : {}),
    ...(event.message !== undefined ? { mentions: countMentions(event.message) } : {}),
  };

  const isContentEvent = event.eventType === 'message' || event.eventType === 'voice';
  const series = isContentEvent ? [...history, currentEntry] : history;

  const inWindow = series.filter((e) => nowMs - e.atMs <= config.windowMs);
  const inBurst = series.filter((e) => nowMs - e.atMs <= config.burstWindowMs);
  const inSustained = series.filter((e) => nowMs - e.atMs <= config.sustainedWindowMs);

  // --- Burst: many messages in a very short window -----------------------
  if (inBurst.length >= config.burstCount) {
    const seconds = round(config.burstWindowMs / 1000, 1);
    signals.push(
      signal({
        code: 'SPAM_BURST',
        severity: inBurst.length >= config.burstCount * 2 ? 'HIGH' : 'MEDIUM',
        confidence: 0.6 + 0.35 * saturate(inBurst.length, config.burstCount, config.burstCount * 3),
        reason: `${inBurst.length} messages sent within ${seconds}s (burst threshold ${config.burstCount}).`,
        evidenceEventIds: idsOf(inBurst),
        nowMs,
        details: {
          messageCount: inBurst.length,
          windowSeconds: seconds,
          threshold: config.burstCount,
        },
      }),
    );
  }

  // --- Sustained high frequency -----------------------------------------
  if (inWindow.length >= config.highFrequencyCount) {
    const seconds = round(config.windowMs / 1000, 1);
    const perMinute = round((inWindow.length / config.windowMs) * 60_000, 1);
    signals.push(
      signal({
        code: 'SPAM_HIGH_FREQUENCY',
        severity: inWindow.length >= config.highFrequencyCount * 2 ? 'HIGH' : 'MEDIUM',
        confidence:
          0.55 +
          0.4 * saturate(inWindow.length, config.highFrequencyCount, config.highFrequencyCount * 3),
        reason: `${inWindow.length} messages in ${seconds}s (~${perMinute}/min), above the configured limit of ${config.highFrequencyCount}.`,
        evidenceEventIds: idsOf(inWindow).slice(-20),
        nowMs,
        details: { messageCount: inWindow.length, windowSeconds: seconds, perMinute },
      }),
    );
  }

  if (inSustained.length >= config.sustainedCount) {
    const minutes = round(config.sustainedWindowMs / 60_000, 1);
    signals.push(
      signal({
        code: 'BOT_SUSTAINED_RATE',
        severity: 'HIGH',
        confidence: 0.75,
        reason: `${inSustained.length} messages sustained over ${minutes} minutes — a rate that is implausible for manual typing.`,
        evidenceEventIds: idsOf(inSustained).slice(-20),
        nowMs,
        details: { messageCount: inSustained.length, windowMinutes: minutes },
      }),
    );
  }

  // --- Identical / near-duplicate repetition ----------------------------
  if (currentEntry.fingerprint !== undefined && currentEntry.fingerprint.length > 0) {
    const fp = currentEntry.fingerprint;
    const identical = inWindowOrAll(series, config.windowMs * 10, nowMs).filter(
      (e) => e.fingerprint === fp,
    );

    // Short phrases recur naturally in conversation, so they need
    // proportionally more repeats before being treated as spam.
    const isShort = fp.length <= config.identicalShortMessageLength;
    const multiplier = isShort ? config.identicalShortRepeatMultiplier : 1;
    const repeatThreshold = config.identicalRepeatCount * multiplier;
    const severeThreshold = config.identicalSevereCount * multiplier;

    if (identical.length >= repeatThreshold) {
      const severe = identical.length >= severeThreshold;
      signals.push(
        signal({
          code: 'SPAM_IDENTICAL_REPEAT',
          severity: severe ? 'SEVERE' : 'MEDIUM',
          confidence: severe
            ? 0.95
            : 0.65 + 0.3 * saturate(identical.length, repeatThreshold, severeThreshold),
          reason:
            `The same message content was sent ${identical.length} times (threshold ${repeatThreshold}` +
            `${severe ? `, severe at ${severeThreshold}` : ''})` +
            `${isShort ? ', adjusted upward because the message is short' : ''}.`,
          evidenceEventIds: idsOf(identical).slice(-20),
          nowMs,
          details: {
            repeatCount: identical.length,
            threshold: repeatThreshold,
            severeThreshold,
            shortMessage: isShort,
          },
        }),
      );
    } else {
      // Near-duplicates: same template with small mutations to defeat exact
      // match. Skipped for short messages, where trigram similarity is too
      // noisy to distinguish spam from ordinary short replies.
      const candidates =
        fp.length >= config.nearDuplicateMinLength
          ? inWindowOrAll(series, config.windowMs * 10, nowMs).filter(
              (e) =>
                e.fingerprint !== undefined &&
                e.fingerprint.length >= config.nearDuplicateMinLength &&
                e.eventId !== event.eventId,
            )
          : [];
      let near = 1;
      const nearIds: string[] = [event.eventId];
      for (const candidate of candidates) {
        const other = candidate.fingerprint;
        if (other === undefined) continue;
        if (similarity(fp, other) >= config.nearDuplicateSimilarity) {
          near += 1;
          nearIds.push(candidate.eventId);
        }
      }
      if (candidates.length > 0 && near >= config.nearDuplicateCount) {
        signals.push(
          signal({
            code: 'SPAM_NEAR_DUPLICATE',
            severity: 'MEDIUM',
            confidence: 0.6 + 0.25 * saturate(near, config.nearDuplicateCount, config.nearDuplicateCount * 3),
            reason: `${near} messages share ≥${Math.round(config.nearDuplicateSimilarity * 100)}% similarity — repeated content with minor variations.`,
            evidenceEventIds: nearIds.slice(-20),
            nowMs,
            details: {
              nearDuplicateCount: near,
              similarityThreshold: config.nearDuplicateSimilarity,
            },
          }),
        );
      }
    }
  }

  // --- Mention flooding --------------------------------------------------
  const currentMentions = currentEntry.mentions ?? 0;
  const windowMentions = inWindow.reduce((sum, e) => sum + (e.mentions ?? 0), 0);
  if (currentMentions > config.mentionsPerMessage || windowMentions > config.mentionsPerWindow) {
    signals.push(
      signal({
        code: 'SPAM_MENTION_FLOOD',
        severity: windowMentions > config.mentionsPerWindow * 2 ? 'HIGH' : 'MEDIUM',
        confidence: 0.7,
        reason:
          currentMentions > config.mentionsPerMessage
            ? `A single message mentioned ${currentMentions} users (limit ${config.mentionsPerMessage}).`
            : `${windowMentions} user mentions within the detection window (limit ${config.mentionsPerWindow}).`,
        evidenceEventIds: [event.eventId],
        nowMs,
        details: { mentionsInMessage: currentMentions, mentionsInWindow: windowMentions },
      }),
    );
  }

  // --- Link flooding ----------------------------------------------------
  if (event.message !== undefined) {
    const urls = extractUrls(event.message);
    if (urls.length >= config.linksPerWindow) {
      signals.push(
        signal({
          code: 'SPAM_LINK_FLOOD',
          severity: 'MEDIUM',
          confidence: 0.65,
          reason: `Message contained ${urls.length} distinct links (limit ${config.linksPerWindow}).`,
          evidenceEventIds: [event.eventId],
          nowMs,
          details: { linkCount: urls.length },
        }),
      );
    }
  }

  // --- Suspicious character patterns ------------------------------------
  if (event.message !== undefined) {
    const anomalies = analyzeCharacters(event.message);
    const reasons: string[] = [];
    let confidence = 0;

    if (anomalies.invisibleInsideWord) {
      reasons.push('zero-width characters inserted inside words');
      confidence = Math.max(confidence, 0.85);
    } else if (anomalies.invisibleCount > 3) {
      reasons.push(`${anomalies.invisibleCount} invisible characters`);
      confidence = Math.max(confidence, 0.6);
    }
    if (anomalies.combiningRatio > 1.5) {
      reasons.push(`excessive combining marks (${round(anomalies.combiningRatio, 1)} per character)`);
      confidence = Math.max(confidence, 0.8);
    }
    if (anomalies.mixedScriptWords > 0) {
      reasons.push(`${anomalies.mixedScriptWords} word(s) mixing Latin with another script`);
      confidence = Math.max(confidence, 0.7);
    }
    if (anomalies.letterSpaced) {
      reasons.push('text appears deliberately letter-spaced');
      confidence = Math.max(confidence, 0.65);
    }
    if (anomalies.maxCharRun >= 15) {
      reasons.push(`a single character repeated ${anomalies.maxCharRun} times`);
      confidence = Math.max(confidence, 0.55);
    }
    if (event.message.length > 40 && anomalies.capsRatio > 0.85) {
      reasons.push('almost entirely uppercase');
      confidence = Math.max(confidence, 0.45);
    }
    if (event.message.length > 20 && anomalies.symbolRatio > 0.5) {
      reasons.push('majority non-alphanumeric characters');
      confidence = Math.max(confidence, 0.5);
    }

    if (reasons.length > 0) {
      signals.push(
        signal({
          code: 'SPAM_SUSPICIOUS_CHARACTERS',
          severity: confidence >= 0.8 ? 'HIGH' : 'LOW',
          confidence,
          reason: `Suspicious character patterns: ${reasons.join('; ')}.`,
          evidenceEventIds: [event.eventId],
          nowMs,
          details: {
            invisibleCount: anomalies.invisibleCount,
            combiningRatio: round(anomalies.combiningRatio, 2),
            capsRatio: round(anomalies.capsRatio, 2),
            maxCharRun: anomalies.maxCharRun,
            symbolRatio: round(anomalies.symbolRatio, 2),
            mixedScriptWords: anomalies.mixedScriptWords,
          },
        }),
      );
    }
  }

  // --- Machine-like timing regularity ------------------------------------
  const timing = analyzeTiming(series, config, nowMs);
  if (timing) signals.push(timing);

  return signals;
}

/**
 * Inter-arrival regularity.
 *
 * A scripted sender posts on a near-fixed cadence, so the coefficient of
 * variation of the gaps collapses toward zero. Humans are irregular. We require
 * a minimum sample count and a reasonably tight mean gap before judging, so a
 * person who happens to send two evenly spaced messages is never flagged.
 */
function analyzeTiming(
  series: readonly WindowEntry[],
  config: SpamConfig,
  nowMs: number,
): DetectionSignal | undefined {
  if (series.length < config.timingMinSamples) return undefined;

  const recent = series.slice(-Math.max(config.timingMinSamples * 4, 12));
  const gaps = deltas(recent.map((e) => e.atMs)).filter((g) => g >= 0);
  if (gaps.length + 1 < config.timingMinSamples) return undefined;

  const meanGap = mean(gaps);
  if (meanGap > config.timingMaxMeanGapMs) return undefined;
  // Sub-50ms mean gaps are usually a batch import, not a live cadence.
  if (meanGap < 50) return undefined;

  const cv = coefficientOfVariation(gaps);
  if (cv > config.timingMaxCoefficientOfVariation) return undefined;

  // Tighter regularity over more samples => higher confidence.
  const regularity = 1 - cv / config.timingMaxCoefficientOfVariation;
  const sampleBoost = saturate(gaps.length, config.timingMinSamples, config.timingMinSamples * 4);
  const confidence = clamp(0.55 + 0.3 * regularity + 0.15 * sampleBoost, 0, 0.97);

  return signal({
    code: 'BOT_UNIFORM_TIMING',
    severity: 'HIGH',
    confidence,
    reason: `Message timing is machine-like: ${gaps.length + 1} messages at a mean interval of ${Math.round(meanGap)}ms with only ${round(cv * 100, 1)}% variation (human conversation typically exceeds ${round(config.timingMaxCoefficientOfVariation * 100, 0)}%).`,
    evidenceEventIds: idsOf(recent).slice(-20),
    nowMs,
    details: {
      sampleCount: gaps.length + 1,
      meanIntervalMs: Math.round(meanGap),
      coefficientOfVariation: round(cv, 4),
      threshold: config.timingMaxCoefficientOfVariation,
    },
  });
}

function inWindowOrAll(
  series: readonly WindowEntry[],
  windowMs: number,
  nowMs: number,
): WindowEntry[] {
  return series.filter((e) => nowMs - e.atMs <= windowMs);
}

function idsOf(entries: readonly WindowEntry[]): string[] {
  return entries.map((e) => e.eventId);
}

function signal(args: {
  code: DetectionSignal['code'];
  severity: Severity;
  confidence: number;
  reason: string;
  evidenceEventIds: string[];
  nowMs: number;
  details?: Record<string, string | number | boolean>;
}): DetectionSignal {
  return {
    code: args.code,
    category: args.code.startsWith('BOT_') ? 'FREQUENCY' : categoryFor(args.code),
    severity: args.severity,
    confidence: round(clamp(args.confidence, 0, 1), 4),
    reason: args.reason,
    evidenceEventIds: [...new Set(args.evidenceEventIds)],
    detector: SPAM_DETECTOR,
    observedAtMs: args.nowMs,
    ...(args.details ? { details: args.details } : {}),
  };
}

function categoryFor(code: DetectionSignal['code']): DetectionSignal['category'] {
  if (code === 'SPAM_HIGH_FREQUENCY' || code === 'SPAM_BURST') return 'FREQUENCY';
  return 'SPAM';
}

/**
 * Update a user's bounded detection window with a new event.
 * Oldest entries are dropped once `maxWindowEvents` is reached, so per-user
 * state can never grow without limit (data minimization + cost control).
 */
export function appendToWindow(
  window: readonly WindowEntry[],
  event: TalkinEvent,
  config: SpamConfig,
): WindowEntry[] {
  const entry: WindowEntry = {
    eventId: event.eventId,
    atMs: event.receivedAtMs,
    eventType: event.eventType,
    roomId: event.roomId,
  };
  if (event.message !== undefined) {
    entry.fingerprint = fingerprint(event.message);
    entry.mentions = countMentions(event.message);
  }
  if (event.clientVersion !== undefined) entry.clientVersion = event.clientVersion;
  entry.platform = event.platform;

  const next = [...window, entry].sort((a, b) => a.atMs - b.atMs);
  return next.length > config.maxWindowEvents ? next.slice(next.length - config.maxWindowEvents) : next;
}

/** Drop window entries older than the longest window we ever inspect. */
export function pruneWindow(
  window: readonly WindowEntry[],
  config: SpamConfig,
  nowMs: number,
): WindowEntry[] {
  const horizon = Math.max(config.sustainedWindowMs, config.windowMs * 10);
  return window.filter((e) => nowMs - e.atMs <= horizon);
}
