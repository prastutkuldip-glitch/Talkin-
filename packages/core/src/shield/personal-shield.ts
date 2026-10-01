/**
 * Personal Shield — protection scoped entirely to the person running it.
 *
 * WHAT THIS IS FOR
 *   You are in a voice room and someone is being abusive. You cannot and should
 *   not be forced to listen to it. This shield watches the incoming audio
 *   *that you are already receiving*, and when a speaker turns abusive it mutes
 *   THEM FOR YOU — their voice stops reaching your ears — and captures evidence
 *   you can report.
 *
 * WHAT THIS IS NOT
 *   This never touches the other person's device, microphone, client or
 *   connection. It cannot disable, jam or silence anyone's mic. The abuser
 *   keeps speaking; other people may still hear them. The ONLY thing that
 *   changes is what *your* client plays back to *you*. That is your right over
 *   your own audio output, and it needs no one else's permission.
 *
 *   Concretely: the output of this module is a set of speaker ids to drop from
 *   YOUR local mix, plus evidence. It emits no command, packet or signal
 *   addressed to anyone else. There is deliberately no code path here that
 *   could.
 *
 * This is the honest, legal and genuinely effective version of "make the
 * abuse stop" — the outcome you actually want, without crossing into
 * controlling someone else's equipment.
 */

import type { AbuseConfig } from '../config/detection-config.ts';
import { buildLexicon, classifyAbuse, type BedrockVerdict } from '../detection/abuse/classifier.ts';
import type { CompiledLexicon } from '../detection/abuse/lexicon.ts';
import type { AbuseClassification, Classification } from '../types/detection.ts';
import { clamp } from '../util/stats.ts';
import { redactIdentifiers, truncate } from '../util/text.ts';

export const SHIELD_VERSION = 'personal-shield@1.0.0';

/** How the shield may act on a speaker — always local to the protected user. */
export const SHIELD_ACTIONS = ['NONE', 'FLAG', 'LOCAL_SOFT_MUTE', 'LOCAL_MUTE', 'LOCAL_BLOCK'] as const;
export type ShieldAction = (typeof SHIELD_ACTIONS)[number];

export interface ShieldConfig {
  /**
   * After this many abusive utterances within `offenseWindowMs`, the speaker is
   * locally muted for the protected user.
   */
  muteAfterOffenses: number;
  /** Window over which offenses are counted. */
  offenseWindowMs: number;
  /** A single THREAT or SEVERE_ABUSE utterance mutes immediately. */
  muteImmediatelyOnSevere: boolean;
  /** How long a local mute lasts before the speaker is auto-unmuted, ms. */
  localMuteDurationMs: number;
  /** Confidence floor below which an utterance is only flagged, never muted. */
  minMuteConfidence: number;
  /** Max transcript characters retained per captured utterance (redacted). */
  evidenceExcerptChars: number;
  /** Max utterances kept in the per-speaker rolling window. */
  maxWindowPerSpeaker: number;
}

export const DEFAULT_SHIELD_CONFIG: ShieldConfig = {
  muteAfterOffenses: 2,
  offenseWindowMs: 60_000,
  muteImmediatelyOnSevere: true,
  localMuteDurationMs: 10 * 60_000,
  minMuteConfidence: 0.6,
  evidenceExcerptChars: 280,
  maxWindowPerSpeaker: 40,
};

/** A single utterance the protected user received (speech-to-text transcript). */
export interface Utterance {
  /** Pseudonymous id of the speaker, as the platform reports it. */
  speakerId: string;
  roomId: string;
  /** Epoch ms the utterance was received by the protected user. */
  atMs: number;
  /** Transcript text. The shield never needs the raw audio bytes. */
  transcript: string;
  /** 0..1 transcription confidence, when the recognizer provides it. */
  transcriptConfidence?: number;
}

/** Rolling per-speaker state, held in the protected user's own client. */
export interface SpeakerState {
  speakerId: string;
  /** Recent offenses: epoch ms + severity, newest last, bounded. */
  offenses: Array<{ atMs: number; classification: Classification }>;
  /** When set, this speaker is locally muted for the user until this epoch ms. */
  mutedUntilMs?: number;
  /** True when the user has permanently blocked this speaker locally. */
  blockedLocally: boolean;
  totalOffenses: number;
}

export interface ShieldEvidence {
  speakerId: string;
  roomId: string;
  atMs: number;
  classification: Classification;
  confidence: number;
  reason: string;
  /** Redacted, truncated transcript excerpt. */
  excerpt: string;
  isTranscript: true;
  shieldVersion: string;
}

export interface ShieldDecision {
  speakerId: string;
  /** The action taken, scoped to the protected user only. */
  action: ShieldAction;
  /**
   * The set of speaker ids the client should currently drop from the LOCAL
   * mix. The client renders exactly this — it is the whole effect of the
   * shield. No other party is contacted.
   */
  locallyMutedSpeakerIds: string[];
  classification?: AbuseClassification;
  /** Plain-language note for the UI, in the user's favour. */
  message: string;
  /** Evidence to persist, when an offense was captured. */
  evidence?: ShieldEvidence;
  nextState: SpeakerState;
}

export interface ShieldInput {
  utterance: Utterance;
  state: SpeakerState | undefined;
  /** All speakers currently muted locally, so we can return the full set. */
  currentlyMuted: ReadonlyMap<string, number>;
  config: ShieldConfig;
  abuseConfig: AbuseConfig;
  nowMs: number;
  /** Optional pre-compiled lexicon (operator term lists included). */
  lexicon?: CompiledLexicon;
  /** Optional AI verdict. Advisory only, exactly as elsewhere. */
  bedrock?: BedrockVerdict;
  /** The user has explicitly blocked this speaker. Highest-priority mute. */
  userBlocked?: boolean;
}

/** Rank for choosing the strongest classification. */
const RANK: Record<Classification, number> = {
  SAFE: 0,
  UNCERTAIN: 1,
  ABUSIVE: 2,
  SEVERE_ABUSE: 3,
  THREAT: 4,
};

export function emptySpeakerState(speakerId: string): SpeakerState {
  return { speakerId, offenses: [], blockedLocally: false, totalOffenses: 0 };
}

/**
 * Process one received utterance and decide what the protected user's client
 * should do about THAT speaker, FOR THIS USER.
 */
export function applyShield(input: ShieldInput): ShieldDecision {
  const { utterance, config, abuseConfig, nowMs } = input;
  const lexicon = input.lexicon ?? buildLexicon(abuseConfig, '1.0.0');
  const state = cloneState(input.state ?? emptySpeakerState(utterance.speakerId));

  // A user-initiated block always wins and is permanent (until they undo it).
  if (input.userBlocked === true) {
    state.blockedLocally = true;
  }

  // Prune the offense window.
  state.offenses = state.offenses.filter((o) => nowMs - o.atMs <= config.offenseWindowMs);

  // Classify the transcript using the same layered classifier as the rest of
  // the system. Audio is only ever handled as a transcript here.
  const result = classifyAbuse({
    event: {
      eventId: `shield-${utterance.atMs}`,
      userId: utterance.speakerId,
      roomId: utterance.roomId,
      timestamp: new Date(utterance.atMs).toISOString(),
      receivedAtMs: utterance.atMs,
      eventType: 'voice',
      message: utterance.transcript,
      messageIsTranscript: true,
      platform: 'unknown',
      metadata: {},
    },
    config: abuseConfig,
    nowMs,
    lexicon,
    ...(input.bedrock ? { bedrock: input.bedrock } : {}),
  });

  const classification = result.classification;
  const isAbusive =
    classification.classification !== 'SAFE' && classification.classification !== 'UNCERTAIN';

  let evidence: ShieldEvidence | undefined;
  if (isAbusive) {
    state.offenses.push({ atMs: nowMs, classification: classification.classification });
    state.totalOffenses += 1;
    if (state.offenses.length > config.maxWindowPerSpeaker) {
      state.offenses = state.offenses.slice(-config.maxWindowPerSpeaker);
    }

    const { text, redacted } = redactIdentifiers(utterance.transcript);
    evidence = {
      speakerId: utterance.speakerId,
      roomId: utterance.roomId,
      atMs: nowMs,
      classification: classification.classification,
      confidence: classification.confidence,
      reason: classification.reason,
      excerpt: truncate(redacted ? text : text, config.evidenceExcerptChars),
      isTranscript: true,
      shieldVersion: SHIELD_VERSION,
    };
  }

  // --- Decide the local action -------------------------------------------
  const action = decideAction(state, classification, isAbusive, config, nowMs);

  if (action === 'LOCAL_MUTE') {
    state.mutedUntilMs = nowMs + config.localMuteDurationMs;
  } else if (action === 'LOCAL_BLOCK') {
    state.blockedLocally = true;
    delete state.mutedUntilMs;
  }

  // --- Build the full set of locally-muted speakers ----------------------
  const muted = new Map<string, number>(input.currentlyMuted);
  // Expire anyone whose local mute has elapsed.
  for (const [id, until] of muted) {
    if (until !== Number.POSITIVE_INFINITY && until <= nowMs) muted.delete(id);
  }
  if (state.blockedLocally) {
    muted.set(utterance.speakerId, Number.POSITIVE_INFINITY);
  } else if (state.mutedUntilMs !== undefined && state.mutedUntilMs > nowMs) {
    muted.set(utterance.speakerId, state.mutedUntilMs);
  } else {
    muted.delete(utterance.speakerId);
  }

  return {
    speakerId: utterance.speakerId,
    action,
    locallyMutedSpeakerIds: [...muted.keys()],
    ...(isAbusive ? { classification } : {}),
    message: messageFor(action, state, classification, config),
    ...(evidence ? { evidence } : {}),
    nextState: state,
  };
}

function decideAction(
  state: SpeakerState,
  classification: AbuseClassification,
  isAbusive: boolean,
  config: ShieldConfig,
  nowMs: number,
): ShieldAction {
  if (state.blockedLocally) return 'LOCAL_BLOCK';

  if (!isAbusive) {
    // Still within an active mute from a previous offense? Keep them muted.
    // Once the mute window has elapsed, a clean utterance returns NONE — the
    // speaker is given a fresh start rather than muted forever.
    const stillMuted = state.mutedUntilMs !== undefined && state.mutedUntilMs > nowMs;
    return stillMuted ? 'LOCAL_MUTE' : 'NONE';
  }

  const severe =
    RANK[classification.classification] >= RANK.SEVERE_ABUSE;

  // A credible threat or severe abuse silences them for you immediately.
  if (severe && config.muteImmediatelyOnSevere) {
    return 'LOCAL_MUTE';
  }

  // Low-confidence findings only flag, never auto-mute.
  if (classification.confidence < config.minMuteConfidence) {
    return 'FLAG';
  }

  // Repeat offenders within the window get locally muted.
  const recentOffenses = state.offenses.length;
  if (recentOffenses >= config.muteAfterOffenses) {
    return 'LOCAL_MUTE';
  }

  // First confident offense: soften them (your client can duck their volume)
  // and warn you, before a full mute on the next one.
  return 'LOCAL_SOFT_MUTE';
}

function messageFor(
  action: ShieldAction,
  state: SpeakerState,
  classification: AbuseClassification,
  config: ShieldConfig,
): string {
  const who = `speaker ${state.speakerId}`;
  switch (action) {
    case 'LOCAL_BLOCK':
      return `${who} is blocked for you. You will not hear them. They are unaffected for everyone else, and nothing was done to their device.`;
    case 'LOCAL_MUTE':
      return `${who} has been muted for you${
        state.mutedUntilMs !== undefined
          ? ` for ${Math.round(config.localMuteDurationMs / 60_000)} minutes`
          : ''
      }. Their voice will not reach you. This changes only your own audio.`;
    case 'LOCAL_SOFT_MUTE':
      return `${who} said something abusive (${classification.classification.toLowerCase()}). Their volume has been reduced for you; one more and they are muted for you.`;
    case 'FLAG':
      return `${who} may have been abusive, but confidence is low (${classification.confidence.toFixed(
        2,
      )}). Flagged for you to review; not muted.`;
    case 'NONE':
    default:
      return 'No abusive content detected in this utterance.';
  }
}

function cloneState(state: SpeakerState): SpeakerState {
  return {
    speakerId: state.speakerId,
    offenses: state.offenses.map((o) => ({ ...o })),
    blockedLocally: state.blockedLocally,
    totalOffenses: state.totalOffenses,
    ...(state.mutedUntilMs !== undefined ? { mutedUntilMs: state.mutedUntilMs } : {}),
  };
}

/**
 * The user can always lift a mute or block themselves — the shield works for
 * them, not against them.
 */
export function clearLocalMute(state: SpeakerState): SpeakerState {
  const next = cloneState(state);
  next.blockedLocally = false;
  delete next.mutedUntilMs;
  return next;
}

/** Fraction of recent abusive utterances, for a per-speaker risk read-out. */
export function speakerAbuseRatio(state: SpeakerState, totalUtterances: number): number {
  if (totalUtterances <= 0) return 0;
  return clamp(state.offenses.length / totalUtterances, 0, 1);
}
