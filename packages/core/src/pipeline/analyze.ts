/**
 * The analysis pipeline: one event in, a complete decision out.
 *
 * Pure function. All I/O (persistence, AI calls, platform calls) is performed by
 * the caller and passed in, which is what makes the whole decision path
 * deterministically testable.
 *
 * Order matters: content detectors run first so that the abuse verdict is
 * available to the response policy, then behavioural detectors, then risk, then
 * policy.
 */

import type { DetectionConfig } from '../config/detection-config.ts';
import { classifyAbuse, type AbuseInput, type BedrockVerdict } from '../detection/abuse/classifier.ts';
import type { CompiledLexicon } from '../detection/abuse/lexicon.ts';
import { assessClient } from '../detection/client.ts';
import { detectEvasion, type ModerationRestriction } from '../detection/evasion.ts';
import { appendToWindow, detectSpam, pruneWindow } from '../detection/spam.ts';
import { planResponse } from '../response/policy.ts';
import { assessRisk, carryForward } from '../risk/engine.ts';
import type { AbuseClassification, ClientRiskAssessment, DetectionSignal } from '../types/detection.ts';
import {
  MAX_ABUSIVE_FINGERPRINTS,
  type TalkinEvent,
  type UserWindowState,
  type WindowEntry,
} from '../types/events.ts';
import type { ResponsePlan, RiskAssessment } from '../types/risk.ts';
import type { IntegrationCapabilities } from '../types/telemetry.ts';
import { fingerprint } from '../util/text.ts';

export interface AnalyzeInput {
  event: TalkinEvent;
  state: UserWindowState;
  config: DetectionConfig;
  capabilities: IntegrationCapabilities;
  nowMs: number;
  /** Optional AI verdict for this event's text. Caller supplies or omits. */
  bedrock?: BedrockVerdict;
  /** Pre-compiled lexicon, cached per config version by the caller. */
  lexicon?: CompiledLexicon;
  /** Platform-reported restrictions in force for this account. */
  restrictions?: readonly ModerationRestriction[];
  /** Malformed-request count attributed to this account by the API layer. */
  malformedRequestCount?: number;
  /** Measured request rate for this account. */
  observedRequestsPerMinute?: number;
  /** Official client attestation result, when the capability exists. */
  attestation?: { verified: boolean; detail?: string };
  /** Fingerprints of this account's previously confirmed-abusive messages. */
  priorAbusiveFingerprints?: readonly string[];
}

export interface AnalyzeResult {
  event: TalkinEvent;
  signals: DetectionSignal[];
  abuse?: AbuseClassification;
  client: ClientRiskAssessment;
  assessment: RiskAssessment;
  plan: ResponsePlan;
  /** Updated per-user state, ready to persist. */
  nextState: UserWindowState;
  /** True when the message indicated risk to the sender themselves. */
  selfHarmConcern: boolean;
  /** Mitigating contexts applied by the abuse classifier. */
  mitigations: string[];
  /** Capability gaps that limited this analysis, for display in the UI. */
  telemetryNotes: string[];
}

export function analyzeEvent(input: AnalyzeInput): AnalyzeResult {
  const { event, config, capabilities, nowMs } = input;
  const signals: DetectionSignal[] = [];
  const telemetryNotes: string[] = [];

  const window = pruneWindow(input.state.recent, config.spam, nowMs);

  // --- Content analysis ---------------------------------------------------
  let abuse: AbuseClassification | undefined;
  let selfHarmConcern = false;
  let mitigations: string[] = [];

  const hasText = typeof event.message === 'string' && event.message.length > 0;

  if (hasText && capabilities.messageContent) {
    const abuseInput: AbuseInput = {
      event,
      config: config.abuse,
      nowMs,
      window,
    };
    if (input.lexicon) abuseInput.lexicon = input.lexicon;
    if (input.bedrock) abuseInput.bedrock = input.bedrock;
    // Prior abusive fingerprints come from persisted user state, so the
    // repetition layer works across events rather than only within one.
    const priorAbusive = input.priorAbusiveFingerprints ?? input.state.abusiveFingerprints;
    if (priorAbusive.length > 0) abuseInput.priorAbusiveFingerprints = priorAbusive;

    const result = classifyAbuse(abuseInput);
    abuse = result.classification;
    selfHarmConcern = result.selfHarmConcern;
    mitigations = result.mitigations;
    signals.push(...result.signals);
  } else if (hasText && !capabilities.messageContent) {
    telemetryNotes.push(
      'Message content analysis skipped: this deployment is not authorized to process message text.',
    );
  } else if (event.eventType === 'voice' && !capabilities.voiceAudio) {
    telemetryNotes.push(
      'Voice analysis skipped: no approved, consented audio integration is configured, so no transcript was available.',
    );
  }

  // --- Spam / automation --------------------------------------------------
  signals.push(...detectSpam({ event, window, config: config.spam, nowMs }));

  // --- Client integrity ---------------------------------------------------
  const clientInput = {
    event,
    window,
    config: config.client,
    nowMs,
    attestationAvailable: capabilities.clientAttestation,
    ...(input.malformedRequestCount !== undefined
      ? { malformedRequestCount: input.malformedRequestCount }
      : {}),
    ...(input.observedRequestsPerMinute !== undefined
      ? { observedRequestsPerMinute: input.observedRequestsPerMinute }
      : {}),
    ...(capabilities.clientAttestation && input.attestation ? { attestation: input.attestation } : {}),
  };
  const client = assessClient(clientInput);
  signals.push(...client.signals);
  if (client.insufficientTelemetry && client.note) telemetryNotes.push(client.note);
  if (!capabilities.clientAttestation) {
    telemetryNotes.push(
      'Client attestation unavailable: modified-client findings are behavioural indicators only, not proof.',
    );
  }

  // --- Evasion ------------------------------------------------------------
  const evasion = detectEvasion({
    event,
    window,
    config: config.evasion,
    nowMs,
    restrictions: input.restrictions ?? [],
    moderationEventsAvailable: capabilities.moderationEvents,
  });
  signals.push(...evasion.signals);
  if (evasion.insufficientTelemetry && evasion.note) telemetryNotes.push(evasion.note);

  // --- Risk ---------------------------------------------------------------
  const assessment = assessRisk({
    userId: event.userId,
    roomId: event.roomId,
    signals,
    config: config.risk,
    nowMs,
    priorViolations: input.state.priorViolations,
    evasionCount: input.state.evasionCount,
    carriedRisk: input.state.carriedRisk,
    ...(input.state.lastViolationAtMs !== undefined
      ? { lastAssessedAtMs: input.state.lastViolationAtMs }
      : {}),
    aiContributed: input.bedrock !== undefined,
  });

  // --- Response plan ------------------------------------------------------
  const plan = planResponse({
    assessment,
    config,
    capabilities,
    ...(abuse ? { abuseClassification: abuse.classification } : {}),
    ...(abuse ? { requiresHumanReview: abuse.requiresHumanReview } : {}),
  });

  // --- Next state ---------------------------------------------------------
  const violationOccurred =
    assessment.level === 'HIGH' ||
    assessment.level === 'CRITICAL' ||
    abuse?.classification === 'SEVERE_ABUSE' ||
    abuse?.classification === 'THREAT';

  const newEvasion = evasion.signals.length > 0 ? 1 : 0;

  // Record this message's fingerprint when it was found abusive, so the
  // repetition layer can see it on the next pass. Bounded, and fingerprints
  // only — the message text itself is never carried in state.
  const abusiveNow =
    abuse !== undefined &&
    (abuse.classification === 'ABUSIVE' ||
      abuse.classification === 'SEVERE_ABUSE' ||
      abuse.classification === 'THREAT');

  const abusiveFingerprints = abusiveNow && event.message !== undefined
    ? [...input.state.abusiveFingerprints, fingerprint(event.message)].slice(-MAX_ABUSIVE_FINGERPRINTS)
    : input.state.abusiveFingerprints;

  const nextState: UserWindowState = {
    userId: event.userId,
    recent: appendToWindow(window, event, config.spam),
    abusiveFingerprints,
    // Only confirmed-high findings increment the durable violation counter,
    // and only once per analysis pass.
    priorViolations: input.state.priorViolations + (violationOccurred ? 1 : 0),
    evasionCount: input.state.evasionCount + newEvasion,
    carriedRisk: carryForward(assessment),
    ...(violationOccurred
      ? { lastViolationAtMs: nowMs }
      : input.state.lastViolationAtMs !== undefined
        ? { lastViolationAtMs: input.state.lastViolationAtMs }
        : {}),
  };

  return {
    event,
    signals,
    ...(abuse ? { abuse } : {}),
    client,
    assessment,
    plan,
    nextState,
    selfHarmConcern,
    mitigations,
    telemetryNotes: [...new Set(telemetryNotes)],
  };
}

/** Initial state for an account we have not seen before. */
export function emptyState(userId: string): UserWindowState {
  return {
    userId,
    recent: [],
    abusiveFingerprints: [],
    priorViolations: 0,
    evasionCount: 0,
    carriedRisk: 0,
  };
}

/** Fingerprints of messages in a window, used for the abuse-repetition layer. */
export function fingerprintsOf(window: readonly WindowEntry[]): string[] {
  return window.map((e) => e.fingerprint).filter((f): f is string => typeof f === 'string');
}

export { fingerprint };
