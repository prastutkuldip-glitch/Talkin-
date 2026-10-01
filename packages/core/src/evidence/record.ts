/**
 * Evidence bundle construction and integrity verification.
 *
 * Integrity model (defence in depth):
 *
 *   1. Content hash — SHA-256 over a canonical (sorted-key) JSON encoding of
 *      the bundle body. Any mutation changes the hash.
 *   2. Hash chain — each bundle records the content hash of the previous
 *      bundle for the same tenant. Removing or reordering a bundle breaks the
 *      chain, so deletion is detectable, not just modification.
 *   3. Storage controls (infrastructure layer) — S3 Object Lock in compliance
 *      mode, SSE-KMS, versioning, and an IAM policy that grants no
 *      `s3:DeleteObject` to the application role. The application can write
 *      evidence and read it back; it cannot rewrite history.
 *
 * Privacy: bundle bodies are built with data minimization in mind. Message text
 * is truncated and run through identifier redaction, and the bundle explicitly
 * records which fields were unavailable rather than silently omitting them.
 */

import type { DetectionSignal } from '../types/detection.ts';
import type {
  ActionRecord,
  Incident,
  MessageExcerpt,
  RiskAssessment,
} from '../types/risk.ts';
import type { IntegrationCapabilities } from '../types/telemetry.ts';
import { canonicalJson, sha256Hex } from '../util/ids.ts';
import { redactIdentifiers, truncate } from '../util/text.ts';

export const EVIDENCE_SCHEMA_VERSION = 'talkinshield-evidence/1.1.0';

/** The hashed portion of an evidence bundle. Never mutated after creation. */
export interface EvidenceBody {
  schemaVersion: string;
  incidentId: string;
  userId: string;
  roomId?: string;
  /** ISO-8601 of bundle creation. */
  createdAt: string;
  createdAtMs: number;
  detectedBehaviors: string[];
  detectionReasons: string[];
  riskScore: number;
  riskLevel: string;
  confidence: number;
  /** Engine and model versions consulted for this decision. */
  modelVersions: string[];
  relevantMessages: MessageExcerpt[];
  authorizedMetadata: Record<string, string | number | boolean>;
  actionsTaken: ActionRecord[];
  signals: EvidenceSignal[];
  /** Explicit record of what we were and were not authorized to collect. */
  authorization: AuthorizationStatement;
}

export interface EvidenceSignal {
  code: string;
  category: string;
  severity: string;
  confidence: number;
  reason: string;
  detector: string;
  observedAt: string;
  evidenceEventIds: string[];
}

/**
 * The honesty record. Stored inside the hashed body so a reviewer can always
 * see the boundary that applied when the evidence was captured.
 */
export interface AuthorizationStatement {
  capabilities: IntegrationCapabilities;
  /** Fields the operator was authorized to collect and did collect. */
  collected: string[];
  /** Fields deliberately not collected, with the reason. */
  notCollected: Array<{ field: string; reason: string }>;
  /** Free-text note shown verbatim in the Evidence UI. */
  note: string;
}

export interface EvidenceBundle {
  /** S3 object key. */
  key: string;
  body: EvidenceBody;
  /** SHA-256 of `canonicalJson(body)`. */
  contentHash: string;
  /** Content hash of the previous bundle, or the genesis constant. */
  previousHash: string;
  /** SHA-256 over `previousHash + contentHash` — the chain link. */
  chainHash: string;
  /** Sequence number within the chain, starting at 1. */
  sequence: number;
}

export const GENESIS_HASH = '0'.repeat(64);

export interface BuildEvidenceInput {
  incident: Incident;
  assessment: RiskAssessment;
  signals: readonly DetectionSignal[];
  capabilities: IntegrationCapabilities;
  /** Raw message events, already authorized for collection. */
  messages: ReadonlyArray<{
    eventId: string;
    atMs: number;
    text?: string;
    isTranscript?: boolean;
  }>;
  excerptMaxChars: number;
  nowMs: number;
  /** Previous bundle in the chain, if any. */
  previous?: { contentHash: string; sequence: number };
}

export function buildEvidenceBundle(input: BuildEvidenceInput): EvidenceBundle {
  const { incident, assessment, capabilities, nowMs } = input;

  const relevantMessages: MessageExcerpt[] = capabilities.messageContent
    ? input.messages.map((m) => {
        const raw = m.text ?? '';
        const { text, redacted } = redactIdentifiers(raw);
        return {
          eventId: m.eventId,
          atMs: m.atMs,
          text: truncate(text, input.excerptMaxChars),
          isTranscript: m.isTranscript === true,
          redacted,
        };
      })
    : [];

  const collected: string[] = ['userId', 'roomId', 'timestamps', 'eventTypes', 'riskAssessment'];
  const notCollected: Array<{ field: string; reason: string }> = [];

  if (capabilities.messageContent) collected.push('messageText(redacted,truncated)');
  else
    notCollected.push({
      field: 'messageText',
      reason: 'This deployment is not authorized to process message content.',
    });

  if (capabilities.voiceAudio) collected.push('voiceTranscript');
  else
    notCollected.push({
      field: 'voiceAudio/voiceTranscript',
      reason:
        'No approved, consented audio integration is configured. No call audio was received or processed.',
    });

  if (capabilities.clientAttestation) collected.push('clientAttestation');
  else
    notCollected.push({
      field: 'clientAttestation',
      reason: 'The platform integration does not provide signed client attestation.',
    });

  if (capabilities.hiddenPresenceEvents) collected.push('hiddenPresenceEvents');
  else
    notCollected.push({
      field: 'hiddenPresenceEvents',
      reason: 'The platform integration does not expose hidden/ghost-mode presence events.',
    });

  // Categories TalkinShield never collects, stated explicitly so a reviewer can
  // confirm the boundary held.
  notCollected.push(
    {
      field: 'deviceLocation',
      reason: 'Out of scope by design. TalkinShield never collects location data.',
    },
    {
      field: 'deviceIdentifiers',
      reason: 'Out of scope by design. No device fingerprinting is performed.',
    },
    {
      field: 'credentials/tokens',
      reason: 'Out of scope by design. Never collected; redacted if encountered.',
    },
    {
      field: 'networkTraffic',
      reason:
        'Out of scope by design. TalkinShield observes only application events delivered to it.',
    },
  );

  const body: EvidenceBody = {
    schemaVersion: EVIDENCE_SCHEMA_VERSION,
    incidentId: incident.incidentId,
    userId: incident.userId,
    ...(incident.roomId !== undefined ? { roomId: incident.roomId } : {}),
    createdAt: new Date(nowMs).toISOString(),
    createdAtMs: nowMs,
    detectedBehaviors: [...incident.detectedBehaviors],
    detectionReasons: [...incident.detectionReasons],
    riskScore: assessment.score,
    riskLevel: assessment.level,
    confidence: assessment.peakConfidence,
    modelVersions: [...incident.modelVersions],
    relevantMessages,
    authorizedMetadata: { ...incident.authorizedMetadata },
    actionsTaken: [...incident.actionsTaken],
    signals: input.signals.map((s) => ({
      code: s.code,
      category: s.category,
      severity: s.severity,
      confidence: s.confidence,
      reason: s.reason,
      detector: s.detector,
      observedAt: new Date(s.observedAtMs).toISOString(),
      evidenceEventIds: [...s.evidenceEventIds],
    })),
    authorization: {
      capabilities: { ...capabilities },
      collected,
      notCollected,
      note:
        'This bundle records only data the operator was authorized to receive through the configured Talkin integration. ' +
        'Fields listed under notCollected were not gathered — their absence is a boundary, not a gap in the record.',
    },
  };

  const contentHash = sha256Hex(canonicalJson(body));
  const previousHash = input.previous?.contentHash ?? GENESIS_HASH;
  const sequence = (input.previous?.sequence ?? 0) + 1;
  const chainHash = sha256Hex(`${previousHash}${contentHash}`);

  return {
    key: evidenceKey(incident.userId, incident.incidentId, nowMs, sequence),
    body,
    contentHash,
    previousHash,
    chainHash,
    sequence,
  };
}

/**
 * Date-partitioned, non-guessable object key.
 * Partitioning keeps S3 listing and lifecycle rules efficient.
 */
export function evidenceKey(
  userId: string,
  incidentId: string,
  nowMs: number,
  sequence: number,
): string {
  const d = new Date(nowMs);
  const yyyy = d.getUTCFullYear();
  const mm = String(d.getUTCMonth() + 1).padStart(2, '0');
  const dd = String(d.getUTCDate()).padStart(2, '0');
  const userShard = sha256Hex(userId).slice(0, 4);
  return `evidence/${yyyy}/${mm}/${dd}/${userShard}/${incidentId}/${String(sequence).padStart(4, '0')}.json`;
}

export interface VerificationResult {
  valid: boolean
  problems: string[];
}

/** Recompute the content hash of a single bundle. */
export function verifyBundle(bundle: EvidenceBundle): VerificationResult {
  const problems: string[] = [];

  const recomputed = sha256Hex(canonicalJson(bundle.body));
  if (recomputed !== bundle.contentHash) {
    problems.push(
      `Content hash mismatch: bundle declares ${bundle.contentHash.slice(0, 16)}… but its body hashes to ${recomputed.slice(0, 16)}…. The bundle has been modified since it was written.`,
    );
  }

  const recomputedChain = sha256Hex(`${bundle.previousHash}${bundle.contentHash}`);
  if (recomputedChain !== bundle.chainHash) {
    problems.push('Chain hash does not match previousHash + contentHash.');
  }

  if (bundle.body.schemaVersion !== EVIDENCE_SCHEMA_VERSION) {
    problems.push(
      `Bundle was written by schema ${bundle.body.schemaVersion}; current schema is ${EVIDENCE_SCHEMA_VERSION}. Verify with the matching schema version.`,
    );
  }

  return { valid: problems.length === 0, problems };
}

/**
 * Verify a whole chain in sequence order. Detects modification, reordering and
 * deletion — a missing bundle breaks the `previousHash` linkage of its
 * successor.
 */
export function verifyChain(bundles: readonly EvidenceBundle[]): VerificationResult {
  const problems: string[] = [];
  const ordered = [...bundles].sort((a, b) => a.sequence - b.sequence);

  let expectedPrevious = GENESIS_HASH;
  let expectedSequence = 1;

  for (const bundle of ordered) {
    const single = verifyBundle(bundle);
    if (!single.valid) {
      problems.push(`Bundle ${bundle.key}: ${single.problems.join(' ')}`);
    }

    if (bundle.sequence !== expectedSequence) {
      problems.push(
        `Sequence gap: expected ${expectedSequence} but found ${bundle.sequence} (${bundle.key}). A bundle is missing or has been removed.`,
      );
      expectedSequence = bundle.sequence;
    }

    if (bundle.previousHash !== expectedPrevious) {
      problems.push(
        `Broken chain at sequence ${bundle.sequence} (${bundle.key}): previousHash ${bundle.previousHash.slice(0, 16)}… does not match the preceding bundle's content hash ${expectedPrevious.slice(0, 16)}….`,
      );
    }

    expectedPrevious = bundle.contentHash;
    expectedSequence += 1;
  }

  return { valid: problems.length === 0, problems };
}
