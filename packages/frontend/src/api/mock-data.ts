/**
 * Local fixtures for the console, used when VITE_USE_MOCK_API=true.
 *
 * Mirrors the shape of the real API, including the capability gaps, so the UI's
 * "insufficient authorized telemetry" and local-only action paths can be
 * exercised without a backend. All data is synthetic.
 */

import type {
  AffordanceResponse,
  AuditRow,
  ActionRow,
  EventRow,
  EvidenceBundleView,
  Incident,
  Me,
  ModerationResult,
  Overview,
  RulesResponse,
  SettingsResponse,
  SignalRow,
  UnavailableField,
  UserDetail,
  UserSummary,
  VerificationResult,
} from './types.ts';

const NOW = Date.now();
const ago = (ms: number): number => NOW - ms;

/**
 * The mock deployment grants message content and moderation events, but NOT
 * voice, hidden presence, attestation, or any platform moderation API — the
 * most common real-world configuration, and the one that exercises the
 * degraded-capability UI.
 */
const CAPABILITIES = {
  messageContent: true,
  moderationEvents: true,
  voiceAudio: false,
  hiddenPresenceEvents: false,
  clientAttestation: false,
  remoteMute: false,
  remoteBlock: false,
};

const UNAVAILABLE: UnavailableField[] = [
  {
    field: 'Voice audio / transcripts',
    status: 'UNAVAILABLE',
    reason: 'No approved, consented audio integration is configured.',
  },
  {
    field: 'Hidden / ghost-mode presence',
    status: 'UNAVAILABLE',
    reason:
      'The platform integration does not expose hidden presence events. Insufficient authorized telemetry.',
  },
  {
    field: 'Client attestation',
    status: 'UNAVAILABLE',
    reason: 'The platform provides no signed official-build proof.',
  },
  {
    field: 'Official mute API',
    status: 'UNAVAILABLE',
    reason: 'MUTE applies locally to the protected user only.',
  },
  {
    field: 'Official block API',
    status: 'UNAVAILABLE',
    reason: 'BLOCK applies locally to the protected user only.',
  },
  { field: 'Location / GPS', status: 'OUT_OF_SCOPE', reason: 'TalkinShield never collects location data.' },
  {
    field: 'Device identifiers & files',
    status: 'OUT_OF_SCOPE',
    reason: 'No device fingerprinting or filesystem access is performed.',
  },
  {
    field: 'Credentials & tokens',
    status: 'OUT_OF_SCOPE',
    reason: 'Never collected; redacted if encountered in content.',
  },
  {
    field: 'Camera / microphone control',
    status: 'OUT_OF_SCOPE',
    reason: 'TalkinShield cannot and does not control any participant device.',
  },
  {
    field: 'Network traffic',
    status: 'OUT_OF_SCOPE',
    reason: 'Only application events delivered to the API are observed.',
  },
];

const SIGNALS: SignalRow[] = [
  {
    code: 'SPAM_IDENTICAL_REPEAT',
    category: 'SPAM',
    severity: 'SEVERE',
    confidence: 0.95,
    reason: 'The same message content was sent 50 times (threshold 4, severe at 15).',
    detector: 'spam-detector@1.2.0',
    observedAtMs: ago(120_000),
    evidenceEventIds: ['evt-1', 'evt-2', 'evt-3'],
    userId: '8F29A1',
    details: { repeatCount: 50, threshold: 4 },
  },
  {
    code: 'ABUSE_REPEATED',
    category: 'ABUSE',
    severity: 'HIGH',
    confidence: 0.8,
    reason: 'Abusive content repeated across multiple messages within the configured repeat window.',
    detector: 'abuse-classifier@1.3.0',
    observedAtMs: ago(118_000),
    evidenceEventIds: ['evt-2'],
    userId: '8F29A1',
  },
  {
    code: 'BOT_UNIFORM_TIMING',
    category: 'FREQUENCY',
    severity: 'HIGH',
    confidence: 0.91,
    reason:
      'Message timing is machine-like: 20 messages at a mean interval of 1000ms with only 2.1% variation (human conversation typically exceeds 18%).',
    detector: 'spam-detector@1.2.0',
    observedAtMs: ago(115_000),
    evidenceEventIds: ['evt-1', 'evt-2'],
    userId: '8F29A1',
    details: { meanIntervalMs: 1000, coefficientOfVariation: 0.021 },
  },
  {
    code: 'CLIENT_UNKNOWN_VERSION',
    category: 'CLIENT',
    severity: 'MEDIUM',
    confidence: 0.75,
    reason:
      'Declared client version "custom-build-9" does not match the expected official version format.',
    detector: 'client-integrity@1.1.0',
    observedAtMs: ago(112_000),
    evidenceEventIds: ['evt-3'],
    userId: '8F29A1',
    details: { declaredVersion: 'custom-build-9' },
  },
  {
    code: 'THREAT_LANGUAGE',
    category: 'THREAT',
    severity: 'SEVERE',
    confidence: 0.9,
    reason:
      'Threat pattern matched (1 construction): actor, intent verb and target all present.',
    detector: 'abuse-classifier@1.3.0',
    observedAtMs: ago(300_000),
    evidenceEventIds: ['evt-9'],
    userId: 'C41B77',
  },
  {
    code: 'EVASION_REJOIN_CYCLING',
    category: 'EVASION',
    severity: 'MEDIUM',
    confidence: 0.78,
    reason:
      '6 leave/rejoin cycles in room XY7788 within 5 minutes — a pattern used to reset room-scoped moderation state.',
    detector: 'evasion-detector@1.0.0',
    observedAtMs: ago(420_000),
    evidenceEventIds: ['evt-20'],
    userId: 'D77E02',
  },
  {
    code: 'COORDINATED_IDENTICAL_CONTENT',
    category: 'COORDINATION',
    severity: 'HIGH',
    confidence: 0.85,
    reason:
      '6 separate accounts posted byte-identical content in room ABC123 within the detection window. Reported as correlated behaviour only — no inference is made that these accounts share an operator.',
    detector: 'coordination-detector@1.0.0',
    observedAtMs: ago(600_000),
    evidenceEventIds: [],
    userId: 'E12F44',
    details: { accountCount: 6, roomId: 'ABC123' },
  },
];

const INCIDENTS: Incident[] = [
  {
    incidentId: 'INC-20260301-A1B2C3D4',
    userId: '8F29A1',
    roomId: 'ABC123',
    createdAtMs: ago(130_000),
    updatedAtMs: ago(110_000),
    status: 'OPEN',
    riskScore: 91,
    riskLevel: 'CRITICAL',
    detectedBehaviors: [
      'SPAM_IDENTICAL_REPEAT',
      'ABUSE_REPEATED',
      'BOT_UNIFORM_TIMING',
      'CLIENT_UNKNOWN_VERSION',
    ],
    detectionReasons: SIGNALS.slice(0, 4).map((s) => `[${s.code}] ${s.reason}`),
    relevantMessages: [
      {
        eventId: 'evt-1',
        atMs: ago(125_000),
        text: 'FREE CRYPTO GIVEAWAY CLICK THE LINK IN MY BIO NOW',
        isTranscript: false,
        redacted: false,
      },
      {
        eventId: 'evt-2',
        atMs: ago(124_000),
        text: 'you are a fucking idiot if you miss this',
        isTranscript: false,
        redacted: false,
      },
      {
        eventId: 'evt-3',
        atMs: ago(123_000),
        text: 'contact me at [redacted-email] for details',
        isTranscript: false,
        redacted: true,
      },
    ],
    authorizedMetadata: {
      riskLevel: 'CRITICAL',
      riskScore: 91,
      peakConfidence: 0.95,
      deterministicOnly: true,
      signalCount: 4,
      platformActionUnavailable: true,
      platform: 'android',
      eventType: 'message',
      declaredClientVersion: 'custom-build-9',
      'meta.region': 'eu-west-1',
    },
    actionsTaken: [
      {
        actionId: 'ACT-1',
        actionType: 'INCIDENT_CREATED',
        actorKind: 'SYSTEM',
        actorId: 'system',
        targetUserId: '8F29A1',
        roomId: 'ABC123',
        atMs: ago(130_000),
        reason:
          'Risk 91/100 (CRITICAL). Principal contributors: SPAM_IDENTICAL_REPEAT (+20), BOT_UNIFORM_TIMING (+20), ABUSE_REPEATED (+25). A temporary platform restriction is warranted, but the connected Talkin integration grants no official block API.',
        scope: 'INTERNAL',
        succeeded: true,
        incidentId: 'INC-20260301-A1B2C3D4',
        riskScoreAtAction: 91,
      },
      {
        actionId: 'ACT-2',
        actionType: 'EVIDENCE_SAVED',
        actorKind: 'SYSTEM',
        actorId: 'system',
        targetUserId: '8F29A1',
        atMs: ago(130_000),
        reason: 'Evidence preserved automatically for CRITICAL risk incident.',
        scope: 'INTERNAL',
        succeeded: true,
        incidentId: 'INC-20260301-A1B2C3D4',
      },
    ],
    confidence: 0.97,
    modelVersions: [
      'risk-engine@1.1.0',
      'spam-detector@1.2.0',
      'abuse-classifier@1.3.0',
      'client-integrity@1.1.0',
    ],
    evidenceKeys: ['evidence/2026/03/01/a1b2/INC-20260301-A1B2C3D4/0001.json'],
  },
  {
    incidentId: 'INC-20260301-E5F6A7B8',
    userId: 'C41B77',
    roomId: 'XY7788',
    createdAtMs: ago(305_000),
    updatedAtMs: ago(290_000),
    status: 'ACKNOWLEDGED',
    riskScore: 78,
    riskLevel: 'CRITICAL',
    detectedBehaviors: ['THREAT_LANGUAGE'],
    detectionReasons: [`[THREAT_LANGUAGE] ${SIGNALS[4]?.reason ?? ''}`],
    relevantMessages: [
      {
        eventId: 'evt-9',
        atMs: ago(300_000),
        text: 'i am going to kill you when i find you',
        isTranscript: false,
        redacted: false,
      },
    ],
    authorizedMetadata: { riskLevel: 'CRITICAL', riskScore: 78, platform: 'ios', deterministicOnly: true },
    actionsTaken: [],
    confidence: 0.9,
    modelVersions: ['risk-engine@1.1.0', 'abuse-classifier@1.3.0'],
    evidenceKeys: ['evidence/2026/03/01/c41b/INC-20260301-E5F6A7B8/0002.json'],
  },
  {
    incidentId: 'INC-20260301-99AA88BB',
    userId: 'D77E02',
    roomId: 'XY7788',
    createdAtMs: ago(430_000),
    updatedAtMs: ago(420_000),
    status: 'DISMISSED_FALSE_POSITIVE',
    riskScore: 52,
    riskLevel: 'HIGH',
    detectedBehaviors: ['EVASION_REJOIN_CYCLING'],
    detectionReasons: [`[EVASION_REJOIN_CYCLING] ${SIGNALS[5]?.reason ?? ''}`],
    relevantMessages: [],
    authorizedMetadata: { riskLevel: 'HIGH', riskScore: 52 },
    actionsTaken: [],
    confidence: 0.78,
    modelVersions: ['risk-engine@1.1.0', 'evasion-detector@1.0.0'],
    evidenceKeys: [],
    reviewNote: 'User had an unstable mobile connection; the rejoin pattern was network churn, not evasion.',
    reviewedBy: 'mod-1',
  },
];

const USERS: UserSummary[] = [
  { userId: '8F29A1', handle: '8F29A1', riskScore: 91, riskLevel: 'CRITICAL', lastSeenAtMs: ago(110_000), roomId: 'ABC123', openIncidents: 1 },
  { userId: 'C41B77', handle: 'C41B77', riskScore: 78, riskLevel: 'CRITICAL', lastSeenAtMs: ago(290_000), roomId: 'XY7788', openIncidents: 0 },
  { userId: 'E12F44', handle: 'E12F44', riskScore: 61, riskLevel: 'HIGH', lastSeenAtMs: ago(600_000), roomId: 'ABC123', openIncidents: 0 },
  { userId: 'D77E02', handle: 'D77E02', riskScore: 52, riskLevel: 'HIGH', lastSeenAtMs: ago(420_000), roomId: 'XY7788', openIncidents: 0 },
  { userId: 'B20C19', handle: 'B20C19', riskScore: 33, riskLevel: 'MEDIUM', lastSeenAtMs: ago(700_000), roomId: 'ABC123', openIncidents: 0 },
  { userId: 'A01D55', handle: 'A01D55', riskScore: 12, riskLevel: 'LOW', lastSeenAtMs: ago(900_000), roomId: 'QQ1234', openIncidents: 0 },
];

const EVENTS: EventRow[] = Array.from({ length: 40 }, (_, i) => {
  const user = USERS[i % USERS.length] as UserSummary;
  const abusive = i % 7 === 0;
  return {
    eventId: `evt-${i + 1}`,
    userId: user.userId,
    roomId: user.roomId ?? 'ABC123',
    timestamp: new Date(ago(i * 9000)).toISOString(),
    receivedAtMs: ago(i * 9000),
    eventType: i % 11 === 0 ? 'join' : 'message',
    message: abusive
      ? 'FREE CRYPTO GIVEAWAY CLICK THE LINK IN MY BIO NOW'
      : `ordinary chat message number ${i + 1}`,
    clientVersion: i % 5 === 0 ? 'custom-build-9' : '4.2.1',
    platform: (['ios', 'android', 'web', 'desktop'] as const)[i % 4] as string,
    metadata: { region: 'eu-west-1' },
  };
});

const ACTIONS: ActionRow[] = [
  {
    actionId: 'ACT-10',
    actionType: 'LOCAL_MUTE',
    actorKind: 'MODERATOR',
    actorId: 'mod-1',
    targetUserId: '8F29A1',
    roomId: 'ABC123',
    atMs: ago(90_000),
    reason:
      'Repeated identical spam with targeted abuse (actioned by alice) — applied locally because no official platform mute API is available.',
    scope: 'LOCAL_TO_REQUESTER',
    succeeded: true,
    incidentId: 'INC-20260301-A1B2C3D4',
  },
  {
    actionId: 'ACT-11',
    actionType: 'REPORT_SUBMITTED',
    actorKind: 'MODERATOR',
    actorId: 'mod-1',
    targetUserId: 'C41B77',
    roomId: 'XY7788',
    atMs: ago(280_000),
    reason: 'Credible threat of violence against a participant (actioned by alice)',
    scope: 'PLATFORM_API',
    succeeded: true,
    incidentId: 'INC-20260301-E5F6A7B8',
  },
  {
    actionId: 'ACT-12',
    actionType: 'MONITORING_INCREASED',
    actorKind: 'SYSTEM',
    actorId: 'system',
    targetUserId: 'B20C19',
    roomId: 'ABC123',
    atMs: ago(700_000),
    reason: 'Risk level MEDIUM: monitoring increased. Risk 33/100 (MEDIUM).',
    scope: 'INTERNAL',
    succeeded: true,
    riskScoreAtAction: 33,
  },
];

const AUDIT: AuditRow[] = [
  {
    auditId: 'AUD-1',
    atMs: ago(60_000),
    actorId: 'mod-1',
    actorKind: 'MODERATOR',
    action: 'MODERATION_MUTE',
    target: '8F29A1',
    reason: 'Repeated identical spam with targeted abuse',
    outcome: 'SUCCESS',
    detail: { scope: 'LOCAL_TO_REQUESTER', platformActionUnavailable: true, moderator: 'alice' },
  },
  {
    auditId: 'AUD-2',
    atMs: ago(130_000),
    actorId: 'system',
    actorKind: 'SYSTEM',
    action: 'INCIDENT_CREATED',
    target: 'INC-20260301-A1B2C3D4',
    reason: 'Risk 91/100 (CRITICAL).',
    outcome: 'SUCCESS',
    detail: { userId: '8F29A1', riskScore: 91, riskLevel: 'CRITICAL', signalCount: 4 },
  },
  {
    auditId: 'AUD-3',
    atMs: ago(200_000),
    actorId: 'view-1',
    actorKind: 'MODERATOR',
    action: 'AUTHZ_DENIED',
    target: 'PUT /rules',
    reason: 'This action requires the "rules:write" permission, which your role does not grant.',
    outcome: 'DENIED',
    detail: { requiredPermission: 'rules:write', roles: 'VIEWER' },
    sourceIp: '198.51.100.24',
  },
  {
    auditId: 'AUD-4',
    atMs: ago(240_000),
    actorId: 'mod-1',
    actorKind: 'MODERATOR',
    action: 'EVIDENCE_ACCESSED',
    target: 'evidence/2026/03/01/a1b2/INC-20260301-A1B2C3D4/0001.json',
    reason: 'Moderator opened an evidence bundle for review.',
    outcome: 'SUCCESS',
    detail: { integrityValid: true },
  },
  {
    auditId: 'AUD-5',
    atMs: ago(420_000),
    actorId: 'mod-1',
    actorKind: 'MODERATOR',
    action: 'INCIDENT_STATUS_CHANGED',
    target: 'INC-20260301-99AA88BB',
    reason: 'User had an unstable mobile connection; the rejoin pattern was network churn, not evasion.',
    outcome: 'SUCCESS',
    detail: { newStatus: 'DISMISSED_FALSE_POSITIVE', moderator: 'alice' },
  },
  {
    auditId: 'AUD-6',
    atMs: ago(900_000),
    actorId: 'admin-1',
    actorKind: 'MODERATOR',
    action: 'DETECTION_RULES_UPDATED',
    target: 'detection-config',
    reason: 'Raised the burst threshold after false positives in a quiz room.',
    outcome: 'SUCCESS',
    detail: { version: 'v1772000000000', keys: 'spam' },
  },
];

const RISK_WEIGHTS: Record<string, number> = {
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
};

let mutableOverrides: Record<string, unknown> = {};
const mutableIncidents = INCIDENTS.map((i) => ({ ...i }));

const delay = <T,>(value: T): Promise<T> =>
  new Promise((resolve) => setTimeout(() => resolve(value), 120));

export const me = (): Promise<Me> =>
  delay({
    subject: 'mod-1',
    username: 'alice (mock)',
    roles: ['MODERATOR', 'VIEWER'],
    groups: ['moderators'],
    mfaPresent: true,
    permissions: [
      'events:read',
      'users:read',
      'incidents:read',
      'incidents:write',
      'evidence:read',
      'evidence:write',
      'moderation:local',
      'moderation:platform',
      'rules:read',
      'logs:read',
      'settings:read',
    ],
    mfaRequiredForDestructive: false,
  });

export const overview = (): Promise<Overview> =>
  delay({
    generatedAtMs: NOW,
    activeIncidents: mutableIncidents.filter((i) => i.status === 'OPEN').length,
    highRiskUsers: USERS.filter((u) => u.riskLevel === 'HIGH' || u.riskLevel === 'CRITICAL').length,
    spamEvents: SIGNALS.filter((s) => ['SPAM', 'FREQUENCY', 'COORDINATION'].includes(s.category)).length,
    abuseEvents: SIGNALS.filter((s) => ['ABUSE', 'THREAT'].includes(s.category)).length,
    blockedEvents: ACTIONS.filter((a) => a.actionType.includes('BLOCK') && a.succeeded).length,
    recentIncidents: mutableIncidents.map((i) => ({
      incidentId: i.incidentId,
      userId: i.userId,
      ...(i.roomId !== undefined ? { roomId: i.roomId } : {}),
      riskScore: i.riskScore,
      riskLevel: i.riskLevel,
      status: i.status,
      createdAtMs: i.createdAtMs,
      topBehaviors: i.detectedBehaviors.slice(0, 4),
    })),
    riskDistribution: [
      { level: 'LOW', range: '0-24', count: USERS.filter((u) => u.riskLevel === 'LOW').length },
      { level: 'MEDIUM', range: '25-49', count: USERS.filter((u) => u.riskLevel === 'MEDIUM').length },
      { level: 'HIGH', range: '50-74', count: USERS.filter((u) => u.riskLevel === 'HIGH').length },
      { level: 'CRITICAL', range: '75-100', count: USERS.filter((u) => u.riskLevel === 'CRITICAL').length },
    ],
    topSignals: SIGNALS.map((s) => ({ code: s.code, count: 1 + (s.code.length % 5) })).sort(
      (a, b) => b.count - a.count,
    ),
  });

export const events = (query: { userId?: string; roomId?: string }): Promise<{ events: EventRow[]; count: number }> => {
  const filtered = EVENTS.filter(
    (e) =>
      (query.userId === undefined || e.userId === query.userId) &&
      (query.roomId === undefined || e.roomId === query.roomId),
  );
  return delay({ events: filtered, count: filtered.length });
};

export const signals = (): Promise<{ signals: SignalRow[]; count: number }> =>
  delay({ signals: SIGNALS, count: SIGNALS.length });

export const users = (): Promise<{ users: UserSummary[]; count: number }> =>
  delay({ users: USERS, count: USERS.length });

export const user = (userId: string): Promise<UserDetail> => {
  const summary = USERS.find((u) => u.userId === userId) ?? (USERS[0] as UserSummary);
  const userSignals = SIGNALS.filter((s) => s.userId === summary.userId);
  const userEvents = EVENTS.filter((e) => e.userId === summary.userId);

  return delay({
    userId: summary.userId,
    handle: summary.handle,
    ...(summary.roomId !== undefined ? { roomId: summary.roomId } : {}),
    riskScore: summary.riskScore,
    riskLevel: summary.riskLevel,
    riskRange:
      summary.riskLevel === 'CRITICAL'
        ? '75-100'
        : summary.riskLevel === 'HIGH'
          ? '50-74'
          : summary.riskLevel === 'MEDIUM'
            ? '25-49'
            : '0-24',
    contributions: userSignals.map((s) => ({
      code: s.code,
      weight: RISK_WEIGHTS[s.code] ?? 10,
      applied: RISK_WEIGHTS[s.code] ?? 10,
      confidence: s.confidence,
      reason: s.reason,
    })),
    messageFrequency: { windowSeconds: 30, count: 18, perMinute: 36 },
    abuseDetections: userSignals.filter((s) => s.category === 'ABUSE' || s.category === 'THREAT'),
    recentEvents: userEvents.slice(0, 15),
    moderationHistory: ACTIONS.filter((a) => a.targetUserId === summary.userId),
    openIncidents: summary.openIncidents,
    priorViolations: summary.riskLevel === 'CRITICAL' ? 2 : 0,
    evasionCount: summary.userId === 'D77E02' ? 1 : 0,
    clientInfo: {
      declaredVersion: userEvents[0]?.clientVersion ?? null,
      declaredPlatform: userEvents[0]?.platform ?? null,
      attestationAvailable: false,
      note: 'Official client attestation is not available; client findings are behavioural indicators only.',
    },
    unavailableData: UNAVAILABLE,
  });
};

export const incidents = (query: { status?: string; userId?: string }): Promise<{
  incidents: Incident[];
  count: number;
}> => {
  const filtered = mutableIncidents.filter(
    (i) =>
      (query.status === undefined || query.status === '' || i.status === query.status) &&
      (query.userId === undefined || i.userId === query.userId),
  );
  return delay({ incidents: filtered, count: filtered.length });
};

export const incident = (incidentId: string): Promise<{ incident: Incident }> => {
  const found = mutableIncidents.find((i) => i.incidentId === incidentId);
  if (found === undefined) return Promise.reject(new Error('Incident not found.'));
  return delay({ incident: found });
};

export const updateIncident = (
  incidentId: string,
  body: { status: string; reviewNote: string },
): Promise<{ incident: Incident }> => {
  const found = mutableIncidents.find((i) => i.incidentId === incidentId);
  if (found === undefined) return Promise.reject(new Error('Incident not found.'));
  found.status = body.status;
  found.reviewNote = body.reviewNote;
  found.reviewedBy = 'mod-1';
  found.updatedAtMs = Date.now();
  return delay({ incident: found });
};

function bundleFor(key: string): EvidenceBundleView {
  const incidentId = key.split('/')[5] ?? INCIDENTS[0]!.incidentId;
  const source = mutableIncidents.find((i) => i.incidentId === incidentId) ?? (mutableIncidents[0] as Incident);
  return {
    key,
    sequence: Number(key.split('/').pop()?.replace('.json', '') ?? '1'),
    contentHash: 'a3f1c9'.padEnd(64, '0'),
    previousHash: '0'.repeat(64),
    chainHash: 'b7e2d4'.padEnd(64, '0'),
    body: {
      schemaVersion: 'talkinshield-evidence/1.1.0',
      incidentId: source.incidentId,
      userId: source.userId,
      ...(source.roomId !== undefined ? { roomId: source.roomId } : {}),
      createdAt: new Date(source.createdAtMs).toISOString(),
      detectedBehaviors: source.detectedBehaviors,
      detectionReasons: source.detectionReasons,
      riskScore: source.riskScore,
      riskLevel: source.riskLevel,
      confidence: source.confidence,
      modelVersions: source.modelVersions,
      relevantMessages: source.relevantMessages,
      authorizedMetadata: source.authorizedMetadata,
      actionsTaken: source.actionsTaken,
      signals: SIGNALS.filter((s) => s.userId === source.userId).map((s) => ({
        code: s.code,
        reason: s.reason,
        detector: s.detector,
        confidence: s.confidence,
      })),
      authorization: {
        capabilities: CAPABILITIES,
        collected: ['userId', 'roomId', 'timestamps', 'eventTypes', 'riskAssessment', 'messageText(redacted,truncated)'],
        notCollected: [
          { field: 'voiceAudio/voiceTranscript', reason: 'No approved, consented audio integration is configured. No call audio was received or processed.' },
          { field: 'clientAttestation', reason: 'The platform integration does not provide signed client attestation.' },
          { field: 'hiddenPresenceEvents', reason: 'The platform integration does not expose hidden/ghost-mode presence events.' },
          { field: 'deviceLocation', reason: 'Out of scope by design. TalkinShield never collects location data.' },
          { field: 'deviceIdentifiers', reason: 'Out of scope by design. No device fingerprinting is performed.' },
          { field: 'credentials/tokens', reason: 'Out of scope by design. Never collected; redacted if encountered.' },
          { field: 'networkTraffic', reason: 'Out of scope by design. TalkinShield observes only application events delivered to it.' },
        ],
        note:
          'This bundle records only data the operator was authorized to receive through the configured Talkin integration. Fields listed under notCollected were not gathered — their absence is a boundary, not a gap in the record.',
      },
    },
  };
}

const VALID: VerificationResult = { valid: true, problems: [] };

export const evidence = (
  key: string,
): Promise<{ bundle: EvidenceBundleView; verification: VerificationResult }> =>
  delay({ bundle: bundleFor(key), verification: VALID });

export const verifyEvidence = (incidentId: string) => {
  const source = mutableIncidents.find((i) => i.incidentId === incidentId);
  const keys = source?.evidenceKeys ?? [];
  return delay({
    incidentId,
    bundleCount: keys.length,
    missing: 0,
    chain: VALID,
    bundles: keys.map((key, i) => ({
      key,
      sequence: i + 1,
      contentHash: bundleFor(key).contentHash,
      verification: VALID,
    })),
  });
};

export const moderate = (body: {
  action: string;
  targetUserId: string;
  roomId?: string;
  reason: string;
  incidentId?: string;
}): Promise<ModerationResult> => {
  const platformCapable =
    (body.action === 'MUTE' && CAPABILITIES.remoteMute) ||
    (body.action === 'BLOCK' && CAPABILITIES.remoteBlock) ||
    body.action === 'REPORT';

  const scope = platformCapable
    ? 'PLATFORM_API'
    : body.action === 'SAVE_EVIDENCE'
      ? 'INTERNAL'
      : 'LOCAL_TO_REQUESTER';

  const messages: Record<string, string> = {
    MUTE: platformCapable
      ? 'Muted via the official Talkin moderation API. This restriction is reversible.'
      : "Muted locally for the protected user only. No official Talkin mute API is configured, so other participants still hear this account. TalkinShield will not attempt to mute another user's microphone by any other means.",
    BLOCK: platformCapable
      ? 'Blocked via the official Talkin moderation API. This restriction is reversible.'
      : 'Blocked locally for the protected user only. No official Talkin block API is configured, so this account is not restricted platform-wide.',
    IGNORE: 'Account is now ignored for the protected user. This is a local preference and affects no one else.',
    REPORT: 'Report submitted through the official reporting channel with the evidence bundle attached.',
    SAVE_EVIDENCE:
      'Evidence bundle requested. See the Evidence page for the stored, hash-chained record.',
  };

  const action: ActionRow = {
    actionId: `ACT-${Math.random().toString(36).slice(2, 8)}`,
    actionType: platformCapable
      ? body.action === 'REPORT'
        ? 'REPORT_SUBMITTED'
        : `PLATFORM_${body.action}`
      : body.action === 'SAVE_EVIDENCE'
        ? 'EVIDENCE_SAVED'
        : `LOCAL_${body.action}`,
    actorKind: 'MODERATOR',
    actorId: 'mod-1',
    targetUserId: body.targetUserId,
    ...(body.roomId !== undefined ? { roomId: body.roomId } : {}),
    atMs: Date.now(),
    reason: `${body.reason} (actioned by alice (mock))`,
    scope: scope as ActionRow['scope'],
    succeeded: true,
    ...(body.incidentId !== undefined ? { incidentId: body.incidentId } : {}),
  };
  ACTIONS.unshift(action);

  return delay({
    applied: true,
    scope,
    message: messages[body.action] ?? 'Action recorded.',
    platformActionUnavailable: !platformCapable && body.action !== 'SAVE_EVIDENCE' && body.action !== 'IGNORE',
    action,
  });
};

export const actions = (query: { userId?: string }): Promise<{ actions: ActionRow[]; count: number }> => {
  const filtered = ACTIONS.filter((a) => query.userId === undefined || a.targetUserId === query.userId);
  return delay({ actions: filtered, count: filtered.length });
};

export const affordances = (): Promise<AffordanceResponse> =>
  delay({
    integration: 'mock (local fixture — not a real integration)',
    capabilities: CAPABILITIES,
    unavailableData: UNAVAILABLE,
    affordances: [
      {
        action: 'MUTE',
        enabled: true,
        scope: 'LOCAL_TO_REQUESTER',
        label: 'MUTE',
        description:
          'Mutes this account locally for the protected user only. No official platform mute API is configured, so other participants are unaffected.',
      },
      {
        action: 'BLOCK',
        enabled: true,
        scope: 'LOCAL_TO_REQUESTER',
        label: 'BLOCK',
        description:
          'Blocks this account locally for the protected user only. No official platform block API is configured.',
      },
      {
        action: 'REPORT',
        enabled: true,
        scope: 'PLATFORM_API',
        label: 'REPORT',
        description:
          'Submits a report with the attached evidence bundle through the official reporting channel.',
      },
      {
        action: 'SAVE_EVIDENCE',
        enabled: true,
        scope: 'INTERNAL',
        label: 'SAVE EVIDENCE',
        description:
          'Writes an immutable, hash-chained evidence bundle to encrypted storage for later review.',
      },
    ],
  });

export const rules = (): Promise<RulesResponse> =>
  delay({
    version: 'default',
    overrides: mutableOverrides,
    effective: {
      spam: {
        windowMs: 30_000,
        highFrequencyCount: 15,
        burstWindowMs: 5000,
        burstCount: 10,
        identicalRepeatCount: 4,
        identicalSevereCount: 15,
        identicalShortMessageLength: 16,
        identicalShortRepeatMultiplier: 3,
        coordinationMinContentLength: 24,
        nearDuplicateSimilarity: 0.78,
        nearDuplicateCount: 5,
        nearDuplicateMinLength: 16,
        mentionsPerMessage: 6,
        mentionsPerWindow: 15,
        linksPerWindow: 6,
        timingMinSamples: 6,
        timingMaxCoefficientOfVariation: 0.18,
        timingMaxMeanGapMs: 20_000,
        sustainedWindowMs: 300_000,
        sustainedCount: 120,
        maxWindowEvents: 200,
      },
      abuse: {
        repeatWindowMs: 600_000,
        repeatCount: 3,
        minConfidence: 0.5,
        disagreementThreshold: 0.45,
        autoActionMinConfidence: 0.7,
        excerptMaxChars: 280,
        extraTerms: { mild: [], severe: [], threat: [] },
        allowTerms: [],
      },
      client: {
        knownVersions: ['4.2.1', '4.3.0'],
        versionFlapWindowMs: 600_000,
        versionFlapCount: 3,
        abnormalRequestsPerMinute: 240,
        malformedCount: 5,
        minTelemetryEvents: 5,
      },
      evasion: { postModerationWindowMs: 600_000, rejoinWindowMs: 300_000, rejoinCount: 5 },
      ghost: { correlationToleranceMs: 3000, minCorrelatedEvents: 2 },
      risk: {
        weights: RISK_WEIGHTS,
        thresholds: { LOW: 0, MEDIUM: 25, HIGH: 50, CRITICAL: 75 },
        repeatViolationWeight: 25,
        maxRepeatBonus: 25,
        confidenceScalingFloor: 0.5,
        maxSingleContribution: 40,
        criticalAutoActionMinConfidence: 0.8,
        historyHalfLifeMs: 86_400_000,
        maxHistoryComponent: 20,
      },
      incident: { dedupeWindowMs: 1_800_000, maxEvidenceBundles: 10, evidenceOnNewBehaviorOnly: true },
      retention: { rawEventsDays: 30, signalsDays: 90, incidentsDays: 365, evidenceDays: 365, auditDays: 730 },
      alert: { minLevel: 'HIGH', dedupeWindowMs: 300_000 },
      configVersion: '1.0.0',
    },
  });

export const saveRules = (overrides: Record<string, unknown>): Promise<{ version: string }> => {
  mutableOverrides = overrides;
  return delay({ version: `v${Date.now()}` });
};

export const settings = (): Promise<SettingsResponse> =>
  delay({
    stage: 'dev (mock)',
    region: 'us-east-1',
    integration: {
      name: 'mock (local fixture — not a real integration)',
      adapter: 'mock',
      capabilities: CAPABILITIES,
    },
    ai: {
      bedrockEnabled: false,
      modelId: null,
      note: 'AI classification is disabled; detection is fully deterministic.',
    },
    voice: {
      transcribeEnabled: false,
      note: 'Transcription is disabled. No call audio is received or processed.',
    },
    retentionDays: { rawEventsDays: 30, signalsDays: 90, incidentsDays: 365, evidenceDays: 365, auditDays: 730 },
    riskThresholds: { LOW: 0, MEDIUM: 25, HIGH: 50, CRITICAL: 75 },
    alerting: { minLevel: 'HIGH' },
    configVersion: 'default',
    unavailableData: UNAVAILABLE,
  });

export const logs = (): Promise<{ entries: AuditRow[]; count: number }> =>
  delay({ entries: AUDIT, count: AUDIT.length });
