import test from 'node:test';
import assert from 'node:assert/strict';

import { DEFAULT_CONFIG, resolveConfig } from '../src/config/detection-config.ts';
import { buildLexicon } from '../src/detection/abuse/classifier.ts';
import { analyzeEvent, emptyState } from '../src/pipeline/analyze.ts';
import { buildIncident, decideAlert } from '../src/pipeline/incident.ts';
import type { TalkinEvent, UserWindowState } from '../src/types/index.ts';
import { FULL_CAPS, MINIMAL_CAPS, T0, evt, hasCode } from './helpers.ts';
import { NO_CAPABILITIES } from '../src/types/telemetry.ts';

const config = resolveConfig({ client: { knownVersions: ['4.2.1', '4.3.0'] } });
const lexicon = buildLexicon(config.abuse, config.configVersion);

/** Replay a sequence of events through the pipeline, threading state. */
function replay(
  events: readonly TalkinEvent[],
  opts: { capabilities?: typeof FULL_CAPS; startState?: UserWindowState } = {},
) {
  let state = opts.startState ?? emptyState(events[0]?.userId ?? 'u1');
  const results = [];
  for (const event of events) {
    const result = analyzeEvent({
      event,
      state,
      config,
      capabilities: opts.capabilities ?? FULL_CAPS,
      nowMs: event.receivedAtMs,
      lexicon,
      observedRequestsPerMinute: 0,
    });
    state = result.nextState;
    results.push(result);
  }
  return { results, finalState: state, last: results[results.length - 1] };
}

test('pipeline: a clean conversation stays LOW with no signals', () => {
  const events = [
    evt({ eventId: 'c1', message: 'hey everyone, how is it going?', receivedAtMs: T0 }),
    evt({ eventId: 'c2', message: 'just joined from the UK', receivedAtMs: T0 + 30_000 }),
    evt({ eventId: 'c3', message: 'anyone up for a game later?', receivedAtMs: T0 + 95_000 }),
  ];
  const { last } = replay(events);
  assert.ok(last);
  assert.equal(last.assessment.level, 'LOW');
  assert.equal(last.assessment.score, 0);
  assert.deepEqual(last.signals, []);
  assert.deepEqual(last.plan.automated, ['LOG']);
});

test("pipeline: the brief's scenario — spam + abuse + bad client reaches CRITICAL", () => {
  // A spam bot: identical abusive messages, machine-timed, unknown client.
  const text = 'you are a fucking idiot, you bitch';
  const events: TalkinEvent[] = [];
  for (let i = 0; i < 20; i += 1) {
    events.push(
      evt({
        eventId: `s${i}`,
        userId: '8F29A1',
        roomId: 'ABC123',
        message: text,
        clientVersion: 'custom-build-x',
        receivedAtMs: T0 + i * 1000, // exactly 1s apart
      }),
    );
  }

  const { last } = replay(events);
  assert.ok(last);

  // Expected detection families from the example panel.
  assert.ok(hasCode(last.signals, 'SPAM_IDENTICAL_REPEAT'), 'message spam');
  assert.ok(hasCode(last.signals, 'ABUSE_REPEATED'), 'repeated abusive language');
  assert.ok(hasCode(last.signals, 'BOT_UNIFORM_TIMING'), 'suspicious activity pattern');
  assert.ok(hasCode(last.signals, 'CLIENT_UNKNOWN_VERSION'), 'abnormal client behavior');

  assert.equal(last.assessment.level, 'CRITICAL');
  assert.ok(last.assessment.score >= 75, `score was ${last.assessment.score}`);

  // Moderator is offered exactly the actions from the example panel.
  assert.deepEqual(last.plan.recommended, ['MUTE', 'BLOCK', 'REPORT']);
  assert.ok(last.plan.automated.includes('CREATE_INCIDENT'));
  assert.ok(last.plan.automated.includes('PRESERVE_EVIDENCE'));
  assert.ok(last.plan.automated.includes('NOTIFY_MODERATOR'));
});

test('pipeline: a threat produces an incident with full provenance', () => {
  const { last } = replay([
    evt({ eventId: 't1', userId: '8F29A1', message: 'i am going to kill you', receivedAtMs: T0 }),
  ]);
  assert.ok(last);
  assert.ok(hasCode(last.signals, 'THREAT_LANGUAGE'));

  const incident = buildIncident({
    assessment: last.assessment,
    signals: last.signals,
    plan: last.plan,
    config,
    ...(last.abuse ? { abuse: last.abuse } : {}),
    events: [last.event],
    messageContentAuthorized: true,
    nowMs: T0,
  });

  assert.ok(incident.incidentId.startsWith('INC-'));
  assert.equal(incident.status, 'OPEN');
  assert.ok(incident.detectedBehaviors.includes('THREAT_LANGUAGE'));
  assert.ok(incident.detectionReasons.every((r) => r.startsWith('[')));
  assert.ok(incident.modelVersions.length >= 2);
  assert.equal(incident.relevantMessages.length, 1);
  // Metadata must be limited to authorized, non-personal fields.
  assert.equal(incident.authorizedMetadata.platform, 'ios');
  for (const key of Object.keys(incident.authorizedMetadata)) {
    assert.ok(!/ip|location|gps|token|password|device/i.test(key), `unexpected metadata key ${key}`);
  }
});

test('pipeline: repeat offenders accumulate, then decay', () => {
  const abusive = (i: number, at: number) =>
    evt({ eventId: `r${i}`, message: 'you are a fucking idiot bitch', receivedAtMs: at });

  // Two separate high-risk episodes an hour apart.
  const first = replay([abusive(1, T0)]);
  const second = replay([abusive(2, T0 + 3_600_000)], { startState: first.finalState });

  assert.ok(second.finalState.priorViolations >= first.finalState.priorViolations);

  // A week later, carried risk has decayed away.
  const later = replay([evt({ eventId: 'q1', message: 'hello again', receivedAtMs: T0 + 7 * 86_400_000 })], {
    startState: second.finalState,
  });
  assert.ok(later.last);
  assert.ok(later.last.assessment.historyComponent < 1, `history was ${later.last.assessment.historyComponent}`);
});

test('pipeline: state stays bounded over a long session', () => {
  const events = Array.from({ length: 500 }, (_, i) =>
    evt({ eventId: `b${i}`, message: `message number ${i}`, receivedAtMs: T0 + i * 1000 }),
  );
  const { finalState } = replay(events);
  assert.ok(
    finalState.recent.length <= config.spam.maxWindowEvents,
    `window grew to ${finalState.recent.length}`,
  );
});

// --- Capability degradation ------------------------------------------------

test('pipeline: unavailable capabilities are reported, never faked', () => {
  const { last } = replay(
    [evt({ eventId: 'm1', message: 'you are a fucking idiot', receivedAtMs: T0 })],
    { capabilities: MINIMAL_CAPS },
  );
  assert.ok(last);
  const notes = last.telemetryNotes.join(' ');
  assert.match(notes, /does not deliver platform moderation events/);
  assert.match(notes, /Client attestation unavailable/);
});

test('pipeline: message content is not analysed when not authorized', () => {
  const { last } = replay(
    [evt({ eventId: 'm2', message: 'i will kill you', receivedAtMs: T0 })],
    { capabilities: NO_CAPABILITIES },
  );
  assert.ok(last);
  assert.equal(last.abuse, undefined);
  assert.ok(!hasCode(last.signals, 'THREAT_LANGUAGE'));
  assert.match(last.telemetryNotes.join(' '), /not authorized to process message text/);
});

test('pipeline: voice events without an audio integration are reported as skipped', () => {
  const { last } = replay([evt({ eventId: 'v1', eventType: 'voice', message: undefined, receivedAtMs: T0 })], {
    capabilities: MINIMAL_CAPS,
  });
  assert.ok(last);
  assert.match(last.telemetryNotes.join(' '), /no approved, consented audio integration/i);
});

test('pipeline: a transcript is analysed exactly like text when audio is authorized', () => {
  const { last } = replay([
    evt({
      eventId: 'v2',
      eventType: 'voice',
      message: 'i am going to kill you',
      messageIsTranscript: true,
      receivedAtMs: T0,
    }),
  ]);
  assert.ok(last);
  assert.equal(last.abuse?.classification, 'THREAT');
  const signal = last.signals.find((s) => s.code === 'THREAT_LANGUAGE');
  assert.equal(signal?.details?.transcript, true);
});

// --- Alerting -------------------------------------------------------------

test('alerts: CRITICAL risk raises an alert', () => {
  const { last } = replay(
    Array.from({ length: 20 }, (_, i) =>
      evt({
        eventId: `a${i}`,
        message: 'you are a fucking idiot bitch',
        clientVersion: 'bad',
        receivedAtMs: T0 + i * 1000,
      }),
    ),
  );
  assert.ok(last);
  const decision = decideAlert({
    assessment: last.assessment,
    signals: last.signals,
    ...(last.abuse ? { abuse: last.abuse } : {}),
    config: config.alert,
  });
  assert.equal(decision.shouldAlert, true);
  assert.ok(decision.reasons.includes('CRITICAL_RISK'));
  assert.ok(decision.dedupeKey.length > 0);
});

test('alerts: a threat alerts even below the configured minimum level', () => {
  const { last } = replay([evt({ eventId: 'th1', message: 'i know where you live', receivedAtMs: T0 })]);
  assert.ok(last);
  const decision = decideAlert({
    assessment: last.assessment,
    signals: last.signals,
    ...(last.abuse ? { abuse: last.abuse } : {}),
    config: { ...config.alert, minLevel: 'CRITICAL' },
  });
  assert.equal(decision.shouldAlert, true);
  assert.ok(decision.reasons.includes('THREAT_DETECTED'));
});

test('alerts: a clean event raises nothing', () => {
  const { last } = replay([evt({ eventId: 'ok1', message: 'good game all', receivedAtMs: T0 })]);
  assert.ok(last);
  const decision = decideAlert({
    assessment: last.assessment,
    signals: last.signals,
    config: config.alert,
  });
  assert.equal(decision.shouldAlert, false);
  assert.deepEqual(decision.reasons, []);
});

test('alerts: individual alert categories can be switched off', () => {
  const { last } = replay([evt({ eventId: 'th2', message: 'i will kill you', receivedAtMs: T0 })]);
  assert.ok(last);
  const decision = decideAlert({
    assessment: last.assessment,
    signals: last.signals,
    ...(last.abuse ? { abuse: last.abuse } : {}),
    config: { ...config.alert, alertOnThreat: false, alertOnSevereAbuse: false, minLevel: 'CRITICAL' },
  });
  assert.ok(!decision.reasons.includes('THREAT_DETECTED'));
});

// --- Determinism ----------------------------------------------------------

test('pipeline: identical inputs produce identical decisions (replayable audit)', () => {
  const events = Array.from({ length: 12 }, (_, i) =>
    evt({ eventId: `d${i}`, message: 'spam spam spam spam', receivedAtMs: T0 + i * 800 }),
  );
  const a = replay(events);
  const b = replay(events);
  assert.deepEqual(
    a.last?.signals.map((s) => [s.code, s.confidence]),
    b.last?.signals.map((s) => [s.code, s.confidence]),
  );
  assert.equal(a.last?.assessment.score, b.last?.assessment.score);
});

test('pipeline: config is honoured end-to-end', () => {
  const strict = resolveConfig({ risk: { thresholds: { LOW: 0, MEDIUM: 5, HIGH: 10, CRITICAL: 15 } } });
  const event = evt({ eventId: 'cfg1', message: 'you are a bitch', receivedAtMs: T0 });
  const lenient = analyzeEvent({
    event,
    state: emptyState('u1'),
    config: DEFAULT_CONFIG,
    capabilities: FULL_CAPS,
    nowMs: T0,
  });
  const tightened = analyzeEvent({
    event,
    state: emptyState('u1'),
    config: strict,
    capabilities: FULL_CAPS,
    nowMs: T0,
  });
  assert.equal(lenient.assessment.score, tightened.assessment.score);
  assert.notEqual(lenient.assessment.level, tightened.assessment.level);
  assert.equal(tightened.assessment.level, 'CRITICAL');
});
