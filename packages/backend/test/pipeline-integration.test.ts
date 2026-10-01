import test from 'node:test';
import assert from 'node:assert/strict';

import { validateEvent, verifyChain, type TalkinEvent } from '@talkinshield/core';

import { analyzeAndRespond } from '../src/app/analysis-service.ts';
import { ingestEvents } from '../src/app/ingest-service.ts';
import { ScriptedClassifier } from '../src/adapters/memory/stores.ts';
import { handleRequest } from '../src/http/router.ts';
import {
  CONTENT_ONLY_CAPS,
  FULL_CAPS,
  MODERATOR_CLAIMS,
  SERVICE_CLAIMS,
  T0,
  bodyOf,
  event,
  harness,
  request,
  type Harness,
} from './harness.ts';

function validated(raw: Record<string, unknown>, nowMs: number): TalkinEvent {
  const result = validateEvent(raw, { nowMs, messageContentAuthorized: true });
  if (!result.ok) throw new Error(`fixture invalid: ${JSON.stringify(result.issues)}`);
  return result.event;
}

/** Drive N events through ingestion + analysis, as the real system does. */
async function drive(
  h: Harness,
  raws: ReadonlyArray<Record<string, unknown>>,
): Promise<Awaited<ReturnType<typeof analyzeAndRespond>>[]> {
  const outcomes = [];
  for (const raw of raws) {
    const atMs = Date.parse(String(raw.timestamp));
    h.clock.set(atMs);
    const ingest = await ingestEvents({ events: [raw] }, 'submitter:svc-1', h.deps);
    if ('error' in ingest) throw new Error(`ingest failed: ${ingest.error}`);
    for (const id of ingest.eventIds) {
      const stored = (await h.events.getByIds([id]))[0];
      assert.ok(stored);
      outcomes.push(await analyzeAndRespond(stored, h.deps));
    }
  }
  return outcomes;
}

// --- INGESTION -------------------------------------------------------------

test('ingest: a valid single event is accepted and published for analysis', async () => {
  const h = harness();
  const result = await ingestEvents({ events: [event()] }, 'submitter:svc-1', h.deps);
  assert.ok(!('error' in result));
  assert.equal(result.accepted, 1);
  assert.equal(result.rejected.length, 0);
  assert.equal(h.events.size, 1);
  assert.equal(h.publisher.published.filter((p) => p.detailType === 'EventIngested').length, 1);
});

test('ingest: a bare event object (no envelope) is accepted', async () => {
  const h = harness();
  const result = await ingestEvents(event(), 'submitter:svc-1', h.deps);
  assert.ok(!('error' in result));
  assert.equal(result.accepted, 1);
});

test('ingest: redelivery of the same event is deduplicated, not double-counted', async () => {
  const h = harness();
  const payload = { events: [event()] };

  const first = await ingestEvents(payload, 'submitter:svc-1', h.deps);
  const second = await ingestEvents(payload, 'submitter:svc-1', h.deps);
  assert.ok(!('error' in first) && !('error' in second));

  assert.equal(first.accepted, 1);
  assert.equal(second.accepted, 0);
  assert.equal(second.duplicates, 1);
  assert.equal(h.events.size, 1);
  // Only the first delivery was fanned out for analysis.
  assert.equal(h.publisher.published.filter((p) => p.detailType === 'EventIngested').length, 1);
});

test('ingest: a partially invalid batch accepts the good events', async () => {
  const h = harness();
  const result = await ingestEvents(
    {
      events: [
        event({ message: 'first' }),
        { userId: 'broken' },
        event({ message: 'second', timestamp: new Date(T0 + 1000).toISOString() }),
      ],
    },
    'submitter:svc-1',
    h.deps,
  );
  assert.ok(!('error' in result));
  assert.equal(result.accepted, 2);
  assert.equal(result.rejected.length, 1);
  assert.equal(result.rejected[0]?.index, 1);
});

test('ingest: malformed payloads count toward the client-integrity signal', async () => {
  const h = harness();
  for (let i = 0; i < 6; i += 1) {
    await ingestEvents({ events: [{ garbage: true }] }, 'submitter:svc-1', h.deps);
  }
  const count = await h.rateLimiter.countMalformed('submitter:svc-1', 300, T0);
  assert.ok(count >= 6, `expected malformed requests to be recorded, got ${count}`);
  assert.ok(h.metrics.total('IngestRejected') >= 6);
});

test('ingest: a non-object body is refused', async () => {
  const h = harness();
  for (const bad of ['string', 42, [], null]) {
    const result = await ingestEvents(bad, 'submitter:svc-1', h.deps);
    assert.ok('error' in result, `expected rejection for ${JSON.stringify(bad)}`);
  }
});

test('ingest: message content is dropped when not authorized', async () => {
  const h = harness({ capabilities: { ...CONTENT_ONLY_CAPS, messageContent: false } });
  const result = await ingestEvents({ events: [event({ message: 'secret text' })] }, 'submitter:svc-1', h.deps);
  assert.ok(!('error' in result));
  assert.equal(result.accepted, 1);

  const stored = (await h.events.listRecent(1))[0];
  assert.equal(stored?.message, undefined);
  assert.ok(result.warnings[0]?.warnings.some((w) => w.code === 'CONTENT_NOT_AUTHORIZED'));
});

test('ingest: batch size limit is enforced', async () => {
  const h = harness({ env: { INGEST_MAX_BATCH_SIZE: '3' } });
  const result = await ingestEvents(
    {
      events: Array.from({ length: 4 }, (_, i) =>
        event({ timestamp: new Date(T0 + i).toISOString() }),
      ),
    },
    'submitter:svc-1',
    h.deps,
  );
  assert.ok('error' in result);
  assert.match(result.error, /at most 3/);
});

// --- END-TO-END SPAM SCENARIO ---------------------------------------------

test('e2e: an ongoing flood folds into ONE incident, not one per event', async () => {
  const h = harness({ capabilities: FULL_CAPS });

  await drive(
    h,
    Array.from({ length: 20 }, (_, i) =>
      event({
        userId: 'flooder',
        message: 'you are a fucking idiot bitch',
        clientVersion: 'custom-build-9',
        timestamp: new Date(T0 + i * 1000).toISOString(),
      }),
    ),
  );

  const incidents = await h.incidents.list({ limit: 100 });
  assert.equal(
    incidents.length,
    1,
    `a single ongoing episode must produce one incident, got ${incidents.length}`,
  );

  const incident = incidents[0];
  assert.ok(incident);
  // The single incident accumulated the whole episode.
  assert.ok(incident.detectionReasons.length > 1);
  assert.ok(incident.updatedAtMs > incident.createdAtMs);
  // Excerpts stay bounded despite 20 messages.
  assert.ok(incident.relevantMessages.length <= 20);
  // Evidence is not rewritten for every repeat of the same behaviour.
  assert.ok(
    incident.evidenceKeys.length < 10,
    `evidence bundles should be bounded, got ${incident.evidenceKeys.length}`,
  );
});

test('e2e: a separate episode after the dedupe window opens a new incident', async () => {
  const h = harness({ capabilities: FULL_CAPS });
  const burst = (base: number) =>
    Array.from({ length: 20 }, (_, i) =>
      event({
        userId: 'repeat-offender',
        message: 'i will kill you',
        timestamp: new Date(base + i * 1000).toISOString(),
      }),
    );

  await drive(h, burst(T0));
  // Two hours later — well beyond the 30-minute dedupe window.
  await drive(h, burst(T0 + 2 * 60 * 60 * 1000));

  const incidents = await h.incidents.list({ limit: 100 });
  assert.equal(incidents.length, 2, `expected two distinct episodes, got ${incidents.length}`);
});

test('e2e: a spam flood escalates, creates an incident, and preserves evidence', async () => {
  const h = harness({ capabilities: FULL_CAPS });

  const raws = Array.from({ length: 20 }, (_, i) =>
    event({
      userId: '8F29A1',
      roomId: 'ABC123',
      message: 'you are a fucking idiot bitch',
      clientVersion: 'custom-build-9',
      timestamp: new Date(T0 + i * 1000).toISOString(),
    }),
  );

  const outcomes = await drive(h, raws);
  const last = outcomes[outcomes.length - 1];
  assert.ok(last);

  assert.equal(last.result.assessment.level, 'CRITICAL');
  assert.ok(last.incident, 'an incident must be created at CRITICAL');

  // A moderator was notified once; later passes are deduplicated rather than
  // spamming the on-call channel, and that distinction is explicit.
  assert.equal(h.notifier.sent.length, 1, 'exactly one alert for one episode');
  assert.ok(
    outcomes.some((o) => o.alerted),
    'at least one pass must have dispatched the alert',
  );
  assert.ok(
    outcomes.some((o) => o.alertSuppressed === true),
    'repeat alerts must be reported as suppressed, not as "no alert"',
  );

  // Evidence was preserved and verifies.
  const evidenceKey = outcomes.find((o) => o.evidenceKey)?.evidenceKey;
  assert.ok(evidenceKey, 'evidence must be preserved');
  const bundle = await h.evidence.get(evidenceKey);
  assert.ok(bundle);
  assert.equal(bundle.body.incidentId, last.incident.incidentId);
  assert.equal(h.evidence.verifyAll().valid, true);

  // The incident carries full provenance.
  assert.ok(last.incident.detectionReasons.length > 0);
  assert.ok(last.incident.modelVersions.length > 0);
  assert.ok(last.incident.relevantMessages.length > 0);

  // Every action has a reason.
  for (const action of last.incident.actionsTaken) {
    assert.ok(action.reason.trim().length > 0);
  }

  // Targeted profanity classifies as ABUSIVE at ~0.68 confidence, below the
  // 0.7 auto-action floor, so the policy refuses the automated platform
  // restriction and routes it to a human instead. CRITICAL risk alone is not
  // sufficient — that is the point of the confidence gate.
  assert.equal(h.mockState.blocked.length, 0);
  assert.ok(!last.result.plan.automated.includes('PLATFORM_TEMPORARY_BLOCK'));
  assert.match(last.result.plan.rationale, /human review/i);
  // The moderator is still offered the actions.
  assert.deepEqual(last.result.plan.recommended, ['MUTE', 'BLOCK', 'REPORT']);
});

test('e2e: a high-confidence threat with corroboration DOES get a temporary restriction', async () => {
  const h = harness({ capabilities: FULL_CAPS });

  const outcomes = await drive(
    h,
    Array.from({ length: 20 }, (_, i) =>
      event({
        userId: 'threat-actor',
        message: 'i am going to kill you when i find you',
        timestamp: new Date(T0 + i * 1000).toISOString(),
      }),
    ),
  );
  const last = outcomes[outcomes.length - 1];
  assert.ok(last);

  assert.equal(last.result.assessment.level, 'CRITICAL');
  assert.equal(last.result.abuse?.classification, 'THREAT');
  assert.equal(last.result.abuse?.requiresHumanReview, false);
  assert.ok(last.result.assessment.peakConfidence >= 0.8);

  // Deterministic threat + corroborating spam signals + high confidence.
  // Applied exactly once for the whole episode, not once per event.
  assert.equal(
    h.mockState.blocked.length,
    1,
    `the restriction must be applied once per episode, got ${h.mockState.blocked.length}`,
  );
  const block = h.mockState.blocked[0];
  assert.ok(block);
  // Time-bounded and reversible — never a permanent ban from automation.
  assert.ok(block.until > T0, 'restriction must expire in the future');
  assert.ok(
    block.until <= T0 + 20_000 + 15 * 60 * 1000,
    'restriction must be a 15-minute window from when it was applied',
  );
  assert.match(block.reason, /pending moderator review/);
});

test('e2e: the evidence chain across multiple incidents verifies', async () => {
  const h = harness({ capabilities: FULL_CAPS });

  for (const userId of ['user-1', 'user-2', 'user-3']) {
    await drive(
      h,
      Array.from({ length: 20 }, (_, i) =>
        event({
          userId,
          message: 'i am going to kill you, you fucking bitch',
          clientVersion: 'modded',
          timestamp: new Date(T0 + i * 1000).toISOString(),
        }),
      ),
    );
  }

  assert.ok(h.evidence.size >= 3, `expected multiple bundles, got ${h.evidence.size}`);

  const incidents = await h.incidents.list({ limit: 50 });
  const bundles = [];
  for (const incident of incidents) {
    for (const key of incident.evidenceKeys) {
      const bundle = await h.evidence.get(key);
      if (bundle) bundles.push(bundle);
    }
  }

  const chain = verifyChain(bundles);
  assert.equal(chain.valid, true, chain.problems.join('; '));
});

test('e2e: evidence storage refuses to overwrite an existing object', async () => {
  const h = harness({ capabilities: FULL_CAPS });
  await drive(
    h,
    Array.from({ length: 20 }, (_, i) =>
      event({ message: 'i will kill you', timestamp: new Date(T0 + i * 1000).toISOString() }),
    ),
  );

  const keys = await h.evidence.listByIncident(
    (await h.incidents.list({ limit: 1 }))[0]?.incidentId ?? '',
  );
  const existing = await h.evidence.get(keys[0] ?? '');
  assert.ok(existing);

  await assert.rejects(() => h.evidence.put(existing), /write-once/);
});

test('e2e: a clean conversation produces no incident and no alert', async () => {
  const h = harness({ capabilities: FULL_CAPS });
  const outcomes = await drive(h, [
    event({ message: 'hey everyone', timestamp: new Date(T0).toISOString() }),
    event({ message: 'how is everyone doing today', timestamp: new Date(T0 + 40_000).toISOString() }),
    event({ message: 'anyone up for a game', timestamp: new Date(T0 + 95_000).toISOString() }),
  ]);

  for (const outcome of outcomes) {
    assert.equal(outcome.result.assessment.level, 'LOW');
    assert.equal(outcome.incident, undefined);
    assert.equal(outcome.alerted, false);
  }
  assert.equal(h.evidence.size, 0);
  assert.equal(h.notifier.sent.length, 0);
});

// --- AI failure handling ---------------------------------------------------

test('resilience: an AI failure does not block detection', async () => {
  const h = harness({
    capabilities: FULL_CAPS,
    classifier: new ScriptedClassifier(undefined, true),
  });

  const outcomes = await drive(h, [
    event({ message: 'i am going to kill you', timestamp: new Date(T0).toISOString() }),
  ]);
  const outcome = outcomes[0];
  assert.ok(outcome);

  // The deterministic threat rule still fired.
  assert.ok(outcome.result.signals.some((s) => s.code === 'THREAT_LANGUAGE'));
  assert.ok(h.metrics.total('ClassifierFailure') >= 1);
  assert.ok(h.logger.lines.some((l) => l.level === 'warn' && /AI classification failed/.test(l.message)));
});

test('resilience: an AI-only verdict cannot trigger an automated platform block', async () => {
  const h = harness({
    capabilities: FULL_CAPS,
    classifier: new ScriptedClassifier({
      classification: 'THREAT',
      confidence: 0.99,
      reason: 'model is very confident',
      modelVersion: 'test-model@1',
    }),
  });

  // Content that matches no deterministic rule at all.
  const outcomes = await drive(h, [
    event({ message: 'the weather is quite pleasant today', timestamp: new Date(T0).toISOString() }),
  ]);
  const outcome = outcomes[0];
  assert.ok(outcome);

  assert.equal(outcome.result.abuse?.requiresHumanReview, true);
  assert.ok(!outcome.result.plan.automated.includes('PLATFORM_TEMPORARY_BLOCK'));
  assert.equal(h.mockState.blocked.length, 0);
});

test('resilience: evidence write failure does not lose the incident', async () => {
  const h = harness({ capabilities: FULL_CAPS });
  h.deps.evidence.put = async () => {
    throw new Error('S3 AccessDenied');
  };

  const outcomes = await drive(
    h,
    Array.from({ length: 20 }, (_, i) =>
      event({ message: 'i will kill you bitch', timestamp: new Date(T0 + i * 1000).toISOString() }),
    ),
  );
  const last = outcomes[outcomes.length - 1];
  assert.ok(last?.incident, 'the incident must still be created');

  const failed = last.incident.actionsTaken.find(
    (a) => a.actionType === 'EVIDENCE_SAVED' && !a.succeeded,
  );
  assert.ok(failed, 'the failed evidence write must be recorded on the incident');
  assert.match(failed.failureReason ?? '', /AccessDenied/);
  assert.ok(h.metrics.total('EvidenceWriteFailure') >= 1);
});

// --- Telemetry honesty -----------------------------------------------------

test('honesty: capability gaps are surfaced on the user detail response', async () => {
  const h = harness({ capabilities: CONTENT_ONLY_CAPS });
  await drive(h, [event({ message: 'hello there', timestamp: new Date(T0).toISOString() })]);

  const response = await handleRequest(
    request('GET', '/users/user-A', { claims: MODERATOR_CLAIMS }),
    h.deps,
  );
  assert.equal(response.statusCode, 200);

  const body = bodyOf<{
    clientInfo: { attestationAvailable: boolean; note: string };
    unavailableData: Array<{ field: string; status: string; reason: string }>;
  }>(response);

  assert.equal(body.clientInfo.attestationAvailable, false);
  assert.match(body.clientInfo.note, /behavioural indicators only/);

  const fields = body.unavailableData.map((u) => u.field);
  assert.ok(fields.includes('Hidden / ghost-mode presence'));
  assert.ok(fields.includes('Voice audio / transcripts'));
  assert.ok(fields.includes('Location / GPS'));

  const hidden = body.unavailableData.find((u) => u.field === 'Hidden / ghost-mode presence');
  assert.match(hidden?.reason ?? '', /Insufficient authorized telemetry/);
});

test('honesty: the user detail response exposes no private data categories', async () => {
  const h = harness({ capabilities: FULL_CAPS });
  await drive(h, [event({ message: 'hello there', timestamp: new Date(T0).toISOString() })]);

  const response = await handleRequest(
    request('GET', '/users/user-A', { claims: MODERATOR_CLAIMS }),
    h.deps,
  );

  // `unavailableData` deliberately *names* the out-of-scope categories in order
  // to state that they were not collected, so it is excluded from the scan.
  const body = { ...(response.body as Record<string, unknown>) };
  delete body.unavailableData;
  const serialized = JSON.stringify(body).toLowerCase();

  for (const forbidden of [
    'latitude',
    'longitude',
    'gps',
    'coordinates',
    'password',
    'access_token',
    'bearer ',
    'macaddress',
    'imei',
    'contacts',
    'ipaddress',
  ]) {
    assert.ok(!serialized.includes(forbidden), `response leaked "${forbidden}"`);
  }
});

test('honesty: message content is withheld from event listings when not authorized', async () => {
  const h = harness({ capabilities: { ...CONTENT_ONLY_CAPS, messageContent: false } });
  await ingestEvents({ events: [event({ message: 'should not appear' })] }, 'submitter:svc-1', h.deps);

  const response = await handleRequest(request('GET', '/events', { claims: MODERATOR_CLAIMS }), h.deps);
  const serialized = JSON.stringify(response.body);
  assert.ok(!serialized.includes('should not appear'));
  assert.match(serialized, /Not authorized to display message content/);
});

// --- Risk persistence ------------------------------------------------------

test('state: risk accumulates across separate ingestion calls', async () => {
  const h = harness({ capabilities: FULL_CAPS });
  const outcomes = await drive(
    h,
    Array.from({ length: 12 }, (_, i) =>
      event({ message: 'buy cheap followers now at this link', timestamp: new Date(T0 + i * 700).toISOString() }),
    ),
  );

  const scores = outcomes.map((o) => o.result.assessment.score);
  assert.ok(
    (scores[scores.length - 1] ?? 0) > (scores[0] ?? 0),
    `risk should rise across the flood: ${scores.join(',')}`,
  );

  const stored = await h.userState.get('user-A');
  assert.ok(stored);
  assert.ok(stored.recent.length > 1, 'window state must persist between calls');
});

test('state: the per-user window stays bounded', async () => {
  const h = harness({ capabilities: FULL_CAPS });
  await drive(
    h,
    Array.from({ length: 60 }, (_, i) =>
      event({ message: `unique message ${i}`, timestamp: new Date(T0 + i * 2000).toISOString() }),
    ),
  );
  const stored = await h.userState.get('user-A');
  assert.ok(stored);
  assert.ok(stored.recent.length <= 200);
});

// --- Full API round trip ---------------------------------------------------

test('API: ingest then read the overview and incident list', async () => {
  const h = harness({ capabilities: FULL_CAPS });

  for (let i = 0; i < 20; i += 1) {
    h.clock.set(T0 + i * 1000);
    const response = await handleRequest(
      request('POST', '/events', {
        claims: SERVICE_CLAIMS,
        body: event({
          userId: 'floodbot',
          message: 'i will kill you all you fucking idiots',
          clientVersion: 'modded-client',
          timestamp: new Date(T0 + i * 1000).toISOString(),
        }),
      }),
      h.deps,
    );
    assert.equal(response.statusCode, 202);
  }

  // Analysis is asynchronous in production (EventBridge); drive it here.
  for (const stored of await h.events.listRecent(50)) {
    await analyzeAndRespond(stored, h.deps);
  }

  const overview = bodyOf<{
    activeIncidents: number;
    highRiskUsers: number;
    abuseEvents: number;
    riskDistribution: Array<{ level: string; range: string; count: number }>;
    topSignals: Array<{ code: string; count: number }>;
  }>(await handleRequest(request('GET', '/overview', { claims: MODERATOR_CLAIMS }), h.deps));

  assert.ok(overview.activeIncidents > 0);
  assert.ok(overview.highRiskUsers > 0);
  assert.ok(overview.abuseEvents > 0);
  assert.equal(overview.riskDistribution.length, 4);
  assert.equal(overview.riskDistribution[0]?.range, '0-24');
  assert.ok(overview.topSignals.length > 0);

  const incidents = bodyOf<{ incidents: Array<{ incidentId: string }> }>(
    await handleRequest(request('GET', '/incidents', { claims: MODERATOR_CLAIMS }), h.deps),
  );
  assert.ok(incidents.incidents.length > 0);

  // Evidence verification endpoint confirms integrity.
  const verification = bodyOf<{ chain: { valid: boolean } }>(
    await handleRequest(
      request('POST', '/evidence/verify', {
        claims: MODERATOR_CLAIMS,
        body: { incidentId: incidents.incidents[0]?.incidentId },
      }),
      h.deps,
    ),
  );
  assert.equal(verification.chain.valid, true);
});

test('API: evidence access is audited', async () => {
  const h = harness({ capabilities: FULL_CAPS });
  await drive(
    h,
    Array.from({ length: 20 }, (_, i) =>
      event({ message: 'i will kill you', timestamp: new Date(T0 + i * 1000).toISOString() }),
    ),
  );

  const incident = (await h.incidents.list({ limit: 1 }))[0];
  assert.ok(incident);
  const key = incident.evidenceKeys[0];
  assert.ok(key);

  // Evidence keys contain `/`, so the route uses a greedy path parameter.
  const response = await handleRequest(
    request('GET', `/evidence/${key}`, { claims: MODERATOR_CLAIMS }),
    h.deps,
  );
  assert.equal(response.statusCode, 200);
  const body = bodyOf<{ verification: { valid: boolean } }>(response);
  assert.equal(body.verification.valid, true);

  assert.ok(h.audit.snapshot.some((e) => e.action === 'EVIDENCE_ACCESSED' && e.target === key));
});

test('e2e: validated fixtures round-trip through the analyzer', async () => {
  const h = harness({ capabilities: FULL_CAPS });
  const stored = validated(event({ message: 'i know where you live' }), T0);
  await h.events.put(stored, 0);
  const outcome = await analyzeAndRespond(stored, h.deps);
  assert.ok(outcome.result.signals.some((s) => s.code === 'THREAT_LANGUAGE'));
  assert.ok(outcome.result.plan.automated.includes('NOTIFY_MODERATOR'));
});
