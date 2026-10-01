#!/usr/bin/env node
/**
 * Mock event CLI.
 *
 *   node --experimental-strip-types src/cli.ts list
 *   node --experimental-strip-types src/cli.ts emit --scenario threat-language
 *   node --experimental-strip-types src/cli.ts emit --all --format ndjson
 *   node --experimental-strip-types src/cli.ts post --url http://localhost:3000/events --token "$JWT"
 *   node --experimental-strip-types src/cli.ts verify
 *
 * `verify` runs every scenario through the real detection pipeline locally and
 * reports whether the expected signals fired — a fast feedback loop for
 * threshold tuning that needs no AWS and no Talkin access.
 */

import {
  aggregateParticipants,
  analyzeEvent,
  buildLexicon,
  detectCoordination,
  emptyState,
  resolveConfig,
  validateEvent,
  type IntegrationCapabilities,
  type UserWindowState,
} from '@talkinshield/core';

import { allScenarios, mixedStream, type MockEvent, type ScenarioResult } from './generator.ts';

const ALL_CAPS: IntegrationCapabilities = {
  messageContent: true,
  moderationEvents: true,
  voiceAudio: true,
  hiddenPresenceEvents: true,
  clientAttestation: false,
  remoteMute: false,
  remoteBlock: false,
};

interface Args {
  command: string;
  scenario?: string;
  all: boolean;
  format: 'json' | 'ndjson';
  url?: string;
  token?: string;
  seed: number;
}

function parseArgs(argv: readonly string[]): Args {
  const args: Args = { command: argv[0] ?? 'help', all: false, format: 'json', seed: 1337 };
  for (let i = 1; i < argv.length; i += 1) {
    const flag = argv[i];
    const value = argv[i + 1];
    switch (flag) {
      case '--scenario':
        if (value !== undefined) args.scenario = value;
        i += 1;
        break;
      case '--all':
        args.all = true;
        break;
      case '--format':
        if (value === 'ndjson' || value === 'json') args.format = value;
        i += 1;
        break;
      case '--url':
        if (value !== undefined) args.url = value;
        i += 1;
        break;
      case '--token':
        if (value !== undefined) args.token = value;
        i += 1;
        break;
      case '--seed':
        if (value !== undefined) args.seed = Number(value) || 1337;
        i += 1;
        break;
      default:
        break;
    }
  }
  return args;
}

function out(text: string): void {
  process.stdout.write(`${text}\n`);
}

function selected(args: Args): ScenarioResult[] {
  const scenarios = allScenarios({ seed: args.seed });
  if (args.all || args.scenario === undefined) return scenarios;
  const found = scenarios.filter((s) => s.name === args.scenario);
  if (found.length === 0) {
    out(`Unknown scenario "${args.scenario}". Available:`);
    for (const s of scenarios) out(`  ${s.name}`);
    process.exitCode = 1;
    return [];
  }
  return found;
}

function cmdList(args: Args): void {
  out('TalkinShield mock scenarios (all data is synthetic — no Talkin access of any kind):\n');
  for (const scenario of allScenarios({ seed: args.seed })) {
    const marker = scenario.expectClean ? 'CLEAN ' : 'SIGNAL';
    out(`  [${marker}] ${scenario.name}  (${scenario.events.length} events)`);
    out(`            ${scenario.description}`);
    if (scenario.expectedSignals.length > 0) {
      out(`            expects: ${scenario.expectedSignals.join(', ')}`);
    }
    out('');
  }
}

function cmdEmit(args: Args): void {
  const scenarios = selected(args);
  if (scenarios.length === 0) return;

  const events = args.all && args.scenario === undefined
    ? mixedStream({ seed: args.seed })
    : scenarios.flatMap((s) => s.events);

  if (args.format === 'ndjson') {
    for (const event of events) out(JSON.stringify(event));
  } else {
    out(JSON.stringify({ events }, null, 2));
  }
}

async function cmdPost(args: Args): Promise<void> {
  if (args.url === undefined) {
    out('--url is required, e.g. --url https://api.example.com/events');
    process.exitCode = 1;
    return;
  }
  if (args.token === undefined) {
    out('--token is required: the ingestion endpoint requires an authenticated principal.');
    process.exitCode = 1;
    return;
  }

  const scenarios = selected(args);
  if (scenarios.length === 0) return;
  const events = scenarios.flatMap((s) => s.events);

  // Batched to respect INGEST_MAX_BATCH_SIZE.
  const BATCH = 25;
  let accepted = 0;
  let rejected = 0;

  for (let i = 0; i < events.length; i += BATCH) {
    const batch = events.slice(i, i + BATCH);
    const response = await fetch(args.url, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        authorization: `Bearer ${args.token}`,
      },
      body: JSON.stringify({ events: batch }),
    });

    if (!response.ok) {
      out(`Batch ${i / BATCH + 1} failed with HTTP ${response.status}.`);
      rejected += batch.length;
      continue;
    }
    const body = (await response.json()) as { accepted?: number; rejected?: unknown[] };
    accepted += body.accepted ?? 0;
    rejected += Array.isArray(body.rejected) ? body.rejected.length : 0;
  }

  out(`Posted ${events.length} events: ${accepted} accepted, ${rejected} rejected.`);
}

/**
 * Run every scenario through the real pipeline and compare against the
 * scenario's declared expectations.
 */
function cmdVerify(args: Args): void {
  const config = resolveConfig({ client: { knownVersions: ['4.2.1', '4.3.0'] } });
  const lexicon = buildLexicon(config.abuse, config.configVersion);

  let failures = 0;
  out('Running every mock scenario through the detection pipeline.\n');

  for (const scenario of allScenarios({ seed: args.seed })) {
    const states = new Map<string, UserWindowState>();
    const produced = new Set<string>();
    let peakScore = 0;
    let peakLevel = 'LOW';

    for (const raw of scenario.events) {
      const validation = validateEvent(raw, {
        nowMs: Date.parse(raw.timestamp),
        messageContentAuthorized: true,
      });
      if (!validation.ok) {
        out(`  ! ${scenario.name}: a fixture event failed validation — ${validation.issues[0]?.message ?? ''}`);
        failures += 1;
        continue;
      }

      const event = validation.event;
      const state = states.get(event.userId) ?? emptyState(event.userId);
      const result = analyzeEvent({
        event,
        state,
        config,
        capabilities: ALL_CAPS,
        nowMs: event.receivedAtMs,
        lexicon,
      });
      states.set(event.userId, result.nextState);
      for (const signal of result.signals) produced.add(signal.code);
      if (result.assessment.score > peakScore) {
        peakScore = result.assessment.score;
        peakLevel = result.assessment.level;
      }
    }

    // Coordination is an aggregate, room-level detection — it cannot be
    // produced by the per-event pipeline, so the sweep is run separately here,
    // mirroring what the scheduled coordination Lambda does in production.
    for (const signal of coordinationSweep(scenario)) produced.add(signal);

    if (scenario.expectClean) {
      if (produced.size === 0) {
        out(`  PASS  ${scenario.name} — clean, as expected (peak risk ${peakScore}).`);
      } else {
        out(
          `  FAIL  ${scenario.name} — expected no findings but got: ${[...produced].join(', ')}`,
        );
        failures += 1;
      }
      continue;
    }

    const missing = scenario.expectedSignals.filter((code) => !produced.has(code));
    if (missing.length === 0) {
      out(
        `  PASS  ${scenario.name} — peak risk ${peakScore}/100 (${peakLevel}); signals: ${[...produced].join(', ')}`,
      );
    } else {
      out(`  FAIL  ${scenario.name} — missing expected signals: ${missing.join(', ')}`);
      out(`        produced: ${[...produced].join(', ') || '(none)'}`);
      failures += 1;
    }
  }

  out('');
  if (failures === 0) {
    out('All scenarios behaved as expected.');
  } else {
    out(`${failures} scenario(s) did not match expectations.`);
    process.exitCode = 1;
  }
}

/**
 * Aggregate a scenario by room and run the coordination detector over it,
 * mirroring what the scheduled coordination Lambda does in production.
 */
function coordinationSweep(scenario: ScenarioResult): string[] {
  const config = resolveConfig().spam;
  const byRoom = new Map<string, MockEvent[]>();

  for (const raw of scenario.events) {
    const existing = byRoom.get(raw.roomId);
    if (existing) existing.push(raw);
    else byRoom.set(raw.roomId, [raw]);
  }

  const latest = scenario.events.reduce(
    (max, e) => Math.max(max, Date.parse(e.timestamp)),
    0,
  );

  const codes: string[] = [];
  for (const [roomId, roomEvents] of byRoom) {
    const participants = aggregateParticipants(
      roomEvents.map((e) => ({
        userId: e.userId,
        eventType: e.eventType,
        receivedAtMs: Date.parse(e.timestamp),
        ...(e.message !== undefined ? { message: e.message } : {}),
      })),
    );
    const findings = detectCoordination({ roomId, participants, config, nowMs: latest });
    for (const finding of findings) {
      for (const signal of finding.signals) codes.push(signal.code);
    }
  }
  return codes;
}

function cmdHelp(): void {
  out(
    [
      'TalkinShield mock event generator',
      '',
      'All output is synthetic. This tool never contacts Talkin infrastructure.',
      '',
      'Commands:',
      '  list                    Describe the available scenarios',
      '  emit                    Print scenario events as JSON',
      '  post                    POST scenario events to a TalkinShield ingestion endpoint',
      '  verify                  Run every scenario through the detection pipeline and check expectations',
      '',
      'Flags:',
      '  --scenario <name>       Restrict to one scenario',
      '  --all                   Use every scenario (interleaved for `emit`)',
      '  --format json|ndjson    Output shape for `emit` (default json)',
      '  --url <url>             Ingestion endpoint for `post`',
      '  --token <jwt>           Bearer token for `post`',
      "  --seed <n>              PRNG seed for deterministic output (default 1337)",
    ].join('\n'),
  );
}

async function main(): Promise<void> {
  const args = parseArgs(process.argv.slice(2));
  switch (args.command) {
    case 'list':
      cmdList(args);
      break;
    case 'emit':
      cmdEmit(args);
      break;
    case 'post':
      await cmdPost(args);
      break;
    case 'verify':
      cmdVerify(args);
      break;
    default:
      cmdHelp();
      break;
  }
}

await main();

export { main };
