/**
 * Mock Talkin event generator.
 *
 * Purpose: exercise every detection path end-to-end WITHOUT connecting to,
 * probing, or in any way touching Talkin's infrastructure. All data here is
 * synthetic.
 *
 * Deterministic by design: a given seed always produces the same stream, so a
 * detection regression shows up as a changed signal set rather than as flaky
 * noise. The scenarios double as the fixture set for tuning thresholds.
 */

import type { EventType, Platform } from '@talkinshield/core';

export interface MockEvent {
  userId: string;
  roomId: string;
  timestamp: string;
  eventType: EventType;
  message?: string;
  clientVersion?: string;
  platform?: Platform;
  metadata?: Record<string, string | number | boolean>;
}

export interface ScenarioResult {
  name: string;
  description: string;
  /** Signal codes this scenario is designed to produce. */
  expectedSignals: string[];
  /** True when the scenario should produce NO signals (false-positive guard). */
  expectClean: boolean;
  events: MockEvent[];
}

/**
 * Small deterministic PRNG (mulberry32). Avoids a dependency and guarantees the
 * same stream for the same seed across platforms and Node versions.
 */
export function createRandom(seed: number): () => number {
  let state = seed >>> 0;
  return () => {
    state = (state + 0x6d2b79f5) >>> 0;
    let t = state;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const OFFICIAL_VERSIONS = ['4.2.1', '4.3.0'];
const PLATFORMS: Platform[] = ['ios', 'android', 'web', 'desktop'];

const BENIGN_MESSAGES = [
  'hey everyone, good to be here',
  'anyone up for a game later?',
  'that last round was wild',
  'brb, getting coffee',
  'gg all, well played',
  'can you hear me okay?',
  'my mic was muted, sorry',
  'what time does the event start?',
  'joining from Berlin, hi all',
  'nice one! that was clean',
  'I disagree but I see your point',
  'lol that was unexpected',
  'ah shit, I missed the shot', // undirected profanity: must not escalate
  'he called me an idiot earlier, just so mods know', // reported speech
  "I'd never hurt anyone, that's not me", // negated intent
  "I'll destroy you in the next round haha", // gaming banter
];

export interface GeneratorOptions {
  seed?: number;
  startMs?: number;
  roomId?: string;
}

/** One scenario per detection family, plus explicit false-positive guards. */
export function allScenarios(options: GeneratorOptions = {}): ScenarioResult[] {
  return [
    benignConversation(options),
    messageSpamBurst(options),
    identicalMessageFlood(options),
    botUniformTiming(options),
    templateSpam(options),
    mentionFlood(options),
    obfuscatedAbuse(options),
    targetedAbuse(options),
    threatLanguage(options),
    suspiciousClient(options),
    impossibleSequence(options),
    coordinatedBrigade(options),
    moderationEvasion(options),
    voiceTranscriptAbuse(options),
    quietRoom(options),
  ];
}

function base(options: GeneratorOptions) {
  return {
    seed: options.seed ?? 1337,
    startMs: options.startMs ?? Date.parse('2026-03-01T12:00:00.000Z'),
    roomId: options.roomId ?? 'ABC123',
  };
}

function iso(ms: number): string {
  return new Date(ms).toISOString();
}

// --- Clean scenarios (false-positive guards) -------------------------------

export function benignConversation(options: GeneratorOptions = {}): ScenarioResult {
  const { seed, startMs, roomId } = base(options);
  const rand = createRandom(seed);
  const events: MockEvent[] = [];
  let at = startMs;

  // Each participant keeps ONE client version and platform for the session,
  // as a genuine client does. Randomising these per message would (correctly)
  // trip the client-integrity detector and make this fixture meaningless.
  const participants = [1, 2, 3, 4].map((n) => ({
    userId: `human-${n}`,
    clientVersion: OFFICIAL_VERSIONS[n % OFFICIAL_VERSIONS.length] as string,
    platform: PLATFORMS[n % PLATFORMS.length] as Platform,
  }));

  for (let i = 0; i < 25; i += 1) {
    // Human cadence: highly irregular, 3-45s gaps.
    at += 3000 + Math.floor(rand() * 42_000);
    const who = participants[Math.floor(rand() * participants.length)] as (typeof participants)[number];
    events.push({
      userId: who.userId,
      roomId,
      timestamp: iso(at),
      eventType: 'message',
      message: BENIGN_MESSAGES[Math.floor(rand() * BENIGN_MESSAGES.length)] as string,
      clientVersion: who.clientVersion,
      platform: who.platform,
      metadata: { region: 'eu-west-1' },
    });
  }

  return {
    name: 'benign-conversation',
    description:
      'Ordinary multi-user conversation at human cadence, including undirected profanity, reported speech, negated intent and in-game banter. Must produce no findings.',
    expectedSignals: [],
    expectClean: true,
    events,
  };
}

export function quietRoom(options: GeneratorOptions = {}): ScenarioResult {
  const { startMs, roomId } = base(options);
  const events: MockEvent[] = [];
  let at = startMs;

  // Evenly spaced but very slow — must NOT trip the bot-timing heuristic,
  // because the mean gap exceeds the configured ceiling.
  for (let i = 0; i < 10; i += 1) {
    at += 120_000;
    events.push({
      userId: 'slow-talker',
      roomId,
      timestamp: iso(at),
      eventType: 'message',
      message: `checking in, message ${i}`,
      clientVersion: '4.2.1',
      platform: 'ios',
    });
  }

  return {
    name: 'quiet-room',
    description:
      'Regularly spaced but very infrequent messages. Guards against flagging a slow, orderly channel as automated.',
    expectedSignals: [],
    expectClean: true,
    events,
  };
}

// --- Spam & automation -----------------------------------------------------

export function messageSpamBurst(options: GeneratorOptions = {}): ScenarioResult {
  const { startMs, roomId } = base(options);
  const events: MockEvent[] = [];
  let at = startMs;

  // 12 messages in ~5 seconds.
  for (let i = 0; i < 12; i += 1) {
    at += 420;
    events.push({
      userId: 'burst-sender',
      roomId,
      timestamp: iso(at),
      eventType: 'message',
      message: `look at this ${i}`,
      clientVersion: '4.2.1',
      platform: 'web',
    });
  }

  return {
    name: 'message-spam-burst',
    description: 'Twelve messages inside five seconds — the brief\'s burst example.',
    expectedSignals: ['SPAM_BURST'],
    expectClean: false,
    events,
  };
}

export function identicalMessageFlood(options: GeneratorOptions = {}): ScenarioResult {
  const { startMs, roomId } = base(options);
  const events: MockEvent[] = [];
  let at = startMs;
  const text = 'FREE CRYPTO GIVEAWAY CLICK THE LINK IN MY BIO NOW';

  for (let i = 0; i < 50; i += 1) {
    at += 1100;
    events.push({
      userId: 'crypto-spammer',
      roomId,
      timestamp: iso(at),
      eventType: 'message',
      // Punctuation jitter, to prove normalization defeats it.
      message: i % 3 === 0 ? `${text}!!!` : i % 3 === 1 ? text.toLowerCase() : `${text}...`,
      clientVersion: '4.2.1',
      platform: 'android',
    });
  }

  return {
    name: 'identical-message-flood',
    description:
      'Fifty identical messages with punctuation and case jitter — the brief\'s high-risk example.',
    expectedSignals: ['SPAM_IDENTICAL_REPEAT', 'SPAM_HIGH_FREQUENCY', 'BOT_UNIFORM_TIMING'],
    expectClean: false,
    events,
  };
}

export function botUniformTiming(options: GeneratorOptions = {}): ScenarioResult {
  const { startMs, roomId } = base(options);
  const events: MockEvent[] = [];
  let at = startMs;

  // Exactly 2000ms apart, varied content: timing alone is the tell.
  for (let i = 0; i < 20; i += 1) {
    at += 2000;
    events.push({
      userId: 'scripted-bot',
      roomId,
      timestamp: iso(at),
      eventType: 'message',
      message: `automated status report number ${i} for this channel`,
      clientVersion: '4.3.0',
      platform: 'web',
    });
  }

  return {
    name: 'bot-uniform-timing',
    description:
      'Varied content posted on a precise two-second cadence. Content looks fine; the machine-like interval is the signal.',
    expectedSignals: ['BOT_UNIFORM_TIMING'],
    expectClean: false,
    events,
  };
}

export function templateSpam(options: GeneratorOptions = {}): ScenarioResult {
  const { startMs, roomId } = base(options);
  const events: MockEvent[] = [];
  let at = startMs;

  for (let i = 0; i < 10; i += 1) {
    at += 2500;
    events.push({
      userId: 'template-spammer',
      roomId,
      timestamp: iso(at),
      eventType: 'message',
      message: `win a prize now visit our site reference number ${1111 * (i + 1)}`,
      clientVersion: '4.2.1',
      platform: 'ios',
    });
  }

  return {
    name: 'template-spam',
    description: 'One template with a mutating reference number, to defeat exact-match detection.',
    expectedSignals: ['SPAM_NEAR_DUPLICATE'],
    expectClean: false,
    events,
  };
}

export function mentionFlood(options: GeneratorOptions = {}): ScenarioResult {
  const { startMs, roomId } = base(options);
  return {
    name: 'mention-flood',
    description: 'A single message mentioning many participants at once.',
    expectedSignals: ['SPAM_MENTION_FLOOD'],
    expectClean: false,
    events: [
      {
        userId: 'mention-spammer',
        roomId,
        timestamp: iso(startMs + 1000),
        eventType: 'message',
        message: '@alice @bob @carol @dave @erin @frank @grace @heidi check out my stream',
        clientVersion: '4.2.1',
        platform: 'web',
      },
    ],
  };
}

// --- Abuse -----------------------------------------------------------------

export function targetedAbuse(options: GeneratorOptions = {}): ScenarioResult {
  const { startMs, roomId } = base(options);
  const events: MockEvent[] = [];
  let at = startMs;
  const lines = [
    'you are a fucking idiot',
    'shut up you bitch',
    'you absolute fucking waste of space',
    'nobody wants you here you prick',
  ];

  for (const [i, line] of lines.entries()) {
    at += 4000 + i * 1500;
    events.push({
      userId: 'abuser-1',
      roomId,
      timestamp: iso(at),
      eventType: 'message',
      message: line,
      clientVersion: '4.2.1',
      platform: 'ios',
    });
  }

  return {
    name: 'targeted-abuse',
    description: 'Repeated profanity aimed directly at another participant.',
    expectedSignals: ['ABUSE_LANGUAGE', 'ABUSE_TARGETED_HARASSMENT', 'ABUSE_REPEATED'],
    expectClean: false,
    events,
  };
}

export function obfuscatedAbuse(options: GeneratorOptions = {}): ScenarioResult {
  const { startMs, roomId } = base(options);
  return {
    name: 'obfuscated-abuse',
    description:
      'Abuse disguised with zero-width characters, homoglyphs, leetspeak and letter spacing — tests the normalizer and the evasion signal.',
    expectedSignals: ['ABUSE_LANGUAGE', 'EVASION_FILTER_OBFUSCATION', 'SPAM_SUSPICIOUS_CHARACTERS'],
    expectClean: false,
    events: [
      {
        userId: 'evader-1',
        roomId,
        timestamp: iso(startMs + 1000),
        eventType: 'message',
        message: 'you are a f\u200Bucking a$$hole',
        clientVersion: '4.2.1',
        platform: 'web',
      },
      {
        userId: 'evader-1',
        roomId,
        timestamp: iso(startMs + 9000),
        eventType: 'message',
        message: 'y o u   a r e   a   b i t c h',
        clientVersion: '4.2.1',
        platform: 'web',
      },
      {
        userId: 'evader-1',
        roomId,
        timestamp: iso(startMs + 21_000),
        eventType: 'message',
        // Cyrillic homoglyphs.
        message: 'shut up you bіtсh',
        clientVersion: '4.2.1',
        platform: 'web',
      },
    ],
  };
}

export function threatLanguage(options: GeneratorOptions = {}): ScenarioResult {
  const { startMs, roomId } = base(options);
  const lines = [
    'i am going to kill you when i find you',
    'i know where you live',
    'im coming to your house tomorrow',
    'i will leak your address if you dont stop',
  ];

  return {
    name: 'threat-language',
    description:
      'Credible threats: direct violence, location intimidation and a doxxing threat. Highest-weight deterministic detection.',
    expectedSignals: ['THREAT_LANGUAGE'],
    expectClean: false,
    events: lines.map((message, i) => ({
      userId: 'threat-actor',
      roomId,
      timestamp: iso(startMs + (i + 1) * 20_000),
      eventType: 'message' as EventType,
      message,
      clientVersion: '4.2.1',
      platform: 'android' as Platform,
    })),
  };
}

export function voiceTranscriptAbuse(options: GeneratorOptions = {}): ScenarioResult {
  const { startMs, roomId } = base(options);
  return {
    name: 'voice-transcript-abuse',
    description:
      'Abuse arriving as a voice transcript. Only meaningful when an authorized, consented audio integration is configured; otherwise the system reports the capability as unavailable.',
    expectedSignals: ['ABUSE_LANGUAGE', 'ABUSE_TARGETED_HARASSMENT'],
    expectClean: false,
    events: [
      {
        userId: 'voice-abuser',
        roomId,
        timestamp: iso(startMs + 5000),
        eventType: 'voice',
        message: 'you are a complete fucking idiot and everyone here knows it',
        clientVersion: '4.2.1',
        platform: 'ios',
        metadata: { transcriptConfidence: 0.91, durationSeconds: 4 },
      },
    ],
  };
}

// --- Client integrity ------------------------------------------------------

export function suspiciousClient(options: GeneratorOptions = {}): ScenarioResult {
  const { startMs, roomId } = base(options);
  const events: MockEvent[] = [];
  let at = startMs;
  const versions = ['4.2.1', 'custom-build-x', '9.9.9-mod', 'totally-not-official'];

  for (let i = 0; i < 12; i += 1) {
    at += 3000;
    events.push({
      userId: 'modded-client-user',
      roomId,
      timestamp: iso(at),
      eventType: 'message',
      message: `message from an unusual client ${i}`,
      clientVersion: versions[i % versions.length] as string,
      // Platform also flaps, which no genuine client does mid-session.
      platform: (i % 2 === 0 ? 'ios' : 'android') as Platform,
    });
  }

  return {
    name: 'suspicious-client',
    description:
      'Declared client version and platform both change mid-session, with unrecognised version strings. Passive telemetry analysis only — nothing is sent to the client.',
    expectedSignals: ['CLIENT_UNKNOWN_VERSION', 'CLIENT_VERSION_FLAPPING', 'CLIENT_PLATFORM_MISMATCH'],
    expectClean: false,
    events,
  };
}

export function impossibleSequence(options: GeneratorOptions = {}): ScenarioResult {
  const { startMs, roomId } = base(options);
  const events: MockEvent[] = [];
  let at = startMs;

  for (let i = 0; i < 8; i += 1) {
    at += 6000;
    events.push({
      userId: 'sequence-breaker',
      roomId,
      timestamp: iso(at),
      eventType: 'message',
      message: `normal chatter ${i}`,
      clientVersion: '4.2.1',
      platform: 'ios',
    });
  }

  at += 5000;
  events.push({
    userId: 'sequence-breaker',
    roomId,
    timestamp: iso(at),
    eventType: 'leave',
    clientVersion: '4.2.1',
    platform: 'ios',
  });

  // Messaging a room long after leaving it, with no rejoin.
  at += 60_000;
  events.push({
    userId: 'sequence-breaker',
    roomId,
    timestamp: iso(at),
    eventType: 'message',
    message: 'still here somehow',
    clientVersion: '4.2.1',
    platform: 'ios',
  });

  return {
    name: 'impossible-sequence',
    description:
      'A message sent a minute after leaving the room with no intervening join — an ordering the official client cannot produce.',
    expectedSignals: ['CLIENT_IMPOSSIBLE_SEQUENCE'],
    expectClean: false,
    events,
  };
}

// --- Coordination & evasion ------------------------------------------------

export function coordinatedBrigade(options: GeneratorOptions = {}): ScenarioResult {
  const { startMs, roomId } = base(options);
  const events: MockEvent[] = [];
  const text = 'this streamer is a scammer do not trust them with your money';

  // Six accounts join one second apart, then post identical content.
  for (let i = 0; i < 6; i += 1) {
    events.push({
      userId: `brigade-${i}`,
      roomId,
      timestamp: iso(startMs + i * 1000),
      eventType: 'join',
      clientVersion: '4.2.1',
      platform: 'web',
    });
  }
  for (let i = 0; i < 6; i += 1) {
    events.push({
      userId: `brigade-${i}`,
      roomId,
      timestamp: iso(startMs + 10_000 + i * 1500),
      eventType: 'message',
      message: text,
      clientVersion: '4.2.1',
      platform: 'web',
    });
  }

  return {
    name: 'coordinated-brigade',
    description:
      'Six accounts entering on a fixed cadence and posting identical content. Reported as correlated behaviour only — no claim is made that the accounts share an operator.',
    expectedSignals: ['COORDINATED_IDENTICAL_CONTENT', 'COORDINATED_SYNCHRONIZED_JOINS'],
    expectClean: false,
    events,
  };
}

export function moderationEvasion(options: GeneratorOptions = {}): ScenarioResult {
  const { startMs, roomId } = base(options);
  const events: MockEvent[] = [];
  let at = startMs;

  // Leave/rejoin cycling to reset room-scoped state.
  for (let i = 0; i < 6; i += 1) {
    events.push({
      userId: 'evasive-user',
      roomId,
      timestamp: iso(at),
      eventType: 'join',
      clientVersion: '4.2.1',
      platform: 'android',
    });
    at += 12_000;
    events.push({
      userId: 'evasive-user',
      roomId,
      timestamp: iso(at),
      eventType: 'message',
      message: 'back again, you cant stop me',
      clientVersion: '4.2.1',
      platform: 'android',
    });
    at += 8000;
    events.push({
      userId: 'evasive-user',
      roomId,
      timestamp: iso(at),
      eventType: 'leave',
      clientVersion: '4.2.1',
      platform: 'android',
    });
    at += 5000;
  }

  return {
    name: 'moderation-evasion',
    description:
      'Repeated leave/rejoin cycling. Requires the platform moderation-events capability; without it the system reports insufficient authorized telemetry rather than guessing.',
    expectedSignals: ['EVASION_REJOIN_CYCLING'],
    expectClean: false,
    events,
  };
}

// --- Aggregate stream ------------------------------------------------------

/**
 * Interleave every scenario into one chronologically ordered stream, as a real
 * firehose would arrive. Useful for load-shape testing and dashboard demos.
 */
export function mixedStream(options: GeneratorOptions = {}): MockEvent[] {
  const scenarios = allScenarios(options);
  const all = scenarios.flatMap((s) => s.events);
  return all.sort((a, b) => Date.parse(a.timestamp) - Date.parse(b.timestamp));
}

/** Synthetic hidden-presence records, for exercising ghost-mode correlation. */
export function hiddenPresenceFixture(options: GeneratorOptions = {}): Array<{
  userId: string;
  roomId: string;
  atMs: number;
  kind: 'HIDDEN_JOIN' | 'HIDDEN_LEAVE' | 'HIDDEN_PRESENT';
  mode?: string;
}> {
  const { startMs, roomId } = base(options);
  return [
    { userId: 'ghost-user-1', roomId, atMs: startMs + 5000, kind: 'HIDDEN_JOIN', mode: 'invisible' },
    { userId: 'ghost-user-1', roomId, atMs: startMs + 90_000, kind: 'HIDDEN_PRESENT', mode: 'invisible' },
  ];
}

/** Events attributable to the hidden user above, for correlation. */
export function ghostCorrelationEvents(options: GeneratorOptions = {}): MockEvent[] {
  const { startMs, roomId } = base(options);
  return [20_000, 45_000, 70_000].map((offset) => ({
    userId: 'ghost-user-1',
    roomId,
    timestamp: iso(startMs + offset),
    eventType: 'message' as EventType,
    message: 'posting while hidden',
    clientVersion: '4.2.1',
    platform: 'web' as Platform,
  }));
}
