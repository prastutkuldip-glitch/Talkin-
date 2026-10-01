import type { IntegrationCapabilities, TalkinEvent, WindowEntry } from '../src/types/index.ts';
import { fingerprint, countMentions } from '../src/util/text.ts';

export const T0 = Date.parse('2026-03-01T12:00:00.000Z');

export function evt(overrides: Partial<TalkinEvent> = {}): TalkinEvent {
  const timestampMs = overrides.receivedAtMs ?? T0;
  return {
    eventId: overrides.eventId ?? `e-${Math.random().toString(36).slice(2, 10)}`,
    userId: 'user-A',
    roomId: 'ABC123',
    timestamp: new Date(timestampMs).toISOString(),
    receivedAtMs: timestampMs,
    eventType: 'message',
    platform: 'ios',
    clientVersion: '4.2.1',
    metadata: {},
    ...overrides,
  };
}

export function entry(atMs: number, text?: string, overrides: Partial<WindowEntry> = {}): WindowEntry {
  return {
    eventId: `w-${atMs}-${Math.random().toString(36).slice(2, 6)}`,
    atMs,
    eventType: 'message',
    roomId: 'ABC123',
    ...(text !== undefined ? { fingerprint: fingerprint(text), mentions: countMentions(text) } : {}),
    ...overrides,
  };
}

/** Build a window of `count` entries spaced `gapMs` apart, ending at `endMs`. */
export function window(
  count: number,
  gapMs: number,
  endMs: number,
  text?: string,
  overrides: Partial<WindowEntry> = {},
): WindowEntry[] {
  const out: WindowEntry[] = [];
  for (let i = count - 1; i >= 0; i -= 1) {
    out.push(entry(endMs - i * gapMs, text, overrides));
  }
  return out;
}

export const FULL_CAPS: IntegrationCapabilities = {
  messageContent: true,
  moderationEvents: true,
  voiceAudio: true,
  hiddenPresenceEvents: true,
  clientAttestation: true,
  remoteMute: true,
  remoteBlock: true,
};

export const MINIMAL_CAPS: IntegrationCapabilities = {
  messageContent: true,
  moderationEvents: false,
  voiceAudio: false,
  hiddenPresenceEvents: false,
  clientAttestation: false,
  remoteMute: false,
  remoteBlock: false,
};

export function codes(signals: ReadonlyArray<{ code: string }>): string[] {
  return signals.map((s) => s.code).sort();
}

export function hasCode(signals: ReadonlyArray<{ code: string }>, code: string): boolean {
  return signals.some((s) => s.code === code);
}
