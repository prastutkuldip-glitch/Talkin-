/**
 * Talkin platform adapters.
 *
 * THE AUTHORIZATION BOUNDARY LIVES HERE.
 *
 * Three implementations, all satisfying the same contract:
 *
 *   - `NoopTalkinAdapter`   — no integration. Every capability is false, every
 *                             action returns `unsupported`. This is the default,
 *                             so an unconfigured deployment is safe and honest.
 *   - `MockTalkinAdapter`   — deterministic local fixture for development and
 *                             tests. Refuses to run when STAGE=prod.
 *   - `HttpTalkinAdapter`   — the real official Talkin moderation API. Requires
 *                             credentials from Secrets Manager.
 *
 * Invariants every implementation must preserve:
 *
 *   1. A capability that is false means the corresponding method returns
 *      `{ ok: false, unsupported: true, reason }`. It must NEVER fall back to
 *      another mechanism to achieve the effect.
 *   2. No method may contact a participant's device, probe a client, or access
 *      anything beyond the documented official API surface.
 *   3. `getHiddenPresence` returns data only when the platform discloses it.
 *      No inference, enumeration, or private-API access.
 */

import type {
  HiddenPresenceRecord,
  IntegrationCapabilities,
  ModerationRestriction,
} from '@talkinshield/core';
import { NO_CAPABILITIES } from '@talkinshield/core';

import type { Logger, PlatformActionResult, SecretProvider, TalkinPlatformAdapter } from '../../ports.ts';

const UNSUPPORTED = (capability: string): PlatformActionResult => ({
  ok: false,
  unsupported: true,
  reason:
    `No official Talkin ${capability} API is configured for this deployment. ` +
    'TalkinShield will not attempt this action by any other means. ' +
    'Use the local protections available to the protected user instead (local mute, block, ignore, report, evidence capture).',
});

// ---------------------------------------------------------------------------
// Noop — the safe default
// ---------------------------------------------------------------------------

export class NoopTalkinAdapter implements TalkinPlatformAdapter {
  readonly name = 'none (no platform integration configured)';

  capabilities(): IntegrationCapabilities {
    return { ...NO_CAPABILITIES };
  }

  async getRestrictions(): Promise<readonly ModerationRestriction[]> {
    return [];
  }

  async getHiddenPresence(): Promise<readonly HiddenPresenceRecord[]> {
    // No capability => no data. Callers render "Insufficient authorized telemetry."
    return [];
  }

  async verifyClient(): Promise<undefined> {
    return undefined;
  }

  async mute(): Promise<PlatformActionResult> {
    return UNSUPPORTED('mute');
  }

  async block(): Promise<PlatformActionResult> {
    return UNSUPPORTED('block');
  }

  async report(): Promise<PlatformActionResult> {
    return {
      ok: false,
      unsupported: true,
      reason:
        'No official Talkin reporting endpoint is configured. The evidence bundle has still been preserved and can be submitted manually.',
    };
  }
}

// ---------------------------------------------------------------------------
// Mock — development and tests
// ---------------------------------------------------------------------------

export interface MockState {
  restrictions: Map<string, ModerationRestriction[]>;
  hiddenPresence: HiddenPresenceRecord[];
  attestationFailures: Set<string>;
  muted: Array<{ userId: string; roomId: string; until: number; reason: string }>;
  blocked: Array<{ userId: string; roomId?: string; until: number; reason: string }>;
  reports: Array<{ userId: string; reason: string; evidenceKeys: readonly string[] }>;
}

export function emptyMockState(): MockState {
  return {
    restrictions: new Map(),
    hiddenPresence: [],
    attestationFailures: new Set(),
    muted: [],
    blocked: [],
    reports: [],
  };
}

export class MockTalkinAdapter implements TalkinPlatformAdapter {
  readonly name = 'mock (local fixture — not a real integration)';
  readonly state: MockState;
  private readonly granted: IntegrationCapabilities;
  private readonly clock: { now(): number };

  constructor(
    granted: IntegrationCapabilities,
    clock: { now(): number },
    state: MockState = emptyMockState(),
    stage = 'dev',
  ) {
    if (stage === 'prod') {
      throw new Error(
        'MockTalkinAdapter must not be used when STAGE=prod: it fabricates platform responses.',
      );
    }
    this.granted = granted;
    this.clock = clock;
    this.state = state;
  }

  capabilities(): IntegrationCapabilities {
    return { ...this.granted };
  }

  async getRestrictions(userId: string, roomId?: string): Promise<readonly ModerationRestriction[]> {
    if (!this.granted.moderationEvents) return [];
    const all = this.state.restrictions.get(userId) ?? [];
    return roomId === undefined
      ? all
      : all.filter((r) => r.roomId === undefined || r.roomId === roomId);
  }

  async getHiddenPresence(roomId: string, sinceMs: number): Promise<readonly HiddenPresenceRecord[]> {
    // Capability gate first — this is the invariant that matters most.
    if (!this.granted.hiddenPresenceEvents) return [];
    return this.state.hiddenPresence.filter((h) => h.roomId === roomId && h.atMs >= sinceMs);
  }

  async verifyClient(
    userId: string,
    clientVersion: string | undefined,
  ): Promise<{ verified: boolean; detail?: string } | undefined> {
    if (!this.granted.clientAttestation) return undefined;
    if (this.state.attestationFailures.has(userId)) {
      return { verified: false, detail: 'mock attestation marked this account as failing' };
    }
    return {
      verified: true,
      ...(clientVersion !== undefined ? { detail: `attested build ${clientVersion}` } : {}),
    };
  }

  async mute(input: {
    userId: string;
    roomId: string;
    durationSeconds: number;
    reason: string;
  }): Promise<PlatformActionResult> {
    if (!this.granted.remoteMute) return UNSUPPORTED('mute');
    this.state.muted.push({
      userId: input.userId,
      roomId: input.roomId,
      until: this.clock.now() + input.durationSeconds * 1000,
      reason: input.reason,
    });
    return { ok: true, reference: `mock-mute-${this.state.muted.length}` };
  }

  async block(input: {
    userId: string;
    roomId?: string;
    durationSeconds: number;
    reason: string;
  }): Promise<PlatformActionResult> {
    if (!this.granted.remoteBlock) return UNSUPPORTED('block');
    this.state.blocked.push({
      userId: input.userId,
      ...(input.roomId !== undefined ? { roomId: input.roomId } : {}),
      until: this.clock.now() + input.durationSeconds * 1000,
      reason: input.reason,
    });
    return { ok: true, reference: `mock-block-${this.state.blocked.length}` };
  }

  async report(input: {
    userId: string;
    reason: string;
    evidenceKeys: readonly string[];
  }): Promise<PlatformActionResult> {
    this.state.reports.push({
      userId: input.userId,
      reason: input.reason,
      evidenceKeys: input.evidenceKeys,
    });
    return { ok: true, reference: `mock-report-${this.state.reports.length}` };
  }
}

// ---------------------------------------------------------------------------
// HTTP — the real official integration
// ---------------------------------------------------------------------------

export interface HttpAdapterConfig {
  baseUrl: string;
  secretName: string;
  timeoutMs: number;
  capabilities: IntegrationCapabilities;
}

/**
 * Calls the official Talkin moderation API.
 *
 * The API shape below is a placeholder that matches the capability model. When
 * Talkin publishes (or you are granted) the real contract, change only the
 * paths, payloads and response parsing in this file — see
 * `docs/AUTHORIZATION_BOUNDARY.md` for the checklist of what each endpoint must
 * be authorized to do before enabling the corresponding capability flag.
 */
export class HttpTalkinAdapter implements TalkinPlatformAdapter {
  readonly name = 'official Talkin moderation API';
  private token: string | undefined;
  private readonly config: HttpAdapterConfig;
  private readonly secrets: SecretProvider;
  private readonly logger: Logger;
  private readonly fetchImpl: typeof fetch;

  constructor(
    config: HttpAdapterConfig,
    secrets: SecretProvider,
    logger: Logger,
    fetchImpl: typeof fetch = fetch,
  ) {
    this.config = config;
    this.secrets = secrets;
    this.logger = logger;
    this.fetchImpl = fetchImpl;
  }

  capabilities(): IntegrationCapabilities {
    return { ...this.config.capabilities };
  }

  private async authHeader(): Promise<Record<string, string>> {
    if (this.token === undefined) {
      const secret = await this.secrets.get(this.config.secretName);
      if (secret === undefined) {
        throw new Error(
          `Talkin API credentials not found in Secrets Manager under "${this.config.secretName}".`,
        );
      }
      // Accept either a bare token or a JSON secret with a `token` field.
      try {
        const parsed: unknown = JSON.parse(secret);
        this.token =
          typeof parsed === 'object' && parsed !== null && 'token' in parsed
            ? String((parsed as { token: unknown }).token)
            : secret;
      } catch {
        this.token = secret;
      }
    }
    return { authorization: `Bearer ${this.token}` };
  }

  private async call<T>(
    method: string,
    path: string,
    body?: unknown,
  ): Promise<{ ok: true; data: T } | { ok: false; reason: string }> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.config.timeoutMs);
    try {
      const headers: Record<string, string> = {
        ...(await this.authHeader()),
        accept: 'application/json',
      };
      if (body !== undefined) headers['content-type'] = 'application/json';

      const response = await this.fetchImpl(`${this.config.baseUrl}${path}`, {
        method,
        headers,
        ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
        signal: controller.signal,
      });

      if (!response.ok) {
        // Never log or surface the response body verbatim — it may echo content.
        return {
          ok: false,
          reason: `Talkin API returned HTTP ${response.status}.`,
        };
      }
      const data = (await response.json()) as T;
      return { ok: true, data };
    } catch (err: unknown) {
      const reason =
        err instanceof Error && err.name === 'AbortError'
          ? `Talkin API call timed out after ${this.config.timeoutMs}ms.`
          : `Talkin API call failed: ${err instanceof Error ? err.message : String(err)}`;
      this.logger.warn('Talkin API call failed.', { path, method });
      return { ok: false, reason };
    } finally {
      clearTimeout(timer);
    }
  }

  async getRestrictions(userId: string, roomId?: string): Promise<readonly ModerationRestriction[]> {
    if (!this.config.capabilities.moderationEvents) return [];
    const query = roomId !== undefined ? `?roomId=${encodeURIComponent(roomId)}` : '';
    const result = await this.call<{ restrictions?: unknown[] }>(
      'GET',
      `/moderation/users/${encodeURIComponent(userId)}/restrictions${query}`,
    );
    if (!result.ok) return [];
    return parseRestrictions(result.data.restrictions);
  }

  async getHiddenPresence(roomId: string, sinceMs: number): Promise<readonly HiddenPresenceRecord[]> {
    // Hard gate: without the granted capability we do not even issue the call.
    if (!this.config.capabilities.hiddenPresenceEvents) return [];
    const result = await this.call<{ presence?: unknown[] }>(
      'GET',
      `/rooms/${encodeURIComponent(roomId)}/hidden-presence?since=${sinceMs}`,
    );
    if (!result.ok) return [];
    return parseHiddenPresence(result.data.presence, roomId);
  }

  async verifyClient(
    userId: string,
    clientVersion: string | undefined,
  ): Promise<{ verified: boolean; detail?: string } | undefined> {
    if (!this.config.capabilities.clientAttestation) return undefined;
    const result = await this.call<{ verified?: unknown; detail?: unknown }>(
      'POST',
      '/attestation/verify',
      { userId, clientVersion },
    );
    if (!result.ok) return undefined; // Unknown, not failed.
    return {
      verified: result.data.verified === true,
      ...(typeof result.data.detail === 'string' ? { detail: result.data.detail } : {}),
    };
  }

  async mute(input: {
    userId: string;
    roomId: string;
    durationSeconds: number;
    reason: string;
  }): Promise<PlatformActionResult> {
    if (!this.config.capabilities.remoteMute) return UNSUPPORTED('mute');
    const result = await this.call<{ reference?: unknown }>('POST', '/moderation/mute', {
      userId: input.userId,
      roomId: input.roomId,
      durationSeconds: input.durationSeconds,
      reason: input.reason,
    });
    if (!result.ok) return { ok: false, unsupported: false, reason: result.reason };
    return {
      ok: true,
      ...(typeof result.data.reference === 'string' ? { reference: result.data.reference } : {}),
    };
  }

  async block(input: {
    userId: string;
    roomId?: string;
    durationSeconds: number;
    reason: string;
  }): Promise<PlatformActionResult> {
    if (!this.config.capabilities.remoteBlock) return UNSUPPORTED('block');
    const result = await this.call<{ reference?: unknown }>('POST', '/moderation/block', {
      userId: input.userId,
      roomId: input.roomId,
      durationSeconds: input.durationSeconds,
      reason: input.reason,
    });
    if (!result.ok) return { ok: false, unsupported: false, reason: result.reason };
    return {
      ok: true,
      ...(typeof result.data.reference === 'string' ? { reference: result.data.reference } : {}),
    };
  }

  async report(input: {
    userId: string;
    roomId?: string;
    reason: string;
    evidenceKeys: readonly string[];
  }): Promise<PlatformActionResult> {
    const result = await this.call<{ reference?: unknown }>('POST', '/reports', {
      userId: input.userId,
      roomId: input.roomId,
      reason: input.reason,
      // Only opaque storage keys are shared, never the evidence content.
      evidenceReferences: input.evidenceKeys,
    });
    if (!result.ok) return { ok: false, unsupported: false, reason: result.reason };
    return {
      ok: true,
      ...(typeof result.data.reference === 'string' ? { reference: result.data.reference } : {}),
    };
  }
}

// --- Defensive parsing of platform responses -------------------------------
// Platform responses are untrusted input and are validated like any other.

function parseRestrictions(raw: unknown): ModerationRestriction[] {
  if (!Array.isArray(raw)) return [];
  const kinds = ['MUTE', 'KICK', 'BAN', 'SUSPEND', 'UNKNOWN'] as const;
  const out: ModerationRestriction[] = [];
  for (const item of raw.slice(0, 100)) {
    if (typeof item !== 'object' || item === null) continue;
    const r = item as Record<string, unknown>;
    const appliedAtMs = toMs(r.appliedAt ?? r.appliedAtMs);
    if (appliedAtMs === undefined) continue;
    const kind = kinds.includes(r.kind as (typeof kinds)[number])
      ? (r.kind as (typeof kinds)[number])
      : 'UNKNOWN';
    const expiresAtMs = toMs(r.expiresAt ?? r.expiresAtMs);
    out.push({
      appliedAtMs,
      kind,
      ...(typeof r.roomId === 'string' ? { roomId: r.roomId } : {}),
      ...(expiresAtMs !== undefined ? { expiresAtMs } : {}),
    });
  }
  return out;
}

function parseHiddenPresence(raw: unknown, roomId: string): HiddenPresenceRecord[] {
  if (!Array.isArray(raw)) return [];
  const kinds = ['HIDDEN_JOIN', 'HIDDEN_LEAVE', 'HIDDEN_PRESENT'] as const;
  const out: HiddenPresenceRecord[] = [];
  for (const item of raw.slice(0, 500)) {
    if (typeof item !== 'object' || item === null) continue;
    const r = item as Record<string, unknown>;
    const atMs = toMs(r.at ?? r.atMs);
    if (atMs === undefined || typeof r.userId !== 'string') continue;
    out.push({
      userId: r.userId,
      roomId: typeof r.roomId === 'string' ? r.roomId : roomId,
      atMs,
      kind: kinds.includes(r.kind as (typeof kinds)[number])
        ? (r.kind as (typeof kinds)[number])
        : 'HIDDEN_PRESENT',
      ...(typeof r.mode === 'string' ? { mode: r.mode } : {}),
    });
  }
  return out;
}

function toMs(value: unknown): number | undefined {
  if (typeof value === 'number' && Number.isFinite(value)) return value;
  if (typeof value === 'string') {
    const parsed = Date.parse(value);
    if (!Number.isNaN(parsed)) return parsed;
    const asNumber = Number(value);
    if (Number.isFinite(asNumber)) return asNumber;
  }
  return undefined;
}
