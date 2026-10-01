/**
 * API client.
 *
 * Two modes:
 *   - live: calls the TalkinShield API with the current Cognito access token.
 *   - mock: serves local fixtures, so the console can be developed and
 *     demonstrated with no backend. Set VITE_USE_MOCK_API=true.
 *
 * The mock mode is clearly labelled in the UI; it must never be mistaken for
 * real detection data.
 */

import { currentSession } from '../auth/cognito.ts';
import * as mock from './mock-data.ts';
import type {
  AffordanceResponse,
  AuditRow,
  EventRow,
  EvidenceBundleView,
  Incident,
  Me,
  ModerationResult,
  Overview,
  RulesResponse,
  SettingsResponse,
  SignalRow,
  UserDetail,
  UserSummary,
  VerificationResult,
} from './types.ts';

export const USE_MOCK = import.meta.env.VITE_USE_MOCK_API === 'true';
const BASE_URL = String(import.meta.env.VITE_API_BASE_URL ?? '').replace(/\/+$/, '');

export class ApiError extends Error {
  readonly status: number;
  readonly code: string;
  readonly problems: string[];

  constructor(status: number, code: string, message: string, problems: string[] = []) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.code = code;
    this.problems = problems;
  }
}

async function request<T>(
  method: string,
  path: string,
  options: { body?: unknown; query?: Record<string, string | undefined> } = {},
): Promise<T> {
  const session = currentSession();
  if (session === undefined) {
    throw new ApiError(401, 'UNAUTHENTICATED', 'Your session has expired. Please sign in again.');
  }

  const url = new URL(`${BASE_URL}${path}`);
  for (const [key, value] of Object.entries(options.query ?? {})) {
    if (value !== undefined && value !== '') url.searchParams.set(key, value);
  }

  const headers: Record<string, string> = {
    accept: 'application/json',
    authorization: `Bearer ${session.accessToken}`,
  };
  if (options.body !== undefined) headers['content-type'] = 'application/json';

  const response = await fetch(url.toString(), {
    method,
    headers,
    ...(options.body !== undefined ? { body: JSON.stringify(options.body) } : {}),
  });

  if (response.status === 204) return undefined as T;

  const text = await response.text();
  const payload: unknown = text.length > 0 ? JSON.parse(text) : undefined;

  if (!response.ok) {
    const error = (payload as { error?: { code?: string; message?: string; problems?: string[] } })
      ?.error;
    throw new ApiError(
      response.status,
      error?.code ?? 'UNKNOWN',
      error?.message ?? `Request failed with HTTP ${response.status}.`,
      Array.isArray(error?.problems) ? error.problems : [],
    );
  }

  return payload as T;
}

export const api = {
  me: (): Promise<Me> => (USE_MOCK ? mock.me() : request('GET', '/me')),

  overview: (): Promise<Overview> => (USE_MOCK ? mock.overview() : request('GET', '/overview')),

  events: (query: { userId?: string; roomId?: string; limit?: string } = {}): Promise<{
    events: EventRow[];
    count: number;
  }> => (USE_MOCK ? mock.events(query) : request('GET', '/events', { query })),

  signals: (limit = '100'): Promise<{ signals: SignalRow[]; count: number }> =>
    USE_MOCK ? mock.signals() : request('GET', '/signals', { query: { limit } }),

  users: (limit = '50'): Promise<{ users: UserSummary[]; count: number }> =>
    USE_MOCK ? mock.users() : request('GET', '/users', { query: { limit } }),

  user: (userId: string): Promise<UserDetail> =>
    USE_MOCK ? mock.user(userId) : request('GET', `/users/${encodeURIComponent(userId)}`),

  incidents: (query: { status?: string; userId?: string; limit?: string } = {}): Promise<{
    incidents: Incident[];
    count: number;
  }> => (USE_MOCK ? mock.incidents(query) : request('GET', '/incidents', { query })),

  incident: (incidentId: string): Promise<{ incident: Incident }> =>
    USE_MOCK
      ? mock.incident(incidentId)
      : request('GET', `/incidents/${encodeURIComponent(incidentId)}`),

  updateIncident: (
    incidentId: string,
    body: { status: string; reviewNote: string },
  ): Promise<{ incident: Incident }> =>
    USE_MOCK
      ? mock.updateIncident(incidentId, body)
      : request('PATCH', `/incidents/${encodeURIComponent(incidentId)}`, { body }),

  evidence: (key: string): Promise<{ bundle: EvidenceBundleView; verification: VerificationResult }> =>
    USE_MOCK
      ? mock.evidence(key)
      : request('GET', `/evidence/${key.split('/').map(encodeURIComponent).join('/')}`),

  verifyEvidence: (
    incidentId: string,
  ): Promise<{
    incidentId: string;
    bundleCount: number;
    missing: number;
    chain: VerificationResult;
    bundles: Array<{ key: string; sequence: number; contentHash: string; verification: VerificationResult }>;
  }> =>
    USE_MOCK
      ? mock.verifyEvidence(incidentId)
      : request('POST', '/evidence/verify', { body: { incidentId } }),

  moderate: (body: {
    action: string;
    targetUserId: string;
    roomId?: string;
    reason: string;
    incidentId?: string;
    durationSeconds?: number;
  }): Promise<ModerationResult> =>
    USE_MOCK ? mock.moderate(body) : request('POST', '/moderation', { body }),

  actions: (query: { userId?: string; limit?: string } = {}): Promise<{
    actions: import('./types.ts').ActionRow[];
    count: number;
  }> => (USE_MOCK ? mock.actions(query) : request('GET', '/moderation/actions', { query })),

  affordances: (): Promise<AffordanceResponse> =>
    USE_MOCK ? mock.affordances() : request('GET', '/moderation/affordances'),

  rules: (): Promise<RulesResponse> => (USE_MOCK ? mock.rules() : request('GET', '/rules')),

  saveRules: (overrides: Record<string, unknown>, reason: string): Promise<{ version: string }> =>
    USE_MOCK
      ? mock.saveRules(overrides)
      : request('PUT', '/rules', { body: { overrides, reason } }),

  settings: (): Promise<SettingsResponse> =>
    USE_MOCK ? mock.settings() : request('GET', '/settings'),

  logs: (query: { actorId?: string; limit?: string } = {}): Promise<{
    entries: AuditRow[];
    count: number;
  }> => (USE_MOCK ? mock.logs() : request('GET', '/logs', { query })),
};
