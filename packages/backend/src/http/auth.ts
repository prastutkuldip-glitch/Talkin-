/**
 * Authentication and authorization.
 *
 * Trust model:
 *   - API Gateway fronts every route with a Cognito JWT authorizer, which
 *     performs signature verification, issuer validation and expiry checks.
 *     A request that reaches this code has already passed those.
 *   - The checks below are defence in depth: they re-validate the claims we
 *     depend on for authorization decisions, so a misconfigured authorizer
 *     (or a future direct-invoke path) cannot silently grant access.
 *   - Roles derive from Cognito groups. Group membership is the single source
 *     of truth; nothing is inferred from a client-supplied header.
 *
 * MFA-ready: `assuranceLevel` reads the standard `amr` claim. When
 * `requireMfaForDestructive` is enabled, actions that affect another account
 * require a multi-factor session. The system works without MFA configured, but
 * enabling it requires no code change.
 */

import type { ApiRequest } from './types.ts';

export const ROLES = ['ADMIN', 'MODERATOR', 'VIEWER', 'SERVICE'] as const;
export type Role = (typeof ROLES)[number];

export interface Principal {
  /** Cognito `sub`. The stable actor id written to the audit log. */
  subject: string;
  username: string;
  roles: Role[];
  groups: string[];
  /** True when the session was established with more than one factor. */
  mfaPresent: boolean;
  /** `client_id` of the app client that issued the token. */
  clientId?: string;
  tokenUse?: string;
  expiresAtMs?: number;
}

export interface AuthConfig {
  userPoolId: string;
  /** App client ids permitted to call this API. Empty disables the check. */
  allowedClientIds: string[];
  region: string;
  moderatorGroups: string[];
  adminGroups: string[];
  /** Cognito groups permitted to submit telemetry to the ingestion endpoint. */
  serviceGroups: string[];
  /** Require an MFA session for actions affecting another account. */
  requireMfaForDestructive: boolean;
}

export type AuthResult =
  | { ok: true; principal: Principal }
  | { ok: false; status: 401 | 403; code: string; message: string };

export function authenticate(
  request: ApiRequest,
  config: AuthConfig,
  nowMs: number,
): AuthResult {
  const claims = request.claims;
  if (claims === undefined || Object.keys(claims).length === 0) {
    return {
      ok: false,
      status: 401,
      code: 'UNAUTHENTICATED',
      message: 'Authentication is required.',
    };
  }

  const subject = str(claims.sub);
  if (subject === undefined) {
    return {
      ok: false,
      status: 401,
      code: 'INVALID_TOKEN',
      message: 'Token is missing a subject claim.',
    };
  }

  // --- Issuer must be the configured user pool ---------------------------
  const issuer = str(claims.iss);
  if (config.userPoolId.length > 0) {
    const expected = `https://cognito-idp.${config.region}.amazonaws.com/${config.userPoolId}`;
    if (issuer !== expected) {
      return {
        ok: false,
        status: 401,
        code: 'INVALID_ISSUER',
        message: 'Token was not issued by the configured identity provider.',
      };
    }
  }

  // --- Token type --------------------------------------------------------
  const tokenUse = str(claims.token_use);
  if (tokenUse !== undefined && tokenUse !== 'access' && tokenUse !== 'id') {
    return {
      ok: false,
      status: 401,
      code: 'INVALID_TOKEN_USE',
      message: 'Token type is not accepted for API access.',
    };
  }

  // --- Expiry (seconds since epoch) --------------------------------------
  const exp = num(claims.exp);
  if (exp !== undefined && exp * 1000 <= nowMs) {
    return { ok: false, status: 401, code: 'TOKEN_EXPIRED', message: 'Token has expired.' };
  }

  // --- App client --------------------------------------------------------
  const clientId = str(claims.client_id) ?? str(claims.aud);
  if (config.allowedClientIds.length > 0) {
    if (clientId === undefined || !config.allowedClientIds.includes(clientId)) {
      return {
        ok: false,
        status: 403,
        code: 'CLIENT_NOT_ALLOWED',
        message: 'This application client is not permitted to call the API.',
      };
    }
  }

  const groups = parseGroups(claims['cognito:groups']);
  const roles = rolesFor(groups, config);

  if (roles.length === 0) {
    return {
      ok: false,
      status: 403,
      code: 'NO_ROLE',
      message:
        'Your account is authenticated but belongs to no TalkinShield group, so it has no permissions.',
    };
  }

  const principal: Principal = {
    subject,
    username: str(claims['cognito:username']) ?? str(claims.username) ?? subject,
    roles,
    groups,
    mfaPresent: hasMfa(claims.amr),
  };
  if (clientId !== undefined) principal.clientId = clientId;
  if (tokenUse !== undefined) principal.tokenUse = tokenUse;
  if (exp !== undefined) principal.expiresAtMs = exp * 1000;

  return { ok: true, principal };
}

function rolesFor(groups: readonly string[], config: AuthConfig): Role[] {
  const roles = new Set<Role>();
  const lower = groups.map((g) => g.toLowerCase());

  if (config.adminGroups.some((g) => lower.includes(g.toLowerCase()))) {
    roles.add('ADMIN');
    // Admins can moderate and read.
    roles.add('MODERATOR');
    roles.add('VIEWER');
  }
  if (config.moderatorGroups.some((g) => lower.includes(g.toLowerCase()))) {
    roles.add('MODERATOR');
    roles.add('VIEWER');
  }
  if (config.serviceGroups.some((g) => lower.includes(g.toLowerCase()))) {
    roles.add('SERVICE');
  }
  // A known group that is none of the above still gets read-only access.
  if (roles.size === 0 && groups.length > 0 && groups.some((g) => g.toLowerCase().includes('viewer'))) {
    roles.add('VIEWER');
  }
  return [...roles];
}

function parseGroups(value: unknown): string[] {
  if (Array.isArray(value)) return value.filter((v): v is string => typeof v === 'string');
  // Cognito sometimes delivers groups as a space- or comma-separated string.
  if (typeof value === 'string') {
    return value
      .replace(/^\[|\]$/gu, '')
      .split(/[,\s]+/u)
      .map((g) => g.trim())
      .filter((g) => g.length > 0);
  }
  return [];
}

/** `amr` lists the authentication methods used for the session. */
function hasMfa(value: unknown): boolean {
  const methods = Array.isArray(value)
    ? value.filter((v): v is string => typeof v === 'string')
    : typeof value === 'string'
      ? value.split(/[,\s]+/u)
      : [];
  const normalized = methods.map((m) => m.toLowerCase());
  return normalized.some((m) => m === 'mfa' || m === 'otp' || m === 'sms' || m === 'swk' || m === 'hwk');
}

function str(value: unknown): string | undefined {
  return typeof value === 'string' && value.length > 0 ? value : undefined;
}

function num(value: unknown): number | undefined {
  if (typeof value === 'number' && Number.isFinite(value)) return value;
  if (typeof value === 'string') {
    const parsed = Number(value);
    return Number.isFinite(parsed) ? parsed : undefined;
  }
  return undefined;
}

// --- Authorization ---------------------------------------------------------

export const PERMISSIONS = [
  'telemetry:ingest',
  'events:read',
  'users:read',
  'incidents:read',
  'incidents:write',
  'evidence:read',
  'evidence:write',
  'moderation:local',
  'moderation:platform',
  'rules:read',
  'rules:write',
  'logs:read',
  'settings:read',
  'settings:write',
  'retention:delete',
] as const;
export type Permission = (typeof PERMISSIONS)[number];

const ROLE_PERMISSIONS: Record<Role, readonly Permission[]> = {
  SERVICE: ['telemetry:ingest'],
  VIEWER: [
    'events:read',
    'users:read',
    'incidents:read',
    'evidence:read',
    'rules:read',
    'logs:read',
    'settings:read',
  ],
  MODERATOR: [
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
  ADMIN: [...PERMISSIONS],
};

/** Permissions that act on another account and so may require MFA. */
const DESTRUCTIVE: ReadonlySet<Permission> = new Set([
  'moderation:platform',
  'rules:write',
  'settings:write',
  'retention:delete',
]);

export function permissionsFor(principal: Principal): Permission[] {
  const out = new Set<Permission>();
  for (const role of principal.roles) {
    for (const permission of ROLE_PERMISSIONS[role]) out.add(permission);
  }
  return [...out];
}

export type AuthorizeResult =
  | { ok: true }
  | { ok: false; status: 403; code: string; message: string };

export function authorize(
  principal: Principal,
  permission: Permission,
  config: AuthConfig,
): AuthorizeResult {
  if (!permissionsFor(principal).includes(permission)) {
    return {
      ok: false,
      status: 403,
      code: 'INSUFFICIENT_PERMISSION',
      message: `This action requires the "${permission}" permission, which your role does not grant.`,
    };
  }

  if (config.requireMfaForDestructive && DESTRUCTIVE.has(permission) && !principal.mfaPresent) {
    return {
      ok: false,
      status: 403,
      code: 'MFA_REQUIRED',
      message:
        'This action affects another account or changes system policy and requires a multi-factor session.',
    };
  }

  return { ok: true };
}
