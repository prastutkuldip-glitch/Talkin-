import test from 'node:test';
import assert from 'node:assert/strict';

import { handleRequest, routeTable } from '../src/http/router.ts';
import { authenticate, authorize, permissionsFor } from '../src/http/auth.ts';
import {
  ADMIN_CLAIMS,
  MODERATOR_CLAIMS,
  SERVICE_CLAIMS,
  T0,
  VIEWER_CLAIMS,
  bodyOf,
  claims,
  errorCode,
  event,
  harness,
  request,
  testEnv,
} from './harness.ts';

// --- AUTHENTICATION --------------------------------------------------------

test('auth: a request with no claims is rejected with 401', async () => {
  const h = harness();
  const response = await handleRequest(request('GET', '/overview'), h.deps);
  assert.equal(response.statusCode, 401);
  assert.equal(errorCode(response), 'UNAUTHENTICATED');
});

test('auth: empty claims object is rejected', async () => {
  const h = harness();
  const response = await handleRequest(request('GET', '/overview', { claims: {} }), h.deps);
  assert.equal(response.statusCode, 401);
});

test('auth: missing subject claim is rejected', () => {
  const env = testEnv();
  const result = authenticate(
    request('GET', '/overview', { claims: { 'cognito:groups': ['admins'] } }),
    env.auth,
    T0,
  );
  assert.ok(!result.ok);
  assert.equal(result.code, 'INVALID_TOKEN');
});

test('auth: a token from the wrong issuer is rejected', async () => {
  const h = harness();
  const response = await handleRequest(
    request('GET', '/overview', {
      claims: claims({ issuer: 'https://cognito-idp.us-east-1.amazonaws.com/us-east-1_EVILPOOL' }),
    }),
    h.deps,
  );
  assert.equal(response.statusCode, 401);
  assert.equal(errorCode(response), 'INVALID_ISSUER');
});

test('auth: an expired token is rejected', async () => {
  const h = harness();
  const response = await handleRequest(
    request('GET', '/overview', { claims: claims({ expSeconds: Math.floor(T0 / 1000) - 10 }) }),
    h.deps,
  );
  assert.equal(response.statusCode, 401);
  assert.equal(errorCode(response), 'TOKEN_EXPIRED');
});

test('auth: a token from an unregistered app client is rejected', async () => {
  const h = harness();
  const response = await handleRequest(
    request('GET', '/overview', { claims: claims({ clientId: 'some-other-app' }) }),
    h.deps,
  );
  assert.equal(response.statusCode, 403);
  assert.equal(errorCode(response), 'CLIENT_NOT_ALLOWED');
});

test('auth: a refresh token is not accepted for API access', async () => {
  const h = harness();
  const response = await handleRequest(
    request('GET', '/overview', { claims: claims({ tokenUse: 'refresh' }) }),
    h.deps,
  );
  assert.equal(response.statusCode, 401);
  assert.equal(errorCode(response), 'INVALID_TOKEN_USE');
});

test('auth: an authenticated user with no known group gets no access', async () => {
  const h = harness();
  const response = await handleRequest(
    request('GET', '/overview', { claims: claims({ groups: ['some-unrelated-group'] }) }),
    h.deps,
  );
  assert.equal(response.statusCode, 403);
  assert.equal(errorCode(response), 'NO_ROLE');
});

test('auth: group membership cannot be forged through headers or the body', async () => {
  const h = harness();
  const req = request('PUT', '/rules', {
    claims: VIEWER_CLAIMS,
    body: { overrides: { risk: { weights: { THREAT_LANGUAGE: 1 } } }, roles: ['ADMIN'] },
  });
  req.headers['x-roles'] = 'ADMIN';
  req.headers['x-cognito-groups'] = 'admins';

  const response = await handleRequest(req, h.deps);
  assert.equal(response.statusCode, 403, 'client-supplied role hints must be ignored');
});

test('auth: Cognito groups delivered as a string are parsed', () => {
  const env = testEnv();
  const result = authenticate(
    request('GET', '/overview', { claims: { ...claims({}), 'cognito:groups': '[moderators admins]' } }),
    env.auth,
    T0,
  );
  assert.ok(result.ok);
  assert.ok(result.principal.roles.includes('MODERATOR'));
});

test('auth: admins inherit moderator and viewer roles', () => {
  const env = testEnv();
  const result = authenticate(request('GET', '/overview', { claims: ADMIN_CLAIMS }), env.auth, T0);
  assert.ok(result.ok);
  assert.deepEqual([...result.principal.roles].sort(), ['ADMIN', 'MODERATOR', 'VIEWER']);
});

test('auth: MFA presence is read from the amr claim', () => {
  const env = testEnv();
  const withMfa = authenticate(
    request('GET', '/overview', { claims: claims({ amr: ['pwd', 'mfa'] }) }),
    env.auth,
    T0,
  );
  const withoutMfa = authenticate(
    request('GET', '/overview', { claims: claims({ amr: ['pwd'] }) }),
    env.auth,
    T0,
  );
  assert.ok(withMfa.ok && withMfa.principal.mfaPresent);
  assert.ok(withoutMfa.ok && !withoutMfa.principal.mfaPresent);
});

// --- AUTHORIZATION ---------------------------------------------------------

test('authz: every route declares a required permission', () => {
  const routes = routeTable();
  assert.ok(routes.length > 10);
  for (const route of routes) {
    assert.ok(route.permission.length > 0, `${route.method} ${route.pattern} has no permission`);
  }
});

test('authz: a viewer cannot change detection rules', async () => {
  const h = harness();
  const response = await handleRequest(
    request('PUT', '/rules', { claims: VIEWER_CLAIMS, body: { overrides: {} } }),
    h.deps,
  );
  assert.equal(response.statusCode, 403);
  assert.equal(errorCode(response), 'INSUFFICIENT_PERMISSION');
});

test('authz: a viewer cannot take moderation actions', async () => {
  const h = harness();
  const response = await handleRequest(
    request('POST', '/moderation', {
      claims: VIEWER_CLAIMS,
      body: { action: 'MUTE', targetUserId: 'user-A', reason: 'spamming the room repeatedly' },
    }),
    h.deps,
  );
  assert.equal(response.statusCode, 403);
});

test('authz: a viewer can read incidents', async () => {
  const h = harness();
  const response = await handleRequest(request('GET', '/incidents', { claims: VIEWER_CLAIMS }), h.deps);
  assert.equal(response.statusCode, 200);
});

test('authz: a moderator cannot change detection rules (admin only)', async () => {
  const h = harness();
  const response = await handleRequest(
    request('PUT', '/rules', { claims: MODERATOR_CLAIMS, body: { overrides: {} } }),
    h.deps,
  );
  assert.equal(response.statusCode, 403);
});

test('authz: an admin can change detection rules', async () => {
  const h = harness();
  const response = await handleRequest(
    request('PUT', '/rules', {
      claims: ADMIN_CLAIMS,
      body: {
        overrides: { spam: { burstCount: 5 } },
        reason: 'tightening burst threshold after a spam wave',
      },
    }),
    h.deps,
  );
  assert.equal(response.statusCode, 200);
  assert.equal(bodyOf<{ effective: { spam: { burstCount: number } } }>(response).effective.spam.burstCount, 5);
});

test('authz: the ingestion role cannot read the dashboard', async () => {
  const h = harness();
  const response = await handleRequest(request('GET', '/users', { claims: SERVICE_CLAIMS }), h.deps);
  assert.equal(response.statusCode, 403);
  assert.equal(errorCode(response), 'INSUFFICIENT_PERMISSION');
});

test('authz: a moderator cannot submit telemetry', async () => {
  const h = harness();
  const response = await handleRequest(
    request('POST', '/events', { claims: MODERATOR_CLAIMS, body: event() }),
    h.deps,
  );
  assert.equal(response.statusCode, 403);
});

test('authz: the ingestion role can submit telemetry', async () => {
  const h = harness();
  const response = await handleRequest(
    request('POST', '/events', { claims: SERVICE_CLAIMS, body: event() }),
    h.deps,
  );
  assert.equal(response.statusCode, 202);
});

test('authz: permission sets are least-privilege per role', () => {
  const env = testEnv();
  const viewer = authenticate(request('GET', '/x', { claims: VIEWER_CLAIMS }), env.auth, T0);
  const service = authenticate(request('GET', '/x', { claims: SERVICE_CLAIMS }), env.auth, T0);
  assert.ok(viewer.ok && service.ok);

  const viewerPerms = permissionsFor(viewer.principal);
  assert.ok(!viewerPerms.includes('moderation:platform'));
  assert.ok(!viewerPerms.includes('rules:write'));
  assert.ok(!viewerPerms.includes('telemetry:ingest'));

  assert.deepEqual(permissionsFor(service.principal), ['telemetry:ingest']);
});

test('authz: MFA is required for destructive actions when configured', () => {
  const env = testEnv();
  env.auth.requireMfaForDestructive = true;

  const noMfa = authenticate(
    request('GET', '/x', { claims: claims({ groups: ['admins'], amr: ['pwd'] }) }),
    env.auth,
    T0,
  );
  assert.ok(noMfa.ok);

  // Reads are fine without MFA...
  assert.ok(authorize(noMfa.principal, 'incidents:read', env.auth).ok);
  // ...but changing policy is not.
  const denied = authorize(noMfa.principal, 'rules:write', env.auth);
  assert.ok(!denied.ok);
  assert.equal(denied.code, 'MFA_REQUIRED');
});

// --- RATE LIMITING ---------------------------------------------------------

test('rate limit: requests beyond the budget return 429 with Retry-After', async () => {
  const h = harness({ env: { API_RATE_LIMIT_PER_MINUTE: '3' } });

  for (let i = 0; i < 3; i += 1) {
    const response = await handleRequest(request('GET', '/overview', { claims: MODERATOR_CLAIMS }), h.deps);
    assert.equal(response.statusCode, 200, `request ${i + 1} should be allowed`);
  }

  const limited = await handleRequest(request('GET', '/overview', { claims: MODERATOR_CLAIMS }), h.deps);
  assert.equal(limited.statusCode, 429);
  assert.equal(errorCode(limited), 'RATE_LIMITED');
  assert.ok(Number(limited.headers?.['retry-after']) > 0);
});

test('rate limit: the budget is per principal, not global', async () => {
  const h = harness({ env: { API_RATE_LIMIT_PER_MINUTE: '2' } });

  await handleRequest(request('GET', '/overview', { claims: MODERATOR_CLAIMS }), h.deps);
  await handleRequest(request('GET', '/overview', { claims: MODERATOR_CLAIMS }), h.deps);
  const exhausted = await handleRequest(request('GET', '/overview', { claims: MODERATOR_CLAIMS }), h.deps);
  assert.equal(exhausted.statusCode, 429);

  // A different principal still has budget.
  const other = await handleRequest(request('GET', '/overview', { claims: ADMIN_CLAIMS }), h.deps);
  assert.equal(other.statusCode, 200);
});

test('rate limit: the budget resets in the next window', async () => {
  const h = harness({ env: { API_RATE_LIMIT_PER_MINUTE: '1' } });

  assert.equal(
    (await handleRequest(request('GET', '/overview', { claims: MODERATOR_CLAIMS }), h.deps)).statusCode,
    200,
  );
  assert.equal(
    (await handleRequest(request('GET', '/overview', { claims: MODERATOR_CLAIMS }), h.deps)).statusCode,
    429,
  );

  h.clock.advance(61_000);
  assert.equal(
    (await handleRequest(request('GET', '/overview', { claims: MODERATOR_CLAIMS }), h.deps)).statusCode,
    200,
  );
});

test('rate limit: ingestion has its own budget, separate from the dashboard API', async () => {
  const h = harness({ env: { API_RATE_LIMIT_PER_MINUTE: '1', INGEST_RATE_LIMIT_PER_MINUTE: '5' } });

  for (let i = 0; i < 5; i += 1) {
    const response = await handleRequest(
      request('POST', '/events', {
        claims: SERVICE_CLAIMS,
        body: event({ message: `message ${i}`, timestamp: new Date(T0 + i).toISOString() }),
      }),
      h.deps,
    );
    assert.equal(response.statusCode, 202, `ingest ${i + 1} should be allowed`);
  }

  const limited = await handleRequest(
    request('POST', '/events', { claims: SERVICE_CLAIMS, body: event({ message: 'one too many' }) }),
    h.deps,
  );
  assert.equal(limited.statusCode, 429);
});

test('rate limit: remaining budget is reported in a response header', async () => {
  const h = harness({ env: { API_RATE_LIMIT_PER_MINUTE: '10' } });
  const response = await handleRequest(request('GET', '/overview', { claims: MODERATOR_CLAIMS }), h.deps);
  assert.equal(response.headers?.['x-ratelimit-remaining'], '9');
});

test('rate limit: unauthenticated requests are rejected before consuming budget', async () => {
  const h = harness({ env: { API_RATE_LIMIT_PER_MINUTE: '1' } });

  for (let i = 0; i < 5; i += 1) {
    const response = await handleRequest(request('GET', '/overview'), h.deps);
    assert.equal(response.statusCode, 401);
  }
  // A valid principal still has its full budget.
  const valid = await handleRequest(request('GET', '/overview', { claims: MODERATOR_CLAIMS }), h.deps);
  assert.equal(valid.statusCode, 200);
});

// --- REQUEST HARDENING -----------------------------------------------------

test('hardening: an oversized payload is refused before parsing', async () => {
  const h = harness();
  const response = await handleRequest(
    request('POST', '/events', { claims: SERVICE_CLAIMS, body: event(), rawBodyLength: 5_000_000 }),
    h.deps,
  );
  assert.equal(response.statusCode, 413);
});

test('hardening: unknown routes return 404 without leaking the route table', async () => {
  const h = harness();
  const response = await handleRequest(
    request('GET', '/admin/secrets', { claims: ADMIN_CLAIMS }),
    h.deps,
  );
  assert.equal(response.statusCode, 404);
  assert.ok(!JSON.stringify(response.body).includes('permission'));
});

test('hardening: path traversal in an evidence key is rejected', async () => {
  const h = harness();
  const response = await handleRequest(
    request('GET', '/evidence/..%2F..%2Fetc%2Fpasswd', { claims: MODERATOR_CLAIMS }),
    h.deps,
  );
  assert.equal(response.statusCode, 400);
  assert.match(JSON.stringify(response.body), /Malformed evidence key/);
});

test('hardening: security headers are present on every response', async () => {
  const h = harness();
  for (const req of [
    request('GET', '/overview', { claims: MODERATOR_CLAIMS }),
    request('GET', '/overview'),
    request('GET', '/nope', { claims: MODERATOR_CLAIMS }),
  ]) {
    const response = await handleRequest(req, h.deps);
    assert.equal(response.headers?.['x-content-type-options'], 'nosniff');
    assert.equal(response.headers?.['cache-control'], 'no-store');
    assert.ok(response.headers?.['strict-transport-security']);
    assert.equal(response.headers?.['x-frame-options'], 'DENY');
  }
});

test('hardening: an internal failure returns 500 without leaking details', async () => {
  const h = harness();
  // Force a failure deep in a handler.
  h.deps.incidents.list = async () => {
    throw new Error('DynamoDB table talkinshield-incidents ProvisionedThroughputExceeded at arn:aws:...');
  };

  const response = await handleRequest(request('GET', '/incidents', { claims: MODERATOR_CLAIMS }), h.deps);
  assert.equal(response.statusCode, 500);
  const serialized = JSON.stringify(response.body);
  assert.ok(!serialized.includes('DynamoDB'), serialized);
  assert.ok(!serialized.includes('arn:aws'), serialized);
  assert.ok(!serialized.includes('ProvisionedThroughput'), serialized);
  // But it is logged internally.
  assert.ok(h.logger.lines.some((l) => l.level === 'error'));
});

// --- AUDIT -----------------------------------------------------------------

test('audit: denied authentication is recorded', async () => {
  const h = harness();
  await handleRequest(
    request('GET', '/overview', { claims: claims({ clientId: 'rogue' }), sourceIp: '203.0.113.9' }),
    h.deps,
  );
  const entry = h.audit.snapshot.find((e) => e.action === 'AUTH_CLIENT_NOT_ALLOWED');
  assert.ok(entry);
  assert.equal(entry.outcome, 'DENIED');
  assert.equal(entry.sourceIp, '203.0.113.9');
});

test('audit: denied authorization is recorded with the required permission', async () => {
  const h = harness();
  await handleRequest(
    request('PUT', '/rules', { claims: VIEWER_CLAIMS, body: { overrides: {} } }),
    h.deps,
  );
  const entry = h.audit.snapshot.find((e) => e.action === 'AUTHZ_DENIED');
  assert.ok(entry);
  assert.equal(entry.detail?.requiredPermission, 'rules:write');
  assert.equal(entry.actorId, 'view-1');
});

test('audit: rule changes are recorded with an actor and a reason', async () => {
  const h = harness();
  await handleRequest(
    request('PUT', '/rules', {
      claims: ADMIN_CLAIMS,
      body: { overrides: { spam: { burstCount: 7 } }, reason: 'reducing false positives in voice rooms' },
    }),
    h.deps,
  );
  const entry = h.audit.snapshot.find((e) => e.action === 'DETECTION_RULES_UPDATED');
  assert.ok(entry);
  assert.equal(entry.actorId, 'admin-1');
  assert.match(entry.reason, /reducing false positives/);
});

test('audit: entries never contain request bodies or tokens', async () => {
  const h = harness();
  await handleRequest(
    request('PUT', '/rules', {
      claims: ADMIN_CLAIMS,
      body: { overrides: { spam: { burstCount: 7 } }, reason: 'tuning', secretField: 'super-secret-token' },
    }),
    h.deps,
  );
  const serialized = JSON.stringify(h.audit.snapshot);
  assert.ok(!serialized.includes('super-secret-token'), serialized);
});

// --- Rules validation ------------------------------------------------------

test('rules: an invalid patch is rejected with explanations', async () => {
  const h = harness();
  const response = await handleRequest(
    request('PUT', '/rules', {
      claims: ADMIN_CLAIMS,
      body: { overrides: { risk: { weights: { THREAT_LANGUAGE: 9999 } } } },
    }),
    h.deps,
  );
  assert.equal(response.statusCode, 400);
  const body = bodyOf<{ error: { problems: string[] } }>(response);
  assert.ok(body.error.problems.length > 0);
});

test('rules: lowering the confidence floor below the safe minimum is refused', async () => {
  const h = harness();
  const response = await handleRequest(
    request('PUT', '/rules', {
      claims: ADMIN_CLAIMS,
      body: { overrides: { abuse: { autoActionMinConfidence: 0.05 } } },
    }),
    h.deps,
  );
  assert.equal(response.statusCode, 400);
  assert.match(JSON.stringify(response.body), /low-confidence predictions/);
});

test('/me reports the caller\'s effective permissions', async () => {
  const h = harness();
  const response = await handleRequest(request('GET', '/me', { claims: MODERATOR_CLAIMS }), h.deps);
  assert.equal(response.statusCode, 200);
  const body = bodyOf<{ roles: string[]; permissions: string[] }>(response);
  assert.ok(body.roles.includes('MODERATOR'));
  assert.ok(body.permissions.includes('moderation:platform'));
  assert.ok(!body.permissions.includes('rules:write'));
});
