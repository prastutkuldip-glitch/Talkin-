/**
 * Cognito Hosted UI authentication, authorization-code flow with PKCE.
 *
 * PKCE rather than the implicit flow because the access token never appears in
 * a URL fragment or browser history. The code verifier lives in sessionStorage
 * for the duration of the redirect only, and tokens are held in memory —
 * deliberately NOT in localStorage, so an XSS foothold cannot read a persisted
 * token and the session dies with the tab.
 *
 * The trade-off is that a refresh re-runs the (silent, if the Cognito session
 * cookie is valid) redirect. For an internal console that is the right call.
 */

const VERIFIER_KEY = 'talkinshield.pkce.verifier';
const STATE_KEY = 'talkinshield.pkce.state';

export interface CognitoConfig {
  domain: string;
  clientId: string;
  redirectUri: string;
  scopes: string[];
}

export interface Session {
  accessToken: string;
  expiresAtMs: number;
  idToken?: string;
}

/** Tokens are held only in module memory. */
let session: Session | undefined;

export function currentSession(): Session | undefined {
  if (session === undefined) return undefined;
  // Treat a token within 30s of expiry as already expired.
  if (session.expiresAtMs - 30_000 <= Date.now()) {
    session = undefined;
    return undefined;
  }
  return session;
}

export function clearSession(): void {
  session = undefined;
}

function base64UrlEncode(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function randomString(byteLength: number): string {
  const bytes = new Uint8Array(byteLength);
  crypto.getRandomValues(bytes);
  return base64UrlEncode(bytes);
}

async function challengeFor(verifier: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier));
  return base64UrlEncode(new Uint8Array(digest));
}

/** Redirect to the Hosted UI to begin sign-in. */
export async function beginLogin(config: CognitoConfig): Promise<void> {
  const verifier = randomString(48);
  const state = randomString(16);
  sessionStorage.setItem(VERIFIER_KEY, verifier);
  sessionStorage.setItem(STATE_KEY, state);

  const params = new URLSearchParams({
    response_type: 'code',
    client_id: config.clientId,
    redirect_uri: config.redirectUri,
    scope: config.scopes.join(' '),
    state,
    code_challenge: await challengeFor(verifier),
    code_challenge_method: 'S256',
  });

  window.location.assign(`https://${config.domain}/oauth2/authorize?${params.toString()}`);
}

/**
 * Complete sign-in if the current URL carries an authorization code.
 * Returns the session, or undefined when there is no code to exchange.
 */
export async function completeLogin(config: CognitoConfig): Promise<Session | undefined> {
  const url = new URL(window.location.href);
  const code = url.searchParams.get('code');
  const returnedState = url.searchParams.get('state');
  if (code === null) return undefined;

  const expectedState = sessionStorage.getItem(STATE_KEY);
  const verifier = sessionStorage.getItem(VERIFIER_KEY);
  sessionStorage.removeItem(STATE_KEY);
  sessionStorage.removeItem(VERIFIER_KEY);

  // Strip the code from the address bar regardless of outcome.
  window.history.replaceState({}, '', url.pathname + url.hash);

  if (verifier === null) throw new Error('Sign-in could not be completed: the PKCE verifier is missing.');
  if (expectedState === null || returnedState !== expectedState) {
    // State mismatch indicates a CSRF attempt or a stale redirect.
    throw new Error('Sign-in could not be completed: the state parameter did not match.');
  }

  const body = new URLSearchParams({
    grant_type: 'authorization_code',
    client_id: config.clientId,
    code,
    redirect_uri: config.redirectUri,
    code_verifier: verifier,
  });

  const response = await fetch(`https://${config.domain}/oauth2/token`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: body.toString(),
  });

  if (!response.ok) {
    throw new Error(`Token exchange failed with HTTP ${response.status}.`);
  }

  const payload = (await response.json()) as {
    access_token?: string;
    id_token?: string;
    expires_in?: number;
  };

  if (typeof payload.access_token !== 'string') {
    throw new Error('Token exchange returned no access token.');
  }

  session = {
    accessToken: payload.access_token,
    expiresAtMs: Date.now() + (payload.expires_in ?? 1800) * 1000,
    ...(typeof payload.id_token === 'string' ? { idToken: payload.id_token } : {}),
  };
  return session;
}

export function logout(config: CognitoConfig): void {
  clearSession();
  const params = new URLSearchParams({
    client_id: config.clientId,
    logout_uri: config.redirectUri,
  });
  window.location.assign(`https://${config.domain}/logout?${params.toString()}`);
}

/**
 * Decode a JWT payload for display only.
 * Never used for an authorization decision — the API re-validates every claim.
 */
export function decodeClaims(token: string): Record<string, unknown> {
  const parts = token.split('.');
  if (parts.length < 2 || parts[1] === undefined) return {};
  try {
    const normalized = parts[1].replace(/-/g, '+').replace(/_/g, '/');
    return JSON.parse(atob(normalized)) as Record<string, unknown>;
  } catch {
    return {};
  }
}
