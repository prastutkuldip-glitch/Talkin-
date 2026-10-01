/**
 * Transport-independent request/response shapes.
 *
 * The router is a pure function of (request, dependencies). API Gateway events
 * are translated into `ApiRequest` at the Lambda edge, which keeps the entire
 * authorization and rate-limiting path testable without AWS.
 */

export interface ApiRequest {
  method: string;
  /** Route path with parameters still templated, e.g. `/users/{userId}`. */
  routeKey: string;
  path: string;
  pathParams: Record<string, string>;
  query: Record<string, string>;
  headers: Record<string, string>;
  /** Parsed JSON body, or undefined. */
  body: unknown;
  /** Raw byte length, used to enforce a payload ceiling before parsing. */
  rawBodyLength: number;
  sourceIp?: string;
  /**
   * JWT claims injected by the API Gateway Cognito authorizer. Signature
   * verification happens at the gateway; the claim checks in `auth.ts` are
   * defence in depth, not the primary control.
   */
  claims?: Record<string, unknown>;
  requestId: string;
}

export interface ApiResponse {
  statusCode: number;
  body: unknown;
  headers?: Record<string, string>;
}

export const SECURITY_HEADERS: Record<string, string> = {
  'content-type': 'application/json',
  'cache-control': 'no-store',
  'x-content-type-options': 'nosniff',
  'strict-transport-security': 'max-age=63072000; includeSubDomains',
  'referrer-policy': 'no-referrer',
  'x-frame-options': 'DENY',
  'content-security-policy': "default-src 'none'; frame-ancestors 'none'",
};

export function ok(body: unknown, headers: Record<string, string> = {}): ApiResponse {
  return { statusCode: 200, body, headers: { ...SECURITY_HEADERS, ...headers } };
}

export function created(body: unknown): ApiResponse {
  return { statusCode: 201, body, headers: { ...SECURITY_HEADERS } };
}

export function accepted(body: unknown): ApiResponse {
  return { statusCode: 202, body, headers: { ...SECURITY_HEADERS } };
}

export function noContent(): ApiResponse {
  return { statusCode: 204, body: undefined, headers: { ...SECURITY_HEADERS } };
}

/**
 * Error responses carry a stable `code` and a safe `message`.
 *
 * They never include stack traces, internal identifiers, or the offending
 * request body — all of which are useful to an attacker and useless to a
 * legitimate client.
 */
export function error(
  statusCode: number,
  code: string,
  message: string,
  extra: Record<string, unknown> = {},
  headers: Record<string, string> = {},
): ApiResponse {
  return {
    statusCode,
    body: { error: { code, message, ...extra } },
    headers: { ...SECURITY_HEADERS, ...headers },
  };
}

export const badRequest = (message: string, extra?: Record<string, unknown>): ApiResponse =>
  error(400, 'BAD_REQUEST', message, extra);

export const unauthorized = (message = 'Authentication is required.'): ApiResponse =>
  error(401, 'UNAUTHENTICATED', message);

export const forbidden = (message = 'You are not authorized to perform this action.'): ApiResponse =>
  error(403, 'FORBIDDEN', message);

export const notFound = (message = 'Resource not found.'): ApiResponse =>
  error(404, 'NOT_FOUND', message);

export const conflict = (message: string): ApiResponse => error(409, 'CONFLICT', message);

export const payloadTooLarge = (message: string): ApiResponse =>
  error(413, 'PAYLOAD_TOO_LARGE', message);

export const tooManyRequests = (retryAfterSeconds: number): ApiResponse =>
  error(
    429,
    'RATE_LIMITED',
    'Request rate limit exceeded.',
    { retryAfterSeconds },
    { 'retry-after': String(retryAfterSeconds) },
  );

export const internalError = (requestId: string): ApiResponse =>
  error(500, 'INTERNAL_ERROR', 'An internal error occurred. Quote the request id when reporting it.', {
    requestId,
  });

export const notImplemented = (message: string): ApiResponse =>
  error(501, 'NOT_IMPLEMENTED', message);
