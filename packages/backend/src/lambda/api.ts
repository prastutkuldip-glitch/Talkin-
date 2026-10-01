/**
 * API Lambda: translates an API Gateway HTTP API v2 event into an `ApiRequest`,
 * delegates to the router, and serialises the response.
 *
 * Everything security-relevant lives in the router. This file is deliberately
 * thin so that the translation layer contains no policy decisions.
 */

import type {
  APIGatewayProxyEventV2WithJWTAuthorizer,
  APIGatewayProxyResultV2,
  Context,
} from 'aws-lambda';

import { handleRequest } from '../http/router.ts';
import { internalError, SECURITY_HEADERS, type ApiRequest } from '../http/types.ts';
import { container } from './container.ts';

export async function handler(
  event: APIGatewayProxyEventV2WithJWTAuthorizer,
  context: Context,
): Promise<APIGatewayProxyResultV2> {
  const deps = container();
  const requestId = event.requestContext?.requestId ?? context.awsRequestId;

  let body: unknown;
  let rawBodyLength = 0;

  if (typeof event.body === 'string' && event.body.length > 0) {
    const raw = event.isBase64Encoded
      ? Buffer.from(event.body, 'base64').toString('utf8')
      : event.body;
    rawBodyLength = Buffer.byteLength(raw, 'utf8');

    // Reject before parsing, so a huge body is never materialised as an object.
    if (rawBodyLength > deps.env.limits.maxRequestBytes) {
      return serialise({
        statusCode: 413,
        body: {
          error: {
            code: 'PAYLOAD_TOO_LARGE',
            message: `Request body exceeds the ${deps.env.limits.maxRequestBytes}-byte limit.`,
          },
        },
        headers: SECURITY_HEADERS,
      });
    }

    try {
      body = JSON.parse(raw);
    } catch {
      return serialise({
        statusCode: 400,
        body: { error: { code: 'INVALID_JSON', message: 'Request body is not valid JSON.' } },
        headers: SECURITY_HEADERS,
      });
    }
  }

  const request: ApiRequest = {
    method: event.requestContext.http.method,
    routeKey: event.routeKey,
    // `rawPath` includes the stage prefix on some configurations; strip it.
    path: normalisePath(event.rawPath, event.requestContext.stage),
    pathParams: event.pathParameters
      ? Object.fromEntries(
          Object.entries(event.pathParameters).filter(
            (entry): entry is [string, string] => typeof entry[1] === 'string',
          ),
        )
      : {},
    query: event.queryStringParameters
      ? Object.fromEntries(
          Object.entries(event.queryStringParameters).filter(
            (entry): entry is [string, string] => typeof entry[1] === 'string',
          ),
        )
      : {},
    headers: lowercaseHeaders(event.headers),
    body,
    rawBodyLength,
    requestId,
    ...(event.requestContext.http.sourceIp !== undefined
      ? { sourceIp: event.requestContext.http.sourceIp }
      : {}),
    ...(event.requestContext.authorizer?.jwt?.claims !== undefined
      ? { claims: event.requestContext.authorizer.jwt.claims as Record<string, unknown> }
      : {}),
  };

  try {
    return serialise(await handleRequest(request, deps));
  } catch (err: unknown) {
    deps.logger.error('API handler failed outside the router.', {
      requestId,
      error: err instanceof Error ? err.message : String(err),
    });
    return serialise(internalError(requestId));
  }
}

function normalisePath(rawPath: string, stage: string | undefined): string {
  if (stage === undefined || stage === '$default') return rawPath;
  const prefix = `/${stage}`;
  return rawPath.startsWith(prefix) ? rawPath.slice(prefix.length) || '/' : rawPath;
}

function lowercaseHeaders(headers: Record<string, string | undefined> | undefined): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [key, value] of Object.entries(headers ?? {})) {
    if (typeof value === 'string') out[key.toLowerCase()] = value;
  }
  return out;
}

function serialise(response: {
  statusCode: number;
  body: unknown;
  headers?: Record<string, string>;
}): APIGatewayProxyResultV2 {
  return {
    statusCode: response.statusCode,
    headers: response.headers ?? SECURITY_HEADERS,
    ...(response.body === undefined ? {} : { body: JSON.stringify(response.body) }),
  };
}
