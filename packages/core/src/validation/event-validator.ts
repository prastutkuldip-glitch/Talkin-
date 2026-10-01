/**
 * Ingestion validation and sanitization.
 *
 * Hand-written rather than schema-library-based so the core package stays
 * dependency-free and the failure modes are explicit. Every field is
 * allow-listed: unknown top-level keys are rejected, and metadata is coerced to
 * a flat map of primitives so no nested object can smuggle in a payload.
 *
 * OWASP alignment: strict type checking, length bounds, rejection of
 * prototype-polluting keys, and no reflection of attacker-controlled strings
 * into error messages beyond a bounded, escaped excerpt.
 */

import {
  isEventType,
  isPlatform,
  type Platform,
  type RawTalkinEvent,
  type TalkinEvent,
} from '../types/events.ts';
import { deriveEventId } from '../util/ids.ts';
import { sanitizeVisible } from '../util/text.ts';

export interface ValidationLimits {
  maxMessageLength: number;
  maxMetadataKeys: number;
  maxMetadataKeyLength: number;
  maxMetadataValueLength: number;
  maxUserIdLength: number;
  maxRoomIdLength: number;
  maxClientVersionLength: number;
  /** Reject timestamps further in the future than this, ms. */
  maxClockSkewFutureMs: number;
  /** Reject timestamps older than this, ms. */
  maxAgeMs: number;
}

export const DEFAULT_LIMITS: ValidationLimits = {
  maxMessageLength: 4000,
  maxMetadataKeys: 25,
  maxMetadataKeyLength: 64,
  maxMetadataValueLength: 512,
  maxUserIdLength: 128,
  maxRoomIdLength: 128,
  maxClientVersionLength: 64,
  maxClockSkewFutureMs: 2 * 60 * 1000,
  maxAgeMs: 7 * 24 * 60 * 60 * 1000,
};

export const ALLOWED_EVENT_KEYS = new Set([
  'eventId',
  'userId',
  'roomId',
  'timestamp',
  'eventType',
  'message',
  'clientVersion',
  'platform',
  'metadata',
  'messageIsTranscript',
]);

/** Keys that must never be accepted into a metadata map. */
const FORBIDDEN_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

const ID_RE = /^[A-Za-z0-9_.:@-]+$/u;

export interface ValidationIssue {
  field: string;
  code: string;
  message: string;
}

export type ValidationResult =
  | { ok: true; event: TalkinEvent; warnings: ValidationIssue[] }
  | { ok: false; issues: ValidationIssue[] };

export function validateEvent(
  input: unknown,
  options: {
    nowMs: number;
    limits?: ValidationLimits;
    /** When false, inbound `message` text is dropped rather than stored. */
    messageContentAuthorized?: boolean;
  },
): ValidationResult {
  const limits = options.limits ?? DEFAULT_LIMITS;
  const issues: ValidationIssue[] = [];
  const warnings: ValidationIssue[] = [];

  if (typeof input !== 'object' || input === null || Array.isArray(input)) {
    return {
      ok: false,
      issues: [{ field: '.', code: 'NOT_AN_OBJECT', message: 'Event must be a JSON object.' }],
    };
  }

  const raw = input as RawTalkinEvent & Record<string, unknown>;

  for (const key of Object.keys(raw)) {
    if (!ALLOWED_EVENT_KEYS.has(key)) {
      issues.push({
        field: key,
        code: 'UNKNOWN_FIELD',
        message: `Unknown field "${safeLabel(key)}" is not accepted.`,
      });
    }
  }

  const userId = requireId(raw.userId, 'userId', limits.maxUserIdLength, issues);
  const roomId = requireId(raw.roomId, 'roomId', limits.maxRoomIdLength, issues);

  // --- timestamp ---------------------------------------------------------
  let timestampMs = 0;
  let timestampIso = '';
  if (typeof raw.timestamp !== 'string' || raw.timestamp.length === 0) {
    issues.push({
      field: 'timestamp',
      code: 'MISSING',
      message: 'timestamp is required and must be an ISO-8601 string.',
    });
  } else {
    const parsed = Date.parse(raw.timestamp);
    if (Number.isNaN(parsed)) {
      issues.push({
        field: 'timestamp',
        code: 'INVALID_FORMAT',
        message: 'timestamp must be a valid ISO-8601 date-time.',
      });
    } else if (parsed > options.nowMs + limits.maxClockSkewFutureMs) {
      issues.push({
        field: 'timestamp',
        code: 'FUTURE_TIMESTAMP',
        message: 'timestamp is too far in the future.',
      });
    } else if (parsed < options.nowMs - limits.maxAgeMs) {
      issues.push({
        field: 'timestamp',
        code: 'TOO_OLD',
        message: 'timestamp is older than the accepted ingestion window.',
      });
    } else {
      timestampMs = parsed;
      timestampIso = new Date(parsed).toISOString();
    }
  }

  // --- eventType ---------------------------------------------------------
  if (!isEventType(raw.eventType)) {
    issues.push({
      field: 'eventType',
      code: 'INVALID_ENUM',
      message: 'eventType must be one of: message, voice, join, leave, moderation.',
    });
  }

  // --- platform ----------------------------------------------------------
  let platform: Platform = 'unknown';
  if (raw.platform !== undefined) {
    if (!isPlatform(raw.platform)) {
      // Unrecognised platform is itself a weak client-integrity signal, so it
      // is recorded as a warning rather than silently normalised away.
      warnings.push({
        field: 'platform',
        code: 'UNRECOGNISED_PLATFORM',
        message: 'platform value is not a recognised official platform.',
      });
    } else {
      platform = raw.platform;
    }
  }

  // --- message -----------------------------------------------------------
  let message: string | undefined;
  if (raw.message !== undefined) {
    if (typeof raw.message !== 'string') {
      issues.push({
        field: 'message',
        code: 'INVALID_TYPE',
        message: 'message must be a string.',
      });
    } else if (raw.message.length > limits.maxMessageLength) {
      issues.push({
        field: 'message',
        code: 'TOO_LONG',
        message: `message exceeds ${limits.maxMessageLength} characters.`,
      });
    } else if (options.messageContentAuthorized === false) {
      warnings.push({
        field: 'message',
        code: 'CONTENT_NOT_AUTHORIZED',
        message:
          'Message content was dropped: this deployment is not authorized to process message text.',
      });
    } else {
      message = sanitizeVisible(raw.message);
    }
  }

  if (raw.eventType === 'message' && raw.message === undefined) {
    warnings.push({
      field: 'message',
      code: 'EMPTY_MESSAGE_EVENT',
      message: 'message event arrived without message text; content detectors will be skipped.',
    });
  }

  // --- clientVersion -----------------------------------------------------
  let clientVersion: string | undefined;
  if (raw.clientVersion !== undefined) {
    if (typeof raw.clientVersion !== 'string') {
      issues.push({
        field: 'clientVersion',
        code: 'INVALID_TYPE',
        message: 'clientVersion must be a string.',
      });
    } else if (raw.clientVersion.length > limits.maxClientVersionLength) {
      issues.push({
        field: 'clientVersion',
        code: 'TOO_LONG',
        message: 'clientVersion is too long.',
      });
    } else {
      clientVersion = raw.clientVersion.trim();
    }
  }

  // --- metadata ----------------------------------------------------------
  const metadata = validateMetadata(raw.metadata, limits, issues);

  let messageIsTranscript = false;
  if (raw.messageIsTranscript !== undefined) {
    if (typeof raw.messageIsTranscript !== 'boolean') {
      issues.push({
        field: 'messageIsTranscript',
        code: 'INVALID_TYPE',
        message: 'messageIsTranscript must be a boolean.',
      });
    } else {
      messageIsTranscript = raw.messageIsTranscript;
    }
  }

  if (issues.length > 0) return { ok: false, issues };

  const eventType = raw.eventType;
  if (!isEventType(eventType)) {
    return {
      ok: false,
      issues: [{ field: 'eventType', code: 'INVALID_ENUM', message: 'eventType is invalid.' }],
    };
  }

  const event: TalkinEvent = {
    eventId:
      typeof raw.eventId === 'string' && ID_RE.test(raw.eventId) && raw.eventId.length <= 128
        ? raw.eventId
        : deriveEventId({
            userId,
            roomId,
            timestamp: timestampIso,
            eventType,
            message,
          }),
    userId,
    roomId,
    timestamp: timestampIso,
    receivedAtMs: timestampMs,
    eventType,
    platform,
    metadata,
  };

  if (message !== undefined && message.length > 0) event.message = message;
  if (messageIsTranscript) event.messageIsTranscript = true;
  if (clientVersion !== undefined && clientVersion.length > 0) event.clientVersion = clientVersion;

  return { ok: true, event, warnings };
}

function requireId(
  value: unknown,
  field: string,
  maxLength: number,
  issues: ValidationIssue[],
): string {
  if (typeof value !== 'string' || value.length === 0) {
    issues.push({ field, code: 'MISSING', message: `${field} is required.` });
    return '';
  }
  if (value.length > maxLength) {
    issues.push({ field, code: 'TOO_LONG', message: `${field} exceeds ${maxLength} characters.` });
    return '';
  }
  if (!ID_RE.test(value)) {
    issues.push({
      field,
      code: 'INVALID_CHARACTERS',
      message: `${field} may only contain letters, digits and _ . : @ -`,
    });
    return '';
  }
  return value;
}

function validateMetadata(
  value: unknown,
  limits: ValidationLimits,
  issues: ValidationIssue[],
): Record<string, string | number | boolean> {
  const out: Record<string, string | number | boolean> = {};
  if (value === undefined || value === null) return out;

  if (typeof value !== 'object' || Array.isArray(value)) {
    issues.push({
      field: 'metadata',
      code: 'INVALID_TYPE',
      message: 'metadata must be a flat object of string, number or boolean values.',
    });
    return out;
  }

  const entries = Object.entries(value as Record<string, unknown>);
  if (entries.length > limits.maxMetadataKeys) {
    issues.push({
      field: 'metadata',
      code: 'TOO_MANY_KEYS',
      message: `metadata may contain at most ${limits.maxMetadataKeys} keys.`,
    });
    return out;
  }

  for (const [key, raw] of entries) {
    if (FORBIDDEN_KEYS.has(key)) {
      issues.push({
        field: `metadata.${safeLabel(key)}`,
        code: 'FORBIDDEN_KEY',
        message: 'metadata key is not permitted.',
      });
      continue;
    }
    if (key.length > limits.maxMetadataKeyLength || !/^[A-Za-z0-9_.-]+$/u.test(key)) {
      issues.push({
        field: `metadata.${safeLabel(key)}`,
        code: 'INVALID_KEY',
        message: 'metadata keys may only contain letters, digits and _ . -',
      });
      continue;
    }
    if (typeof raw === 'string') {
      if (raw.length > limits.maxMetadataValueLength) {
        issues.push({
          field: `metadata.${safeLabel(key)}`,
          code: 'VALUE_TOO_LONG',
          message: `metadata value exceeds ${limits.maxMetadataValueLength} characters.`,
        });
        continue;
      }
      out[key] = sanitizeVisible(raw);
    } else if (typeof raw === 'number') {
      if (!Number.isFinite(raw)) {
        issues.push({
          field: `metadata.${safeLabel(key)}`,
          code: 'INVALID_NUMBER',
          message: 'metadata numbers must be finite.',
        });
        continue;
      }
      out[key] = raw;
    } else if (typeof raw === 'boolean') {
      out[key] = raw;
    } else {
      issues.push({
        field: `metadata.${safeLabel(key)}`,
        code: 'INVALID_VALUE_TYPE',
        message: 'metadata values must be string, number or boolean.',
      });
    }
  }

  return out;
}

/** Bound and strip a caller-supplied label before echoing it in an error. */
function safeLabel(key: string): string {
  return key.replace(/[^\w.-]/gu, '').slice(0, 64);
}

export interface BatchValidationResult {
  accepted: TalkinEvent[];
  rejected: Array<{ index: number; issues: ValidationIssue[] }>;
  warnings: Array<{ index: number; warnings: ValidationIssue[] }>;
}

export function validateBatch(
  inputs: readonly unknown[],
  options: {
    nowMs: number;
    maxBatchSize: number;
    limits?: ValidationLimits;
    messageContentAuthorized?: boolean;
  },
): BatchValidationResult | { error: string } {
  if (!Array.isArray(inputs)) return { error: 'events must be an array.' };
  if (inputs.length === 0) return { error: 'events must contain at least one event.' };
  if (inputs.length > options.maxBatchSize) {
    return { error: `events may contain at most ${options.maxBatchSize} items.` };
  }

  const accepted: TalkinEvent[] = [];
  const rejected: Array<{ index: number; issues: ValidationIssue[] }> = [];
  const warnings: Array<{ index: number; warnings: ValidationIssue[] }> = [];
  const seen = new Set<string>();

  inputs.forEach((input, index) => {
    const result = validateEvent(input, options);
    if (!result.ok) {
      rejected.push({ index, issues: result.issues });
      return;
    }
    if (seen.has(result.event.eventId)) {
      rejected.push({
        index,
        issues: [
          {
            field: 'eventId',
            code: 'DUPLICATE_IN_BATCH',
            message: 'Duplicate event within the same batch was discarded.',
          },
        ],
      });
      return;
    }
    seen.add(result.event.eventId);
    accepted.push(result.event);
    if (result.warnings.length > 0) warnings.push({ index, warnings: result.warnings });
  });

  return { accepted, rejected, warnings };
}
