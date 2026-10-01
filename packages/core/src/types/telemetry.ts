/**
 * Explicit modelling of *what the operator is actually authorized to see*.
 *
 * This is the backbone of TalkinShield's honesty guarantee: the dashboard must
 * never imply that data was collected when the integration cannot provide it.
 * Every capability defaults to `false`, so an unconfigured deployment reports
 * "insufficient authorized telemetry" rather than inventing findings.
 */

export const AVAILABILITY = [
  /** Operator holds authorization and the data is present. */
  'AUTHORIZED',
  /** Operator holds authorization but the platform returned nothing. */
  'AUTHORIZED_EMPTY',
  /** The integration does not expose this data at all. */
  'UNAVAILABLE',
  /** Data exists but this deployment is not authorized to read it. */
  'NOT_AUTHORIZED',
] as const;
export type Availability = (typeof AVAILABILITY)[number];

/**
 * A value that may legitimately be absent. Detectors return these instead of
 * silently substituting defaults, so the UI can distinguish "clean" from
 * "never looked".
 */
export interface TelemetryValue<T> {
  availability: Availability;
  value?: T;
  /** Operator-facing explanation shown verbatim in the dashboard. */
  note?: string;
}

export function authorized<T>(value: T): TelemetryValue<T> {
  return { availability: 'AUTHORIZED', value };
}

export function authorizedEmpty<T>(note?: string): TelemetryValue<T> {
  return note === undefined
    ? { availability: 'AUTHORIZED_EMPTY' }
    : { availability: 'AUTHORIZED_EMPTY', note };
}

export function unavailable<T>(note = 'Insufficient authorized telemetry.'): TelemetryValue<T> {
  return { availability: 'UNAVAILABLE', note };
}

export function notAuthorized<T>(
  note = 'This deployment is not authorized to access the required data.',
): TelemetryValue<T> {
  return { availability: 'NOT_AUTHORIZED', note };
}

export function hasValue<T>(tv: TelemetryValue<T>): boolean {
  return tv.availability === 'AUTHORIZED' && tv.value !== undefined;
}

/**
 * Capabilities granted by the connected Talkin integration.
 *
 * `remoteMute` / `remoteBlock` describe whether an *official platform API*
 * exists for acting on another account. When false, TalkinShield only offers
 * protections scoped to the requesting user (local mute, block, ignore,
 * report, evidence capture). It never attempts to reach another participant's
 * device or microphone by any other means.
 */
export interface IntegrationCapabilities {
  /** Message text is provided for authorized rooms. */
  messageContent: boolean;
  /** Platform-side moderation events (mutes, kicks, bans) are delivered. */
  moderationEvents: boolean;
  /** Call audio is delivered through an approved, consented integration. */
  voiceAudio: boolean;
  /** Platform exposes presence events for hidden / "ghost mode" users. */
  hiddenPresenceEvents: boolean;
  /** Platform provides signed client attestation (official-build proof). */
  clientAttestation: boolean;
  /** Official API for server-side muting another account exists. */
  remoteMute: boolean;
  /** Official API for server-side blocking/suspending an account exists. */
  remoteBlock: boolean;
}

export const NO_CAPABILITIES: IntegrationCapabilities = {
  messageContent: false,
  moderationEvents: false,
  voiceAudio: false,
  hiddenPresenceEvents: false,
  clientAttestation: false,
  remoteMute: false,
  remoteBlock: false,
};

/** Human-readable description of each capability, surfaced in Settings. */
export const CAPABILITY_LABELS: Record<keyof IntegrationCapabilities, string> = {
  messageContent: 'Message content for authorized rooms',
  moderationEvents: 'Platform moderation events',
  voiceAudio: 'Call audio via approved, consented integration',
  hiddenPresenceEvents: 'Presence events for hidden / ghost-mode users',
  clientAttestation: 'Signed official-client attestation',
  remoteMute: 'Official server-side mute API',
  remoteBlock: 'Official server-side block/suspend API',
};
