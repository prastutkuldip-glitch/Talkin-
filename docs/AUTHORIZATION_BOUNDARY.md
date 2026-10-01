# Authorization boundary

This document is the contract for what TalkinShield may observe and do. It is the reference
for reviewing a change: if a proposed change would widen this boundary, it needs an explicit
authorization decision, not just a code review.

## Out of scope under every configuration

There is no setting, flag or integration that enables any of the following. They are absent
by construction — no module in this repository contains code for them, and adding such code
would be a change of product, not a feature.

| Not implemented | Why it stays out |
| --- | --- |
| Access to Talkin servers or databases | TalkinShield only receives telemetry pushed to its own API. |
| Account takeover, credential or token theft | Never collected; opaque long tokens are *redacted* if they appear in content. |
| Malware, droppers, persistence | Out of product scope. |
| Packet flooding, DDoS, network jamming | TalkinShield makes no unsolicited outbound contact with any participant. |
| Remotely disabling another person's microphone | Only an official platform mute API can mute an account. Absent that, mute is local to the requesting user. |
| Remote control of another person's device | No agent, no client-side control channel, no device commands. |
| Location / GPS extraction | Never collected. Listed as `OUT_OF_SCOPE` in every evidence bundle and on every console panel. |
| Exploiting vulnerabilities in third-party clients | The client-integrity detector is strictly passive. It never contacts the suspected client. |
| Bypassing authentication or access controls | The ghost-mode correlator uses platform-disclosed data only, and has no inference fallback. |
| Stealth surveillance | Operator actions are audited; the system is intended to be visible to those who run it. |

## Capabilities you may enable

Each capability is `false` by default. Enabling one is an assertion that your deployment holds
the stated authorization. The system degrades safely and states the gap when a capability is
absent.

### `TALKIN_CAP_MESSAGE_CONTENT`

**Requires:** a lawful basis to process message text for the rooms you monitor, and a
first-party or officially-sanctioned feed of that text.

**When false:** message text is dropped at ingestion (with a warning on the response, not
silently), content detectors are skipped, and no excerpts are stored in incidents or evidence.

### `TALKIN_CAP_MODERATION_EVENTS`

**Requires:** an official feed of platform moderation events (mutes, kicks, bans).

**When false:** moderation evasion cannot be assessed. `detectEvasion` returns
`insufficientTelemetry: true` and the console shows *"Insufficient authorized telemetry."*
rather than guessing from behaviour.

### `TALKIN_CAP_VOICE_AUDIO`

**Requires — all of:**
1. A lawful basis for processing call audio in every jurisdiction where participants are located.
2. Participant consent or notice sufficient for that basis, recorded and retrievable.
3. An approved integration that delivers the audio. TalkinShield does not capture audio itself.

Additionally, `TRANSCRIBE_ENABLED=true` is rejected unless this capability is `true`, and
`TranscribeAdapter.startJob` refuses any job where the caller does not assert
`consentRecorded: true`. The CDK app refuses to synthesise with `capVoiceAudio` unless
`-c confirmVoiceConsent=true` is also passed — a deliberate speed bump.

**When false:** no audio is received or processed. Voice events arrive without a transcript and
the console records that voice analysis was skipped.

### `TALKIN_CAP_HIDDEN_PRESENCE`

**Requires:** the platform explicitly discloses presence events for hidden / invisible / ghost-mode
users to your integration.

This is the most sensitive capability and has the strictest rule. `packages/core/src/detection/ghost.ts`
correlates hidden-presence records the platform **already sends us** with authorized events in
the same room and window. It must never:

- probe or enumerate private APIs to discover concealed users
- bypass or test access controls
- infer hidden identities from timing side channels
- touch another participant's device

**When false:** the correct and required behaviour is to report exactly
`"Insufficient authorized telemetry."` There is intentionally **no fallback inference path** in
the code. If you find yourself wanting to add one, that is the boundary doing its job.

### `TALKIN_CAP_CLIENT_ATTESTATION`

**Requires:** the platform provides signed attestation that a client is an official build.

**When false:** client-integrity findings are behavioural indicators only. The console states
this on the user detail page, and `verifyClient` returns `undefined` — *unknown*, never
*failed*. Absence of attestation is never treated as evidence of a modified client.

### `TALKIN_CAP_REMOTE_MUTE` / `TALKIN_CAP_REMOTE_BLOCK`

**Requires:** an official Talkin moderation API, and authorization to act on accounts through
it. Both require `TALKIN_ADAPTER=http`; the CDK app refuses to synthesise otherwise, because
declaring the capability without an API to call would advertise an ability the system cannot
honour.

**When false:**
- MUTE and BLOCK are recorded with scope `LOCAL_TO_REQUESTER` and take effect only for the
  protected user. The API response and the console both say so explicitly.
- No automated platform restriction is applied at CRITICAL risk; the response plan sets
  `platformActionUnavailable: true` and explains the fallback in its rationale.
- TalkinShield does not attempt the action by any other means.

## Gates on automated action

Even with full capabilities, an automated platform restriction requires **all** of:

1. Risk level `CRITICAL`.
2. Peak signal confidence ≥ `risk.criticalAutoActionMinConfidence` (default 0.8).
3. At least one corroborating deterministic signal — spam, frequency, client-integrity,
   evasion or coordination. An AI-only escalation is refused.
4. The abuse classifier did not flag the decision for human review.
5. `remoteBlock` granted.

The restriction that results is temporary (15 minutes) and reversible. A permanent penalty
always requires explicit human confirmation. This is enforced in
`packages/core/src/response/policy.ts` and covered by tests in `packages/core/test/risk.test.ts`.

## Reviewing a change against this document

Ask:

1. Does this read data the operator was not already receiving? If so, which capability covers
   it, and is that capability gated?
2. Does this take an action affecting an account other than the requester's? If so, does it go
   through an official API, and does it degrade honestly when that API is absent?
3. Does this create a path by which a capability's absence is worked around rather than
   reported?
4. Does the evidence bundle's `authorization.notCollected` list still describe reality?

A "yes" to 3 means the change should not land in this form.
