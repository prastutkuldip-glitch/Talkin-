# TalkinShield

A defensive abuse-detection, moderation and incident-response platform for voice-chat
applications. It ingests authorized Talkin telemetry, detects spam, automation, abusive
language, threats, modified clients and moderation evasion, scores risk, and gives
moderators an auditable console for acting on it.

**This is a defensive tool.** It observes only what the operator is authorized to receive,
and it acts only through official platform APIs or protections scoped to the requesting
user. It contains no capability to access Talkin servers, take over accounts, read
credentials, flood networks, control another participant's device or microphone, obtain
location data, or bypass authentication — and the architecture is arranged so those
capabilities cannot be added by configuration. See
[`docs/AUTHORIZATION_BOUNDARY.md`](docs/AUTHORIZATION_BOUNDARY.md).

---

## What it does

| Capability | How |
| --- | --- |
| **Spam & flood detection** | Burst, sustained-rate, identical-repeat, near-duplicate template, mention flood, link flood |
| **Automation detection** | Inter-arrival regularity (coefficient of variation), sustained machine-rate |
| **Abusive language** | Four layers — structural rules, tiered lexicon, repetition, optional Bedrock classification — with explicit arbitration |
| **Threat detection** | Structural patterns requiring actor + intent + target; highest deterministic weight |
| **Modified-client detection** | Passive telemetry only: version plausibility, version/platform flapping, impossible event sequences, malformed-request rate, official attestation when granted |
| **Moderation evasion** | Activity under an active platform restriction, leave/rejoin cycling |
| **Coordinated behaviour** | Identical content and synchronised joins across accounts, reported without identity inference |
| **Hidden / ghost activity** | Correlates platform-disclosed hidden presence only; otherwise reports *"Insufficient authorized telemetry."* |
| **Risk engine** | Configurable weights and bands, confidence scaling, per-signal caps, decaying history |
| **Automated response** | Log → increase monitoring → recommend → (at CRITICAL, gated) temporary reversible platform restriction |
| **Evidence** | Hash-chained, KMS-encrypted, Object-Locked bundles with full provenance |
| **Audit** | Append-only trail of every automated and human action, including denied access |

## Design decisions worth knowing

A few choices shape everything else:

**The detection core is pure and dependency-free.** `@talkinshield/core` performs no I/O and
has no runtime dependencies. The entire decision path — validation, detection, scoring,
policy — is a pure function of its inputs, so it is exhaustively testable, replayable
against historical data, and reviewable without AWS in the picture.

**AI is advisory, never authoritative.** A Bedrock verdict can raise or lower confidence and
can surface abuse the rules missed, but it cannot by itself justify a durable penalty. An
automated platform restriction requires high confidence *and* at least one corroborating
deterministic signal. Where the layers materially disagree, the result is `UNCERTAIN` and
goes to a human. See `packages/core/src/detection/abuse/classifier.ts`.

**Capabilities are declared, not assumed.** Every integration capability defaults to
`false`. An unconfigured deployment reports "insufficient authorized telemetry" rather than
inventing findings, and the dashboard distinguishes *"nothing was found"* from *"we were
never able to look"* on every panel.

**No platform API means no platform action.** When `remoteMute` / `remoteBlock` are not
granted, MUTE and BLOCK degrade to protections scoped to the requesting user — local mute,
block, ignore, report, evidence capture — and say so plainly in the UI. There is no fallback
path that reaches another participant's client by other means.

**False positives are a first-class concern.** The abuse classifier downgrades quoted and
reported speech, negated intent, in-game banter and self-directed language. Short repeated
phrases ("lol" four times) are tolerated where long repeated messages are not. Coordination
requires content long enough that identical phrasing across accounts is improbable. Self-harm
language routes to a wellbeing response, never to enforcement. These are tested explicitly —
see `packages/core/test/abuse.test.ts` and the `benign-conversation` / `quiet-room` mock
scenarios.

## Repository layout

```
packages/
  core/        Pure detection, risk, policy and evidence logic. Zero dependencies.
  backend/     Lambda handlers, application services, AWS adapters, in-memory adapters.
  frontend/    React dashboard (the Security Console).
  infra/       AWS CDK: KMS, DynamoDB, S3, Cognito, API Gateway, WAF, EventBridge, alarms.
  mocks/       Deterministic mock event generator and scenario verifier.
docs/
  ARCHITECTURE.md             Data flow, table schemas, IAM posture.
  AUTHORIZATION_BOUNDARY.md   What each capability requires before you enable it.
  DEPLOYMENT.md               Build, deploy, bootstrap, operate.
  PRIVACY.md                  Data minimization, retention, deletion.
```

## Quick start

Requires Node 22.6+.

```bash
npm install

# Run the full test suite (core + backend + mocks).
npm test

# Typecheck everything.
npm run typecheck:all

# Explore the mock scenarios, and verify them against the real detection pipeline.
npm run mock:stream list
npm run mock:stream verify

# Run the console against local fixtures — no AWS, no backend.
VITE_USE_MOCK_API=true npm run dev:frontend
```

The mock scenario verifier is the fastest feedback loop for tuning: it runs fifteen
scenarios (including two deliberately clean ones) through the real pipeline and reports
whether the expected signals fired.

```
PASS  benign-conversation — clean, as expected (peak risk 0).
PASS  identical-message-flood — peak risk 100/100 (CRITICAL); signals: SPAM_IDENTICAL_REPEAT, …
PASS  threat-language — peak risk 100/100 (CRITICAL); signals: THREAT_LANGUAGE, …
```

## Configuration

Copy `.env.example` to `.env`. Nothing sensitive belongs in it: credentials are fetched at
runtime from AWS Secrets Manager by name, and only the *name* appears in the environment.

The settings that most change behaviour:

| Variable | Effect |
| --- | --- |
| `TALKIN_ADAPTER` | `noop` (no integration, safe default), `mock` (local fixtures, refused in prod), `http` (official API) |
| `TALKIN_CAP_*` | Declares which capabilities your authorization actually grants. All default to `false`. |
| `BEDROCK_ENABLED` | Optional AI classification. Detection is fully deterministic when `false`. |
| `TRANSCRIBE_ENABLED` | Requires `TALKIN_CAP_VOICE_AUDIO=true`; refused otherwise. |
| `RETENTION_*_DAYS` | Retention windows. Evidence retention may not be shorter than incident retention. |

Detection thresholds, risk weights and bands are **not** environment variables — they are
edited from the Detection Rules page, validated server-side, versioned, and recorded in the
audit log. Defaults live in `packages/core/src/config/detection-config.ts`.

## Ingestion API

`POST /events` accepts a single event or a batch:

```json
{
  "events": [
    {
      "userId": "8F29A1",
      "roomId": "ABC123",
      "timestamp": "2026-03-01T12:00:00.000Z",
      "eventType": "message",
      "message": "hello everyone",
      "clientVersion": "4.2.1",
      "platform": "ios",
      "metadata": { "region": "eu-west-1" }
    }
  ]
}
```

Every field is allow-listed and bounds-checked; unknown top-level fields are rejected rather
than ignored; metadata is flattened to primitives; and event ids are derived deterministically
from the payload so a redelivered event deduplicates instead of inflating a risk score. A
partially invalid batch accepts the valid events and reports the rest per-index. Repeated
malformed payloads from one submitter become a client-integrity signal.

## Console

Ten pages: Overview, Live Events, Users, Incidents, Risk Analysis, Evidence, Moderation
Actions, Detection Rules, System Logs, Settings.

The user detail page leads with the risk panel:

```
User: 8F29A1        Status: CRITICAL        Room: ABC123        Risk: 91/100

Detected
  ✓ SPAM_IDENTICAL_REPEAT   +20   95%   The same message content was sent 50 times…
  ✓ ABUSE_REPEATED          +25   80%   Abusive content repeated across multiple messages…
  ✓ BOT_UNIFORM_TIMING      +20   91%   Message timing is machine-like: 20 messages at a…
  ✓ CLIENT_UNKNOWN_VERSION  +10   75%   Declared client version "custom-build-9" does not…

Recommended actions
  [ MUTE · LOCAL ONLY ]  [ BLOCK · LOCAL ONLY ]  [ REPORT · PLATFORM API ]  [ SAVE EVIDENCE ]
```

Each button carries its true scope, and a reason is mandatory before any action is applied.

## Security

Cognito authentication with MFA-ready configuration; role-based authorization derived from
group membership with a table-driven permission per route; per-principal rate limiting;
AWS WAF with managed rule sets and per-IP rate limiting; KMS customer-managed keys
throughout; S3 Object Lock in compliance mode for evidence; an audit table that no function
holds permission to update or delete; and least-privilege IAM scoped per Lambda. Details in
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

## Connecting the real Talkin API

`packages/backend/src/adapters/platform/talkin-adapter.ts` holds three implementations of
one interface: `NoopTalkinAdapter` (default), `MockTalkinAdapter` (development) and
`HttpTalkinAdapter` (official API). To connect a real integration, change only the paths,
payloads and response parsing in `HttpTalkinAdapter`, then enable the corresponding
capability flags. Read [`docs/AUTHORIZATION_BOUNDARY.md`](docs/AUTHORIZATION_BOUNDARY.md)
first: it lists what authorization each capability requires before it may be turned on.

## Licence

Apache-2.0.
