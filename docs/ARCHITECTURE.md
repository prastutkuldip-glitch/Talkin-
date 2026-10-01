# Architecture

## Data flow

```
Authorized Talkin telemetry
        │
        ▼
  API Gateway (HTTP API)  ── WAF: managed rule sets + per-IP rate limit
        │                     Cognito JWT authorizer
        ▼
  Lambda: api  ──────────▶ validate → dedupe → persist → publish
        │                  (ingestion returns immediately; no AI on this path)
        ▼
  EventBridge  "EventIngested"
        │
        ▼
  Lambda: analyze ───────▶ detection pipeline (pure core)
        │                   ├─ spam / automation
        │                   ├─ abuse (rules + lexicon + repetition + optional Bedrock)
        │                   ├─ client integrity
        │                   └─ evasion
        │                  risk engine → response policy
        │
        ├──▶ DynamoDB: user state, signals, incidents, actions, audit
        ├──▶ S3: hash-chained evidence (KMS, Object Lock)
        ├──▶ Official Talkin API: temporary restriction (only when gated checks pass)
        └──▶ EventBridge "RiskAssessed" / "WellbeingConcern" / "CoordinationDetected"
                     │
                     ▼
               Lambda: alert ──▶ SNS ──▶ operators

  Scheduled:
    Lambda: coordination (5 min)  room-level cross-account sweep
    Lambda: retention   (daily)   evidence deletion under policy, itself audited
```

**Why ingestion and analysis are separate.** A Bedrock call or a platform API call can take
seconds. Keeping them off the ingestion path means telemetry submission stays fast and cannot
fail because an AI model is throttled. Analysis is idempotent — event ids are deterministic and
deduplicated at write time — so at-least-once delivery is safe.

**Why the detection core is pure.** `@talkinshield/core` has no dependencies and performs no
I/O. Every decision is a function of (event, user state, config, capabilities). That makes the
whole decision path testable without AWS, replayable against historical events, and reviewable
as ordinary logic. The backend's job is to gather inputs, call the core, and persist the result.

## Package boundaries

| Package | Depends on | Contains |
| --- | --- | --- |
| `core` | nothing | Types, config, validation, detectors, risk engine, response policy, evidence, pipeline |
| `backend` | `core`, AWS SDK | Ports (interfaces), application services, HTTP router, AWS adapters, in-memory adapters, Lambda handlers |
| `frontend` | React | Console UI, API client, mock fixtures |
| `infra` | CDK | Three stacks: data, auth, app |
| `mocks` | `core` | Deterministic scenario generator and verifier |

The backend depends on `ports.ts` interfaces only. AWS SDK usage is confined to
`adapters/aws/*`; `adapters/memory/*` provides equivalents used by the tests and local
development. That split is why authentication, authorization, rate limiting and the full
moderation flow can be tested without AWS.

## DynamoDB schema

All tables: on-demand billing, SSE with a customer-managed KMS key, point-in-time recovery,
and an `expiresAt` TTL attribute.

| Table | PK | SK | GSIs |
| --- | --- | --- | --- |
| `events` | `userId` | `{paddedMs}#{eventId}` | `byRoom` (roomId / receivedAtMs), `byEventId` (eventId) |
| `user-state` | `userId` | — | `byRisk` (riskBucket / riskScore) |
| `signals` | `userId` | `{paddedMs}#{code}` | `byDay` (day / observedAtMs) |
| `incidents` | `incidentId` | — | `byStatus` (status / createdAtMs), `byUser` (userId / updatedAtMs) |
| `actions` | `targetUserId` | `{paddedMs}#{actionId}` | `byDay` (day / atMs) |
| `audit` | `auditId` | — | `byDay` (day / atMs), `byActor` (actorId / atMs) |
| `rules` | `configKey` | — | — |
| `ratelimit` | `bucketKey` | — | — |

**Design notes.**

- *Sort keys are zero-padded epoch milliseconds* so lexicographic order equals chronological
  order, and a `ScanIndexForward: false` query returns newest-first without a sort.
- *The `byRisk` index uses a constant partition key* (`riskBucket = "ALL"`). High-risk users are
  therefore a query by score, not a table scan. This concentrates writes on one partition; at
  very high account volumes, shard the bucket key.
- *`byDay` indexes exist so "recent across all users" is a query, not a scan.* The dashboard's
  recency views walk the last day or two of partitions.
- *User state uses optimistic concurrency* on a `version` attribute. Two events for the same
  user processed concurrently cannot clobber each other; the loser re-reads and merges, so
  neither update is lost.
- *Rate limiting uses fixed windows with an atomic `ADD`.* A single round trip, no
  read-modify-write race, and the window boundary derives from the clock.

## Evidence integrity

Four independent layers:

1. **Content hash** — SHA-256 over a canonical (sorted-key) JSON encoding of the bundle body.
   Any mutation changes it. Canonical encoding matters: a bundle re-serialised with different
   key order must not appear tampered with.
2. **Hash chain** — each bundle records the previous bundle's content hash. Removing or
   reordering a bundle breaks its successor's link, so *deletion* is detectable, not just
   modification.
3. **Storage controls** — S3 `IfNoneMatch: '*'` on write (no silent overwrite), SSE-KMS,
   versioning, and Object Lock in COMPLIANCE mode. The application IAM role is granted
   PutObject/GetObject with an explicit `Deny` on DeleteObject, PutObjectRetention and
   BypassGovernanceRetention.
4. **Authorization snapshot inside the hashed body** — the capability set that applied when the
   evidence was captured is part of what gets hashed, so a reviewer can always see the boundary
   in force, and it cannot be edited after the fact.

The chain head pointer (`chain/head.json`) is deliberately *not* Object-Locked: it is an index,
not evidence. Losing it costs a re-scan, not integrity, because the chain is reconstructible
from the bundles themselves.

## IAM posture

Least privilege per function, not per application:

| Function | Notable grants | Notable denials |
| --- | --- | --- |
| `api` | Read all served tables; read-write incidents/actions/rules/ratelimit; PutObject evidence | Deny all evidence deletion; deny audit mutation |
| `analyze` | Read-write user-state/signals/incidents/actions; PutObject evidence; `bedrock:InvokeModel` on the single configured model | Deny all evidence deletion; deny audit mutation |
| `coordination` | Read events; read-write signals | — |
| `alert` | SNS publish; audit append | Deny audit mutation |
| `retention` | Read incidents; **the only** `s3:DeleteObject` on evidence | Deny audit mutation |

**The audit table is append-only by IAM.** Every function gets `PutItem`, `Query` and
`GetItem`, plus an explicit `Deny` on `UpdateItem`, `DeleteItem` and `BatchWriteItem`. The
application cannot rewrite audit history even if this code were changed to try — which is the
point of putting the control in IAM rather than in a method signature.

No function is granted any KMS key-policy action or `ScheduleKeyDeletion`.

## Request handling order

The router applies the same sequence to every route, so a new route cannot accidentally skip a
control:

1. Payload size ceiling — enforced on raw bytes, before JSON parsing.
2. Authentication — claim re-validation (issuer, token type, expiry, app client) as defence in
   depth behind the API Gateway authorizer.
3. Rate limiting — per principal, with separate budgets for ingestion and dashboard traffic.
4. Route resolution — explicit table; an unmatched path is a 404.
5. Authorization — every route declares a required permission; there is no default-allow.
6. Handler.

Error responses carry a stable code and a safe message. Internal details — table names, ARNs,
stack traces, throughput errors — are logged and never returned.

## Observability

Structured JSON logs for CloudWatch Logs Insights, and CloudWatch metrics via the Embedded
Metric Format (so emitting a metric costs a log line, not a synchronous API call on the request
path). Alarms cover Lambda errors and throttles, DLQ depth, and the custom metrics that indicate
a *silent* degradation:

| Metric | Why it alarms |
| --- | --- |
| `EvidenceWriteFailure` | Incidents are being created without supporting evidence |
| `AuditWriteFailure` | The audit trail is incomplete |
| `AuthFailure` | Unusual volume of failed authentication |
| `ClassifierFailure` | Detection has silently degraded to rules only |
| `UserStateConflict` | Concurrency conflicts are dropping state updates |

Logs never contain message content, tokens or raw request bodies. The detectors already produce
human-readable reasons that are safe to record, and those are what gets logged.
