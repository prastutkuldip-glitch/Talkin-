# Deployment

## Prerequisites

- Node 22.6 or later (the toolchain uses native TypeScript execution for tests and CDK).
- An AWS account, and credentials with permission to create KMS keys, DynamoDB tables, S3
  buckets with Object Lock, Cognito user pools, Lambda functions, API Gateway, WAF and
  EventBridge rules.
- CDK bootstrapped in the target account and region: `npx cdk bootstrap aws://ACCOUNT/REGION`.
- If using Bedrock: model access granted for your chosen model in that region.

## Build

```bash
npm install
npm test              # core + backend + mocks
npm run typecheck:all
npm run build         # compiles core, backend and the frontend bundle
```

`npm run build` produces `packages/backend/dist`, which is what the CDK Lambda functions
package. Deploying without building first will fail at asset resolution.

## Deploy

Three stacks, deployed together. Stage is selected with `-c stage=...`.

```bash
cd packages/infra

# Development: no platform integration, mock adapter, data destroyed on teardown.
npx cdk deploy --all -c stage=dev -c talkinAdapter=mock

# Production.
npx cdk deploy --all \
  -c stage=prod \
  -c talkinAdapter=http \
  -c talkinApiBaseUrl=https://api.talkin.example/v1 \
  -c talkinApiSecretName=talkinshield/talkin-api \
  -c capMessageContent=true \
  -c capModerationEvents=true \
  -c alertEmail=security-oncall@example.com \
  -c bedrockEnabled=true
```

Stack order is handled by CDK through construct references: `Data` (KMS, DynamoDB, S3) and
`Auth` (Cognito) before `App` (Lambda, API, WAF, EventBridge).

### Production defaults

Setting `stage=prod` changes behaviour deliberately:

- Cognito MFA becomes `REQUIRED`, and `REQUIRE_MFA_FOR_DESTRUCTIVE=true` so platform moderation,
  rule changes and retention deletion need a multi-factor session.
- All data stores use `RemovalPolicy.RETAIN` with deletion protection.
- `talkinAdapter=mock` is **rejected** — the mock adapter fabricates platform responses.
- No CORS origin is pre-authorised; set your console's real origin in `app-stack.ts`.
- `COGNITO_USER_POOL_ID`, `EVIDENCE_BUCKET` and `DISPLAY_HANDLE_SALT` become required.

### Context flags the CDK app refuses

These are guard rails, not suggestions. Synthesis fails rather than deploying something
misleading:

| Condition | Why it is refused |
| --- | --- |
| `stage=prod` with `talkinAdapter=mock` | The mock adapter invents platform responses. |
| `capRemoteMute` / `capRemoteBlock` without `talkinAdapter=http` | There would be no official API to call. |
| `capVoiceAudio` without `confirmVoiceConsent=true` | Processing call audio needs an explicit acknowledgement of lawful basis and consent. |
| `retentionEvidence < retentionIncidents` | An incident would outlive the evidence that justifies it. |

## Post-deploy setup

### 1. Secrets

Store the Talkin API credential and the display-handle salt:

```bash
aws secretsmanager create-secret \
  --name talkinshield/talkin-api \
  --secret-string '{"token":"..."}'
```

The application reads secrets by name at runtime and caches them for the container lifetime.
No credential is ever placed in an environment variable in a deployed stage.

### 2. Operators

Create users and assign groups. Group membership is the only source of authorization.

```bash
POOL=$(aws cloudformation describe-stacks --stack-name TalkinShield-prod-Auth \
  --query "Stacks[0].Outputs[?OutputKey=='UserPoolId'].OutputValue" --output text)

aws cognito-idp admin-create-user --user-pool-id "$POOL" \
  --username alice --user-attributes Name=email,Value=alice@example.com

aws cognito-idp admin-add-user-to-group --user-pool-id "$POOL" \
  --username alice --group-name moderators
```

| Group | Can |
| --- | --- |
| `admins` | Everything, including detection rules, settings and retention |
| `moderators` | Review incidents, act, read and save evidence. **Not** rule changes |
| `viewers` | Read-only. No moderation actions |
| `telemetry-ingest` | Submit telemetry only. No console access |

### 3. Console

Build and host the frontend as static files:

```bash
cd packages/frontend
VITE_API_BASE_URL=https://<api-id>.execute-api.<region>.amazonaws.com \
VITE_COGNITO_DOMAIN=<pool-domain>.auth.<region>.amazoncognito.com \
VITE_COGNITO_CLIENT_ID=<dashboard-client-id> \
VITE_USE_MOCK_API=false \
npm run build
```

Serve `dist/` from S3 behind CloudFront with HTTPS. Add the console's origin to the Cognito app
client's callback URLs and to the API's CORS `allowOrigins`.

The console uses the authorization-code flow with PKCE and holds tokens **in memory only** — not
in `localStorage` — so a persisted token cannot be read by injected script, and the session ends
with the tab. The trade-off is that a page refresh re-runs the redirect, which is silent while the
Cognito session cookie is valid.

### 4. Verify

```bash
# Submit a synthetic scenario against the live ingestion endpoint.
npm run mock:stream -- post \
  --url https://<api-id>.execute-api.<region>.amazonaws.com/events \
  --token "$INGEST_JWT" \
  --scenario identical-message-flood
```

Then confirm, in order:

1. **Overview** shows a non-zero spam count and an open incident.
2. **Incidents** shows the incident with its detection reasons and model versions.
3. **Evidence** verifies the chain as intact.
4. **System Logs** shows `INCIDENT_CREATED` from `system`.
5. **Moderation Actions** shows the correct scope for MUTE given your capability flags — if
   `capRemoteMute` is false it must read LOCAL ONLY.
6. Your alert email received a CRITICAL notification.

If step 5 shows PLATFORM API while `capRemoteMute` is false, stop and check the environment: the
console is reporting an authority the deployment does not have.

## Operating

### Tuning detection

Edit thresholds and weights on the **Detection Rules** page, not through environment variables.
Changes are validated server-side, versioned, and recorded in the audit log with the reason you
supply. Before applying a change to production traffic, check it locally:

```bash
npm run mock:stream verify
```

Fifteen scenarios run through the real pipeline, including `benign-conversation` and
`quiet-room`, which must stay clean. A change that makes either produce signals has introduced a
false positive.

### False positives

Dismiss the incident with status `DISMISSED_FALSE_POSITIVE` and a note explaining the cause. That
emits a `FalsePositiveReported` event and a `FalsePositiveReported` metric dimensioned by the top
signal code, so you can see which detector is noisy before you start adjusting weights.

### Retention

TTL expires events, signals and audit entries automatically. The daily retention Lambda handles
evidence, which cannot be lifecycle-expired early because of Object Lock. It refuses to delete
evidence still referenced by an incident that has not reached its own retention age, and writes
an audit entry for every deletion including the content hash of what was removed — so the
resulting gap in the hash chain is explained rather than suspicious.

### Cost shape

The dominant costs at low-to-moderate volume are Lambda invocations (one analysis per event),
DynamoDB on-demand writes, and Bedrock if enabled. To reduce:

- Set `BEDROCK_ENABLED=false`. Detection remains fully functional on deterministic rules; you
  lose the ability to catch abuse the rules do not model.
- Shorten `RETENTION_RAW_EVENTS_DAYS` — raw events are the highest-volume store and are only
  needed for the detection window and incident excerpts.
- Buffer analysis behind SQS using the `sqsHandler` export in `lambda/analyze.ts`, which batches
  invocations and reports partial batch failures.

### Teardown

```bash
npx cdk destroy --all -c stage=dev
```

In `prod`, data stores are retained by policy and must be removed deliberately. Evidence objects
cannot be deleted before their Object Lock retain-until date — by design.
