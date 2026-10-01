# Privacy and data handling

TalkinShield is a moderation tool, so it necessarily processes some content about people. This
document states what it keeps, for how long, and what it deliberately does not keep.

## Data minimization

**Only what detection needs.** The per-user detection window stores *fingerprints* of messages,
not the messages themselves — a normalised, punctuation-stripped hash sufficient to answer "is
this the same message again?" and nothing more. Full text is retained only in incident excerpts
and evidence bundles, where a reviewer genuinely needs it.

**Redacted before storage.** Every excerpt passes through identifier redaction before it is
written. Emails, phone numbers, IP addresses, long opaque tokens and card-like number sequences
are replaced with `[redacted-…]` markers. An abuse excerpt does not need the target's email
address to be useful, and a credential that happens to appear in chat must never be persisted.

**Truncated.** Excerpts are capped at `abuse.excerptMaxChars` (280 by default).

**Bounded state.** The detection window is capped at `spam.maxWindowEvents` entries and the
abusive-fingerprint list at 50. Per-user state cannot grow without limit.

**Pseudonymous display handles.** `displayHandle(userId, salt)` derives a short, non-reversible
handle so operators can discuss a case without the raw platform identifier being on screen
throughout.

## Never collected

Under any configuration. These appear in every evidence bundle's `authorization.notCollected`
list and on the console's data-boundary panels, so their absence is explicit rather than
ambiguous:

- Location or GPS data
- Device identifiers, hardware details, filesystem contents
- Credentials, tokens, passwords
- Contacts, camera or microphone access
- Network traffic

See [`AUTHORIZATION_BOUNDARY.md`](AUTHORIZATION_BOUNDARY.md) for the full list and the reasoning.

## Authorized vs unavailable

The system distinguishes four states for any piece of data, and the UI renders them differently:

| State | Meaning |
| --- | --- |
| `AUTHORIZED` | We hold authorization and the data is present |
| `AUTHORIZED_EMPTY` | We hold authorization, queried, and found nothing |
| `UNAVAILABLE` | The integration does not expose it |
| `NOT_AUTHORIZED` | It exists but this deployment may not read it |

The distinction between `AUTHORIZED_EMPTY` and `UNAVAILABLE` is the one that matters most
operationally: a blank panel must never be mistaken for a clean result. Where a capability is
missing, the console shows *"Insufficient authorized telemetry."* rather than an empty table.

## Retention

| Data | Default | Rationale |
| --- | --- | --- |
| Raw events | 30 days | Only needed for the detection window and incident excerpts |
| Detection signals | 90 days | Supports trend analysis and threshold tuning |
| Incidents | 365 days | Case history and appeal handling |
| Evidence | 365 days | Must be ≥ incident retention, enforced at config load and at CDK synth |
| Audit log | 730 days | Longest, because it is the record of what the *operators* did |

Enforcement is layered: DynamoDB TTL expires events, signals and audit entries without
application involvement; a daily Lambda handles evidence, which Object Lock prevents from being
lifecycle-expired early.

**Evidence retention may not be shorter than incident retention.** An incident that outlived its
supporting evidence would be an unexplainable accusation. This is checked when configuration is
loaded and again at CDK synth.

## Deletion

Evidence deletion runs only under the retention policy, only from the retention Lambda (the only
principal granted `s3:DeleteObject`), and only once the Object Lock retain-until date has passed.
Every deletion writes an audit entry recording the content hash, sequence number and creation
date of what was removed — so the resulting gap in the hash chain is *explained*, and chain
verification can distinguish policy-driven deletion from tampering.

## Decision transparency

Every automated moderation decision stores:

- The signal codes that fired, each with a human-readable reason
- The detector name and version that produced each signal
- Confidence per signal and in aggregate
- The risk score, level, and each contribution's weight and applied value
- Which model or ruleset versions were consulted, including any AI model
- Whether the decision rested on deterministic logic alone
- The capability set in force at the time

This is what makes a decision reviewable months later, and appealable. It is also why
`recordAction` throws on an empty reason: an action without a reason is not auditable, and
failing loudly at the point of creation is better than discovering the gap during a review.

## AI processing

When Bedrock is enabled, message text is sent to the model for classification. Only the text is
sent — no user identifier, room identifier or metadata, because the model does not need them and
sending them would widen exposure for no classification benefit. The prompt instructs the model
to judge only the text given.

The model's verdict is advisory. It cannot alone justify a durable penalty, and
`requiresHumanReview` is set whenever AI is the dominant basis for a finding.

## Wellbeing

Language indicating risk to the *sender* (rather than abuse of another participant) is detected
separately and routed to a `WellbeingConcern` event and a support notification. It never
contributes to a risk score and never triggers enforcement. Treating a person in distress as a
policy violator would be both harmful and useless.
