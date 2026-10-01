/**
 * Amazon Bedrock text classifier.
 *
 * Design constraints that matter:
 *   - The classifier is ADVISORY. `response-policy` refuses to apply a durable
 *     penalty on an AI verdict without deterministic corroboration, so a model
 *     error degrades precision, never safety.
 *   - A hard timeout and a never-throw contract: if Bedrock is slow or
 *     unavailable, `classify` returns undefined and detection continues on
 *     rules alone.
 *   - The model is instructed to return strict JSON, and the response is
 *     validated. An unparseable or out-of-range answer is discarded rather than
 *     coerced, because a silently-clamped confidence would corrupt the risk
 *     score.
 *   - Content sent to the model is already sanitized and length-bounded. No
 *     user identifier, room id, or metadata is included: the model needs only
 *     the text, and sending identifiers would widen the data exposure for no
 *     classification benefit.
 */

import { BedrockRuntimeClient, InvokeModelCommand } from '@aws-sdk/client-bedrock-runtime';

import type { Logger, Metrics, TextClassifier } from '../../ports.ts';

export interface BedrockConfig {
  enabled: boolean;
  modelId: string;
  maxTokens: number;
  timeoutMs: number;
  classifierVersion: string;
}

const CLASSIFICATIONS = ['SAFE', 'ABUSIVE', 'SEVERE_ABUSE', 'THREAT', 'UNCERTAIN'] as const;
type Classification = (typeof CLASSIFICATIONS)[number];

/**
 * The rubric is explicit about the distinctions that cause the most
 * disagreement with the deterministic rules — quoted speech, negated intent,
 * in-game banter and self-directed language — so the two layers are judging the
 * same thing and `UNCERTAIN` is reserved for genuine ambiguity.
 */
const SYSTEM_PROMPT = `You are a content-moderation classifier for a voice-chat platform. You classify a single message for abusive content.

Return ONLY a JSON object, no prose, no markdown:
{"classification":"SAFE|ABUSIVE|SEVERE_ABUSE|THREAT|UNCERTAIN","confidence":0.0-1.0,"reason":"one sentence"}

Definitions:
- SAFE: no abuse directed at a person. Ordinary profanity used as emphasis, not aimed at anyone, is SAFE.
- ABUSIVE: insults, demeaning language or harassment aimed at a specific person.
- SEVERE_ABUSE: dehumanising language, identity-based hatred, sexual harassment, or telling someone to kill themselves.
- THREAT: a credible statement of intent to cause physical harm, to appear at someone's location, to dox, or to swat.
- UNCERTAIN: genuinely ambiguous, or you cannot tell who the target is.

Classify as SAFE, not abusive, when the message is:
- quoting or reporting what someone else said (e.g. "he called me a ...", "mods, he said ...")
- explicitly negating intent ("I would never hurt you")
- clearly about in-game action ("I'll destroy you next round")
- self-directed frustration ("I'm so stupid")

Judge only the text given. Do not speculate about the author. Set confidence below 0.6 whenever the target or intent is unclear.`;

export class BedrockClassifier implements TextClassifier {
  readonly enabled: boolean;
  private readonly client: BedrockRuntimeClient;
  private readonly config: BedrockConfig;
  private readonly logger: Logger;
  private readonly metrics: Metrics;

  constructor(
    client: BedrockRuntimeClient,
    config: BedrockConfig,
    logger: Logger,
    metrics: Metrics,
  ) {
    this.client = client;
    this.config = config;
    this.logger = logger;
    this.metrics = metrics;
    this.enabled = config.enabled;
  }

  async classify(
    text: string,
    context: { isTranscript: boolean },
  ): Promise<
    | { classification: Classification; confidence: number; reason: string; modelVersion: string }
    | undefined
  > {
    if (!this.enabled) return undefined;

    const started = Date.now();
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.config.timeoutMs);

    try {
      const userMessage = context.isTranscript
        ? `The following is an automatic speech transcript and may contain recognition errors:\n\n${text}`
        : text;

      const response = await this.client.send(
        new InvokeModelCommand({
          modelId: this.config.modelId,
          contentType: 'application/json',
          accept: 'application/json',
          body: JSON.stringify({
            anthropic_version: 'bedrock-2023-05-31',
            max_tokens: this.config.maxTokens,
            temperature: 0,
            system: SYSTEM_PROMPT,
            messages: [{ role: 'user', content: userMessage }],
          }),
        }),
        { abortSignal: controller.signal },
      );

      this.metrics.gauge('ClassifierLatencyMs', Date.now() - started);

      const raw = new TextDecoder().decode(response.body);
      const parsed = JSON.parse(raw) as { content?: Array<{ text?: unknown }> };
      const completion = parsed.content?.[0]?.text;
      if (typeof completion !== 'string') {
        this.metrics.count('ClassifierUnparseable');
        return undefined;
      }

      const verdict = parseVerdict(completion);
      if (verdict === undefined) {
        this.logger.warn('Bedrock returned an unparseable classification; discarding it.');
        this.metrics.count('ClassifierUnparseable');
        return undefined;
      }

      return {
        ...verdict,
        modelVersion: `bedrock:${this.config.modelId}@${this.config.classifierVersion}`,
      };
    } catch (err: unknown) {
      const aborted = err instanceof Error && err.name === 'AbortError';
      this.logger.warn('Bedrock classification unavailable; continuing on rules only.', {
        timedOut: aborted,
      });
      this.metrics.count(aborted ? 'ClassifierTimeout' : 'ClassifierError');
      return undefined;
    } finally {
      clearTimeout(timer);
    }
  }
}

/**
 * Strictly validate the model's answer.
 * An out-of-range confidence or unknown label is discarded, not repaired —
 * a fabricated value would silently distort the risk score.
 */
function parseVerdict(
  completion: string,
): { classification: Classification; confidence: number; reason: string } | undefined {
  // Tolerate a fenced code block but nothing more creative than that.
  const jsonText = completion
    .trim()
    .replace(/^```(?:json)?\s*/iu, '')
    .replace(/\s*```$/u, '');

  const start = jsonText.indexOf('{');
  const end = jsonText.lastIndexOf('}');
  if (start === -1 || end <= start) return undefined;

  let parsed: unknown;
  try {
    parsed = JSON.parse(jsonText.slice(start, end + 1));
  } catch {
    return undefined;
  }

  if (typeof parsed !== 'object' || parsed === null) return undefined;
  const record = parsed as Record<string, unknown>;

  const classification = record.classification;
  if (
    typeof classification !== 'string' ||
    !CLASSIFICATIONS.includes(classification as Classification)
  ) {
    return undefined;
  }

  const confidence = record.confidence;
  if (typeof confidence !== 'number' || !Number.isFinite(confidence) || confidence < 0 || confidence > 1) {
    return undefined;
  }

  const reason = typeof record.reason === 'string' ? record.reason.slice(0, 400) : '';
  if (reason.length === 0) return undefined;

  return { classification: classification as Classification, confidence, reason };
}

export function createBedrockClient(region: string): BedrockRuntimeClient {
  return new BedrockRuntimeClient({ region });
}
