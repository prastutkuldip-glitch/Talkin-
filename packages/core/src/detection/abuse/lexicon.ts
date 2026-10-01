/**
 * Tiered abuse lexicon and structural threat patterns.
 *
 * DESIGN NOTE — why the built-in word lists are deliberately small:
 *
 * Shipping an exhaustive hard-coded list of slurs in source control is both a
 * liability and ineffective: such lists leak into logs and diffs, go stale, and
 * differ per community, language and reclaimed-usage context. Instead:
 *
 *   - `BUILTIN_MILD` carries only widely-recognised general profanity, used as
 *     a weak signal that never escalates on its own.
 *   - `BUILTIN_SEVERE` carries *structural* severe-abuse patterns (dehumanising
 *     constructions, identity-directed hostility templates) rather than an
 *     enumeration of slurs.
 *   - `THREAT_PATTERNS` are structural and language-driven — threats are
 *     expressed as grammar ("I will <harm> you"), which generalises far better
 *     than a keyword list.
 *   - Operators supply their own curated, community-appropriate term lists via
 *     `AbuseConfig.extraTerms`, administered from the Detection Rules page and
 *     stored in DynamoDB. That is the intended extension point.
 *
 * All matching runs against `normalizeForMatch` output, so obfuscation
 * (`f-u-c-k`, `fսck`, `f\u200Buck`, `phuck`) folds into the same form first.
 */

export const TIERS = ['mild', 'severe', 'threat'] as const;
export type Tier = (typeof TIERS)[number];

/**
 * Weak-signal general profanity. Matched as whole words. Presence alone is
 * never sufficient for a penalty — see `rules.ts` for how this is weighted.
 */
export const BUILTIN_MILD: readonly string[] = [
  'fuck',
  'fucking',
  'shit',
  'bitch',
  'bastard',
  'asshole',
  'dickhead',
  'wanker',
  'prick',
  'cunt',
  'slut',
  'whore',
  'retard',
  'retarded',
];

/**
 * Structural severe-abuse templates. `{t}` expands to a target reference
 * (you / u / him / her / them / <@mention>).
 */
export const BUILTIN_SEVERE_PATTERNS: readonly string[] = [
  // Dehumanisation and eliminationist phrasing.
  String.raw`(?:you|u|they|he|she)\s+(?:are|is|r)\s+(?:not\s+)?(?:a\s+)?(?:human|people|person)`,
  String.raw`(?:sub|non)[\s-]?human`,
  String.raw`(?:should|ought\s+to|need\s+to)\s+(?:all\s+)?(?:die|be\s+(?:killed|gassed|exterminated|wiped\s+out))`,
  String.raw`(?:go\s+)?(?:kill|hang)\s+(?:your\s*self|yourself|urself|ur\s*self)`,
  String.raw`(?:kys)\b`,
  String.raw`(?:no\s+one|nobody)\s+(?:would|will)\s+miss\s+(?:you|u)`,
  String.raw`(?:the\s+world|everyone)\s+(?:would|will)\s+be\s+better\s+(?:off\s+)?without\s+(?:you|u)`,
  // Identity-directed hostility templates (term-agnostic).
  String.raw`(?:all|every)\s+\w+\s+(?:are|should\s+be)\s+(?:killed|gassed|deported|exterminated|eliminated)`,
  String.raw`go\s+back\s+to\s+your\s+(?:country|shithole)`,
  // Sexual harassment directed at a participant.
  String.raw`(?:send|show)\s+(?:me\s+)?(?:your\s+)?(?:nudes|tits|dick)`,
  String.raw`i\s+(?:will|wanna|want\s+to|gonna)\s+(?:rape|molest)\s+(?:you|u|her|him|them)`,
];

/**
 * Credible-threat patterns. These are the highest-weight deterministic
 * detections in the system and intentionally require an actor, an intent verb
 * and a target.
 */
export const THREAT_PATTERNS: readonly string[] = [
  // Direct violence: "I'm going to kill you", "ill beat u up", "we will hurt them"
  String.raw`\b(?:i|we|im|i\s*am|ill|i\s*will|we\s*will|were|we\s*are)\b[^.!?]{0,24}\b(?:kill|murder|stab|shoot|strangle|behead|beat|bash|hurt|harm|destroy|end|slit|burn)\b[^.!?]{0,16}\b(?:you|u|yall|him|her|them|your\s+family|ur\s+family)\b`,
  // "you're dead", "you are a dead man"
  String.raw`\b(?:you|u|yall)\s*(?:are|re|r)?\s*(?:a\s+)?dead\s*(?:man|meat)?\b`,
  // Location-based intimidation / stalking
  String.raw`\bi\s*(?:know|found\s+out)\b[^.!?]{0,20}\bwhere\s+(?:you|u|he|she|they)\s+(?:live|work|sleep|go\s+to\s+school)`,
  String.raw`\bi\s*(?:am|m)?\s*(?:coming|gonna\s+come|going\s+to\s+come)\s+(?:to\s+)?(?:your|ur)\s+(?:house|home|place|school|work)`,
  String.raw`\bwatch\s+(?:your|ur)\s+back\b`,
  String.raw`\b(?:sleep\s+with\s+one\s+eye\s+open)\b`,
  // Doxxing threats
  String.raw`\bi\s*(?:will|ll|m\s+gonna|am\s+going\s+to)\b[^.!?]{0,20}\b(?:dox|doxx|leak|post|expose)\b[^.!?]{0,24}\b(?:your|ur|his|her|their)\s+(?:address|number|info|details|photos|nudes|identity)`,
  // Swatting
  String.raw`\b(?:swat|swatting)\s+(?:you|u|him|her|them)\b`,
  String.raw`\b(?:send|call)\s+(?:the\s+)?(?:cops|police|swat)\s+(?:to|on)\s+(?:your|ur|his|her|their)\b`,
  // Weapon possession paired with a target
  String.raw`\bi\s+(?:have|got|own)\s+(?:a\s+)?(?:gun|knife|bomb|weapon)\b[^.!?]{0,24}\b(?:you|u|him|her|them)\b`,
  // Threats to family/children
  String.raw`\b(?:i|we)\b[^.!?]{0,20}\b(?:hurt|kill|take|touch)\b[^.!?]{0,16}\b(?:your|ur)\s+(?:kids|children|daughter|son|wife|husband|mother|father|mom|dad)\b`,
];

/**
 * Contexts that *reduce* or remove an abuse finding. These are the main
 * false-positive guards and are applied before any signal is emitted.
 */
export const MITIGATING_PATTERNS: readonly { name: string; pattern: string }[] = [
  {
    name: 'reported-speech',
    // "he called me a ...", "they said ... to me", "someone told me ..."
    pattern: String.raw`\b(?:he|she|they|someone|somebody|he\s*/\s*she|that\s+guy|this\s+user|\w+)\s+(?:called|said|told|typed|wrote|messaged|dm'?d)\s+(?:me|us|him|her|them)\b`,
  },
  {
    name: 'quotation',
    pattern: String.raw`["“'][^"”']{3,}["”']`,
  },
  {
    name: 'negated-intent',
    // "I would never hurt you", "I'm not going to kill anyone"
    pattern: String.raw`\b(?:never|not|don'?t|doesn'?t|wouldn'?t|won'?t|would\s+never|no\s+way)\b[^.!?]{0,24}\b(?:kill|hurt|harm|beat|stab|shoot|threaten)\b`,
  },
  {
    name: 'reporting-abuse',
    // A user reporting abuse to a moderator should not be penalised for
    // repeating what was said to them.
    pattern: String.raw`\b(?:report|reporting|flag|flagging|mod|mods|moderator|admin)\b[^.!?]{0,40}\b(?:said|called|threatened|abusing|harassing|spamming)\b`,
  },
  {
    name: 'self-directed',
    // "I'm so stupid", "I hate myself" — a wellbeing concern, not abuse of
    // another participant. Routed to support, never to enforcement.
    pattern: String.raw`\b(?:i|im|i\s*am|i\s*m)\b[^.!?]{0,12}\b(?:so\s+)?(?:stupid|dumb|an?\s+idiot|useless|worthless|trash)\b|\bi\s+hate\s+(?:my\s*self|myself)\b`,
  },
  {
    name: 'gaming-context',
    // "I'll kill you in the next round", "destroy you at chess"
    pattern: String.raw`\b(?:kill|destroy|beat|crush|wreck|smoke)\b[^.!?]{0,30}\b(?:in\s+(?:the\s+)?(?:game|match|round|rank|lobby|server)|at\s+(?:chess|fifa|cod|valorant|csgo|dota|lol)|next\s+(?:game|round|match))\b`,
  },
];

/** Self-harm indicators — handled as a wellbeing route, never as enforcement. */
export const SELF_HARM_PATTERNS: readonly string[] = [
  String.raw`\bi\s*(?:want|wanna|am\s+going|m\s+going|will)\s+to?\s*(?:kill\s+my\s*self|end\s+(?:it|my\s+life)|die)\b`,
  String.raw`\bi\s*(?:don'?t|dont)\s+want\s+to\s+(?:live|be\s+here)\b`,
  String.raw`\b(?:suicidal|suicide)\b[^.!?]{0,20}\b(?:i|me|my)\b`,
];

export interface CompiledLexicon {
  mild: RegExp;
  severe: RegExp;
  threat: RegExp;
  allow: RegExp | undefined;
  mitigating: ReadonlyArray<{ name: string; re: RegExp }>;
  selfHarm: RegExp;
  /**
   * Boundary-relaxed variants, used ONLY against text that has been collapsed
   * from a letter-spaced form ("k i l l  y o u" -> "killyou").
   *
   * Collapsing destroys word boundaries, so `\b`-anchored patterns can never
   * match the result. These variants drop `\b` so the pattern still fires.
   * They are intentionally not applied to normal text, where dropping word
   * boundaries would cause substring false positives (e.g. matching a term
   * inside an unrelated longer word).
   */
  dense: { mild: RegExp; severe: RegExp; threat: RegExp };
  /** Version string recorded on every decision this lexicon contributes to. */
  version: string;
}

function wordListToPattern(terms: readonly string[]): string | undefined {
  const cleaned = terms
    .map((t) => t.trim().toLowerCase())
    .filter((t) => t.length > 0)
    .map(escapeRegex)
    // Allow the normalizer's residual single spaces between characters.
    .map((t) => t.replace(/\\?\s+/gu, String.raw`\s*`));
  if (cleaned.length === 0) return undefined;
  return String.raw`\b(?:${cleaned.join('|')})\b`;
}

function escapeRegex(input: string): string {
  return input.replace(/[.*+?^${}()|[\]\\]/gu, String.raw`\$&`);
}

const NEVER_MATCH = /(?!)/u;

/**
 * Compile the built-in lists plus operator extensions into regexes.
 * Called once per config version and cached by the caller.
 */
export function compileLexicon(extra: {
  mild: readonly string[];
  severe: readonly string[];
  threat: readonly string[];
  allow: readonly string[];
  version: string;
}): CompiledLexicon {
  const mildPattern = wordListToPattern([...BUILTIN_MILD, ...extra.mild]);
  const severePattern = [
    ...BUILTIN_SEVERE_PATTERNS,
    ...(wordListToPattern(extra.severe) ? [wordListToPattern(extra.severe) as string] : []),
  ].join('|');
  const threatPattern = [
    ...THREAT_PATTERNS,
    ...(wordListToPattern(extra.threat) ? [wordListToPattern(extra.threat) as string] : []),
  ].join('|');
  const allowPattern = wordListToPattern(extra.allow);

  return {
    mild: mildPattern ? new RegExp(mildPattern, 'giu') : NEVER_MATCH,
    severe: new RegExp(severePattern, 'giu'),
    threat: new RegExp(threatPattern, 'giu'),
    allow: allowPattern ? new RegExp(allowPattern, 'giu') : undefined,
    mitigating: MITIGATING_PATTERNS.map((m) => ({ name: m.name, re: new RegExp(m.pattern, 'iu') })),
    selfHarm: new RegExp(SELF_HARM_PATTERNS.join('|'), 'iu'),
    dense: {
      mild: mildPattern ? denseVariant(mildPattern) : NEVER_MATCH,
      severe: denseVariant(severePattern),
      threat: denseVariant(threatPattern),
    },
    version: extra.version,
  };
}

/**
 * Strip word-boundary and whitespace assertions so a pattern can match text
 * whose spacing has been removed. `\s*` / `\s+` become `\s*` (still optional),
 * and `\b` is dropped entirely.
 */
function denseVariant(pattern: string): RegExp {
  const relaxed = pattern
    .replace(/\\b/gu, '')
    .replace(/\\s\+/gu, String.raw`\s*`);
  return new RegExp(relaxed, 'giu');
}

/** Collect unique matches for a global regex without leaking regex state. */
export function matchAll(re: RegExp, text: string): string[] {
  if (re === NEVER_MATCH) return [];
  const global = re.global ? re : new RegExp(re.source, `${re.flags}g`);
  global.lastIndex = 0;
  const out = new Set<string>();
  let m: RegExpExecArray | null = global.exec(text);
  let guard = 0;
  while (m !== null && guard < 200) {
    if (m[0].length === 0) {
      global.lastIndex += 1;
    } else {
      out.add(m[0].toLowerCase());
    }
    m = global.exec(text);
    guard += 1;
  }
  return [...out];
}
