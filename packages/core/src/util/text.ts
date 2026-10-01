/**
 * Text normalization and obfuscation analysis.
 *
 * Abuse and spam detection is mostly a normalization problem: `f r e e  m0ney`,
 * `ｆｒｅｅ ｍｏｎｅｙ` and `fre\u200Be money` are the same message to a human and
 * must become the same string before any rule or lexicon is applied.
 */

/** Zero-width and other invisible formatting characters used to defeat filters. */
const INVISIBLE_RE =
  /[\u00AD\u200B\u200C\u200D\u200E\u200F\u2060\u2061\u2062\u2063\u2064\u206A-\u206F\uFEFF]/gu;

/** Combining marks — a dense run of these is "zalgo" text. */
const COMBINING_RE = /\p{Mn}/gu;

/**
 * Non-Latin letters that visually impersonate a Latin letter. Always safe to
 * fold, because these are letters in any position.
 */
const SCRIPT_CONFUSABLES: Record<string, string> = {
  // Cyrillic
  а: 'a', в: 'b', с: 'c', е: 'e', н: 'h', к: 'k', м: 'm', о: 'o', р: 'p',
  ѕ: 's', т: 't', у: 'y', х: 'x', і: 'i', ј: 'j', ԁ: 'd', ԛ: 'q', ԝ: 'w',
  // Greek
  α: 'a', β: 'b', ε: 'e', ι: 'i', κ: 'k', ν: 'v', ο: 'o', ρ: 'p', τ: 't',
  υ: 'u', χ: 'x', γ: 'y', ς: 's',
};

/**
 * Digit/symbol substitutions ("leetspeak").
 *
 * These are applied ONLY to runs that sit between two letters. Folding them
 * everywhere is actively harmful: it would turn `buy now!!!` into `buy nowiii`
 * (so punctuation variants of the same spam would stop matching each other) and
 * `site number 1111` into `site number iiii`. Restricting to interior runs
 * catches the cases that matter — `m0ney`, `k!ll`, `a$$hole`, `p@ypal` — while
 * leaving ordinary punctuation and real numbers untouched.
 */
const LEET_CONFUSABLES: Record<string, string> = {
  '0': 'o', '1': 'i', '3': 'e', '4': 'a', '5': 's', '7': 't', '8': 'b',
  '@': 'a', $: 's', '!': 'i', '|': 'i', '+': 't', '(': 'c', '€': 'e', '£': 'l',
};

/** Fold leet substitutions only where a run is flanked by letters on both sides. */
function foldInteriorLeet(input: string): string {
  return input.replace(/(?<=[a-z])([^a-z\s]+)(?=[a-z])/gu, (run) =>
    [...run].map((ch) => LEET_CONFUSABLES[ch] ?? ch).join(''),
  );
}

const SCRIPT_TESTS: ReadonlyArray<readonly [string, RegExp]> = [
  ['Latin', /\p{Script=Latin}/u],
  ['Cyrillic', /\p{Script=Cyrillic}/u],
  ['Greek', /\p{Script=Greek}/u],
  ['Arabic', /\p{Script=Arabic}/u],
  ['Hebrew', /\p{Script=Hebrew}/u],
  ['Han', /\p{Script=Han}/u],
  ['Hiragana', /\p{Script=Hiragana}/u],
  ['Katakana', /\p{Script=Katakana}/u],
  ['Hangul', /\p{Script=Hangul}/u],
  ['Thai', /\p{Script=Thai}/u],
  ['Devanagari', /\p{Script=Devanagari}/u],
];

const URL_RE = /\b(?:https?:\/\/|www\.)[^\s<>"']+|\b[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.(?:com|net|org|io|gg|ru|cn|xyz|top|link|me|co|tv|info|biz|online|site)\b(?:\/[^\s<>"']*)?/giu;

const MENTION_RE = /(?:^|[\s(])@([A-Za-z0-9_.-]{2,32})/gu;

/**
 * Strip invisible characters and apply Unicode compatibility folding, without
 * yet collapsing letters. Used when we want to preserve readable text.
 */
export function sanitizeVisible(input: string): string {
  return input.normalize('NFKC').replace(INVISIBLE_RE, '').replace(/\s+/gu, ' ').trim();
}

/**
 * Aggressive normalization used for comparison, lexicon matching and
 * fingerprinting. Lossy by design.
 */
export function normalizeForMatch(input: string): string {
  let s = input.normalize('NFKD').replace(INVISIBLE_RE, '');
  // Drop combining marks so "ạ" and zalgo text fold to plain letters.
  s = s.replace(COMBINING_RE, '');
  s = s.toLowerCase();
  // Letter-for-letter confusables are always folded...
  s = [...s].map((ch) => SCRIPT_CONFUSABLES[ch] ?? ch).join('');
  // ...but symbol/digit substitutions only inside words.
  s = foldInteriorLeet(s);
  // Collapse runs of 3+ identical characters down to 2 ("heyyyyy" -> "heyy").
  s = s.replace(/(.)\1{2,}/gu, '$1$1');
  // Remove separators commonly inserted between letters to defeat filters.
  s = s.replace(/[\s._\-*~`'"^]+/gu, ' ');
  return s.replace(/\s+/gu, ' ').trim();
}

/**
 * A fingerprint for "is this the same message again?". Strips all non
 * alphanumeric characters so punctuation shuffling does not defeat it.
 */
export function fingerprint(input: string): string {
  const normalized = normalizeForMatch(input);
  const stripped = normalized.replace(/[^\p{L}\p{N}]+/gu, '');
  return stripped.length > 0 ? stripped : normalized;
}

/**
 * Collapse letter-spaced text: "f r e e  m o n e y" -> "freemoney".
 * Only applied when most tokens are single characters, so ordinary prose with
 * short words ("a", "I") is unaffected.
 */
export function collapseLetterSpacing(normalized: string): string | undefined {
  const tokens = normalized.split(' ').filter((t) => t.length > 0);
  if (tokens.length < 4) return undefined;
  const singles = tokens.filter((t) => t.length === 1).length;
  if (singles / tokens.length < 0.6) return undefined;
  return tokens.join('');
}

export function countMentions(input: string): number {
  MENTION_RE.lastIndex = 0;
  let count = 0;
  while (MENTION_RE.exec(input) !== null) count += 1;
  return count;
}

export function extractUrls(input: string): string[] {
  URL_RE.lastIndex = 0;
  const found = input.match(URL_RE);
  if (!found) return [];
  return [...new Set(found.map((u) => u.toLowerCase()))];
}

export function scriptsUsed(input: string): string[] {
  const out: string[] = [];
  for (const [name, re] of SCRIPT_TESTS) {
    if (re.test(input)) out.push(name);
  }
  return out;
}

export interface CharacterAnomalies {
  /** Invisible / zero-width characters present. */
  invisibleCount: number;
  /** Invisible characters inserted *inside* words — a filter-evasion marker. */
  invisibleInsideWord: boolean;
  /** Combining marks per base character. */
  combiningRatio: number;
  /** Uppercase letters as a fraction of all letters. */
  capsRatio: number;
  /** Longest run of a single repeated character. */
  maxCharRun: number;
  /** Non-alphanumeric, non-space characters as a fraction of length. */
  symbolRatio: number;
  /** Mixed-script words (e.g. Latin + Cyrillic in one token). */
  mixedScriptWords: number;
  /** Distinct scripts across the whole message. */
  scripts: string[];
  /** True when the message appears to be letter-spaced to defeat filters. */
  letterSpaced: boolean;
}

export function analyzeCharacters(input: string): CharacterAnomalies {
  const invisibleMatches = input.match(INVISIBLE_RE);
  const invisibleCount = invisibleMatches ? invisibleMatches.length : 0;

  // An invisible char with a letter on both sides is almost always deliberate.
  const invisibleInsideWord =
    /\p{L}[\u00AD\u200B\u200C\u200D\u2060\uFEFF]+\p{L}/u.test(input);

  const combining = input.normalize('NFD').match(COMBINING_RE);
  const baseChars = [...input.normalize('NFD').replace(COMBINING_RE, '')].length || 1;
  const combiningRatio = (combining ? combining.length : 0) / baseChars;

  const letters = input.match(/\p{L}/gu) ?? [];
  const uppers = input.match(/\p{Lu}/gu) ?? [];
  const capsRatio = letters.length > 0 ? uppers.length / letters.length : 0;

  let maxCharRun = 0;
  let run = 0;
  let prev = '';
  for (const ch of input) {
    if (ch === prev) {
      run += 1;
    } else {
      run = 1;
      prev = ch;
    }
    if (run > maxCharRun) maxCharRun = run;
  }

  const symbols = input.match(/[^\p{L}\p{N}\s]/gu) ?? [];
  const symbolRatio = input.length > 0 ? symbols.length / input.length : 0;

  let mixedScriptWords = 0;
  for (const word of input.split(/\s+/u)) {
    if (word.length < 2) continue;
    const scripts = scriptsUsed(word).filter((s) => s !== 'Latin');
    if (scripts.length > 0 && /\p{Script=Latin}/u.test(word)) mixedScriptWords += 1;
  }

  const normalized = normalizeForMatch(input);
  const letterSpaced = collapseLetterSpacing(normalized) !== undefined;

  return {
    invisibleCount,
    invisibleInsideWord,
    combiningRatio,
    capsRatio,
    maxCharRun,
    symbolRatio,
    mixedScriptWords,
    scripts: scriptsUsed(input),
    letterSpaced,
  };
}

/** Character trigrams, used for near-duplicate similarity. */
export function trigrams(input: string): Set<string> {
  const s = ` ${normalizeForMatch(input)} `;
  const out = new Set<string>();
  for (let i = 0; i + 3 <= s.length; i += 1) out.add(s.slice(i, i + 3));
  return out;
}

/** Jaccard similarity over character trigrams, 0..1. */
export function similarity(a: string, b: string): number {
  if (a === b) return 1;
  const ta = trigrams(a);
  const tb = trigrams(b);
  if (ta.size === 0 || tb.size === 0) return 0;
  let shared = 0;
  for (const t of ta) if (tb.has(t)) shared += 1;
  return shared / (ta.size + tb.size - shared);
}

/**
 * Redact obvious direct identifiers before text is stored as evidence.
 * Data minimization: an abuse excerpt does not need the target's email or
 * phone number to be useful to a reviewer.
 */
export function redactIdentifiers(input: string): { text: string; redacted: boolean } {
  let redacted = false;
  let text = input;

  const apply = (re: RegExp, token: string): void => {
    text = text.replace(re, () => {
      redacted = true;
      return token;
    });
  };

  apply(/\b[\w.+-]+@[\w-]+\.[\w.-]{2,}\b/gu, '[redacted-email]');
  apply(/\b(?:\+?\d[\d\s().-]{7,}\d)\b/gu, '[redacted-phone]');
  apply(/\b(?:\d{1,3}\.){3}\d{1,3}\b/gu, '[redacted-ip]');
  // Long opaque tokens (API keys, session tokens) must never be retained.
  apply(/\b[A-Za-z0-9_-]{32,}\b/gu, '[redacted-token]');
  apply(/\b\d{13,19}\b/gu, '[redacted-number]');

  return { text, redacted };
}

/** Truncate for storage, preserving whole characters. */
export function truncate(input: string, maxChars: number): string {
  const chars = [...input];
  if (chars.length <= maxChars) return input;
  return `${chars.slice(0, Math.max(0, maxChars - 1)).join('')}…`;
}
