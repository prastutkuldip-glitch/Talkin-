/**
 * @talkinshield/core — pure detection, risk, policy and evidence logic.
 *
 * This package has zero runtime dependencies and performs no I/O. That is
 * deliberate: the entire decision path is a pure function of its inputs, so it
 * can be exhaustively tested, replayed against historical data, and reasoned
 * about without AWS, network access, or mocks.
 */

// Types
export * from './types/index.ts';

// Configuration
export * from './config/detection-config.ts';

// Validation
export * from './validation/event-validator.ts';

// Detection
export * from './detection/spam.ts';
export * from './detection/client.ts';
export * from './detection/evasion.ts';
export * from './detection/ghost.ts';
export * from './detection/coordination.ts';
export * from './detection/abuse/classifier.ts';
export {
  compileLexicon,
  matchAll,
  BUILTIN_MILD,
  BUILTIN_SEVERE_PATTERNS,
  THREAT_PATTERNS,
  MITIGATING_PATTERNS,
  SELF_HARM_PATTERNS,
  TIERS,
  type CompiledLexicon,
  type Tier,
} from './detection/abuse/lexicon.ts';

// Risk & response
export * from './risk/engine.ts';
export * from './response/policy.ts';

// Evidence
export * from './evidence/record.ts';

// Pipeline
export * from './pipeline/analyze.ts';
export * from './pipeline/incident.ts';

// Utilities
export * from './util/text.ts';
export * from './util/stats.ts';
export * from './util/ids.ts';
