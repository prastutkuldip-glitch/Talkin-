/** Small statistics helpers used by the timing / frequency detectors. */

export function mean(values: readonly number[]): number {
  if (values.length === 0) return 0;
  let total = 0;
  for (const v of values) total += v;
  return total / values.length;
}

export function stdDev(values: readonly number[]): number {
  if (values.length < 2) return 0;
  const m = mean(values);
  let acc = 0;
  for (const v of values) acc += (v - m) ** 2;
  // Sample standard deviation.
  return Math.sqrt(acc / (values.length - 1));
}

/**
 * Coefficient of variation (stdDev / mean).
 *
 * This is the core bot-timing heuristic. A human typing in a chat produces
 * highly irregular gaps (CV typically > 0.4); a scripted sender fires on a
 * near-fixed interval, driving CV toward 0.
 */
export function coefficientOfVariation(values: readonly number[]): number {
  const m = mean(values);
  if (m === 0) return 0;
  return stdDev(values) / m;
}

/** Consecutive differences between sorted timestamps. */
export function deltas(sortedMs: readonly number[]): number[] {
  const out: number[] = [];
  for (let i = 1; i < sortedMs.length; i += 1) {
    const prev = sortedMs[i - 1];
    const cur = sortedMs[i];
    if (prev === undefined || cur === undefined) continue;
    out.push(cur - prev);
  }
  return out;
}

export function clamp(value: number, min: number, max: number): number {
  if (Number.isNaN(value)) return min;
  return Math.min(max, Math.max(min, value));
}

export function round(value: number, places = 2): number {
  const factor = 10 ** places;
  return Math.round(value * factor) / factor;
}

/**
 * Combine independent confidences with a noisy-OR.
 *
 * Several weak, independent indicators should raise confidence, but never to
 * certainty. Used when multiple detector layers agree.
 */
export function noisyOr(confidences: readonly number[]): number {
  let inverse = 1;
  for (const c of confidences) inverse *= 1 - clamp(c, 0, 1);
  return round(1 - inverse, 4);
}

/** Exponential decay by half-life. */
export function decay(value: number, elapsedMs: number, halfLifeMs: number): number {
  if (halfLifeMs <= 0 || elapsedMs <= 0) return value;
  return value * 0.5 ** (elapsedMs / halfLifeMs);
}

/** Map a count onto 0..1, saturating as it approaches `saturationAt`. */
export function saturate(count: number, threshold: number, saturationAt: number): number {
  if (count <= threshold) return 0;
  if (saturationAt <= threshold) return 1;
  return clamp((count - threshold) / (saturationAt - threshold), 0, 1);
}
