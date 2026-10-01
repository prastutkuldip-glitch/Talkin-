import { useEffect, useState } from 'react';

import { api, ApiError } from '../api/client.ts';
import { useAsync } from '../hooks.ts';
import { Empty, ErrorNotice, Loading, Panel } from '../components/ui.tsx';

/**
 * Detection Rules editor.
 *
 * Operators tune thresholds and weights here. Two deliberate choices:
 *   - Only numeric scalars are editable in the form. Term lists and allow-lists
 *     are edited as JSON, because a free-text field for abuse terms needs the
 *     reviewer to see exactly what they are committing.
 *   - The server re-validates every patch and rejects unsafe values (for
 *     example lowering the auto-action confidence floor below 0.5). The UI shows
 *     those rejections verbatim rather than pre-filtering them, so the operator
 *     learns the real constraint.
 */

const SPAM_FIELDS: Array<{ key: string; label: string; hint: string }> = [
  { key: 'burstCount', label: 'Burst count', hint: 'Messages within the burst window that trip a flood signal' },
  { key: 'burstWindowMs', label: 'Burst window (ms)', hint: 'Short-window flood detection' },
  { key: 'highFrequencyCount', label: 'High-frequency count', hint: 'Messages within the main window' },
  { key: 'windowMs', label: 'Main window (ms)', hint: 'Sliding window for frequency analysis' },
  { key: 'identicalRepeatCount', label: 'Identical repeats', hint: 'Identical messages before a spam signal' },
  { key: 'identicalSevereCount', label: 'Identical repeats (severe)', hint: 'Count at which repetition is SEVERE' },
  { key: 'identicalShortMessageLength', label: 'Short-message length', hint: 'At or below this length, repeat thresholds are multiplied' },
  { key: 'identicalShortRepeatMultiplier', label: 'Short-message multiplier', hint: 'Tolerance for repeated short phrases like "lol"' },
  { key: 'coordinationMinContentLength', label: 'Coordination min length', hint: 'Content shorter than this is not treated as cross-account coordination' },
  { key: 'nearDuplicateCount', label: 'Near-duplicate count', hint: 'Similar messages before a template-spam signal' },
  { key: 'mentionsPerMessage', label: 'Mentions per message', hint: 'Mention-flood limit for one message' },
  { key: 'mentionsPerWindow', label: 'Mentions per window', hint: 'Mention-flood limit across the window' },
  { key: 'linksPerWindow', label: 'Links per message', hint: 'Distinct links before a link-flood signal' },
  { key: 'timingMinSamples', label: 'Timing min samples', hint: 'Messages required before timing is judged' },
  { key: 'sustainedCount', label: 'Sustained count', hint: 'Messages per sustained window implying automation' },
];

export function DetectionRulesPage(): JSX.Element {
  const { data, error, loading, reload } = useAsync(() => api.rules());

  const [spam, setSpam] = useState<Record<string, number>>({});
  const [weights, setWeights] = useState<Record<string, number>>({});
  const [thresholds, setThresholds] = useState<Record<string, number>>({});
  const [termsJson, setTermsJson] = useState('');
  const [reason, setReason] = useState('');
  const [saving, setSaving] = useState(false);
  const [saveError, setSaveError] = useState<{ message: string; problems: string[] } | undefined>();
  const [saved, setSaved] = useState<string | undefined>();

  useEffect(() => {
    if (data === undefined) return;
    const numericSpam: Record<string, number> = {};
    for (const field of SPAM_FIELDS) {
      const value = data.effective.spam[field.key];
      if (typeof value === 'number') numericSpam[field.key] = value;
    }
    setSpam(numericSpam);
    setWeights({ ...data.effective.risk.weights });
    setThresholds({ ...data.effective.risk.thresholds });
    setTermsJson(
      JSON.stringify(
        {
          extraTerms: data.effective.abuse.extraTerms ?? { mild: [], severe: [], threat: [] },
          allowTerms: data.effective.abuse.allowTerms ?? [],
        },
        null,
        2,
      ),
    );
  }, [data]);

  if (loading && data === undefined) return <Loading what="detection rules" />;
  if (error !== undefined) return <ErrorNotice error={error} onRetry={reload} />;
  if (data === undefined) return <Empty message="Rules unavailable." />;

  const save = async (): Promise<void> => {
    setSaving(true);
    setSaveError(undefined);
    setSaved(undefined);

    let abusePatch: Record<string, unknown> = {};
    try {
      const parsed = JSON.parse(termsJson) as Record<string, unknown>;
      abusePatch = {
        extraTerms: parsed.extraTerms ?? { mild: [], severe: [], threat: [] },
        allowTerms: parsed.allowTerms ?? [],
      };
    } catch {
      setSaveError({
        message: 'The term lists are not valid JSON.',
        problems: ['Fix the JSON syntax in the abuse term list before saving.'],
      });
      setSaving(false);
      return;
    }

    try {
      const result = await api.saveRules(
        { spam, risk: { weights, thresholds }, abuse: abusePatch },
        reason.trim().length > 0 ? reason.trim() : 'Detection rules updated from the console.',
      );
      setSaved(result.version);
      setReason('');
      reload();
    } catch (err) {
      setSaveError(
        err instanceof ApiError
          ? { message: err.message, problems: err.problems }
          : { message: 'The rules could not be saved.', problems: [] },
      );
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="page">
      <Panel
        title="Detection rules"
        subtitle={`Active configuration version: ${data.version}. Changes are validated server-side and recorded in the audit log.`}
      >
        <div className="notice notice-unavailable inline">
          <strong>Tuning changes behaviour immediately.</strong>
          <p>
            Lowering a threshold increases sensitivity and false positives; raising it risks missed
            abuse. Use the Risk Analysis page and the mock scenario verifier
            (<span className="mono">npm run mock:stream verify</span>) to check a change before
            applying it to production traffic.
          </p>
        </div>
      </Panel>

      <Panel title="Spam and automation thresholds" subtitle="All values are operator-configurable">
        <div className="field-grid">
          {SPAM_FIELDS.map((field) => (
            <div key={field.key} className="field">
              <label htmlFor={`spam-${field.key}`}>{field.label}</label>
              <input
                id={`spam-${field.key}`}
                type="number"
                value={spam[field.key] ?? 0}
                onChange={(e) =>
                  setSpam({ ...spam, [field.key]: Number(e.target.value) })
                }
              />
              <span className="muted small">{field.hint}</span>
            </div>
          ))}
        </div>
      </Panel>

      <Panel title="Risk bands" subtitle="Lower bound of each level. Must be strictly increasing.">
        <div className="field-grid">
          {(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'] as const).map((level) => (
            <div key={level} className="field">
              <label htmlFor={`threshold-${level}`}>{level}</label>
              <input
                id={`threshold-${level}`}
                type="number"
                min={0}
                max={100}
                disabled={level === 'LOW'}
                value={thresholds[level] ?? 0}
                onChange={(e) => setThresholds({ ...thresholds, [level]: Number(e.target.value) })}
              />
              {level === 'LOW' && <span className="muted small">Always 0</span>}
            </div>
          ))}
        </div>
      </Panel>

      <Panel title="Signal weights" subtitle="Points added to the risk score per detection (0–100)">
        <div className="field-grid">
          {Object.keys(weights)
            .sort()
            .map((code) => (
              <div key={code} className="field">
                <label htmlFor={`weight-${code}`} className="mono small">
                  {code}
                </label>
                <input
                  id={`weight-${code}`}
                  type="number"
                  min={0}
                  max={100}
                  value={weights[code] ?? 0}
                  onChange={(e) => setWeights({ ...weights, [code]: Number(e.target.value) })}
                />
              </div>
            ))}
        </div>
      </Panel>

      <Panel
        title="Abuse term lists"
        subtitle="Operator-supplied terms, layered over the built-in structural patterns"
      >
        <p className="muted">
          The built-in lexicon carries structural threat and severe-abuse patterns plus a small set
          of general profanity. Community-specific terms belong here, as does the allow-list for
          terms your community uses non-abusively. Edited as JSON so you can see exactly what you
          are committing.
        </p>
        <textarea
          className="code"
          rows={12}
          value={termsJson}
          onChange={(e) => setTermsJson(e.target.value)}
          spellCheck={false}
        />
      </Panel>

      <Panel title="Apply changes" subtitle="A reason is recorded with the configuration version">
        <div className="form">
          <label htmlFor="rules-reason">Reason for this change</label>
          <input
            id="rules-reason"
            type="text"
            value={reason}
            placeholder="e.g. raising burst threshold after false positives in quiz rooms"
            onChange={(e) => setReason(e.target.value)}
          />
          <div className="form-actions">
            <button
              type="button"
              className="btn btn-primary"
              disabled={saving}
              onClick={() => void save()}
            >
              {saving ? 'Saving…' : 'Save detection rules'}
            </button>
            <button type="button" className="btn" onClick={reload} disabled={saving}>
              Discard changes
            </button>
          </div>

          {saved !== undefined && (
            <div className="notice notice-ok inline">
              Saved as configuration version <span className="mono">{saved}</span>. The change is
              recorded in System Logs.
            </div>
          )}

          {saveError !== undefined && (
            <div className="notice notice-error inline">
              <strong>{saveError.message}</strong>
              {saveError.problems.length > 0 && (
                <ul>
                  {saveError.problems.map((p) => (
                    <li key={p}>{p}</li>
                  ))}
                </ul>
              )}
            </div>
          )}
        </div>
      </Panel>
    </div>
  );
}
