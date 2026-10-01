/** Shared presentational components for the console. */

import type { ReactNode } from 'react';
import type { RiskLevel, UnavailableField } from '../api/types.ts';

export function Panel({
  title,
  subtitle,
  actions,
  children,
}: {
  title: string;
  subtitle?: string;
  actions?: ReactNode;
  children: ReactNode;
}): JSX.Element {
  return (
    <section className="panel">
      <header className="panel-head">
        <div>
          <h2>{title}</h2>
          {subtitle !== undefined && <p className="muted">{subtitle}</p>}
        </div>
        {actions !== undefined && <div className="panel-actions">{actions}</div>}
      </header>
      <div className="panel-body">{children}</div>
    </section>
  );
}

export function RiskBadge({ level, score }: { level: RiskLevel; score?: number }): JSX.Element {
  return (
    <span className={`risk risk-${level.toLowerCase()}`}>
      {level}
      {score !== undefined && <span className="risk-score">{score}/100</span>}
    </span>
  );
}

export function StatCard({
  label,
  value,
  hint,
  tone,
}: {
  label: string;
  value: number | string;
  hint?: string;
  tone?: 'neutral' | 'warn' | 'danger';
}): JSX.Element {
  return (
    <div className={`stat stat-${tone ?? 'neutral'}`}>
      <div className="stat-value">{value}</div>
      <div className="stat-label">{label}</div>
      {hint !== undefined && <div className="stat-hint">{hint}</div>}
    </div>
  );
}

export function SeverityTag({ severity }: { severity: string }): JSX.Element {
  return <span className={`tag sev-${severity.toLowerCase()}`}>{severity}</span>;
}

export function ScopeTag({ scope }: { scope: string }): JSX.Element {
  const label =
    scope === 'LOCAL_TO_REQUESTER'
      ? 'LOCAL ONLY'
      : scope === 'PLATFORM_API'
        ? 'PLATFORM API'
        : 'INTERNAL';
  return <span className={`tag scope-${scope.toLowerCase()}`}>{label}</span>;
}

export function Confidence({ value }: { value: number }): JSX.Element {
  const pct = Math.round(value * 100);
  return (
    <span className="confidence" title={`Detector confidence ${pct}%`}>
      <span className="confidence-bar">
        <span className="confidence-fill" style={{ width: `${pct}%` }} />
      </span>
      {pct}%
    </span>
  );
}

export function Loading({ what = 'data' }: { what?: string }): JSX.Element {
  return <div className="loading">Loading {what}…</div>;
}

export function ErrorNotice({
  error,
  onRetry,
}: {
  error: { message: string; problems?: string[] };
  onRetry?: () => void;
}): JSX.Element {
  return (
    <div className="notice notice-error">
      <strong>Something went wrong.</strong>
      <p>{error.message}</p>
      {error.problems !== undefined && error.problems.length > 0 && (
        <ul>
          {error.problems.map((p) => (
            <li key={p}>{p}</li>
          ))}
        </ul>
      )}
      {onRetry !== undefined && (
        <button type="button" className="btn" onClick={onRetry}>
          Retry
        </button>
      )}
    </div>
  );
}

export function Empty({ message }: { message: string }): JSX.Element {
  return <div className="empty">{message}</div>;
}

/**
 * The transparency panel.
 *
 * This is a product requirement, not decoration: a blank panel must never be
 * ambiguous between "nothing was found" and "we were never able to look".
 * `UNAVAILABLE` means the integration cannot provide it; `OUT_OF_SCOPE` means
 * TalkinShield does not collect it under any configuration.
 */
export function TelemetryDisclosure({ fields }: { fields: UnavailableField[] }): JSX.Element {
  if (fields.length === 0) {
    return (
      <div className="notice notice-ok">
        All telemetry categories this deployment relies on are available.
      </div>
    );
  }

  const unavailable = fields.filter((f) => f.status !== 'OUT_OF_SCOPE');
  const outOfScope = fields.filter((f) => f.status === 'OUT_OF_SCOPE');

  return (
    <div className="disclosure">
      {unavailable.length > 0 && (
        <>
          <h4>Not available from this integration</h4>
          <p className="muted">
            These are gaps in what the platform grants us. Panels that depend on them will say
            “Insufficient authorized telemetry.” rather than show an empty result.
          </p>
          <table className="table">
            <thead>
              <tr>
                <th>Data</th>
                <th>Status</th>
                <th>Why</th>
              </tr>
            </thead>
            <tbody>
              {unavailable.map((f) => (
                <tr key={f.field}>
                  <td>{f.field}</td>
                  <td>
                    <span className="tag status-unavailable">{f.status}</span>
                  </td>
                  <td className="muted">{f.reason}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      )}

      {outOfScope.length > 0 && (
        <>
          <h4>Never collected, by design</h4>
          <p className="muted">
            TalkinShield is a defensive moderation tool. These categories are outside its remit
            under every configuration — there is no setting that enables them.
          </p>
          <table className="table">
            <thead>
              <tr>
                <th>Data</th>
                <th>Why not</th>
              </tr>
            </thead>
            <tbody>
              {outOfScope.map((f) => (
                <tr key={f.field}>
                  <td>{f.field}</td>
                  <td className="muted">{f.reason}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      )}
    </div>
  );
}

export function InsufficientTelemetry({ what, reason }: { what: string; reason?: string }): JSX.Element {
  return (
    <div className="notice notice-unavailable">
      <strong>Insufficient authorized telemetry.</strong>
      <p>
        {what} cannot be assessed by this deployment.
        {reason !== undefined ? ` ${reason}` : ''}
      </p>
      <p className="muted">
        TalkinShield will not attempt to obtain this data by any other means.
      </p>
    </div>
  );
}

export function timeAgo(ms: number): string {
  const delta = Date.now() - ms;
  if (delta < 60_000) return `${Math.max(1, Math.round(delta / 1000))}s ago`;
  if (delta < 3_600_000) return `${Math.round(delta / 60_000)}m ago`;
  if (delta < 86_400_000) return `${Math.round(delta / 3_600_000)}h ago`;
  return `${Math.round(delta / 86_400_000)}d ago`;
}

export function formatTime(ms: number): string {
  return new Date(ms).toISOString().replace('T', ' ').slice(0, 19) + 'Z';
}
