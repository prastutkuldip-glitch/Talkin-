import { api } from '../api/client.ts';
import { useAsync } from '../hooks.ts';
import {
  Confidence,
  Empty,
  ErrorNotice,
  Loading,
  Panel,
  RiskBadge,
  SeverityTag,
} from '../components/ui.tsx';
import type { RiskLevel } from '../api/types.ts';

const LEVELS: RiskLevel[] = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];

export function RiskAnalysisPage(): JSX.Element {
  const rules = useAsync(() => api.rules());
  const signals = useAsync(() => api.signals('200'));
  const users = useAsync(() => api.users('100'));

  if (rules.loading && rules.data === undefined) return <Loading what="risk model" />;
  if (rules.error !== undefined) return <ErrorNotice error={rules.error} onRetry={rules.reload} />;

  const config = rules.data?.effective;
  if (config === undefined) return <Empty message="Risk configuration unavailable." />;

  const thresholds = config.risk.thresholds;
  const weights = Object.entries(config.risk.weights).sort((a, b) => b[1] - a[1]);
  const maxWeight = Math.max(1, ...weights.map(([, w]) => w));

  // Category totals from the live signal window.
  const byCategory = new Map<string, number>();
  for (const s of signals.data?.signals ?? []) {
    byCategory.set(s.category, (byCategory.get(s.category) ?? 0) + 1);
  }
  const maxCategory = Math.max(1, ...byCategory.values());

  return (
    <div className="page">
      <Panel
        title="Risk bands"
        subtitle="Configurable from Detection Rules. A score is the sum of confidence-scaled signal weights, capped at 100."
      >
        <div className="band-strip">
          {LEVELS.map((level) => {
            const lower = thresholds[level];
            const upper =
              level === 'CRITICAL'
                ? 100
                : thresholds[LEVELS[LEVELS.indexOf(level) + 1] as RiskLevel] - 1;
            return (
              <div
                key={level}
                className={`band band-${level.toLowerCase()}`}
                style={{ flexGrow: Math.max(1, upper - lower + 1) }}
              >
                <RiskBadge level={level} />
                <span className="band-range">
                  {lower}–{upper}
                </span>
                <span className="band-count">
                  {users.data?.users.filter((u) => u.riskLevel === level).length ?? 0} users
                </span>
              </div>
            );
          })}
        </div>
      </Panel>

      <div className="two-col">
        <Panel
          title="Signal weights"
          subtitle="Points added per detection, before confidence scaling"
        >
          <ul className="bars">
            {weights.map(([code, weight]) => (
              <li key={code}>
                <span className="bar-label mono small">{code}</span>
                <span className="bar-track">
                  <span
                    className="bar-fill bar-neutral"
                    style={{ width: `${(weight / maxWeight) * 100}%` }}
                  />
                </span>
                <span className="bar-value">+{weight}</span>
              </li>
            ))}
          </ul>
        </Panel>

        <div className="stack">
          <Panel title="Detections by category" subtitle="Current signal window">
            {byCategory.size === 0 ? (
              <Empty message="No detections in the current window." />
            ) : (
              <ul className="bars">
                {[...byCategory.entries()]
                  .sort((a, b) => b[1] - a[1])
                  .map(([category, count]) => (
                    <li key={category}>
                      <span className="bar-label">{category}</span>
                      <span className="bar-track">
                        <span
                          className="bar-fill bar-neutral"
                          style={{ width: `${(count / maxCategory) * 100}%` }}
                        />
                      </span>
                      <span className="bar-value">{count}</span>
                    </li>
                  ))}
              </ul>
            )}
          </Panel>

          <Panel title="Safeguards in the scoring model" subtitle="Why a single signal cannot escalate a user">
            <dl className="facts">
              <div>
                <dt>Confidence scaling floor</dt>
                <dd>{config.risk.confidenceScalingFloor}</dd>
              </div>
              <div>
                <dt>Max single contribution</dt>
                <dd>{config.risk.maxSingleContribution} points</dd>
              </div>
              <div>
                <dt>Repeat-violation bonus</dt>
                <dd>
                  +{config.risk.repeatViolationWeight} each, capped at {config.risk.maxRepeatBonus}
                </dd>
              </div>
              <div>
                <dt>History half-life</dt>
                <dd>{Math.round(config.risk.historyHalfLifeMs / 3_600_000)}h</dd>
              </div>
              <div>
                <dt>Max carried history</dt>
                <dd>{config.risk.maxHistoryComponent} points</dd>
              </div>
              <div>
                <dt>Automated action floor</dt>
                <dd>{config.risk.criticalAutoActionMinConfidence} confidence</dd>
              </div>
            </dl>
            <p className="muted small">
              A signal below the scaling floor contributes proportionally less than its weight. An
              automated platform restriction additionally requires at least one deterministic
              (non-AI) signal, so an AI prediction alone can never trigger one.
            </p>
          </Panel>
        </div>
      </div>

      <Panel title="Strongest recent detections" subtitle="Highest confidence first">
        {(signals.data?.signals.length ?? 0) === 0 ? (
          <Empty message="No detections in the current window." />
        ) : (
          <table className="table">
            <thead>
              <tr>
                <th>Detection</th>
                <th>Category</th>
                <th>Severity</th>
                <th>Confidence</th>
                <th>Weight</th>
                <th>Reason</th>
              </tr>
            </thead>
            <tbody>
              {[...(signals.data?.signals ?? [])]
                .sort((a, b) => b.confidence - a.confidence)
                .slice(0, 20)
                .map((s, i) => (
                  <tr key={`${s.code}-${i}`}>
                    <td className="mono">{s.code}</td>
                    <td>{s.category}</td>
                    <td>
                      <SeverityTag severity={s.severity} />
                    </td>
                    <td>
                      <Confidence value={s.confidence} />
                    </td>
                    <td>+{config.risk.weights[s.code] ?? 0}</td>
                    <td className="reason">{s.reason}</td>
                  </tr>
                ))}
            </tbody>
          </table>
        )}
      </Panel>
    </div>
  );
}
