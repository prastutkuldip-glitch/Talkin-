import { api } from '../api/client.ts';
import { useAsync, navigate } from '../hooks.ts';
import {
  Empty,
  ErrorNotice,
  Loading,
  Panel,
  RiskBadge,
  StatCard,
  timeAgo,
} from '../components/ui.tsx';

export function OverviewPage(): JSX.Element {
  const { data, error, loading, reload } = useAsync(() => api.overview());

  if (loading && data === undefined) return <Loading what="overview" />;
  if (error !== undefined) return <ErrorNotice error={error} onRetry={reload} />;
  if (data === undefined) return <Empty message="No data." />;

  const maxCount = Math.max(1, ...data.riskDistribution.map((d) => d.count));
  const maxSignal = Math.max(1, ...data.topSignals.map((s) => s.count));

  return (
    <div className="page">
      <div className="stat-grid">
        <StatCard
          label="Active incidents"
          value={data.activeIncidents}
          tone={data.activeIncidents > 0 ? 'danger' : 'neutral'}
          hint="Open, awaiting review"
        />
        <StatCard
          label="High-risk users"
          value={data.highRiskUsers}
          tone={data.highRiskUsers > 0 ? 'warn' : 'neutral'}
          hint="HIGH or CRITICAL"
        />
        <StatCard label="Spam events" value={data.spamEvents} hint="Spam, frequency, coordination" />
        <StatCard label="Abuse events" value={data.abuseEvents} hint="Abuse and threat findings" />
        <StatCard
          label="Blocked events"
          value={data.blockedEvents}
          hint="Blocks that actually took effect"
        />
      </div>

      <div className="two-col">
        <Panel title="Risk distribution" subtitle="Users by current risk band">
          <ul className="bars">
            {data.riskDistribution.map((d) => (
              <li key={d.level}>
                <span className="bar-label">
                  <RiskBadge level={d.level} /> <span className="muted">{d.range}</span>
                </span>
                <span className="bar-track">
                  <span
                    className={`bar-fill bar-${d.level.toLowerCase()}`}
                    style={{ width: `${(d.count / maxCount) * 100}%` }}
                  />
                </span>
                <span className="bar-value">{d.count}</span>
              </li>
            ))}
          </ul>
        </Panel>

        <Panel title="Most frequent detections" subtitle="Across the recent signal window">
          {data.topSignals.length === 0 ? (
            <Empty message="No detections in the current window." />
          ) : (
            <ul className="bars">
              {data.topSignals.map((s) => (
                <li key={s.code}>
                  <span className="bar-label mono">{s.code}</span>
                  <span className="bar-track">
                    <span
                      className="bar-fill bar-neutral"
                      style={{ width: `${(s.count / maxSignal) * 100}%` }}
                    />
                  </span>
                  <span className="bar-value">{s.count}</span>
                </li>
              ))}
            </ul>
          )}
        </Panel>
      </div>

      <Panel
        title="Recent incidents"
        subtitle="Newest first"
        actions={
          <button type="button" className="btn" onClick={() => navigate('incidents')}>
            View all
          </button>
        }
      >
        {data.recentIncidents.length === 0 ? (
          <Empty message="No incidents recorded." />
        ) : (
          <table className="table">
            <thead>
              <tr>
                <th>Incident</th>
                <th>User</th>
                <th>Room</th>
                <th>Risk</th>
                <th>Status</th>
                <th>Detected</th>
                <th>Opened</th>
              </tr>
            </thead>
            <tbody>
              {data.recentIncidents.map((i) => (
                <tr
                  key={i.incidentId}
                  className="clickable"
                  onClick={() => navigate('incidents', i.incidentId)}
                >
                  <td className="mono">{i.incidentId}</td>
                  <td className="mono">{i.userId}</td>
                  <td className="mono">{i.roomId ?? '—'}</td>
                  <td>
                    <RiskBadge level={i.riskLevel} score={i.riskScore} />
                  </td>
                  <td>
                    <span className={`tag status-${i.status.toLowerCase()}`}>{i.status}</span>
                  </td>
                  <td>
                    <div className="chips">
                      {i.topBehaviors.map((b) => (
                        <span key={b} className="chip mono">
                          {b}
                        </span>
                      ))}
                    </div>
                  </td>
                  <td className="muted">{timeAgo(i.createdAtMs)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Panel>
    </div>
  );
}
