import { api } from '../api/client.ts';
import { navigate, useAsync } from '../hooks.ts';
import { ActionBar } from '../components/ActionBar.tsx';
import {
  Confidence,
  Empty,
  ErrorNotice,
  InsufficientTelemetry,
  Loading,
  Panel,
  RiskBadge,
  ScopeTag,
  SeverityTag,
  TelemetryDisclosure,
  formatTime,
  timeAgo,
} from '../components/ui.tsx';

export function UsersPage(): JSX.Element {
  const { data, error, loading, reload } = useAsync(() => api.users());

  if (loading && data === undefined) return <Loading what="users" />;
  if (error !== undefined) return <ErrorNotice error={error} onRetry={reload} />;

  return (
    <div className="page">
      <Panel
        title="Monitored accounts"
        subtitle="Ordered by current risk score. Select an account for detail."
      >
        {(data?.users.length ?? 0) === 0 ? (
          <Empty message="No accounts have produced telemetry yet." />
        ) : (
          <table className="table">
            <thead>
              <tr>
                <th>Account</th>
                <th>Risk</th>
                <th>Room</th>
                <th>Open incidents</th>
                <th>Last seen</th>
              </tr>
            </thead>
            <tbody>
              {data?.users.map((u) => (
                <tr key={u.userId} className="clickable" onClick={() => navigate('users', u.userId)}>
                  <td className="mono">{u.userId}</td>
                  <td>
                    <RiskBadge level={u.riskLevel} score={u.riskScore} />
                  </td>
                  <td className="mono">{u.roomId ?? '—'}</td>
                  <td>{u.openIncidents > 0 ? u.openIncidents : <span className="muted">0</span>}</td>
                  <td className="muted">{timeAgo(u.lastSeenAtMs)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Panel>
    </div>
  );
}

export function UserDetailPage({ userId }: { userId: string }): JSX.Element {
  const user = useAsync(() => api.user(userId), [userId]);
  const affordances = useAsync(() => api.affordances());

  if (user.loading && user.data === undefined) return <Loading what="account detail" />;
  if (user.error !== undefined) return <ErrorNotice error={user.error} onRetry={user.reload} />;

  const d = user.data;
  if (d === undefined) return <Empty message="No telemetry for this account." />;

  return (
    <div className="page">
      {/* The example panel from the specification. */}
      <section className={`risk-card risk-card-${d.riskLevel.toLowerCase()}`}>
        <div className="risk-card-main">
          <dl className="risk-card-facts">
            <div>
              <dt>User</dt>
              <dd className="mono big">{d.userId}</dd>
            </div>
            <div>
              <dt>Status</dt>
              <dd>
                <RiskBadge level={d.riskLevel} />
              </dd>
            </div>
            <div>
              <dt>Room</dt>
              <dd className="mono big">{d.roomId ?? '—'}</dd>
            </div>
            <div>
              <dt>Risk score</dt>
              <dd className="big">
                {d.riskScore}/100 <span className="muted small">band {d.riskRange}</span>
              </dd>
            </div>
          </dl>

          <div className="risk-card-detected">
            <h3>Detected</h3>
            {d.contributions.length === 0 ? (
              <p className="muted">No detections contributed to this score.</p>
            ) : (
              <ul className="checklist">
                {d.contributions.map((c) => (
                  <li key={c.code}>
                    <span className="check">✓</span>
                    <span className="mono">{c.code}</span>
                    <span className="muted"> +{c.applied}</span>
                    <Confidence value={c.confidence} />
                    <div className="muted small">{c.reason}</div>
                  </li>
                ))}
              </ul>
            )}
          </div>
        </div>

        <div className="risk-card-actions">
          <h3>Recommended actions</h3>
          {affordances.data === undefined ? (
            <Loading what="available actions" />
          ) : (
            <ActionBar
              targetUserId={d.userId}
              {...(d.roomId !== undefined ? { roomId: d.roomId } : {})}
              affordances={affordances.data.affordances}
              onActionTaken={() => user.reload()}
            />
          )}
        </div>
      </section>

      <div className="two-col">
        <Panel title="Message frequency" subtitle="Within the configured detection window">
          <dl className="facts">
            <div>
              <dt>Window</dt>
              <dd>{d.messageFrequency.windowSeconds}s</dd>
            </div>
            <div>
              <dt>Messages in window</dt>
              <dd>{d.messageFrequency.count}</dd>
            </div>
            <div>
              <dt>Rate</dt>
              <dd>{d.messageFrequency.perMinute}/min</dd>
            </div>
            <div>
              <dt>Prior violations</dt>
              <dd>{d.priorViolations}</dd>
            </div>
            <div>
              <dt>Evasion episodes</dt>
              <dd>{d.evasionCount}</dd>
            </div>
            <div>
              <dt>Open incidents</dt>
              <dd>{d.openIncidents}</dd>
            </div>
          </dl>
        </Panel>

        <Panel
          title="Client information"
          subtitle="Only what the platform legitimately reports"
        >
          <dl className="facts">
            <div>
              <dt>Declared version</dt>
              <dd className="mono">{d.clientInfo.declaredVersion ?? 'not reported'}</dd>
            </div>
            <div>
              <dt>Declared platform</dt>
              <dd>{d.clientInfo.declaredPlatform ?? 'not reported'}</dd>
            </div>
            <div>
              <dt>Attestation</dt>
              <dd>{d.clientInfo.attestationAvailable ? 'available' : 'not available'}</dd>
            </div>
          </dl>
          <p className="muted small">{d.clientInfo.note}</p>
          {!d.clientInfo.attestationAvailable && (
            <InsufficientTelemetry
              what="Official client verification"
              reason="The platform provides no signed official-build proof, so modified-client findings are behavioural indicators only."
            />
          )}
        </Panel>
      </div>

      <Panel title="Abuse detections" subtitle="Abuse and threat findings for this account">
        {d.abuseDetections.length === 0 ? (
          <Empty message="No abuse or threat findings for this account." />
        ) : (
          <table className="table">
            <thead>
              <tr>
                <th>When</th>
                <th>Detection</th>
                <th>Severity</th>
                <th>Confidence</th>
                <th>Reason</th>
              </tr>
            </thead>
            <tbody>
              {d.abuseDetections.map((s, i) => (
                <tr key={`${s.code}-${i}`}>
                  <td className="muted nowrap">{timeAgo(s.observedAtMs)}</td>
                  <td className="mono">{s.code}</td>
                  <td>
                    <SeverityTag severity={s.severity} />
                  </td>
                  <td>
                    <Confidence value={s.confidence} />
                  </td>
                  <td className="reason">{s.reason}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Panel>

      <Panel title="Recent events" subtitle="Authorized telemetry only">
        {d.recentEvents.length === 0 ? (
          <Empty message="No events recorded." />
        ) : (
          <table className="table dense">
            <thead>
              <tr>
                <th>Timestamp</th>
                <th>Type</th>
                <th>Room</th>
                <th>Content</th>
              </tr>
            </thead>
            <tbody>
              {d.recentEvents.map((e) => (
                <tr key={e.eventId}>
                  <td className="muted mono small nowrap">{formatTime(e.receivedAtMs)}</td>
                  <td>
                    <span className="tag">{e.eventType}</span>
                  </td>
                  <td className="mono">{e.roomId}</td>
                  <td className="reason">
                    {e.messageUnavailable !== undefined ? (
                      <span className="muted italic">{e.messageUnavailable}</span>
                    ) : (
                      (e.message ?? <span className="muted">—</span>)
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Panel>

      <Panel title="Moderation history" subtitle="Every action taken against this account">
        {d.moderationHistory.length === 0 ? (
          <Empty message="No moderation actions have been taken." />
        ) : (
          <table className="table">
            <thead>
              <tr>
                <th>When</th>
                <th>Action</th>
                <th>Scope</th>
                <th>By</th>
                <th>Outcome</th>
                <th>Reason</th>
              </tr>
            </thead>
            <tbody>
              {d.moderationHistory.map((a) => (
                <tr key={a.actionId}>
                  <td className="muted nowrap">{timeAgo(a.atMs)}</td>
                  <td className="mono">{a.actionType}</td>
                  <td>
                    <ScopeTag scope={a.scope} />
                  </td>
                  <td>
                    {a.actorKind === 'SYSTEM' ? (
                      <span className="tag">system</span>
                    ) : (
                      <span className="mono">{a.actorId}</span>
                    )}
                  </td>
                  <td>
                    {a.succeeded ? (
                      <span className="tag status-ok">applied</span>
                    ) : (
                      <span className="tag status-failed">failed</span>
                    )}
                  </td>
                  <td className="reason">
                    {a.reason}
                    {a.failureReason !== undefined && (
                      <div className="muted small">{a.failureReason}</div>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Panel>

      <Panel
        title="Data this view does not show"
        subtitle="So an empty panel is never mistaken for a clean result"
      >
        <TelemetryDisclosure fields={d.unavailableData} />
      </Panel>
    </div>
  );
}
