import { api } from '../api/client.ts';
import { navigate, useAsync } from '../hooks.ts';
import {
  Empty,
  ErrorNotice,
  Loading,
  Panel,
  ScopeTag,
  TelemetryDisclosure,
  formatTime,
} from '../components/ui.tsx';

export function ModerationActionsPage(): JSX.Element {
  const actions = useAsync(() => api.actions({ limit: '100' }));
  const affordances = useAsync(() => api.affordances());

  return (
    <div className="page">
      <Panel
        title="What this console can actually do"
        subtitle="Capabilities are granted by the connected Talkin integration, not assumed"
      >
        {affordances.loading && affordances.data === undefined ? (
          <Loading what="capabilities" />
        ) : affordances.error !== undefined ? (
          <ErrorNotice error={affordances.error} onRetry={affordances.reload} />
        ) : affordances.data === undefined ? (
          <Empty message="Capability information unavailable." />
        ) : (
          <>
            <p className="muted">
              Integration: <span className="mono">{affordances.data.integration}</span>
            </p>

            <table className="table">
              <thead>
                <tr>
                  <th>Action</th>
                  <th>Scope</th>
                  <th>What it does</th>
                </tr>
              </thead>
              <tbody>
                {affordances.data.affordances.map((a) => (
                  <tr key={a.action}>
                    <td className="mono">{a.label}</td>
                    <td>
                      <ScopeTag scope={a.scope} />
                    </td>
                    <td className="reason">{a.description}</td>
                  </tr>
                ))}
              </tbody>
            </table>

            <div className="notice notice-unavailable inline">
              <strong>Where no official API exists</strong>
              <p>
                TalkinShield falls back to protections scoped to the protected user — local mute,
                block, ignore, report and evidence capture. It does not attempt to reach another
                participant's device, client or microphone by any other means, and there is no
                setting that enables it to.
              </p>
            </div>

            <h4>Capability status</h4>
            <table className="table dense">
              <tbody>
                {Object.entries(affordances.data.capabilities).map(([key, granted]) => (
                  <tr key={key}>
                    <td className="mono">{key}</td>
                    <td>
                      {granted ? (
                        <span className="tag status-ok">granted</span>
                      ) : (
                        <span className="tag status-unavailable">not granted</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </>
        )}
      </Panel>

      <Panel title="Action log" subtitle="Every moderation action, automated and human">
        {actions.loading && actions.data === undefined ? (
          <Loading what="actions" />
        ) : actions.error !== undefined ? (
          <ErrorNotice error={actions.error} onRetry={actions.reload} />
        ) : (actions.data?.actions.length ?? 0) === 0 ? (
          <Empty message="No moderation actions have been taken." />
        ) : (
          <table className="table">
            <thead>
              <tr>
                <th>When</th>
                <th>Action</th>
                <th>Scope</th>
                <th>Target</th>
                <th>By</th>
                <th>Outcome</th>
                <th>Reason</th>
              </tr>
            </thead>
            <tbody>
              {actions.data?.actions.map((a) => (
                <tr key={a.actionId}>
                  <td className="muted mono small nowrap">{formatTime(a.atMs)}</td>
                  <td className="mono">{a.actionType}</td>
                  <td>
                    <ScopeTag scope={a.scope} />
                  </td>
                  <td>
                    <button
                      type="button"
                      className="link mono"
                      onClick={() => navigate('users', a.targetUserId)}
                    >
                      {a.targetUserId}
                    </button>
                  </td>
                  <td>
                    {a.actorKind === 'SYSTEM' ? (
                      <span className="tag">system</span>
                    ) : (
                      <span className="mono small">{a.actorId}</span>
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

      {affordances.data !== undefined && (
        <Panel title="Data boundaries" subtitle="What this deployment cannot and will not collect">
          <TelemetryDisclosure fields={affordances.data.unavailableData} />
        </Panel>
      )}
    </div>
  );
}
