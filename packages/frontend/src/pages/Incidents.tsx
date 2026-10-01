import { useState } from 'react';

import { api, ApiError } from '../api/client.ts';
import { navigate, useAsync } from '../hooks.ts';
import { ActionBar } from '../components/ActionBar.tsx';
import {
  Confidence,
  Empty,
  ErrorNotice,
  Loading,
  Panel,
  RiskBadge,
  ScopeTag,
  formatTime,
  timeAgo,
} from '../components/ui.tsx';

const STATUSES = ['OPEN', 'ACKNOWLEDGED', 'ACTIONED', 'DISMISSED_FALSE_POSITIVE', 'CLOSED'];

export function IncidentsPage(): JSX.Element {
  const [status, setStatus] = useState('');
  const { data, error, loading, reload } = useAsync(
    () => api.incidents({ limit: '50', ...(status !== '' ? { status } : {}) }),
    [status],
  );

  if (loading && data === undefined) return <Loading what="incidents" />;
  if (error !== undefined) return <ErrorNotice error={error} onRetry={reload} />;

  return (
    <div className="page">
      <Panel
        title="Incidents"
        subtitle="Durable records of automated decisions, with full provenance"
        actions={
          <select value={status} onChange={(e) => setStatus(e.target.value)}>
            <option value="">All statuses</option>
            {STATUSES.map((s) => (
              <option key={s} value={s}>
                {s}
              </option>
            ))}
          </select>
        }
      >
        {(data?.incidents.length ?? 0) === 0 ? (
          <Empty message="No incidents match this filter." />
        ) : (
          <table className="table">
            <thead>
              <tr>
                <th>Incident</th>
                <th>User</th>
                <th>Risk</th>
                <th>Status</th>
                <th>Confidence</th>
                <th>Detected</th>
                <th>Updated</th>
              </tr>
            </thead>
            <tbody>
              {data?.incidents.map((i) => (
                <tr
                  key={i.incidentId}
                  className="clickable"
                  onClick={() => navigate('incidents', i.incidentId)}
                >
                  <td className="mono">{i.incidentId}</td>
                  <td className="mono">{i.userId}</td>
                  <td>
                    <RiskBadge level={i.riskLevel} score={i.riskScore} />
                  </td>
                  <td>
                    <span className={`tag status-${i.status.toLowerCase()}`}>{i.status}</span>
                  </td>
                  <td>
                    <Confidence value={i.confidence} />
                  </td>
                  <td>
                    <div className="chips">
                      {i.detectedBehaviors.slice(0, 3).map((b) => (
                        <span key={b} className="chip mono">
                          {b}
                        </span>
                      ))}
                      {i.detectedBehaviors.length > 3 && (
                        <span className="chip">+{i.detectedBehaviors.length - 3}</span>
                      )}
                    </div>
                  </td>
                  <td className="muted">{timeAgo(i.updatedAtMs)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Panel>
    </div>
  );
}

export function IncidentDetailPage({ incidentId }: { incidentId: string }): JSX.Element {
  const incident = useAsync(() => api.incident(incidentId), [incidentId]);
  const affordances = useAsync(() => api.affordances());
  const [newStatus, setNewStatus] = useState('');
  const [note, setNote] = useState('');
  const [saving, setSaving] = useState(false);
  const [saveError, setSaveError] = useState<string | undefined>();

  if (incident.loading && incident.data === undefined) return <Loading what="incident" />;
  if (incident.error !== undefined) {
    return <ErrorNotice error={incident.error} onRetry={incident.reload} />;
  }

  const i = incident.data?.incident;
  if (i === undefined) return <Empty message="Incident not found." />;

  const save = async (): Promise<void> => {
    if (newStatus === '' || note.trim().length < 8) return;
    setSaving(true);
    setSaveError(undefined);
    try {
      await api.updateIncident(i.incidentId, { status: newStatus, reviewNote: note.trim() });
      setNewStatus('');
      setNote('');
      incident.reload();
    } catch (err) {
      setSaveError(err instanceof ApiError ? err.message : 'The status could not be updated.');
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="page">
      <Panel
        title={i.incidentId}
        subtitle={`Opened ${formatTime(i.createdAtMs)} · last updated ${timeAgo(i.updatedAtMs)}`}
        actions={
          <button type="button" className="btn" onClick={() => navigate('incidents')}>
            Back to incidents
          </button>
        }
      >
        <dl className="facts">
          <div>
            <dt>Account</dt>
            <dd>
              <button type="button" className="link mono" onClick={() => navigate('users', i.userId)}>
                {i.userId}
              </button>
            </dd>
          </div>
          <div>
            <dt>Room</dt>
            <dd className="mono">{i.roomId ?? '—'}</dd>
          </div>
          <div>
            <dt>Risk</dt>
            <dd>
              <RiskBadge level={i.riskLevel} score={i.riskScore} />
            </dd>
          </div>
          <div>
            <dt>Status</dt>
            <dd>
              <span className={`tag status-${i.status.toLowerCase()}`}>{i.status}</span>
            </dd>
          </div>
          <div>
            <dt>Aggregate confidence</dt>
            <dd>
              <Confidence value={i.confidence} />
            </dd>
          </div>
        </dl>

        <h4>Model and engine versions consulted</h4>
        <div className="chips">
          {i.modelVersions.map((v) => (
            <span key={v} className="chip mono">
              {v}
            </span>
          ))}
        </div>

        {i.reviewNote !== undefined && (
          <div className="notice notice-ok inline">
            <strong>Reviewed by {i.reviewedBy ?? 'unknown'}</strong>
            <p>{i.reviewNote}</p>
          </div>
        )}
      </Panel>

      <Panel title="Why this was flagged" subtitle="Every contributing detection, recorded verbatim">
        <ul className="reasons">
          {i.detectionReasons.map((r, idx) => (
            <li key={idx}>{r}</li>
          ))}
        </ul>
      </Panel>

      <Panel
        title="Relevant messages"
        subtitle="Truncated and redacted before storage, per data-minimization policy"
      >
        {i.relevantMessages.length === 0 ? (
          <Empty message="No message content was stored for this incident. Either none was authorized, or none was relevant." />
        ) : (
          <table className="table">
            <thead>
              <tr>
                <th>When</th>
                <th>Source</th>
                <th>Excerpt</th>
              </tr>
            </thead>
            <tbody>
              {i.relevantMessages.map((m) => (
                <tr key={m.eventId}>
                  <td className="muted mono small nowrap">{formatTime(m.atMs)}</td>
                  <td>
                    {m.isTranscript ? (
                      <span className="tag">transcript</span>
                    ) : (
                      <span className="tag">text</span>
                    )}
                    {m.redacted && <span className="tag status-unavailable">redacted</span>}
                  </td>
                  <td className="reason">{m.text}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Panel>

      <Panel title="Actions taken" subtitle="Automated and human, each with its reason">
        {i.actionsTaken.length === 0 ? (
          <Empty message="No actions have been taken yet." />
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
              {i.actionsTaken.map((a) => (
                <tr key={a.actionId}>
                  <td className="muted nowrap">{timeAgo(a.atMs)}</td>
                  <td className="mono">{a.actionType}</td>
                  <td>
                    <ScopeTag scope={a.scope} />
                  </td>
                  <td>{a.actorKind === 'SYSTEM' ? <span className="tag">system</span> : a.actorId}</td>
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

      <Panel title="Authorized metadata" subtitle="Non-personal context only">
        <table className="table dense">
          <tbody>
            {Object.entries(i.authorizedMetadata).map(([k, v]) => (
              <tr key={k}>
                <td className="mono">{k}</td>
                <td>{String(v)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </Panel>

      <Panel title="Evidence" subtitle="Hash-chained bundles for this incident">
        {i.evidenceKeys.length === 0 ? (
          <Empty message="No evidence bundle was written for this incident." />
        ) : (
          <ul className="keylist">
            {i.evidenceKeys.map((k) => (
              <li key={k}>
                <button type="button" className="link mono" onClick={() => navigate('evidence', k)}>
                  {k}
                </button>
              </li>
            ))}
          </ul>
        )}
      </Panel>

      <Panel title="Take action" subtitle="Scope is shown on every button">
        {affordances.data === undefined ? (
          <Loading what="available actions" />
        ) : (
          <ActionBar
            targetUserId={i.userId}
            {...(i.roomId !== undefined ? { roomId: i.roomId } : {})}
            incidentId={i.incidentId}
            affordances={affordances.data.affordances}
            onActionTaken={() => incident.reload()}
          />
        )}
      </Panel>

      <Panel
        title="Review"
        subtitle="Marking an incident a false positive feeds threshold tuning"
      >
        <div className="form">
          <label htmlFor="incident-status">New status</label>
          <select
            id="incident-status"
            value={newStatus}
            onChange={(e) => setNewStatus(e.target.value)}
          >
            <option value="">Select…</option>
            {STATUSES.map((s) => (
              <option key={s} value={s}>
                {s}
              </option>
            ))}
          </select>

          <label htmlFor="incident-note">
            Review note <span className="muted">(required, recorded in the audit log)</span>
          </label>
          <textarea
            id="incident-note"
            rows={3}
            value={note}
            placeholder="What did you conclude, and why?"
            onChange={(e) => setNote(e.target.value)}
          />

          <div className="form-actions">
            <button
              type="button"
              className="btn btn-primary"
              disabled={saving || newStatus === '' || note.trim().length < 8}
              onClick={() => void save()}
            >
              {saving ? 'Saving…' : 'Update status'}
            </button>
            {note.trim().length < 8 && newStatus !== '' && (
              <span className="muted">A note of at least 8 characters is required.</span>
            )}
          </div>

          {saveError !== undefined && <div className="notice notice-error inline">{saveError}</div>}
        </div>
      </Panel>
    </div>
  );
}
