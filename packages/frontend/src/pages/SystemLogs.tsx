import { useState } from 'react';

import { api } from '../api/client.ts';
import { useAsync } from '../hooks.ts';
import { Empty, ErrorNotice, Loading, Panel, formatTime } from '../components/ui.tsx';

export function SystemLogsPage(): JSX.Element {
  const [actorFilter, setActorFilter] = useState('');
  const [outcomeFilter, setOutcomeFilter] = useState('');

  const { data, error, loading, reload } = useAsync(
    () => api.logs({ limit: '200', ...(actorFilter !== '' ? { actorId: actorFilter } : {}) }),
    [actorFilter],
  );

  const entries = (data?.entries ?? []).filter(
    (e) => outcomeFilter === '' || e.outcome === outcomeFilter,
  );

  return (
    <div className="page">
      <Panel
        title="Audit trail"
        subtitle="Append-only. Every automated and human action, including denied access attempts."
        actions={
          <>
            <input
              type="text"
              placeholder="Filter by actor id"
              value={actorFilter}
              onChange={(e) => setActorFilter(e.target.value.trim())}
            />
            <select value={outcomeFilter} onChange={(e) => setOutcomeFilter(e.target.value)}>
              <option value="">All outcomes</option>
              <option value="SUCCESS">SUCCESS</option>
              <option value="FAILURE">FAILURE</option>
              <option value="DENIED">DENIED</option>
            </select>
            <button type="button" className="btn" onClick={reload}>
              Refresh
            </button>
          </>
        }
      >
        <p className="muted">
          This table is written with PutItem only — no function in the system holds permission to
          update or delete an audit entry. Entries expire solely by their configured retention TTL,
          and a retention deletion is itself audited.
        </p>

        {loading && data === undefined ? (
          <Loading what="audit log" />
        ) : error !== undefined ? (
          <ErrorNotice error={error} onRetry={reload} />
        ) : entries.length === 0 ? (
          <Empty message="No audit entries match this filter." />
        ) : (
          <table className="table">
            <thead>
              <tr>
                <th>When</th>
                <th>Actor</th>
                <th>Action</th>
                <th>Target</th>
                <th>Outcome</th>
                <th>Reason</th>
              </tr>
            </thead>
            <tbody>
              {entries.map((e) => (
                <tr key={e.auditId} className={e.outcome === 'DENIED' ? 'row-denied' : ''}>
                  <td className="muted mono small nowrap">{formatTime(e.atMs)}</td>
                  <td>
                    {e.actorKind === 'SYSTEM' ? (
                      <span className="tag">system</span>
                    ) : (
                      <span className="mono small">{e.actorId}</span>
                    )}
                  </td>
                  <td className="mono small">{e.action}</td>
                  <td className="mono small break">{e.target}</td>
                  <td>
                    <span className={`tag outcome-${e.outcome.toLowerCase()}`}>{e.outcome}</span>
                  </td>
                  <td className="reason">
                    {e.reason}
                    {e.detail !== undefined && (
                      <div className="muted small">
                        {Object.entries(e.detail)
                          .map(([k, v]) => `${k}=${String(v)}`)
                          .join(' · ')}
                      </div>
                    )}
                    {e.sourceIp !== undefined && (
                      <div className="muted small">source: {e.sourceIp}</div>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Panel>
    </div>
  );
}
