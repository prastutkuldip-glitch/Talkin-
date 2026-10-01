import { useState } from 'react';

import { api } from '../api/client.ts';
import { navigate, useAsync } from '../hooks.ts';
import {
  Confidence,
  Empty,
  ErrorNotice,
  Loading,
  Panel,
  RiskBadge,
  TelemetryDisclosure,
  formatTime,
} from '../components/ui.tsx';
import type { RiskLevel, UnavailableField } from '../api/types.ts';

export function EvidencePage({ evidenceKey }: { evidenceKey?: string }): JSX.Element {
  const incidents = useAsync(() => api.incidents({ limit: '50' }));
  const [selectedIncident, setSelectedIncident] = useState<string | undefined>();

  const bundle = useAsync(
    () => (evidenceKey === undefined ? Promise.resolve(undefined) : api.evidence(evidenceKey)),
    [evidenceKey],
  );

  const chain = useAsync(
    () =>
      selectedIncident === undefined
        ? Promise.resolve(undefined)
        : api.verifyEvidence(selectedIncident),
    [selectedIncident],
  );

  if (evidenceKey !== undefined) {
    if (bundle.loading && bundle.data === undefined) return <Loading what="evidence bundle" />;
    if (bundle.error !== undefined) {
      return <ErrorNotice error={bundle.error} onRetry={bundle.reload} />;
    }
    const loaded = bundle.data;
    if (loaded === undefined) return <Empty message="Evidence bundle not found." />;

    const b = loaded.bundle;
    const notCollected: UnavailableField[] = b.body.authorization.notCollected.map((n) => ({
      field: n.field,
      status: 'UNAVAILABLE',
      reason: n.reason,
    }));

    return (
      <div className="page">
        <Panel
          title="Evidence bundle"
          subtitle={b.key}
          actions={
            <button type="button" className="btn" onClick={() => navigate('evidence')}>
              Back to evidence
            </button>
          }
        >
          <div
            className={`notice ${loaded.verification.valid ? 'notice-ok' : 'notice-error'} inline`}
          >
            <strong>
              {loaded.verification.valid
                ? 'Integrity verified'
                : 'INTEGRITY CHECK FAILED — this bundle has been altered'}
            </strong>
            {loaded.verification.valid ? (
              <p>
                The stored content hashes to the value recorded in the bundle, and the chain link
                matches. Nothing has been modified since it was written.
              </p>
            ) : (
              <ul>
                {loaded.verification.problems.map((p) => (
                  <li key={p}>{p}</li>
                ))}
              </ul>
            )}
          </div>

          <dl className="facts">
            <div>
              <dt>Incident</dt>
              <dd>
                <button
                  type="button"
                  className="link mono"
                  onClick={() => navigate('incidents', b.body.incidentId)}
                >
                  {b.body.incidentId}
                </button>
              </dd>
            </div>
            <div>
              <dt>Account</dt>
              <dd className="mono">{b.body.userId}</dd>
            </div>
            <div>
              <dt>Room</dt>
              <dd className="mono">{b.body.roomId ?? '—'}</dd>
            </div>
            <div>
              <dt>Created</dt>
              <dd>{b.body.createdAt}</dd>
            </div>
            <div>
              <dt>Risk</dt>
              <dd>
                <RiskBadge level={b.body.riskLevel as RiskLevel} score={b.body.riskScore} />
              </dd>
            </div>
            <div>
              <dt>Confidence</dt>
              <dd>
                <Confidence value={b.body.confidence} />
              </dd>
            </div>
            <div>
              <dt>Chain sequence</dt>
              <dd>#{b.sequence}</dd>
            </div>
            <div>
              <dt>Schema</dt>
              <dd className="mono small">{b.body.schemaVersion}</dd>
            </div>
          </dl>

          <h4>Integrity hashes</h4>
          <table className="table dense">
            <tbody>
              <tr>
                <td>Content hash</td>
                <td className="mono small break">{b.contentHash}</td>
              </tr>
              <tr>
                <td>Previous hash</td>
                <td className="mono small break">{b.previousHash}</td>
              </tr>
              <tr>
                <td>Chain hash</td>
                <td className="mono small break">{b.chainHash}</td>
              </tr>
            </tbody>
          </table>
        </Panel>

        <Panel title="Detections recorded" subtitle="With the detector version that produced each">
          <table className="table">
            <thead>
              <tr>
                <th>Detection</th>
                <th>Confidence</th>
                <th>Detector</th>
                <th>Reason</th>
              </tr>
            </thead>
            <tbody>
              {b.body.signals.map((s, i) => (
                <tr key={`${s.code}-${i}`}>
                  <td className="mono">{s.code}</td>
                  <td>
                    <Confidence value={s.confidence} />
                  </td>
                  <td className="mono small">{s.detector}</td>
                  <td className="reason">{s.reason}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </Panel>

        <Panel title="Message excerpts" subtitle="Truncated and identifier-redacted at capture time">
          {b.body.relevantMessages.length === 0 ? (
            <Empty message="No message content was captured in this bundle." />
          ) : (
            <table className="table">
              <tbody>
                {b.body.relevantMessages.map((m) => (
                  <tr key={m.eventId}>
                    <td className="mono small">{m.eventId}</td>
                    <td>
                      {m.redacted && <span className="tag status-unavailable">redacted</span>}
                      {m.isTranscript && <span className="tag">transcript</span>}
                    </td>
                    <td className="reason">{m.text}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Panel>

        <Panel
          title="Authorization record"
          subtitle="Captured inside the hashed body, so the boundary that applied is part of the evidence"
        >
          <p className="muted">{b.body.authorization.note}</p>

          <h4>Collected</h4>
          <div className="chips">
            {b.body.authorization.collected.map((c) => (
              <span key={c} className="chip mono">
                {c}
              </span>
            ))}
          </div>

          <h4>Not collected</h4>
          <TelemetryDisclosure fields={notCollected} />
        </Panel>
      </div>
    );
  }

  // --- Index view ---------------------------------------------------------
  return (
    <div className="page">
      <Panel
        title="Evidence store"
        subtitle="Immutable, encrypted, hash-chained bundles. Select an incident to verify its chain."
      >
        {incidents.loading && incidents.data === undefined ? (
          <Loading what="incidents" />
        ) : incidents.error !== undefined ? (
          <ErrorNotice error={incidents.error} onRetry={incidents.reload} />
        ) : (
          <table className="table">
            <thead>
              <tr>
                <th>Incident</th>
                <th>Account</th>
                <th>Bundles</th>
                <th>Created</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {incidents.data?.incidents.map((i) => (
                <tr key={i.incidentId}>
                  <td className="mono">{i.incidentId}</td>
                  <td className="mono">{i.userId}</td>
                  <td>
                    {i.evidenceKeys.length === 0 ? (
                      <span className="muted">none</span>
                    ) : (
                      i.evidenceKeys.length
                    )}
                  </td>
                  <td className="muted mono small">{formatTime(i.createdAtMs)}</td>
                  <td>
                    <button
                      type="button"
                      className="btn btn-small"
                      disabled={i.evidenceKeys.length === 0}
                      onClick={() => setSelectedIncident(i.incidentId)}
                    >
                      Verify chain
                    </button>
                    {i.evidenceKeys[0] !== undefined && (
                      <button
                        type="button"
                        className="btn btn-small"
                        onClick={() => navigate('evidence', i.evidenceKeys[0] as string)}
                      >
                        Open bundle
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Panel>

      {selectedIncident !== undefined && (
        <Panel title="Chain verification" subtitle={selectedIncident}>
          {chain.loading && chain.data === undefined ? (
            <Loading what="verification" />
          ) : chain.error !== undefined ? (
            <ErrorNotice error={chain.error} onRetry={chain.reload} />
          ) : chain.data === undefined ? (
            <Empty message="No bundles to verify." />
          ) : (
            <>
              <div className={`notice ${chain.data.chain.valid ? 'notice-ok' : 'notice-error'} inline`}>
                <strong>
                  {chain.data.chain.valid
                    ? `Chain intact across ${chain.data.bundleCount} bundle(s)`
                    : 'CHAIN BROKEN'}
                </strong>
                {chain.data.chain.valid ? (
                  <p>
                    Each bundle links to its predecessor's content hash. No bundle has been modified,
                    reordered or removed.
                  </p>
                ) : (
                  <ul>
                    {chain.data.chain.problems.map((p) => (
                      <li key={p}>{p}</li>
                    ))}
                  </ul>
                )}
              </div>

              <table className="table dense">
                <thead>
                  <tr>
                    <th>#</th>
                    <th>Key</th>
                    <th>Content hash</th>
                    <th>Status</th>
                  </tr>
                </thead>
                <tbody>
                  {chain.data.bundles.map((b) => (
                    <tr key={b.key}>
                      <td>{b.sequence}</td>
                      <td>
                        <button
                          type="button"
                          className="link mono small"
                          onClick={() => navigate('evidence', b.key)}
                        >
                          {b.key}
                        </button>
                      </td>
                      <td className="mono small">{b.contentHash.slice(0, 16)}…</td>
                      <td>
                        {b.verification.valid ? (
                          <span className="tag status-ok">verified</span>
                        ) : (
                          <span className="tag status-failed">altered</span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </>
          )}
        </Panel>
      )}
    </div>
  );
}
