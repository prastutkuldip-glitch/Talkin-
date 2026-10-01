import { useCallback, useState } from 'react';

import { api } from '../api/client.ts';
import { navigate, useAsync, usePolling } from '../hooks.ts';
import {
  Confidence,
  Empty,
  ErrorNotice,
  Loading,
  Panel,
  SeverityTag,
  formatTime,
  timeAgo,
} from '../components/ui.tsx';

export function LiveEventsPage(): JSX.Element {
  const [live, setLive] = useState(true);
  const [roomFilter, setRoomFilter] = useState('');

  const events = useAsync(
    () => api.events({ limit: '60', ...(roomFilter !== '' ? { roomId: roomFilter } : {}) }),
    [roomFilter],
  );
  const signals = useAsync(() => api.signals('60'));

  const refresh = useCallback(() => {
    events.reload();
    signals.reload();
  }, [events, signals]);

  usePolling(refresh, 5000, live);

  return (
    <div className="page">
      <Panel
        title="Live security events"
        subtitle="Detections as they are produced, newest first"
        actions={
          <>
            <input
              type="text"
              placeholder="Filter by room id"
              value={roomFilter}
              onChange={(e) => setRoomFilter(e.target.value.trim())}
            />
            <button
              type="button"
              className={`btn ${live ? 'btn-active' : ''}`}
              onClick={() => setLive(!live)}
            >
              {live ? 'Live · 5s' : 'Paused'}
            </button>
            <button type="button" className="btn" onClick={refresh}>
              Refresh
            </button>
          </>
        }
      >
        {signals.loading && signals.data === undefined ? (
          <Loading what="detections" />
        ) : signals.error !== undefined ? (
          <ErrorNotice error={signals.error} onRetry={signals.reload} />
        ) : (signals.data?.signals.length ?? 0) === 0 ? (
          <Empty message="No detections in the current window. Nothing has been flagged." />
        ) : (
          <table className="table">
            <thead>
              <tr>
                <th>When</th>
                <th>User</th>
                <th>Detection</th>
                <th>Severity</th>
                <th>Confidence</th>
                <th>Reason</th>
              </tr>
            </thead>
            <tbody>
              {signals.data?.signals.map((s, i) => (
                <tr key={`${s.code}-${s.observedAtMs}-${i}`}>
                  <td className="muted nowrap">{timeAgo(s.observedAtMs)}</td>
                  <td>
                    <button
                      type="button"
                      className="link mono"
                      onClick={() => navigate('users', s.userId)}
                    >
                      {s.userId}
                    </button>
                  </td>
                  <td className="mono">{s.code}</td>
                  <td>
                    <SeverityTag severity={s.severity} />
                  </td>
                  <td>
                    <Confidence value={s.confidence} />
                  </td>
                  <td className="reason">
                    {s.reason}
                    <div className="muted small">detector: {s.detector}</div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Panel>

      <Panel title="Raw event stream" subtitle="Authorized telemetry as received">
        {events.loading && events.data === undefined ? (
          <Loading what="events" />
        ) : events.error !== undefined ? (
          <ErrorNotice error={events.error} onRetry={events.reload} />
        ) : (events.data?.events.length ?? 0) === 0 ? (
          <Empty message="No events received." />
        ) : (
          <table className="table dense">
            <thead>
              <tr>
                <th>Timestamp</th>
                <th>User</th>
                <th>Room</th>
                <th>Type</th>
                <th>Platform</th>
                <th>Client</th>
                <th>Content</th>
              </tr>
            </thead>
            <tbody>
              {events.data?.events.map((e) => (
                <tr key={e.eventId}>
                  <td className="muted nowrap mono small">{formatTime(e.receivedAtMs)}</td>
                  <td>
                    <button
                      type="button"
                      className="link mono"
                      onClick={() => navigate('users', e.userId)}
                    >
                      {e.userId}
                    </button>
                  </td>
                  <td className="mono">{e.roomId}</td>
                  <td>
                    <span className="tag">{e.eventType}</span>
                    {e.messageIsTranscript === true && <span className="tag">transcript</span>}
                  </td>
                  <td className="muted">{e.platform}</td>
                  <td className="mono small">{e.clientVersion ?? '—'}</td>
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
    </div>
  );
}
