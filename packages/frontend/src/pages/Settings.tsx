import { api, USE_MOCK } from '../api/client.ts';
import { useAsync } from '../hooks.ts';
import {
  Empty,
  ErrorNotice,
  Loading,
  Panel,
  TelemetryDisclosure,
} from '../components/ui.tsx';

export function SettingsPage(): JSX.Element {
  const settings = useAsync(() => api.settings());
  const me = useAsync(() => api.me());

  if (settings.loading && settings.data === undefined) return <Loading what="settings" />;
  if (settings.error !== undefined) {
    return <ErrorNotice error={settings.error} onRetry={settings.reload} />;
  }

  const s = settings.data;
  if (s === undefined) return <Empty message="Settings unavailable." />;

  return (
    <div className="page">
      {USE_MOCK && (
        <div className="notice notice-unavailable">
          <strong>Mock mode.</strong>
          <p>
            This console is serving local fixtures, not real detection data. Set
            <span className="mono"> VITE_USE_MOCK_API=false</span> and point
            <span className="mono"> VITE_API_BASE_URL</span> at a deployed API to see live data.
          </p>
        </div>
      )}

      <div className="two-col">
        <Panel title="Deployment" subtitle="Non-sensitive configuration only">
          <dl className="facts">
            <div>
              <dt>Stage</dt>
              <dd>{s.stage}</dd>
            </div>
            <div>
              <dt>Region</dt>
              <dd>{s.region}</dd>
            </div>
            <div>
              <dt>Config version</dt>
              <dd className="mono small">{s.configVersion}</dd>
            </div>
            <div>
              <dt>Alert threshold</dt>
              <dd>{s.alerting.minLevel} and above</dd>
            </div>
          </dl>
          <p className="muted small">
            Resource identifiers, ARNs and secret names are deliberately not exposed through the API.
          </p>
        </Panel>

        <Panel title="Your access" subtitle="Roles come from Cognito group membership">
          {me.data === undefined ? (
            <Loading what="your profile" />
          ) : (
            <>
              <dl className="facts">
                <div>
                  <dt>User</dt>
                  <dd className="mono">{me.data.username}</dd>
                </div>
                <div>
                  <dt>Roles</dt>
                  <dd>{me.data.roles.join(', ')}</dd>
                </div>
                <div>
                  <dt>MFA session</dt>
                  <dd>
                    {me.data.mfaPresent ? (
                      <span className="tag status-ok">present</span>
                    ) : (
                      <span className="tag status-unavailable">absent</span>
                    )}
                  </dd>
                </div>
                <div>
                  <dt>MFA required for destructive actions</dt>
                  <dd>{me.data.mfaRequiredForDestructive ? 'yes' : 'no'}</dd>
                </div>
              </dl>
              <h4>Permissions</h4>
              <div className="chips">
                {me.data.permissions.map((p) => (
                  <span key={p} className="chip mono small">
                    {p}
                  </span>
                ))}
              </div>
            </>
          )}
        </Panel>
      </div>

      <Panel
        title="Talkin integration"
        subtitle="Which capabilities this deployment is authorized to use"
      >
        <dl className="facts">
          <div>
            <dt>Adapter</dt>
            <dd className="mono">{s.integration.adapter}</dd>
          </div>
          <div>
            <dt>Integration</dt>
            <dd>{s.integration.name}</dd>
          </div>
        </dl>

        <table className="table dense">
          <thead>
            <tr>
              <th>Capability</th>
              <th>Status</th>
              <th>Effect when not granted</th>
            </tr>
          </thead>
          <tbody>
            {CAPABILITY_ROWS.map((row) => {
              const granted = s.integration.capabilities[row.key];
              return (
                <tr key={row.key}>
                  <td>{row.label}</td>
                  <td>
                    {granted ? (
                      <span className="tag status-ok">granted</span>
                    ) : (
                      <span className="tag status-unavailable">not granted</span>
                    )}
                  </td>
                  <td className="muted">{granted ? '—' : row.effect}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </Panel>

      <div className="two-col">
        <Panel title="AI classification" subtitle="Advisory only, never authoritative">
          <dl className="facts">
            <div>
              <dt>Bedrock</dt>
              <dd>
                {s.ai.bedrockEnabled ? (
                  <span className="tag status-ok">enabled</span>
                ) : (
                  <span className="tag status-unavailable">disabled</span>
                )}
              </dd>
            </div>
            <div>
              <dt>Model</dt>
              <dd className="mono small">{s.ai.modelId ?? '—'}</dd>
            </div>
          </dl>
          <p className="muted small">{s.ai.note}</p>
        </Panel>

        <Panel title="Voice processing" subtitle="Requires an authorized, consented audio integration">
          <dl className="facts">
            <div>
              <dt>Transcription</dt>
              <dd>
                {s.voice.transcribeEnabled ? (
                  <span className="tag status-ok">enabled</span>
                ) : (
                  <span className="tag status-unavailable">disabled</span>
                )}
              </dd>
            </div>
          </dl>
          <p className="muted small">{s.voice.note}</p>
        </Panel>
      </div>

      <Panel
        title="Data retention"
        subtitle="Enforced by storage TTL and a scheduled retention job, not by application code alone"
      >
        <table className="table dense">
          <thead>
            <tr>
              <th>Data</th>
              <th>Retained for</th>
            </tr>
          </thead>
          <tbody>
            {Object.entries(s.retentionDays).map(([key, days]) => (
              <tr key={key}>
                <td className="mono">{key}</td>
                <td>{days} days</td>
              </tr>
            ))}
          </tbody>
        </table>
        <p className="muted small">
          Evidence retention is never shorter than incident retention, so an incident cannot outlive
          the evidence that justifies it. Deleting evidence under retention is itself recorded in the
          audit log, including the hash of what was removed, so the resulting chain gap is explained.
        </p>
      </Panel>

      <Panel
        title="Risk bands"
        subtitle="Editable on the Detection Rules page"
      >
        <table className="table dense">
          <tbody>
            {Object.entries(s.riskThresholds).map(([level, lower]) => (
              <tr key={level}>
                <td>{level}</td>
                <td>from {lower}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </Panel>

      <Panel title="Data boundaries" subtitle="What this deployment cannot and will not collect">
        <TelemetryDisclosure fields={s.unavailableData} />
      </Panel>
    </div>
  );
}

const CAPABILITY_ROWS: Array<{
  key: keyof import('../api/types.ts').Capabilities;
  label: string;
  effect: string;
}> = [
  {
    key: 'messageContent',
    label: 'Message content',
    effect: 'Text detectors are skipped and no message excerpts are stored.',
  },
  {
    key: 'moderationEvents',
    label: 'Platform moderation events',
    effect: 'Moderation evasion cannot be assessed; the console reports insufficient telemetry.',
  },
  {
    key: 'voiceAudio',
    label: 'Call audio (consented)',
    effect: 'No audio is received or transcribed; voice abuse cannot be analysed.',
  },
  {
    key: 'hiddenPresenceEvents',
    label: 'Hidden / ghost-mode presence',
    effect:
      'Hidden activity cannot be correlated. The console shows "Insufficient authorized telemetry." and makes no attempt to discover concealed users.',
  },
  {
    key: 'clientAttestation',
    label: 'Signed client attestation',
    effect: 'Modified-client findings are behavioural indicators only, never proof.',
  },
  {
    key: 'remoteMute',
    label: 'Official mute API',
    effect: 'MUTE applies locally to the protected user only; other participants are unaffected.',
  },
  {
    key: 'remoteBlock',
    label: 'Official block API',
    effect:
      'BLOCK applies locally only, and no automated platform restriction is ever applied at CRITICAL risk.',
  },
];
