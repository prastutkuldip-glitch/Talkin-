/**
 * Moderation action bar — MUTE / BLOCK / REPORT / SAVE EVIDENCE.
 *
 * Two product rules are enforced in the UI here:
 *
 *  1. Each button states its true scope. When no official platform API is
 *     configured, MUTE and BLOCK are labelled LOCAL ONLY and the confirmation
 *     text says plainly that other participants are unaffected. A moderator must
 *     never believe they have restricted an account platform-wide when they have
 *     not.
 *  2. A reason is mandatory. The submit button stays disabled until one is
 *     entered, because the backend records it on the action and in the audit log.
 */

import { useState } from 'react';

import { api, ApiError } from '../api/client.ts';
import type { Affordance, ModerationResult } from '../api/types.ts';
import { ScopeTag } from './ui.tsx';

const MIN_REASON = 8;

export function ActionBar({
  targetUserId,
  roomId,
  incidentId,
  affordances,
  onActionTaken,
}: {
  targetUserId: string;
  roomId?: string;
  incidentId?: string;
  affordances: Affordance[];
  onActionTaken?: (result: ModerationResult) => void;
}): JSX.Element {
  const [pending, setPending] = useState<Affordance | undefined>();
  const [reason, setReason] = useState('');
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<ModerationResult | undefined>();
  const [error, setError] = useState<string | undefined>();

  const submit = async (): Promise<void> => {
    if (pending === undefined || reason.trim().length < MIN_REASON) return;
    setBusy(true);
    setError(undefined);
    try {
      const outcome = await api.moderate({
        action: pending.action,
        targetUserId,
        ...(roomId !== undefined ? { roomId } : {}),
        ...(incidentId !== undefined ? { incidentId } : {}),
        reason: reason.trim(),
      });
      setResult(outcome);
      setPending(undefined);
      setReason('');
      onActionTaken?.(outcome);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'The action could not be completed.');
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="actionbar">
      <div className="actionbar-buttons">
        {affordances.map((a) => (
          <button
            key={a.action}
            type="button"
            className={`btn btn-action ${pending?.action === a.action ? 'btn-active' : ''}`}
            disabled={!a.enabled}
            title={a.description}
            onClick={() => {
              setPending(pending?.action === a.action ? undefined : a);
              setResult(undefined);
              setError(undefined);
            }}
          >
            {a.label}
            <ScopeTag scope={a.scope} />
          </button>
        ))}
      </div>

      {pending !== undefined && (
        <div className="actionbar-confirm">
          <p className="action-description">{pending.description}</p>

          {pending.scope === 'LOCAL_TO_REQUESTER' && (
            <p className="notice notice-unavailable inline">
              This takes effect for the protected user only. No official Talkin API is configured for
              this action, so the account is not restricted platform-wide.
            </p>
          )}

          <label htmlFor="action-reason">
            Reason <span className="muted">(recorded on the action and in the audit log)</span>
          </label>
          <textarea
            id="action-reason"
            value={reason}
            rows={3}
            placeholder="Why is this action being taken?"
            onChange={(e) => setReason(e.target.value)}
          />
          <div className="actionbar-submit">
            <button
              type="button"
              className="btn btn-primary"
              disabled={busy || reason.trim().length < MIN_REASON}
              onClick={() => void submit()}
            >
              {busy ? 'Working…' : `Confirm ${pending.label}`}
            </button>
            <button type="button" className="btn" onClick={() => setPending(undefined)}>
              Cancel
            </button>
            {reason.trim().length < MIN_REASON && (
              <span className="muted">
                A reason of at least {MIN_REASON} characters is required.
              </span>
            )}
          </div>
        </div>
      )}

      {error !== undefined && <div className="notice notice-error inline">{error}</div>}

      {result !== undefined && (
        <div className={`notice ${result.applied ? 'notice-ok' : 'notice-error'} inline`}>
          <strong>{result.applied ? 'Action recorded' : 'Action not applied'}</strong>
          <p>{result.message}</p>
          <p className="muted">
            Scope: {result.scope}
            {result.platformActionUnavailable ? ' · no official platform API available' : ''}
          </p>
        </div>
      )}
    </div>
  );
}
