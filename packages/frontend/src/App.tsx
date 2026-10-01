import { useEffect, useState } from 'react';

import { USE_MOCK, api } from './api/client.ts';
import type { Me } from './api/types.ts';
import {
  beginLogin,
  completeLogin,
  currentSession,
  logout,
  type CognitoConfig,
} from './auth/cognito.ts';
import { navigate, useAsync, useRoute } from './hooks.ts';
import { Loading } from './components/ui.tsx';
import { DetectionRulesPage } from './pages/DetectionRules.tsx';
import { EvidencePage } from './pages/Evidence.tsx';
import { IncidentDetailPage, IncidentsPage } from './pages/Incidents.tsx';
import { LiveEventsPage } from './pages/LiveEvents.tsx';
import { ModerationActionsPage } from './pages/ModerationActions.tsx';
import { OverviewPage } from './pages/Overview.tsx';
import { RiskAnalysisPage } from './pages/RiskAnalysis.tsx';
import { SettingsPage } from './pages/Settings.tsx';
import { SystemLogsPage } from './pages/SystemLogs.tsx';
import { UserDetailPage, UsersPage } from './pages/Users.tsx';

const NAV: Array<{ page: string; label: string; permission?: string }> = [
  { page: 'overview', label: 'Overview' },
  { page: 'events', label: 'Live Events' },
  { page: 'users', label: 'Users' },
  { page: 'incidents', label: 'Incidents' },
  { page: 'risk', label: 'Risk Analysis' },
  { page: 'evidence', label: 'Evidence', permission: 'evidence:read' },
  { page: 'moderation', label: 'Moderation Actions' },
  { page: 'rules', label: 'Detection Rules', permission: 'rules:read' },
  { page: 'logs', label: 'System Logs', permission: 'logs:read' },
  { page: 'settings', label: 'Settings', permission: 'settings:read' },
];

const cognitoConfig: CognitoConfig = {
  domain: String(import.meta.env.VITE_COGNITO_DOMAIN ?? ''),
  clientId: String(import.meta.env.VITE_COGNITO_CLIENT_ID ?? ''),
  redirectUri: window.location.origin + window.location.pathname,
  scopes: ['openid', 'email', 'profile'],
};

export function App(): JSX.Element {
  const route = useRoute();
  const [authState, setAuthState] = useState<'checking' | 'signed-out' | 'signed-in'>(
    USE_MOCK ? 'signed-in' : 'checking',
  );
  const [authError, setAuthError] = useState<string | undefined>();

  // Complete the PKCE redirect, if one is in progress.
  useEffect(() => {
    if (USE_MOCK) return;
    let cancelled = false;

    completeLogin(cognitoConfig)
      .then((session) => {
        if (cancelled) return;
        setAuthState(session !== undefined || currentSession() !== undefined ? 'signed-in' : 'signed-out');
      })
      .catch((err: unknown) => {
        if (cancelled) return;
        setAuthError(err instanceof Error ? err.message : 'Sign-in failed.');
        setAuthState('signed-out');
      });

    return () => {
      cancelled = true;
    };
  }, []);

  if (authState === 'checking') return <Loading what="your session" />;

  if (authState === 'signed-out') {
    return (
      <SignIn
        error={authError}
        onSignIn={() => {
          if (cognitoConfig.domain === '' || cognitoConfig.clientId === '') {
            setAuthError(
              'Cognito is not configured. Set VITE_COGNITO_DOMAIN and VITE_COGNITO_CLIENT_ID, or run with VITE_USE_MOCK_API=true.',
            );
            return;
          }
          void beginLogin(cognitoConfig);
        }}
      />
    );
  }

  return <Console route={route} />;
}

function SignIn({
  error,
  onSignIn,
}: {
  error?: string;
  onSignIn: () => void;
}): JSX.Element {
  return (
    <div className="signin">
      <div className="signin-card">
        <h1>
          Talkin<span className="accent">Shield</span>
        </h1>
        <p className="muted">Security Console</p>
        <p className="signin-blurb">
          A defensive moderation and incident-response console. Access is restricted to provisioned
          operators and every action is recorded in an append-only audit log.
        </p>
        {error !== undefined && <div className="notice notice-error inline">{error}</div>}
        <button type="button" className="btn btn-primary btn-wide" onClick={onSignIn}>
          Sign in with Cognito
        </button>
      </div>
    </div>
  );
}

function Console({ route }: { route: { page: string; param?: string } }): JSX.Element {
  const me = useAsync<Me>(() => api.me());
  const permissions = me.data?.permissions ?? [];

  const visibleNav = NAV.filter(
    (item) =>
      item.permission === undefined ||
      permissions.length === 0 ||
      permissions.includes(item.permission),
  );

  return (
    <div className="shell">
      <aside className="sidebar">
        <div className="brand">
          <span className="brand-mark" aria-hidden="true">
            ◈
          </span>
          <div>
            <strong>
              Talkin<span className="accent">Shield</span>
            </strong>
            <div className="muted small">Security Console</div>
          </div>
        </div>

        <nav>
          {visibleNav.map((item) => (
            <button
              key={item.page}
              type="button"
              className={`nav-item ${route.page === item.page ? 'nav-active' : ''}`}
              onClick={() => navigate(item.page)}
            >
              {item.label}
            </button>
          ))}
        </nav>

        <div className="sidebar-foot">
          {me.data !== undefined && (
            <>
              <div className="mono small">{me.data.username}</div>
              <div className="muted small">{me.data.roles.join(' · ')}</div>
            </>
          )}
          {USE_MOCK ? (
            <div className="tag status-unavailable">MOCK DATA</div>
          ) : (
            <button type="button" className="btn btn-small" onClick={() => logout(cognitoConfig)}>
              Sign out
            </button>
          )}
        </div>
      </aside>

      <main className="main">
        <header className="topbar">
          <h1>{currentTitle(route.page)}</h1>
          {route.param !== undefined && <span className="mono muted">{route.param}</span>}
        </header>
        <div className="content">{renderPage(route)}</div>
      </main>
    </div>
  );
}

function currentTitle(page: string): string {
  return NAV.find((n) => n.page === page)?.label ?? 'Overview';
}

function renderPage(route: { page: string; param?: string }): JSX.Element {
  switch (route.page) {
    case 'overview':
      return <OverviewPage />;
    case 'events':
      return <LiveEventsPage />;
    case 'users':
      return route.param !== undefined ? <UserDetailPage userId={route.param} /> : <UsersPage />;
    case 'incidents':
      return route.param !== undefined ? (
        <IncidentDetailPage incidentId={route.param} />
      ) : (
        <IncidentsPage />
      );
    case 'risk':
      return <RiskAnalysisPage />;
    case 'evidence':
      return route.param !== undefined ? <EvidencePage evidenceKey={route.param} /> : <EvidencePage />;
    case 'moderation':
      return <ModerationActionsPage />;
    case 'rules':
      return <DetectionRulesPage />;
    case 'logs':
      return <SystemLogsPage />;
    case 'settings':
      return <SettingsPage />;
    default:
      return <OverviewPage />;
  }
}
