#!/usr/bin/env node
/**
 * CDK entry point.
 *
 * Stage is selected with `-c stage=dev|staging|prod`. Production defaults are
 * deliberately stricter: MFA required, data retained on stack deletion, mock
 * platform adapter forbidden, and no CORS origin pre-authorised.
 */

import { App, Tags } from 'aws-cdk-lib';

import { AppStack } from '../lib/app-stack.ts';
import { AuthStack } from '../lib/auth-stack.ts';
import { DataStack } from '../lib/data-stack.ts';

const app = new App();

const stage = String(app.node.tryGetContext('stage') ?? 'dev');
const isProd = stage === 'prod';

const env = {
  account: process.env.CDK_DEFAULT_ACCOUNT,
  region: process.env.CDK_DEFAULT_REGION ?? 'us-east-1',
};

const retentionDays = {
  rawEvents: Number(app.node.tryGetContext('retentionRawEvents') ?? 30),
  signals: Number(app.node.tryGetContext('retentionSignals') ?? 90),
  incidents: Number(app.node.tryGetContext('retentionIncidents') ?? 365),
  evidence: Number(app.node.tryGetContext('retentionEvidence') ?? 365),
  audit: Number(app.node.tryGetContext('retentionAudit') ?? 730),
};

if (retentionDays.evidence < retentionDays.incidents) {
  throw new Error(
    'retentionEvidence must be >= retentionIncidents, otherwise incidents would outlive the evidence that justifies them.',
  );
}

const talkinAdapter = String(app.node.tryGetContext('talkinAdapter') ?? 'noop') as
  | 'noop'
  | 'mock'
  | 'http';

if (isProd && talkinAdapter === 'mock') {
  throw new Error('The mock Talkin adapter must not be deployed to prod: it fabricates platform responses.');
}

/**
 * Capability flags.
 *
 * All default to false. Enabling one is an assertion that this deployment holds
 * the corresponding authorization — see docs/AUTHORIZATION_BOUNDARY.md for what
 * each one requires before you turn it on.
 */
const capabilities = {
  messageContent: flag(app, 'capMessageContent', true),
  moderationEvents: flag(app, 'capModerationEvents', false),
  voiceAudio: flag(app, 'capVoiceAudio', false),
  hiddenPresenceEvents: flag(app, 'capHiddenPresence', false),
  clientAttestation: flag(app, 'capClientAttestation', false),
  remoteMute: flag(app, 'capRemoteMute', false),
  remoteBlock: flag(app, 'capRemoteBlock', false),
};

if ((capabilities.remoteMute || capabilities.remoteBlock) && talkinAdapter !== 'http') {
  throw new Error(
    'capRemoteMute / capRemoteBlock require talkinAdapter=http: there must be a real official API to call.',
  );
}
if (capabilities.voiceAudio && !flag(app, 'confirmVoiceConsent', false)) {
  throw new Error(
    'capVoiceAudio requires -c confirmVoiceConsent=true, an explicit acknowledgement that you hold a lawful basis and participant consent for processing call audio.',
  );
}

const data = new DataStack(app, `TalkinShield-${stage}-Data`, {
  env,
  stage,
  evidenceRetentionDays: retentionDays.evidence,
  retainOnDelete: isProd,
  description: 'TalkinShield data layer: KMS, DynamoDB, S3 evidence storage.',
});

const auth = new AuthStack(app, `TalkinShield-${stage}-Auth`, {
  env,
  stage,
  requireMfa: isProd,
  retainOnDelete: isProd,
  ...(app.node.tryGetContext('domainPrefix') !== undefined
    ? { domainPrefix: String(app.node.tryGetContext('domainPrefix')) }
    : {}),
  description: 'TalkinShield authentication: Cognito user pool, clients and operator groups.',
});

new AppStack(app, `TalkinShield-${stage}-App`, {
  env,
  stage,
  key: data.key,
  evidenceBucket: data.evidenceBucket,
  tables: data.tables,
  userPool: auth.userPool,
  dashboardClient: auth.dashboardClient,
  ingestClient: auth.ingestClient,
  ...(app.node.tryGetContext('alertEmail') !== undefined
    ? { alertEmail: String(app.node.tryGetContext('alertEmail')) }
    : {}),
  bedrockEnabled: flag(app, 'bedrockEnabled', false),
  bedrockModelId: String(
    app.node.tryGetContext('bedrockModelId') ?? 'anthropic.claude-3-5-haiku-20241022-v1:0',
  ),
  talkinAdapter,
  ...(app.node.tryGetContext('talkinApiBaseUrl') !== undefined
    ? { talkinApiBaseUrl: String(app.node.tryGetContext('talkinApiBaseUrl')) }
    : {}),
  ...(app.node.tryGetContext('talkinApiSecretName') !== undefined
    ? { talkinApiSecretName: String(app.node.tryGetContext('talkinApiSecretName')) }
    : {}),
  capabilities,
  retentionDays,
  wafRateLimit: Number(app.node.tryGetContext('wafRateLimit') ?? 2000),
  description: 'TalkinShield application: API, Lambda detection pipeline, EventBridge, WAF, alarms.',
});

Tags.of(app).add('Application', 'TalkinShield');
Tags.of(app).add('Stage', stage);
Tags.of(app).add('Purpose', 'DefensiveModerationAndIncidentResponse');
Tags.of(app).add('DataClassification', 'Confidential');

function flag(scope: App, key: string, fallback: boolean): boolean {
  const value = scope.node.tryGetContext(key);
  if (value === undefined) return fallback;
  return value === true || value === 'true';
}
