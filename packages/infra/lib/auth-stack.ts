/**
 * Auth stack: Amazon Cognito user pool, app client and operator groups.
 *
 * MFA is configured as OPTIONAL by default with TOTP enabled, which makes the
 * deployment MFA-ready without locking out an operator mid-rollout. Setting
 * `requireMfa: true` (recommended for prod) switches it to REQUIRED; the
 * backend's `REQUIRE_MFA_FOR_DESTRUCTIVE` flag then enforces a multi-factor
 * session for any action that affects another account or changes policy.
 */

import { CfnOutput, Duration, RemovalPolicy, Stack, type StackProps } from 'aws-cdk-lib';
import * as cognito from 'aws-cdk-lib/aws-cognito';
import type { Construct } from 'constructs';

export interface AuthStackProps extends StackProps {
  stage: string;
  requireMfa: boolean;
  retainOnDelete: boolean;
  /** Optional custom domain prefix for the hosted UI. */
  domainPrefix?: string;
}

export const GROUPS = {
  admins: 'admins',
  moderators: 'moderators',
  viewers: 'viewers',
  telemetryIngest: 'telemetry-ingest',
} as const;

export class AuthStack extends Stack {
  readonly userPool: cognito.UserPool;
  readonly dashboardClient: cognito.UserPoolClient;
  readonly ingestClient: cognito.UserPoolClient;

  constructor(scope: Construct, id: string, props: AuthStackProps) {
    super(scope, id, props);

    this.userPool = new cognito.UserPool(this, 'UserPool', {
      userPoolName: `talkinshield-${props.stage}`,
      selfSignUpEnabled: false, // Operators are provisioned, never self-registered.
      signInAliases: { email: true, username: true },
      standardAttributes: { email: { required: true, mutable: false } },
      passwordPolicy: {
        minLength: 14,
        requireLowercase: true,
        requireUppercase: true,
        requireDigits: true,
        requireSymbols: true,
        tempPasswordValidity: Duration.days(3),
      },
      mfa: props.requireMfa ? cognito.Mfa.REQUIRED : cognito.Mfa.OPTIONAL,
      mfaSecondFactor: { sms: false, otp: true },
      accountRecovery: cognito.AccountRecovery.EMAIL_ONLY,
      advancedSecurityMode: cognito.AdvancedSecurityMode.ENFORCED,
      removalPolicy: props.retainOnDelete ? RemovalPolicy.RETAIN : RemovalPolicy.DESTROY,
      deletionProtection: props.retainOnDelete,
    });

    // Dashboard client: short-lived access tokens, refresh rotation.
    this.dashboardClient = this.userPool.addClient('DashboardClient', {
      userPoolClientName: 'talkinshield-dashboard',
      authFlows: { userSrp: true, custom: false, userPassword: false },
      generateSecret: false, // Public SPA client — no secret can be kept safe.
      accessTokenValidity: Duration.minutes(30),
      idTokenValidity: Duration.minutes(30),
      refreshTokenValidity: Duration.days(7),
      preventUserExistenceErrors: true,
      enableTokenRevocation: true,
    });

    // Ingestion client: machine-to-machine only, with a secret.
    this.ingestClient = this.userPool.addClient('IngestClient', {
      userPoolClientName: 'talkinshield-ingest',
      authFlows: { userSrp: true },
      generateSecret: true,
      accessTokenValidity: Duration.hours(1),
      refreshTokenValidity: Duration.days(1),
      preventUserExistenceErrors: true,
      enableTokenRevocation: true,
    });

    if (props.domainPrefix !== undefined) {
      this.userPool.addDomain('HostedUi', {
        cognitoDomain: { domainPrefix: props.domainPrefix },
      });
    }

    for (const groupName of Object.values(GROUPS)) {
      new cognito.CfnUserPoolGroup(this, `Group${groupName}`, {
        userPoolId: this.userPool.userPoolId,
        groupName,
        description: describeGroup(groupName),
      });
    }

    new CfnOutput(this, 'UserPoolId', { value: this.userPool.userPoolId });
    new CfnOutput(this, 'DashboardClientId', { value: this.dashboardClient.userPoolClientId });
    new CfnOutput(this, 'IngestClientId', { value: this.ingestClient.userPoolClientId });
  }
}

function describeGroup(group: string): string {
  switch (group) {
    case GROUPS.admins:
      return 'Full access: detection rules, settings, retention and all moderation actions.';
    case GROUPS.moderators:
      return 'Review incidents, take moderation actions, read and save evidence. Cannot change detection rules.';
    case GROUPS.viewers:
      return 'Read-only access to the console. Cannot take any moderation action.';
    case GROUPS.telemetryIngest:
      return 'Machine principal for submitting authorized telemetry. No dashboard access.';
    default:
      return 'TalkinShield group.';
  }
}
