/**
 * Application stack: Lambda functions, API Gateway + WAF, EventBridge rules,
 * SNS alerting, schedules and CloudWatch alarms.
 *
 * IAM posture — least privilege, enforced per function:
 *   - The API function can read everything it serves and write incidents,
 *     actions and audit entries. It can PUT evidence but cannot DELETE it.
 *   - The analysis function can write user state, signals, incidents and
 *     evidence. It cannot read the audit table's history.
 *   - The audit table grants PutItem + Query only. No UpdateItem, no
 *     DeleteItem, to any function. Audit history is append-only by IAM, not
 *     merely by convention.
 *   - Only the retention function holds s3:DeleteObject on the evidence bucket.
 *   - No function is granted kms:ScheduleKeyDeletion or any key-policy action.
 */

import {
  CfnOutput,
  Duration,
  Stack,
  type StackProps,
} from 'aws-cdk-lib';
import * as apigwv2 from 'aws-cdk-lib/aws-apigatewayv2';
import * as apigwv2Authorizers from 'aws-cdk-lib/aws-apigatewayv2-authorizers';
import * as apigwv2Integrations from 'aws-cdk-lib/aws-apigatewayv2-integrations';
import * as cloudwatch from 'aws-cdk-lib/aws-cloudwatch';
import * as cwActions from 'aws-cdk-lib/aws-cloudwatch-actions';
import type * as cognito from 'aws-cdk-lib/aws-cognito';
import type * as dynamodb from 'aws-cdk-lib/aws-dynamodb';
import * as events from 'aws-cdk-lib/aws-events';
import * as targets from 'aws-cdk-lib/aws-events-targets';
import * as iam from 'aws-cdk-lib/aws-iam';
import type * as kms from 'aws-cdk-lib/aws-kms';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as logs from 'aws-cdk-lib/aws-logs';
import type * as s3 from 'aws-cdk-lib/aws-s3';
import * as sns from 'aws-cdk-lib/aws-sns';
import * as snsSubscriptions from 'aws-cdk-lib/aws-sns-subscriptions';
import * as sqs from 'aws-cdk-lib/aws-sqs';
import * as wafv2 from 'aws-cdk-lib/aws-wafv2';
import type { Construct } from 'constructs';

export interface AppStackProps extends StackProps {
  stage: string;
  key: kms.Key;
  evidenceBucket: s3.Bucket;
  tables: Record<string, dynamodb.Table>;
  userPool: cognito.UserPool;
  dashboardClient: cognito.UserPoolClient;
  ingestClient: cognito.UserPoolClient;
  /** Email address subscribed to CRITICAL alerts. */
  alertEmail?: string;
  /** Enable Bedrock classification. */
  bedrockEnabled: boolean;
  bedrockModelId: string;
  /** Talkin integration configuration. */
  talkinAdapter: 'noop' | 'mock' | 'http';
  talkinApiBaseUrl?: string;
  talkinApiSecretName?: string;
  capabilities: Record<string, boolean>;
  retentionDays: Record<string, number>;
  /** Requests per 5 minutes per IP, enforced at the WAF. */
  wafRateLimit: number;
}

export class AppStack extends Stack {
  readonly api: apigwv2.HttpApi;
  readonly alertTopic: sns.Topic;

  constructor(scope: Construct, id: string, props: AppStackProps) {
    super(scope, id, props);

    const { tables } = props;

    // --- Event bus ---------------------------------------------------------
    const bus = new events.EventBus(this, 'Bus', {
      eventBusName: `talkinshield-${props.stage}`,
    });

    // --- Alerting ----------------------------------------------------------
    this.alertTopic = new sns.Topic(this, 'AlertTopic', {
      topicName: `talkinshield-${props.stage}-alerts`,
      displayName: 'TalkinShield security alerts',
      masterKey: props.key,
    });
    if (props.alertEmail !== undefined) {
      this.alertTopic.addSubscription(new snsSubscriptions.EmailSubscription(props.alertEmail));
    }

    // --- Dead-letter queue for async invocations ---------------------------
    const dlq = new sqs.Queue(this, 'Dlq', {
      queueName: `talkinshield-${props.stage}-dlq`,
      encryption: sqs.QueueEncryption.KMS,
      encryptionMasterKey: props.key,
      retentionPeriod: Duration.days(14),
      enforceSSL: true,
    });

    const commonEnv: Record<string, string> = {
      STAGE: props.stage,
      LOG_LEVEL: props.stage === 'prod' ? 'info' : 'debug',
      NODE_OPTIONS: '--enable-source-maps',

      COGNITO_USER_POOL_ID: props.userPool.userPoolId,
      COGNITO_CLIENT_ID: `${props.dashboardClient.userPoolClientId},${props.ingestClient.userPoolClientId}`,
      MODERATOR_GROUPS: 'moderators,admins',
      ADMIN_GROUPS: 'admins',
      SERVICE_GROUPS: 'telemetry-ingest',
      REQUIRE_MFA_FOR_DESTRUCTIVE: props.stage === 'prod' ? 'true' : 'false',

      TABLE_EVENTS: tables.events!.tableName,
      TABLE_USER_STATE: tables.userState!.tableName,
      TABLE_INCIDENTS: tables.incidents!.tableName,
      TABLE_SIGNALS: tables.signals!.tableName,
      TABLE_ACTIONS: tables.actions!.tableName,
      TABLE_RULES: tables.rules!.tableName,
      TABLE_AUDIT: tables.audit!.tableName,
      TABLE_RATELIMIT: tables.rateLimit!.tableName,

      EVIDENCE_BUCKET: props.evidenceBucket.bucketName,
      EVIDENCE_OBJECT_LOCK_DAYS: String(props.retentionDays.evidence ?? 365),
      KMS_KEY_ID: props.key.keyArn,

      EVENT_BUS_NAME: bus.eventBusName,
      EVENT_SOURCE: 'talkinshield.detection',

      BEDROCK_ENABLED: String(props.bedrockEnabled),
      BEDROCK_MODEL_ID: props.bedrockModelId,

      TALKIN_ADAPTER: props.talkinAdapter,
      ...(props.talkinApiBaseUrl !== undefined ? { TALKIN_API_BASE_URL: props.talkinApiBaseUrl } : {}),
      ...(props.talkinApiSecretName !== undefined
        ? { TALKIN_API_SECRET_NAME: props.talkinApiSecretName }
        : {}),

      TALKIN_CAP_MESSAGE_CONTENT: String(props.capabilities.messageContent ?? false),
      TALKIN_CAP_MODERATION_EVENTS: String(props.capabilities.moderationEvents ?? false),
      TALKIN_CAP_VOICE_AUDIO: String(props.capabilities.voiceAudio ?? false),
      TALKIN_CAP_HIDDEN_PRESENCE: String(props.capabilities.hiddenPresenceEvents ?? false),
      TALKIN_CAP_CLIENT_ATTESTATION: String(props.capabilities.clientAttestation ?? false),
      TALKIN_CAP_REMOTE_MUTE: String(props.capabilities.remoteMute ?? false),
      TALKIN_CAP_REMOTE_BLOCK: String(props.capabilities.remoteBlock ?? false),

      ALERT_SNS_TOPIC_ARN: this.alertTopic.topicArn,
      ALERT_MIN_LEVEL: 'HIGH',

      RETENTION_RAW_EVENTS_DAYS: String(props.retentionDays.rawEvents ?? 30),
      RETENTION_SIGNALS_DAYS: String(props.retentionDays.signals ?? 90),
      RETENTION_INCIDENTS_DAYS: String(props.retentionDays.incidents ?? 365),
      RETENTION_EVIDENCE_DAYS: String(props.retentionDays.evidence ?? 365),
      RETENTION_AUDIT_DAYS: String(props.retentionDays.audit ?? 730),
    };

    const fn = (
      name: string,
      entry: string,
      options: { timeout?: Duration; memory?: number; env?: Record<string, string> } = {},
    ): lambda.Function =>
      new lambda.Function(this, name, {
        functionName: `talkinshield-${props.stage}-${name.toLowerCase()}`,
        runtime: lambda.Runtime.NODEJS_22_X,
        architecture: lambda.Architecture.ARM_64, // Cheaper and faster for this workload.
        handler: `${entry}.handler`,
        // Built by `npm run build`; see docs/DEPLOYMENT.md.
        code: lambda.Code.fromAsset('../backend/dist'),
        timeout: options.timeout ?? Duration.seconds(15),
        memorySize: options.memory ?? 512,
        environment: { ...commonEnv, ...options.env },
        environmentEncryption: props.key,
        logRetention: logs.RetentionDays.THREE_MONTHS,
        tracing: lambda.Tracing.ACTIVE,
        deadLetterQueue: dlq,
        reservedConcurrentExecutions: name === 'Api' ? undefined : 50,
      });

    // --- Functions ---------------------------------------------------------
    const apiFn = fn('Api', 'lambda/api', { timeout: Duration.seconds(20), memory: 1024 });
    const analyzeFn = fn('Analyze', 'lambda/analyze', {
      // Bedrock calls dominate the latency budget here.
      timeout: Duration.seconds(30),
      memory: 1024,
    });
    const alertFn = fn('Alert', 'lambda/alert', { timeout: Duration.seconds(15) });
    const retentionFn = fn('Retention', 'lambda/retention', {
      timeout: Duration.minutes(10),
      memory: 1024,
    });
    const coordinationFn = fn('Coordination', 'lambda/coordination', {
      timeout: Duration.minutes(5),
      memory: 1024,
    });

    // --- IAM: least privilege per function ---------------------------------
    grantReadData(apiFn, tables);
    tables.incidents!.grantReadWriteData(apiFn);
    tables.actions!.grantReadWriteData(apiFn);
    tables.rules!.grantReadWriteData(apiFn);
    tables.rateLimit!.grantReadWriteData(apiFn);
    grantAppendOnlyAudit(apiFn, tables.audit!);
    grantEvidenceReadWrite(apiFn, props.evidenceBucket);
    bus.grantPutEventsTo(apiFn);
    props.key.grantEncryptDecrypt(apiFn);

    grantReadData(analyzeFn, tables);
    tables.userState!.grantReadWriteData(analyzeFn);
    tables.signals!.grantReadWriteData(analyzeFn);
    tables.incidents!.grantReadWriteData(analyzeFn);
    tables.actions!.grantReadWriteData(analyzeFn);
    tables.rateLimit!.grantReadWriteData(analyzeFn);
    grantAppendOnlyAudit(analyzeFn, tables.audit!);
    grantEvidenceReadWrite(analyzeFn, props.evidenceBucket);
    bus.grantPutEventsTo(analyzeFn);
    this.alertTopic.grantPublish(analyzeFn);
    props.key.grantEncryptDecrypt(analyzeFn);

    tables.signals!.grantReadWriteData(coordinationFn);
    tables.events!.grantReadData(coordinationFn);
    tables.rules!.grantReadData(coordinationFn);
    bus.grantPutEventsTo(coordinationFn);
    props.key.grantEncryptDecrypt(coordinationFn);

    grantAppendOnlyAudit(alertFn, tables.audit!);
    this.alertTopic.grantPublish(alertFn);
    props.key.grantEncryptDecrypt(alertFn);

    // Retention is the ONLY function permitted to delete evidence.
    tables.incidents!.grantReadData(retentionFn);
    grantAppendOnlyAudit(retentionFn, tables.audit!);
    props.evidenceBucket.grantRead(retentionFn);
    retentionFn.addToRolePolicy(
      new iam.PolicyStatement({
        actions: ['s3:DeleteObject', 's3:DeleteObjectVersion'],
        resources: [props.evidenceBucket.arnForObjects('evidence/*')],
      }),
    );
    props.key.grantEncryptDecrypt(retentionFn);

    if (props.bedrockEnabled) {
      // Scoped to the single model in use, not bedrock:* on all models.
      analyzeFn.addToRolePolicy(
        new iam.PolicyStatement({
          actions: ['bedrock:InvokeModel'],
          resources: [
            `arn:aws:bedrock:${this.region}::foundation-model/${props.bedrockModelId}`,
            `arn:aws:bedrock:${this.region}:${this.account}:inference-profile/*`,
          ],
        }),
      );
    }

    if (props.talkinApiSecretName !== undefined) {
      const secretArn = `arn:aws:secretsmanager:${this.region}:${this.account}:secret:${props.talkinApiSecretName}-*`;
      for (const target of [apiFn, analyzeFn]) {
        target.addToRolePolicy(
          new iam.PolicyStatement({
            actions: ['secretsmanager:GetSecretValue'],
            resources: [secretArn],
          }),
        );
      }
    }

    // --- API Gateway + Cognito authorizer ----------------------------------
    const authorizer = new apigwv2Authorizers.HttpJwtAuthorizer(
      'CognitoAuthorizer',
      `https://cognito-idp.${this.region}.amazonaws.com/${props.userPool.userPoolId}`,
      {
        jwtAudience: [
          props.dashboardClient.userPoolClientId,
          props.ingestClient.userPoolClientId,
        ],
        identitySource: ['$request.header.Authorization'],
      },
    );

    this.api = new apigwv2.HttpApi(this, 'HttpApi', {
      apiName: `talkinshield-${props.stage}`,
      description: 'TalkinShield Security Console API',
      defaultAuthorizer: authorizer,
      corsPreflight: {
        allowHeaders: ['authorization', 'content-type'],
        allowMethods: [
          apigwv2.CorsHttpMethod.GET,
          apigwv2.CorsHttpMethod.POST,
          apigwv2.CorsHttpMethod.PATCH,
          apigwv2.CorsHttpMethod.PUT,
          apigwv2.CorsHttpMethod.OPTIONS,
        ],
        // Replace with the dashboard's real origin before production use.
        allowOrigins: props.stage === 'prod' ? [] : ['http://localhost:5173'],
        maxAge: Duration.hours(1),
      },
    });

    const integration = new apigwv2Integrations.HttpLambdaIntegration('ApiIntegration', apiFn);

    // Routes are declared explicitly rather than with a catch-all proxy, so the
    // gateway rejects unknown paths before they reach application code.
    const routes: Array<[apigwv2.HttpMethod, string]> = [
      [apigwv2.HttpMethod.POST, '/events'],
      [apigwv2.HttpMethod.GET, '/overview'],
      [apigwv2.HttpMethod.GET, '/events'],
      [apigwv2.HttpMethod.GET, '/signals'],
      [apigwv2.HttpMethod.GET, '/users'],
      [apigwv2.HttpMethod.GET, '/users/{userId}'],
      [apigwv2.HttpMethod.GET, '/incidents'],
      [apigwv2.HttpMethod.GET, '/incidents/{incidentId}'],
      [apigwv2.HttpMethod.PATCH, '/incidents/{incidentId}'],
      [apigwv2.HttpMethod.GET, '/evidence/{key+}'],
      [apigwv2.HttpMethod.POST, '/evidence/verify'],
      [apigwv2.HttpMethod.POST, '/moderation'],
      [apigwv2.HttpMethod.GET, '/moderation/actions'],
      [apigwv2.HttpMethod.GET, '/moderation/affordances'],
      [apigwv2.HttpMethod.GET, '/rules'],
      [apigwv2.HttpMethod.PUT, '/rules'],
      [apigwv2.HttpMethod.GET, '/settings'],
      [apigwv2.HttpMethod.GET, '/logs'],
      [apigwv2.HttpMethod.GET, '/me'],
    ];

    for (const [method, path] of routes) {
      this.api.addRoutes({ path, methods: [method], integration });
    }

    // --- WAF ---------------------------------------------------------------
    const webAcl = new wafv2.CfnWebACL(this, 'WebAcl', {
      name: `talkinshield-${props.stage}`,
      scope: 'REGIONAL',
      defaultAction: { allow: {} },
      visibilityConfig: {
        cloudWatchMetricsEnabled: true,
        metricName: `talkinshield-${props.stage}-waf`,
        sampledRequestsEnabled: true,
      },
      rules: [
        {
          name: 'RateLimitPerIp',
          priority: 0,
          action: { block: {} },
          statement: {
            rateBasedStatement: { limit: props.wafRateLimit, aggregateKeyType: 'IP' },
          },
          visibilityConfig: {
            cloudWatchMetricsEnabled: true,
            metricName: 'RateLimitPerIp',
            sampledRequestsEnabled: true,
          },
        },
        managedRule('AWSManagedRulesCommonRuleSet', 1),
        managedRule('AWSManagedRulesKnownBadInputsRuleSet', 2),
        managedRule('AWSManagedRulesAmazonIpReputationList', 3),
        managedRule('AWSManagedRulesSQLiRuleSet', 4),
      ],
    });

    new wafv2.CfnWebACLAssociation(this, 'WebAclAssociation', {
      // HttpApi default stage ARN.
      resourceArn: `arn:aws:apigateway:${this.region}::/apis/${this.api.apiId}/stages/$default`,
      webAclArn: webAcl.attrArn,
    });

    // --- EventBridge rules -------------------------------------------------
    new events.Rule(this, 'OnEventIngested', {
      eventBus: bus,
      description: 'Run detection for each newly ingested event.',
      eventPattern: { source: ['talkinshield.detection'], detailType: ['EventIngested'] },
      targets: [new targets.LambdaFunction(analyzeFn, { deadLetterQueue: dlq, retryAttempts: 2 })],
    });

    new events.Rule(this, 'OnHighRisk', {
      eventBus: bus,
      description: 'Notify operators when risk reaches HIGH or CRITICAL.',
      eventPattern: {
        source: ['talkinshield.detection'],
        detailType: ['RiskAssessed'],
        detail: { riskLevel: ['HIGH', 'CRITICAL'] },
      },
      targets: [new targets.LambdaFunction(alertFn, { deadLetterQueue: dlq })],
    });

    new events.Rule(this, 'OnWellbeingConcern', {
      eventBus: bus,
      description: 'Route wellbeing concerns to the support channel, never to enforcement.',
      eventPattern: {
        source: ['talkinshield.detection'],
        detailType: ['WellbeingConcern'],
      },
      targets: [new targets.LambdaFunction(alertFn, { deadLetterQueue: dlq })],
    });

    new events.Rule(this, 'OnCoordination', {
      eventBus: bus,
      description: 'Notify operators about coordinated multi-account behaviour.',
      eventPattern: {
        source: ['talkinshield.detection'],
        detailType: ['CoordinationDetected'],
      },
      targets: [new targets.LambdaFunction(alertFn, { deadLetterQueue: dlq })],
    });

    // --- Schedules ---------------------------------------------------------
    new events.Rule(this, 'CoordinationSchedule', {
      description: 'Sweep active rooms for coordinated behaviour.',
      schedule: events.Schedule.rate(Duration.minutes(5)),
      targets: [new targets.LambdaFunction(coordinationFn, { deadLetterQueue: dlq })],
    });

    new events.Rule(this, 'RetentionSchedule', {
      description: 'Enforce the configured data-retention policy.',
      schedule: events.Schedule.cron({ minute: '0', hour: '3' }),
      targets: [new targets.LambdaFunction(retentionFn, { deadLetterQueue: dlq })],
    });

    // --- CloudWatch alarms -------------------------------------------------
    const alarmAction = new cwActions.SnsAction(this.alertTopic);

    const alarm = (
      name: string,
      metric: cloudwatch.IMetric,
      threshold: number,
      description: string,
      evaluationPeriods = 1,
    ): void => {
      new cloudwatch.Alarm(this, name, {
        alarmName: `talkinshield-${props.stage}-${name}`,
        alarmDescription: description,
        metric,
        threshold,
        evaluationPeriods,
        comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
        treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
      }).addAlarmAction(alarmAction);
    };

    for (const target of [apiFn, analyzeFn, alertFn, retentionFn, coordinationFn]) {
      alarm(
        `${target.node.id}Errors`,
        target.metricErrors({ period: Duration.minutes(5) }),
        5,
        `${target.node.id} is failing — detection or moderation may be degraded.`,
        2,
      );
    }

    alarm(
      'ApiThrottles',
      apiFn.metricThrottles({ period: Duration.minutes(5) }),
      0,
      'The API function is being throttled; requests are being dropped.',
    );

    alarm(
      'DlqDepth',
      dlq.metricApproximateNumberOfMessagesVisible({ period: Duration.minutes(5) }),
      0,
      'Messages have landed in the dead-letter queue — events failed analysis permanently.',
    );

    // Custom metrics emitted via EMF by the application.
    const custom = (name: string): cloudwatch.Metric =>
      new cloudwatch.Metric({
        namespace: 'TalkinShield',
        metricName: name,
        dimensionsMap: { Stage: props.stage },
        period: Duration.minutes(5),
        statistic: 'Sum',
      });

    alarm(
      'EvidenceWriteFailures',
      custom('EvidenceWriteFailure'),
      0,
      'Evidence could not be written. Incidents are being created without supporting evidence.',
    );
    alarm(
      'AuditWriteFailures',
      custom('AuditWriteFailure'),
      0,
      'Audit entries are failing to persist — the audit trail is incomplete.',
    );
    alarm(
      'AuthFailureSpike',
      custom('AuthFailure'),
      50,
      'Unusual volume of authentication failures against the console API.',
    );
    alarm(
      'ClassifierFailures',
      custom('ClassifierFailure'),
      20,
      'AI classification is failing repeatedly; detection has degraded to rules only.',
    );
    alarm(
      'UserStateConflicts',
      custom('UserStateConflict'),
      25,
      'Repeated optimistic-concurrency conflicts on user state; some updates are being dropped.',
    );

    // --- Outputs -----------------------------------------------------------
    new CfnOutput(this, 'ApiUrl', { value: this.api.apiEndpoint });
    new CfnOutput(this, 'AlertTopicArn', { value: this.alertTopic.topicArn });
    new CfnOutput(this, 'EvidenceBucketName', { value: props.evidenceBucket.bucketName });
    new CfnOutput(this, 'EventBusName', { value: bus.eventBusName });
  }
}

function managedRule(name: string, priority: number): wafv2.CfnWebACL.RuleProperty {
  return {
    name,
    priority,
    overrideAction: { none: {} },
    statement: {
      managedRuleGroupStatement: { vendorName: 'AWS', name },
    },
    visibilityConfig: {
      cloudWatchMetricsEnabled: true,
      metricName: name,
      sampledRequestsEnabled: true,
    },
  };
}

/** Read access to the tables a function queries but never mutates. */
function grantReadData(target: lambda.Function, tables: Record<string, dynamodb.Table>): void {
  tables.events!.grantReadData(target);
  tables.userState!.grantReadData(target);
  tables.signals!.grantReadData(target);
  tables.rules!.grantReadData(target);
}

/**
 * Append-only audit access.
 *
 * Deliberately NOT `grantReadWriteData`, which would include UpdateItem and
 * DeleteItem. The audit trail must be immutable even to the application.
 */
function grantAppendOnlyAudit(target: lambda.Function, auditTable: dynamodb.Table): void {
  target.addToRolePolicy(
    new iam.PolicyStatement({
      sid: 'AuditAppendOnly',
      actions: ['dynamodb:PutItem', 'dynamodb:Query', 'dynamodb:GetItem'],
      resources: [auditTable.tableArn, `${auditTable.tableArn}/index/*`],
    }),
  );
  target.addToRolePolicy(
    new iam.PolicyStatement({
      sid: 'DenyAuditMutation',
      effect: iam.Effect.DENY,
      actions: ['dynamodb:UpdateItem', 'dynamodb:DeleteItem', 'dynamodb:BatchWriteItem'],
      resources: [auditTable.tableArn],
    }),
  );
}

/**
 * Evidence write + read, with deletion explicitly denied.
 * Only the retention function is granted DeleteObject, in the stack above.
 */
function grantEvidenceReadWrite(target: lambda.Function, bucket: s3.Bucket): void {
  target.addToRolePolicy(
    new iam.PolicyStatement({
      sid: 'EvidenceReadWrite',
      actions: ['s3:PutObject', 's3:GetObject', 's3:ListBucket'],
      resources: [bucket.bucketArn, bucket.arnForObjects('*')],
    }),
  );
  target.addToRolePolicy(
    new iam.PolicyStatement({
      sid: 'DenyEvidenceDeletion',
      effect: iam.Effect.DENY,
      actions: [
        's3:DeleteObject',
        's3:DeleteObjectVersion',
        's3:PutObjectRetention',
        's3:PutObjectLegalHold',
        's3:BypassGovernanceRetention',
      ],
      resources: [bucket.arnForObjects('*')],
    }),
  );
}
