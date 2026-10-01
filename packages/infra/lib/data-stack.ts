/**
 * Data stack: KMS, DynamoDB tables and the S3 evidence bucket.
 *
 * Security posture:
 *   - One customer-managed KMS key per environment, with rotation enabled.
 *     Using a CMK rather than an AWS-managed key means decryption is auditable
 *     through CloudTrail and revocable via key policy.
 *   - Every table: SSE with the CMK, point-in-time recovery, on-demand billing,
 *     and a TTL attribute so retention is enforced by the platform rather than
 *     by application code that might regress.
 *   - Evidence bucket: versioning, Object Lock in COMPLIANCE mode, TLS-only
 *     bucket policy, all public access blocked, and access logging to a separate
 *     bucket.
 */

import {
  Duration,
  RemovalPolicy,
  Stack,
  type StackProps,
} from 'aws-cdk-lib';
import * as dynamodb from 'aws-cdk-lib/aws-dynamodb';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as kms from 'aws-cdk-lib/aws-kms';
import * as s3 from 'aws-cdk-lib/aws-s3';
import type { Construct } from 'constructs';

export interface DataStackProps extends StackProps {
  stage: string;
  /** Object Lock retention for evidence, in days. */
  evidenceRetentionDays: number;
  /** Retain data on stack deletion. Always true for prod. */
  retainOnDelete: boolean;
}

export class DataStack extends Stack {
  readonly key: kms.Key;
  readonly evidenceBucket: s3.Bucket;
  readonly tables: Record<string, dynamodb.Table>;

  constructor(scope: Construct, id: string, props: DataStackProps) {
    super(scope, id, props);

    const removalPolicy = props.retainOnDelete ? RemovalPolicy.RETAIN : RemovalPolicy.DESTROY;

    // --- KMS ---------------------------------------------------------------
    this.key = new kms.Key(this, 'TalkinShieldKey', {
      description: `TalkinShield ${props.stage} — encrypts all detection data and evidence.`,
      enableKeyRotation: true,
      rotationPeriod: Duration.days(365),
      removalPolicy,
      // A pending window gives time to recover from an accidental deletion.
      pendingWindow: Duration.days(props.retainOnDelete ? 30 : 7),
    });
    this.key.addAlias(`alias/talkinshield-${props.stage}`);

    // --- Access-log bucket -------------------------------------------------
    const accessLogs = new s3.Bucket(this, 'AccessLogsBucket', {
      encryption: s3.BucketEncryption.S3_MANAGED,
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      enforceSSL: true,
      versioned: false,
      removalPolicy,
      lifecycleRules: [{ expiration: Duration.days(400) }],
    });

    // --- Evidence bucket ---------------------------------------------------
    this.evidenceBucket = new s3.Bucket(this, 'EvidenceBucket', {
      encryption: s3.BucketEncryption.KMS,
      encryptionKey: this.key,
      bucketKeyEnabled: true,
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      enforceSSL: true,
      // Versioning is a prerequisite for Object Lock and gives a second line of
      // defence against overwrite.
      versioned: true,
      objectLockEnabled: true,
      objectLockDefaultRetention: s3.ObjectLockRetention.compliance(
        Duration.days(props.evidenceRetentionDays),
      ),
      serverAccessLogsBucket: accessLogs,
      serverAccessLogsPrefix: 'evidence-access/',
      removalPolicy,
      lifecycleRules: [
        {
          // Cheaper storage for older evidence that is still within retention.
          transitions: [
            {
              storageClass: s3.StorageClass.INFREQUENT_ACCESS,
              transitionAfter: Duration.days(60),
            },
          ],
        },
      ],
    });

    // Deny any attempt to write evidence without KMS encryption, belt and
    // braces against a future code change that forgets the header.
    this.evidenceBucket.addToResourcePolicy(
      new iam.PolicyStatement({
        sid: 'DenyUnencryptedUploads',
        effect: iam.Effect.DENY,
        principals: [new iam.AnyPrincipal()],
        actions: ['s3:PutObject'],
        resources: [this.evidenceBucket.arnForObjects('*')],
        conditions: { StringNotEquals: { 's3:x-amz-server-side-encryption': 'aws:kms' } },
      }),
    );

    // --- DynamoDB ----------------------------------------------------------
    const table = (
      name: string,
      partitionKey: dynamodb.Attribute,
      sortKey?: dynamodb.Attribute,
    ): dynamodb.Table =>
      new dynamodb.Table(this, name, {
        tableName: `talkinshield-${props.stage}-${name.toLowerCase()}`,
        partitionKey,
        ...(sortKey ? { sortKey } : {}),
        billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
        encryption: dynamodb.TableEncryption.CUSTOMER_MANAGED,
        encryptionKey: this.key,
        pointInTimeRecoverySpecification: { pointInTimeRecoveryEnabled: true },
        timeToLiveAttribute: 'expiresAt',
        removalPolicy,
        deletionProtection: props.retainOnDelete,
      });

    const S = dynamodb.AttributeType.STRING;
    const N = dynamodb.AttributeType.NUMBER;

    const events = table('Events', { name: 'userId', type: S }, { name: 'sk', type: S });
    events.addGlobalSecondaryIndex({
      indexName: 'byRoom',
      partitionKey: { name: 'roomId', type: S },
      sortKey: { name: 'receivedAtMs', type: N },
    });
    events.addGlobalSecondaryIndex({
      indexName: 'byEventId',
      partitionKey: { name: 'eventId', type: S },
      projectionType: dynamodb.ProjectionType.ALL,
    });

    const userState = table('UserState', { name: 'userId', type: S });
    userState.addGlobalSecondaryIndex({
      indexName: 'byRisk',
      partitionKey: { name: 'riskBucket', type: S },
      sortKey: { name: 'riskScore', type: N },
    });

    const signals = table('Signals', { name: 'userId', type: S }, { name: 'sk', type: S });
    signals.addGlobalSecondaryIndex({
      indexName: 'byDay',
      partitionKey: { name: 'day', type: S },
      sortKey: { name: 'observedAtMs', type: N },
    });

    const incidents = table('Incidents', { name: 'incidentId', type: S });
    incidents.addGlobalSecondaryIndex({
      indexName: 'byStatus',
      partitionKey: { name: 'status', type: S },
      sortKey: { name: 'createdAtMs', type: N },
    });
    incidents.addGlobalSecondaryIndex({
      indexName: 'byUser',
      partitionKey: { name: 'userId', type: S },
      sortKey: { name: 'updatedAtMs', type: N },
    });

    const actions = table('Actions', { name: 'targetUserId', type: S }, { name: 'sk', type: S });
    actions.addGlobalSecondaryIndex({
      indexName: 'byDay',
      partitionKey: { name: 'day', type: S },
      sortKey: { name: 'atMs', type: N },
    });

    const audit = table('Audit', { name: 'auditId', type: S });
    audit.addGlobalSecondaryIndex({
      indexName: 'byDay',
      partitionKey: { name: 'day', type: S },
      sortKey: { name: 'atMs', type: N },
    });
    audit.addGlobalSecondaryIndex({
      indexName: 'byActor',
      partitionKey: { name: 'actorId', type: S },
      sortKey: { name: 'atMs', type: N },
    });

    const rules = table('Rules', { name: 'configKey', type: S });
    const rateLimit = table('RateLimit', { name: 'bucketKey', type: S });

    this.tables = {
      events,
      userState,
      signals,
      incidents,
      actions,
      audit,
      rules,
      rateLimit,
    };
  }
}
