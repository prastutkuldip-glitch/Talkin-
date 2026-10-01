/**
 * S3 evidence storage.
 *
 * Integrity controls, layered:
 *   - `IfNoneMatch: '*'` on PUT makes writes conditional: an existing key is
 *     never silently overwritten, even by this code.
 *   - SSE-KMS with a customer-managed key, so decryption is separately
 *     auditable through CloudTrail and revocable via key policy.
 *   - Object Lock in COMPLIANCE mode with a retention date, applied by the
 *     bucket configuration: not even the account root can delete an object
 *     before its retain-until date.
 *   - The application IAM role is granted PutObject/GetObject only — no
 *     DeleteObject, no PutObjectRetention. Retention deletion runs under a
 *     separate role.
 *   - Bucket versioning plus a hash chain in the object body, so deletion or
 *     substitution is detectable even if storage controls were bypassed.
 */

import {
  GetObjectCommand,
  ListObjectsV2Command,
  PutObjectCommand,
  S3Client,
  DeleteObjectCommand,
} from '@aws-sdk/client-s3';

import type { EvidenceBundle } from '@talkinshield/core';

import type { EvidenceStore, Logger } from '../../ports.ts';

export interface S3EvidenceConfig {
  bucket: string;
  kmsKeyId?: string;
  objectLockDays: number;
}

const CHAIN_HEAD_KEY = 'chain/head.json';

export class S3EvidenceStore implements EvidenceStore {
  private readonly client: S3Client;
  private readonly config: S3EvidenceConfig;
  private readonly logger: Logger;

  constructor(client: S3Client, config: S3EvidenceConfig, logger: Logger) {
    this.client = client;
    this.config = config;
    this.logger = logger;
  }

  async put(bundle: EvidenceBundle): Promise<{ key: string; versionId?: string }> {
    const body = JSON.stringify(
      {
        body: bundle.body,
        contentHash: bundle.contentHash,
        previousHash: bundle.previousHash,
        chainHash: bundle.chainHash,
        sequence: bundle.sequence,
      },
      null,
      2,
    );

    const retainUntil = new Date(Date.now() + this.config.objectLockDays * 86_400_000);

    const result = await this.client.send(
      new PutObjectCommand({
        Bucket: this.config.bucket,
        Key: bundle.key,
        Body: body,
        ContentType: 'application/json',
        // Write-once: fails with PreconditionFailed if the key already exists.
        IfNoneMatch: '*',
        ...(this.config.kmsKeyId !== undefined
          ? { ServerSideEncryption: 'aws:kms', SSEKMSKeyId: this.config.kmsKeyId }
          : { ServerSideEncryption: 'aws:kms' }),
        ObjectLockMode: 'COMPLIANCE',
        ObjectLockRetainUntilDate: retainUntil,
        // Integrity metadata is duplicated into object metadata so it can be
        // checked with a HEAD request, without downloading the body.
        Metadata: {
          'content-hash': bundle.contentHash,
          'chain-hash': bundle.chainHash,
          sequence: String(bundle.sequence),
          'schema-version': bundle.body.schemaVersion,
        },
        ChecksumAlgorithm: 'SHA256',
      }),
    );

    return {
      key: bundle.key,
      ...(result.VersionId !== undefined ? { versionId: result.VersionId } : {}),
    };
  }

  async get(key: string): Promise<EvidenceBundle | undefined> {
    try {
      const result = await this.client.send(
        new GetObjectCommand({ Bucket: this.config.bucket, Key: key }),
      );
      const text = await result.Body?.transformToString();
      if (text === undefined) return undefined;
      const parsed = JSON.parse(text) as Omit<EvidenceBundle, 'key'>;
      return { ...parsed, key };
    } catch (err: unknown) {
      if (isNotFound(err)) return undefined;
      throw err;
    }
  }

  async listByIncident(incidentId: string): Promise<string[]> {
    // Incident id is embedded in the key prefix, so this is a prefix list.
    // The date partition is unknown here, so we list by the incident segment
    // using the delimiter-free prefix scan bounded to a sane page size.
    const result = await this.client.send(
      new ListObjectsV2Command({
        Bucket: this.config.bucket,
        Prefix: 'evidence/',
        MaxKeys: 1000,
      }),
    );
    return (result.Contents ?? [])
      .map((o) => o.Key)
      .filter((k): k is string => typeof k === 'string' && k.includes(`/${incidentId}/`))
      .sort();
  }

  async getChainHead(): Promise<{ contentHash: string; sequence: number } | undefined> {
    try {
      const result = await this.client.send(
        new GetObjectCommand({ Bucket: this.config.bucket, Key: CHAIN_HEAD_KEY }),
      );
      const text = await result.Body?.transformToString();
      if (text === undefined) return undefined;
      const parsed = JSON.parse(text) as { contentHash?: unknown; sequence?: unknown };
      if (typeof parsed.contentHash !== 'string' || typeof parsed.sequence !== 'number') {
        return undefined;
      }
      return { contentHash: parsed.contentHash, sequence: parsed.sequence };
    } catch (err: unknown) {
      if (isNotFound(err)) return undefined;
      throw err;
    }
  }

  async setChainHead(contentHash: string, sequence: number): Promise<void> {
    // The head pointer is mutable by design (it is an index, not evidence), so
    // it is NOT object-locked. Losing it costs a chain re-scan, not integrity:
    // the chain itself is reconstructible from the stored bundles.
    await this.client.send(
      new PutObjectCommand({
        Bucket: this.config.bucket,
        Key: CHAIN_HEAD_KEY,
        Body: JSON.stringify({ contentHash, sequence, updatedAt: new Date().toISOString() }),
        ContentType: 'application/json',
        ServerSideEncryption: 'aws:kms',
        ...(this.config.kmsKeyId !== undefined ? { SSEKMSKeyId: this.config.kmsKeyId } : {}),
      }),
    );
  }

  /**
   * Retention deletion. Requires a role with `s3:DeleteObject` AND an object
   * whose Object Lock retain-until date has passed; otherwise S3 refuses.
   */
  async deleteForRetention(key: string): Promise<boolean> {
    try {
      await this.client.send(
        new DeleteObjectCommand({ Bucket: this.config.bucket, Key: key }),
      );
      return true;
    } catch (err: unknown) {
      this.logger.warn('Retention deletion refused by storage controls.', {
        key,
        error: err instanceof Error ? err.message : String(err),
      });
      return false;
    }
  }
}

function isNotFound(err: unknown): boolean {
  if (typeof err !== 'object' || err === null) return false;
  const name = (err as { name?: string }).name;
  return name === 'NoSuchKey' || name === 'NotFound';
}
