// AWS Security Hub fetcher — auth-agnostic TS API.
//
// Per the project rule (see `fetchers/README.md`): this library accepts a
// caller-supplied `SecurityHubClient`. The client carries AWS credentials
// via the SDK's standard chain (env vars, ~/.aws/credentials, IAM instance
// role, AssumeRole, etc.). The library never touches credential material.

import {
  DescribeHubCommand,
  GetFindingsCommand,
  type AwsSecurityFinding,
  type AwsSecurityFindingFilters,
  type SecurityHubClient,
} from '@aws-sdk/client-securityhub';
import { convertAsffToHdf } from '../../../converters/asff-to-hdf/typescript/converter.js';
import type { HDFResults } from '@mitre/hdf-schema';

const DEFAULT_MAX_PAGES = 10_000;
const DEFAULT_PAGE_SIZE = 100;

export interface FetchOptions {
  /** Optional ASFF finding filter — pass-through to GetFindings. */
  filters?: AwsSecurityFindingFilters;
  /** Cap pagination loop iterations. Values <= 0 or non-integers use the default (10_000). */
  maxPages?: number;
  /** Override the default page size. Must be an integer in 1..100 (the API max). */
  pageSize?: number;
  /** Optional converter version string written into the HDF Generator field. */
  converterVersion?: string;
}

/**
 * Verifies that the supplied client can authenticate against AWS Security
 * Hub. Returns true on success, false on credential-related errors (auth
 * denied, unrecognized client). Other errors (throttling, network) throw.
 */
export async function verifyAWSSecurityHubCredentials(
  client: SecurityHubClient,
): Promise<boolean> {
  try {
    await client.send(new DescribeHubCommand({}));
    return true;
  } catch (err) {
    if (isAuthError(err)) return false;
    throw err;
  }
}

/**
 * Pages through GetFindings, accumulates the findings into the standard
 * `{"Findings": [...]}` envelope that asff-to-hdf accepts, and returns
 * the converted HDF Results.
 */
export async function fetchAWSSecurityHubToHdf(
  client: SecurityHubClient,
  opts: FetchOptions = {},
): Promise<HDFResults> {
  // Mirror the Go fetcher: a non-positive/non-integer maxPages falls back to the
  // default rather than throwing a confusing "page limit (0)" on the first loop.
  const maxPages =
    Number.isInteger(opts.maxPages) && (opts.maxPages as number) > 0
      ? (opts.maxPages as number)
      : DEFAULT_MAX_PAGES;

  const pageSize = opts.pageSize ?? DEFAULT_PAGE_SIZE;
  if (!Number.isInteger(pageSize) || pageSize < 1 || pageSize > 100) {
    throw new Error(
      `aws-securityhub: pageSize must be an integer in 1..100 (the GetFindings API max), got ${pageSize}`,
    );
  }

  const findings: AwsSecurityFinding[] = [];
  let nextToken: string | undefined;

  for (let page = 0; ; page++) {
    if (page >= maxPages) {
      throw new Error(
        `aws-securityhub GetFindings: exceeded maximum page limit (${maxPages})`,
      );
    }

    const out = await client.send(
      new GetFindingsCommand({
        NextToken: nextToken,
        MaxResults: pageSize,
        Filters: opts.filters,
      }),
    );

    if (out.Findings) findings.push(...out.Findings);

    if (!out.NextToken) break;
    nextToken = out.NextToken;
  }

  const envelope = JSON.stringify({ Findings: findings });
  const hdfJson = await convertAsffToHdf(envelope, opts.converterVersion);
  return JSON.parse(hdfJson) as HDFResults;
}

// ---- helpers ----

function isAuthError(err: unknown): boolean {
  if (!err || typeof err !== 'object') return false;
  const name = (err as { name?: string }).name;
  if (!name) return false;
  return (
    name === 'AccessDeniedException' ||
    name === 'UnrecognizedClientException' ||
    name === 'InvalidAccessKeyId' ||
    name === 'SignatureDoesNotMatch'
  );
}
