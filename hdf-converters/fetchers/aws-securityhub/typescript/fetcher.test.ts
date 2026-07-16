import { describe, it, expect, vi } from 'vitest';
import type {
  SecurityHubClient,
  GetFindingsCommandInput,
  GetFindingsCommandOutput,
  DescribeHubCommandOutput,
  AwsSecurityFinding,
  AwsSecurityFindingFilters,
} from '@aws-sdk/client-securityhub';

import {
  verifyAWSSecurityHubCredentials,
  fetchAWSSecurityHubToHdf,
} from './fetcher.js';

// ---- mock harness ----

interface MockSetup {
  // Pages returned by successive GetFindings calls.
  pages?: Array<{ Findings: Partial<AwsSecurityFinding>[]; NextToken?: string }>;
  // Error to return from any GetFindings call.
  getFindingsError?: Error;
  // DescribeHub response and/or error.
  describeHubResponse?: Partial<DescribeHubCommandOutput>;
  describeHubError?: Error;
}

interface MockResult {
  client: SecurityHubClient;
  getFindingsInputs: GetFindingsCommandInput[];
  getFindingsCalls: number;
  describeHubCalls: number;
}

function makeClient(setup: MockSetup): MockResult {
  const inputs: GetFindingsCommandInput[] = [];
  let pageIdx = 0;
  let describeHubCalls = 0;

  const send = vi.fn(async (cmd: { input: unknown; constructor: { name: string } }) => {
    const name = cmd.constructor.name;
    if (name === 'GetFindingsCommand') {
      if (setup.getFindingsError) throw setup.getFindingsError;
      const input = cmd.input as GetFindingsCommandInput;
      inputs.push(input);

      const pages = setup.pages ?? [];
      if (pageIdx >= pages.length) {
        return { Findings: [] } as GetFindingsCommandOutput;
      }
      const page = pages[pageIdx];
      pageIdx++;
      return {
        Findings: page.Findings as AwsSecurityFinding[],
        NextToken: page.NextToken,
      } as GetFindingsCommandOutput;
    }
    if (name === 'DescribeHubCommand') {
      describeHubCalls++;
      if (setup.describeHubError) throw setup.describeHubError;
      return (setup.describeHubResponse ?? {
        HubArn: 'arn:aws:securityhub:us-east-1:123456789012:hub/default',
      }) as DescribeHubCommandOutput;
    }
    throw new Error(`unexpected command: ${name}`);
  });

  const client = { send } as unknown as SecurityHubClient;

  return {
    client,
    getFindingsInputs: inputs,
    get getFindingsCalls() {
      return inputs.length;
    },
    get describeHubCalls() {
      return describeHubCalls;
    },
  };
}

function minimalFinding(id: string): Partial<AwsSecurityFinding> {
  return {
    AwsAccountId: '123456789012',
    Id: id,
    GeneratorId: 'test-generator',
    ProductArn: 'arn:aws:securityhub:us-east-1::product/aws/securityhub',
    SchemaVersion: '2018-10-08',
    Title: `Test finding ${id}`,
    Description: 'test description',
    Severity: { Label: 'MEDIUM' },
    Resources: [{ Type: 'AwsS3Bucket', Id: 'arn:aws:s3:::test' }],
    Types: [
      'Software and Configuration Checks/Industry and Regulatory Standards/AWS-Foundational-Security-Best-Practices',
    ],
    CreatedAt: '2026-01-01T00:00:00.000Z',
    UpdatedAt: '2026-01-01T00:00:00.000Z',
  };
}

// ---- verifyAWSSecurityHubCredentials ----

describe('verifyAWSSecurityHubCredentials', () => {
  it('returns true when DescribeHub succeeds', async () => {
    const m = makeClient({});
    expect(await verifyAWSSecurityHubCredentials(m.client)).toBe(true);
    expect(m.describeHubCalls).toBe(1);
  });

  it('returns false on AccessDenied / Unauthorized SDK errors', async () => {
    const m = makeClient({
      describeHubError: Object.assign(new Error('access denied'), {
        name: 'AccessDeniedException',
      }),
    });
    expect(await verifyAWSSecurityHubCredentials(m.client)).toBe(false);
  });

  it('returns false on UnrecognizedClient error', async () => {
    const m = makeClient({
      describeHubError: Object.assign(new Error('bad creds'), {
        name: 'UnrecognizedClientException',
      }),
    });
    expect(await verifyAWSSecurityHubCredentials(m.client)).toBe(false);
  });

  it('throws on non-auth errors (network, throttle, etc.)', async () => {
    const m = makeClient({
      describeHubError: Object.assign(new Error('throttled'), {
        name: 'ThrottlingException',
      }),
    });
    await expect(verifyAWSSecurityHubCredentials(m.client)).rejects.toThrow(/throttl/i);
  });

  it('returns false on InvalidAccessKeyId', async () => {
    const m = makeClient({
      describeHubError: Object.assign(new Error('bad key'), {
        name: 'InvalidAccessKeyId',
      }),
    });
    expect(await verifyAWSSecurityHubCredentials(m.client)).toBe(false);
  });

  it('returns false on SignatureDoesNotMatch', async () => {
    const m = makeClient({
      describeHubError: Object.assign(new Error('bad signature'), {
        name: 'SignatureDoesNotMatch',
      }),
    });
    expect(await verifyAWSSecurityHubCredentials(m.client)).toBe(false);
  });

  it('treats non-Error throws (e.g. string) as non-auth and re-throws', async () => {
    // Defense-in-depth coverage on the err-not-object guard in isAuthError.
    const send = vi.fn(async () => {
      throw 'literal string';
    });
    const client = { send } as unknown as SecurityHubClient;
    await expect(verifyAWSSecurityHubCredentials(client)).rejects.toBeTruthy();
  });
});

// ---- fetchAWSSecurityHubToHdf ----

describe('fetchAWSSecurityHubToHdf', () => {
  it('returns HDFResults from a single page of findings', async () => {
    const m = makeClient({
      pages: [{ Findings: [minimalFinding('f1'), minimalFinding('f2')] }],
    });
    const hdf = await fetchAWSSecurityHubToHdf(m.client);
    expect(hdf).toBeTruthy();
    expect(hdf.baselines).toBeDefined();
    expect(hdf.baselines.length).toBeGreaterThan(0);
    expect(m.getFindingsCalls).toBe(1);
    expect(m.getFindingsInputs[0].NextToken).toBeUndefined();
  });

  it('pages through findings via NextToken', async () => {
    const m = makeClient({
      pages: [
        { Findings: [minimalFinding('f1')], NextToken: 'page-2' },
        { Findings: [minimalFinding('f2')] },
      ],
    });
    await fetchAWSSecurityHubToHdf(m.client);
    expect(m.getFindingsCalls).toBe(2);
    expect(m.getFindingsInputs[1].NextToken).toBe('page-2');
  });

  it('returns a valid HDFResults envelope when zero findings', async () => {
    const m = makeClient({ pages: [{ Findings: [] }] });
    const hdf = await fetchAWSSecurityHubToHdf(m.client);
    expect(hdf).toBeTruthy();
    // The asff-to-hdf converter synthesizes a placeholder requirement.
    expect(hdf.baselines.length).toBeGreaterThan(0);
  });

  it('passes filters through to GetFindings', async () => {
    const filters: AwsSecurityFindingFilters = {
      ProductArn: [
        {
          Value: 'arn:aws:securityhub:us-east-1::product/aws/securityhub',
          Comparison: 'EQUALS',
        },
      ],
    };
    const m = makeClient({ pages: [{ Findings: [] }] });
    await fetchAWSSecurityHubToHdf(m.client, { filters });
    expect(m.getFindingsInputs[0].Filters).toEqual(filters);
  });

  it('enforces the pagination cap on a runaway NextToken loop', async () => {
    // Always return a NextToken — the fetcher must break out at maxPages.
    const send = vi.fn(async () => ({
      Findings: [],
      NextToken: 'forever',
    }));
    const client = { send } as unknown as SecurityHubClient;
    await expect(
      fetchAWSSecurityHubToHdf(client, { maxPages: 3 }),
    ).rejects.toThrow(/page limit/);
  });

  it('throws on SDK errors during GetFindings', async () => {
    const m = makeClient({
      getFindingsError: Object.assign(new Error('access denied'), {
        name: 'AccessDeniedException',
      }),
    });
    await expect(fetchAWSSecurityHubToHdf(m.client)).rejects.toThrow(/access denied/i);
  });

  it('rejects a pageSize above the API maximum before any request', async () => {
    const m = makeClient({ pages: [{ Findings: [] }] });
    await expect(
      fetchAWSSecurityHubToHdf(m.client, { pageSize: 500 }),
    ).rejects.toThrow(/pageSize must be an integer in 1\.\.100/);
    expect(m.getFindingsCalls).toBe(0);
  });

  it('rejects a non-positive / non-integer pageSize', async () => {
    const m = makeClient({ pages: [{ Findings: [] }] });
    await expect(
      fetchAWSSecurityHubToHdf(m.client, { pageSize: 0 }),
    ).rejects.toThrow(/pageSize/);
    await expect(
      fetchAWSSecurityHubToHdf(m.client, { pageSize: 2.5 }),
    ).rejects.toThrow(/pageSize/);
    expect(m.getFindingsCalls).toBe(0);
  });

  it('coerces a non-positive maxPages to the default instead of erroring', async () => {
    // maxPages: 0 must NOT surface the confusing "page limit (0)" error; it
    // falls back to the default, matching the Go fetcher.
    const m = makeClient({ pages: [{ Findings: [minimalFinding('f1')] }] });
    const hdf = await fetchAWSSecurityHubToHdf(m.client, { maxPages: 0 });
    expect(hdf.baselines.length).toBeGreaterThan(0);
    expect(m.getFindingsCalls).toBe(1);
  });
});

// ---- auth-agnostic invariant ----

describe('auth-agnostic invariant', () => {
  it('library NEVER calls client.send() with credential-shaped command names', async () => {
    const m = makeClient({ pages: [{ Findings: [] }] });
    await fetchAWSSecurityHubToHdf(m.client).catch(() => {});
    await verifyAWSSecurityHubCredentials(m.client).catch(() => {});

    // Every send() call must be a documented SDK command — never a custom
    // shape that would suggest the library is hand-rolling auth.
    const send = m.client.send as ReturnType<typeof vi.fn>;
    for (const call of send.mock.calls) {
      const cmd = call[0] as { constructor: { name: string } };
      expect(['GetFindingsCommand', 'DescribeHubCommand']).toContain(
        cmd.constructor.name,
      );
    }
  });
});
