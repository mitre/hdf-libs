import { describe, it, expect, vi } from 'vitest';
import type { Service, ServiceResponse } from 'splunk-sdk';
import {
  fetchSplunkToHdf,
  pushHdfToSplunk,
  verifySplunkCredentials,
} from './fetcher.js';

// ---- mock harness ----

interface CapturedCall {
  method: 'GET' | 'POST';
  path: string;
  params?: Record<string, unknown>;
}

function makeService(opts: {
  serverInfoResponse?: ServiceResponse | (() => ServiceResponse);
  serverInfoError?: unknown;
  getHandler?: (path: string, params?: Record<string, unknown>) => ServiceResponse | Promise<ServiceResponse>;
  postHandler?: (path: string, params?: Record<string, unknown>) => ServiceResponse | Promise<ServiceResponse>;
}): { service: Service; calls: CapturedCall[] } {
  const calls: CapturedCall[] = [];
  const service: Service = {
    serverInfo: vi.fn(async () => {
      if (opts.serverInfoError) throw opts.serverInfoError;
      const r = opts.serverInfoResponse ?? { status: 200, body: { generator: 'splunk' } };
      return typeof r === 'function' ? r() : r;
    }),
    get: vi.fn(async (path: string, params?: Record<string, unknown>) => {
      calls.push({ method: 'GET', path, params });
      if (opts.getHandler) return opts.getHandler(path, params);
      return { status: 200, body: {} };
    }),
    post: vi.fn(async (path: string, params?: Record<string, unknown>) => {
      calls.push({ method: 'POST', path, params });
      if (opts.postHandler) return opts.postHandler(path, params);
      return { status: 200, body: {} };
    }),
  };
  return { service, calls };
}

// HDF input — single baseline, one requirement → push produces 1 report + 1 profile + 1 control.
function minimalHDF(): string {
  return JSON.stringify({
    baselines: [
      {
        name: 'Test',
        version: '1.0',
        integrity: { algorithm: 'sha256', checksum: 'deadbeef' },
        requirements: [
          {
            id: 'REQ-1',
            title: 't',
            impact: 0.5,
            tags: {},
            descriptions: [{ label: 'default', data: 'd' }],
            results: [
              { status: 'passed', codeDesc: 'ok', startTime: '2026-01-01T00:00:00Z' },
            ],
          },
        ],
      },
    ],
    tool: { name: 'test', version: '1.0' },
    generator: { name: 'test', version: '1.0' },
    timestamp: '2026-01-01T00:00:00Z',
  });
}

function hdfWithNRequirements(n: number): string {
  const reqs = Array.from({ length: n }, (_, i) => ({
    id: `REQ-${i}`,
    title: 't',
    impact: 0.1,
    tags: {},
    descriptions: [{ label: 'default', data: 'd' }],
    results: [{ status: 'passed', codeDesc: 'ok', startTime: '2026-01-01T00:00:00Z' }],
  }));
  return JSON.stringify({
    baselines: [
      {
        name: 'Big',
        version: '1',
        integrity: { algorithm: 'sha256', checksum: 'deadbeef' },
        requirements: reqs,
      },
    ],
  });
}

// =============================================================================
// verifySplunkCredentials
// =============================================================================

describe('verifySplunkCredentials', () => {
  it('returns true when serverInfo responds 200', async () => {
    const { service } = makeService({});
    await expect(verifySplunkCredentials(service)).resolves.toBe(true);
  });

  it('returns false when serverInfo rejects with 401', async () => {
    const { service } = makeService({ serverInfoError: { status: 401, message: 'unauthorized' } });
    await expect(verifySplunkCredentials(service)).resolves.toBe(false);
  });

  it('returns false when serverInfo rejects with 403', async () => {
    const { service } = makeService({ serverInfoError: { status: 403 } });
    await expect(verifySplunkCredentials(service)).resolves.toBe(false);
  });

  it('returns false when serverInfo resolves with non-2xx status', async () => {
    const { service } = makeService({ serverInfoResponse: { status: 500 } });
    await expect(verifySplunkCredentials(service)).resolves.toBe(false);
  });

  it('rethrows non-auth transport errors', async () => {
    const { service } = makeService({ serverInfoError: new Error('connection refused') });
    await expect(verifySplunkCredentials(service)).rejects.toThrow(/connection refused/);
  });

  it('does NOT call any credential-shaped methods on the service', async () => {
    const { service } = makeService({});
    await verifySplunkCredentials(service);
    expect((service as unknown as { login?: unknown }).login).toBeUndefined();
    expect(service.serverInfo).toHaveBeenCalledTimes(1);
  });
});

// =============================================================================
// pushHdfToSplunk
// =============================================================================

describe('pushHdfToSplunk', () => {
  it('issues report + profile + control POSTs in order', async () => {
    const { service, calls } = makeService({});
    await pushHdfToSplunk(service, minimalHDF(), { index: 'hdf' });

    const preflight = calls.filter((c) => c.method === 'GET' && c.path.startsWith('data/indexes/'));
    expect(preflight).toHaveLength(1);

    const posts = calls.filter(
      (c) => c.method === 'POST' && c.path === 'receivers/simple',
    );
    expect(posts).toHaveLength(3); // 1 report + 1 profile + 1 control

    for (const p of posts) {
      expect(p.params?.index).toBe('hdf');
      expect(p.params?.sourcetype).toBe('HDF2Splunk');
    }
  });

  it('chunks controls at 100 per request', async () => {
    const { service, calls } = makeService({});
    await pushHdfToSplunk(service, hdfWithNRequirements(250), { index: 'hdf' });

    // 1 report + 1 profile + ceil(250/100) = 3 control posts = 5 total
    const posts = calls.filter(
      (c) => c.method === 'POST' && c.path === 'receivers/simple',
    );
    expect(posts).toHaveLength(5);
  });

  it('sends batched records as NDJSON in the request body', async () => {
    const { service, calls } = makeService({});
    await pushHdfToSplunk(service, hdfWithNRequirements(5), { index: 'hdf' });

    const posts = calls.filter(
      (c) => c.method === 'POST' && c.path === 'receivers/simple',
    );
    expect(posts).toHaveLength(3);
    const controlBatch = posts[2];
    const body = controlBatch.params?.body as string;
    expect(body.split('\n').filter(Boolean)).toHaveLength(5);
  });

  it('throws when preflight returns 404 for the index', async () => {
    const { service } = makeService({
      getHandler: () => { throw { status: 404 }; },
    });
    await expect(
      pushHdfToSplunk(service, minimalHDF(), { index: 'missing' }),
    ).rejects.toThrow(/missing.*does not exist/);
  });

  it('throws when receivers/simple POST returns 5xx', async () => {
    const { service } = makeService({
      postHandler: () => ({ status: 500 }),
    });
    await expect(
      pushHdfToSplunk(service, minimalHDF(), { index: 'hdf' }),
    ).rejects.toThrow(/HTTP 500/);
  });

  it('throws when index is missing', async () => {
    const { service } = makeService({});
    await expect(
      pushHdfToSplunk(service, minimalHDF(), { index: '' }),
    ).rejects.toThrow(/index/);
  });

  it('rejects unsafe index identifiers', async () => {
    const { service } = makeService({});
    await expect(
      pushHdfToSplunk(service, minimalHDF(), { index: 'idx|inject' }),
    ).rejects.toThrow(/invalid characters/);
  });

  it('rejects invalid HDF input before any network call', async () => {
    const { service, calls } = makeService({});
    await expect(
      pushHdfToSplunk(service, 'not json', { index: 'hdf' }),
    ).rejects.toThrow();
    expect(calls).toHaveLength(0);
  });

  it('honors a custom sourcetype', async () => {
    const { service, calls } = makeService({});
    await pushHdfToSplunk(service, minimalHDF(), { index: 'hdf', sourcetype: 'CustomST' });
    const posts = calls.filter((c) => c.method === 'POST');
    for (const p of posts) {
      expect(p.params?.sourcetype).toBe('CustomST');
    }
  });

  it('does NOT call any credential-shaped methods on the service', async () => {
    const { service } = makeService({});
    await pushHdfToSplunk(service, minimalHDF(), { index: 'hdf' });
    expect((service as unknown as { login?: unknown }).login).toBeUndefined();
  });
});

// =============================================================================
// fetchSplunkToHdf
// =============================================================================

describe('fetchSplunkToHdf', () => {
  it('issues a blocking search and then GETs the results', async () => {
    const { service, calls } = makeService({
      postHandler: (path) => {
        expect(path).toBe('search/jobs');
        return { status: 200, body: { sid: 'test-sid' } };
      },
      getHandler: (path) => {
        expect(path).toBe('search/v2/jobs/test-sid/results');
        return {
          status: 200,
          body: {
            fields: [{ name: '_raw' }],
            // splunk-to-hdf requires at least one header + profile + control event.
            rows: [
              [JSON.stringify({ meta: { guid: 'g', subtype: 'header' }, platform: { name: 'inspec' }, statistics: {}, version: '5' })],
              [JSON.stringify({ meta: { guid: 'g', subtype: 'profile' }, sha256: 'abc', name: 'p', controls: [] })],
              [JSON.stringify({ meta: { guid: 'g', subtype: 'control', profile_sha256: 'abc' }, id: 'R1', title: 't', impact: 0.5, code: '', desc: '', tags: {}, descriptions: [], refs: [], results: [{ status: 'passed', code_desc: 'ok', start_time: '2026-01-01T00:00:00Z' }] })],
            ],
          },
        };
      },
    });
    const out = await fetchSplunkToHdf(service, { index: 'hdf', guid: 'g' });
    expect(out).toBeTruthy();
    expect(calls.some((c) => c.method === 'POST' && c.path === 'search/jobs')).toBe(true);
  });

  it('throws when index is invalid', async () => {
    const { service } = makeService({});
    await expect(
      fetchSplunkToHdf(service, { index: 'idx|x', guid: 'g' }),
    ).rejects.toThrow(/invalid characters/);
  });

  it('throws when guid is invalid', async () => {
    const { service } = makeService({});
    await expect(
      fetchSplunkToHdf(service, { index: 'idx', guid: '../escape' }),
    ).rejects.toThrow(/invalid characters/);
  });

  it('throws when search job returns no SID', async () => {
    const { service } = makeService({
      postHandler: () => ({ status: 200, body: {} }),
    });
    await expect(
      fetchSplunkToHdf(service, { index: 'hdf', guid: 'g' }),
    ).rejects.toThrow(/no SID/);
  });

  it('throws when search submission fails', async () => {
    const { service } = makeService({
      postHandler: () => ({ status: 500 }),
    });
    await expect(
      fetchSplunkToHdf(service, { index: 'hdf', guid: 'g' }),
    ).rejects.toThrow(/HTTP 500/);
  });

  it('skips rows where _raw is not valid JSON', async () => {
    const { service } = makeService({
      postHandler: () => ({ status: 200, body: { sid: 'sid1' } }),
      getHandler: () => ({
        status: 200,
        body: {
          fields: [{ name: '_raw' }],
          rows: [
            ['not json'],
            [JSON.stringify({ meta: { guid: 'g', subtype: 'header' }, platform: { name: 'inspec' }, statistics: {}, version: '5' })],
            [JSON.stringify({ meta: { guid: 'g', subtype: 'profile' }, sha256: 'abc', name: 'p', controls: [] })],
            [JSON.stringify({ meta: { guid: 'g', subtype: 'control', profile_sha256: 'abc' }, id: 'R1', title: 't', impact: 0.5, code: '', desc: '', tags: {}, descriptions: [], refs: [], results: [{ status: 'passed', code_desc: 'ok', start_time: '2026-01-01T00:00:00Z' }] })],
          ],
        },
      }),
    });
    const out = await fetchSplunkToHdf(service, { index: 'hdf', guid: 'g' });
    expect(out).toBeTruthy();
  });

  it('throws when results response is missing _raw field', async () => {
    const { service } = makeService({
      postHandler: () => ({ status: 200, body: { sid: 'sid1' } }),
      getHandler: () => ({
        status: 200,
        body: { fields: [{ name: 'other' }], rows: [['val']] },
      }),
    });
    // No _raw field → events array is empty → convertSplunkToHdf rejects empty input
    await expect(
      fetchSplunkToHdf(service, { index: 'hdf', guid: 'g' }),
    ).rejects.toThrow();
  });
});
