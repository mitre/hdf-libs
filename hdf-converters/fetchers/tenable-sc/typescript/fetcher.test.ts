import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { zipSync, strToU8 } from 'fflate';
import { describe, it, expect, vi } from 'vitest';

import {
  verifyTenableSCCredentials,
  listTenableSCScans,
  fetchTenableSCScanToHdf,
  type TenableSCAuthFetch,
} from './fetcher.js';

const __dirname = dirname(fileURLToPath(import.meta.url));

// Real .nessus XML lives in the nessus converter's fixture dir — same
// content Tenable.SC returns from downloadType=v2.
const NESSUS_FIXTURE_PATH = join(
  __dirname,
  '..',
  '..',
  '..',
  'converters',
  'nessus-to-hdf',
  'fixtures',
  'input',
  'compliance.nessus',
);

function loadNessusFixture(): string {
  return readFileSync(NESSUS_FIXTURE_PATH, 'utf-8');
}

// ---- mock harness ----

type AuthFetchMock = ReturnType<typeof vi.fn> & TenableSCAuthFetch;

interface MockSetup {
  status?: number;
  bodyText?: string;
  bodyBytes?: Uint8Array;
  bodyJson?: unknown;
  contentType?: string;
}

function makeAuthFetch(handler: (path: string, init?: RequestInit) => MockSetup): AuthFetchMock {
  const fn = vi.fn(async (path: string, init?: RequestInit): Promise<Response> => {
    const result = handler(path, init);
    const status = result.status ?? 200;
    let body: BodyInit | null;
    let contentType = result.contentType ?? 'application/json';

    if (result.bodyBytes !== undefined) {
      body = new Blob([result.bodyBytes]);
      contentType = result.contentType ?? 'application/octet-stream';
    } else if (result.bodyJson !== undefined) {
      body = JSON.stringify(result.bodyJson);
    } else {
      body = result.bodyText ?? null;
      if (result.bodyText !== undefined && result.contentType === undefined) {
        contentType = 'text/plain';
      }
    }

    return new Response(body, {
      status,
      headers: { 'Content-Type': contentType },
    });
  });
  return fn as AuthFetchMock;
}

// ---- verifyTenableSCCredentials ----

describe('verifyTenableSCCredentials', () => {
  it('returns true on 200 from /rest/currentUser', async () => {
    const authFetch = makeAuthFetch((path) => {
      expect(path).toBe('/rest/currentUser');
      return { status: 200, bodyJson: { response: { username: 'test' } } };
    });

    expect(await verifyTenableSCCredentials(authFetch)).toBe(true);
    expect(authFetch).toHaveBeenCalledOnce();
  });

  it('returns false on 401', async () => {
    const authFetch = makeAuthFetch(() => ({ status: 401 }));
    expect(await verifyTenableSCCredentials(authFetch)).toBe(false);
  });

  it('returns false on 403', async () => {
    const authFetch = makeAuthFetch(() => ({ status: 403 }));
    expect(await verifyTenableSCCredentials(authFetch)).toBe(false);
  });

  it('throws on 5xx (network / server failure is distinct from auth failure)', async () => {
    const authFetch = makeAuthFetch(() => ({ status: 500 }));
    await expect(verifyTenableSCCredentials(authFetch)).rejects.toThrow(/500/);
  });

  it('uses GET', async () => {
    const seen: string[] = [];
    const authFetch = makeAuthFetch((_p, init) => {
      seen.push(init?.method ?? 'GET');
      return { status: 200, bodyJson: { response: {} } };
    });
    await verifyTenableSCCredentials(authFetch);
    expect(seen[0]).toBe('GET');
  });
});

// ---- listTenableSCScans ----

describe('listTenableSCScans', () => {
  function listBody(ids: string[]) {
    return {
      response: {
        usable: ids.map((id) => ({
          id,
          name: `scan-${id}`,
          description: 'test',
          scannedIPs: '10.0.0.1',
          startTime: '1700000000',
          finishTime: '1700001000',
          status: 'Completed',
        })),
      },
    };
  }

  it('returns the usable scans on 200', async () => {
    const authFetch = makeAuthFetch((path) => {
      expect(path).toContain('/rest/scanResult');
      return { status: 200, bodyJson: listBody(['42', '43']) };
    });

    const scans = await listTenableSCScans(authFetch);
    expect(scans).toHaveLength(2);
    expect(scans[0].id).toBe('42');
    expect(scans[0].name).toBe('scan-42');
  });

  it('uses the configured time window', async () => {
    let capturedPath = '';
    const authFetch = makeAuthFetch((path) => {
      capturedPath = path;
      return { status: 200, bodyJson: listBody([]) };
    });
    await listTenableSCScans(authFetch, { startTime: 100, endTime: 200 });
    expect(capturedPath).toContain('startTime=100');
    expect(capturedPath).toContain('endTime=200');
    expect(capturedPath).toContain('fields=');
  });

  it('defaults endTime to "now" when not provided', async () => {
    let capturedPath = '';
    const authFetch = makeAuthFetch((path) => {
      capturedPath = path;
      return { status: 200, bodyJson: listBody([]) };
    });
    await listTenableSCScans(authFetch);
    expect(capturedPath).toMatch(/startTime=0/);
    expect(capturedPath).toMatch(/endTime=\d{8,}/);
  });

  it('returns empty array when response.usable is empty', async () => {
    const authFetch = makeAuthFetch(() => ({ status: 200, bodyJson: listBody([]) }));
    expect(await listTenableSCScans(authFetch)).toEqual([]);
  });

  it('throws on unauthorized', async () => {
    const authFetch = makeAuthFetch(() => ({ status: 401 }));
    await expect(listTenableSCScans(authFetch)).rejects.toThrow(/unauthorized/i);
  });

  it('throws on malformed JSON', async () => {
    const authFetch = makeAuthFetch(() => ({
      status: 200,
      bodyText: 'not json',
      contentType: 'application/json',
    }));
    await expect(listTenableSCScans(authFetch)).rejects.toThrow();
  });

  it('throws with the status code on unexpected non-200 (e.g. 500)', async () => {
    const authFetch = makeAuthFetch(() => ({ status: 500 }));
    await expect(listTenableSCScans(authFetch)).rejects.toThrow(/500/);
  });
});

// ---- fetchTenableSCScanToHdf ----

describe('fetchTenableSCScanToHdf', () => {
  it('downloads raw .nessus XML and pipes through nessus-to-hdf', async () => {
    const xml = loadNessusFixture();
    let methodSeen = '';
    let pathSeen = '';
    const authFetch = makeAuthFetch((path, init) => {
      pathSeen = path;
      methodSeen = init?.method ?? 'GET';
      return { status: 200, bodyText: xml, contentType: 'application/xml' };
    });

    const hdf = await fetchTenableSCScanToHdf(authFetch, '42');
    expect(hdf).toBeTruthy();
    expect(hdf.baselines).toBeDefined();
    expect(hdf.baselines.length).toBeGreaterThan(0);

    expect(pathSeen).toBe('/rest/scanResult/42/download?downloadType=v2');
    expect(methodSeen).toBe('POST');
  });

  it('unzips a single-entry zip response and pipes through nessus-to-hdf', async () => {
    const xml = loadNessusFixture();
    const zipped = zipSync({ 'scan-42.nessus': strToU8(xml) });
    const authFetch = makeAuthFetch(() => ({
      status: 200,
      bodyBytes: zipped,
      contentType: 'application/zip',
    }));

    const hdf = await fetchTenableSCScanToHdf(authFetch, '42');
    expect(hdf).toBeTruthy();
    expect(hdf.baselines.length).toBeGreaterThan(0);
  });

  it('rejects an invalid scan ID before issuing a request', async () => {
    const authFetch = makeAuthFetch(() => {
      throw new Error('should not reach server');
    });
    await expect(fetchTenableSCScanToHdf(authFetch, '../1')).rejects.toThrow(/scan ID/i);
    expect(authFetch).not.toHaveBeenCalled();
  });

  it('rejects an empty scan ID', async () => {
    const authFetch = makeAuthFetch(() => {
      throw new Error('should not reach server');
    });
    await expect(fetchTenableSCScanToHdf(authFetch, '')).rejects.toThrow(/scan ID/i);
    expect(authFetch).not.toHaveBeenCalled();
  });

  it('throws on 401 download', async () => {
    const authFetch = makeAuthFetch(() => ({ status: 401 }));
    await expect(fetchTenableSCScanToHdf(authFetch, '42')).rejects.toThrow(/unauthorized/i);
  });

  it('throws on 403 download with a hint about scan completeness', async () => {
    const authFetch = makeAuthFetch(() => ({ status: 403 }));
    await expect(fetchTenableSCScanToHdf(authFetch, '42')).rejects.toThrow(/403/);
  });

  it('throws on 404 download mentioning the scan ID', async () => {
    const authFetch = makeAuthFetch(() => ({ status: 404 }));
    await expect(fetchTenableSCScanToHdf(authFetch, '42')).rejects.toThrow(/42/);
  });

  it('throws on empty zip', async () => {
    const empty = zipSync({});
    const authFetch = makeAuthFetch(() => ({ status: 200, bodyBytes: empty }));
    await expect(fetchTenableSCScanToHdf(authFetch, '42')).rejects.toThrow(/empty/i);
  });

  it('throws on corrupt zip', async () => {
    const corrupt = new Uint8Array([0x50, 0x4b, 0x03, 0x04, 0x00, 0x00]);
    const authFetch = makeAuthFetch(() => ({ status: 200, bodyBytes: corrupt }));
    await expect(fetchTenableSCScanToHdf(authFetch, '42')).rejects.toThrow();
  });

  it('throws with the status code on unexpected non-200 (e.g. 500)', async () => {
    const authFetch = makeAuthFetch(() => ({ status: 500 }));
    await expect(fetchTenableSCScanToHdf(authFetch, '42')).rejects.toThrow(/500/);
  });
});

// ---- auth-agnostic invariant ----

describe('auth-agnostic invariant', () => {
  it('library NEVER passes credentials via the RequestInit headers it constructs', async () => {
    // The authFetch callable is the ONLY thing that injects credentials.
    // If the library starts setting x-apikey in init.headers itself, that
    // would be a contract violation — the whole point of authFetch is to
    // own that header.
    const allHeaders: Array<HeadersInit | undefined> = [];
    const authFetch = makeAuthFetch((_path, init) => {
      allHeaders.push(init?.headers);
      return { status: 200, bodyJson: { response: { usable: [] } } };
    });

    await verifyTenableSCCredentials(authFetch).catch(() => {});
    await listTenableSCScans(authFetch).catch(() => {});

    for (const h of allHeaders) {
      if (!h) continue;
      const headers = new Headers(h);
      expect(headers.has('x-apikey')).toBe(false);
      expect(headers.has('X-ApiKey')).toBe(false);
      expect(headers.has('Authorization')).toBe(false);
    }
  });
});
