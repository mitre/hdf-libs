import {describe, it, expect} from 'vitest';
import {fetchDefectDojoToHdf, verifyDefectDojoCredentials, type AuthFetch} from './fetcher.js';
import type {HDFResults} from '@mitre/hdf-schema';

// A pre-authenticated transport stand-in that serves two findings pages and a
// user_profile endpoint. The auth injection is the caller's concern, so the
// library never sees credentials — the mock represents that boundary.
function makeAuthFetch(calls: string[]): AuthFetch {
  return async (path: string) => {
    calls.push(path);
    if (path.startsWith('/api/v2/user_profile/')) {
      return new Response('{"username":"admin"}', {status: 200});
    }
    if (path.includes('offset=100')) {
      return new Response(
        JSON.stringify({
          next: null,
          results: [{id: 2, title: 'Second', severity: 'Medium', active: true, related_fields: {test: {test_type: {name: 'Trivy Scan'}}}}],
        }),
        {status: 200},
      );
    }
    return new Response(
      JSON.stringify({
        next: 'http://dd.example/api/v2/findings/?limit=100&offset=100',
        results: [{id: 1, title: 'First', severity: 'High', active: true, related_fields: {test: {test_type: {name: 'Trivy Scan'}}}}],
      }),
      {status: 200},
    );
  };
}

describe('defectdojo fetcher (TS)', () => {
  it('paginates and pipes assembled findings through the converter', async () => {
    const calls: string[] = [];
    const hdf = JSON.parse(await fetchDefectDojoToHdf(makeAuthFetch(calls))) as HDFResults;

    // both pages requested (first page + the reduced `next` path)
    expect(calls.some(c => c.includes('related_fields=true'))).toBe(true);
    expect(calls.some(c => c.includes('offset=100'))).toBe(true);

    expect(hdf.baselines).toHaveLength(1);
    expect(hdf.baselines[0].name).toBe('DefectDojo: Trivy Scan');
    expect(hdf.baselines[0].requirements).toHaveLength(2);
  });

  it('verifies credentials with a single request', async () => {
    const calls: string[] = [];
    await expect(verifyDefectDojoCredentials(makeAuthFetch(calls))).resolves.toBeUndefined();
    expect(calls).toEqual(['/api/v2/user_profile/']);
  });

  it('throws on a non-ok response', async () => {
    const authFetch: AuthFetch = async () => new Response('nope', {status: 401});
    await expect(fetchDefectDojoToHdf(authFetch)).rejects.toThrow();
    await expect(verifyDefectDojoCredentials(authFetch)).rejects.toThrow();
  });

  it('refuses a scheme-relative pagination link (SSRF guard)', async () => {
    // A malicious/misconfigured server hands back an off-host next link.
    const authFetch: AuthFetch = async () =>
      new Response(
        JSON.stringify({next: '//evil.example/api/v2/findings/?offset=100', results: []}),
        {status: 200},
      );
    await expect(fetchDefectDojoToHdf(authFetch)).rejects.toThrow(/scheme-relative/);
  });
});
