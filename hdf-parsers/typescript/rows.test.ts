import { describe, it, expect } from 'vitest';
import { flattenToRows } from './rows.js';
import type { HDFResults, EvaluatedBaseline, EvaluatedRequirement, Cvss, Epss, Kev, AffectedPackage } from '@mitre/hdf-schema';

function makeReq(
  id: string,
  overrides: Partial<EvaluatedRequirement> = {}
): EvaluatedRequirement {
  return {
    id,
    impact: 0.5,
    tags: {},
    results: [],
    descriptions: [{ label: 'default', data: `Requirement ${id}` }],
    ...overrides,
  };
}

function makeBaseline(name: string, requirements: EvaluatedRequirement[]): EvaluatedBaseline {
  return { name, requirements };
}

function makeResults(baselines: EvaluatedBaseline[]): HDFResults {
  return { baselines };
}

function withLegacyTag(req: EvaluatedRequirement, key: string, value: unknown): EvaluatedRequirement {
  return { ...req, tags: { ...(req.tags as Record<string, unknown>), [key]: value } };
}

describe('flattenToRows', () => {
  it('returns empty array for empty results', () => {
    expect(flattenToRows({ baselines: [] })).toEqual([]);
  });

  it('emits id and baseline columns for every requirement', () => {
    const results = makeResults([
      makeBaseline('base', [makeReq('V-1')]),
    ]);
    const rows = flattenToRows(results);
    expect(rows).toHaveLength(1);
    expect(rows[0].id).toBe('V-1');
    expect(rows[0].baseline).toBe('base');
  });

  it('populates all CVE-ecosystem columns from structured fields', () => {
    const cvss: Cvss = {
      version: '3.1',
      baseVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
      baseScore: 7.5,
      computedScore: 8.1,
    } as Cvss;
    const epss: Epss = { score: 0.42, percentile: 0.88, date: '2026-05-26' } as Epss;
    const kev: Kev = { inKev: true, dateAdded: '2026-03-15', dueDate: '2026-04-05' } as Kev;
    const affectedPackages: AffectedPackage[] = [
      { name: 'openssl', version: '1.1.1k', ecosystem: 'rpm' } as AffectedPackage,
    ];

    const results = makeResults([
      makeBaseline('base', [
        makeReq('CVE-1', { cvss: [cvss], epss, kev, cwe: ['CWE-79', 'CWE-89'], affectedPackages }),
      ]),
    ]);
    const rows = flattenToRows(results);
    expect(rows).toHaveLength(1);
    const r = rows[0];
    expect(r.cvss_base_score).toBe('7.5');
    expect(r.cvss_computed_score).toBe('8.1');
    expect(r.epss_score).toBe('0.42');
    expect(r.epss_percentile).toBe('0.88');
    expect(r.kev_in_kev).toBe('true');
    expect(r.cwe).toBe('CWE-79;CWE-89');
    expect(r.affected_packages).toBe('openssl@1.1.1k');
  });

  it('falls back to legacy tags.cvss_base_score when no structured cvss[]', () => {
    const req = withLegacyTag(makeReq('CVE-Legacy'), 'cvss_base_score', '6.4');
    const results = makeResults([makeBaseline('base', [req])]);
    const rows = flattenToRows(results);
    expect(rows[0].cvss_base_score).toBe('6.4');
    expect(rows[0].cvss_computed_score).toBeUndefined();
  });

  it('structured cvss[] takes precedence over legacy tag', () => {
    const cvss: Cvss = {
      version: '3.1',
      baseVector: 'CVSS:3.1/AV:N',
      baseScore: 9.8,
    } as Cvss;
    const req = withLegacyTag(makeReq('CVE-Both', { cvss: [cvss] }), 'cvss_base_score', '3.2');
    const results = makeResults([makeBaseline('base', [req])]);
    const rows = flattenToRows(results);
    expect(rows[0].cvss_base_score).toBe('9.8');
  });

  it('uses first cvss[] entry for cvss_base_score when multiple', () => {
    const results = makeResults([
      makeBaseline('base', [
        makeReq('CVE-Multi', {
          cvss: [
            { version: '3.1', baseVector: 'CVSS:3.1/AV:N', baseScore: 7.5 } as Cvss,
            { version: '3.1', baseVector: 'CVSS:3.1/AV:L', baseScore: 3.1 } as Cvss,
          ],
        }),
      ]),
    ]);
    const rows = flattenToRows(results);
    expect(rows[0].cvss_base_score).toBe('7.5');
  });

  it('joins cwe[] with semicolons', () => {
    const results = makeResults([
      makeBaseline('base', [makeReq('CVE-Cwe', { cwe: ['CWE-79', 'CWE-89', 'CWE-352'] })]),
    ]);
    const rows = flattenToRows(results);
    expect(rows[0].cwe).toBe('CWE-79;CWE-89;CWE-352');
  });

  it('joins affectedPackages[] as name@version pairs', () => {
    const results = makeResults([
      makeBaseline('base', [
        makeReq('CVE-Pkg', {
          affectedPackages: [
            { name: 'openssl', version: '1.1.1k', ecosystem: 'rpm' } as AffectedPackage,
            { name: 'libcurl', version: '7.81.0', ecosystem: 'rpm' } as AffectedPackage,
          ],
        }),
      ]),
    ]);
    const rows = flattenToRows(results);
    expect(rows[0].affected_packages).toBe('openssl@1.1.1k;libcurl@7.81.0');
  });

  it('emits name alone when affectedPackage version is empty', () => {
    const results = makeResults([
      makeBaseline('base', [
        makeReq('CVE-NoVer', {
          affectedPackages: [{ name: 'openssl', version: '', ecosystem: 'rpm' } as AffectedPackage],
        }),
      ]),
    ]);
    const rows = flattenToRows(results);
    expect(rows[0].affected_packages).toBe('openssl');
  });

  it('omits CVE columns when no CVE data present', () => {
    const results = makeResults([makeBaseline('base', [makeReq('V-NoCve')])]);
    const rows = flattenToRows(results);
    const r = rows[0];
    for (const key of ['cvss_base_score', 'cvss_computed_score', 'epss_score', 'epss_percentile', 'kev_in_kev', 'cwe', 'affected_packages']) {
      expect(r[key]).toBeUndefined();
    }
  });

  it('emits kev_in_kev=false when KEV present with inKev:false', () => {
    const results = makeResults([
      makeBaseline('base', [makeReq('CVE-NotInKev', { kev: { inKev: false } as Kev })]),
    ]);
    const rows = flattenToRows(results);
    expect(rows[0].kev_in_kev).toBe('false');
  });

  it('flattens multiple requirements across multiple baselines in order', () => {
    const results = makeResults([
      makeBaseline('baseline-A', [
        makeReq('CVE-A1', { cvss: [{ version: '3.1', baseVector: 'CVSS:3.1/AV:N', baseScore: 5.0 } as Cvss] }),
        makeReq('CVE-A2'),
      ]),
      makeBaseline('baseline-B', [
        makeReq('CVE-B1', { cvss: [{ version: '3.1', baseVector: 'CVSS:3.1/AV:N', baseScore: 9.5 } as Cvss] }),
      ]),
    ]);
    const rows = flattenToRows(results);
    expect(rows).toHaveLength(3);
    expect(rows[0]).toMatchObject({ baseline: 'baseline-A', id: 'CVE-A1', cvss_base_score: '5' });
    expect(rows[1]).toMatchObject({ baseline: 'baseline-A', id: 'CVE-A2' });
    expect(rows[2]).toMatchObject({ baseline: 'baseline-B', id: 'CVE-B1', cvss_base_score: '9.5' });
  });

  it('legacy tag value can be numeric', () => {
    const req = withLegacyTag(makeReq('CVE-Num'), 'cvss_base_score', 6.4);
    const rows = flattenToRows(makeResults([makeBaseline('base', [req])]));
    expect(rows[0].cvss_base_score).toBe('6.4');
  });

  it('empty-string legacy tag does not populate column', () => {
    const req = withLegacyTag(makeReq('CVE-Empty'), 'cvss_base_score', '');
    const rows = flattenToRows(makeResults([makeBaseline('base', [req])]));
    expect(rows[0].cvss_base_score).toBeUndefined();
  });

  it('legacy integer tag value coerces to string', () => {
    const req = withLegacyTag(makeReq('CVE-Int'), 'cvss_base_score', 7);
    const rows = flattenToRows(makeResults([makeBaseline('base', [req])]));
    expect(rows[0].cvss_base_score).toBe('7');
  });
});
