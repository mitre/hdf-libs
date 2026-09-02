import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { describe, it, expect } from 'vitest';
import { convertKicsToHdf, resolveControls } from './converter.js';
import { runConverterContractTests } from '../../../shared/typescript/converter-contract.js';
import { expectValidResults } from '../../../test/helpers/expectValidHdf.js';
import { ResultStatus } from '@mitre/hdf-schema';
import type { HDFResults, EvaluatedRequirement } from '@mitre/hdf-schema';

const __dirname = dirname(fileURLToPath(import.meta.url));
const FIXTURES = join(__dirname, '..', 'fixtures');

const load = (n: string): string => readFileSync(join(FIXTURES, 'input', n), 'utf-8');
const convert = async (n: string): Promise<HDFResults> =>
  JSON.parse(await convertKicsToHdf(load(n))) as HDFResults;

/** Requirements derived from actual findings, excluding the synthetic ones. */
const findings = (h: HDFResults): EvaluatedRequirement[] =>
  h.baselines[0]!.requirements.filter(
    (r) => r.id !== 'kics-scan-coverage' && r.id !== 'kics-no-findings',
  );
runConverterContractTests({
  converterName: 'kics-to-hdf',
  convertFn: convertKicsToHdf,
  minimalFixture: 'minimal.json',
});

describe('kics to HDF converter', () => {
  it('rejects input that is not a KICS report', async () => {
    for (const input of [
      '{"foo":1}',
      '{"queries":[]}',
      '{"kics_version":"v1"}',
      // key present but wrong type: must match Go's typed probe exactly
      '{"kics_version":"v2.1.20","queries":null}',
      '{"kics_version":"v2.1.20","queries":{}}',
      '{"kics_version":5,"queries":[]}',
      '{"kics_version":null,"queries":[]}',
    ]) {
      await expect(convertKicsToHdf(input)).rejects.toThrow('does not look like a KICS report');
    }
  });

  describe('findings fixture', () => {
    it('produces a schema-valid document', async () => {
      const hdf = await convert('findings.json');
      expectValidResults(hdf);
      expect(hdf.baselines[0]!.name).toBe('KICS Scan');
      expect(hdf.tool?.name).toBe('KICS');
      expect(hdf.generator?.name).toBe('kics-to-hdf');
    });

    it('emits one requirement per query, keyed on the stable query id', async () => {
      const hdf = await convert('findings.json');
      const ids = findings(hdf).map((r) => r.id);
      expect(new Set(ids).size).toBe(ids.length);
      // every id is a KICS query UUID
      for (const id of ids) expect(id).toMatch(/^[0-9a-f-]{36}$/);
    });

    it('maps all five KICS severities without collapsing CRITICAL into HIGH', async () => {
      const hdf = await convert('findings.json');
      const impacts = new Set(findings(hdf).map((r) => r.impact));
      // SARIF collapses CRITICAL and HIGH to `error`; the native scale must not
      expect(impacts.size).toBeGreaterThan(1);
    });

    it('maps INFO findings to the canonical 0.0 info-tier impact', async () => {
      // the effective-status layer treats impact-0 requirements as
      // notApplicable, so info-tier findings stay visible without entering
      // the compliance ratio, like every other converter's info tier
      const hdf = await convert('findings.json');
      const infoReqs = findings(hdf).filter((r) => r.tags?.severity === 'INFO');
      expect(infoReqs.length).toBeGreaterThan(0);
      for (const r of infoReqs) expect(r.impact).toBe(0);
    });

    it('carries the remediation pair SARIF drops', async () => {
      const hdf = await convert('findings.json');
      const withExpected = hdf.baselines[0]!.requirements.flatMap((r) => r.results)
        .filter((res) => (res.message ?? '').includes('Expected'));
      expect(withExpected.length).toBeGreaterThan(0);
      expect(withExpected[0]!.message).toContain('Actual');
    });

    it('tags the KICS metadata SARIF flattens or drops', async () => {
      const hdf = await convert('findings.json');
      const r = findings(hdf)[0]!;
      expect(r.tags?.platform).toBeDefined();
      expect(r.tags?.category).toBeDefined();
      expect(r.tags?.cwe).toBeDefined();
      expect(r.tags?.issueType).toBeDefined();
    });

    it('records why a NIST tag is what it is', async () => {
      const hdf = await convert('findings.json');
      for (const r of findings(hdf)) {
        expect(['mapped', 'cwe-derived', 'static-fallback']).toContain(r.tags?.nistMapping);
      }
    });

    it('marks fallback tags as fallback rather than passing them off as a mapping', async () => {
      const hdf = await convert('findings.json');
      for (const r of findings(hdf)) {
        const nist = r.tags?.nist as string[];
        const isFallback = [...nist].sort().join() === ['RA-5', 'SA-11'].join();
        expect(r.tags?.nistMapping).toBe(isFallback ? 'static-fallback' : 'cwe-derived');
      }
    });

    it('keeps the source CWE visible even when it does not resolve', async () => {
      const hdf = await convert('findings.json');
      const unmapped = findings(hdf).filter(
        (r) => r.tags?.nistMapping === 'static-fallback',
      );
      // an unresolved CWE must still be readable, or the gap is invisible
      for (const r of unmapped) expect(r.tags?.cwe).toBeTruthy();
    });

    it('reports every finding as failed', async () => {
      const hdf = await convert('findings.json');
      for (const r of findings(hdf))
        for (const res of r.results) expect(res.status).toBe(ResultStatus.Failed);
    });

    it('locates each finding by file and line', async () => {
      const hdf = await convert('findings.json');
      const res = findings(hdf)[0]!.results[0]!;
      expect(res.codeDesc).toMatch(/\.tf/);
    });
  });

  describe('zero-findings fixture', () => {
    it('produces a no-findings requirement rather than an empty baseline', async () => {
      const hdf = await convert('zero-findings.json');
      expectValidResults(hdf);
      expect(findings(hdf)).toHaveLength(0);
      const placeholder = hdf.baselines[0]!.requirements.find((r) => r.id === 'kics-no-findings');
      expect(placeholder?.impact).toBe(0);
    });
  });
});

describe('sparse and malformed queries', () => {
  const scan = (queries: unknown[], extra: Record<string, unknown> = {}): string =>
    JSON.stringify({ kics_version: 'v2.1.20', files_scanned: 2, queries, ...extra });

  const one = async (queries: unknown[]): Promise<EvaluatedRequirement> =>
    (JSON.parse(await convertKicsToHdf(scan(queries))) as HDFResults).baselines[0]!.requirements[0]!;

  it('converts a query that declares no optional metadata', async () => {
    const r = await one([{ query_id: 'q1', query_name: 'Bare', files: [{ file_name: 'a.tf' }] }]);
    expect(r.tags?.nist).toEqual(['SA-11', 'RA-5']);
    expect(r.tags?.nistMapping).toBe('static-fallback');
    for (const absent of ['platform', 'cloudProvider', 'category', 'riskScore', 'descriptionId', 'experimental', 'severity', 'cwe']) {
      expect(r.tags?.[absent]).toBeUndefined();
    }
    expect(r.impact).toBe(0.5);
    expect(r.results[0]!.codeDesc).toBe('File: a.tf');
    expect(r.results[0]!.message).toBe('');
  });

  it('carries optional metadata when the query declares it', async () => {
    const r = await one([{
      query_id: 'q2', query_name: 'Full', severity: 'CRITICAL', platform: 'Terraform',
      cloud_provider: 'aws', category: 'Encryption', risk_score: 8.6, description_id: 'abc123',
      experimental: true, cwe: '311',
      files: [{ file_name: 'a.tf', line: 3, resource_type: 't', resource_name: 'n', search_key: 'k',
                expected_value: 'should be true', actual_value: 'is null', issue_type: 'MissingAttribute', search_value: 'v' }],
    }]);
    expect(r.impact).toBe(0.9);
    expect(r.tags?.riskScore).toBe('8.6');
    expect(r.tags?.experimental).toBe(true);
    expect(r.tags?.nistMapping).toBe('cwe-derived');
    expect(r.results[0]!.codeDesc).toContain('Resource: n');
    expect(r.results[0]!.message).toContain('Search value: v');
  });

  it('omits the literal "unknown" resource name rather than rendering it', async () => {
    const r = await one([{ query_id: 'q3', files: [{ file_name: 'a.tf', resource_name: 'unknown' }] }]);
    expect(r.results[0]!.codeDesc).not.toContain('Resource: unknown');
  });

  it('ignores a line number of zero', async () => {
    const r = await one([{ query_id: 'q4', files: [{ file_name: 'a.tf', line: 0 }] }]);
    expect(r.results[0]!.codeDesc).toBe('File: a.tf');
  });

  it('normalizes CWE whether bare, prefixed, blank or malformed', async () => {
    for (const [cwe, expected] of [['311', ['CWE-311']], ['CWE-311', ['CWE-311']]] as [string, string[]][]) {
      const r = await one([{ query_id: 'c', cwe, files: [{ file_name: 'a.tf' }] }]);
      expect(r.tags?.cwe).toEqual(expected);
    }
    for (const cwe of ['', '   ', 'not-a-number']) {
      const r = await one([{ query_id: 'c', cwe, files: [{ file_name: 'a.tf' }] }]);
      expect(r.tags?.cwe).toBeUndefined();
      expect(r.tags?.nistMapping).toBe('static-fallback');
    }
  });

  it('falls back to the query name when the id is missing, and vice versa', async () => {
    const named = await one([{ query_name: 'Only Name', files: [{ file_name: 'a.tf' }] }]);
    expect(named.id).toBe('Only Name');
    const ided = await one([{ query_id: 'only-id', files: [{ file_name: 'a.tf' }] }]);
    expect(ided.title).toBe('only-id');
  });

  it('skips queries with no occurrences and falls back to the placeholder', async () => {
    const hdf = JSON.parse(await convertKicsToHdf(scan([{ query_id: 'q', files: [] }]))) as HDFResults;
    const ids = hdf.baselines[0]!.requirements.map((r) => r.id);
    expect(ids).toContain('kics-no-findings');
    expect(ids).not.toContain('q');
  });

  it('treats an unrecognized severity as moderate rather than zero', async () => {
    const r = await one([{ query_id: 'q', severity: 'NOVEL', files: [{ file_name: 'a.tf' }] }]);
    expect(r.impact).toBe(0.5);
    // an unrecognized token is a rating we don't know, not an absent rating
    expect(r.tags?.severity_rating).toBeUndefined();
  });

  it('marks an absent severity with the shared unrated marker', async () => {
    const r = await one([{ query_id: 'q', files: [{ file_name: 'a.tf' }] }]);
    expect(r.impact).toBe(0.5);
    expect(r.tags?.severity_rating).toBe('unrated');
    const rated = await one([{ query_id: 'q', severity: 'HIGH', files: [{ file_name: 'a.tf' }] }]);
    expect(rated.tags?.severity_rating).toBeUndefined();
  });

  it('survives prototype-named query_id and severity, matching Go', async () => {
    // Object.prototype member names must behave like any other unknown token:
    // "constructor" as query_id falls through to the CWE/static tiers instead
    // of crashing, and as severity takes the moderate default as a number.
    const r = await one([{ query_id: 'constructor', severity: 'constructor', files: [{ file_name: 'a.tf' }] }]);
    expect(r.id).toBe('constructor');
    expect(r.tags?.nistMapping).toBe('static-fallback');
    expect(r.impact).toBe(0.5);
  });

  it('falls through empty-string identity fields exactly like Go', async () => {
    const named = await one([{ query_id: '', query_name: 'Some Check', files: [{ file_name: 'a.tf' }] }]);
    expect(named.id).toBe('Some Check');
    const bare = await one([{ query_id: '', query_name: '', files: [{ file_name: '' }] }]);
    expect(bare.id).toBe('unknown');
    expect(bare.title).toBe('Unnamed KICS query');
    expect(bare.results[0]!.codeDesc).toBe('File: unknown');
  });

  it('omits the riskScore tag when risk_score is JSON null', async () => {
    const r = await one([{ query_id: 'q', risk_score: null, files: [{ file_name: 'a.tf' }] }]);
    expect(r.tags?.riskScore).toBeUndefined();
    const big = await one([{ query_id: 'q', risk_score: 1000000, files: [{ file_name: 'a.tf' }] }]);
    expect(big.tags?.riskScore).toBe('1000000');
  });

  it('carries the similarity id KICS computes per occurrence', async () => {
    const r = await one([{ query_id: 'q', files: [{ file_name: 'a.tf', similarity_id: '4efca9c9' }] }]);
    expect(r.results[0]!.codeDesc).toContain('Similarity ID: 4efca9c9');
    const bare = await one([{ query_id: 'q', files: [{ file_name: 'a.tf' }] }]);
    expect(bare.results[0]!.codeDesc).not.toContain('Similarity ID');
  });

  it('carries the query documentation url as a tag', async () => {
    const r = await one([{ query_id: 'q', query_url: 'https://example.com/docs', files: [{ file_name: 'a.tf' }] }]);
    expect(r.tags?.queryUrl).toBe('https://example.com/docs');
    const bare = await one([{ query_id: 'q', files: [{ file_name: 'a.tf' }] }]);
    expect(bare.tags?.queryUrl).toBeUndefined();
  });
});

describe('control resolution precedence', () => {
  // The shipped table is intentionally empty until adjudication completes, so
  // the table tier is exercised with a stub rather than by shipping unreviewed
  // rows.
  const stub = { 'query-in-table': { cci: ['CCI-000366'], nist: ['CM-6 b'] } };

  it('prefers the reviewed per-query table over the CWE', () => {
    const r = resolveControls({ query_id: 'query-in-table', cwe: '311' }, stub);
    expect(r.nist).toEqual(['CM-6 b']);
    expect(r.cci).toEqual(['CCI-000366']);
    expect(r.source).toBe('mapped');
  });

  it('falls back to the CWE when the query is not in the table', () => {
    const r = resolveControls({ query_id: 'absent', cwe: '311' }, stub);
    expect(r.source).toBe('cwe-derived');
    expect(r.nist.length).toBeGreaterThan(0);
  });

  it('falls back to the defaults when the CWE does not resolve', () => {
    // CWE-778 is one of the 72 KICS uses that the CWE table lacks
    const r = resolveControls({ query_id: 'absent', cwe: '778' }, stub);
    expect(r.source).toBe('static-fallback');
    expect(r.cci.length).toBeGreaterThan(0);
  });

  it('falls back to the defaults when the query carries no CWE', () => {
    expect(resolveControls({ query_id: 'absent' }, stub).source).toBe('static-fallback');
  });

  it('ignores a table entry with no controls', () => {
    const r = resolveControls({ query_id: 'e', cwe: '311' }, { e: { cci: [], nist: [] } });
    expect(r.source).toBe('cwe-derived');
  });
});

describe('scan coverage requirement', () => {
  it('records the denominator KICS otherwise reports only in counters', async () => {
    const hdf = JSON.parse(await convertKicsToHdf(load('findings.json'))) as HDFResults;
    const cov = hdf.baselines[0]!.requirements.find((r) => r.id === 'kics-scan-coverage');
    expect(cov).toBeDefined();
    expect(cov!.tags?.queriesExecuted).toBeGreaterThan(cov!.tags?.queriesWithFindings as number);
    expect(cov!.tags?.filesScanned).toBeGreaterThan(0);
  });

  it('stays out of the compliance score', async () => {
    const hdf = JSON.parse(await convertKicsToHdf(load('findings.json'))) as HDFResults;
    const cov = hdf.baselines[0]!.requirements.find((r) => r.id === 'kics-scan-coverage')!;
    expect(cov.impact).toBe(0);
    // notApplicable matches what the effective-status layer derives for an
    // impact-0 requirement, and it is the one status the compliance rollup
    // excludes. Passed would export to CKL as NotAFinding and count as a free
    // pass in raw status rollups.
    expect(cov.results[0]!.status).toBe(ResultStatus.NotApplicable);
  });

  it('says plainly that no passing requirements can be derived', async () => {
    const hdf = JSON.parse(await convertKicsToHdf(load('findings.json'))) as HDFResults;
    const cov = hdf.baselines[0]!.requirements.find((r) => r.id === 'kics-scan-coverage')!;
    expect(cov.descriptions?.[0]?.data).toContain('violations only');
    expect(cov.descriptions?.[0]?.data).toContain('should not be read as a pass rate');
  });

  it('is present even on a scan with no findings', async () => {
    const hdf = JSON.parse(await convertKicsToHdf(load('zero-findings.json'))) as HDFResults;
    expect(hdf.baselines[0]!.requirements.some((r) => r.id === 'kics-scan-coverage')).toBe(true);
  });
});
