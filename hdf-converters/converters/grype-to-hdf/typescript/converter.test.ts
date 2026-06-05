import {readFileSync} from 'fs';
import {join} from 'path';
import {describe, expect, it} from 'vitest';
import {convertGrypeToHdf} from './converter';
import {runConverterContractTests} from '../../../shared/typescript/converter-contract.js';
import {parseJSON} from '@mitre/hdf-utilities';
import type {HDFResults} from '@mitre/hdf-schema';

const FIXTURES_DIR = join(__dirname, '..', 'fixtures');

function loadFixture(name: string): string {
  return readFileSync(join(FIXTURES_DIR, 'input', name), 'utf-8');
}

runConverterContractTests({
  converterName: 'grype-to-hdf',
  convertFn: convertGrypeToHdf,
  minimalFixture: 'amazon.json',
});

describe('Grype Converter', async () => {
  describe('convertGrypeToHdf', async () => {
    it('should convert real Grype report to HDF', async () => {
      const input = loadFixture('amazon.json');
      const output = await convertGrypeToHdf(input);
      const hdf = parseJSON<HDFResults>(output);

      expect(hdf.baselines).toHaveLength(1);
      expect(hdf.generator.name).toBe('grype');
      expect(hdf.generator.version).toBe('0.79.3');
      expect(hdf.tool?.name).toBe('Grype');
      expect(hdf.tool?.version).toBe('0.79.3');
      expect(hdf.tool?.format).toBeUndefined();
      // Timestamp from real Grype output: "2024-08-29T13:47:41.623667-04:00"
      expect(hdf.timestamp).toBeDefined();
    });

    it('should create baseline with correct name from scan target', async () => {
      const input = loadFixture('amazon.json');
      const output = await convertGrypeToHdf(input);
      const hdf = parseJSON<HDFResults>(output);

      expect(hdf.baselines[0].name).toBe('cloudwatch_to_s3:latest');
    });

    it('should convert matches to requirements', async () => {
      const input = loadFixture('amazon.json');
      const output = await convertGrypeToHdf(input);
      const hdf = parseJSON<HDFResults>(output);

      const requirements = hdf.baselines[0].requirements;
      expect(requirements).toHaveLength(16); // 16 real vulnerability matches

      // Check Low severity match: ALAS-2024-2607 (ca-certificates)
      const alas2607 = requirements.find(r => r.id === 'Grype/ALAS-2024-2607');
      expect(alas2607).toBeDefined();
      expect(alas2607?.impact).toBe(0.3); // Low severity
      expect(alas2607?.results).toHaveLength(1);
      expect(alas2607?.results[0].status).toBe('failed');

      // Check High severity match: CVE-2024-7592 (python binary)
      const cve7592 = requirements.find(r => r.id === 'Grype/CVE-2024-7592');
      expect(cve7592).toBeDefined();
      expect(cve7592?.impact).toBe(0.7); // High severity
    });

    it('should handle ignored matches correctly', async () => {
      // Use inline fixture since the real amazon.json scan has no ignored matches
      const ignoredReport = JSON.stringify({
        descriptor: {name: 'grype', version: '0.79.3'},
        source: {target: {userInput: 'test-image'}},
        matches: [],
        ignoredMatches: [{
          vulnerability: {
            id: 'CVE-2024-0001',
            severity: 'Low',
            urls: ['https://nvd.nist.gov/vuln/detail/CVE-2024-0001'],
            description: 'Test ignored vulnerability',
          },
          matchDetails: [{type: 'exact-direct-match', matcher: 'rpm-matcher'}],
          artifact: {name: 'test-pkg', version: '1.0.0', type: 'rpm'},
        }],
      });

      const output = await convertGrypeToHdf(ignoredReport);
      const hdf = parseJSON<HDFResults>(output);

      const requirements = hdf.baselines[0].requirements;
      const ignored = requirements.find(r => r.id === 'Grype-Ignored-Match/CVE-2024-0001');

      expect(ignored).toBeDefined();
      expect(ignored?.results[0].status).toBe('notReviewed');
      expect(ignored?.results[0].message).toContain('ignored by configured rules');
    });

    it('should include NIST and CCI tags', async () => {
      const input = loadFixture('amazon.json');
      const output = await convertGrypeToHdf(input);
      const hdf = parseJSON<HDFResults>(output);

      const req = hdf.baselines[0].requirements[0];
      expect(req.tags?.nist).toEqual(['SA-11', 'RA-5']);
      // CCI tags from curated NIST→CCI mapping: SA-11→CCI-003173, RA-5→CCI-001643
      expect(req.tags?.cci).toEqual(['CCI-001643', 'CCI-003173']);
    });

    it('should include descriptions for vulnerability, fix, and check', async () => {
      const input = loadFixture('amazon.json');
      const output = await convertGrypeToHdf(input);
      const hdf = parseJSON<HDFResults>(output);

      const req = hdf.baselines[0].requirements[0];
      expect(req.descriptions).toBeDefined();
      expect(req.descriptions?.length).toBeGreaterThanOrEqual(3);

      const defaultDesc = req.descriptions?.find(d => d.label === 'default');
      const fixDesc = req.descriptions?.find(d => d.label === 'fix');
      const checkDesc = req.descriptions?.find(d => d.label === 'check');

      expect(defaultDesc).toBeDefined();
      expect(fixDesc).toBeDefined();
      expect(checkDesc).toBeDefined();
    });

    it('should include references from vulnerability URLs', async () => {
      const input = loadFixture('amazon.json');
      const output = await convertGrypeToHdf(input);
      const hdf = parseJSON<HDFResults>(output);

      // First match (ALAS-2024-2607) has URLs including the ALAS advisory URL
      const req = hdf.baselines[0].requirements[0];
      expect(req.refs).toBeDefined();
      expect(req.refs!.length).toBeGreaterThan(0);
      expect(req.refs![0].url).toBeDefined();
    });

    it('should calculate SHA256 checksum of input', async () => {
      const input = loadFixture('amazon.json');
      const output = await convertGrypeToHdf(input);
      const hdf = parseJSON<HDFResults>(output);

      const baseline = hdf.baselines[0];
      expect(baseline.resultsChecksum).toBeDefined();
      expect(baseline.resultsChecksum?.algorithm).toBe('sha256');
      expect(baseline.resultsChecksum?.value).toMatch(/^[a-f0-9]{64}$/);
    });

    it('should handle fix information correctly', async () => {
      const input = loadFixture('amazon.json');
      const output = await convertGrypeToHdf(input);
      const hdf = parseJSON<HDFResults>(output);

      // ALAS-2024-2607 has fix state "fixed" with version "2023.2.68-1.amzn2.0.1"
      const alas2607 = hdf.baselines[0].requirements.find(r => r.id === 'Grype/ALAS-2024-2607');
      const fixDesc = alas2607?.descriptions?.find(d => d.label === 'fix');

      expect(fixDesc?.data).toContain('vulnerability is fixed');
      expect(fixDesc?.data).toContain('2023.2.68-1.amzn2.0.1');
    });

    it('should include code description with package details', async () => {
      const input = loadFixture('amazon.json');
      const output = await convertGrypeToHdf(input);
      const hdf = parseJSON<HDFResults>(output);

      // First match is ca-certificates rpm package
      const req = hdf.baselines[0].requirements[0];
      expect(req.results[0].codeDesc).toContain('Package:');
      expect(req.results[0].codeDesc).toContain('Type:');
      expect(req.results[0].codeDesc).toContain('Location:');
    });

    it('should handle missing optional fields gracefully', async () => {
      const minimalReport = JSON.stringify({
        descriptor: {
          name: 'grype',
          version: '1.0.0'
        },
        source: {
          target: {
            userInput: 'test-image'
          }
        },
        matches: []
      });

      const output = await convertGrypeToHdf(minimalReport);
      const hdf = parseJSON<HDFResults>(output);

      expect(hdf.baselines).toHaveLength(1);
      const reqs = hdf.baselines[0].requirements;
      expect(reqs).toHaveLength(1);
      expect(reqs[0].id).toBe('grype-no-findings');
      expect(reqs[0].results[0].status).toBe('passed');
      expect(reqs[0].results[0].codeDesc).toContain('Grype');
      expect(reqs[0].results[0].codeDesc).toContain('test-image');
    });

    it('synthesizes a passed placeholder for empty fixture', async () => {
      const input = loadFixture('empty.json');
      const output = await convertGrypeToHdf(input);
      const hdf = parseJSON<HDFResults>(output);

      expect(hdf.baselines).toHaveLength(1);
      const reqs = hdf.baselines[0].requirements;
      expect(reqs).toHaveLength(1);
      expect(reqs[0].id).toBe('grype-no-findings');
      expect(reqs[0].results[0].status).toBe('passed');
      expect(reqs[0].results[0].codeDesc).toContain('Grype');
      expect(reqs[0].results[0].codeDesc).toContain('alpine:3.20');
    });

    it('should populate CVE-ecosystem fields from enriched Grype output', async () => {
      // Inline fixture: the static sample fixtures predate Grype's EPSS/KEV
      // enrichment, so they never exercise buildEpss/buildKev/extractCwe. This
      // input follows the anchore/grype JSON output shape (vulnerability.epss[],
      // vulnerability.kev, vulnerability.cwe[]) for a real CVE (Log4Shell).
      const enriched = JSON.stringify({
        descriptor: {name: 'grype', version: '0.85.0'},
        source: {target: {userInput: 'enriched-image'}},
        matches: [{
          vulnerability: {
            id: 'CVE-2021-44228',
            severity: 'Critical',
            urls: ['https://nvd.nist.gov/vuln/detail/CVE-2021-44228'],
            description: 'Log4Shell remote code execution',
            cvss: [{
              source: 'nvd@nist.gov',
              type: 'Primary',
              version: '3.1',
              vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',
              metrics: {baseScore: 10.0},
            }],
            cwe: ['CWE-502', 'not-a-cwe', 'CWE-917'],
            epss: [{cve: 'CVE-2021-44228', epss: 0.97, percentile: 0.999, date: '2026-05-26'}],
            kev: {inKev: true, dateAdded: '2021-12-10', dueDate: '2021-12-24', notes: 'Apply vendor updates'},
            fix: {state: 'fixed', versions: ['2.17.0']},
          },
          matchDetails: [{type: 'exact-direct-match', matcher: 'java-matcher'}],
          artifact: {
            name: 'log4j-core',
            version: '2.14.1',
            type: 'java-archive',
            purl: 'pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1',
            cpes: ['cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*'],
          },
        }],
      });

      const output = await convertGrypeToHdf(enriched);
      const hdf = parseJSON<HdfResults>(output);
      const req = hdf.baselines[0].requirements.find(r => r.id === 'Grype/CVE-2021-44228');
      expect(req).toBeDefined();

      // cwe[] — malformed entry dropped, valid IDs kept.
      expect(req?.cwe).toEqual(['CWE-502', 'CWE-917']);
      // epss
      expect(req?.epss?.score).toBe(0.97);
      expect(req?.epss?.percentile).toBe(0.999);
      expect(req?.epss?.date).toBe('2026-05-26');
      // kev
      expect(req?.kev?.inKev).toBe(true);
      expect(req?.kev?.dateAdded).toBe('2021-12-10');
      expect(req?.kev?.dueDate).toBe('2021-12-24');
      expect(req?.kev?.notes).toBe('Apply vendor updates');
      // cvss[]
      expect(req?.cvss?.[0].baseScore).toBe(10.0);
      // affectedPackages[] — purl, cpe, and fixedInVersion all populated.
      const pkg = req?.affectedPackages?.[0];
      expect(pkg?.name).toBe('log4j-core');
      expect(pkg?.purl).toContain('pkg:maven');
      expect(pkg?.cpe).toContain('cpe:2.3:a:apache:log4j');
      expect(pkg?.fixedInVersion).toBe('2.17.0');
    });

    it('should omit epss when the entry has no date', async () => {
      // buildEpss returns undefined when the newest entry lacks a publish date.
      const noDate = JSON.stringify({
        descriptor: {name: 'grype', version: '0.85.0'},
        source: {target: {userInput: 'img'}},
        matches: [{
          vulnerability: {
            id: 'CVE-2024-9999',
            severity: 'Medium',
            epss: [{cve: 'CVE-2024-9999', epss: 0.1, percentile: 0.5}],
          },
          matchDetails: [{type: 'exact-direct-match', matcher: 'rpm-matcher'}],
          artifact: {name: 'pkg', version: '1.0.0', type: 'rpm'},
        }],
      });
      const output = await convertGrypeToHdf(noDate);
      const hdf = parseJSON<HdfResults>(output);
      const req = hdf.baselines[0].requirements.find(r => r.id === 'Grype/CVE-2024-9999');
      expect(req?.epss).toBeUndefined();
    });

    it('should emit cvss entries with only the present base fields', async () => {
      // First cvss entry: score but no vector -> baseVector omitted (an empty
      // vector would fail the schema pattern). Second: vector but no score ->
      // baseScore omitted (not coerced to 0).
      const report = JSON.stringify({
        descriptor: {name: 'grype', version: '0.85.0'},
        source: {target: {userInput: 'img'}},
        matches: [{
          vulnerability: {
            id: 'CVE-2024-2222',
            severity: 'High',
            cvss: [
              {version: '3.1', metrics: {baseScore: 7.5}},
              {version: '3.1', vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N'},
            ],
          },
          matchDetails: [{type: 'exact-direct-match', matcher: 'rpm-matcher'}],
          artifact: {name: 'pkg', version: '1.0.0', type: 'rpm'},
        }],
      });
      const output = await convertGrypeToHdf(report);
      const hdf = parseJSON<HdfResults>(output);
      const req = hdf.baselines[0].requirements.find(r => r.id === 'Grype/CVE-2024-2222');
      expect(req?.cvss).toHaveLength(2);
      expect(req?.cvss?.[0].baseScore).toBe(7.5);
      expect(req?.cvss?.[0].baseVector).toBeUndefined();
      expect(req?.cvss?.[1].baseVector).toContain('AV:N');
      expect(req?.cvss?.[1].baseScore).toBeUndefined();
    });

    it('should handle sparse CVE-ecosystem fields', async () => {
      // kev with only inKev set, all-malformed cwe[] (dropped -> undefined), and
      // an epss entry missing score/percentile (coalesced to 0). Exercises the
      // negative branches of buildKev/extractCwe/buildEpss.
      const sparse = JSON.stringify({
        descriptor: {name: 'grype', version: '0.85.0'},
        source: {target: {userInput: 'img'}},
        matches: [{
          vulnerability: {
            id: 'CVE-2024-1111',
            severity: 'Low',
            cwe: ['not-a-cwe', 'GHSA-xxxx'],
            epss: [{cve: 'CVE-2024-1111', date: '2026-05-26'}],
            kev: {inKev: false},
          },
          matchDetails: [{type: 'exact-direct-match', matcher: 'rpm-matcher'}],
          artifact: {name: 'pkg', version: '1.0.0', type: 'rpm'},
        }],
      });
      const output = await convertGrypeToHdf(sparse);
      const hdf = parseJSON<HdfResults>(output);
      const req = hdf.baselines[0].requirements.find(r => r.id === 'Grype/CVE-2024-1111');
      expect(req).toBeDefined();
      // all-malformed cwe -> field omitted
      expect(req?.cwe).toBeUndefined();
      // epss present (has date) but score/percentile defaulted to 0
      expect(req?.epss?.score).toBe(0);
      expect(req?.epss?.percentile).toBe(0);
      // kev present with only inKev
      expect(req?.kev?.inKev).toBe(false);
      expect(req?.kev?.dateAdded).toBeUndefined();
    });

    it('should default to epoch time for start time', async () => {
      const input = loadFixture('amazon.json');
      const output = await convertGrypeToHdf(input);
      const hdf = parseJSON<HDFResults>(output);

      const req = hdf.baselines[0].requirements[0];
      // StartTime format may include milliseconds (.000Z) depending on serialization
      expect(req.results[0].startTime).toMatch(/^0001-01-01T00:00:00(\.000)?Z$/);
    });
  });
});
