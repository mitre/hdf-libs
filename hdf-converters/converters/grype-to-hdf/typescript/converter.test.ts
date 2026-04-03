import {readFileSync} from 'fs';
import {join} from 'path';
import {describe, expect, it} from 'vitest';
import {convertGrypeToHdf} from './converter';
import {runConverterContractTests} from '../../../shared/typescript/converter-contract.js';
import {parseJSON} from '@mitre/hdf-utilities';
import type {HdfResults} from '@mitre/hdf-schema';

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
      const hdf = parseJSON<HdfResults>(output);

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
      const hdf = parseJSON<HdfResults>(output);

      expect(hdf.baselines[0].name).toBe('cloudwatch_to_s3:latest');
    });

    it('should convert matches to requirements', async () => {
      const input = loadFixture('amazon.json');
      const output = await convertGrypeToHdf(input);
      const hdf = parseJSON<HdfResults>(output);

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
      const hdf = parseJSON<HdfResults>(output);

      const requirements = hdf.baselines[0].requirements;
      const ignored = requirements.find(r => r.id === 'Grype-Ignored-Match/CVE-2024-0001');

      expect(ignored).toBeDefined();
      expect(ignored?.results[0].status).toBe('notReviewed');
      expect(ignored?.results[0].message).toContain('ignored by configured rules');
    });

    it('should include NIST and CCI tags', async () => {
      const input = loadFixture('amazon.json');
      const output = await convertGrypeToHdf(input);
      const hdf = parseJSON<HdfResults>(output);

      const req = hdf.baselines[0].requirements[0];
      expect(req.tags?.nist).toEqual(['SA-11', 'RA-5']);
      // CCI tags from curated NIST→CCI mapping: SA-11→CCI-003173, RA-5→CCI-001643
      expect(req.tags?.cci).toEqual(['CCI-001643', 'CCI-003173']);
    });

    it('should include descriptions for vulnerability, fix, and check', async () => {
      const input = loadFixture('amazon.json');
      const output = await convertGrypeToHdf(input);
      const hdf = parseJSON<HdfResults>(output);

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
      const hdf = parseJSON<HdfResults>(output);

      // First match (ALAS-2024-2607) has URLs including the ALAS advisory URL
      const req = hdf.baselines[0].requirements[0];
      expect(req.refs).toBeDefined();
      expect(req.refs!.length).toBeGreaterThan(0);
      expect(req.refs![0].url).toBeDefined();
    });

    it('should calculate SHA256 checksum of input', async () => {
      const input = loadFixture('amazon.json');
      const output = await convertGrypeToHdf(input);
      const hdf = parseJSON<HdfResults>(output);

      const baseline = hdf.baselines[0];
      expect(baseline.resultsChecksum).toBeDefined();
      expect(baseline.resultsChecksum?.algorithm).toBe('sha256');
      expect(baseline.resultsChecksum?.value).toMatch(/^[a-f0-9]{64}$/);
    });

    it('should handle fix information correctly', async () => {
      const input = loadFixture('amazon.json');
      const output = await convertGrypeToHdf(input);
      const hdf = parseJSON<HdfResults>(output);

      // ALAS-2024-2607 has fix state "fixed" with version "2023.2.68-1.amzn2.0.1"
      const alas2607 = hdf.baselines[0].requirements.find(r => r.id === 'Grype/ALAS-2024-2607');
      const fixDesc = alas2607?.descriptions?.find(d => d.label === 'fix');

      expect(fixDesc?.data).toContain('vulnerability is fixed');
      expect(fixDesc?.data).toContain('2023.2.68-1.amzn2.0.1');
    });

    it('should include code description with package details', async () => {
      const input = loadFixture('amazon.json');
      const output = await convertGrypeToHdf(input);
      const hdf = parseJSON<HdfResults>(output);

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
      const hdf = parseJSON<HdfResults>(output);

      expect(hdf.baselines).toHaveLength(1);
      expect(hdf.baselines[0].requirements).toHaveLength(0);
    });

    it('should default to epoch time for start time', async () => {
      const input = loadFixture('amazon.json');
      const output = await convertGrypeToHdf(input);
      const hdf = parseJSON<HdfResults>(output);

      const req = hdf.baselines[0].requirements[0];
      // StartTime format may include milliseconds (.000Z) depending on serialization
      expect(req.results[0].startTime).toMatch(/^0001-01-01T00:00:00(\.000)?Z$/);
    });
  });
});
