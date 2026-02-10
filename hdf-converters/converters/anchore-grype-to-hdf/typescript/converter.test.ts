import {readFileSync} from 'fs';
import {join} from 'path';
import {describe, expect, it} from 'vitest';
import {convertAnchoreGrypeToHdf} from './converter';
import {parseJSON} from '@mitre/hdf-utilities';
import type {HdfResults} from '@mitre/hdf-schema';

const FIXTURES_DIR = join(__dirname, '..', 'fixtures');

function loadFixture(name: string): string {
  return readFileSync(join(FIXTURES_DIR, 'input', name), 'utf-8');
}

describe('Anchore Grype Converter', () => {
  describe('convertAnchoreGrypeToHdf', () => {
    it('should convert minimal Grype report to HDF', () => {
      const input = loadFixture('minimal.json');
      const output = convertAnchoreGrypeToHdf(input);
      const hdf = parseJSON<HdfResults>(output);

      expect(hdf.baselines).toHaveLength(1);
      expect(hdf.generator.name).toBe('grype');
      expect(hdf.generator.version).toBe('0.79.3');
      // Timestamp format may include milliseconds (.000Z) depending on serialization
      expect(hdf.timestamp).toMatch(/^2024-01-15T10:30:00(\.000)?Z$/);
    });

    it('should create baseline with correct name', () => {
      const input = loadFixture('minimal.json');
      const output = convertAnchoreGrypeToHdf(input);
      const hdf = parseJSON<HdfResults>(output);

      expect(hdf.baselines[0].name).toBe('alpine:3.18');
    });

    it('should convert matches to requirements', () => {
      const input = loadFixture('minimal.json');
      const output = convertAnchoreGrypeToHdf(input);
      const hdf = parseJSON<HdfResults>(output);

      const requirements = hdf.baselines[0].requirements;
      expect(requirements).toHaveLength(3); // 2 matches + 1 ignoredMatch

      // Check regular match
      const cve12345 = requirements.find(r => r.id === 'Grype/CVE-2023-12345');
      expect(cve12345).toBeDefined();
      expect(cve12345?.impact).toBe(0.7); // High severity
      expect(cve12345?.results).toHaveLength(1);
      expect(cve12345?.results[0].status).toBe('failed');

      // Check critical vulnerability
      const cve67890 = requirements.find(r => r.id === 'Grype/CVE-2023-67890');
      expect(cve67890).toBeDefined();
      expect(cve67890?.impact).toBe(0.9); // Critical severity
    });

    it('should handle ignored matches correctly', () => {
      const input = loadFixture('minimal.json');
      const output = convertAnchoreGrypeToHdf(input);
      const hdf = parseJSON<HdfResults>(output);

      const requirements = hdf.baselines[0].requirements;
      const ignored = requirements.find(r => r.id === 'Grype-Ignored-Match/CVE-2022-99999');

      expect(ignored).toBeDefined();
      expect(ignored?.results[0].status).toBe('notReviewed');
      expect(ignored?.results[0].message).toContain('ignored by configured rules');
    });

    it('should include NIST and CCI tags', () => {
      const input = loadFixture('minimal.json');
      const output = convertAnchoreGrypeToHdf(input);
      const hdf = parseJSON<HdfResults>(output);

      const req = hdf.baselines[0].requirements[0];
      expect(req.tags?.nist).toEqual(['SA-11', 'RA-5']);
      // CCI tags should be omitted when empty (SA-11 and RA-5 have no CCI mappings)
      expect(req.tags?.cci).toBeUndefined();
    });

    it('should include descriptions for vulnerability, fix, and check', () => {
      const input = loadFixture('minimal.json');
      const output = convertAnchoreGrypeToHdf(input);
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

    it('should include references from vulnerability URLs', () => {
      const input = loadFixture('minimal.json');
      const output = convertAnchoreGrypeToHdf(input);
      const hdf = parseJSON<HdfResults>(output);

      const req = hdf.baselines[0].requirements[0];
      expect(req.refs).toBeDefined();
      expect(req.refs!.length).toBeGreaterThan(0);
      expect(req.refs![0].url).toBeDefined();
    });

    it('should calculate SHA256 checksum of input', () => {
      const input = loadFixture('minimal.json');
      const output = convertAnchoreGrypeToHdf(input);
      const hdf = parseJSON<HdfResults>(output);

      const baseline = hdf.baselines[0];
      expect(baseline.resultsChecksum).toBeDefined();
      expect(baseline.resultsChecksum?.algorithm).toBe('sha256');
      expect(baseline.resultsChecksum?.value).toMatch(/^[a-f0-9]{64}$/);
    });

    it('should handle fix information correctly', () => {
      const input = loadFixture('minimal.json');
      const output = convertAnchoreGrypeToHdf(input);
      const hdf = parseJSON<HdfResults>(output);

      const cve12345 = hdf.baselines[0].requirements.find(r => r.id === 'Grype/CVE-2023-12345');
      const fixDesc = cve12345?.descriptions?.find(d => d.label === 'fix');

      expect(fixDesc?.data).toContain('vulnerability is fixed');
      expect(fixDesc?.data).toContain('3.1.0-r5');
    });

    it('should include code description with package details', () => {
      const input = loadFixture('minimal.json');
      const output = convertAnchoreGrypeToHdf(input);
      const hdf = parseJSON<HdfResults>(output);

      const req = hdf.baselines[0].requirements[0];
      expect(req.results[0].codeDesc).toContain('Package:');
      expect(req.results[0].codeDesc).toContain('Type:');
      expect(req.results[0].codeDesc).toContain('Location:');
    });

    it('should throw error for invalid JSON', () => {
      expect(() => convertAnchoreGrypeToHdf('not valid json')).toThrow();
    });

    it('should throw error for empty input', () => {
      expect(() => convertAnchoreGrypeToHdf('')).toThrow();
    });

    it('should handle missing optional fields gracefully', () => {
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

      const output = convertAnchoreGrypeToHdf(minimalReport);
      const hdf = parseJSON<HdfResults>(output);

      expect(hdf.baselines).toHaveLength(1);
      expect(hdf.baselines[0].requirements).toHaveLength(0);
    });

    it('should default to epoch time for start time', () => {
      const input = loadFixture('minimal.json');
      const output = convertAnchoreGrypeToHdf(input);
      const hdf = parseJSON<HdfResults>(output);

      const req = hdf.baselines[0].requirements[0];
      // StartTime format may include milliseconds (.000Z) depending on serialization
      expect(req.results[0].startTime).toMatch(/^0001-01-01T00:00:00(\.000)?Z$/);
    });
  });
});
