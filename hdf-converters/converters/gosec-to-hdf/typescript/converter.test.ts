import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { describe, it, expect } from 'vitest';
import { convertGosecToHdf } from './converter.js';
import type { HdfResults } from '@mitre/hdf-schema';

const __dirname = dirname(fileURLToPath(import.meta.url));
const FIXTURES_DIR = join(__dirname, '..', 'fixtures');

function loadFixture(name: string): string {
  return readFileSync(join(FIXTURES_DIR, 'input', name), 'utf-8');
}

describe('gosec to HDF converter', () => {
  describe('convertGosecToHdf', () => {
    it('should throw on invalid JSON', () => {
      expect(() => convertGosecToHdf('not json')).toThrow();
    });

    it('should throw on empty input', () => {
      expect(() => convertGosecToHdf('')).toThrow();
    });

    it('should throw when Issues field is missing', () => {
      expect(() => convertGosecToHdf(JSON.stringify({ GosecVersion: '2.18.0' }))).toThrow(
        'missing or invalid Issues field'
      );
    });

    it('should produce valid HDF structure from minimal fixture', () => {
      const output = convertGosecToHdf(loadFixture('minimal.json'));
      const hdf = JSON.parse(output) as HdfResults;

      expect(hdf.timestamp).toBeTruthy();
      expect(hdf.generator?.name).toBe('gosec-to-hdf');
      expect(hdf.generator?.version).toBe('1.0.0');
      expect(hdf.dataSource?.name).toBe('gosec');
      expect(hdf.dataSource?.version).toBe('2.18.0');
      expect(hdf.dataSource?.format).toBeUndefined();
      expect(hdf.baselines).toHaveLength(1);
    });

    it('should use "gosec Scan" as the baseline name', () => {
      const hdf = JSON.parse(convertGosecToHdf(loadFixture('minimal.json'))) as HdfResults;
      expect(hdf.baselines[0]!.name).toBe('gosec Scan');
    });

    it('should include a sha256 checksum', () => {
      const hdf = JSON.parse(convertGosecToHdf(loadFixture('minimal.json'))) as HdfResults;
      const checksum = hdf.baselines[0]!.resultsChecksum;
      expect(checksum?.algorithm).toBe('sha256');
      expect(checksum?.value).toMatch(/^[a-f0-9]{64}$/);
    });

    it('should group issues by rule_id', () => {
      // minimal.json has G304 (2 issues) and G404 (1 issue) → 2 requirements
      const hdf = JSON.parse(convertGosecToHdf(loadFixture('minimal.json'))) as HdfResults;
      const reqs = hdf.baselines[0]!.requirements;

      expect(reqs).toHaveLength(2);
      const ids = reqs.map(r => r.id).sort();
      expect(ids).toEqual(['G304', 'G404']);
    });

    it('should create multiple results for repeated rule_id', () => {
      const hdf = JSON.parse(convertGosecToHdf(loadFixture('minimal.json'))) as HdfResults;
      const g304 = hdf.baselines[0]!.requirements.find(r => r.id === 'G304');
      expect(g304?.results).toHaveLength(2);
    });

    it('should map HIGH severity to 0.7', () => {
      const hdf = JSON.parse(convertGosecToHdf(loadFixture('minimal.json'))) as HdfResults;
      const g404 = hdf.baselines[0]!.requirements.find(r => r.id === 'G404');
      expect(g404?.impact).toBe(0.7);
    });

    it('should map MEDIUM severity to 0.5', () => {
      const hdf = JSON.parse(convertGosecToHdf(loadFixture('minimal.json'))) as HdfResults;
      const g304 = hdf.baselines[0]!.requirements.find(r => r.id === 'G304');
      expect(g304?.impact).toBe(0.5);
    });

    it('should map LOW severity to 0.3', () => {
      const input = JSON.stringify({
        'Golang errors': {},
        Issues: [{
          severity: 'LOW', confidence: 'HIGH',
          cwe: { id: '703', url: 'https://cwe.mitre.org/data/definitions/703.html' },
          rule_id: 'G104', details: 'Errors unhandled',
          file: '/app/main.go', code: 'defer f.Close()\n',
          line: '5', column: '2', nosec: false, suppressions: null,
        }],
        Stats: { files: 1, lines: 10, nosec: 0, found: 1 },
        GosecVersion: '2.18.0',
      });
      const hdf = JSON.parse(convertGosecToHdf(input)) as HdfResults;
      expect(hdf.baselines[0]!.requirements[0]!.impact).toBe(0.3);
    });

    it('should mark non-suppressed issues as failed', () => {
      const hdf = JSON.parse(convertGosecToHdf(loadFixture('minimal.json'))) as HdfResults;
      const g304 = hdf.baselines[0]!.requirements.find(r => r.id === 'G304');
      for (const result of g304!.results) {
        expect(result.status).toBe('failed');
      }
    });

    it('should mark suppressed issues as notReviewed', () => {
      const hdf = JSON.parse(convertGosecToHdf(loadFixture('minimal.json'))) as HdfResults;
      const g404 = hdf.baselines[0]!.requirements.find(r => r.id === 'G404');
      expect(g404?.results[0]?.status).toBe('notReviewed');
    });

    it('should include justification in skip message', () => {
      const hdf = JSON.parse(convertGosecToHdf(loadFixture('minimal.json'))) as HdfResults;
      const g404 = hdf.baselines[0]!.requirements.find(r => r.id === 'G404');
      expect(g404?.results[0]?.message).toContain('Acceptable for non-security context.');
      expect(g404?.results[0]?.message).toContain('inSource');
    });

    it('should include code_desc with rule, file, line, column', () => {
      const hdf = JSON.parse(convertGosecToHdf(loadFixture('minimal.json'))) as HdfResults;
      const g304 = hdf.baselines[0]!.requirements.find(r => r.id === 'G304');
      const codeDesc = g304?.results[0]?.codeDesc ?? '';
      expect(codeDesc).toContain('G304');
      expect(codeDesc).toContain('/app/main.go');
      expect(codeDesc).toContain('42');
    });

    it('should include a default description with rule details text', () => {
      const hdf = JSON.parse(convertGosecToHdf(loadFixture('minimal.json'))) as HdfResults;
      const g304 = hdf.baselines[0]!.requirements.find(r => r.id === 'G304');
      const defaultDesc = g304?.descriptions?.find(d => d.label === 'default');
      expect(defaultDesc?.data).toBe('Potential file inclusion via variable');
    });

    it('should include a check description with CWE reference', () => {
      const hdf = JSON.parse(convertGosecToHdf(loadFixture('minimal.json'))) as HdfResults;
      const g304 = hdf.baselines[0]!.requirements.find(r => r.id === 'G304');
      const checkDesc = g304?.descriptions?.find(d => d.label === 'check');
      expect(checkDesc?.data).toContain('CWE-22');
      expect(checkDesc?.data).toContain('cwe.mitre.org');
    });

    it('should look up NIST tags from CWE (CWE-338 → SC-13)', () => {
      const hdf = JSON.parse(convertGosecToHdf(loadFixture('minimal.json'))) as HdfResults;
      const g404 = hdf.baselines[0]!.requirements.find(r => r.id === 'G404');
      expect(g404?.tags?.['nist']).toContain('SC-13');
    });

    it('should fall back to ["SI-2", "RA-5"] for unknown CWE', () => {
      const input = JSON.stringify({
        'Golang errors': {},
        Issues: [{
          severity: 'MEDIUM', confidence: 'HIGH',
          cwe: { id: '99999', url: '' },
          rule_id: 'G999', details: 'Unknown',
          file: '/app/main.go', code: 'x()\n',
          line: '1', column: '1', nosec: false, suppressions: null,
        }],
        Stats: { files: 1, lines: 5, nosec: 0, found: 1 },
        GosecVersion: '2.18.0',
      });
      const hdf = JSON.parse(convertGosecToHdf(input)) as HdfResults;
      expect(hdf.baselines[0]!.requirements[0]!.tags?.['nist']).toEqual(['SI-2', 'RA-5']);
    });

    it('should include CWE object in tags', () => {
      const hdf = JSON.parse(convertGosecToHdf(loadFixture('minimal.json'))) as HdfResults;
      const g304 = hdf.baselines[0]!.requirements.find(r => r.id === 'G304');
      const cweTag = g304?.tags?.['cwe'] as { id: string; url: string };
      expect(cweTag?.id).toBe('22');
      expect(cweTag?.url).toContain('cwe.mitre.org');
    });

    it('should handle empty Issues array', () => {
      const input = JSON.stringify({
        'Golang errors': {},
        Issues: [],
        Stats: { files: 0, lines: 0, nosec: 0, found: 0 },
        GosecVersion: '2.18.0',
      });
      const hdf = JSON.parse(convertGosecToHdf(input)) as HdfResults;
      expect(hdf.baselines[0]!.requirements).toHaveLength(0);
    });

    it('should handle real fixture without errors', () => {
      const hdf = JSON.parse(convertGosecToHdf(loadFixture('real.json'))) as HdfResults;
      const reqs = hdf.baselines[0]!.requirements;
      expect(reqs.length).toBeGreaterThan(0);
      for (const req of reqs) {
        expect(req.id).toBeTruthy();
        expect(req.results.length).toBeGreaterThan(0);
      }
    });

    it('should handle suppressed fixture correctly', () => {
      const hdf = JSON.parse(convertGosecToHdf(loadFixture('suppressed.json'))) as HdfResults;
      const reqs = hdf.baselines[0]!.requirements;

      // suppressed.json: G301 (external suppression), G104 (nosec=true + nosec=false)
      const g301 = reqs.find(r => r.id === 'G301');
      expect(g301?.results[0]?.status).toBe('notReviewed');
      expect(g301?.results[0]?.message).toContain('Globally suppressed.');

      const g104 = reqs.find(r => r.id === 'G104');
      expect(g104?.results).toHaveLength(2);
    });
  });

  describe('SARIF format routing', () => {
    function loadSarifFixture(name: string): string {
      return readFileSync(join(__dirname, '..', '..', 'sarif-to-hdf', 'fixtures', 'input', name), 'utf-8');
    }

    it('should detect SARIF input and delegate to SARIF converter', () => {
      const input = loadSarifFixture('gosec.sarif');
      const hdf = JSON.parse(convertGosecToHdf(input)) as HdfResults;

      // SARIF converter uses tool driver name as baseline name
      expect(hdf.baselines).toHaveLength(1);
      expect(hdf.baselines[0]!.name).toBe('gosec');
      expect(hdf.baselines[0]!.requirements.length).toBeGreaterThan(0);

      // Verify enriched SARIF data — CWE from relationships
      const g201 = hdf.baselines[0]!.requirements.find(r => r.id === 'G201');
      expect(g201).toBeDefined();
      expect(g201!.tags.cwe).toContain('CWE-89');
    });

    it('should not route native gosec JSON to SARIF converter', () => {
      const hdf = JSON.parse(convertGosecToHdf(loadFixture('minimal.json'))) as HdfResults;

      // Native output uses "gosec Scan" baseline name
      expect(hdf.baselines[0]!.name).toBe('gosec Scan');
    });
  });
});
