import { describe, it, expect } from 'vitest';
import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { convertHdfToCsv } from './converter.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const fixturesDir = join(__dirname, '..', 'fixtures');

function loadFixture(type: 'input' | 'expected', filename: string): string {
  return readFileSync(join(fixturesDir, type, filename), 'utf-8');
}

describe('hdfcsv Converter', () => {
  describe('Basic conversion', () => {
    it('should convert minimal HDF to CSV', () => {
      const input = loadFixture('input', 'minimal.json');
      const expected = loadFixture('expected', 'minimal.csv');

      const result = convertHdfToCsv(input);

      expect(result).toBe(expected);
    });

    it('should handle empty baselines array', () => {
      const input = JSON.stringify({
        baselines: [],
        targets: [],
        statistics: { duration: 0 }
      });

      const result = convertHdfToCsv(input);

      // When there are no rows, buildCsv returns empty string
      expect(result).toBe('');
    });

    it('should handle baselines with no requirements', () => {
      const input = JSON.stringify({
        baselines: [{
          name: 'Empty Baseline',
          version: '1.0.0',
          title: 'Test',
          maintainer: 'Test',
          supports: [],
          attributes: [],
          groups: [],
          checksum: { algorithm: 'sha256', value: 'abc' },
          requirements: []
        }],
        targets: [],
        statistics: { duration: 0 }
      });

      const result = convertHdfToCsv(input);

      // When there are no rows, buildCsv returns empty string
      expect(result).toBe('');
    });
  });

  describe('Multiple baselines and targets', () => {
    it('should handle multiple baselines', () => {
      const input = JSON.stringify({
        baselines: [
          {
            name: 'Baseline 1',
            version: '1.0.0',
            title: 'First Baseline',
            maintainer: 'Test',
            supports: [],
            attributes: [],
            groups: [],
            checksum: { algorithm: 'sha256', value: 'abc' },
            requirements: [{
              id: 'REQ-001',
              title: 'Test Requirement',
              descriptions: [{ label: 'default', data: 'Test description' }],
              impact: 0.5,
              tags: { severity: 'medium' },
              sourceLocation: { ref: 'REQ-001', line: 1 },
              results: [{ status: 'passed', codeDesc: 'Test', startTime: '2026-01-29T18:00:00.000Z' }]
            }]
          },
          {
            name: 'Baseline 2',
            version: '2.0.0',
            title: 'Second Baseline',
            maintainer: 'Test',
            supports: [],
            attributes: [],
            groups: [],
            checksum: { algorithm: 'sha256', value: 'def' },
            requirements: [{
              id: 'REQ-002',
              title: 'Another Requirement',
              descriptions: [{ label: 'default', data: 'Another description' }],
              impact: 0.7,
              tags: { severity: 'high' },
              sourceLocation: { ref: 'REQ-002', line: 1 },
              results: [{ status: 'failed', codeDesc: 'Test', startTime: '2026-01-29T18:00:00.000Z' }]
            }]
          }
        ],
        targets: [],
        statistics: { duration: 0 }
      });

      const result = convertHdfToCsv(input);
      const lines = result.split('\n').filter(l => l.trim());

      // Header + 2 requirement rows
      expect(lines.length).toBe(3);
      expect(result).toContain('Baseline 1');
      expect(result).toContain('Baseline 2');
    });

    it('should handle multiple targets', () => {
      const input = JSON.stringify({
        baselines: [{
          name: 'Test Baseline',
          version: '1.0.0',
          title: 'Test',
          maintainer: 'Test',
          supports: [],
          attributes: [],
          groups: [],
          checksum: { algorithm: 'sha256', value: 'abc' },
          requirements: [{
            id: 'REQ-001',
            title: 'Test Requirement',
            descriptions: [{ label: 'default', data: 'Test description' }],
            impact: 0.5,
            tags: { severity: 'medium' },
            sourceLocation: { ref: 'REQ-001', line: 1 },
            results: [{ status: 'passed', codeDesc: 'Test', startTime: '2026-01-29T18:00:00.000Z' }]
          }]
        }],
        targets: [
          { name: 'target1', type: 'host' },
          { name: 'target2', type: 'container' }
        ],
        statistics: { duration: 0 }
      });

      const result = convertHdfToCsv(input);

      // Each target should appear in output
      expect(result).toContain('target1,host');
      expect(result).toContain('target2,container');
    });
  });

  describe('Field extraction', () => {
    it('should extract NIST controls from tags', () => {
      const input = JSON.stringify({
        baselines: [{
          name: 'Test',
          version: '1.0.0',
          title: 'Test',
          maintainer: 'Test',
          supports: [],
          attributes: [],
          groups: [],
          checksum: { algorithm: 'sha256', value: 'abc' },
          requirements: [{
            id: 'REQ-001',
            title: 'Test',
            descriptions: [{ label: 'default', data: 'Test' }],
            impact: 0.5,
            tags: {
              nist: ['AC-2', 'AC-3', 'IA-5 (1)'],
              severity: 'medium'
            },
            sourceLocation: { ref: 'REQ-001', line: 1 },
            results: [{ status: 'passed', codeDesc: 'Test', startTime: '2026-01-29T18:00:00.000Z' }]
          }]
        }],
        targets: [],
        statistics: { duration: 0 }
      });

      const result = convertHdfToCsv(input);

      expect(result).toContain('AC-2; AC-3; IA-5 (1)');
    });

    it('should extract CCI controls from tags', () => {
      const input = JSON.stringify({
        baselines: [{
          name: 'Test',
          version: '1.0.0',
          title: 'Test',
          maintainer: 'Test',
          supports: [],
          attributes: [],
          groups: [],
          checksum: { algorithm: 'sha256', value: 'abc' },
          requirements: [{
            id: 'REQ-001',
            title: 'Test',
            descriptions: [{ label: 'default', data: 'Test' }],
            impact: 0.5,
            tags: {
              cci: ['CCI-000001', 'CCI-000002'],
              severity: 'medium'
            },
            sourceLocation: { ref: 'REQ-001', line: 1 },
            results: [{ status: 'passed', codeDesc: 'Test', startTime: '2026-01-29T18:00:00.000Z' }]
          }]
        }],
        targets: [],
        statistics: { duration: 0 }
      });

      const result = convertHdfToCsv(input);

      expect(result).toContain('CCI-000001; CCI-000002');
    });

    it('should extract result message from failed results', () => {
      const input = JSON.stringify({
        baselines: [{
          name: 'Test',
          version: '1.0.0',
          title: 'Test',
          maintainer: 'Test',
          supports: [],
          attributes: [],
          groups: [],
          checksum: { algorithm: 'sha256', value: 'abc' },
          requirements: [{
            id: 'REQ-001',
            title: 'Test',
            descriptions: [{ label: 'default', data: 'Test' }],
            impact: 0.5,
            tags: { severity: 'medium' },
            sourceLocation: { ref: 'REQ-001', line: 1 },
            results: [{
              status: 'failed',
              codeDesc: 'Test',
              message: 'Security control not implemented',
              startTime: '2026-01-29T18:00:00.000Z'
            }]
          }]
        }],
        targets: [],
        statistics: { duration: 0 }
      });

      const result = convertHdfToCsv(input);

      expect(result).toContain('Security control not implemented');
    });

    it('should use first result for status when multiple results exist', () => {
      const input = JSON.stringify({
        baselines: [{
          name: 'Test',
          version: '1.0.0',
          title: 'Test',
          maintainer: 'Test',
          supports: [],
          attributes: [],
          groups: [],
          checksum: { algorithm: 'sha256', value: 'abc' },
          requirements: [{
            id: 'REQ-001',
            title: 'Test',
            descriptions: [{ label: 'default', data: 'Test' }],
            impact: 0.5,
            tags: { severity: 'medium' },
            sourceLocation: { ref: 'REQ-001', line: 1 },
            results: [
              { status: 'failed', codeDesc: 'Test 1', message: 'First failure', startTime: '2026-01-29T18:00:00.000Z' },
              { status: 'passed', codeDesc: 'Test 2', startTime: '2026-01-29T18:00:01.000Z' }
            ]
          }]
        }],
        targets: [],
        statistics: { duration: 0 }
      });

      const result = convertHdfToCsv(input);

      // Should use first result
      expect(result).toContain('failed');
      expect(result).toContain('First failure');
    });
  });

  describe('CSV injection protection', () => {
    it('should sanitize formulas in descriptions', () => {
      const input = JSON.stringify({
        baselines: [{
          name: 'Test',
          version: '1.0.0',
          title: 'Test',
          maintainer: 'Test',
          supports: [],
          attributes: [],
          groups: [],
          checksum: { algorithm: 'sha256', value: 'abc' },
          requirements: [{
            id: 'REQ-001',
            title: '=1+1',
            descriptions: [{ label: 'default', data: '=SUM(A1:A10)' }],
            impact: 0.5,
            tags: { severity: 'medium' },
            sourceLocation: { ref: 'REQ-001', line: 1 },
            results: [{ status: 'passed', codeDesc: 'Test', startTime: '2026-01-29T18:00:00.000Z' }]
          }]
        }],
        targets: [],
        statistics: { duration: 0 }
      });

      const result = convertHdfToCsv(input);

      // Formulas should be prefixed with '
      expect(result).toContain("'=1+1");
      expect(result).toContain("'=SUM(A1:A10)");
    });

    it('should sanitize all formula trigger characters', () => {
      const input = JSON.stringify({
        baselines: [{
          name: 'Test',
          version: '1.0.0',
          title: 'Test',
          maintainer: 'Test',
          supports: [],
          attributes: [],
          groups: [],
          checksum: { algorithm: 'sha256', value: 'abc' },
          requirements: [
            {
              id: 'REQ-001',
              title: '+dangerous',
              descriptions: [{ label: 'default', data: 'test' }],
              impact: 0.5,
              tags: { severity: 'medium' },
              sourceLocation: { ref: 'REQ-001', line: 1 },
              results: [{ status: 'passed', codeDesc: 'Test', startTime: '2026-01-29T18:00:00.000Z' }]
            },
            {
              id: 'REQ-002',
              title: '-dangerous',
              descriptions: [{ label: 'default', data: 'test' }],
              impact: 0.5,
              tags: { severity: 'medium' },
              sourceLocation: { ref: 'REQ-002', line: 1 },
              results: [{ status: 'passed', codeDesc: 'Test', startTime: '2026-01-29T18:00:00.000Z' }]
            },
            {
              id: 'REQ-003',
              title: '@dangerous',
              descriptions: [{ label: 'default', data: 'test' }],
              impact: 0.5,
              tags: { severity: 'medium' },
              sourceLocation: { ref: 'REQ-003', line: 1 },
              results: [{ status: 'passed', codeDesc: 'Test', startTime: '2026-01-29T18:00:00.000Z' }]
            }
          ]
        }],
        targets: [],
        statistics: { duration: 0 }
      });

      const result = convertHdfToCsv(input);

      expect(result).toContain("'+dangerous");
      expect(result).toContain("'-dangerous");
      expect(result).toContain("'@dangerous");
    });
  });

  describe('Error handling', () => {
    it('should throw on invalid JSON', () => {
      expect(() => convertHdfToCsv('not valid json')).toThrow();
    });

    it('should throw on missing baselines field', () => {
      expect(() => convertHdfToCsv('{}')).toThrow();
    });

    it('should throw on invalid HDF structure', () => {
      expect(() => convertHdfToCsv('{ "baselines": "not an array" }')).toThrow();
    });
  });

  describe('edge cases: missing optional fields', () => {
    it('should handle requirement with no tags', () => {
      const input = JSON.stringify({
        baselines: [{
          name: 'B1',
          requirements: [{
            id: 'R1',
            title: 'Test',
            descriptions: [{ label: 'default', data: 'desc' }],
            impact: 0.5,
            tags: {},
            results: [{ status: 'passed', codeDesc: 'Test', startTime: '2025-01-01T00:00:00Z' }]
          }]
        }],
        targets: [],
      });
      const result = convertHdfToCsv(input);
      expect(result).toContain('R1');
    });

    it('should handle requirement with no default description', () => {
      const input = JSON.stringify({
        baselines: [{
          name: 'B1',
          requirements: [{
            id: 'R1',
            descriptions: [{ label: 'check', data: 'check data' }],
            impact: 0.5,
            tags: {},
            results: [{ status: 'passed', codeDesc: 'Test', startTime: '2025-01-01T00:00:00Z' }]
          }]
        }],
        targets: [],
      });
      const result = convertHdfToCsv(input);
      expect(result).toContain('R1');
    });

    it('should handle severity as array in tags', () => {
      const input = JSON.stringify({
        baselines: [{
          name: 'B1',
          requirements: [{
            id: 'R1',
            descriptions: [{ label: 'default', data: 'desc' }],
            impact: 0.5,
            tags: { severity: ['high', 'medium'] },
            results: [{ status: 'passed', codeDesc: 'Test', startTime: '2025-01-01T00:00:00Z' }]
          }]
        }],
        targets: [],
      });
      const result = convertHdfToCsv(input);
      expect(result).toContain('high');
    });

    it('should handle no targets (default empty target)', () => {
      const input = JSON.stringify({
        baselines: [{
          name: 'B1',
          requirements: [{
            id: 'R1',
            descriptions: [{ label: 'default', data: 'desc' }],
            impact: 0.2,
            tags: {},
            results: [{ status: 'passed', codeDesc: 'Test', startTime: '2025-01-01T00:00:00Z' }]
          }]
        }],
      });
      const result = convertHdfToCsv(input);
      expect(result).toContain('R1');
      expect(result).toContain('low'); // impact 0.2 → low severity
    });

    it('should handle impact >= 0.7 as high severity', () => {
      const input = JSON.stringify({
        baselines: [{
          name: 'B1',
          requirements: [{
            id: 'R1',
            descriptions: [{ label: 'default', data: 'desc' }],
            impact: 0.8,
            tags: {},
            results: [{ status: 'failed', codeDesc: 'Test', startTime: '2025-01-01T00:00:00Z', message: 'fail msg' }]
          }]
        }],
        targets: [{ name: 't1', type: 'host' }],
      });
      const result = convertHdfToCsv(input);
      expect(result).toContain('high');
    });

    it('should handle null/undefined tags gracefully in extractArrayFromTags', () => {
      const input = JSON.stringify({
        baselines: [{
          name: 'B1',
          requirements: [{
            id: 'R1',
            descriptions: [{ label: 'default', data: 'desc' }],
            impact: 0.5,
            results: [{ status: 'passed', codeDesc: 'Test', startTime: '2025-01-01T00:00:00Z' }]
          }]
        }],
        targets: [],
      });
      const result = convertHdfToCsv(input);
      expect(result).toContain('R1');
    });

    it('should handle requirement with no title and no version', () => {
      const input = JSON.stringify({
        baselines: [{
          name: 'B1',
          requirements: [{
            id: 'R1',
            descriptions: [{ label: 'default', data: 'desc' }],
            impact: 0.5,
            tags: { nist: ['AC-1'] },
            results: [{ status: 'passed', codeDesc: 'Test', startTime: '2025-01-01T00:00:00Z' }]
          }]
        }],
        targets: [],
      });
      const result = convertHdfToCsv(input);
      expect(result).toContain('AC-1');
    });
  });
});
