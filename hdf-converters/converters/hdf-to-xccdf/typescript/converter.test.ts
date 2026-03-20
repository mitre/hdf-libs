import { describe, it, expect } from 'vitest';
import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { convertHdfToXccdf } from './converter.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const fixturesDir = join(__dirname, '..', 'fixtures');

function loadFixture(filename: string): string {
  return readFileSync(join(fixturesDir, 'input', filename), 'utf-8');
}

describe('hdf-to-xccdf Converter', () => {
  describe('Minimal round-trip', () => {
    it('should convert minimal HDF to XCCDF XML', () => {
      const input = loadFixture('minimal.json');
      const result = convertHdfToXccdf(input);

      // XML structure
      expect(result).toContain('<?xml');
      expect(result).toContain('http://checklists.nist.gov/xccdf/1.2');
      expect(result).toContain('<Benchmark');
      expect(result).toContain('</Benchmark>');

      // Rules present
      expect(result).toContain('<Rule');
      expect(result).toContain('xccdf_hdf_rule_xccdf_moc.elpmaxe.www_rule_1_rule');
      expect(result).toContain('xccdf_hdf_rule_xccdf_moc.elpmaxe.www_rule_2_rule');

      // TestResult
      expect(result).toContain('<TestResult');
      expect(result).toContain('<target>Test Target</target>');

      // Result statuses
      expect(result).toContain('<result>fail</result>');
      expect(result).toContain('<result>pass</result>');
    });
  });

  describe('STIG RHEL7', () => {
    it('should preserve CCI idents', () => {
      const input = loadFixture('stig-rhel7.json');
      const result = convertHdfToXccdf(input);

      expect(result).toContain('http://cyber.mil/cci');
      expect(result).toContain('CCI-000048');
      expect(result).toContain('CCI-000366');
    });

    it('should map severities correctly', () => {
      const input = loadFixture('stig-rhel7.json');
      const result = convertHdfToXccdf(input);

      // impact 0.5 → medium, 0.7 → high, 0.3 → low
      expect(result).toContain('severity="medium"');
      expect(result).toContain('severity="high"');
      expect(result).toContain('severity="low"');
    });

    it('should preserve target info', () => {
      const input = loadFixture('stig-rhel7.json');
      const result = convertHdfToXccdf(input);

      expect(result).toContain('<target>localhost.localdomain</target>');
      expect(result).toContain('<target-address>127.0.0.1</target-address>');
    });

    it('should preserve fix text', () => {
      const input = loadFixture('stig-rhel7.json');
      const result = convertHdfToXccdf(input);

      expect(result).toContain('<fixtext>');
    });
  });

  describe('Status mapping', () => {
    const statuses: Array<[string, string]> = [
      ['passed', 'pass'],
      ['failed', 'fail'],
      ['error', 'error'],
      ['notReviewed', 'notchecked'],
      ['notApplicable', 'notapplicable'],
    ];

    for (const [hdfStatus, xccdfResult] of statuses) {
      it(`should map ${hdfStatus} to ${xccdfResult}`, () => {
        const input = JSON.stringify({
          baselines: [{
            name: 'test',
            requirements: [{
              id: 'REQ-001',
              descriptions: [{ label: 'default', data: 'test' }],
              impact: 0.5,
              tags: {},
              results: [{
                codeDesc: 'Test',
                startTime: '2025-01-01T00:00:00Z',
                status: hdfStatus,
              }],
            }],
          }],
          statistics: {},
        });

        const result = convertHdfToXccdf(input);
        expect(result).toContain(`<result>${xccdfResult}</result>`);
      });
    }
  });

  describe('Impact to severity mapping', () => {
    const mappings: Array<[number, string]> = [
      [0.9, 'high'],
      [0.7, 'high'],
      [0.5, 'medium'],
      [0.4, 'medium'],
      [0.3, 'low'],
      [0.1, 'low'],
      [0.0, 'info'],
    ];

    for (const [impact, severity] of mappings) {
      it(`should map impact ${impact} to severity ${severity}`, () => {
        const input = JSON.stringify({
          baselines: [{
            name: 'test',
            requirements: [{
              id: 'REQ-001',
              descriptions: [{ label: 'default', data: 'test' }],
              impact,
              tags: {},
              results: [{
                codeDesc: 'Test',
                startTime: '2025-01-01T00:00:00Z',
                status: 'passed',
              }],
            }],
          }],
          statistics: {},
        });

        const result = convertHdfToXccdf(input);
        expect(result).toContain(`severity="${severity}"`);
      });
    }
  });

  describe('Error handling', () => {
    it('should throw on invalid JSON', () => {
      expect(() => convertHdfToXccdf('not json')).toThrow('Invalid JSON');
    });

    it('should throw on missing baselines', () => {
      expect(() => convertHdfToXccdf('{"foo": "bar"}')).toThrow(
        'Invalid HDF structure: missing baselines field',
      );
    });

    it('should throw on non-array baselines', () => {
      expect(() => convertHdfToXccdf('{"baselines": "bad"}')).toThrow(
        'Invalid HDF structure: baselines must be an array',
      );
    });
  });

  describe('Edge cases', () => {
    it('should handle empty baselines array', () => {
      const input = JSON.stringify({
        baselines: [],
        statistics: {},
      });

      const result = convertHdfToXccdf(input);
      expect(result).toContain('xccdf_hdf_benchmark_exported');
      expect(result).toContain('HDF Export');
    });

    it('should escape special characters', () => {
      const input = JSON.stringify({
        baselines: [{
          name: 'Test',
          requirements: [{
            id: 'REQ-001',
            title: 'Rule with <angle> & "quotes"',
            descriptions: [{ label: 'default', data: 'Data & <more>' }],
            impact: 0.5,
            tags: {},
            results: [{
              codeDesc: 'Test',
              startTime: '2025-01-01T00:00:00Z',
              status: 'passed',
            }],
          }],
        }],
        statistics: {},
      });

      const result = convertHdfToXccdf(input);
      expect(result).toContain('&amp;');
      expect(result).toContain('&lt;');
    });

    it('should handle requirements with no results', () => {
      const input = JSON.stringify({
        baselines: [{
          name: 'test',
          requirements: [{
            id: 'REQ-001',
            descriptions: [{ label: 'default', data: 'test' }],
            impact: 0.5,
            tags: {},
            results: [],
          }],
        }],
        statistics: {},
      });

      const result = convertHdfToXccdf(input);
      expect(result).toContain('<Rule');
      expect(result).toContain('REQ-001');
    });
  });
});
