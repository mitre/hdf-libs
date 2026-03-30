import { describe, it, expect } from 'vitest';
import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { convertHdfToXml } from './converter.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const fixturesDir = join(__dirname, '..', 'fixtures');

function loadFixture(type: 'input' | 'expected', filename: string): string {
  return readFileSync(join(fixturesDir, type, filename), 'utf-8');
}

describe('hdf-to-xml Converter', () => {
  describe('Basic conversion', () => {
    it('should convert minimal HDF to XML', () => {
      const input = loadFixture('input', 'minimal.json');
      const expected = loadFixture('expected', 'minimal.xml');

      const result = convertHdfToXml(input);

      expect(result.trim()).toBe(expected.trim());
    });

    it('should handle empty baselines array', () => {
      const input = JSON.stringify({
        baselines: [],
        components: [],
        statistics: { duration: 0 }
      });

      const result = convertHdfToXml(input);

      expect(result).toContain('<HdfResults>');
      expect(result).toContain('<baselines></baselines>');
      expect(result).toContain('</HdfResults>');
    });

    it('should handle baselines with no requirements', () => {
      const input = JSON.stringify({
        baselines: [{
          name: 'Empty Baseline',
          version: '1.0.0',
          title: 'Test',
          integrity: { algorithm: 'sha256', checksum: 'abc' },
          requirements: []
        }],
        components: [],
        statistics: { duration: 0 }
      });

      const result = convertHdfToXml(input);

      expect(result).toContain('<baseline>');
      expect(result).toContain('<name>Empty Baseline</name>');
      expect(result).toContain('<requirements></requirements>');
    });
  });

  describe('Error handling', () => {
    it('should throw error for invalid JSON', () => {
      expect(() => convertHdfToXml('not json')).toThrow('Invalid JSON');
    });

    it('should throw error for missing baselines field', () => {
      const invalid = JSON.stringify({ foo: 'bar' });
      expect(() => convertHdfToXml(invalid)).toThrow('Invalid HDF structure: missing baselines field');
    });

    it('should throw error for non-array baselines', () => {
      const invalid = JSON.stringify({ baselines: 'not an array' });
      expect(() => convertHdfToXml(invalid)).toThrow('Invalid HDF structure: baselines must be an array');
    });
  });

  describe('Complex structures', () => {
    it('should handle multiple baselines and targets', () => {
      const input = JSON.stringify({
        baselines: [
          {
            name: 'Baseline 1',
            version: '1.0.0',
            integrity: { algorithm: 'sha256', checksum: 'abc' },
            requirements: [{
              id: 'REQ-001',
              title: 'Test Requirement',
              descriptions: [{ label: 'default', data: 'Test description' }],
              impact: 0.5,
              tags: {},
              results: [{ status: 'passed', codeDesc: 'Test', startTime: '2025-01-01T00:00:00Z' }]
            }]
          }
        ],
        components: [{ name: 'Target 1', type: 'host' }],
        statistics: { duration: 10.5 }
      });

      const result = convertHdfToXml(input);

      expect(result).toContain('<name>Baseline 1</name>');
      expect(result).toContain('<id>REQ-001</id>');
      expect(result).toContain('<title>Test Requirement</title>');
      expect(result).toContain('<target>');
      expect(result).toContain('<name>Target 1</name>');
      expect(result).toContain('<type>host</type>');
    });

    it('should preserve special characters in XML', () => {
      const input = JSON.stringify({
        baselines: [{
          name: 'Test & < > " \'',
          integrity: { algorithm: 'sha256', checksum: 'abc' },
          requirements: [{
            id: 'REQ-001',
            title: 'Description with <tags> & special chars',
            descriptions: [{ label: 'default', data: 'Data' }],
            impact: 0.5,
            tags: {},
            results: [{ status: 'passed', codeDesc: 'Test', startTime: '2025-01-01T00:00:00Z' }]
          }]
        }],
        statistics: {}
      });

      const result = convertHdfToXml(input);

      // XML should escape special characters
      expect(result).toContain('&amp;');
      expect(result).toContain('&lt;');
      expect(result).toContain('&gt;');
    });

    it('should handle baselines with no version or title', () => {
      const input = JSON.stringify({
        baselines: [{
          name: 'MinBaseline',
          integrity: { algorithm: 'sha256', checksum: 'abc' },
          requirements: [{
            id: 'REQ-001',
            descriptions: [{ label: 'default', data: 'Data' }],
            impact: 0.5,
            tags: { nist: ['AC-1'], empty: [] },
            results: [{ status: 'passed', codeDesc: 'Test', startTime: '2025-01-01T00:00:00Z', message: 'ok', runTime: 1.5 }]
          }]
        }],
        components: [{ name: 't1', type: 'host', fqdn: 'test.local', ipAddress: '1.2.3.4', hostname: 'myhost' }],
        timestamp: '2025-01-01T00:00:00Z',
        generator: { name: 'test', version: '1.0' },
        statistics: { duration: 10, requirements: { total: 1 } },
      });
      const result = convertHdfToXml(input);
      expect(result).toContain('MinBaseline');
      expect(result).toContain('fqdn');
      expect(result).toContain('ipAddress');
      expect(result).toContain('hostname');
      expect(result).toContain('message');
      expect(result).toContain('runTime');
      expect(result).toContain('timestamp');
      expect(result).toContain('generator');
    });

    it('should handle requirement with empty tags', () => {
      const input = JSON.stringify({
        baselines: [{
          name: 'B1',
          integrity: { algorithm: 'sha256', checksum: 'abc' },
          requirements: [{
            id: 'REQ-001',
            descriptions: [],
            impact: 0.0,
            tags: {},
            results: []
          }]
        }],
      });
      const result = convertHdfToXml(input);
      expect(result).toContain('REQ-001');
    });

    it('should handle baselines with no integrity', () => {
      const input = JSON.stringify({
        baselines: [{
          name: 'NoIntegrity',
          requirements: [{
            id: 'REQ-001',
            title: 'Test',
            descriptions: [{ label: 'default', data: 'desc' }],
            impact: 0.5,
            tags: { custom: 'value' },
            results: [{ status: 'passed', codeDesc: 'Test', startTime: '2025-01-01T00:00:00Z' }]
          }]
        }],
      });
      const result = convertHdfToXml(input);
      expect(result).toContain('NoIntegrity');
      expect(result).not.toContain('integrity');
    });

    it('should handle no components', () => {
      const input = JSON.stringify({
        baselines: [{
          name: 'B1',
          requirements: []
        }],
        statistics: {},
      });
      const result = convertHdfToXml(input);
      expect(result).not.toContain('<components>');
    });
  });
});
