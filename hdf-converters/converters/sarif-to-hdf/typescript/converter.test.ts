import { describe, it, expect } from 'vitest';
import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { convertSarifToHdf } from './converter.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const fixturesDir = join(__dirname, '..', 'fixtures');

function loadFixture(type: 'input' | 'expected', filename: string): string {
  return readFileSync(join(fixturesDir, type, filename), 'utf-8');
}

describe('SARIF Converter', () => {
  describe('Basic conversion', () => {
    it('should convert minimal SARIF to HDF', () => {
      const input = loadFixture('input', 'minimal.sarif');

      const result = JSON.parse(convertSarifToHdf(input));

      // Compare structure (ignore timestamp and generator version)
      expect(result.dataSource?.format).toBe('SARIF');
      expect(result.dataSource?.name).toBe('Flawfinder');
      expect(result.dataSource?.version).toBe('2.0.15');
      expect(result.baselines).toHaveLength(1);
      expect(result.baselines[0].name).toBe('SARIF');
      expect(result.baselines[0].version).toBe('2.1.0');
      expect(result.baselines[0].requirements).toHaveLength(2);

      // Check first requirement
      const req1 = result.baselines[0].requirements[0];
      expect(req1.id).toBe('RULE-001');
      expect(req1.title).toBe('buffer/strcpy');
      expect(req1.descriptions[0].data).toContain('Does not check for buffer overflows');
      expect(req1.impact).toBe(0.7);
      expect(req1.tags.severity).toBe('error');
      expect(req1.tags.cwe).toContain('CWE-120');
      expect(req1.tags.cwe).toContain('CWE-20');
      expect(req1.tags.nist).toContain('SI-10');
      expect(req1.sourceLocation.ref).toBe('src/main.c');
      expect(req1.sourceLocation.line).toBe(42);
      expect(req1.results).toHaveLength(1);
      expect(req1.results[0].status).toBe('failed');
      expect(req1.results[0].codeDesc).toContain('src/main.c');
      expect(req1.results[0].codeDesc).toContain('LINE : 42');

      // Check second requirement
      const req2 = result.baselines[0].requirements[1];
      expect(req2.id).toBe('RULE-002');
      expect(req2.title).toBe('format/printf');
      expect(req2.impact).toBe(0.5);
      expect(req2.tags.severity).toBe('warning');
      expect(req2.tags.cwe).toContain('CWE-134');
    });

    it('should handle empty results array', () => {
      const input = JSON.stringify({
        version: '2.1.0',
        runs: [{
          tool: { driver: { name: 'TestTool', version: '1.0.0' } },
          results: []
        }]
      });

      const result = JSON.parse(convertSarifToHdf(input));

      expect(result.baselines).toHaveLength(1);
      expect(result.baselines[0].requirements).toHaveLength(0);
    });

    it('should handle missing locations', () => {
      const input = JSON.stringify({
        version: '2.1.0',
        runs: [{
          tool: { driver: { name: 'TestTool', version: '1.0.0' } },
          results: [{
            ruleId: 'TEST-001',
            level: 'error',
            message: { text: 'test/issue: Test issue description (CWE-79).' },
            locations: []
          }]
        }]
      });

      const result = JSON.parse(convertSarifToHdf(input));

      const req = result.baselines[0].requirements[0];
      expect(req.sourceLocation).toBeUndefined();
      expect(req.results).toHaveLength(0);
    });
  });

  describe('Impact mapping', () => {
    it('should map error level to 0.7', () => {
      const input = JSON.stringify({
        version: '2.1.0',
        runs: [{
          tool: { driver: { name: 'Test', version: '1.0' } },
          results: [{
            ruleId: 'TEST',
            level: 'error',
            message: { text: 'test: description' },
            locations: []
          }]
        }]
      });

      const result = JSON.parse(convertSarifToHdf(input));
      expect(result.baselines[0].requirements[0].impact).toBe(0.7);
    });

    it('should map warning level to 0.5', () => {
      const input = JSON.stringify({
        version: '2.1.0',
        runs: [{
          tool: { driver: { name: 'Test', version: '1.0' } },
          results: [{
            ruleId: 'TEST',
            level: 'warning',
            message: { text: 'test: description' },
            locations: []
          }]
        }]
      });

      const result = JSON.parse(convertSarifToHdf(input));
      expect(result.baselines[0].requirements[0].impact).toBe(0.5);
    });

    it('should map note level to 0.3', () => {
      const input = JSON.stringify({
        version: '2.1.0',
        runs: [{
          tool: { driver: { name: 'Test', version: '1.0' } },
          results: [{
            ruleId: 'TEST',
            level: 'note',
            message: { text: 'test: description' },
            locations: []
          }]
        }]
      });

      const result = JSON.parse(convertSarifToHdf(input));
      expect(result.baselines[0].requirements[0].impact).toBe(0.3);
    });

    it('should default to 0.1 for missing level', () => {
      const input = JSON.stringify({
        version: '2.1.0',
        runs: [{
          tool: { driver: { name: 'Test', version: '1.0' } },
          results: [{
            ruleId: 'TEST',
            message: { text: 'test: description' },
            locations: []
          }]
        }]
      });

      const result = JSON.parse(convertSarifToHdf(input));
      expect(result.baselines[0].requirements[0].impact).toBe(0.1);
    });
  });

  describe('CWE extraction', () => {
    it('should extract CWE IDs from message text with commas', () => {
      const input = JSON.stringify({
        version: '2.1.0',
        runs: [{
          tool: { driver: { name: 'Test', version: '1.0' } },
          results: [{
            ruleId: 'TEST',
            level: 'error',
            message: { text: 'test: description (CWE-79, CWE-89).' },
            locations: []
          }]
        }]
      });

      const result = JSON.parse(convertSarifToHdf(input));
      const cwes = result.baselines[0].requirements[0].tags.cwe;
      expect(cwes).toContain('CWE-79');
      expect(cwes).toContain('CWE-89');
    });

    it('should extract CWE IDs from message text with !/', () => {
      const input = JSON.stringify({
        version: '2.1.0',
        runs: [{
          tool: { driver: { name: 'Test', version: '1.0' } },
          results: [{
            ruleId: 'TEST',
            level: 'note',
            message: { text: 'test: description (CWE-119!/CWE-120).' },
            locations: []
          }]
        }]
      });

      const result = JSON.parse(convertSarifToHdf(input));
      const cwes = result.baselines[0].requirements[0].tags.cwe;
      expect(cwes).toContain('CWE-119');
      expect(cwes).toContain('CWE-120');
    });

    it('should handle message with no CWE IDs', () => {
      const input = JSON.stringify({
        version: '2.1.0',
        runs: [{
          tool: { driver: { name: 'Test', version: '1.0' } },
          results: [{
            ruleId: 'TEST',
            level: 'error',
            message: { text: 'test: description without CWE.' },
            locations: []
          }]
        }]
      });

      const result = JSON.parse(convertSarifToHdf(input));
      expect(result.baselines[0].requirements[0].tags.cwe).toEqual([]);
    });
  });

  describe('Message parsing', () => {
    it('should split title and description on first colon', () => {
      const input = JSON.stringify({
        version: '2.1.0',
        runs: [{
          tool: { driver: { name: 'Test', version: '1.0' } },
          results: [{
            ruleId: 'TEST',
            level: 'error',
            message: { text: 'buffer/strcpy: Does not check for buffer overflows (CWE-120).' },
            locations: []
          }]
        }]
      });

      const result = JSON.parse(convertSarifToHdf(input));
      const req = result.baselines[0].requirements[0];
      expect(req.title).toBe('buffer/strcpy');
      expect(req.descriptions[0].data).toBe('Does not check for buffer overflows (CWE-120).');
    });

    it('should handle message without colon', () => {
      const input = JSON.stringify({
        version: '2.1.0',
        runs: [{
          tool: { driver: { name: 'Test', version: '1.0' } },
          results: [{
            ruleId: 'TEST',
            level: 'error',
            message: { text: 'Simple message without colon' },
            locations: []
          }]
        }]
      });

      const result = JSON.parse(convertSarifToHdf(input));
      const req = result.baselines[0].requirements[0];
      expect(req.title).toBe('Simple message without colon');
      expect(req.descriptions[0].data).toBe('');
    });
  });

  describe('Multiple locations', () => {
    it('should create one result per location', () => {
      const input = JSON.stringify({
        version: '2.1.0',
        runs: [{
          tool: { driver: { name: 'Test', version: '1.0' } },
          results: [{
            ruleId: 'TEST',
            level: 'error',
            message: { text: 'test: description (CWE-120).' },
            locations: [
              {
                physicalLocation: {
                  artifactLocation: { uri: 'file1.c' },
                  region: { startLine: 10, startColumn: 5 }
                }
              },
              {
                physicalLocation: {
                  artifactLocation: { uri: 'file2.c' },
                  region: { startLine: 20, startColumn: 3 }
                }
              }
            ]
          }]
        }]
      });

      const result = JSON.parse(convertSarifToHdf(input));
      const req = result.baselines[0].requirements[0];

      // Should use first location for sourceLocation
      expect(req.sourceLocation.ref).toBe('file1.c');
      expect(req.sourceLocation.line).toBe(10);

      // Should have two results
      expect(req.results).toHaveLength(2);
      expect(req.results[0].codeDesc).toContain('file1.c');
      expect(req.results[0].codeDesc).toContain('LINE : 10');
      expect(req.results[1].codeDesc).toContain('file2.c');
      expect(req.results[1].codeDesc).toContain('LINE : 20');
    });
  });

  describe('Error handling', () => {
    it('should error on invalid JSON', () => {
      expect(() => convertSarifToHdf('not valid json')).toThrow();
    });

    it('should error on missing runs', () => {
      const input = JSON.stringify({ version: '2.1.0' });
      expect(() => convertSarifToHdf(input)).toThrow('Invalid SARIF structure');
    });

    it('should error on non-array runs', () => {
      const input = JSON.stringify({ version: '2.1.0', runs: {} });
      expect(() => convertSarifToHdf(input)).toThrow('Invalid SARIF structure');
    });
  });
});
