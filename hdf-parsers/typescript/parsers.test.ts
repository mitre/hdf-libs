import { describe, it, expect } from 'vitest';
import {
  parseResults,
  parseBaseline,
  parse
} from './index.js';

describe('HDF Results Parsing', () => {
  describe('Valid documents', () => {
    it('should parse minimal valid HDF results from string', () => {
      const validJson = JSON.stringify({
        baselines: [{
          name: 'Test Baseline',
          checksum: { algorithm: 'sha256', value: 'abc123' },
          requirements: [{
            id: 'REQ-001',
            descriptions: [{ label: 'default', data: 'Test description' }],
            impact: 0.5,
            tags: {},
            results: [{
              status: 'passed',
              codeDesc: 'Test',
              startTime: '2025-01-01T00:00:00Z'
            }]
          }]
        }],
        targets: [],
        statistics: {}
      });

      const result = parseResults(validJson);

      expect(result.success).toBe(true);
      expect(result.error).toBeUndefined();
      expect(result.data).toBeDefined();
      expect(result.data!.baselines).toHaveLength(1);
      expect(result.data!.baselines![0].name).toBe('Test Baseline');
    });

    it('should parse HDF results from bytes', () => {
      const validJson = JSON.stringify({
        baselines: [{
          name: 'Test',
          checksum: { algorithm: 'sha256', value: 'test' },
          requirements: []
        }],
        targets: [],
        statistics: {}
      });

      const bytes = new TextEncoder().encode(validJson);
      const result = parseResults(bytes);

      expect(result.success).toBe(true);
      expect(result.data).toBeDefined();
    });

    it('should parse complex HDF results with multiple baselines', () => {
      const complexJson = JSON.stringify({
        baselines: [
          {
            name: 'Baseline 1',
            checksum: { algorithm: 'sha256', value: 'hash1' },
            requirements: [{
              id: 'REQ-001',
              descriptions: [{ label: 'default', data: 'Desc 1' }],
              impact: 0.7,
              tags: { nist: ['AC-1'] },
              results: [{
                status: 'failed',
                codeDesc: 'Check 1',
                startTime: '2025-01-01T00:00:00Z',
                message: 'Failed check'
              }]
            }]
          },
          {
            name: 'Baseline 2',
            checksum: { algorithm: 'sha512', value: 'hash2' },
            requirements: [{
              id: 'REQ-002',
              descriptions: [{ label: 'default', data: 'Desc 2' }],
              impact: 0.3,
              tags: {},
              results: [{
                status: 'passed',
                codeDesc: 'Check 2',
                startTime: '2025-01-02T00:00:00Z'
              }]
            }]
          }
        ],
        targets: [],
        statistics: {}
      });

      const result = parseResults(complexJson);

      expect(result.success).toBe(true);
      expect(result.data!.baselines).toHaveLength(2);
      expect(result.data!.baselines![0].requirements).toHaveLength(1);
      expect(result.data!.baselines![1].requirements).toHaveLength(1);
    });
  });

  describe('Invalid documents', () => {
    it('should reject invalid JSON syntax', () => {
      const invalidJson = '{ "baselines": [invalid json }';

      const result = parseResults(invalidJson);

      expect(result.success).toBe(false);
      expect(result.error).toBeDefined();
      expect(result.error).toContain('JSON');
      expect(result.data).toBeUndefined();
    });

    it('should reject results missing baselines field', () => {
      const invalidJson = JSON.stringify({
        targets: [],
        statistics: {}
      });

      const result = parseResults(invalidJson);

      expect(result.success).toBe(false);
      expect(result.error).toBeDefined();
      expect(result.error).toContain('baselines');
    });

    it('should reject results with invalid baseline structure', () => {
      const invalidJson = JSON.stringify({
        baselines: [{
          // Missing name
          checksum: { algorithm: 'sha256', value: 'test' },
          requirements: []
        }],
        targets: [],
        statistics: {}
      });

      const result = parseResults(invalidJson);

      expect(result.success).toBe(false);
      expect(result.error).toBeDefined();
    });

    it('should reject results with invalid requirement', () => {
      const invalidJson = JSON.stringify({
        baselines: [{
          name: 'Test',
          checksum: { algorithm: 'sha256', value: 'test' },
          requirements: [{
            id: 'REQ-001',
            // Missing descriptions
            impact: 0.5,
            tags: {},
            results: []
          }]
        }],
        targets: [],
        statistics: {}
      });

      const result = parseResults(invalidJson);

      expect(result.success).toBe(false);
      expect(result.error).toBeDefined();
    });

    it('should reject results with wrong type for baselines', () => {
      const invalidJson = JSON.stringify({
        baselines: 'not an array',
        targets: [],
        statistics: {}
      });

      const result = parseResults(invalidJson);

      expect(result.success).toBe(false);
      expect(result.error).toBeDefined();
    });

    it('should detect trailing garbage after valid JSON', () => {
      const invalidJson = '{"baselines":[],"targets":[],"statistics":{}}garbage';

      const result = parseResults(invalidJson);

      expect(result.success).toBe(false);
      expect(result.error).toBeDefined();
      expect(result.error).toMatch(/JSON|unexpected|non-whitespace/i);
    });

    it('should reject empty string', () => {
      const result = parseResults('');

      expect(result.success).toBe(false);
      expect(result.error).toBeDefined();
    });

    it('should reject whitespace-only string', () => {
      const result = parseResults('   \n\t  ');

      expect(result.success).toBe(false);
      expect(result.error).toBeDefined();
    });
  });
});

describe('HDF Baseline Parsing', () => {
  describe('Valid documents', () => {
    it('should parse minimal valid HDF baseline', () => {
      const validJson = JSON.stringify({
        name: 'Security Baseline',
        title: 'Test Baseline',
        version: '1.0.0',
        checksum: { algorithm: 'sha256', value: 'def456' },
        requirements: [{
          id: 'REQ-001',
          title: 'Access Control',
          descriptions: [{ label: 'default', data: 'Requirement description' }],
          impact: 0.7,
          tags: { nist: ['AC-1', 'AC-2'] }
        }]
      });

      const result = parseBaseline(validJson);

      expect(result.success).toBe(true);
      expect(result.data).toBeDefined();
      expect(result.data!.name).toBe('Security Baseline');
      expect(result.data!.requirements).toHaveLength(1);
    });

    it('should parse baseline with multiple requirements', () => {
      const validJson = JSON.stringify({
        name: 'Multi-Req Baseline',
        version: '2.0.0',
        checksum: { algorithm: 'sha512', value: 'hash' },
        requirements: [
          {
            id: 'REQ-001',
            title: 'Requirement 1',
            descriptions: [{ label: 'default', data: 'Desc 1' }],
            impact: 0.5,
            tags: {}
          },
          {
            id: 'REQ-002',
            title: 'Requirement 2',
            descriptions: [{ label: 'default', data: 'Desc 2' }],
            impact: 0.8,
            tags: { nist: ['AU-1'] }
          }
        ]
      });

      const result = parseBaseline(validJson);

      expect(result.success).toBe(true);
      expect(result.data!.requirements).toHaveLength(2);
    });
  });

  describe('Invalid documents', () => {
    it('should reject baseline missing name', () => {
      const invalidJson = JSON.stringify({
        version: '1.0.0',
        checksum: { algorithm: 'sha256', value: 'test' },
        requirements: []
      });

      const result = parseBaseline(invalidJson);

      expect(result.success).toBe(false);
      expect(result.error).toBeDefined();
    });

    it('should reject baseline with empty requirements array', () => {
      const invalidJson = JSON.stringify({
        name: 'Test Baseline',
        checksum: { algorithm: 'sha256', value: 'test' },
        requirements: []
      });

      const result = parseBaseline(invalidJson);

      expect(result.success).toBe(false);
      expect(result.error).toBeDefined();
    });
  });
});

describe('Auto-Detection Parsing', () => {
  it('should auto-detect and parse HDF Results', () => {
    const resultsJson = JSON.stringify({
      baselines: [{
        name: 'Test',
        checksum: { algorithm: 'sha256', value: 'test' },
        requirements: []
      }],
      targets: [],
      statistics: {}
    });

    const result = parse(resultsJson);

    expect(result.success).toBe(true);
    expect(result.type).toBe('results');
    expect(result.data).toBeDefined();
  });

  it('should auto-detect and parse HDF Baseline', () => {
    const baselineJson = JSON.stringify({
      name: 'Test Baseline',
      version: '1.0.0',
      checksum: { algorithm: 'sha256', value: 'test' },
      requirements: [{
        id: 'REQ-001',
        title: 'Test',
        descriptions: [{ label: 'default', data: 'Test' }],
        impact: 0.5,
        tags: {}
      }]
    });

    const result = parse(baselineJson);

    expect(result.success).toBe(true);
    expect(result.type).toBe('baseline');
    expect(result.data).toBeDefined();
  });

  it('should return error for ambiguous document', () => {
    const ambiguousJson = JSON.stringify({
      unknown: 'field'
    });

    const result = parse(ambiguousJson);

    expect(result.success).toBe(false);
    expect(result.error).toBeDefined();
  });

  it('should return error for invalid document', () => {
    const invalidJson = '{ invalid }';

    const result = parse(invalidJson);

    expect(result.success).toBe(false);
    expect(result.error).toBeDefined();
  });
});

describe('Whitespace-equivalent JSON (isWhitespaceEquivalent path)', () => {
  const validResultsData = {
    baselines: [{
      name: 'WS Test Baseline',
      checksum: { algorithm: 'sha256', value: 'abc123' },
      requirements: [{
        id: 'REQ-001',
        descriptions: [{ label: 'default', data: 'Test' }],
        impact: 0.5,
        tags: {},
        results: [{
          status: 'passed',
          codeDesc: 'ok',
          startTime: '2025-01-01T00:00:00Z'
        }]
      }]
    }],
    targets: [],
    statistics: {}
  };

  it('parseResults accepts pretty-printed JSON (exercises isWhitespaceEquivalent)', () => {
    // Pretty-printed JSON has extra internal whitespace: compact serialized != trimmed input
    // but isWhitespaceEquivalent returns true, so it should parse successfully
    const prettyJson = JSON.stringify(validResultsData, null, 2);
    const result = parseResults(prettyJson);
    expect(result.success).toBe(true);
    expect(result.data).toBeDefined();
  });

  it('parseResults accepts compact JSON with trailing whitespace', () => {
    const json = JSON.stringify(validResultsData) + '   \n';
    const result = parseResults(json);
    expect(result.success).toBe(true);
  });

  it('parseBaseline accepts pretty-printed JSON', () => {
    const validBaselineData = {
      name: 'WS Baseline',
      version: '1.0.0',
      checksum: { algorithm: 'sha256', value: 'def456' },
      requirements: [{
        id: 'REQ-001',
        title: 'Test',
        descriptions: [{ label: 'default', data: 'Test' }],
        impact: 0.5,
        tags: {}
      }]
    };
    const prettyJson = JSON.stringify(validBaselineData, null, 2);
    const result = parseBaseline(prettyJson);
    expect(result.success).toBe(true);
  });
});

describe('Trailing garbage detection (parseBaseline and parse)', () => {
  it('parseBaseline rejects trailing non-whitespace data', () => {
    const validJson = JSON.stringify({
      name: 'Test',
      version: '1.0.0',
      checksum: { algorithm: 'sha256', value: 'test' },
      requirements: [{
        id: 'REQ-001',
        title: 'Test',
        descriptions: [{ label: 'default', data: 'Test' }],
        impact: 0.5,
        tags: {}
      }]
    }) + ' garbage_data';

    const result = parseBaseline(validJson);

    expect(result.success).toBe(false);
    expect(result.error).toBeDefined();
    expect(result.error).toMatch(/JSON|trailing|unexpected/i);
  });

  it('parse rejects trailing garbage after valid JSON', () => {
    const validJson = '{"baselines":[],"targets":[],"statistics":{}}extraGarbage';

    const result = parse(validJson);

    expect(result.success).toBe(false);
    expect(result.error).toBeDefined();
    expect(result.error).toMatch(/JSON|trailing|unexpected/i);
  });
});

describe('Schema validation error messages', () => {
  it('parseResults error explicitly contains Schema validation failed', () => {
    const validJsonButInvalidHdf = JSON.stringify({ notHdf: true });
    const result = parseResults(validJsonButInvalidHdf);
    expect(result.success).toBe(false);
    expect(result.error).toContain('Schema validation failed');
  });

  it('parseBaseline error explicitly contains Schema validation failed', () => {
    const invalidSchema = JSON.stringify({ name: 'test', notRequirements: true });
    const result = parseBaseline(invalidSchema);
    expect(result.success).toBe(false);
    expect(result.error).toContain('Schema validation failed');
  });

  it('parse auto-detect error for object missing HDF keys', () => {
    const result = parse(JSON.stringify({ name: 'test' }));
    expect(result.success).toBe(false);
    expect(result.error).toBeDefined();
  });
});

describe('Error Messages', () => {
  it('should provide helpful error message for schema validation failure', () => {
    const invalidJson = JSON.stringify({
      baselines: [{
        // Missing required fields
        name: 'Test'
      }],
      targets: [],
      statistics: {}
    });

    const result = parseResults(invalidJson);

    expect(result.success).toBe(false);
    expect(result.error).toBeDefined();
    expect(result.error!.length).toBeGreaterThan(0);
  });

  it('should provide helpful error for JSON parse failure', () => {
    const result = parseResults('{ not valid json');

    expect(result.success).toBe(false);
    expect(result.error).toBeDefined();
    expect(result.error).toMatch(/JSON|parse|syntax/i);
  });
});
