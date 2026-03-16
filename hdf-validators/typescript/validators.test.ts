import { describe, it, expect } from 'vitest';
import { validateResults, validateBaseline, ValidationResult } from './index.js';

describe('HDF Results Validation', () => {
  describe('Valid documents', () => {
    it('should validate minimal valid HDF results', () => {
      const validResults = {
        baselines: [
          {
            name: 'Test Baseline',
            checksum: {
              algorithm: 'sha256',
              value: 'abc123'
            },
            requirements: [
              {
                id: 'REQ-001',
                descriptions: [{ label: 'default', data: 'Test description' }],
                impact: 0.5,
                tags: {},
                results: [
                  {
                    status: 'passed',
                    codeDesc: 'Test',
                    startTime: '2025-01-01T00:00:00Z'
                  }
                ]
              }
            ]
          }
        ],
        targets: [],
        statistics: {}
      };

      const result = validateResults(validResults);
      expect(result.valid).toBe(true);
      expect(result.errors).toEqual([]);
    });

    it('should validate results with targets and statistics', () => {
      const validResults = {
        baselines: [
          {
            name: 'Test Baseline',
            checksum: { algorithm: 'sha256', value: 'abc123' },
            requirements: []
          }
        ],
        targets: [
          {
            name: 'web-server-01',
            type: 'host'
          }
        ],
        statistics: {
          duration: 45.5
        }
      };

      const result = validateResults(validResults);
      expect(result.valid).toBe(true);
    });

    it('should validate results with optional fields', () => {
      const validResults = {
        baselines: [
          {
            name: 'Test Baseline',
            version: '1.0.0',
            title: 'Test Title',
            checksum: { algorithm: 'sha256', value: 'abc123' },
            requirements: []
          }
        ],
        targets: [],
        statistics: {},
        timestamp: '2025-01-01T00:00:00Z'
      };

      const result = validateResults(validResults);
      expect(result.valid).toBe(true);
    });
  });

  describe('Invalid documents', () => {
    it('should reject results missing baselines field', () => {
      const invalid = {
        targets: [],
        statistics: {}
      };

      const result = validateResults(invalid);
      expect(result.valid).toBe(false);
      expect(result.errors.length).toBeGreaterThan(0);
      expect(result.errors.some(e => e.field.includes('baselines'))).toBe(true);
    });

    it('should reject results with invalid baselines type', () => {
      const invalid = {
        baselines: 'not an array',
        targets: [],
        statistics: {}
      };

      const result = validateResults(invalid);
      expect(result.valid).toBe(false);
      expect(result.errors.some(e => e.field.includes('baselines'))).toBe(true);
    });

    it('should reject baseline missing required name field', () => {
      const invalid = {
        baselines: [
          {
            checksum: { algorithm: 'sha256', value: 'abc123' },
            requirements: []
          }
        ],
        targets: [],
        statistics: {}
      };

      const result = validateResults(invalid);
      expect(result.valid).toBe(false);
      expect(result.errors.some(e => e.field.includes('name'))).toBe(true);
    });

    it('should accept baseline missing checksum', () => {
      const valid = {
        baselines: [
          {
            name: 'Test',
            requirements: []
          }
        ],
        targets: [],
        statistics: {}
      };

      const result = validateResults(valid);
      expect(result.valid).toBe(true);
    });

    it('should reject requirement with invalid impact value', () => {
      const invalid = {
        baselines: [
          {
            name: 'Test',
            checksum: { algorithm: 'sha256', value: 'abc123' },
            requirements: [
              {
                id: 'REQ-001',
                descriptions: [{ label: 'default', data: 'Test' }],
                impact: 1.5, // Invalid: must be 0-1
                tags: {},
                results: [{ status: 'passed', codeDesc: 'Test', startTime: '2025-01-01T00:00:00Z' }]
              }
            ]
          }
        ],
        targets: [],
        statistics: {}
      };

      const result = validateResults(invalid);
      expect(result.valid).toBe(false);
      expect(result.errors.some(e => e.field.includes('impact'))).toBe(true);
    });

    it('should reject invalid result status', () => {
      const invalid = {
        baselines: [
          {
            name: 'Test',
            checksum: { algorithm: 'sha256', value: 'abc123' },
            requirements: [
              {
                id: 'REQ-001',
                descriptions: [{ label: 'default', data: 'Test' }],
                impact: 0.5,
                tags: {},
                results: [
                  {
                    status: 'invalid-status',
                    codeDesc: 'Test',
                    startTime: '2025-01-01T00:00:00Z'
                  }
                ]
              }
            ]
          }
        ],
        targets: [],
        statistics: {}
      };

      const result = validateResults(invalid);
      expect(result.valid).toBe(false);
      expect(result.errors.some(e => e.field.includes('status'))).toBe(true);
    });
  });

  describe('Error messages', () => {
    it('should provide descriptive error messages', () => {
      const invalid = {
        baselines: [
          {
            name: 'Test',
            requirements: [
              {
                // Missing required fields: id, descriptions, impact, tags
                results: []
              }
            ]
          }
        ]
      };

      const result = validateResults(invalid);
      expect(result.valid).toBe(false);
      expect(result.errors.length).toBeGreaterThan(0);

      const errorMsg = result.getErrorMessage();
      expect(errorMsg).toBeTruthy();
      expect(errorMsg.length).toBeGreaterThan(0);
    });

    it('should list all validation errors', () => {
      const invalid = {
        baselines: [
          {
            // Missing name and checksum
            requirements: 'not an array' // Also invalid type
          }
        ]
      };

      const result = validateResults(invalid);
      expect(result.valid).toBe(false);
      expect(result.errors.length).toBeGreaterThan(1); // Multiple errors
    });
  });
});

describe('HDF Baseline Validation', () => {
  describe('Valid documents', () => {
    it('should validate minimal valid baseline', () => {
      const validBaseline = {
        name: 'Test Baseline',
        title: 'Test Baseline Title',
        version: '1.0.0',
        checksum: {
          algorithm: 'sha256',
          value: 'abc123'
        },
        requirements: [
          {
            id: 'REQ-001',
            title: 'Test Requirement',
            descriptions: [{ label: 'default', data: 'Description' }],
            impact: 0.7,
            tags: {}
          }
        ]
      };

      const result = validateBaseline(validBaseline);
      expect(result.valid).toBe(true);
      expect(result.errors).toEqual([]);
    });

    it('should validate baseline with requirements', () => {
      const validBaseline = {
        name: 'Test Baseline',
        title: 'Test Title',
        version: '1.0.0',
        checksum: { algorithm: 'sha256', value: 'abc123' },
        requirements: [
          {
            id: 'REQ-001',
            title: 'Test Requirement',
            descriptions: [{ label: 'default', data: 'Description' }],
            impact: 0.7,
            tags: { nist: ['AC-1'] }
          }
        ]
      };

      const result = validateBaseline(validBaseline);
      expect(result.valid).toBe(true);
    });
  });

  describe('Invalid documents', () => {
    it('should reject baseline missing name', () => {
      const invalid = {
        title: 'Test',
        version: '1.0.0',
        checksum: { algorithm: 'sha256', value: 'abc123' },
        requirements: []
      };

      const result = validateBaseline(invalid);
      expect(result.valid).toBe(false);
      expect(result.errors.some(e => e.field.includes('name'))).toBe(true);
    });

    it('should accept baseline missing checksum', () => {
      const valid = {
        name: 'Test',
        title: 'Test',
        version: '1.0.0',
        requirements: [
          {
            id: 'test-1',
            impact: 0.5,
            tags: {},
            descriptions: [{ label: 'default', data: 'Test requirement' }],
          },
        ],
      };

      const result = validateBaseline(valid);
      expect(result.valid).toBe(true);
    });
  });
});

describe('ValidationResult', () => {
  it('should format error messages correctly', () => {
    const result: ValidationResult = {
      valid: false,
      errors: [
        { field: 'baselines', message: 'is required' },
        { field: 'baselines[0].name', message: 'must be a string' }
      ],
      getErrorMessage: function() {
        return this.errors.map(e => `${e.field}: ${e.message}`).join('; ');
      }
    };

    const msg = result.getErrorMessage();
    expect(msg).toContain('baselines');
    expect(msg).toContain('name');
  });

  it('should return empty string for valid results', () => {
    const result: ValidationResult = {
      valid: true,
      errors: [],
      getErrorMessage: () => ''
    };

    expect(result.getErrorMessage()).toBe('');
  });
});
