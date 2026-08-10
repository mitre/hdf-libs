import { describe, it, expect } from 'vitest';
import {
  validateResults,
  validateBaseline,
  validateAmendments,
  validateRequirementChangeEvent,
  ValidationResult,
} from './index.js';

/** Minimal requirement that satisfies EvaluatedBaseline.requirements minItems: 1. */
const minReq = {
  id: 'SV-1', impact: 0.5, tags: {},
  descriptions: [{ label: 'default', data: 'Test' }],
  results: [{ status: 'passed', codeDesc: 'Test', startTime: '2025-01-01T00:00:00Z' }],
};

/**
 * Helper: wrap an Evaluated_Requirement in a minimal-valid hdf-results document.
 * Used by the CVE-ecosystem accept/reject tests below so each case only has to
 * vary the requirement fields under test.
 */
function resultsWith(req: Record<string, unknown>): Record<string, unknown> {
  return {
    baselines: [
      {
        name: 'CVE-Ecosystem Test Baseline',
        checksum: { algorithm: 'sha256', value: 'abc123' },
        requirements: [
          {
            id: 'CVE-2024-12345',
            descriptions: [{ label: 'default', data: 'Test CVE finding' }],
            impact: 0.7,
            tags: {},
            results: [
              { status: 'failed', codeDesc: 'Vulnerable', startTime: '2026-05-26T00:00:00Z' },
            ],
            ...req,
          },
        ],
      },
    ],
    targets: [],
    statistics: {},
  };
}

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
            requirements: [minReq]
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
            requirements: [minReq]
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
            requirements: [minReq]
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

  // A POA&M is a time-boxed acceptance of an open finding; without a deadline it
  // lets a failing requirement duck remediation indefinitely (bead 2cyd).
  describe('POA&M deadline enforcement', () => {
    const poam = (extra: Record<string, unknown>): Record<string, unknown> =>
      resultsWith({
        poams: [
          {
            type: 'remediation',
            explanation: 'Patch deployment scheduled pending vendor fix.',
            appliedBy: { type: 'email', identifier: 'ops@agency.gov' },
            appliedAt: '2026-01-20T10:00:00Z',
            ...extra,
          },
        ],
      });

    it('rejects a POA&M without expiresAt', () => {
      const result = validateResults(poam({}));
      expect(result.valid).toBe(false);
      expect(result.getErrorMessage()).toContain('expiresAt');
    });

    it('accepts a POA&M with expiresAt', () => {
      const result = validateResults(poam({ expiresAt: '2099-12-31T00:00:00Z' }));
      expect(result.valid).toBe(true);
    });
  });

  // Shared shape asserted identically by the Go and TS validator suites: a
  // requirement carrying amendment fields (effectiveStatus, disposition,
  // statusOverrides, poams) and vulnerability fields (cwe, cvss, refs) together.
  // Keep its fields and values in sync with amendmentAndVulnRequirementFields in validators_test.go.
  describe('amendment + vulnerability fields on one requirement', () => {
    it('validates a requirement carrying both amendment and vuln fields', () => {
      const doc = resultsWith({
        effectiveStatus: 'failed',
        disposition: 'poam',
        statusOverrides: [
          {
            type: 'riskAdjustment',
            impact: { value: 0.4 },
            reason: 'Environmental exposure reduced — internal VPN only.',
            appliedBy: { type: 'simple', identifier: 'sec' },
            appliedAt: '2025-01-01T00:00:00Z',
            expiresAt: '2099-12-31T00:00:00Z',
          },
        ],
        poams: [
          {
            type: 'remediation',
            explanation: 'Patch deployment scheduled pending vendor fix.',
            appliedBy: { type: 'simple', identifier: 'ops' },
            appliedAt: '2025-01-01T00:00:00Z',
            expiresAt: '2099-12-31T00:00:00Z',
          },
        ],
        cwe: ['CWE-327'],
        cvss: [{ version: '3.1', baseScore: 7.5, baseSeverity: 'high' }],
        refs: [{ url: 'https://example.gov/advisory' }],
      });

      const result = validateResults(doc);
      expect(result.valid, result.getErrorMessage()).toBe(true);
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

// ---------------------------------------------------------------------------
// CVE-ecosystem primitives (Cvss, Epss, Kev, AffectedPackage, cwe[]).
// Wave 1 of epic hdf-libs-8zn0 / bead hdf-libs-tilc.
//
// These tests exercise the validator integration: real bundled schemas + real
// Ajv setup + real HDF document shape. A failure here indicates either a
// schema or a wiring bug, not a test setup bug — flag, do not paper over.
// ---------------------------------------------------------------------------

describe('CVE-ecosystem: cvss[]', () => {
  describe('Accepts', () => {
    it('accepts a full Base+Threat+Environmental CVSS entry', () => {
      const data = resultsWith({
        cvss: [
          {
            version: '3.1',
            source: 'CVE-2024-3094',
            baseVector: 'CVSS:3.1/AV:L/AC:H/PR:H/UI:N/S:U/C:H/I:H/A:H',
            baseScore: 6.7,
            baseSeverity: 'medium',
            threatVector: 'E:A/RL:O/RC:C',
            threatScore: 6.5,
            environmentalVector: 'MAV:N/CR:H/IR:H/AR:H',
            environmentalScore: 9.0,
            computedScore: 9.0,
            computedSeverity: 'critical',
          },
        ],
      });
      const result = validateResults(data);
      expect(result.valid).toBe(true);
      expect(result.errors).toEqual([]);
    });

    it('accepts multiple CVSS entries on one requirement (Nessus plugin → multiple CVEs)', () => {
      const data = resultsWith({
        cvss: [
          {
            version: '3.1',
            source: 'CVE-2024-12345',
            baseVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
            baseScore: 9.8,
            baseSeverity: 'critical',
          },
          {
            version: '3.1',
            source: 'CVE-2024-12346',
            baseVector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N',
            baseScore: 4.7,
            baseSeverity: 'medium',
          },
          {
            version: '2.0',
            source: 'CVE-2014-0160',
            baseVector: 'AV:N/AC:L/Au:N/C:P/I:N/A:N',
            baseScore: 5.0,
          },
        ],
      });
      const result = validateResults(data);
      expect(result.valid).toBe(true);
      expect(result.errors).toEqual([]);
    });
  });

  describe('Rejects', () => {
    it('rejects a malformed baseVector string', () => {
      const data = resultsWith({
        cvss: [
          {
            version: '3.1',
            source: 'CVE-2024-12345',
            baseVector: 'not a vector',
            baseScore: 9.8,
          },
        ],
      });
      const result = validateResults(data);
      expect(result.valid).toBe(false);
      expect(
        result.errors.some(
          e => e.field.includes('baseVector') || e.message.toLowerCase().includes('pattern'),
        ),
      ).toBe(true);
    });

    it('rejects a CVSS entry missing the required version field', () => {
      const data = resultsWith({
        cvss: [
          {
            source: 'CVE-2024-12345',
            baseVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
            baseScore: 9.8,
          },
        ],
      });
      const result = validateResults(data);
      expect(result.valid).toBe(false);
      expect(result.errors.some(e => e.field.includes('version'))).toBe(true);
    });

    it('rejects a baseScore outside 0.0–10.0', () => {
      const data = resultsWith({
        cvss: [
          {
            version: '3.1',
            baseVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
            baseScore: 12.5,
          },
        ],
      });
      const result = validateResults(data);
      expect(result.valid).toBe(false);
      expect(result.errors.some(e => e.field.includes('baseScore'))).toBe(true);
    });
  });
});

describe('CVE-ecosystem: epss', () => {
  describe('Accepts', () => {
    it('accepts a fully-populated EPSS object', () => {
      const data = resultsWith({
        epss: { score: 0.97532, percentile: 0.99987, date: '2026-05-26' },
      });
      const result = validateResults(data);
      expect(result.valid).toBe(true);
      expect(result.errors).toEqual([]);
    });
  });

  describe('Rejects', () => {
    it('rejects EPSS score above 1.0', () => {
      const data = resultsWith({
        epss: { score: 1.5, percentile: 0.5, date: '2026-05-26' },
      });
      const result = validateResults(data);
      expect(result.valid).toBe(false);
      expect(result.errors.some(e => e.field.includes('score'))).toBe(true);
    });

    it('rejects EPSS score below 0.0', () => {
      const data = resultsWith({
        epss: { score: -0.1, percentile: 0.5, date: '2026-05-26' },
      });
      const result = validateResults(data);
      expect(result.valid).toBe(false);
      expect(result.errors.some(e => e.field.includes('score'))).toBe(true);
    });

    it('rejects EPSS missing the required date field', () => {
      const data = resultsWith({
        epss: { score: 0.5, percentile: 0.5 },
      });
      const result = validateResults(data);
      expect(result.valid).toBe(false);
      expect(result.errors.some(e => e.field.includes('date'))).toBe(true);
    });

    it('rejects EPSS percentile outside 0.0–1.0', () => {
      const data = resultsWith({
        epss: { score: 0.5, percentile: 1.01, date: '2026-05-26' },
      });
      const result = validateResults(data);
      expect(result.valid).toBe(false);
      expect(result.errors.some(e => e.field.includes('percentile'))).toBe(true);
    });
  });
});

describe('CVE-ecosystem: kev', () => {
  describe('Accepts', () => {
    it('accepts inKev:true with required dateAdded + dueDate', () => {
      const data = resultsWith({
        kev: {
          inKev: true,
          dateAdded: '2026-03-15',
          dueDate: '2026-04-05',
          notes: 'Active ransomware exploitation observed.',
        },
      });
      const result = validateResults(data);
      expect(result.valid).toBe(true);
      expect(result.errors).toEqual([]);
    });

    it('accepts inKev:false without dateAdded/dueDate (conditional-required test)', () => {
      const data = resultsWith({ kev: { inKev: false } });
      const result = validateResults(data);
      expect(result.valid).toBe(true);
      expect(result.errors).toEqual([]);
    });
  });

  describe('Rejects', () => {
    it('rejects inKev:true with missing dateAdded', () => {
      const data = resultsWith({
        kev: { inKev: true, dueDate: '2026-04-05' },
      });
      const result = validateResults(data);
      expect(result.valid).toBe(false);
      expect(result.errors.some(e => e.field.includes('dateAdded'))).toBe(true);
    });

    it('rejects inKev:true with missing dueDate', () => {
      const data = resultsWith({
        kev: { inKev: true, dateAdded: '2026-03-15' },
      });
      const result = validateResults(data);
      expect(result.valid).toBe(false);
      expect(result.errors.some(e => e.field.includes('dueDate'))).toBe(true);
    });
  });
});

describe('CVE-ecosystem: cwe[]', () => {
  describe('Accepts', () => {
    it('accepts three valid CWE IDs', () => {
      const data = resultsWith({ cwe: ['CWE-79', 'CWE-89', 'CWE-352'] });
      const result = validateResults(data);
      expect(result.valid).toBe(true);
      expect(result.errors).toEqual([]);
    });

    it('accepts an empty cwe array (no CWEs assigned)', () => {
      const data = resultsWith({ cwe: [] });
      const result = validateResults(data);
      expect(result.valid).toBe(true);
      expect(result.errors).toEqual([]);
    });
  });

  describe('Rejects', () => {
    it('rejects lowercase cwe-79', () => {
      const data = resultsWith({ cwe: ['cwe-79'] });
      const result = validateResults(data);
      expect(result.valid).toBe(false);
      expect(
        result.errors.some(e => e.field.includes('cwe') || e.message.toLowerCase().includes('pattern')),
      ).toBe(true);
    });

    it('rejects bare numeric "79" with no CWE- prefix', () => {
      const data = resultsWith({ cwe: ['79'] });
      const result = validateResults(data);
      expect(result.valid).toBe(false);
      expect(
        result.errors.some(e => e.field.includes('cwe') || e.message.toLowerCase().includes('pattern')),
      ).toBe(true);
    });

    it('rejects CWE-0 (zero is not a valid CWE ID)', () => {
      const data = resultsWith({ cwe: ['CWE-0'] });
      const result = validateResults(data);
      expect(result.valid).toBe(false);
      expect(
        result.errors.some(e => e.field.includes('cwe') || e.message.toLowerCase().includes('pattern')),
      ).toBe(true);
    });

    it('rejects CWE-079 (leading-zero formatting)', () => {
      const data = resultsWith({ cwe: ['CWE-079'] });
      const result = validateResults(data);
      expect(result.valid).toBe(false);
      expect(
        result.errors.some(e => e.field.includes('cwe') || e.message.toLowerCase().includes('pattern')),
      ).toBe(true);
    });
  });
});

describe('CVE-ecosystem: affectedPackages[]', () => {
  describe('Accepts', () => {
    it('accepts rpm + npm + maven entries together', () => {
      const data = resultsWith({
        affectedPackages: [
          {
            name: 'openssl',
            version: '1.1.1k-7.el8_4',
            ecosystem: 'rpm',
            cpe: 'cpe:2.3:a:openssl:openssl:1.1.1k:*:*:*:*:*:*:*',
            purl: 'pkg:rpm/redhat/openssl@1.1.1k-7.el8_4?arch=x86_64',
            fixedInVersion: '1.1.1l',
          },
          {
            name: 'lodash',
            version: '4.17.20',
            ecosystem: 'npm',
            purl: 'pkg:npm/lodash@4.17.20',
            fixedInVersion: '4.17.21',
          },
          {
            name: 'org.apache.logging.log4j:log4j-core',
            version: '2.14.1',
            ecosystem: 'maven',
            cpe: 'cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*',
            purl: 'pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1',
            fixedInVersion: '2.17.1',
          },
        ],
      });
      const result = validateResults(data);
      expect(result.valid).toBe(true);
      expect(result.errors).toEqual([]);
    });
  });

  describe('Rejects', () => {
    it('rejects an AffectedPackage missing the required ecosystem field', () => {
      const data = resultsWith({
        affectedPackages: [{ name: 'openssl', version: '1.1.1k' }],
      });
      const result = validateResults(data);
      expect(result.valid).toBe(false);
      expect(result.errors.some(e => e.field.includes('ecosystem'))).toBe(true);
    });

    it('rejects an AffectedPackage with a CPE missing the "cpe:2.3:" prefix', () => {
      const data = resultsWith({
        affectedPackages: [
          {
            name: 'openssl',
            version: '1.1.1k',
            ecosystem: 'rpm',
            cpe: 'openssl:1.0',
          },
        ],
      });
      const result = validateResults(data);
      expect(result.valid).toBe(false);
      expect(
        result.errors.some(e => e.field.includes('cpe') || e.message.toLowerCase().includes('pattern')),
      ).toBe(true);
    });

    it('rejects an AffectedPackage with a PURL missing the "pkg:" prefix', () => {
      const data = resultsWith({
        affectedPackages: [
          {
            name: 'foo',
            version: '1.0',
            ecosystem: 'npm',
            purl: 'foo@1.0',
          },
        ],
      });
      const result = validateResults(data);
      expect(result.valid).toBe(false);
      expect(
        result.errors.some(e => e.field.includes('purl') || e.message.toLowerCase().includes('pattern')),
      ).toBe(true);
    });

    it('rejects an AffectedPackage with an unknown ecosystem enum value', () => {
      const data = resultsWith({
        affectedPackages: [
          { name: 'thing', version: '1.0', ecosystem: 'snapcraft' },
        ],
      });
      const result = validateResults(data);
      expect(result.valid).toBe(false);
      expect(
        result.errors.some(e => e.field.includes('ecosystem') || e.message.toLowerCase().includes('enum')),
      ).toBe(true);
    });
  });
});

describe('CVE-ecosystem: Status_Override.cvss', () => {
  it('accepts a riskAdjustment Status_Override with an attached cvss block', () => {
    const data = resultsWith({
      overrides: [
        {
          type: 'riskAdjustment',
          impact: { value: 0.5 },
          reason: 'Environmental exposure reduced — service reachable only via internal VPN.',
          appliedBy: { type: 'email', identifier: 'sec@org.gov' },
          appliedAt: '2026-04-14T10:00:00Z',
          expiresAt: '2026-10-14T00:00:00Z',
          cvss: {
            version: '3.1',
            source: 'CVE-2024-12345',
            baseVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
            baseScore: 9.8,
            baseSeverity: 'critical',
            environmentalVector: 'MAV:A/CR:M/IR:M/AR:M',
            environmentalScore: 5.0,
            computedScore: 5.0,
            computedSeverity: 'medium',
          },
        },
      ],
    });
    const result = validateResults(data);
    expect(result.valid).toBe(true);
    expect(result.errors).toEqual([]);
  });
});

describe('CVE-ecosystem: Standalone_Override.cvss in an amendments document', () => {
  it('accepts a riskAdjustment Standalone_Override with an attached cvss block', () => {
    const doc = {
      name: 'CVE-Ecosystem Amendments',
      overrides: [
        {
          type: 'riskAdjustment',
          requirementId: 'CVE-2024-12345',
          baselineRef: 'Test',
          impact: { value: 0.5 },
          reason: 'Environmental enrichment — internal-only exposure reduces base score.',
          appliedBy: { type: 'email', identifier: 'sec@org.gov' },
          appliedAt: '2026-04-14T10:00:00Z',
          expiresAt: '2026-10-14T00:00:00Z',
          cvss: {
            version: '3.1',
            source: 'CVE-2024-12345',
            baseVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
            baseScore: 9.8,
            baseSeverity: 'critical',
            environmentalVector: 'MAV:A/CR:M/IR:M/AR:M',
            environmentalScore: 5.0,
            computedScore: 5.0,
            computedSeverity: 'medium',
          },
        },
      ],
    };
    const result = validateAmendments(doc);
    expect(result.valid).toBe(true);
    expect(result.errors).toEqual([]);
  });
});

describe('HDF Requirement Change Event Validation', () => {
  const validEvent = {
    eventId: '0190f6f2-1c4e-7c3a-9f2a-3b1d5e7a9c01',
    source: 'inspec://web01/rhel9-stig',
    sequence: 412,
    systemRef: 'apptier.hdf-system.json',
    componentId: '6e0f2a3b-9c01-4d5e-8f7a-1b2c3d4e5f60',
    timestamp: '2026-07-22T14:03:11Z',
    priorChecksum: {
      algorithm: 'sha256',
      value: '704f62b2d0803438ad6b7b9bab45e2c4f350b7344135a2a7f8ef986d98669021',
    },
    requirementId: 'RHEL-09-255065',
    state: 'fixed',
    changeReasons: ['resultChanged'],
    before: { effectiveStatus: 'failed', effectiveImpact: 0.5 },
    after: {
      id: 'RHEL-09-255065',
      impact: 0.5,
      tags: {},
      descriptions: [{ label: 'default', data: 'SSH FIPS ciphers' }],
      results: [
        { status: 'passed', codeDesc: 'ciphers ok', startTime: '2026-07-22T14:03:11Z' },
      ],
    },
  };

  it('validates a well-formed change event', () => {
    const result = validateRequirementChangeEvent(validEvent);
    expect(result.valid, JSON.stringify(result.errors)).toBe(true);
  });

  it('rejects null after on a non-absent state', () => {
    const result = validateRequirementChangeEvent({ ...validEvent, after: null });
    expect(result.valid).toBe(false);
  });

  it('rejects a batch-only state', () => {
    const result = validateRequirementChangeEvent({ ...validEvent, state: 'split' });
    expect(result.valid).toBe(false);
  });
});
