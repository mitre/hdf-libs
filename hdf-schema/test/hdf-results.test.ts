import { describe, it, expect, beforeAll } from 'vitest';
import Ajv from 'ajv';
import {
  createAjvWithPrimitives,
  loadSchema,
  loadFixture,
  createMinimalResultsDoc,
  createMinimalEvaluatedBaseline,
  createMinimalControl,
  createMinimalResult,
} from './setup';

describe('hdf-results.schema.json (refactored)', () => {
  let ajv: Ajv;
  let validate: ReturnType<Ajv['compile']>;

  beforeAll(() => {
    ajv = createAjvWithPrimitives();
    validate = ajv.compile(loadSchema('hdf-results.schema.json'));
  });

  describe('root-level structure', () => {
    it('should validate a minimal valid document', () => {
      const isValid = validate(createMinimalResultsDoc());
      expect(isValid).toBe(true);
      expect(validate.errors).toBeNull();
    });

    it('should reject document missing required fields', () => {
      const invalidDoc = { platform: { name: 'ubuntu', release: '20.04' } };
      expect(validate(invalidDoc)).toBe(false);
      expect(validate.errors).not.toBeNull();
    });

    it('should accept optional id field with UUID format', () => {
      const doc = createMinimalResultsDoc({ id: '550e8400-e29b-41d4-a716-446655440000' });
      expect(validate(doc)).toBe(true);
    });

    it('should accept optional timestamp field', () => {
      const doc = createMinimalResultsDoc({ timestamp: '2025-11-25T12:00:00Z' });
      expect(validate(doc)).toBe(true);
    });

    it('should accept optional generator field', () => {
      const doc = createMinimalResultsDoc({
        generator: { name: 'Chef InSpec', version: '5.22.3' },
      });
      expect(validate(doc)).toBe(true);
    });

    it('should accept optional integrity field', () => {
      const doc = createMinimalResultsDoc({
        integrity: { algorithm: 'sha256', checksum: 'abc123def456' },
      });
      expect(validate(doc)).toBe(true);
    });

    it('should accept optional runner field', () => {
      const doc = createMinimalResultsDoc({
        runner: { name: 'ubuntu', release: '20.04', architecture: 'x86_64' },
      });
      expect(validate(doc)).toBe(true);
    });

    it('should accept minimal runner with only name', () => {
      const doc = createMinimalResultsDoc({
        runner: { name: 'ubuntu' },
      });
      expect(validate(doc)).toBe(true);
    });

    it('should accept runner with hostname', () => {
      const doc = createMinimalResultsDoc({
        runner: { name: 'ubuntu', hostname: 'ci-runner-01' },
      });
      expect(validate(doc)).toBe(true);
    });
  });

  describe('targets array (new field)', () => {
    it('should accept empty targets array', () => {
      expect(validate(createMinimalResultsDoc({ targets: [] }))).toBe(true);
    });

    it('should accept host target', () => {
      const doc = createMinimalResultsDoc({
        targets: [{ type: 'host', name: 'web-server-01', fqdn: 'web-server-01.example.com' }],
      });
      expect(validate(doc)).toBe(true);
    });

    it('should accept container_image target', () => {
      const doc = createMinimalResultsDoc({
        targets: [{ type: 'containerImage', name: 'nginx:latest', image_id: 'sha256:abc123' }],
      });
      expect(validate(doc)).toBe(true);
    });

    it('should accept cloud_account target', () => {
      const doc = createMinimalResultsDoc({
        targets: [{ type: 'cloudAccount', name: 'prod-aws', provider: 'aws', account_id: '123456789012' }],
      });
      expect(validate(doc)).toBe(true);
    });

    it('should accept multiple targets of different types', () => {
      const doc = createMinimalResultsDoc({
        targets: [
          { type: 'host', name: 'server-01' },
          { type: 'containerImage', name: 'app:v1', image_id: 'sha256:xyz' },
          { type: 'database', name: 'prod-db', engine: 'postgresql' },
        ],
      });
      expect(validate(doc)).toBe(true);
    });
  });

  describe('baselines array (Evaluated_Baseline)', () => {
    it('should validate baseline with minimal required fields', () => {
      const doc = createMinimalResultsDoc({ baselines: [createMinimalEvaluatedBaseline()] });
      expect(validate(doc)).toBe(true);
    });

    it('should validate baseline with sha256 only', () => {
      const doc = createMinimalResultsDoc({
        baselines: [createMinimalEvaluatedBaseline()],
      });
      expect(validate(doc)).toBe(true);
    });

    it('should validate baseline with sha512 checksum', () => {
      const baseline = {
        name: 'test-baseline',
        supports: [],
        attributes: [],
        groups: [],
        requirements: [],
        checksum: { algorithm: 'sha512', value: 'longer-sha512-hash-value' },
      };
      const doc = createMinimalResultsDoc({ baselines: [baseline] });
      expect(validate(doc)).toBe(true);
    });

    it('should validate baseline with sha384 checksum', () => {
      const doc = createMinimalResultsDoc({
        baselines: [createMinimalEvaluatedBaseline({
          checksum: { algorithm: 'sha384', value: 'sha384-value' }
        })],
      });
      expect(validate(doc)).toBe(true);
    });

    it('should reject baseline without checksum', () => {
      const baseline = {
        name: 'test-baseline',
        supports: [],
        attributes: [],
        groups: [],
        requirements: [],
      };
      const doc = createMinimalResultsDoc({ baselines: [baseline] });
      expect(validate(doc)).toBe(false);
    });

    it('should validate baseline with full metadata', () => {
      const doc = createMinimalResultsDoc({
        baselines: [
          createMinimalEvaluatedBaseline({
            title: 'Ubuntu 20.04 STIG Baseline',
            maintainer: 'ACME Corp',
            license: 'Apache-2.0',
            version: '1.0.0',
            groups: [{ id: 'controls/ssh.rb', requirements: ['SV-238196'] }],
          }),
        ],
      });
      expect(validate(doc)).toBe(true);
    });
  });

  describe('requirements array (Evaluated_Requirement)', () => {
    it('should validate control with minimal required fields', () => {
      const doc = createMinimalResultsDoc({
        baselines: [createMinimalEvaluatedBaseline({ requirements: [createMinimalControl()] })],
      });
      expect(validate(doc)).toBe(true);
    });

    it('should reject control without descriptions array', () => {
      const control = {
        id: 'SV-238196',
        impact: 0.7,
        tags: {},
        sourceLocation: {},
        results: [],
        // Missing descriptions array
      };
      const doc = createMinimalResultsDoc({
        baselines: [createMinimalEvaluatedBaseline({ requirements: [control] })],
      });
      expect(validate(doc)).toBe(false);
      expect(validate.errors).toMatchObject([
        expect.objectContaining({
          message: expect.stringMatching(/required|missing/i),
          params: expect.objectContaining({ missingProperty: 'descriptions' }),
        }),
      ]);
    });

    it('should reject control with empty descriptions array', () => {
      const control = createMinimalControl({ descriptions: [] });
      const doc = createMinimalResultsDoc({
        baselines: [createMinimalEvaluatedBaseline({ requirements: [control] })],
      });
      expect(validate(doc)).toBe(false);
      expect(validate.errors).toBeDefined();
      expect(validate.errors?.[0].keyword).toBe('minItems');
      expect(validate.errors?.[0].message).toMatch(/must NOT have fewer than 1 items/i);
    });

    it('should validate control with descriptions array containing default label', () => {
      const control = createMinimalControl({
        descriptions: [{ label: 'default', data: 'This is the main description' }],
      });
      const doc = createMinimalResultsDoc({
        baselines: [createMinimalEvaluatedBaseline({ requirements: [control] })],
      });
      expect(validate(doc)).toBe(true);
    });

    it('should validate control with multiple labeled descriptions', () => {
      const control = createMinimalControl({
        descriptions: [
          { label: 'default', data: 'Main vulnerability discussion' },
          { label: 'check', data: 'Verification steps...' },
          { label: 'fix', data: 'Remediation steps...' },
          { label: 'rationale', data: 'Why this matters...' },
        ],
      });
      const doc = createMinimalResultsDoc({
        baselines: [createMinimalEvaluatedBaseline({ requirements: [control] })],
      });
      expect(validate(doc)).toBe(true);
    });

    it('should validate custom description labels', () => {
      const control = createMinimalControl({
        descriptions: [
          { label: 'default', data: 'Main description' },
          { label: 'custom_label', data: 'Tool-specific description' },
          { label: 'another-label', data: 'Another custom description' },
        ],
      });
      const doc = createMinimalResultsDoc({
        baselines: [createMinimalEvaluatedBaseline({ requirements: [control] })],
      });
      expect(validate(doc)).toBe(true);
    });

    it('should validate control without refs (refs is optional)', () => {
      const control = createMinimalControl();
      expect(control).not.toHaveProperty('refs');
      const doc = createMinimalResultsDoc({
        baselines: [createMinimalEvaluatedBaseline({ requirements: [control] })],
      });
      expect(validate(doc)).toBe(true);
    });

    it('should validate control with refs array', () => {
      const doc = createMinimalResultsDoc({
        baselines: [
          createMinimalEvaluatedBaseline({
            requirements: [createMinimalControl({ refs: [{ url: 'https://example.com' }] })],
          }),
        ],
      });
      expect(validate(doc)).toBe(true);
    });

    it('should validate control with null refs', () => {
      const doc = createMinimalResultsDoc({
        baselines: [
          createMinimalEvaluatedBaseline({
            requirements: [createMinimalControl({ refs: null })],
          }),
        ],
      });
      expect(validate(doc)).toBe(true);
    });

    it('should validate control with effectiveStatus field', () => {
      const doc = createMinimalResultsDoc({
        baselines: [
          createMinimalEvaluatedBaseline({
            requirements: [
              createMinimalControl({
                results: [createMinimalResult({ status: 'failed' })],
                effectiveStatus: 'notApplicable',
              }),
            ],
          }),
        ],
      });
      expect(validate(doc)).toBe(true);
    });

    it('should validate control with single waiver override', () => {
      const doc = createMinimalResultsDoc({
        baselines: [
          createMinimalEvaluatedBaseline({
            requirements: [
              createMinimalControl({
                results: [createMinimalResult({ status: 'failed' })],
                overrides: [
                  {
                    type: 'waiver',
                    status: 'notApplicable',
                    reason: 'Compensating controls in place',
                    appliedBy: 'isso@example.com',
                    appliedAt: '2025-12-05T10:00:00Z',
                    expiresAt: '2026-12-05T10:00:00Z',
                  },
                ],
                effectiveStatus: 'notApplicable',
              }),
            ],
          }),
        ],
      });
      expect(validate(doc)).toBe(true);
    });

    it('should validate control with single attestation override', () => {
      const doc = createMinimalResultsDoc({
        baselines: [
          createMinimalEvaluatedBaseline({
            requirements: [
              createMinimalControl({
                results: [createMinimalResult({ status: 'notReviewed' })],
                overrides: [
                  {
                    type: 'attestation',
                    status: 'passed',
                    reason: 'Manually verified by security team during audit',
                    appliedBy: 'security-team@example.com',
                    appliedAt: '2025-11-25T15:30:00Z',
                    expiresAt: '2026-11-25T15:30:00Z',
                  },
                ],
                effectiveStatus: 'passed',
              }),
            ],
          }),
        ],
      });
      expect(validate(doc)).toBe(true);
    });

    it('should validate control with multiple overrides (chronological history)', () => {
      const doc = createMinimalResultsDoc({
        baselines: [
          createMinimalEvaluatedBaseline({
            requirements: [
              createMinimalControl({
                results: [createMinimalResult({ status: 'failed' })],
                overrides: [
                  // Most recent override first
                  {
                    type: 'attestation',
                    status: 'failed',
                    reason: 'Re-evaluated, confirmed failure',
                    appliedBy: 'auditor@example.com',
                    appliedAt: '2025-12-10T14:00:00Z',
                    expiresAt: '2026-12-10T14:00:00Z',
                  },
                  // Earlier override
                  {
                    type: 'waiver',
                    status: 'notApplicable',
                    reason: 'Initially thought to be false positive',
                    appliedBy: 'engineer@example.com',
                    appliedAt: '2025-12-01T10:00:00Z',
                    expiresAt: '2026-12-01T10:00:00Z',
                  },
                ],
                effectiveStatus: 'failed', // Most recent override wins
              }),
            ],
          }),
        ],
      });
      expect(validate(doc)).toBe(true);
    });

    it('should validate control with override containing digital signature', () => {
      const doc = createMinimalResultsDoc({
        baselines: [
          createMinimalEvaluatedBaseline({
            requirements: [
              createMinimalControl({
                results: [createMinimalResult({ status: 'failed' })],
                overrides: [
                  {
                    type: 'waiver',
                    status: 'notApplicable',
                    reason: 'Risk accepted by CISO',
                    appliedBy: 'ciso@example.com',
                    appliedAt: '2025-12-05T16:00:00Z',
                    expiresAt: '2027-12-05T16:00:00Z',
                    signature: 'base64-encoded-digital-signature',
                  },
                ],
                effectiveStatus: 'notApplicable',
              }),
            ],
          }),
        ],
      });
      expect(validate(doc)).toBe(true);
    });

    it('should validate control with severity field', () => {
      const doc = createMinimalResultsDoc({
        baselines: [
          createMinimalEvaluatedBaseline({
            requirements: [createMinimalControl({ severity: 'high' })],
          }),
        ],
      });
      expect(validate(doc)).toBe(true);
    });

    it('should validate all severity values', () => {
      const severities = ['critical', 'high', 'medium', 'low', 'informational'];
      for (const severity of severities) {
        const doc = createMinimalResultsDoc({
          baselines: [
            createMinimalEvaluatedBaseline({
              requirements: [createMinimalControl({ severity })],
            }),
          ],
        });
        expect(validate(doc)).toBe(true);
      }
    });

    it('should reject invalid severity value', () => {
      const doc = createMinimalResultsDoc({
        baselines: [
          createMinimalEvaluatedBaseline({
            requirements: [createMinimalControl({ severity: 'unknown' })],
          }),
        ],
      });
      expect(validate(doc)).toBe(false);
    });
  });

  describe('results array (Requirement_Result)', () => {
    it('should validate result with minimal required fields', () => {
      const doc = createMinimalResultsDoc({
        baselines: [
          createMinimalEvaluatedBaseline({
            requirements: [createMinimalControl({ results: [createMinimalResult()] })],
          }),
        ],
      });
      expect(validate(doc)).toBe(true);
    });

    it('should validate all status values', () => {
      const statuses = ['passed', 'failed', 'notApplicable', 'notReviewed', 'error'];
      for (const status of statuses) {
        const doc = createMinimalResultsDoc({
          baselines: [
            createMinimalEvaluatedBaseline({
              requirements: [createMinimalControl({ results: [createMinimalResult({ status })] })],
            }),
          ],
        });
        expect(validate(doc)).toBe(true);
      }
    });

    it('should reject skipped status', () => {
      const doc = createMinimalResultsDoc({
        baselines: [
          createMinimalEvaluatedBaseline({
            requirements: [createMinimalControl({ results: [createMinimalResult({ status: 'skipped' })] })],
          }),
        ],
      });
      expect(validate(doc)).toBe(false);
      expect(validate.errors).toBeDefined();
      expect(validate.errors?.[0].message).toMatch(/must be equal to one of the allowed values/i);
    });

    it('should reject invalid status value', () => {
      const doc = createMinimalResultsDoc({
        baselines: [
          createMinimalEvaluatedBaseline({
            requirements: [createMinimalControl({ results: [createMinimalResult({ status: 'unknown' })] })],
          }),
        ],
      });
      expect(validate(doc)).toBe(false);
    });

    it('should validate result with full details', () => {
      const doc = createMinimalResultsDoc({
        baselines: [
          createMinimalEvaluatedBaseline({
            requirements: [
              createMinimalControl({
                results: [
                  createMinimalResult({
                    status: 'failed',
                    runTime: 0.023,
                    message: 'expected "MaxAuthTries 6" to match /MaxAuthTries\\s+4/',
                    resource: 'file',
                    resource_id: '/etc/ssh/sshd_config',
                    }),
                ],
              }),
            ],
          }),
        ],
      });
      expect(validate(doc)).toBe(true);
    });
  });

  describe('statistics', () => {
    it('should validate statistics with vendor-neutral status values', () => {
      const doc = createMinimalResultsDoc({
        statistics: {
          duration: 45.5,
          requirements: {
            passed: { total: 50 },
            failed: { total: 5 },
            notApplicable: { total: 10 },
            notReviewed: { total: 3 },
            error: { total: 1 },
          },
        },
      });
      expect(validate(doc)).toBe(true);
    });
  });

  describe('backward compatibility (v1 format)', () => {
    // NOTE: v1 files must be converted
    it.skip('should accept legacy InSpec output structure (inline) - REQUIRES CONVERTER', () => {
      const legacyDoc = {
        platform: { name: 'ubuntu', release: '20.04', target_id: 'web-server-01' },
        profiles: [
          {
            name: 'ubuntu-stig-baseline',
            sha256: 'abc123',
            supports: [{ 'platform-name': 'ubuntu' }],
            attributes: [{ name: 'input_var', options: { value: 'test' } }],
            groups: [{ id: 'controls/ssh.rb', controls: ['SV-238196'] }],
            controls: [
              {
                id: 'SV-238196',
                title: 'SSH must be configured',
                impact: 0.7,
                refs: [],
                tags: { severity: 'medium' },
                code: 'control "SV-238196" do\nend',
                sourceLocation: { ref: 'controls/ssh.rb', line: 10 },
                results: [{ codeDesc: 'SSH configured', startTime: '2025-11-25T12:00:00Z', status: 'passed' }],
              },
            ],
          },
        ],
        statistics: { duration: 10.5, controls: { passed: { total: 1 }, failed: null } },
        version: '5.22.3',
      };
      expect(validate(legacyDoc)).toBe(true);
    });

    it.skip('should validate real InSpec exec-json file from heimdall2 - REQUIRES CONVERTER', () => {
      const realInspecOutput = loadFixture('legacy-inspec-exec.json');
      const isValid = validate(realInspecOutput);
      if (!isValid) {
        console.error('Validation errors:', JSON.stringify(validate.errors, null, 2));
      }
      expect(isValid).toBe(true);
    });
  });
});
