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
        targets: [{ type: 'container_image', name: 'nginx:latest', image_id: 'sha256:abc123' }],
      });
      expect(validate(doc)).toBe(true);
    });

    it('should accept cloud_account target', () => {
      const doc = createMinimalResultsDoc({
        targets: [{ type: 'cloud_account', name: 'prod-aws', provider: 'aws', account_id: '123456789012' }],
      });
      expect(validate(doc)).toBe(true);
    });

    it('should accept multiple targets of different types', () => {
      const doc = createMinimalResultsDoc({
        targets: [
          { type: 'host', name: 'server-01' },
          { type: 'container_image', name: 'app:v1', image_id: 'sha256:xyz' },
          { type: 'database', name: 'prod-db', engine: 'postgresql' },
        ],
      });
      expect(validate(doc)).toBe(true);
    });
  });

  describe('profiles array (Evaluated_Baseline)', () => {
    it('should validate profile with minimal required fields', () => {
      const doc = createMinimalResultsDoc({ profiles: [createMinimalEvaluatedBaseline()] });
      expect(validate(doc)).toBe(true);
    });

    it('should validate profile with sha256 only', () => {
      const doc = createMinimalResultsDoc({
        profiles: [createMinimalEvaluatedBaseline()],
      });
      expect(validate(doc)).toBe(true);
    });

    it('should validate profile with sha512 only', () => {
      const profile = {
        name: 'test-baseline',
        supports: [],
        attributes: [],
        groups: [],
        controls: [],
        sha512: 'longer-sha512-hash-value',
      };
      const doc = createMinimalResultsDoc({ profiles: [profile] });
      expect(validate(doc)).toBe(true);
    });

    it('should validate profile with both sha256 and sha512', () => {
      const doc = createMinimalResultsDoc({
        profiles: [createMinimalEvaluatedBaseline({ sha512: 'def456789' })],
      });
      expect(validate(doc)).toBe(true);
    });

    it('should reject profile with neither sha256 nor sha512', () => {
      const profile = {
        name: 'test-baseline',
        supports: [],
        attributes: [],
        groups: [],
        controls: [],
      };
      const doc = createMinimalResultsDoc({ profiles: [profile] });
      expect(validate(doc)).toBe(false);
    });

    it('should validate profile with full metadata', () => {
      const doc = createMinimalResultsDoc({
        profiles: [
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

  describe('controls array (Evaluated_Requirement)', () => {
    it('should validate control with minimal required fields', () => {
      const doc = createMinimalResultsDoc({
        profiles: [createMinimalEvaluatedBaseline({ controls: [createMinimalControl()] })],
      });
      expect(validate(doc)).toBe(true);
    });

    it('should validate control without refs (refs is optional)', () => {
      const control = createMinimalControl();
      expect(control).not.toHaveProperty('refs');
      const doc = createMinimalResultsDoc({
        profiles: [createMinimalEvaluatedBaseline({ controls: [control] })],
      });
      expect(validate(doc)).toBe(true);
    });

    it('should validate control with refs array', () => {
      const doc = createMinimalResultsDoc({
        profiles: [
          createMinimalEvaluatedBaseline({
            controls: [createMinimalControl({ refs: [{ url: 'https://example.com' }] })],
          }),
        ],
      });
      expect(validate(doc)).toBe(true);
    });

    it('should validate control with null refs', () => {
      const doc = createMinimalResultsDoc({
        profiles: [
          createMinimalEvaluatedBaseline({
            controls: [createMinimalControl({ refs: null })],
          }),
        ],
      });
      expect(validate(doc)).toBe(true);
    });

    it('should validate control with overall_status field', () => {
      const doc = createMinimalResultsDoc({
        profiles: [
          createMinimalEvaluatedBaseline({
            controls: [
              createMinimalControl({
                results: [createMinimalResult({ status: 'passed' })],
                overall_status: 'passed',
              }),
            ],
          }),
        ],
      });
      expect(validate(doc)).toBe(true);
    });

    it('should validate control with waiver_data', () => {
      const doc = createMinimalResultsDoc({
        profiles: [
          createMinimalEvaluatedBaseline({
            controls: [
              createMinimalControl({
                waiver_data: { expiration_date: '2026-01-01', justification: 'Compensating control' },
              }),
            ],
          }),
        ],
      });
      expect(validate(doc)).toBe(true);
    });

    it('should validate control with attestation_data', () => {
      const doc = createMinimalResultsDoc({
        profiles: [
          createMinimalEvaluatedBaseline({
            controls: [
              createMinimalControl({
                attestation_data: {
                  control_id: 'SV-238196',
                  explanation: 'Manually verified',
                  frequency: 'annually',
                  status: 'passed',
                  updated: '2025-11-25',
                  updated_by: 'security-team@example.com',
                },
                overall_status: 'passed',
              }),
            ],
          }),
        ],
      });
      expect(validate(doc)).toBe(true);
    });

    it('should validate control with descriptions array', () => {
      const doc = createMinimalResultsDoc({
        profiles: [
          createMinimalEvaluatedBaseline({
            controls: [
              createMinimalControl({
                title: 'SSH MaxAuthTries must be set to 4 or less',
                descriptions: [
                  { label: 'fix', data: 'Set MaxAuthTries to 4' },
                  { label: 'check', data: 'Verify MaxAuthTries' },
                ],
              }),
            ],
          }),
        ],
      });
      expect(validate(doc)).toBe(true);
    });
  });

  describe('results array (Requirement_Result)', () => {
    it('should validate result with minimal required fields', () => {
      const doc = createMinimalResultsDoc({
        profiles: [
          createMinimalEvaluatedBaseline({
            controls: [createMinimalControl({ results: [createMinimalResult()] })],
          }),
        ],
      });
      expect(validate(doc)).toBe(true);
    });

    it('should validate all status values', () => {
      const statuses = ['passed', 'failed', 'not_applicable', 'not_reviewed', 'error'];
      for (const status of statuses) {
        const doc = createMinimalResultsDoc({
          profiles: [
            createMinimalEvaluatedBaseline({
              controls: [createMinimalControl({ results: [createMinimalResult({ status })] })],
            }),
          ],
        });
        expect(validate(doc)).toBe(true);
      }
    });

    it('should accept deprecated skipped status for backward compatibility', () => {
      const doc = createMinimalResultsDoc({
        profiles: [
          createMinimalEvaluatedBaseline({
            controls: [createMinimalControl({ results: [createMinimalResult({ status: 'skipped' })] })],
          }),
        ],
      });
      expect(validate(doc)).toBe(true);
    });

    it('should reject invalid status value', () => {
      const doc = createMinimalResultsDoc({
        profiles: [
          createMinimalEvaluatedBaseline({
            controls: [createMinimalControl({ results: [createMinimalResult({ status: 'unknown' })] })],
          }),
        ],
      });
      expect(validate(doc)).toBe(false);
    });

    it('should validate result with full details', () => {
      const doc = createMinimalResultsDoc({
        profiles: [
          createMinimalEvaluatedBaseline({
            controls: [
              createMinimalControl({
                results: [
                  createMinimalResult({
                    status: 'failed',
                    run_time: 0.023,
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
          controls: {
            passed: { total: 50 },
            failed: { total: 5 },
            not_applicable: { total: 10 },
            not_reviewed: { total: 3 },
            error: { total: 1 },
          },
        },
      });
      expect(validate(doc)).toBe(true);
    });
  });

  describe('backward compatibility', () => {
    it('should accept legacy InSpec output structure (inline)', () => {
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
                source_location: { ref: 'controls/ssh.rb', line: 10 },
                results: [{ code_desc: 'SSH configured', start_time: '2025-11-25T12:00:00Z', status: 'passed' }],
              },
            ],
          },
        ],
        statistics: { duration: 10.5, controls: { passed: { total: 1 }, failed: null } },
        version: '5.22.3',
      };
      expect(validate(legacyDoc)).toBe(true);
    });

    it('should validate real InSpec exec-json file from heimdall2', () => {
      // This is an actual InSpec output file from the heimdall2 sample data
      const realInspecOutput = loadFixture('legacy-inspec-exec.json');
      const isValid = validate(realInspecOutput);
      if (!isValid) {
        console.error('Validation errors:', JSON.stringify(validate.errors, null, 2));
      }
      expect(isValid).toBe(true);
    });
  });
});
