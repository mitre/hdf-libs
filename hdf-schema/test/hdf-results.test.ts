import { describe, it, expect, beforeAll } from 'vitest';
import Ajv2020 from 'ajv/dist/2020.js';
import {
  createAjvWithPrimitives,
  loadSchema,
  loadFixture,
  createMinimalResultsDoc,
  createMinimalEvaluatedBaseline,
  createMinimalRequirement,
  createMinimalResult,
} from './setup';

describe('hdf-results.schema.json (refactored)', () => {
  let ajv: Ajv2020;
  let validate: ReturnType<Ajv2020['compile']>;

  beforeAll(() => {
    ajv = createAjvWithPrimitives();
    validate = ajv.compile(loadSchema('hdf-results.schema.json'));
  });

  describe('metaschema validation', () => {
    it('should validate hdf-results.schema.json against JSON Schema 2020-12 metaschema', () => {
      const schema = loadSchema('hdf-results.schema.json');
      const isValid = ajv.validateSchema(schema);
      if (!isValid) {
        console.error('Metaschema validation errors:', ajv.errors);
      }
      expect(isValid).toBe(true);
    });
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

    it('should accept tool with name and version', () => {
      const doc = createMinimalResultsDoc({
        tool: { name: 'gosec', version: '2.18.0' },
      });
      expect(validate(doc)).toBe(true);
    });

    it('should accept tool with name only', () => {
      const doc = createMinimalResultsDoc({
        tool: { name: 'AWS Config' },
      });
      expect(validate(doc)).toBe(true);
    });

    it('should accept tool with name, version, and format', () => {
      const doc = createMinimalResultsDoc({
        tool: { name: 'Semgrep', version: '1.45.0', format: 'SARIF' },
      });
      expect(validate(doc)).toBe(true);
    });

    it('should accept tool with format only (tool unknown)', () => {
      const doc = createMinimalResultsDoc({
        tool: { format: 'SARIF' },
      });
      expect(validate(doc)).toBe(true);
    });

    it('should accept tool as empty object (all fields optional)', () => {
      const doc = createMinimalResultsDoc({
        tool: {},
      });
      expect(validate(doc)).toBe(true);
    });

    it('should accept document with tool omitted entirely', () => {
      const doc = createMinimalResultsDoc();
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

  describe('extensions field (for tool-specific data)', () => {
    it('should accept extensions field with arbitrary data', () => {
      const doc = createMinimalResultsDoc({
        extensions: {
          auxiliary_data: [
            {
              name: 'SonarQube',
              data: { projectKey: 'my-app', version: '1.0.0' }
            }
          ]
        }
      });
      expect(validate(doc)).toBe(true);
    });

    it('should accept extensions with raw tool output', () => {
      const doc = createMinimalResultsDoc({
        extensions: {
          raw: { original: 'tool output here' },
          custom_field: 'any value'
        }
      });
      expect(validate(doc)).toBe(true);
    });

    it('should accept empty extensions object', () => {
      const doc = createMinimalResultsDoc({
        extensions: {}
      });
      expect(validate(doc)).toBe(true);
    });

    it('should reject invalid top-level custom fields', () => {
      const doc = createMinimalResultsDoc({});
      (doc as any).invalid_custom_field = 'should be rejected';
      expect(validate(doc)).toBe(false);
      expect(validate.errors).not.toBeNull();
    });
  });

  describe('components array (new field)', () => {
    it('should accept empty components array', () => {
      expect(validate(createMinimalResultsDoc({ components: [] }))).toBe(true);
    });

    it('should accept host component', () => {
      const doc = createMinimalResultsDoc({
        components: [{ type: 'host', name: 'web-server-01', fqdn: 'web-server-01.example.com' }],
      });
      expect(validate(doc)).toBe(true);
    });

    it('should accept container_image component', () => {
      const doc = createMinimalResultsDoc({
        components: [{ type: 'containerImage', name: 'nginx:latest', imageId: 'sha256:abc123' }],
      });
      expect(validate(doc)).toBe(true);
    });

    it('should accept cloud_account component', () => {
      const doc = createMinimalResultsDoc({
        components: [{ type: 'cloudAccount', name: 'prod-aws', provider: 'aws', accountId: '123456789012' }],
      });
      expect(validate(doc)).toBe(true);
    });

    it('should accept multiple components of different types', () => {
      const doc = createMinimalResultsDoc({
        components: [
          { type: 'host', name: 'server-01' },
          { type: 'containerImage', name: 'app:v1', imageId: 'sha256:xyz' },
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

    it('should validate baseline with sha512 integrity', () => {
      const baseline = {
        name: 'test-baseline',
        requirements: [createMinimalRequirement()],
        integrity: { algorithm: 'sha512', checksum: 'longer-sha512-hash-value' },
      };
      const doc = createMinimalResultsDoc({ baselines: [baseline] });
      expect(validate(doc)).toBe(true);
    });

    it('should validate baseline with sha384 integrity', () => {
      const doc = createMinimalResultsDoc({
        baselines: [createMinimalEvaluatedBaseline({
          integrity: { algorithm: 'sha384', checksum: 'sha384-value' }
        })],
      });
      expect(validate(doc)).toBe(true);
    });

    it('should accept baseline without integrity', () => {
      const baseline = {
        name: 'test-baseline',
        requirements: [createMinimalRequirement()],
      };
      const doc = createMinimalResultsDoc({ baselines: [baseline] });
      expect(validate(doc)).toBe(true);
    });

    it('should accept baseline without supports field', () => {
      const baseline = {
        name: 'test-baseline',
        requirements: [createMinimalRequirement()],
        integrity: { algorithm: 'sha256', checksum: 'abc123' },
      };
      const doc = createMinimalResultsDoc({ baselines: [baseline] });
      expect(validate(doc)).toBe(true);
    });

    it('should accept baseline without attributes field', () => {
      const baseline = {
        name: 'test-baseline',
        requirements: [createMinimalRequirement()],
        integrity: { algorithm: 'sha256', checksum: 'abc123' },
      };
      const doc = createMinimalResultsDoc({ baselines: [baseline] });
      expect(validate(doc)).toBe(true);
    });

    it('should accept baseline without groups field', () => {
      const baseline = {
        name: 'test-baseline',
        requirements: [createMinimalRequirement()],
        integrity: { algorithm: 'sha256', checksum: 'abc123' },
      };
      const doc = createMinimalResultsDoc({ baselines: [baseline] });
      expect(validate(doc)).toBe(true);
    });

    it('should accept baseline with supports field when provided', () => {
      const baseline = {
        name: 'test-baseline',
        requirements: [createMinimalRequirement()],
        integrity: { algorithm: 'sha256', checksum: 'abc123' },
        supports: [{ platformFamily: 'redhat', platformName: 'centos' }],
      };
      const doc = createMinimalResultsDoc({ baselines: [baseline] });
      expect(validate(doc)).toBe(true);
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

    it('should reject toolVersion field on baseline (removed in v2)', () => {
      const doc = createMinimalResultsDoc({
        baselines: [
          createMinimalEvaluatedBaseline({
            toolVersion: '5.22.3',
          } as any),
        ],
      });
      expect(validate(doc)).toBe(false);
    });

    it('should accept extensions field on baseline', () => {
      const doc = createMinimalResultsDoc({
        baselines: [
          createMinimalEvaluatedBaseline({
            extensions: {
              profile_metadata: { original_format: 'InSpec' },
              custom_data: 'any value'
            }
          })
        ]
      });
      expect(validate(doc)).toBe(true);
    });

    it('should accept baseline with originalChecksum', () => {
      const doc = createMinimalResultsDoc({
        baselines: [
          createMinimalEvaluatedBaseline({
            originalChecksum: {
              algorithm: 'sha256',
              value: 'abc123def456...',
            },
          }),
        ],
      });
      expect(validate(doc)).toBe(true);
    });

    it('should accept baseline with resultsChecksum', () => {
      const doc = createMinimalResultsDoc({
        baselines: [
          createMinimalEvaluatedBaseline({
            resultsChecksum: {
              algorithm: 'sha256',
              value: '789xyz012...',
            },
          }),
        ],
      });
      expect(validate(doc)).toBe(true);
    });

    it('should accept baseline with both originalChecksum and resultsChecksum', () => {
      const doc = createMinimalResultsDoc({
        baselines: [
          createMinimalEvaluatedBaseline({
            originalChecksum: {
              algorithm: 'sha256',
              value: 'abc123def456...',
            },
            resultsChecksum: {
              algorithm: 'sha256',
              value: '789xyz012...',
            },
          }),
        ],
      });
      expect(validate(doc)).toBe(true);
    });

    it('should reject baseline with explicit null originalChecksum', () => {
      const doc = createMinimalResultsDoc({
        baselines: [
          createMinimalEvaluatedBaseline({
            originalChecksum: null,
          }),
        ],
      });
      expect(validate(doc)).toBe(false);
    });

    it('should reject baseline with explicit null resultsChecksum', () => {
      const doc = createMinimalResultsDoc({
        baselines: [
          createMinimalEvaluatedBaseline({
            resultsChecksum: null,
          }),
        ],
      });
      expect(validate(doc)).toBe(false);
    });

    it('should accept baseline with parentBaseline', () => {
      const doc = createMinimalResultsDoc({
        baselines: [
          createMinimalEvaluatedBaseline({
            parentBaseline: 'rhel-9-baseline',
          }),
        ],
      });
      expect(validate(doc)).toBe(true);
    });

    it('should reject baseline with explicit null parentBaseline', () => {
      const doc = createMinimalResultsDoc({
        baselines: [
          createMinimalEvaluatedBaseline({
            parentBaseline: null,
          }),
        ],
      });
      expect(validate(doc)).toBe(false);
    });

    it('should accept baseline without parentBaseline field', () => {
      const doc = createMinimalResultsDoc({
        baselines: [createMinimalEvaluatedBaseline()],
      });
      expect(validate(doc)).toBe(true);
    });
  });

  describe('requirements array (Evaluated_Requirement)', () => {
    it('should validate requirement with minimal required fields', () => {
      const doc = createMinimalResultsDoc({
        baselines: [createMinimalEvaluatedBaseline({ requirements: [createMinimalRequirement()] })],
      });
      expect(validate(doc)).toBe(true);
    });

    it('should reject requirement without descriptions array', () => {
      const requirement = {
        id: 'SV-238196',
        impact: 0.7,
        tags: {},
        sourceLocation: {},
        results: [
          {
            status: 'passed',
            codeDesc: 'Test description',
            startTime: '2025-11-25T12:00:00Z',
          }
        ],
        // Missing descriptions array
      };
      const doc = createMinimalResultsDoc({
        baselines: [createMinimalEvaluatedBaseline({ requirements: [requirement] })],
      });
      expect(validate(doc)).toBe(false);
      expect(validate.errors).toMatchObject([
        expect.objectContaining({
          message: expect.stringMatching(/required|missing/i),
          params: expect.objectContaining({ missingProperty: 'descriptions' }),
        }),
      ]);
    });

    it('should reject requirement with empty descriptions array', () => {
      const requirement = createMinimalRequirement({ descriptions: [] });
      const doc = createMinimalResultsDoc({
        baselines: [createMinimalEvaluatedBaseline({ requirements: [requirement] })],
      });
      expect(validate(doc)).toBe(false);
      expect(validate.errors).toBeDefined();
      expect(validate.errors?.[0].keyword).toBe('minItems');
      expect(validate.errors?.[0].message).toMatch(/must NOT have fewer than 1 items/i);
    });

    it('should validate requirement with descriptions array containing default label', () => {
      const requirement = createMinimalRequirement({
        descriptions: [{ label: 'default', data: 'This is the main description' }],
      });
      const doc = createMinimalResultsDoc({
        baselines: [createMinimalEvaluatedBaseline({ requirements: [requirement] })],
      });
      expect(validate(doc)).toBe(true);
    });

    it('should validate requirement with multiple labeled descriptions', () => {
      const requirement = createMinimalRequirement({
        descriptions: [
          { label: 'default', data: 'Main vulnerability discussion' },
          { label: 'check', data: 'Verification steps...' },
          { label: 'fix', data: 'Remediation steps...' },
          { label: 'rationale', data: 'Why this matters...' },
        ],
      });
      const doc = createMinimalResultsDoc({
        baselines: [createMinimalEvaluatedBaseline({ requirements: [requirement] })],
      });
      expect(validate(doc)).toBe(true);
    });

    it('should validate custom description labels', () => {
      const requirement = createMinimalRequirement({
        descriptions: [
          { label: 'default', data: 'Main description' },
          { label: 'custom_label', data: 'Tool-specific description' },
          { label: 'another-label', data: 'Another custom description' },
        ],
      });
      const doc = createMinimalResultsDoc({
        baselines: [createMinimalEvaluatedBaseline({ requirements: [requirement] })],
      });
      expect(validate(doc)).toBe(true);
    });

    it('should validate requirement without refs (refs is optional)', () => {
      const requirement = createMinimalRequirement();
      expect(requirement).not.toHaveProperty('refs');
      const doc = createMinimalResultsDoc({
        baselines: [createMinimalEvaluatedBaseline({ requirements: [requirement] })],
      });
      expect(validate(doc)).toBe(true);
    });

    it('should validate requirement with refs array', () => {
      const doc = createMinimalResultsDoc({
        baselines: [
          createMinimalEvaluatedBaseline({
            requirements: [createMinimalRequirement({ refs: [{ url: 'https://example.com' }] })],
          }),
        ],
      });
      expect(validate(doc)).toBe(true);
    });

    it('should reject requirement with explicit null refs', () => {
      const doc = createMinimalResultsDoc({
        baselines: [
          createMinimalEvaluatedBaseline({
            requirements: [createMinimalRequirement({ refs: null })],
          }),
        ],
      });
      expect(validate(doc)).toBe(false);
    });

    it('should validate requirement with effectiveStatus field', () => {
      const doc = createMinimalResultsDoc({
        baselines: [
          createMinimalEvaluatedBaseline({
            requirements: [
              createMinimalRequirement({
                results: [createMinimalResult({ status: 'failed' })],
                effectiveStatus: 'notApplicable',
              }),
            ],
          }),
        ],
      });
      expect(validate(doc)).toBe(true);
    });

    it('should validate requirement with single waiver override', () => {
      const doc = createMinimalResultsDoc({
        baselines: [
          createMinimalEvaluatedBaseline({
            requirements: [
              createMinimalRequirement({
                results: [createMinimalResult({ status: 'failed' })],
                statusOverrides: [
                  {
                    type: 'waiver',
                    status: 'notApplicable',
                    reason: 'Compensating controls in place',
                    appliedBy: {
            identifier: 'isso@example.com',
            type: 'simple',
          },
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

    it('should validate requirement with single attestation status override', () => {
      const doc = createMinimalResultsDoc({
        baselines: [
          createMinimalEvaluatedBaseline({
            requirements: [
              createMinimalRequirement({
                results: [createMinimalResult({ status: 'notReviewed' })],
                statusOverrides: [
                  {
                    type: 'attestation',
                    status: 'passed',
                    reason: 'Manually verified by security team during audit',
                    appliedBy: {
            identifier: 'security-team@example.com',
            type: 'simple',
          },
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

    it('should validate requirement with multiple status overrides (chronological history)', () => {
      const doc = createMinimalResultsDoc({
        baselines: [
          createMinimalEvaluatedBaseline({
            requirements: [
              createMinimalRequirement({
                results: [createMinimalResult({ status: 'failed' })],
                statusOverrides: [
                  // Most recent override first
                  {
                    type: 'attestation',
                    status: 'failed',
                    reason: 'Re-evaluated, confirmed failure',
                    appliedBy: {
            identifier: 'auditor@example.com',
            type: 'simple',
          },
                    appliedAt: '2025-12-10T14:00:00Z',
                    expiresAt: '2026-12-10T14:00:00Z',
                  },
                  // Earlier override
                  {
                    type: 'waiver',
                    status: 'notApplicable',
                    reason: 'Initially thought to be false positive',
                    appliedBy: {
            identifier: 'engineer@example.com',
            type: 'simple',
          },
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

    it('should validate requirement with status override containing digital signature', () => {
      const doc = createMinimalResultsDoc({
        baselines: [
          createMinimalEvaluatedBaseline({
            requirements: [
              createMinimalRequirement({
                results: [createMinimalResult({ status: 'failed' })],
                statusOverrides: [
                  {
                    type: 'waiver',
                    status: 'notApplicable',
                    reason: 'Risk accepted by CISO',
                    appliedBy: {
            identifier: 'ciso@example.com',
            type: 'simple',
          },
                    appliedAt: '2025-12-05T16:00:00Z',
                    expiresAt: '2027-12-05T16:00:00Z',
                    signature: {
                      type: 'JsonWebSignature2020',
                      created: '2025-12-05T16:00:00Z',
                      creator: {
                        identifier: 'ciso@example.com',
                        type: 'email',
                      },
                      signatureValue: 'base64-encoded-digital-signature',
                      proofPurpose: 'attestation',
                      verificationMethod: {
                        type: 'JsonWebKey2020',
                        controller: 'https://example.com/ciso/keys/1',
                        publicKeyJwk: {
                          kty: 'RSA',
                          n: 'xGOr-H7A...',
                          e: 'AQAB',
                        },
                      },
                    },
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

    it('should validate requirement with failed result and remediation POAM', () => {
      const doc = createMinimalResultsDoc({
        baselines: [
          createMinimalEvaluatedBaseline({
            requirements: [
              createMinimalRequirement({
                results: [createMinimalResult({ status: 'failed' })],
                poams: [
                  {
                    type: 'remediation',
                    explanation: 'Security patch scheduled for deployment in next maintenance window',
                    appliedBy: {
            identifier: 'ops-team@example.com',
            type: 'simple',
          },
                    appliedAt: '2025-12-01T10:00:00Z',
                  },
                ],
                effectiveStatus: 'failed', // POAM doesn't change status
              }),
            ],
          }),
        ],
      });
      expect(validate(doc)).toBe(true);
    });

    it('should validate requirement with failed result and mitigation POAM with milestones', () => {
      const doc = createMinimalResultsDoc({
        baselines: [
          createMinimalEvaluatedBaseline({
            requirements: [
              createMinimalRequirement({
                results: [createMinimalResult({ status: 'failed', message: 'MD5 hash algorithm detected' })],
                poams: [
                  {
                    type: 'mitigation',
                    explanation: 'Network segmentation implemented while awaiting vendor patch for hash algorithm upgrade',
                    appliedBy: {
            identifier: 'network-team@example.com',
            type: 'simple',
          },
                    appliedAt: '2025-12-01T10:00:00Z',
                    milestones: [
                      {
                        description: 'Implement firewall rules to isolate affected system',
                        estimatedCompletion: '2025-12-05T00:00:00Z',
                        status: 'completed',
                        completedAt: '2025-12-04T14:30:00Z',
                        completedBy: {
                          identifier: 'network-admin@example.com',
                          type: 'email',
                        },
                      },
                      {
                        description: 'Deploy vendor patch when available',
                        estimatedCompletion: '2026-01-15T00:00:00Z',
                        status: 'pending',
                      },
                    ],
                  },
                ],
                effectiveStatus: 'failed', // still failing, but mitigated
              }),
            ],
          }),
        ],
      });
      expect(validate(doc)).toBe(true);
    });

    it('should validate requirement with statusOverride AND POAM (both allowed)', () => {
      const doc = createMinimalResultsDoc({
        baselines: [
          createMinimalEvaluatedBaseline({
            requirements: [
              createMinimalRequirement({
                results: [createMinimalResult({ status: 'failed' })],
                statusOverrides: [
                  {
                    type: 'waiver',
                    status: 'notApplicable',
                    reason: 'Temporary exception granted pending remediation',
                    appliedBy: {
            identifier: 'isso@example.com',
            type: 'simple',
          },
                    appliedAt: '2025-12-01T10:00:00Z',
                    expiresAt: '2026-01-15T10:00:00Z',
                  },
                ],
                poams: [
                  {
                    type: 'remediation',
                    explanation: 'Patch deployment scheduled for January 2026',
                    appliedBy: {
            identifier: 'ops-team@example.com',
            type: 'simple',
          },
                    appliedAt: '2025-12-01T10:00:00Z',
                    milestones: [
                      {
                        description: 'Test patch in staging',
                        estimatedCompletion: '2025-12-15T00:00:00Z',
                        status: 'pending',
                      },
                      {
                        description: 'Deploy to production',
                        estimatedCompletion: '2026-01-10T00:00:00Z',
                        status: 'pending',
                      },
                    ],
                  },
                ],
                effectiveStatus: 'notApplicable', // override changes status, POAM tracks work
              }),
            ],
          }),
        ],
      });
      expect(validate(doc)).toBe(true);
    });

    it('should validate requirement with multiple POAMs', () => {
      const doc = createMinimalResultsDoc({
        baselines: [
          createMinimalEvaluatedBaseline({
            requirements: [
              createMinimalRequirement({
                results: [createMinimalResult({ status: 'failed' })],
                poams: [
                  {
                    type: 'mitigation',
                    explanation: 'Primary mitigation: network segmentation',
                    appliedBy: {
            identifier: 'network-team@example.com',
            type: 'simple',
          },
                    appliedAt: '2025-12-01T10:00:00Z',
                  },
                  {
                    type: 'mitigation',
                    explanation: 'Secondary mitigation: enhanced monitoring',
                    appliedBy: {
            identifier: 'security-team@example.com',
            type: 'simple',
          },
                    appliedAt: '2025-12-02T10:00:00Z',
                  },
                  {
                    type: 'remediation',
                    explanation: 'Root cause remediation: patch deployment',
                    appliedBy: {
            identifier: 'ops-team@example.com',
            type: 'simple',
          },
                    appliedAt: '2025-12-03T10:00:00Z',
                  },
                ],
                effectiveStatus: 'failed',
              }),
            ],
          }),
        ],
      });
      expect(validate(doc)).toBe(true);
    });

    it('should validate requirement with severity field', () => {
      const doc = createMinimalResultsDoc({
        baselines: [
          createMinimalEvaluatedBaseline({
            requirements: [createMinimalRequirement({ severity: 'high' })],
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
              requirements: [createMinimalRequirement({ severity })],
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
            requirements: [createMinimalRequirement({ severity: 'unknown' })],
          }),
        ],
      });
      expect(validate(doc)).toBe(false);
    });

    it('should validate requirement with evidence array', () => {
      const doc = createMinimalResultsDoc({
        baselines: [
          createMinimalEvaluatedBaseline({
            requirements: [
              createMinimalRequirement({
                evidence: [
                  {
                    type: 'screenshot',
                    data: 'base64-encoded-screenshot',
                    description: 'Screenshot showing compliant configuration',
                  },
                ],
              }),
            ],
          }),
        ],
      });
      expect(validate(doc)).toBe(true);
    });

    it('should validate requirement with multiple evidence items', () => {
      const doc = createMinimalResultsDoc({
        baselines: [
          createMinimalEvaluatedBaseline({
            requirements: [
              createMinimalRequirement({
                evidence: [
                  {
                    type: 'screenshot',
                    data: 'base64-screenshot-data',
                    description: 'Configuration interface screenshot',
                    mimeType: 'image/png',
                    encoding: 'base64',
                    capturedAt: '2025-12-07T15:30:00Z',
                    capturedBy: {
                      identifier: 'auditor@example.com',
                      type: 'email',
                    },
                  },
                  {
                    type: 'url',
                    data: 'https://github.com/org/repo/blob/main/config.yaml',
                    description: 'Link to configuration file in source control',
                  },
                  {
                    type: 'log',
                    data: '[2025-12-07 15:30:00] INFO: Configuration validation passed',
                    description: 'Log excerpt showing successful validation',
                  },
                ],
              }),
            ],
          }),
        ],
      });
      expect(validate(doc)).toBe(true);
    });

    it('should validate requirement without evidence field', () => {
      const req = createMinimalRequirement();
      delete (req as Record<string, unknown>).evidence;
      const doc = createMinimalResultsDoc({
        baselines: [
          createMinimalEvaluatedBaseline({
            requirements: [req],
          }),
        ],
      });
      expect(validate(doc)).toBe(true);
    });

    it('should reject requirement with null evidence field', () => {
      const doc = createMinimalResultsDoc({
        baselines: [
          createMinimalEvaluatedBaseline({
            requirements: [createMinimalRequirement({ evidence: null })],
          }),
        ],
      });
      expect(validate(doc)).toBe(false);
    });

    it('should validate requirement with empty evidence array', () => {
      const doc = createMinimalResultsDoc({
        baselines: [
          createMinimalEvaluatedBaseline({
            requirements: [createMinimalRequirement({ evidence: [] })],
          }),
        ],
      });
      expect(validate(doc)).toBe(true);
    });

    it('should validate requirement without poams field', () => {
      const req = createMinimalRequirement();
      delete (req as Record<string, unknown>).poams;
      const doc = createMinimalResultsDoc({
        baselines: [
          createMinimalEvaluatedBaseline({
            requirements: [req],
          }),
        ],
      });
      expect(validate(doc)).toBe(true);
    });

    it('should reject requirement with null poams field', () => {
      const doc = createMinimalResultsDoc({
        baselines: [
          createMinimalEvaluatedBaseline({
            requirements: [createMinimalRequirement({ poams: null })],
          }),
        ],
      });
      expect(validate(doc)).toBe(false);
    });

    it('should validate requirement without statusOverrides field', () => {
      const req = createMinimalRequirement();
      delete (req as Record<string, unknown>).statusOverrides;
      const doc = createMinimalResultsDoc({
        baselines: [
          createMinimalEvaluatedBaseline({
            requirements: [req],
          }),
        ],
      });
      expect(validate(doc)).toBe(true);
    });

    it('should reject requirement with null statusOverrides field', () => {
      const doc = createMinimalResultsDoc({
        baselines: [
          createMinimalEvaluatedBaseline({
            requirements: [createMinimalRequirement({ statusOverrides: null })],
          }),
        ],
      });
      expect(validate(doc)).toBe(false);
    });
  });

  describe('results array (Requirement_Result)', () => {
    it('should reject result without status field', () => {
      const doc = createMinimalResultsDoc({
        baselines: [
          createMinimalEvaluatedBaseline({
            requirements: [
              createMinimalRequirement({
                results: [
                  {
                    codeDesc: 'Test description',
                    startTime: '2025-11-25T12:00:00Z',
                    // Missing status field
                  },
                ],
              }),
            ],
          }),
        ],
      });
      expect(validate(doc)).toBe(false);
      expect(validate.errors).toMatchObject([
        expect.objectContaining({
          message: expect.stringMatching(/required|missing/i),
          params: expect.objectContaining({ missingProperty: 'status' }),
        }),
      ]);
    });

    it('should validate result with minimal required fields', () => {
      const doc = createMinimalResultsDoc({
        baselines: [
          createMinimalEvaluatedBaseline({
            requirements: [createMinimalRequirement({ results: [createMinimalResult()] })],
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
              requirements: [createMinimalRequirement({ results: [createMinimalResult({ status })] })],
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
            requirements: [createMinimalRequirement({ results: [createMinimalResult({ status: 'skipped' })] })],
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
            requirements: [createMinimalRequirement({ results: [createMinimalResult({ status: 'unknown' })] })],
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
              createMinimalRequirement({
                results: [
                  createMinimalResult({
                    status: 'failed',
                    runTime: 0.023,
                    message: 'expected "MaxAuthTries 6" to match /MaxAuthTries\\s+4/',
                    resource: 'file',
                    resourceId: '/etc/ssh/sshd_config',
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
        platform: { name: 'ubuntu', release: '20.04', targetId: 'web-server-01' },
        profiles: [
          {
            name: 'ubuntu-stig-baseline',
            sha256: 'abc123',
            supports: [{ platformName: 'ubuntu' }],
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

  describe('remediation field', () => {
    it('should accept results with remediation URI and checksum', () => {
      const doc = createMinimalResultsDoc({
        remediation: {
          uri: 'https://github.com/RedHatOfficial/ansible-role-rhel9-stig',
          checksum: {
            algorithm: 'sha256',
            value: 'abc123def456...',
          },
        },
      });
      expect(validate(doc)).toBe(true);
    });

    it('should accept results with remediation URI only', () => {
      const doc = createMinimalResultsDoc({
        remediation: {
          uri: 'https://public.cyber.mil/stigs/supplemental-automation-content/',
        },
      });
      expect(validate(doc)).toBe(true);
    });

    it('should accept results without remediation field', () => {
      const doc = createMinimalResultsDoc();
      expect(validate(doc)).toBe(true);
    });
  });

  describe('array constraints (minItems)', () => {
    it('should accept results array with at least one result', () => {
      const doc = createMinimalResultsDoc({
        baselines: [
          createMinimalEvaluatedBaseline({
            requirements: [
              createMinimalRequirement({
                results: [createMinimalResult()],
              }),
            ],
          }),
        ],
      });
      expect(validate(doc)).toBe(true);
    });

    it('should reject empty results array', () => {
      const doc = createMinimalResultsDoc({
        baselines: [
          createMinimalEvaluatedBaseline({
            requirements: [
              createMinimalRequirement({
                results: [],
              }),
            ],
          }),
        ],
      });
      expect(validate(doc)).toBe(false);
      expect(validate.errors).toContainEqual(
        expect.objectContaining({
          keyword: 'minItems',
        })
      );
    });

    it('should accept descriptions array with at least one description', () => {
      const doc = createMinimalResultsDoc({
        baselines: [
          createMinimalEvaluatedBaseline({
            requirements: [
              createMinimalRequirement({
                descriptions: [
                  { label: 'default', data: 'Test requirement' },
                ],
              }),
            ],
          }),
        ],
      });
      expect(validate(doc)).toBe(true);
    });

    it('should reject empty descriptions array', () => {
      const doc = createMinimalResultsDoc({
        baselines: [
          createMinimalEvaluatedBaseline({
            requirements: [
              createMinimalRequirement({
                descriptions: [],
              }),
            ],
          }),
        ],
      });
      expect(validate(doc)).toBe(false);
      expect(validate.errors).toContainEqual(
        expect.objectContaining({
          keyword: 'minItems',
        })
      );
    });
  });

  describe('descriptions contains validation', () => {
    it('should accept descriptions with default label', () => {
      const doc = createMinimalResultsDoc({
        baselines: [
          createMinimalEvaluatedBaseline({
            requirements: [
              createMinimalRequirement({
                descriptions: [
                  { label: 'default', data: 'Primary description' },
                  { label: 'check', data: 'How to check' },
                ],
              }),
            ],
          }),
        ],
      });
      expect(validate(doc)).toBe(true);
    });

    it('should reject descriptions missing default label', () => {
      const doc = createMinimalResultsDoc({
        baselines: [
          createMinimalEvaluatedBaseline({
            requirements: [
              createMinimalRequirement({
                descriptions: [
                  { label: 'check', data: 'How to check' },
                  { label: 'fix', data: 'How to fix' },
                ],
              }),
            ],
          }),
        ],
      });
      expect(validate(doc)).toBe(false);
      expect(validate.errors).toContainEqual(
        expect.objectContaining({
          keyword: 'contains',
        })
      );
    });

    it('should accept default label in any position', () => {
      const doc = createMinimalResultsDoc({
        baselines: [
          createMinimalEvaluatedBaseline({
            requirements: [
              createMinimalRequirement({
                descriptions: [
                  { label: 'check', data: 'How to check' },
                  { label: 'default', data: 'Primary description' },
                  { label: 'fix', data: 'How to fix' },
                ],
              }),
            ],
          }),
        ],
      });
      expect(validate(doc)).toBe(true);
    });
  });
});
