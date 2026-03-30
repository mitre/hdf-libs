import { describe, it, expect, beforeAll } from 'vitest';
import Ajv2020 from 'ajv/dist/2020.js';
import {
  createAjvWithPrimitives,
  loadSchema,
  createMinimalBaselineDoc,
  createMinimalBaselineRequirement,
} from './setup';

describe('hdf-baseline.schema.json (refactored)', () => {
  let ajv: Ajv2020;
  let validate: ReturnType<Ajv2020['compile']>;

  beforeAll(() => {
    ajv = createAjvWithPrimitives();
    validate = ajv.compile(loadSchema('hdf-baseline.schema.json'));
  });

  describe('metaschema validation', () => {
    it('should validate hdf-baseline.schema.json against JSON Schema 2020-12 metaschema', () => {
      const schema = loadSchema('hdf-baseline.schema.json');
      const isValid = ajv.validateSchema(schema);
      if (!isValid) {
        console.error('Metaschema validation errors:', ajv.errors);
      }
      expect(isValid).toBe(true);
    });
  });

  describe('root-level structure', () => {
    it('should validate a minimal valid document', () => {
      expect(validate(createMinimalBaselineDoc())).toBe(true);
      expect(validate.errors).toBeNull();
    });

    it('should reject document missing required fields', () => {
      expect(validate({ name: 'test-baseline' })).toBe(false);
      expect(validate.errors).not.toBeNull();
    });

    it('should accept integrity with sha256 algorithm', () => {
      const doc = createMinimalBaselineDoc({
        integrity: { algorithm: 'sha256', checksum: 'abc123def456' }
      });
      expect(validate(doc)).toBe(true);
    });

    it('should accept integrity with sha512 algorithm', () => {
      const doc = createMinimalBaselineDoc({
        integrity: { algorithm: 'sha512', checksum: 'longer-sha512-hash-value' }
      });
      expect(validate(doc)).toBe(true);
    });

    it('should accept integrity with sha384 algorithm', () => {
      const doc = createMinimalBaselineDoc({
        integrity: { algorithm: 'sha384', checksum: 'sha384-hash-value' }
      });
      expect(validate(doc)).toBe(true);
    });

    it('should accept document without integrity', () => {
      const doc = {
        name: 'test-baseline',
        requirements: [
          {
            id: 'test-req-1',
            impact: 0.5,
            tags: {},
            descriptions: [{ label: 'default', data: 'Test requirement' }],
          },
        ],
      };
      expect(validate(doc)).toBe(true);
    });

    it('should reject integrity with invalid algorithm', () => {
      const doc = {
        name: 'test-baseline',
        requirements: [],
        integrity: { algorithm: 'md5', checksum: 'bad-algorithm' }
      };
      expect(validate(doc)).toBe(false);
    });

    it('should accept baseline without supports field', () => {
      const doc = createMinimalBaselineDoc();
      delete (doc as Record<string, unknown>).supports;
      expect(validate(doc)).toBe(true);
    });

    it('should accept baseline without groups field', () => {
      const doc = createMinimalBaselineDoc();
      delete (doc as Record<string, unknown>).groups;
      expect(validate(doc)).toBe(true);
    });

    it('should accept baseline with supports field when provided', () => {
      const doc = createMinimalBaselineDoc({
        supports: [{ platformFamily: 'redhat', platformName: 'centos' }],
      });
      expect(validate(doc)).toBe(true);
    });

    it('should accept baseline with groups field when provided', () => {
      const doc = createMinimalBaselineDoc({
        groups: [{ id: 'controls/ssh.rb', requirements: ['SV-238196'] }],
      });
      expect(validate(doc)).toBe(true);
    });

    it('should accept optional generator field', () => {
      const doc = createMinimalBaselineDoc({
        generator: { name: 'Chef InSpec', version: '5.22.3' },
      });
      expect(validate(doc)).toBe(true);
    });

    it('should accept full metadata', () => {
      const doc = createMinimalBaselineDoc({
        title: 'Ubuntu 20.04 STIG Baseline',
        maintainer: 'ACME Corp',
        copyright: 'ACME Corporation',
        license: 'Apache-2.0',
        summary: 'InSpec Baseline for Ubuntu 20.04 STIG',
        version: '1.0.0',
        status: 'loaded',
      });
      expect(validate(doc)).toBe(true);
    });
  });

  describe('supports array', () => {
    it('should accept empty supports array', () => {
      expect(validate(createMinimalBaselineDoc())).toBe(true);
    });

    it('should accept supported platform with platformName', () => {
      const doc = createMinimalBaselineDoc({ supports: [{ platformName: 'ubuntu' }] });
      expect(validate(doc)).toBe(true);
    });

    it('should accept supported platform with platformFamily', () => {
      const doc = createMinimalBaselineDoc({ supports: [{ platformFamily: 'debian' }] });
      expect(validate(doc)).toBe(true);
    });

    it('should accept supported platform with release', () => {
      const doc = createMinimalBaselineDoc({
        supports: [{ platformName: 'ubuntu', release: '20.04' }],
      });
      expect(validate(doc)).toBe(true);
    });

    it('should accept cloud platform support', () => {
      const doc = createMinimalBaselineDoc({ supports: [{ platform: 'aws' }] });
      expect(validate(doc)).toBe(true);
    });
  });

  describe('groups array (Requirement_Group)', () => {
    it('should accept group with requirements field (new format)', () => {
      const doc = createMinimalBaselineDoc({
        groups: [{ id: 'controls/ssh.rb', requirements: ['SV-238196', 'SV-238197'] }],
      });
      expect(validate(doc)).toBe(true);
    });

    it('should accept group with title', () => {
      const doc = createMinimalBaselineDoc({
        groups: [{ id: 'controls/ssh.rb', title: 'SSH Configuration', requirements: ['SV-238196'] }],
      });
      expect(validate(doc)).toBe(true);
    });
  });

  describe('requirements array (Baseline_Requirement)', () => {
    it('should validate requirement with minimal required fields', () => {
      const doc = createMinimalBaselineDoc({ requirements: [createMinimalBaselineRequirement()] });
      expect(validate(doc)).toBe(true);
    });

    it('should validate requirement with full metadata', () => {
      const doc = createMinimalBaselineDoc({
        requirements: [
          createMinimalBaselineRequirement({
            title: 'SSH MaxAuthTries must be set to 4 or less',
            refs: [{ url: 'https://nvd.nist.gov/vuln/detail/CVE-2021-1234' }],
            tags: { severity: 'medium', cci: ['CCI-000044'] },
            sourceLocation: { ref: 'controls/ssh.rb', line: 15 },
          }),
        ],
      });
      expect(validate(doc)).toBe(true);
    });

    it('should validate requirement with descriptions array', () => {
      const doc = createMinimalBaselineDoc({
        requirements: [
          createMinimalBaselineRequirement({
            descriptions: [
              { label: 'default', data: 'SSH authentication must be configured properly' },
              { label: 'fix', data: 'Set MaxAuthTries to 4 in /etc/ssh/sshd_config' },
              { label: 'check', data: 'Verify MaxAuthTries is set to 4 or less' },
            ],
          }),
        ],
      });
      expect(validate(doc)).toBe(true);
    });

    it('should validate requirement with impact at boundaries', () => {
      expect(validate(createMinimalBaselineDoc({
        requirements: [createMinimalBaselineRequirement({ impact: 0.0 })],
      }))).toBe(true);

      expect(validate(createMinimalBaselineDoc({
        requirements: [createMinimalBaselineRequirement({ impact: 1.0 })],
      }))).toBe(true);
    });

    it('should reject requirement with impact out of range', () => {
      const doc = createMinimalBaselineDoc({
        requirements: [createMinimalBaselineRequirement({ impact: 1.5 })],
      });
      expect(validate(doc)).toBe(false);
    });

    it('should reject requirement with explicit null code (manual-only requirement)', () => {
      const doc = createMinimalBaselineDoc({
        requirements: [
          createMinimalBaselineRequirement({
            id: 'MAN-001',
            code: null,
          }),
        ],
      });
      expect(validate(doc)).toBe(false);
    });

    it('should accept requirement without code field (omitted)', () => {
      const doc = createMinimalBaselineDoc({
        requirements: [
          {
            id: 'DRAFT-001',
            impact: 0.5,
            descriptions: [{ label: 'default', data: 'Draft requirement without code' }],
            tags: {},
            // code field omitted entirely
          },
        ],
      });
      expect(validate(doc)).toBe(true);
    });

    it('should accept requirement with empty code string', () => {
      const doc = createMinimalBaselineDoc({
        requirements: [
          createMinimalBaselineRequirement({
            id: 'EMPTY-001',
            code: '',
          }),
        ],
      });
      expect(validate(doc)).toBe(true);
    });
  });

  describe('inputs/attributes array', () => {
    it('should accept inputs array with objects', () => {
      const doc = createMinimalBaselineDoc({
        inputs: [
          { name: 'ssh_max_auth_tries', value: 4 },
          { name: 'allowed_users', value: ['root', 'admin'] },
        ],
      });
      expect(validate(doc)).toBe(true);
    });

    it('should reject explicit null inputs', () => {
      const doc = createMinimalBaselineDoc({ inputs: null });
      expect(validate(doc)).toBe(false);
    });
  });

  describe('depends array (dependencies)', () => {
    it('should accept depends array', () => {
      const doc = createMinimalBaselineDoc({
        depends: [{ name: 'base-ubuntu-baseline', url: 'https://github.com/my-org/ubuntu-baseline' }],
      });
      expect(validate(doc)).toBe(true);
    });

    it('should accept git dependency', () => {
      const doc = createMinimalBaselineDoc({
        depends: [{ name: 'base-ubuntu-baseline', git: 'https://github.com/my-org/ubuntu-baseline.git', branch: 'main' }],
      });
      expect(validate(doc)).toBe(true);
    });

    it('should accept path dependency', () => {
      const doc = createMinimalBaselineDoc({
        depends: [{ name: 'base-ubuntu-baseline', path: '../base-ubuntu-baseline' }],
      });
      expect(validate(doc)).toBe(true);
    });
  });

  describe('backward compatibility (v1 format)', () => {
    // NOTE: v1 baseline files use object for descriptions, v2 uses array
    it.skip('should accept legacy InSpec profile JSON structure - REQUIRES CONVERTER', () => {
      const legacyDoc = {
        name: 'ubuntu-stig-baseline',
        title: 'Ubuntu 20.04 STIG Baseline',
        maintainer: 'ACME Corp',
        copyright: 'ACME Corporation',
        license: 'Apache-2.0',
        version: '1.0.0',
        supports: [{ 'platformName': 'ubuntu' }],
        controls: [
          {
            id: 'SV-238196',
            title: 'SSH must be configured',
            desc: 'Configure SSH securely',
            descriptions: { default: 'Configure SSH', check: 'Verify SSH', fix: 'Configure SSH' },
            impact: 0.7,
            refs: [],
            tags: { severity: 'medium' },
            code: 'control "SV-238196" do\nend',
            sourceLocation: { ref: 'controls/ssh.rb', line: 10 },
          },
        ],
        groups: [{ id: 'controls/ssh.rb', controls: ['SV-238196'] }],
        sha256: 'abc123def456',
        status: 'loaded',
        generator: { name: 'inspec', version: '5.22.3' },
      };
      expect(validate(legacyDoc)).toBe(true);
    });
  });

  describe('remediation field', () => {
    it('should accept baseline with remediation URI and checksum', () => {
      const doc = createMinimalBaselineDoc({
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

    it('should accept baseline with remediation URI only', () => {
      const doc = createMinimalBaselineDoc({
        remediation: {
          uri: 'https://github.com/ComplianceAsCode/content/tree/master/linux_os/guide/system',
        },
      });
      expect(validate(doc)).toBe(true);
    });

    it('should accept baseline without remediation field', () => {
      const doc = createMinimalBaselineDoc();
      expect(validate(doc)).toBe(true);
    });

    it('should reject remediation missing required uri field', () => {
      const doc = createMinimalBaselineDoc({
        remediation: {
          checksum: {
            algorithm: 'sha256',
            value: 'abc123',
          },
        },
      });
      expect(validate(doc)).toBe(false);
    });
  });

  describe('array constraints (minItems)', () => {
    it('should accept requirements array with at least one requirement', () => {
      const doc = createMinimalBaselineDoc({
        requirements: [createMinimalBaselineRequirement()],
      });
      expect(validate(doc)).toBe(true);
    });

    it('should reject empty requirements array', () => {
      const doc = createMinimalBaselineDoc({
        requirements: [],
      });
      expect(validate(doc)).toBe(false);
      expect(validate.errors).toContainEqual(
        expect.objectContaining({
          keyword: 'minItems',
        })
      );
    });

    it('should accept descriptions array with at least one description', () => {
      const req = createMinimalBaselineRequirement({
        descriptions: [
          { label: 'default', data: 'Test requirement' },
        ],
      });
      const doc = createMinimalBaselineDoc({ requirements: [req] });
      expect(validate(doc)).toBe(true);
    });

    it('should reject empty descriptions array', () => {
      const req = createMinimalBaselineRequirement({
        descriptions: [],
      });
      const doc = createMinimalBaselineDoc({ requirements: [req] });
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
      const req = createMinimalBaselineRequirement({
        descriptions: [
          { label: 'default', data: 'Primary description' },
          { label: 'check', data: 'How to check' },
        ],
      });
      const doc = createMinimalBaselineDoc({ requirements: [req] });
      expect(validate(doc)).toBe(true);
    });

    it('should reject descriptions missing default label', () => {
      const req = createMinimalBaselineRequirement({
        descriptions: [
          { label: 'check', data: 'How to check' },
          { label: 'fix', data: 'How to fix' },
        ],
      });
      const doc = createMinimalBaselineDoc({ requirements: [req] });
      expect(validate(doc)).toBe(false);
      expect(validate.errors).toContainEqual(
        expect.objectContaining({
          keyword: 'contains',
        })
      );
    });

    it('should accept default label in any position', () => {
      const req = createMinimalBaselineRequirement({
        descriptions: [
          { label: 'check', data: 'How to check' },
          { label: 'default', data: 'Primary description' },
          { label: 'fix', data: 'How to fix' },
        ],
      });
      const doc = createMinimalBaselineDoc({ requirements: [req] });
      expect(validate(doc)).toBe(true);
    });
  });
});
