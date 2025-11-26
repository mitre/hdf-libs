import { describe, it, expect, beforeAll } from 'vitest';
import Ajv from 'ajv';
import {
  createAjvWithPrimitives,
  loadSchema,
  createMinimalBaselineDoc,
  createMinimalBaselineControl,
} from './setup';

describe('hdf-baseline.schema.json (refactored)', () => {
  let ajv: Ajv;
  let validate: ReturnType<Ajv['compile']>;

  beforeAll(() => {
    ajv = createAjvWithPrimitives();
    validate = ajv.compile(loadSchema('hdf-baseline.schema.json'));
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

    it('should accept optional sha512 field', () => {
      const doc = createMinimalBaselineDoc({ sha512: 'longer-sha512-hash-value' });
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

    it('should accept supported platform with platform-name', () => {
      const doc = createMinimalBaselineDoc({ supports: [{ 'platform-name': 'ubuntu' }] });
      expect(validate(doc)).toBe(true);
    });

    it('should accept supported platform with platform-family', () => {
      const doc = createMinimalBaselineDoc({ supports: [{ 'platform-family': 'debian' }] });
      expect(validate(doc)).toBe(true);
    });

    it('should accept supported platform with release', () => {
      const doc = createMinimalBaselineDoc({
        supports: [{ 'platform-name': 'ubuntu', release: '20.04' }],
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

    it('should accept group with controls field (legacy format)', () => {
      const doc = createMinimalBaselineDoc({
        groups: [{ id: 'controls/ssh.rb', controls: ['SV-238196', 'SV-238197'] }],
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

  describe('controls array (Baseline_Requirement)', () => {
    it('should validate control with minimal required fields', () => {
      const doc = createMinimalBaselineDoc({ controls: [createMinimalBaselineControl()] });
      expect(validate(doc)).toBe(true);
    });

    it('should validate control with full metadata', () => {
      const doc = createMinimalBaselineDoc({
        controls: [
          createMinimalBaselineControl({
            title: 'SSH MaxAuthTries must be set to 4 or less',
            desc: 'The SSH server must limit authentication attempts.',
            refs: [{ url: 'https://nvd.nist.gov/vuln/detail/CVE-2021-1234' }],
            tags: { severity: 'medium', cci: ['CCI-000044'] },
            source_location: { ref: 'controls/ssh.rb', line: 15 },
          }),
        ],
      });
      expect(validate(doc)).toBe(true);
    });

    it('should validate control with descriptions (object format)', () => {
      const doc = createMinimalBaselineDoc({
        controls: [
          createMinimalBaselineControl({
            descriptions: {
              fix: 'Set MaxAuthTries to 4 in /etc/ssh/sshd_config',
              check: 'Verify MaxAuthTries is set to 4 or less',
            },
          }),
        ],
      });
      expect(validate(doc)).toBe(true);
    });

    it('should validate control with impact at boundaries', () => {
      expect(validate(createMinimalBaselineDoc({
        controls: [createMinimalBaselineControl({ impact: 0.0 })],
      }))).toBe(true);

      expect(validate(createMinimalBaselineDoc({
        controls: [createMinimalBaselineControl({ impact: 1.0 })],
      }))).toBe(true);
    });

    it('should reject control with impact out of range', () => {
      const doc = createMinimalBaselineDoc({
        controls: [createMinimalBaselineControl({ impact: 1.5 })],
      });
      expect(validate(doc)).toBe(false);
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

    it('should accept null inputs', () => {
      const doc = createMinimalBaselineDoc({ inputs: null });
      expect(validate(doc)).toBe(true);
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

  describe('backward compatibility', () => {
    it('should accept legacy InSpec profile JSON structure', () => {
      const legacyDoc = {
        name: 'ubuntu-stig-baseline',
        title: 'Ubuntu 20.04 STIG Baseline',
        maintainer: 'ACME Corp',
        copyright: 'ACME Corporation',
        license: 'Apache-2.0',
        version: '1.0.0',
        supports: [{ 'platform-name': 'ubuntu' }],
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
            source_location: { ref: 'controls/ssh.rb', line: 10 },
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
});
