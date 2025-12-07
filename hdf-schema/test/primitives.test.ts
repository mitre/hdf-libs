import { describe, it, expect } from 'vitest';
import Ajv2020 from 'ajv/dist/2020.js';
import addFormats from 'ajv-formats';
import commonSchema from '../src/schemas/primitives/common.schema.json';
import platformSchema from '../src/schemas/primitives/platform.schema.json';
import targetSchema from '../src/schemas/primitives/target.schema.json';
import runnerSchema from '../src/schemas/primitives/runner.schema.json';
import statisticsSchema from '../src/schemas/primitives/statistics.schema.json';
import resultSchema from '../src/schemas/primitives/result.schema.json';
import extensionsSchema from '../src/schemas/primitives/extensions.schema.json';

describe('Primitive Schema Validation', () => {
  const ajv = new Ajv2020({ strict: false, allErrors: true, validateFormats: true });
  addFormats(ajv);

  // Register all schemas so $ref works
  ajv.addSchema(commonSchema);
  ajv.addSchema(platformSchema);
  ajv.addSchema(targetSchema);
  ajv.addSchema(runnerSchema);
  ajv.addSchema(statisticsSchema);
  ajv.addSchema(resultSchema);
  ajv.addSchema(extensionsSchema);

  describe('common.schema.json', () => {
    describe('Requirement_Group', () => {
      const validate = ajv.compile({
        $ref: 'https://mitre.github.io/hdf-libs/schemas/primitives/common/v1.0.0#/$defs/Requirement_Group',
      });

      it('should validate a valid Requirement_Group', () => {
        const valid = {
          id: 'controls/ssh.rb',
          title: 'SSH Configuration Controls',
          requirements: ['SV-238196', 'SV-238197', 'SV-238198'],
        };
        expect(validate(valid)).toBe(true);
        expect(validate.errors).toBeNull();
      });

      it('should validate Requirement_Group with null title', () => {
        const valid = {
          id: 'controls/ssh.rb',
          title: null,
          requirements: ['SV-238196'],
        };
        expect(validate(valid)).toBe(true);
      });

      it('should reject Requirement_Group missing required id', () => {
        const invalid = {
          title: 'SSH Controls',
          requirements: ['SV-238196'],
        };
        expect(validate(invalid)).toBe(false);
        expect(validate.errors).not.toBeNull();
      });

      it('should reject Requirement_Group missing required requirements array', () => {
        const invalid = {
          id: 'controls/ssh.rb',
          title: 'SSH Controls',
        };
        expect(validate(invalid)).toBe(false);
      });

      it('should reject Requirement_Group with non-string requirements', () => {
        const invalid = {
          id: 'controls/ssh.rb',
          requirements: [123, 456],
        };
        expect(validate(invalid)).toBe(false);
      });
    });

    describe('Dependency', () => {
      const validate = ajv.compile({
        $ref: 'https://mitre.github.io/hdf-libs/schemas/primitives/common/v1.0.0#/$defs/Dependency',
      });

      it('should validate a valid Dependency with git URL', () => {
        const valid = {
          name: 'ubuntu-22.04-stig-baseline',
          git: 'https://github.com/my-org/ubuntu-22.04-stig-baseline.git',
          branch: 'main',
          status: 'loaded',
        };
        expect(validate(valid)).toBe(true);
      });

      it('should validate an empty Dependency (no required fields)', () => {
        const valid = {};
        expect(validate(valid)).toBe(true);
      });

      it('should validate Dependency with null fields', () => {
        const valid = {
          name: null,
          url: null,
          status: null,
        };
        expect(validate(valid)).toBe(true);
      });
    });

    describe('Reference', () => {
      const validate = ajv.compile({
        $ref: 'https://mitre.github.io/hdf-libs/schemas/primitives/common/v1.0.0#/$defs/Reference',
      });

      it('should validate Reference with ref string', () => {
        const valid = { ref: 'NIST SP 800-53 Rev 5' };
        expect(validate(valid)).toBe(true);
      });

      it('should validate Reference with url', () => {
        const valid = { url: 'https://nvd.nist.gov/800-53' };
        expect(validate(valid)).toBe(true);
      });

      it('should validate Reference with uri', () => {
        const valid = { uri: 'urn:isbn:0451450523' };
        expect(validate(valid)).toBe(true);
      });

      it('should validate Reference with ref array', () => {
        const valid = {
          ref: [
            { title: 'NIST 800-53', section: 'AC-2' },
            { title: 'CIS Benchmark', section: '5.1' },
          ],
        };
        expect(validate(valid)).toBe(true);
      });

      it('should reject Reference with no recognized field', () => {
        const invalid = { other: 'something' };
        expect(validate(invalid)).toBe(false);
      });
    });

    describe('Source_Location', () => {
      const validate = ajv.compile({
        $ref: 'https://mitre.github.io/hdf-libs/schemas/primitives/common/v1.0.0#/$defs/Source_Location',
      });

      it('should validate a valid Source_Location', () => {
        const valid = {
          ref: 'controls/ssh.rb',
          line: 42,
        };
        expect(validate(valid)).toBe(true);
      });

      it('should validate Source_Location with null values', () => {
        const valid = {
          ref: null,
          line: null,
        };
        expect(validate(valid)).toBe(true);
      });

      it('should validate empty Source_Location', () => {
        const valid = {};
        expect(validate(valid)).toBe(true);
      });
    });

    describe('Supported_Platform', () => {
      const validate = ajv.compile({
        $ref: 'https://mitre.github.io/hdf-libs/schemas/primitives/common/v1.0.0#/$defs/Supported_Platform',
      });

      it('should validate a valid Supported_Platform', () => {
        const valid = {
          'platformFamily': 'redhat',
          'platformName': 'centos',
          release: '8',
        };
        expect(validate(valid)).toBe(true);
      });

      it('should validate Supported_Platform with platform field', () => {
        const valid = {
          platform: 'aws',
        };
        expect(validate(valid)).toBe(true);
      });

      it('should validate empty Supported_Platform', () => {
        const valid = {};
        expect(validate(valid)).toBe(true);
      });

    });
  });

  describe('platform.schema.json', () => {
    describe('Platform', () => {
      const validate = ajv.compile({
        $ref: 'https://mitre.github.io/hdf-libs/schemas/primitives/platform/v1.0.0#/$defs/Platform',
      });

      it('should validate a valid Platform', () => {
        const valid = {
          name: 'ubuntu',
          release: '20.04',
        };
        expect(validate(valid)).toBe(true);
      });

      it('should validate Platform with targetId', () => {
        const valid = {
          name: 'windows',
          release: '10',
          targetId: '21H2',
        };
        expect(validate(valid)).toBe(true);
      });

      it('should validate Platform with null targetId', () => {
        const valid = {
          name: 'ubuntu',
          release: '20.04',
          targetId: null,
        };
        expect(validate(valid)).toBe(true);
      });

      it('should reject Platform missing required name', () => {
        const invalid = {
          release: '20.04',
        };
        expect(validate(invalid)).toBe(false);
      });

      it('should reject Platform missing required release', () => {
        const invalid = {
          name: 'ubuntu',
        };
        expect(validate(invalid)).toBe(false);
      });
    });
  });

  describe('target.schema.json', () => {
    const validate = ajv.compile({
      $ref: 'https://mitre.github.io/hdf-libs/schemas/primitives/target/v1.0.0#/$defs/Target',
    });

    describe('Host_Target', () => {
      it('should validate a valid host target', () => {
        const valid = {
          type: 'host',
          name: 'web-server-01',
          fqdn: 'web-server-01.example.com',
          ipAddress: '192.168.1.100',
          osName: 'Ubuntu',
          osVersion: '22.04',
        };
        expect(validate(valid)).toBe(true);
      });

      it('should validate minimal host target', () => {
        const valid = {
          type: 'host',
          name: 'server',
        };
        expect(validate(valid)).toBe(true);
      });
    });

    describe('Container_Image_Target', () => {
      it('should validate a valid container image target', () => {
        const valid = {
          type: 'containerImage',
          name: 'nginx:1.25',
          registry: 'docker.io',
          repository: 'library/nginx',
          tag: '1.25',
          digest: 'sha256:abc123def456',
        };
        expect(validate(valid)).toBe(true);
      });

      it('should validate minimal container image target', () => {
        const valid = {
          type: 'containerImage',
          name: 'my-image',
        };
        expect(validate(valid)).toBe(true);
      });
    });

    describe('Container_Instance_Target', () => {
      it('should validate a valid container instance target', () => {
        const valid = {
          type: 'containerInstance',
          name: 'nginx-abc123',
          containerId: 'abc123def456',
          image: 'nginx:1.25',
          runtime: 'containerd',
        };
        expect(validate(valid)).toBe(true);
      });
    });

    describe('Container_Platform_Target', () => {
      it('should validate a valid container platform target', () => {
        const valid = {
          type: 'containerPlatform',
          name: 'production-cluster',
          platformType: 'kubernetes',
          clusterName: 'prod-k8s',
          namespace: 'default',
          version: '1.28',
        };
        expect(validate(valid)).toBe(true);
      });
    });

    describe('Cloud_Account_Target', () => {
      it('should validate a valid AWS account target', () => {
        const valid = {
          type: 'cloudAccount',
          name: 'Production AWS',
          provider: 'aws',
          accountId: '123456789012',
          region: 'us-east-1',
        };
        expect(validate(valid)).toBe(true);
      });

      it('should validate Azure subscription target', () => {
        const valid = {
          type: 'cloudAccount',
          name: 'Azure Production',
          provider: 'azure',
          accountId: 'subscription-uuid',
        };
        expect(validate(valid)).toBe(true);
      });

      it('should reject invalid provider', () => {
        const invalid = {
          type: 'cloudAccount',
          name: 'Unknown Cloud',
          provider: 'invalid_provider',
        };
        expect(validate(invalid)).toBe(false);
      });
    });

    describe('Cloud_Resource_Target', () => {
      it('should validate a valid cloud resource target', () => {
        const valid = {
          type: 'cloudResource',
          name: 'web-server-ec2',
          provider: 'aws',
          resourceType: 'ec2:instance',
          resourceId: 'i-1234567890abcdef0',
          arn: 'arn:aws:ec2:us-east-1:123456789012:instance/i-1234567890abcdef0',
          region: 'us-east-1',
        };
        expect(validate(valid)).toBe(true);
      });
    });

    describe('Repository_Target', () => {
      it('should validate a valid repository target', () => {
        const valid = {
          type: 'repository',
          name: 'my-app',
          url: 'https://github.com/org/my-app',
          branch: 'main',
          commit: 'abc123def456789',
        };
        expect(validate(valid)).toBe(true);
      });
    });

    describe('Application_Target', () => {
      it('should validate a valid application target', () => {
        const valid = {
          type: 'application',
          name: 'Customer Portal',
          url: 'https://portal.example.com',
          version: '2.5.0',
          environment: 'production',
        };
        expect(validate(valid)).toBe(true);
      });
    });

    describe('Artifact_Target', () => {
      it('should validate a valid artifact target', () => {
        const valid = {
          type: 'artifact',
          name: 'lodash',
          packageManager: 'npm',
          packageName: 'lodash',
          version: '4.17.21',
          checksum: 'sha256:abc123',
        };
        expect(validate(valid)).toBe(true);
      });
    });

    describe('Network_Target', () => {
      it('should validate a valid network target', () => {
        const valid = {
          type: 'network',
          name: 'Corporate LAN',
          cidr: '10.0.0.0/8',
          gateway: '10.0.0.1',
        };
        expect(validate(valid)).toBe(true);
      });
    });

    describe('Database_Target', () => {
      it('should validate a valid database target', () => {
        const valid = {
          type: 'database',
          name: 'Production PostgreSQL',
          engine: 'postgresql',
          version: '15.2',
          host: 'db.example.com',
          port: 5432,
        };
        expect(validate(valid)).toBe(true);
      });
    });

    describe('Target discriminator validation', () => {
      it('should reject target with invalid type', () => {
        const invalid = {
          type: 'invalid_type',
          name: 'something',
        };
        expect(validate(invalid)).toBe(false);
      });

      it('should reject target missing type', () => {
        const invalid = {
          name: 'something',
        };
        expect(validate(invalid)).toBe(false);
      });

      it('should reject target missing name', () => {
        const invalid = {
          type: 'host',
        };
        expect(validate(invalid)).toBe(false);
      });
    });
  });

  describe('runner.schema.json', () => {
    const validate = ajv.compile({
      $ref: 'https://mitre.github.io/hdf-libs/schemas/primitives/runner/v1.0.0#/$defs/Runner',
    });

    it('should validate a minimal runner with only name', () => {
      const valid = {
        name: 'ubuntu',
      };
      expect(validate(valid)).toBe(true);
    });

    it('should validate a full runner with all fields', () => {
      const valid = {
        name: 'ubuntu',
        release: '20.04',
        architecture: 'x86_64',
        hostname: 'ci-runner-01',
      };
      expect(validate(valid)).toBe(true);
    });

    it('should validate runner with release only', () => {
      const valid = {
        name: 'macos',
        release: '13.2',
      };
      expect(validate(valid)).toBe(true);
    });

    it('should validate runner with architecture', () => {
      const valid = {
        name: 'ubuntu',
        architecture: 'arm64',
      };
      expect(validate(valid)).toBe(true);
    });

    it('should reject runner missing required name', () => {
      const invalid = {
        release: '20.04',
        architecture: 'x86_64',
      };
      expect(validate(invalid)).toBe(false);
    });
  });

  describe('statistics.schema.json', () => {
    describe('Statistic_Block', () => {
      const validate = ajv.compile({
        $ref: 'https://mitre.github.io/hdf-libs/schemas/primitives/statistics/v1.0.0#/$defs/Statistic_Block',
      });

      it('should validate a valid Statistic_Block', () => {
        const valid = { total: 42 };
        expect(validate(valid)).toBe(true);
      });

      it('should reject Statistic_Block missing required total', () => {
        const invalid = {};
        expect(validate(invalid)).toBe(false);
      });

      it('should reject Statistic_Block with non-number total', () => {
        const invalid = { total: 'forty-two' };
        expect(validate(invalid)).toBe(false);
      });
    });

    describe('Statistic_Hash', () => {
      const validate = ajv.compile({
        $ref: 'https://mitre.github.io/hdf-libs/schemas/primitives/statistics/v1.0.0#/$defs/Statistic_Hash',
      });

      it('should validate a full Statistic_Hash', () => {
        const valid = {
          passed: { total: 10 },
          failed: { total: 2 },
          notApplicable: { total: 5 },
          notReviewed: { total: 3 },
          error: { total: 0 },
        };
        expect(validate(valid)).toBe(true);
      });

      it('should validate Statistic_Hash with null values', () => {
        const valid = {
          passed: { total: 10 },
          failed: null,
          notApplicable: null,
          notReviewed: null,
          error: null,
        };
        expect(validate(valid)).toBe(true);
      });

      it('should validate empty Statistic_Hash', () => {
        const valid = {};
        expect(validate(valid)).toBe(true);
      });

      it('should validate partial Statistic_Hash', () => {
        const valid = {
          passed: { total: 15 },
          failed: { total: 3 },
        };
        expect(validate(valid)).toBe(true);
      });
    });

    describe('Statistics', () => {
      const validate = ajv.compile({
        $ref: 'https://mitre.github.io/hdf-libs/schemas/primitives/statistics/v1.0.0#/$defs/Statistics',
      });

      it('should validate a full Statistics object', () => {
        const valid = {
          duration: 45.5,
          requirements: {
            passed: { total: 50 },
            failed: { total: 5 },
            notApplicable: { total: 10 },
            notReviewed: { total: 2 },
            error: { total: 1 },
          },
        };
        expect(validate(valid)).toBe(true);
      });

      it('should validate Statistics with only duration', () => {
        const valid = {
          duration: 30.0,
        };
        expect(validate(valid)).toBe(true);
      });

      it('should validate Statistics with null duration', () => {
        const valid = {
          duration: null,
          requirements: {
            passed: { total: 10 },
          },
        };
        expect(validate(valid)).toBe(true);
      });

      it('should validate Statistics with null requirements', () => {
        const valid = {
          duration: 15.5,
          requirements: null,
        };
        expect(validate(valid)).toBe(true);
      });

      it('should validate empty Statistics', () => {
        const valid = {};
        expect(validate(valid)).toBe(true);
      });
    });
  });

  describe('result.schema.json', () => {
    describe('Result_Status', () => {
      const validate = ajv.compile({
        $ref: 'https://mitre.github.io/hdf-libs/schemas/primitives/result/v1.0.0#/$defs/Result_Status',
      });

      it('should validate "passed" status', () => {
        expect(validate('passed')).toBe(true);
      });

      it('should validate "failed" status', () => {
        expect(validate('failed')).toBe(true);
      });

      it('should validate "notApplicable" status', () => {
        expect(validate('notApplicable')).toBe(true);
      });

      it('should validate "notReviewed" status', () => {
        expect(validate('notReviewed')).toBe(true);
      });

      it('should validate "error" status', () => {
        expect(validate('error')).toBe(true);
      });

      it('should reject skipped status', () => {
        expect(validate('skipped')).toBe(false);
      });

      it('should reject invalid status', () => {
        expect(validate('unknown')).toBe(false);
      });
    });

    describe('Requirement_Result', () => {
      const validate = ajv.compile({
        $ref: 'https://mitre.github.io/hdf-libs/schemas/primitives/result/v1.0.0#/$defs/Requirement_Result',
      });

      it('should validate a full Requirement_Result', () => {
        const valid = {
          status: 'passed',
          codeDesc: 'File /etc/passwd should exist',
          runTime: 0.005,
          startTime: '2025-01-15T10:30:00Z',
          resource: 'file',
          resourceId: '/etc/passwd',
          message: null,
          skipMessage: null,
          exception: null,
          backtrace: null,
        };
        expect(validate(valid)).toBe(true);
      });

      it('should validate minimal Requirement_Result', () => {
        const valid = {
          codeDesc: 'Test description',
          startTime: '2025-01-15T10:30:00Z',
        };
        expect(validate(valid)).toBe(true);
      });

      it('should validate Requirement_Result with failed status and message', () => {
        const valid = {
          status: 'failed',
          codeDesc: 'File /etc/secure should have mode 0600',
          startTime: '2025-01-15T10:30:00Z',
          message: 'expected mode to be 0600, got 0644',
        };
        expect(validate(valid)).toBe(true);
      });

      it('should validate Requirement_Result with notReviewed status', () => {
        const valid = {
          status: 'notReviewed',
          codeDesc: 'Manual verification required',
          startTime: '2025-01-15T10:30:00Z',
          skipMessage: 'This check requires manual verification by an auditor',
        };
        expect(validate(valid)).toBe(true);
      });

      it('should validate Requirement_Result with error and backtrace', () => {
        const valid = {
          status: 'error',
          codeDesc: 'Check failed to execute',
          startTime: '2025-01-15T10:30:00Z',
          exception: 'RuntimeError',
          backtrace: ['line1', 'line2', 'line3'],
        };
        expect(validate(valid)).toBe(true);
      });

      it('should reject Requirement_Result missing required codeDesc', () => {
        const invalid = {
          startTime: '2025-01-15T10:30:00Z',
        };
        expect(validate(invalid)).toBe(false);
      });

      it('should reject Requirement_Result missing required startTime', () => {
        const invalid = {
          codeDesc: 'Test description',
        };
        expect(validate(invalid)).toBe(false);
      });
    });

    describe('Requirement_Description', () => {
      const validate = ajv.compile({
        $ref: 'https://mitre.github.io/hdf-libs/schemas/primitives/result/v1.0.0#/$defs/Requirement_Description',
      });

      it('should validate a valid Requirement_Description', () => {
        const valid = {
          label: 'fix',
          data: 'Configure the SSH daemon to use only FIPS-approved ciphers.',
        };
        expect(validate(valid)).toBe(true);
      });

      it('should validate check description', () => {
        const valid = {
          label: 'check',
          data: 'Verify the SSH daemon is configured to use FIPS-approved ciphers.',
        };
        expect(validate(valid)).toBe(true);
      });

      it('should reject Requirement_Description missing label', () => {
        const invalid = {
          data: 'Some description text',
        };
        expect(validate(invalid)).toBe(false);
      });

      it('should reject Requirement_Description missing data', () => {
        const invalid = {
          label: 'fix',
        };
        expect(validate(invalid)).toBe(false);
      });
    });
  });

  describe('extensions.schema.json', () => {
    describe('Override', () => {
      const validate = ajv.compile({
        $ref: 'https://mitre.github.io/hdf-libs/schemas/primitives/extensions/v1.0.0#/$defs/Override',
      });

      it('should validate a waiver override with all required fields', () => {
        const valid = {
          type: 'waiver',
          status: 'notApplicable',
          reason: 'Risk accepted by ISSO pending system upgrade',
          appliedBy: 'isso@example.com',
          appliedAt: '2025-12-05T20:30:00Z',
          expiresAt: '2026-12-05T20:30:00Z',
        };
        expect(validate(valid)).toBe(true);
      });

      it('should validate an attestation override with all required fields', () => {
        const valid = {
          type: 'attestation',
          status: 'passed',
          reason: 'Manually verified by security team during audit',
          appliedBy: 'security-team@example.com',
          appliedAt: '2025-12-05T15:30:00Z',
          expiresAt: '2026-12-05T15:30:00Z',
        };
        expect(validate(valid)).toBe(true);
      });

      it('should validate override with optional signature field', () => {
        const valid = {
          type: 'waiver',
          status: 'notApplicable',
          reason: 'Compensating controls in place',
          appliedBy: 'ciso@example.com',
          appliedAt: '2025-12-05T20:30:00Z',
          expiresAt: '2027-12-05T20:30:00Z',
          signature: 'base64-encoded-signature-data',
        };
        expect(validate(valid)).toBe(true);
      });

      it('should validate override with all valid status values (including error)', () => {
        const statuses = ['passed', 'failed', 'notApplicable', 'notReviewed', 'error'];
        statuses.forEach(status => {
          const valid = {
            type: 'attestation',
            status,
            reason: 'Test override',
            appliedBy: 'test@example.com',
            appliedAt: '2025-12-05T20:30:00Z',
            expiresAt: '2026-12-05T20:30:00Z',
          };
          expect(validate(valid)).toBe(true);
        });
      });

      it('should reject override missing expiresAt (no permanent overrides)', () => {
        const invalid = {
          type: 'waiver',
          status: 'notApplicable',
          reason: 'Test',
          appliedBy: 'test@example.com',
          appliedAt: '2025-12-05T20:30:00Z',
          // missing: expiresAt
        };
        expect(validate(invalid)).toBe(false);
      });

      it('should reject override with null expiresAt (no permanent overrides)', () => {
        const invalid = {
          type: 'waiver',
          status: 'notApplicable',
          reason: 'Test',
          appliedBy: 'test@example.com',
          appliedAt: '2025-12-05T20:30:00Z',
          expiresAt: null,
        };
        expect(validate(invalid)).toBe(false);
      });

      it('should reject override missing required fields', () => {
        const invalid = {
          type: 'waiver',
          // missing: status, reason, appliedBy, appliedAt, expiresAt
        };
        expect(validate(invalid)).toBe(false);
      });

      it('should reject override with invalid type', () => {
        const invalid = {
          type: 'exception', // invalid - only waiver/attestation allowed
          status: 'notApplicable',
          reason: 'Test',
          appliedBy: 'test@example.com',
          appliedAt: '2025-12-05T20:30:00Z',
          expiresAt: '2026-12-05T20:30:00Z',
        };
        expect(validate(invalid)).toBe(false);
      });

      it('should reject override with invalid status', () => {
        const invalid = {
          type: 'waiver',
          status: 'skipped', // invalid - skipped was removed
          reason: 'Test',
          appliedBy: 'test@example.com',
          appliedAt: '2025-12-05T20:30:00Z',
          expiresAt: '2026-12-05T20:30:00Z',
        };
        expect(validate(invalid)).toBe(false);
      });
    });

    describe('Generator', () => {
      const validate = ajv.compile({
        $ref: 'https://mitre.github.io/hdf-libs/schemas/primitives/extensions/v1.0.0#/$defs/Generator',
      });

      it('should validate a valid Generator', () => {
        const valid = {
          name: 'Chef InSpec',
          version: '5.22.3',
        };
        expect(validate(valid)).toBe(true);
      });

      it('should validate Generator with different tool', () => {
        const valid = {
          name: 'Heimdall',
          version: '2.10.0',
        };
        expect(validate(valid)).toBe(true);
      });

      it('should reject Generator missing required name', () => {
        const invalid = {
          version: '1.0.0',
        };
        expect(validate(invalid)).toBe(false);
      });

      it('should reject Generator missing required version', () => {
        const invalid = {
          name: 'SomeTool',
        };
        expect(validate(invalid)).toBe(false);
      });
    });

    describe('Integrity', () => {
      const validate = ajv.compile({
        $ref: 'https://mitre.github.io/hdf-libs/schemas/primitives/extensions/v1.0.0#/$defs/Integrity',
      });

      it('should validate Integrity with sha256', () => {
        const valid = {
          algorithm: 'sha256',
          checksum: 'abc123def456789...',
        };
        expect(validate(valid)).toBe(true);
      });

      it('should validate Integrity with sha512 and signature', () => {
        const valid = {
          algorithm: 'sha512',
          checksum: 'abc123def456789...',
          signature: 'base64-encoded-signature',
          signedBy: 'security-team@example.com',
        };
        expect(validate(valid)).toBe(true);
      });

      it('should validate Integrity with null optional fields', () => {
        const valid = {
          algorithm: 'sha384',
          checksum: 'abc123...',
          signature: null,
          signedBy: null,
        };
        expect(validate(valid)).toBe(true);
      });

      it('should validate empty Integrity', () => {
        const valid = {};
        expect(validate(valid)).toBe(true);
      });

      it('should reject Integrity with invalid algorithm', () => {
        const invalid = {
          algorithm: 'md5',
          checksum: 'abc123',
        };
        expect(validate(invalid)).toBe(false);
      });

      it('should reject Integrity with algorithm but no checksum', () => {
        const invalid = {
          algorithm: 'sha256',
        };
        expect(validate(invalid)).toBe(false);
      });

      it('should reject Integrity with checksum but no algorithm', () => {
        const invalid = {
          checksum: 'abc123def456',
        };
        expect(validate(invalid)).toBe(false);
      });
    });
  });
});
