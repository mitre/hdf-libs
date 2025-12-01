import { describe, it, expect } from 'vitest';
import Ajv from 'ajv';
import addFormats from 'ajv-formats';
import commonSchema from '../src/schemas/primitives/common.schema.json';
import platformSchema from '../src/schemas/primitives/platform.schema.json';
import targetSchema from '../src/schemas/primitives/target.schema.json';
import statisticsSchema from '../src/schemas/primitives/statistics.schema.json';
import resultSchema from '../src/schemas/primitives/result.schema.json';
import extensionsSchema from '../src/schemas/primitives/extensions.schema.json';

describe('Primitive Schema Validation', () => {
  const ajv = new Ajv({ strict: false, allErrors: true });
  addFormats(ajv);

  // Register all schemas so $ref works
  ajv.addSchema(commonSchema);
  ajv.addSchema(platformSchema);
  ajv.addSchema(targetSchema);
  ajv.addSchema(statisticsSchema);
  ajv.addSchema(resultSchema);
  ajv.addSchema(extensionsSchema);

  describe('common.schema.json', () => {
    describe('Requirement_Group', () => {
      const validate = ajv.compile({
        $ref: 'https://mitre.github.io/hdf-libs/schemas/primitives/common/v1.0.0#/definitions/Requirement_Group',
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
        $ref: 'https://mitre.github.io/hdf-libs/schemas/primitives/common/v1.0.0#/definitions/Dependency',
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
        $ref: 'https://mitre.github.io/hdf-libs/schemas/primitives/common/v1.0.0#/definitions/Reference',
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
        $ref: 'https://mitre.github.io/hdf-libs/schemas/primitives/common/v1.0.0#/definitions/Source_Location',
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
        $ref: 'https://mitre.github.io/hdf-libs/schemas/primitives/common/v1.0.0#/definitions/Supported_Platform',
      });

      it('should validate a valid Supported_Platform', () => {
        const valid = {
          'platform-family': 'redhat',
          'platform-name': 'centos',
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

      it('should validate deprecated os-family and os-name', () => {
        const valid = {
          'os-family': 'debian',
          'os-name': 'ubuntu',
        };
        expect(validate(valid)).toBe(true);
      });
    });
  });

  describe('platform.schema.json', () => {
    describe('Platform', () => {
      const validate = ajv.compile({
        $ref: 'https://mitre.github.io/hdf-libs/schemas/primitives/platform/v1.0.0#/definitions/Platform',
      });

      it('should validate a valid Platform', () => {
        const valid = {
          name: 'ubuntu',
          release: '20.04',
        };
        expect(validate(valid)).toBe(true);
      });

      it('should validate Platform with target_id', () => {
        const valid = {
          name: 'windows',
          release: '10',
          target_id: '21H2',
        };
        expect(validate(valid)).toBe(true);
      });

      it('should validate Platform with null target_id', () => {
        const valid = {
          name: 'ubuntu',
          release: '20.04',
          target_id: null,
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
      $ref: 'https://mitre.github.io/hdf-libs/schemas/primitives/target/v1.0.0#/definitions/Target',
    });

    describe('Host_Target', () => {
      it('should validate a valid host target', () => {
        const valid = {
          type: 'host',
          name: 'web-server-01',
          fqdn: 'web-server-01.example.com',
          ip_address: '192.168.1.100',
          os_name: 'Ubuntu',
          os_version: '22.04',
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
          type: 'container_image',
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
          type: 'container_image',
          name: 'my-image',
        };
        expect(validate(valid)).toBe(true);
      });
    });

    describe('Container_Instance_Target', () => {
      it('should validate a valid container instance target', () => {
        const valid = {
          type: 'container_instance',
          name: 'nginx-abc123',
          container_id: 'abc123def456',
          image: 'nginx:1.25',
          runtime: 'containerd',
        };
        expect(validate(valid)).toBe(true);
      });
    });

    describe('Container_Platform_Target', () => {
      it('should validate a valid container platform target', () => {
        const valid = {
          type: 'container_platform',
          name: 'production-cluster',
          platform_type: 'kubernetes',
          cluster_name: 'prod-k8s',
          namespace: 'default',
          version: '1.28',
        };
        expect(validate(valid)).toBe(true);
      });
    });

    describe('Cloud_Account_Target', () => {
      it('should validate a valid AWS account target', () => {
        const valid = {
          type: 'cloud_account',
          name: 'Production AWS',
          provider: 'aws',
          account_id: '123456789012',
          region: 'us-east-1',
        };
        expect(validate(valid)).toBe(true);
      });

      it('should validate Azure subscription target', () => {
        const valid = {
          type: 'cloud_account',
          name: 'Azure Production',
          provider: 'azure',
          account_id: 'subscription-uuid',
        };
        expect(validate(valid)).toBe(true);
      });

      it('should reject invalid provider', () => {
        const invalid = {
          type: 'cloud_account',
          name: 'Unknown Cloud',
          provider: 'invalid_provider',
        };
        expect(validate(invalid)).toBe(false);
      });
    });

    describe('Cloud_Resource_Target', () => {
      it('should validate a valid cloud resource target', () => {
        const valid = {
          type: 'cloud_resource',
          name: 'web-server-ec2',
          provider: 'aws',
          resource_type: 'ec2:instance',
          resource_id: 'i-1234567890abcdef0',
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
          package_manager: 'npm',
          package_name: 'lodash',
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

  describe('statistics.schema.json', () => {
    describe('Statistic_Block', () => {
      const validate = ajv.compile({
        $ref: 'https://mitre.github.io/hdf-libs/schemas/primitives/statistics/v1.0.0#/definitions/Statistic_Block',
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
        $ref: 'https://mitre.github.io/hdf-libs/schemas/primitives/statistics/v1.0.0#/definitions/Statistic_Hash',
      });

      it('should validate a full Statistic_Hash', () => {
        const valid = {
          passed: { total: 10 },
          failed: { total: 2 },
          not_applicable: { total: 5 },
          not_reviewed: { total: 3 },
          error: { total: 0 },
        };
        expect(validate(valid)).toBe(true);
      });

      it('should validate Statistic_Hash with null values', () => {
        const valid = {
          passed: { total: 10 },
          failed: null,
          not_applicable: null,
          not_reviewed: null,
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
        $ref: 'https://mitre.github.io/hdf-libs/schemas/primitives/statistics/v1.0.0#/definitions/Statistics',
      });

      it('should validate a full Statistics object', () => {
        const valid = {
          duration: 45.5,
          controls: {
            passed: { total: 50 },
            failed: { total: 5 },
            not_applicable: { total: 10 },
            not_reviewed: { total: 2 },
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
          controls: {
            passed: { total: 10 },
          },
        };
        expect(validate(valid)).toBe(true);
      });

      it('should validate Statistics with null controls', () => {
        const valid = {
          duration: 15.5,
          controls: null,
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
        $ref: 'https://mitre.github.io/hdf-libs/schemas/primitives/result/v1.0.0#/definitions/Result_Status',
      });

      it('should validate "passed" status', () => {
        expect(validate('passed')).toBe(true);
      });

      it('should validate "failed" status', () => {
        expect(validate('failed')).toBe(true);
      });

      it('should validate "not_applicable" status', () => {
        expect(validate('not_applicable')).toBe(true);
      });

      it('should validate "not_reviewed" status', () => {
        expect(validate('not_reviewed')).toBe(true);
      });

      it('should validate "error" status', () => {
        expect(validate('error')).toBe(true);
      });

      it('should accept deprecated skipped status for backward compatibility', () => {
        expect(validate('skipped')).toBe(true);
      });

      it('should reject invalid status', () => {
        expect(validate('unknown')).toBe(false);
      });
    });

    describe('Overall_Status', () => {
      const validate = ajv.compile({
        $ref: 'https://mitre.github.io/hdf-libs/schemas/primitives/result/v1.0.0#/definitions/Overall_Status',
      });

      it('should validate all Overall_Status values', () => {
        expect(validate('passed')).toBe(true);
        expect(validate('failed')).toBe(true);
        expect(validate('not_applicable')).toBe(true);
        expect(validate('not_reviewed')).toBe(true);
        expect(validate('error')).toBe(true);
      });

      it('should reject invalid Overall_Status', () => {
        expect(validate('skipped')).toBe(false);
      });
    });

    describe('Requirement_Result', () => {
      const validate = ajv.compile({
        $ref: 'https://mitre.github.io/hdf-libs/schemas/primitives/result/v1.0.0#/definitions/Requirement_Result',
      });

      it('should validate a full Requirement_Result', () => {
        const valid = {
          status: 'passed',
          code_desc: 'File /etc/passwd should exist',
          run_time: 0.005,
          start_time: '2025-01-15T10:30:00Z',
          resource: 'file',
          resource_id: '/etc/passwd',
          message: null,
          skip_message: null,
          exception: null,
          backtrace: null,
        };
        expect(validate(valid)).toBe(true);
      });

      it('should validate minimal Requirement_Result', () => {
        const valid = {
          code_desc: 'Test description',
          start_time: '2025-01-15T10:30:00Z',
        };
        expect(validate(valid)).toBe(true);
      });

      it('should validate Requirement_Result with failed status and message', () => {
        const valid = {
          status: 'failed',
          code_desc: 'File /etc/secure should have mode 0600',
          start_time: '2025-01-15T10:30:00Z',
          message: 'expected mode to be 0600, got 0644',
        };
        expect(validate(valid)).toBe(true);
      });

      it('should validate Requirement_Result with not_reviewed status', () => {
        const valid = {
          status: 'not_reviewed',
          code_desc: 'Manual verification required',
          start_time: '2025-01-15T10:30:00Z',
          skip_message: 'This check requires manual verification by an auditor',
        };
        expect(validate(valid)).toBe(true);
      });

      it('should validate Requirement_Result with error and backtrace', () => {
        const valid = {
          status: 'error',
          code_desc: 'Check failed to execute',
          start_time: '2025-01-15T10:30:00Z',
          exception: 'RuntimeError',
          backtrace: ['line1', 'line2', 'line3'],
        };
        expect(validate(valid)).toBe(true);
      });

      it('should reject Requirement_Result missing required code_desc', () => {
        const invalid = {
          start_time: '2025-01-15T10:30:00Z',
        };
        expect(validate(invalid)).toBe(false);
      });

      it('should reject Requirement_Result missing required start_time', () => {
        const invalid = {
          code_desc: 'Test description',
        };
        expect(validate(invalid)).toBe(false);
      });
    });

    describe('Requirement_Description', () => {
      const validate = ajv.compile({
        $ref: 'https://mitre.github.io/hdf-libs/schemas/primitives/result/v1.0.0#/definitions/Requirement_Description',
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
    describe('Waiver_Data', () => {
      const validate = ajv.compile({
        $ref: 'https://mitre.github.io/hdf-libs/schemas/primitives/extensions/v1.0.0#/definitions/Waiver_Data',
      });

      it('should validate a full Waiver_Data', () => {
        const valid = {
          expiration_date: '2025-12-31',
          justification: 'Risk accepted by ISSO pending system upgrade',
          message: 'Waiver applied',
          run: true,
          skipped_due_to_waiver: true,
        };
        expect(validate(valid)).toBe(true);
      });

      it('should validate Waiver_Data with null values', () => {
        const valid = {
          expiration_date: null,
          justification: null,
          message: null,
          run: null,
          skipped_due_to_waiver: null,
        };
        expect(validate(valid)).toBe(true);
      });

      it('should validate empty Waiver_Data', () => {
        const valid = {};
        expect(validate(valid)).toBe(true);
      });

      it('should validate Waiver_Data with string skipped_due_to_waiver', () => {
        const valid = {
          skipped_due_to_waiver: 'yes',
        };
        expect(validate(valid)).toBe(true);
      });
    });

    describe('Attestation_Status', () => {
      const validate = ajv.compile({
        $ref: 'https://mitre.github.io/hdf-libs/schemas/primitives/extensions/v1.0.0#/definitions/Attestation_Status',
      });

      it('should validate "passed" attestation status', () => {
        expect(validate('passed')).toBe(true);
      });

      it('should validate "failed" attestation status', () => {
        expect(validate('failed')).toBe(true);
      });

      it('should reject invalid attestation status', () => {
        expect(validate('skipped')).toBe(false);
        expect(validate('not_applicable')).toBe(false);
      });
    });

    describe('Attestation_Data', () => {
      const validate = ajv.compile({
        $ref: 'https://mitre.github.io/hdf-libs/schemas/primitives/extensions/v1.0.0#/definitions/Attestation_Data',
      });

      it('should validate a full Attestation_Data', () => {
        const valid = {
          control_id: 'SV-238196',
          explanation: 'Verified manually by security team during audit',
          frequency: 'annually',
          status: 'passed',
          updated: '2025-01-15T10:30:00Z',
          updated_by: 'john.doe@example.com',
        };
        expect(validate(valid)).toBe(true);
      });

      it('should validate Attestation_Data with failed status', () => {
        const valid = {
          control_id: 'SV-238197',
          explanation: 'Manual review found non-compliance',
          frequency: 'quarterly',
          status: 'failed',
          updated: '2025-01-15T10:30:00Z',
          updated_by: 'jane.smith@example.com',
        };
        expect(validate(valid)).toBe(true);
      });

      it('should reject Attestation_Data missing required fields', () => {
        const invalid = {
          control_id: 'SV-238196',
          // missing: explanation, frequency, status, updated, updated_by
        };
        expect(validate(invalid)).toBe(false);
      });

      it('should reject Attestation_Data with invalid status', () => {
        const invalid = {
          control_id: 'SV-238196',
          explanation: 'Test',
          frequency: 'annually',
          status: 'skipped',
          updated: '2025-01-15T10:30:00Z',
          updated_by: 'test@example.com',
        };
        expect(validate(invalid)).toBe(false);
      });
    });

    describe('Generator', () => {
      const validate = ajv.compile({
        $ref: 'https://mitre.github.io/hdf-libs/schemas/primitives/extensions/v1.0.0#/definitions/Generator',
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
        $ref: 'https://mitre.github.io/hdf-libs/schemas/primitives/extensions/v1.0.0#/definitions/Integrity',
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
          signed_by: 'security-team@example.com',
        };
        expect(validate(valid)).toBe(true);
      });

      it('should validate Integrity with null optional fields', () => {
        const valid = {
          algorithm: 'sha384',
          checksum: 'abc123...',
          signature: null,
          signed_by: null,
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
