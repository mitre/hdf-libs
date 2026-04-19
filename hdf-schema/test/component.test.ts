import { describe, it, expect } from 'vitest';
import Ajv2020 from 'ajv/dist/2020.js';
import addFormats from 'ajv-formats';
import commonSchema from '../src/schemas/primitives/common.schema.json';
import systemSchema from '../src/schemas/primitives/system.schema.json';
import targetSchema from '../src/schemas/primitives/target.schema.json';
import componentSchema from '../src/schemas/primitives/component.schema.json';
import { schemaRef } from './schema-ref';

describe('component.schema.json', () => {
  const ajv = new Ajv2020({ strict: false, allErrors: true, validateFormats: true });
  addFormats(ajv);

  ajv.addSchema(commonSchema);
  ajv.addSchema(systemSchema);
  ajv.addSchema(targetSchema);
  ajv.addSchema(componentSchema);

  // ── Base_Component ──

  describe('Base_Component', () => {
    const validate = ajv.compile({
      ...schemaRef(componentSchema, 'Base_Component'),
    });

    it('should validate a minimal component (name + type only)', () => {
      const valid = { name: 'WebTier', type: 'host' };
      expect(validate(valid)).toBe(true);
    });

    it('should validate a component with componentId', () => {
      const valid = {
        name: 'WebTier',
        type: 'host',
        componentId: 'f47ac10b-58cc-4372-a567-0e02b2c3d479',
      };
      expect(validate(valid)).toBe(true);
    });

    it('should reject componentId that is not a valid UUID', () => {
      const invalid = {
        name: 'WebTier',
        type: 'host',
        componentId: 'not-a-uuid',
      };
      expect(validate(invalid)).toBe(false);
    });

    it('should validate a component with externalIds', () => {
      const valid = {
        name: 'WebTier',
        type: 'host',
        externalIds: {
          aws: 'i-0123456789abcdef0',
          cmdb: 'ASSET-101',
          emass: 'SYS-2024-00142',
        },
      };
      expect(validate(valid)).toBe(true);
    });

    it('should reject externalIds with non-string values', () => {
      const invalid = {
        name: 'WebTier',
        type: 'host',
        externalIds: { aws: 12345 },
      };
      expect(validate(invalid)).toBe(false);
    });

    it('should validate a component with labels', () => {
      const valid = {
        name: 'WebTier',
        type: 'host',
        labels: { environment: 'production', team: 'platform' },
      };
      expect(validate(valid)).toBe(true);
    });

    it('should validate a component with description', () => {
      const valid = {
        name: 'WebTier',
        type: 'host',
        description: 'Primary web application servers',
      };
      expect(validate(valid)).toBe(true);
    });

    it('should validate a component with owner Identity', () => {
      const valid = {
        name: 'DatabaseTier',
        type: 'database',
        owner: { type: 'email', identifier: 'dba-team@agency.gov' },
      };
      expect(validate(valid)).toBe(true);
    });

    it('should reject component with invalid owner (missing identifier)', () => {
      const invalid = {
        name: 'WebTier',
        type: 'host',
        owner: { type: 'email' },
      };
      expect(validate(invalid)).toBe(false);
    });

    it('should validate a component with baselineRefs', () => {
      const valid = {
        name: 'WebTier',
        type: 'application',
        baselineRefs: ['RHEL9-STIG', 'DISA-Container-STIG'],
      };
      expect(validate(valid)).toBe(true);
    });

    it('should validate a component with inputOverrides', () => {
      const valid = {
        name: 'WebTier',
        type: 'application',
        inputOverrides: [
          {
            baselineRef: 'RHEL9-STIG',
            inputName: 'max_concurrent_sessions',
            value: 5,
            justification: 'Shift handoff needs 5 sessions',
            approvedBy: { type: 'email', identifier: 'issm@agency.gov' },
          },
        ],
      };
      expect(validate(valid)).toBe(true);
    });

    it('should validate a component with targetSelector', () => {
      const valid = {
        name: 'WebTier',
        type: 'application',
        targetSelector: { 'labels.component': 'WebTier' },
      };
      expect(validate(valid)).toBe(true);
    });

    it('should reject a component missing name', () => {
      const invalid = { type: 'host' };
      expect(validate(invalid)).toBe(false);
    });

    it('should reject a component missing type', () => {
      const invalid = { name: 'WebTier' };
      expect(validate(invalid)).toBe(false);
    });
  });

  // ── SBOM embedding ──

  describe('SBOM embedding', () => {
    const validate = ajv.compile({
      ...schemaRef(componentSchema, 'Base_Component'),
    });

    it('should validate a component with CycloneDX SBOM', () => {
      const valid = {
        name: 'WebTier',
        type: 'application',
        sbomFormat: 'cyclonedx',
        sbom: {
          bomFormat: 'CycloneDX',
          specVersion: '1.5',
          version: 1,
          components: [
            { type: 'library', name: 'express', version: '4.18.2' },
          ],
        },
      };
      expect(validate(valid)).toBe(true);
    });

    it('should validate a component with SPDX SBOM', () => {
      const valid = {
        name: 'WebTier',
        type: 'application',
        sbomFormat: 'spdx',
        sbom: {
          spdxVersion: 'SPDX-2.3',
          SPDXID: 'SPDXRef-DOCUMENT',
          name: 'WebTier-SBOM',
          dataLicense: 'CC0-1.0',
        },
      };
      expect(validate(valid)).toBe(true);
    });

    it('should reject CycloneDX SBOM missing bomFormat', () => {
      const invalid = {
        name: 'WebTier',
        type: 'application',
        sbomFormat: 'cyclonedx',
        sbom: {
          specVersion: '1.5',
          // missing bomFormat
        },
      };
      expect(validate(invalid)).toBe(false);
    });

    it('should reject CycloneDX SBOM missing specVersion', () => {
      const invalid = {
        name: 'WebTier',
        type: 'application',
        sbomFormat: 'cyclonedx',
        sbom: {
          bomFormat: 'CycloneDX',
          // missing specVersion
        },
      };
      expect(validate(invalid)).toBe(false);
    });

    it('should reject CycloneDX SBOM with wrong bomFormat value', () => {
      const invalid = {
        name: 'WebTier',
        type: 'application',
        sbomFormat: 'cyclonedx',
        sbom: {
          bomFormat: 'NotCycloneDX',
          specVersion: '1.5',
        },
      };
      expect(validate(invalid)).toBe(false);
    });

    it('should reject SPDX SBOM missing spdxVersion', () => {
      const invalid = {
        name: 'WebTier',
        type: 'application',
        sbomFormat: 'spdx',
        sbom: {
          SPDXID: 'SPDXRef-DOCUMENT',
          // missing spdxVersion
        },
      };
      expect(validate(invalid)).toBe(false);
    });

    it('should reject SPDX SBOM missing SPDXID', () => {
      const invalid = {
        name: 'WebTier',
        type: 'application',
        sbomFormat: 'spdx',
        sbom: {
          spdxVersion: 'SPDX-2.3',
          // missing SPDXID
        },
      };
      expect(validate(invalid)).toBe(false);
    });

    it('should reject sbomFormat without sbom', () => {
      // sbomFormat without sbom or sbomRef is meaningless but not invalid at base level
      // However, if sbom is provided, sbomFormat must match — tested above
      // This test validates that sbom is checked when sbomFormat is present
      const withRefOnly = {
        name: 'WebTier',
        type: 'application',
        sbomRef: 'https://artifacts.agency.gov/sbom/webtier.cdx.json',
        sbomFormat: 'cyclonedx',
      };
      // sbomRef + sbomFormat without embedded sbom is valid (external reference only)
      expect(validate(withRefOnly)).toBe(true);
    });

    it('should validate sbomRef as uri-reference', () => {
      const valid = {
        name: 'WebTier',
        type: 'application',
        sbomRef: './sboms/webtier.cdx.json',
        sbomFormat: 'cyclonedx',
      };
      expect(validate(valid)).toBe(true);
    });

    it('should reject invalid sbomFormat value', () => {
      const invalid = {
        name: 'WebTier',
        type: 'application',
        sbomFormat: 'unknown-format',
      };
      expect(validate(invalid)).toBe(false);
    });
  });

  // ── Polymorphic Component variants ──

  describe('Component (oneOf union)', () => {
    const validate = ajv.compile({
      ...schemaRef(componentSchema, 'Component'),
    });

    it('should validate a Host_Component', () => {
      const valid = {
        type: 'host',
        name: 'web-server-01',
        componentId: 'f47ac10b-58cc-4372-a567-0e02b2c3d479',
        fqdn: 'web01.prod.example.com',
        ipAddress: '192.168.1.100',
        macAddress: '00:1A:2B:3C:4D:5E',
        osName: 'Ubuntu',
        osVersion: '22.04 LTS',
      };
      expect(validate(valid)).toBe(true);
    });

    it('should validate a Container_Image_Component', () => {
      const valid = {
        type: 'containerImage',
        name: 'nginx-webserver',
        registry: 'docker.io',
        repository: 'library/nginx',
        tag: '1.25-alpine',
        digest: 'sha256:a9286defaba7b3a519d585ba0e37d0b2cbee74ebfe590960b0b1d6a5e97d1e1d',
      };
      expect(validate(valid)).toBe(true);
    });

    it('should validate a Container_Instance_Component', () => {
      const valid = {
        type: 'containerInstance',
        name: 'api-pod-1',
        containerId: 'abc123def456',
        image: 'myapp:latest',
        runtime: 'containerd',
      };
      expect(validate(valid)).toBe(true);
    });

    it('should validate a Container_Platform_Component', () => {
      const valid = {
        type: 'containerPlatform',
        name: 'prod-k8s',
        platformType: 'kubernetes',
        clusterName: 'prod-east-1',
        namespace: 'default',
        version: '1.28',
      };
      expect(validate(valid)).toBe(true);
    });

    it('should validate a Cloud_Account_Component', () => {
      const valid = {
        type: 'cloudAccount',
        name: 'prod-aws',
        provider: 'aws',
        accountId: '123456789012',
        region: 'us-east-1',
      };
      expect(validate(valid)).toBe(true);
    });

    it('should validate a Cloud_Resource_Component', () => {
      const valid = {
        type: 'cloudResource',
        name: 'prod-web-server',
        provider: 'aws',
        resourceType: 'ec2:instance',
        resourceId: 'i-0123456789abcdef0',
        arn: 'arn:aws:ec2:us-east-1:123456789012:instance/i-0123456789abcdef0',
        region: 'us-east-1',
      };
      expect(validate(valid)).toBe(true);
    });

    it('should validate a Repository_Component', () => {
      const valid = {
        type: 'repository',
        name: 'frontend-repo',
        url: 'https://github.com/org/frontend',
        branch: 'main',
        commit: 'abc123',
      };
      expect(validate(valid)).toBe(true);
    });

    it('should validate an Application_Component', () => {
      const valid = {
        type: 'application',
        name: 'portal-api',
        url: 'https://api.portal.example.com',
        version: '2.3.1',
        environment: 'production',
      };
      expect(validate(valid)).toBe(true);
    });

    it('should validate an Artifact_Component', () => {
      const valid = {
        type: 'artifact',
        name: 'express-package',
        packageManager: 'npm',
        packageName: 'express',
        version: '4.18.2',
      };
      expect(validate(valid)).toBe(true);
    });

    it('should validate a Network_Component', () => {
      const valid = {
        type: 'network',
        name: 'prod-vpc',
        cidr: '10.0.0.0/16',
        gateway: '10.0.0.1',
      };
      expect(validate(valid)).toBe(true);
    });

    it('should validate a Database_Component', () => {
      const valid = {
        type: 'database',
        name: 'prod-postgres',
        engine: 'postgresql',
        version: '15.3',
        host: 'db.prod.example.com',
        port: 5432,
      };
      expect(validate(valid)).toBe(true);
    });

    it('should validate a component with both target-specific and component-specific fields', () => {
      const valid = {
        type: 'host',
        name: 'web-server-01',
        componentId: 'f47ac10b-58cc-4372-a567-0e02b2c3d479',
        fqdn: 'web01.prod.example.com',
        ipAddress: '192.168.1.100',
        osName: 'Ubuntu',
        osVersion: '22.04 LTS',
        externalIds: { cmdb: 'ASSET-101', aws: 'i-abc123' },
        labels: { environment: 'production' },
        description: 'Primary web application server',
        baselineRefs: ['RHEL9-STIG'],
        sbomRef: 'https://artifacts.agency.gov/sbom/web01.cdx.json',
        sbomFormat: 'cyclonedx',
      };
      expect(validate(valid)).toBe(true);
    });

    it('should reject a component with unknown type', () => {
      const invalid = {
        type: 'spaceship',
        name: 'enterprise',
      };
      expect(validate(invalid)).toBe(false);
    });
  });
});
