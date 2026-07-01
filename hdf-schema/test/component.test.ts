import { describe, it, expect } from 'vitest';
import Ajv2020 from 'ajv/dist/2020.js';
import addFormats from 'ajv-formats';
import commonSchema from '../src/schemas/primitives/common.schema.json';
import systemSchema from '../src/schemas/primitives/system.schema.json';
import targetSchema from '../src/schemas/primitives/target.schema.json';
import componentSchema from '../src/schemas/primitives/component.schema.json';
import bomSchema from '../src/schemas/primitives/bom.schema.json';
import { schemaRef } from './schema-ref';

describe('component.schema.json', () => {
  const ajv = new Ajv2020({ strict: false, allErrors: true, validateFormats: true });
  addFormats(ajv);

  ajv.addSchema(commonSchema);
  ajv.addSchema(systemSchema);
  ajv.addSchema(targetSchema);
  ajv.addSchema(bomSchema);
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

  // ── BOM attachment (boms[]) — generalized, replaces the SBOM trio ──

  describe('BOM attachment (boms[])', () => {
    const validate = ajv.compile({
      ...schemaRef(componentSchema, 'Base_Component'),
    });

    it('should validate a component with a passthrough SBOM by reference', () => {
      const valid = {
        name: 'WebTier',
        type: 'application',
        boms: [
          {
            bomType: 'sbom',
            format: 'cyclonedx',
            ref: 'https://artifacts.agency.gov/sbom/webtier.cdx.json',
          },
        ],
      };
      expect(validate(valid)).toBe(true);
    });

    it('should validate a component with an embedded (document) passthrough SBOM', () => {
      const valid = {
        name: 'WebTier',
        type: 'application',
        boms: [
          {
            bomType: 'sbom',
            format: 'cyclonedx',
            document: { bomFormat: 'CycloneDX', specVersion: '1.5' },
          },
        ],
      };
      expect(validate(valid)).toBe(true);
    });

    it('should validate a component carrying multiple BOMs (sbom + ai-model)', () => {
      const valid = {
        name: 'InferenceService',
        type: 'application',
        boms: [
          { bomType: 'sbom', format: 'spdx', ref: './sboms/svc.spdx.json' },
          {
            bomType: 'ai-model',
            format: 'cyclonedx-ml',
            model: { parameterCount: 6738415616, adaptationType: 'finetune' },
          },
        ],
      };
      expect(validate(valid)).toBe(true);
    });

    it('should validate passthrough for every reserved bomType', () => {
      const reserved = ['sbom', 'ai-model', 'dataset', 'hbom', 'cbom', 'saasbom', 'obom', 'mbom', 'kbom'];
      for (const bomType of reserved) {
        const valid = {
          name: 'C',
          type: 'application',
          boms: [{ bomType, format: 'cyclonedx', ref: './x.json' }],
        };
        expect(validate(valid), `passthrough should validate for ${bomType}`).toBe(true);
      }
    });

    it('should reject a BOM missing bomType', () => {
      const invalid = {
        name: 'WebTier',
        type: 'application',
        boms: [{ format: 'cyclonedx', ref: './x.json' }],
      };
      expect(validate(invalid)).toBe(false);
    });

    it('should reject a BOM missing format', () => {
      const invalid = {
        name: 'WebTier',
        type: 'application',
        boms: [{ bomType: 'sbom', ref: './x.json' }],
      };
      expect(validate(invalid)).toBe(false);
    });

    it('should reject an unknown bomType value', () => {
      const invalid = {
        name: 'WebTier',
        type: 'application',
        boms: [{ bomType: 'vex', format: 'cyclonedx', ref: './x.json' }],
      };
      expect(validate(invalid)).toBe(false);
    });

    it('should reject a BOM with an unknown property (strict base)', () => {
      const invalid = {
        name: 'WebTier',
        type: 'application',
        boms: [{ bomType: 'sbom', format: 'cyclonedx', sbomFormat: 'cyclonedx' }],
      };
      expect(validate(invalid)).toBe(false);
    });

    it('should reject an invalid adaptationType enum value', () => {
      const invalid = {
        name: 'M',
        type: 'application',
        boms: [
          { bomType: 'ai-model', format: 'cyclonedx-ml', model: { adaptationType: 'distilled' } },
        ],
      };
      expect(validate(invalid)).toBe(false);
    });

    it('should reject the ai-model extension on a non-ai-model BOM (three-tier discipline)', () => {
      const invalid = {
        name: 'WebTier',
        type: 'application',
        boms: [{ bomType: 'sbom', format: 'cyclonedx', model: { parameterCount: 100 } }],
      };
      expect(validate(invalid)).toBe(false);
    });

    it('should reject the normalized packages extension on a non-sbom BOM', () => {
      const invalid = {
        name: 'M',
        type: 'application',
        boms: [
          { bomType: 'ai-model', format: 'cyclonedx-ml', packages: [{ name: 'express' }] },
        ],
      };
      expect(validate(invalid)).toBe(false);
    });

    it('should validate a normalized dataset BOM', () => {
      const valid = {
        name: 'TrainingCorpus',
        type: 'application',
        boms: [
          {
            bomType: 'dataset',
            format: 'croissant',
            dataset: { recordCount: 2500000, datasetFormat: 'parquet' },
          },
        ],
      };
      expect(validate(valid)).toBe(true);
    });

    it('should validate a dataset BOM with lineage (baseDatasetRefs + derivation)', () => {
      const valid = {
        name: 'TrainingCorpus',
        type: 'application',
        boms: [
          {
            bomType: 'dataset',
            format: 'croissant',
            dataset: {
              recordCount: 1000000,
              baseDatasetRefs: ['b7c8d9e0-1a2b-4c3d-8e4f-5a6b7c8d9e0f'],
              derivation: 'filtered',
            },
          },
        ],
      };
      expect(validate(valid)).toBe(true);
    });

    it('should reject an invalid dataset derivation enum value', () => {
      const invalid = {
        name: 'TrainingCorpus',
        type: 'application',
        boms: [
          { bomType: 'dataset', format: 'croissant', dataset: { derivation: 'synthesized' } },
        ],
      };
      expect(validate(invalid)).toBe(false);
    });

    it('should reject dataset lineage carried on a non-dataset BOM (three-tier)', () => {
      const invalid = {
        name: 'M',
        type: 'application',
        boms: [
          { bomType: 'ai-model', format: 'cyclonedx-ml', dataset: { derivation: 'filtered' } },
        ],
      };
      expect(validate(invalid)).toBe(false);
    });
  });

  // ── Artifact integrity (Base_Component.integrity) ──

  describe('Artifact integrity (Base_Component.integrity)', () => {
    const validate = ajv.compile({
      ...schemaRef(componentSchema, 'Base_Component'),
    });

    it('should validate a component with an integrity checksum array', () => {
      const valid = {
        name: 'Llama-2-7b weights',
        type: 'aiModel',
        integrity: [
          { algorithm: 'sha256', value: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855' },
        ],
      };
      expect(validate(valid)).toBe(true);
    });

    it('should validate multi-file (sharded) artifact integrity', () => {
      const valid = {
        name: 'sharded-model',
        type: 'aiModel',
        integrity: [
          { algorithm: 'sha256', value: 'aa11bb22cc33dd44ee55ff66aa11bb22cc33dd44ee55ff66aa11bb22cc33dd44' },
          { algorithm: 'sha512', value: 'cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e' },
        ],
      };
      expect(validate(valid)).toBe(true);
    });

    it('should validate dataset artifact integrity via the same shared field', () => {
      const valid = {
        name: 'training-corpus',
        type: 'dataset',
        integrity: [
          { algorithm: 'sha512', value: 'cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e' },
        ],
      };
      expect(validate(valid)).toBe(true);
    });

    it('should accept blake3 as a hash algorithm (absorbed container-image digests)', () => {
      const valid = {
        name: 'nginx',
        type: 'containerImage',
        integrity: [{ algorithm: 'blake3', value: 'a9286defaba7b3a519d585ba0e37d0b2cbee74ebfe590960b0b1d6a5e97d1e1d' }],
      };
      expect(validate(valid)).toBe(true);
    });

    it('should reject an integrity entry with an unknown hash algorithm', () => {
      const invalid = {
        name: 'M',
        type: 'aiModel',
        integrity: [{ algorithm: 'md5', value: 'd41d8cd98f00b204e9800998ecf8427e' }],
      };
      expect(validate(invalid)).toBe(false);
    });

    it('should reject an integrity entry missing the value', () => {
      const invalid = {
        name: 'M',
        type: 'aiModel',
        integrity: [{ algorithm: 'sha256' }],
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
        integrity: [{ algorithm: 'sha256', value: 'a9286defaba7b3a519d585ba0e37d0b2cbee74ebfe590960b0b1d6a5e97d1e1d' }],
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
        boms: [{ bomType: 'sbom', format: 'cyclonedx', ref: 'https://artifacts.agency.gov/sbom/web01.cdx.json' }],
      };
      expect(validate(valid)).toBe(true);
    });

    it('should validate an AI_Model_Component', () => {
      const valid = {
        type: 'aiModel',
        name: 'Llama-2-7b-chat (finetuned)',
        componentId: 'b7c8d9e0-1a2b-4c3d-8e4f-5a6b7c8d9e0f',
        modelId: 'acme/llama-2-7b-chat-support',
        version: '1.2.0',
        boms: [
          {
            bomType: 'ai-model',
            format: 'cyclonedx-ml',
            model: { parameterCount: 6738415616, serializationFormat: 'safetensors', adaptationType: 'finetune' },
          },
        ],
      };
      expect(validate(valid)).toBe(true);
    });

    it('should validate a Dataset_Component', () => {
      const valid = {
        type: 'dataset',
        name: 'UltraChat-200k (filtered)',
        componentId: 'c1d2e3f4-a5b6-4c7d-8e9f-0a1b2c3d4e5f',
        datasetId: 'acme/ultrachat-200k-filtered',
        version: '2026-06-01',
        boms: [
          {
            bomType: 'dataset',
            format: 'croissant',
            dataset: {
              recordCount: 180000,
              datasetFormat: 'parquet',
              dataClassification: 'public',
              baseDatasetRefs: ['HuggingFaceH4/ultrachat_200k'],
              derivation: 'filtered',
            },
          },
        ],
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
