import { describe, it, expect } from 'vitest';
import Ajv2020 from 'ajv/dist/2020.js';
import addFormats from 'ajv-formats';
import commonSchema from '../src/schemas/primitives/common.schema.json';
import targetSchema from '../src/schemas/primitives/target.schema.json';
import platformSchema from '../src/schemas/primitives/platform.schema.json';

describe('Labels — optional Record<string, string> on components and baselines', () => {
  const ajv = new Ajv2020({ strict: false, allErrors: true, validateFormats: true });
  addFormats(ajv);

  ajv.addSchema(commonSchema);
  ajv.addSchema(targetSchema);
  ajv.addSchema(platformSchema);

  describe('Base_Target labels', () => {
    const validate = ajv.compile({
      $ref: 'https://mitre.github.io/hdf-libs/schemas/primitives/target/v2.0.0#/$defs/Base_Target',
    });

    it('should validate a target without labels (backward compatible)', () => {
      const target = { type: 'host', name: 'web-01' };
      expect(validate(target)).toBe(true);
    });

    it('should validate a target with labels', () => {
      const target = {
        type: 'host',
        name: 'web-01',
        labels: {
          system: 'Portal-Prod',
          component: 'WebTier',
          environment: 'production',
          region: 'us-gov-west-1',
          team: 'platform-eng',
        },
      };
      expect(validate(target)).toBe(true);
    });

    it('should validate a target with empty labels', () => {
      const target = { type: 'host', name: 'web-01', labels: {} };
      expect(validate(target)).toBe(true);
    });

    it('should reject labels with non-string values', () => {
      const target = { type: 'host', name: 'web-01', labels: { count: 42 } };
      expect(validate(target)).toBe(false);
    });

    it('should reject labels with null values', () => {
      const target = { type: 'host', name: 'web-01', labels: { env: null } };
      expect(validate(target)).toBe(false);
    });

    it('should reject labels with array values', () => {
      const target = { type: 'host', name: 'web-01', labels: { tags: ['a', 'b'] } };
      expect(validate(target)).toBe(false);
    });

    it('should reject labels with object values', () => {
      const target = { type: 'host', name: 'web-01', labels: { meta: { nested: true } } };
      expect(validate(target)).toBe(false);
    });

    it('should reject non-object labels', () => {
      const target = { type: 'host', name: 'web-01', labels: 'not-an-object' };
      expect(validate(target)).toBe(false);
    });
  });

  describe('Host_Target labels (inherited via allOf)', () => {
    const validate = ajv.compile({
      $ref: 'https://mitre.github.io/hdf-libs/schemas/primitives/target/v2.0.0#/$defs/Host_Target',
    });

    it('should validate a Host_Target with labels', () => {
      const target = {
        type: 'host',
        name: 'web-01',
        fqdn: 'web01.prod.example.com',
        labels: { system: 'Portal', environment: 'prod' },
      };
      expect(validate(target)).toBe(true);
    });

    it('should validate a Host_Target without labels', () => {
      const target = { type: 'host', name: 'web-01' };
      expect(validate(target)).toBe(true);
    });
  });

  describe('Cloud_Account_Target labels (inherited via allOf)', () => {
    const validate = ajv.compile({
      $ref: 'https://mitre.github.io/hdf-libs/schemas/primitives/target/v2.0.0#/$defs/Cloud_Account_Target',
    });

    it('should validate a Cloud_Account_Target with labels', () => {
      const target = {
        type: 'cloudAccount',
        name: 'prod-aws',
        provider: 'aws',
        accountId: '123456789012',
        labels: { system: 'MainApp', team: 'cloud-ops' },
      };
      expect(validate(target)).toBe(true);
    });
  });

  describe('Baseline_Metadata labels', () => {
    const validate = ajv.compile({
      $ref: 'https://mitre.github.io/hdf-libs/schemas/primitives/common/v2.0.0#/$defs/Baseline_Metadata',
    });

    it('should validate Baseline_Metadata without labels (backward compatible)', () => {
      const meta = { name: 'my-baseline', version: '1.0.0' };
      expect(validate(meta)).toBe(true);
    });

    it('should validate Baseline_Metadata with labels', () => {
      const meta = {
        name: 'my-baseline',
        version: '1.0.0',
        labels: {
          system: 'Portal-Prod',
          environment: 'production',
        },
      };
      expect(validate(meta)).toBe(true);
    });

    it('should validate Baseline_Metadata with empty labels', () => {
      const meta = { name: 'my-baseline', labels: {} };
      expect(validate(meta)).toBe(true);
    });

    it('should reject Baseline_Metadata labels with non-string values', () => {
      const meta = { name: 'my-baseline', labels: { priority: 1 } };
      expect(validate(meta)).toBe(false);
    });

    it('should reject Baseline_Metadata labels with boolean values', () => {
      const meta = { name: 'my-baseline', labels: { active: true } };
      expect(validate(meta)).toBe(false);
    });
  });
});
