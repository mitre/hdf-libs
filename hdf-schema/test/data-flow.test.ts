import { describe, it, expect } from 'vitest';
import Ajv2020 from 'ajv/dist/2020.js';
import addFormats from 'ajv-formats';
import commonSchema from '../src/schemas/primitives/common.schema.json';
import dataFlowSchema from '../src/schemas/primitives/data-flow.schema.json';
import { schemaRef } from './schema-ref';

describe('data-flow.schema.json', () => {
  const ajv = new Ajv2020({ strict: false, allErrors: true, validateFormats: true });
  addFormats(ajv);

  ajv.addSchema(commonSchema);
  ajv.addSchema(dataFlowSchema);

  // ── Data_Flow ──

  describe('Data_Flow', () => {
    const validate = ajv.compile({
      ...schemaRef(dataFlowSchema, 'Data_Flow'),
    });

    it('should validate a minimal data flow (from + to as local componentIds)', () => {
      const valid = {
        from: 'f47ac10b-58cc-4372-a567-0e02b2c3d479',
        to: 'a1b2c3d4-e5f6-7890-abcd-ef1234567890',
      };
      expect(validate(valid)).toBe(true);
    });

    it('should validate a fully specified local data flow', () => {
      const valid = {
        from: 'f47ac10b-58cc-4372-a567-0e02b2c3d479',
        to: 'a1b2c3d4-e5f6-7890-abcd-ef1234567890',
        protocol: 'https',
        port: 443,
        direction: 'unidirectional',
        description: 'API calls from WebTier to DatabaseTier',
        authentication: 'mTLS',
      };
      expect(validate(valid)).toBe(true);
    });

    it('should validate a data flow to a cross-system component', () => {
      const valid = {
        from: 'f47ac10b-58cc-4372-a567-0e02b2c3d479',
        to: {
          systemRef: 'https://systems.agency.gov/auth-system.json',
          componentId: 'b2c3d4e5-f6a7-8901-bcde-f12345678901',
        },
        protocol: 'https',
        direction: 'bidirectional',
        description: 'Authentication requests to auth system',
      };
      expect(validate(valid)).toBe(true);
    });

    it('should validate a data flow to an external endpoint', () => {
      const valid = {
        from: 'f47ac10b-58cc-4372-a567-0e02b2c3d479',
        to: {
          external: true,
          description: 'Third-party payment gateway (Stripe API)',
        },
        protocol: 'https',
        port: 443,
        direction: 'bidirectional',
        description: 'Payment processing via Stripe',
        authentication: 'API key + TLS',
      };
      expect(validate(valid)).toBe(true);
    });

    it('should reject a data flow missing from', () => {
      const invalid = {
        to: 'a1b2c3d4-e5f6-7890-abcd-ef1234567890',
      };
      expect(validate(invalid)).toBe(false);
    });

    it('should reject a data flow missing to', () => {
      const invalid = {
        from: 'f47ac10b-58cc-4372-a567-0e02b2c3d479',
      };
      expect(validate(invalid)).toBe(false);
    });

    it('should reject from that is not a valid UUID', () => {
      const invalid = {
        from: 'not-a-uuid',
        to: 'a1b2c3d4-e5f6-7890-abcd-ef1234567890',
      };
      expect(validate(invalid)).toBe(false);
    });

    it('should reject invalid direction value', () => {
      const invalid = {
        from: 'f47ac10b-58cc-4372-a567-0e02b2c3d479',
        to: 'a1b2c3d4-e5f6-7890-abcd-ef1234567890',
        direction: 'sideways',
      };
      expect(validate(invalid)).toBe(false);
    });

    it('should reject invalid port number', () => {
      const invalid = {
        from: 'f47ac10b-58cc-4372-a567-0e02b2c3d479',
        to: 'a1b2c3d4-e5f6-7890-abcd-ef1234567890',
        port: 0,
      };
      expect(validate(invalid)).toBe(false);
    });

    it('should reject port above 65535', () => {
      const invalid = {
        from: 'f47ac10b-58cc-4372-a567-0e02b2c3d479',
        to: 'a1b2c3d4-e5f6-7890-abcd-ef1234567890',
        port: 70000,
      };
      expect(validate(invalid)).toBe(false);
    });

    it('should reject cross-system reference missing componentId', () => {
      const invalid = {
        from: 'f47ac10b-58cc-4372-a567-0e02b2c3d479',
        to: {
          systemRef: 'https://systems.agency.gov/auth-system.json',
          // missing componentId
        },
      };
      expect(validate(invalid)).toBe(false);
    });

    it('should reject cross-system reference missing systemRef', () => {
      const invalid = {
        from: 'f47ac10b-58cc-4372-a567-0e02b2c3d479',
        to: {
          componentId: 'b2c3d4e5-f6a7-8901-bcde-f12345678901',
          // missing systemRef
        },
      };
      expect(validate(invalid)).toBe(false);
    });

    it('should reject external endpoint missing description', () => {
      const invalid = {
        from: 'f47ac10b-58cc-4372-a567-0e02b2c3d479',
        to: {
          external: true,
          // missing description
        },
      };
      expect(validate(invalid)).toBe(false);
    });

    it('should reject external endpoint with external=false', () => {
      const invalid = {
        from: 'f47ac10b-58cc-4372-a567-0e02b2c3d479',
        to: {
          external: false,
          description: 'This should fail because external must be true',
        },
      };
      expect(validate(invalid)).toBe(false);
    });
  });

  // ── Cross_System_Reference ──

  describe('Cross_System_Reference', () => {
    const validate = ajv.compile({
      ...schemaRef(dataFlowSchema, 'Cross_System_Reference'),
    });

    it('should validate a cross-system reference with URI', () => {
      const valid = {
        systemRef: 'https://systems.agency.gov/auth-system.json',
        componentId: 'b2c3d4e5-f6a7-8901-bcde-f12345678901',
      };
      expect(validate(valid)).toBe(true);
    });

    it('should validate a cross-system reference with relative path', () => {
      const valid = {
        systemRef: '../systems/auth-system.json',
        componentId: 'b2c3d4e5-f6a7-8901-bcde-f12345678901',
      };
      expect(validate(valid)).toBe(true);
    });

    it('should reject missing systemRef', () => {
      const invalid = {
        componentId: 'b2c3d4e5-f6a7-8901-bcde-f12345678901',
      };
      expect(validate(invalid)).toBe(false);
    });

    it('should reject missing componentId', () => {
      const invalid = {
        systemRef: 'https://systems.agency.gov/auth-system.json',
      };
      expect(validate(invalid)).toBe(false);
    });

    it('should reject componentId that is not a UUID', () => {
      const invalid = {
        systemRef: 'https://systems.agency.gov/auth-system.json',
        componentId: 'not-a-uuid',
      };
      expect(validate(invalid)).toBe(false);
    });
  });

  // ── External_Endpoint ──

  describe('External_Endpoint', () => {
    const validate = ajv.compile({
      ...schemaRef(dataFlowSchema, 'External_Endpoint'),
    });

    it('should validate a valid external endpoint', () => {
      const valid = {
        external: true,
        description: 'Third-party payment gateway',
      };
      expect(validate(valid)).toBe(true);
    });

    it('should reject external=false', () => {
      const invalid = {
        external: false,
        description: 'Not external',
      };
      expect(validate(invalid)).toBe(false);
    });

    it('should reject missing external field', () => {
      const invalid = {
        description: 'No external flag',
      };
      expect(validate(invalid)).toBe(false);
    });

    it('should reject missing description', () => {
      const invalid = {
        external: true,
      };
      expect(validate(invalid)).toBe(false);
    });
  });
});
