import { describe, it, expect } from 'vitest';
import Ajv2020 from 'ajv/dist/2020.js';
import addFormats from 'ajv-formats';
import commonSchema from '../src/schemas/primitives/common.schema.json';
import parameterSchema from '../src/schemas/primitives/parameter.schema.json';
import { schemaRef } from './schema-ref';

describe('parameter.schema.json — Input primitive', () => {
  const ajv = new Ajv2020({ strict: false, allErrors: true, validateFormats: true });
  addFormats(ajv);

  ajv.addSchema(commonSchema);
  ajv.addSchema(parameterSchema);

  const validate = ajv.compile({
    ...schemaRef(parameterSchema, 'Input'),
  });

  describe('valid inputs', () => {
    it('should validate a minimal Input (name only)', () => {
      const input = { name: 'max_sessions' };
      expect(validate(input)).toBe(true);
      expect(validate.errors).toBeNull();
    });

    it('should validate a fully-specified Numeric Input', () => {
      const input = {
        name: 'max_concurrent_sessions',
        type: 'Numeric',
        value: 3,
        description: 'Maximum concurrent sessions per user',
        required: true,
        sensitive: false,
        operator: 'le',
        constraints: { min: 1, max: 100 },
      };
      expect(validate(input)).toBe(true);
      expect(validate.errors).toBeNull();
    });

    it('should validate a String Input with pattern constraint', () => {
      const input = {
        name: 'allowed_ciphers',
        type: 'String',
        value: 'AES256-GCM',
        description: 'Permitted TLS cipher suite',
        constraints: { pattern: '^AES' },
      };
      expect(validate(input)).toBe(true);
    });

    it('should validate a Boolean Input', () => {
      const input = {
        name: 'enforce_tls',
        type: 'Boolean',
        value: true,
        required: true,
      };
      expect(validate(input)).toBe(true);
    });

    it('should validate an Array Input with allowedValues constraint', () => {
      const input = {
        name: 'permitted_protocols',
        type: 'Array',
        value: ['TLSv1.2', 'TLSv1.3'],
        constraints: { allowedValues: ['TLSv1.2', 'TLSv1.3', 'TLSv1.1'] },
      };
      expect(validate(input)).toBe(true);
    });

    it('should validate a Hash Input', () => {
      const input = {
        name: 'firewall_rules',
        type: 'Hash',
        value: { inbound: 'deny', outbound: 'allow' },
      };
      expect(validate(input)).toBe(true);
    });

    it('should validate a Regexp Input', () => {
      const input = {
        name: 'log_pattern',
        type: 'Regexp',
        value: '^ERROR|WARN',
        operator: 'matches',
      };
      expect(validate(input)).toBe(true);
    });

    it('should validate an Input with sensitive flag', () => {
      const input = {
        name: 'db_password',
        type: 'String',
        sensitive: true,
      };
      expect(validate(input)).toBe(true);
    });

    it('should accept all valid operator values', () => {
      const operators = ['eq', 'ne', 'lt', 'le', 'gt', 'ge', 'contains', 'matches', 'in', 'notIn'];
      for (const op of operators) {
        const input = { name: 'test', operator: op };
        expect(validate(input)).toBe(true);
      }
    });

    it('should accept all valid type values', () => {
      const types = ['String', 'Numeric', 'Boolean', 'Array', 'Hash', 'Regexp'];
      for (const type of types) {
        const input = { name: 'test', type };
        expect(validate(input)).toBe(true);
      }
    });

    it('should accept value of any JSON type', () => {
      const values = [42, 'hello', true, [1, 2], { key: 'val' }, null];
      for (const value of values) {
        const input = { name: 'test', value };
        expect(validate(input)).toBe(true);
      }
    });

    it('should accept constraints with only min', () => {
      const input = { name: 'port', constraints: { min: 1 } };
      expect(validate(input)).toBe(true);
    });

    it('should accept constraints with only max', () => {
      const input = { name: 'port', constraints: { max: 65535 } };
      expect(validate(input)).toBe(true);
    });

    it('should accept constraints with min and max', () => {
      const input = { name: 'port', constraints: { min: 1, max: 65535 } };
      expect(validate(input)).toBe(true);
    });
  });

  describe('invalid inputs', () => {
    it('should reject Input missing required name', () => {
      const input = { type: 'String', value: 'hello' };
      expect(validate(input)).toBe(false);
    });

    it('should reject Input with non-string name', () => {
      const input = { name: 123 };
      expect(validate(input)).toBe(false);
    });

    it('should reject Input with invalid type enum', () => {
      const input = { name: 'test', type: 'Integer' };
      expect(validate(input)).toBe(false);
    });

    it('should reject Input with invalid operator enum', () => {
      const input = { name: 'test', operator: 'like' };
      expect(validate(input)).toBe(false);
    });

    it('should reject Input with non-boolean required field', () => {
      const input = { name: 'test', required: 'yes' };
      expect(validate(input)).toBe(false);
    });

    it('should reject Input with non-boolean sensitive field', () => {
      const input = { name: 'test', sensitive: 1 };
      expect(validate(input)).toBe(false);
    });

    it('should reject Input with non-string description', () => {
      const input = { name: 'test', description: 42 };
      expect(validate(input)).toBe(false);
    });

    it('should reject Input with unknown properties', () => {
      const input = { name: 'test', unknown: 'field' };
      expect(validate(input)).toBe(false);
    });

    it('should reject constraints with non-number min', () => {
      const input = { name: 'test', constraints: { min: 'low' } };
      expect(validate(input)).toBe(false);
    });

    it('should reject constraints with non-number max', () => {
      const input = { name: 'test', constraints: { max: 'high' } };
      expect(validate(input)).toBe(false);
    });

    it('should reject constraints with non-string pattern', () => {
      const input = { name: 'test', constraints: { pattern: 123 } };
      expect(validate(input)).toBe(false);
    });

    it('should reject constraints with non-array allowedValues', () => {
      const input = { name: 'test', constraints: { allowedValues: 'foo' } };
      expect(validate(input)).toBe(false);
    });
  });
});
