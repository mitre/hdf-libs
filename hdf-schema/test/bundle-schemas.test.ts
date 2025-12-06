import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { existsSync, rmSync, readFileSync } from 'fs';
import { join } from 'path';
import Ajv2020 from 'ajv/dist/2020.js';
import { bundleSchemas } from '../src/bundle-schemas';
import { loadFixture } from './setup';

const DIST_DIR = join(__dirname, '..', 'dist', 'schemas');

describe('bundle-schemas', () => {
  beforeAll(async () => {
    // Clean dist directory before tests
    if (existsSync(DIST_DIR)) {
      rmSync(DIST_DIR, { recursive: true });
    }
    // Run the bundler
    await bundleSchemas();
  });

  afterAll(() => {
    // Clean up after tests
    if (existsSync(DIST_DIR)) {
      rmSync(DIST_DIR, { recursive: true });
    }
  });

  describe('output files', () => {
    it('should create dist/schemas directory', () => {
      expect(existsSync(DIST_DIR)).toBe(true);
    });

    it('should create bundled hdf-results.schema.json', () => {
      expect(existsSync(join(DIST_DIR, 'hdf-results.schema.json'))).toBe(true);
    });

    it('should create bundled hdf-baseline.schema.json', () => {
      expect(existsSync(join(DIST_DIR, 'hdf-baseline.schema.json'))).toBe(true);
    });
  });

  describe('bundled hdf-results.schema.json', () => {
    let schema: Record<string, unknown>;
    let ajv: Ajv2020;

    beforeAll(() => {
      const content = readFileSync(join(DIST_DIR, 'hdf-results.schema.json'), 'utf-8');
      schema = JSON.parse(content);
      ajv = new Ajv2020({ strict: false, allErrors: true, validateFormats: true });
    });

    it('should be valid JSON', () => {
      expect(schema).toBeDefined();
      expect(typeof schema).toBe('object');
    });

    it('should have no external $ref (all resolved)', () => {
      const content = readFileSync(join(DIST_DIR, 'hdf-results.schema.json'), 'utf-8');
      // Should not contain references to external URLs
      expect(content).not.toContain('https://mitre.github.io/hdf-libs/schemas/primitives');
    });

    it.skip('should be self-contained (contain platform definition inline) - REMOVED IN v2', () => {
      // platform field removed, use targets array instead
      const properties = schema.properties as Record<string, unknown>;
      const platform = properties.platform as Record<string, unknown>;
      expect(platform).toHaveProperty('properties');
      expect(platform).not.toHaveProperty('$ref');
    });

    it('should validate a minimal results document', () => {
      const validate = ajv.compile(schema);
      const doc = {
        baselines: [{ name: 'test-baseline', checksum: { algorithm: 'sha256', value: 'abc123' }, supports: [], attributes: [], groups: [], requirements: [] }],
        statistics: { duration: 1.0 },
      };
      expect(validate(doc)).toBe(true);
    });

    it.skip('should validate legacy InSpec output - REQUIRES CONVERTER', () => {
      // v1 InSpec files must be converted
      const validate = ajv.compile(schema);
      const legacyDoc = loadFixture('legacy-inspec-exec.json');
      const isValid = validate(legacyDoc);
      if (!isValid) {
        console.error('Validation errors:', JSON.stringify(validate.errors, null, 2));
      }
      expect(isValid).toBe(true);
    });
  });

  describe('bundled hdf-baseline.schema.json', () => {
    let schema: Record<string, unknown>;
    let ajv: Ajv2020;

    beforeAll(() => {
      const content = readFileSync(join(DIST_DIR, 'hdf-baseline.schema.json'), 'utf-8');
      schema = JSON.parse(content);
      ajv = new Ajv2020({ strict: false, allErrors: true, validateFormats: true });
    });

    it('should be valid JSON', () => {
      expect(schema).toBeDefined();
      expect(typeof schema).toBe('object');
    });

    it('should have no external $ref (all resolved)', () => {
      const content = readFileSync(join(DIST_DIR, 'hdf-baseline.schema.json'), 'utf-8');
      expect(content).not.toContain('https://mitre.github.io/hdf-libs/schemas/primitives');
    });

    it('should be self-contained (no external $ref in groups)', () => {
      // The bundler inlines definitions where they're used
      const properties = schema.properties as Record<string, unknown>;
      const groups = properties.groups as Record<string, unknown>;
      const items = groups.items as Record<string, unknown>;
      expect(items).toHaveProperty('properties');
      expect(items).not.toHaveProperty('$ref');
    });

    it('should validate a minimal baseline document', () => {
      const validate = ajv.compile(schema);
      const doc = {
        name: 'test-baseline',
        checksum: { algorithm: 'sha256', value: 'abc123' },
        supports: [],
        attributes: [],
        groups: [],
        requirements: [],
      };
      expect(validate(doc)).toBe(true);
    });
  });
});
