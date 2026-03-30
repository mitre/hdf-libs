import { describe, it, expect, beforeAll } from 'vitest';
import { existsSync, rmSync, readFileSync } from 'fs';
import { join } from 'path';
import Ajv2020 from 'ajv/dist/2020.js';
import addFormats from 'ajv-formats';
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
      addFormats(ajv);
    });

    it('should be valid JSON', () => {
      expect(schema).toBeDefined();
      expect(typeof schema).toBe('object');
    });

    it('should embed referenced schemas in $defs (spec-compliant bundling)', () => {
      const content = readFileSync(join(DIST_DIR, 'hdf-results.schema.json'), 'utf-8');
      const bundled = JSON.parse(content);

      // The bundle should contain $refs to primitive schemas (spec-compliant approach)
      expect(content).toContain('https://mitre.github.io/hdf-libs/schemas/primitives');

      // But those schemas should be embedded in $defs at the end of the file
      expect(bundled).toHaveProperty('$defs');

      // Check that primitive schemas are embedded (not external)
      const defsKeys = Object.keys(bundled.$defs || {});
      const hasEmbeddedPrimitives = defsKeys.some(key =>
        key.includes('https://mitre.github.io/hdf-libs/schemas/primitives')
      );
      expect(hasEmbeddedPrimitives).toBe(true);
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
        baselines: [{ name: 'test-baseline', integrity: { algorithm: 'sha256', checksum: 'abc123' }, supports: [], inputs: [], groups: [], requirements: [{ id: 'SV-1', impact: 0.5, tags: {}, descriptions: [{ label: 'default', data: 'Test' }], results: [{ status: 'passed', codeDesc: 'Test', startTime: '2025-01-01T00:00:00Z' }] }] }],
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
      addFormats(ajv);
    });

    it('should be valid JSON', () => {
      expect(schema).toBeDefined();
      expect(typeof schema).toBe('object');
    });

    it('should embed referenced schemas in $defs (spec-compliant bundling)', () => {
      const content = readFileSync(join(DIST_DIR, 'hdf-baseline.schema.json'), 'utf-8');
      const bundled = JSON.parse(content);

      // The bundle should contain $refs to primitive schemas (spec-compliant approach)
      expect(content).toContain('https://mitre.github.io/hdf-libs/schemas/primitives');

      // But those schemas should be embedded in $defs
      expect(bundled).toHaveProperty('$defs');

      // Check that primitive schemas are embedded (not external)
      const defsKeys = Object.keys(bundled.$defs || {});
      const hasEmbeddedPrimitives = defsKeys.some(key =>
        key.includes('https://mitre.github.io/hdf-libs/schemas/primitives')
      );
      expect(hasEmbeddedPrimitives).toBe(true);
    });

    it('should preserve $ref URIs (spec-compliant bundling)', () => {
      // The spec-compliant bundler maintains $ref URIs rather than inlining everything
      // This allows tools to resolve by $id, which is more robust
      const properties = schema.properties as Record<string, unknown>;
      const groups = properties.groups as Record<string, unknown>;
      const items = groups.items as Record<string, unknown>;

      // groups.items should have a $ref (spec-compliant)
      expect(items).toHaveProperty('$ref');
    });

    it('should validate a minimal baseline document', () => {
      const validate = ajv.compile(schema);
      const doc = {
        name: 'test-baseline',
        integrity: { algorithm: 'sha256', checksum: 'abc123' },
        supports: [],
        groups: [],
        requirements: [
          {
            id: 'SV-238196',
            impact: 0.7,
            tags: {},
            code: 'control "SV-238196" do\nend',
            descriptions: [
              { label: 'default', data: 'Test requirement' }
            ],
          }
        ],
      };
      expect(validate(doc)).toBe(true);
    });
  });
});
