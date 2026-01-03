import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { existsSync, rmSync, readFileSync, renameSync } from 'fs';
import { join } from 'path';
import { bundleSchemas } from '../src/bundle-schemas';
import { generateTypes } from '../src/generate-types';

const DIST_DIR = join(__dirname, '..', 'dist');
const SCHEMAS_DIR = join(DIST_DIR, 'schemas');

describe('generate-types', () => {
  beforeAll(async () => {
    // Clean type output directories before tests
    for (const lang of ['ts', 'go', 'python']) {
      const dir = join(DIST_DIR, lang);
      if (existsSync(dir)) {
        rmSync(dir, { recursive: true });
      }
    }
    // First bundle schemas, then generate types
    await bundleSchemas();
    await generateTypes();
  });

  describe('TypeScript output', () => {
    it('should create dist/ts directory', () => {
      expect(existsSync(join(DIST_DIR, 'ts'))).toBe(true);
    });

    it('should create hdf-results.ts', () => {
      expect(existsSync(join(DIST_DIR, 'ts', 'hdf-results.ts'))).toBe(true);
    });

    it('should create hdf-baseline.ts', () => {
      expect(existsSync(join(DIST_DIR, 'ts', 'hdf-baseline.ts'))).toBe(true);
    });

    it('should export interfaces in hdf-results.ts', () => {
      const content = readFileSync(join(DIST_DIR, 'ts', 'hdf-results.ts'), 'utf-8');
      expect(content).toContain('export interface');
    });

    it('should contain HdfResults type', () => {
      const content = readFileSync(join(DIST_DIR, 'ts', 'hdf-results.ts'), 'utf-8');
      expect(content).toMatch(/export interface.*HdfResults|HDF.*Results/i);
    });
  });

  describe('Go output', () => {
    it('should create dist/go directory', () => {
      expect(existsSync(join(DIST_DIR, 'go'))).toBe(true);
    });

    it('should create hdf_results.go', () => {
      expect(existsSync(join(DIST_DIR, 'go', 'hdf_results.go'))).toBe(true);
    });

    it('should create hdf_baseline.go', () => {
      expect(existsSync(join(DIST_DIR, 'go', 'hdf_baseline.go'))).toBe(true);
    });

    it('should contain package declaration', () => {
      const content = readFileSync(join(DIST_DIR, 'go', 'hdf_results.go'), 'utf-8');
      expect(content).toContain('package hdf');
    });

    it('should contain struct definitions', () => {
      const content = readFileSync(join(DIST_DIR, 'go', 'hdf_results.go'), 'utf-8');
      expect(content).toContain('type');
      expect(content).toContain('struct');
    });
  });

  describe('Python output', () => {
    it('should create dist/python directory', () => {
      expect(existsSync(join(DIST_DIR, 'python'))).toBe(true);
    });

    it('should create hdf_results.py', () => {
      expect(existsSync(join(DIST_DIR, 'python', 'hdf_results.py'))).toBe(true);
    });

    it('should create hdf_baseline.py', () => {
      expect(existsSync(join(DIST_DIR, 'python', 'hdf_baseline.py'))).toBe(true);
    });

    it('should contain class definitions', () => {
      const content = readFileSync(join(DIST_DIR, 'python', 'hdf_results.py'), 'utf-8');
      expect(content).toContain('class');
    });

    it('should use dataclasses or typing', () => {
      const content = readFileSync(join(DIST_DIR, 'python', 'hdf_results.py'), 'utf-8');
      expect(content).toMatch(/dataclass|@dataclass|from typing|TypedDict/);
    });
  });

  describe('Error handling', () => {
    it('should throw error when bundled schemas directory does not exist', async () => {
      // Temporarily rename schemas directory
      const tempDir = join(DIST_DIR, 'schemas-temp');
      if (existsSync(SCHEMAS_DIR)) {
        renameSync(SCHEMAS_DIR, tempDir);
      }

      try {
        await expect(generateTypes()).rejects.toThrow(
          'Bundled schemas not found'
        );
      } finally {
        // Restore schemas directory
        if (existsSync(tempDir)) {
          renameSync(tempDir, SCHEMAS_DIR);
        }
      }
    });

    it('should handle missing schema files gracefully', async () => {
      // Temporarily rename one schema file
      const schemaFile = join(SCHEMAS_DIR, 'hdf-results.schema.json');
      const tempFile = join(SCHEMAS_DIR, 'hdf-results.schema.json.temp');

      if (existsSync(schemaFile)) {
        renameSync(schemaFile, tempFile);
      }

      try {
        // Should not throw, just skip the missing file
        await expect(generateTypes()).resolves.not.toThrow();
      } finally {
        // Restore schema file
        if (existsSync(tempFile)) {
          renameSync(tempFile, schemaFile);
        }
      }
    });
  });
});
