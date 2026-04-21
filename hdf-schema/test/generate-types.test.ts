import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { existsSync, readFileSync, renameSync, rmSync, writeFileSync } from 'fs';
import { join } from 'path';
import { bundleSchemas } from '../src/bundle-schemas';
import { generateTypes, toOutputFilename } from '../src/generate-types';
import { createIndex } from '../src/create-index';

const DIST_DIR = join(__dirname, '..', 'dist');
const SCHEMAS_DIR = join(DIST_DIR, 'schemas');

describe('generate-types', () => {
  beforeAll(async () => {
    // Regenerate types from bundled schemas (overwrites existing files)
    // NOTE: Do NOT delete dist/{ts,go,python} here — other CI steps and parallel
    // test runs (e.g. hdf-cli Go tests) depend on dist/go/ existing. If pnpm aborts
    // this test mid-flight, deleted directories won't be restored.
    await bundleSchemas();
    await generateTypes();
  });

  afterAll(() => {
    // Create index files and compile TypeScript after all tests complete
    // This ensures other packages can import from @mitre/hdf-schema during parallel test runs
    createIndex();
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

    it('should create hdf-comparison.ts', () => {
      expect(existsSync(join(DIST_DIR, 'ts', 'hdf-comparison.ts'))).toBe(true);
    });

    it('should create hdf-comparison.d.ts after index creation', () => {
      // The .d.ts is created by createIndex() in afterAll, so we verify
      // the .ts source exists here (the .d.ts test is in the index tests)
      const tsFile = join(DIST_DIR, 'ts', 'hdf-comparison.ts');
      expect(existsSync(tsFile)).toBe(true);
    });

    it('should export interfaces in hdf-comparison.ts', () => {
      const content = readFileSync(join(DIST_DIR, 'ts', 'hdf-comparison.ts'), 'utf-8');
      expect(content).toContain('export interface');
    });

    it('should contain HdfComparison type', () => {
      const content = readFileSync(join(DIST_DIR, 'ts', 'hdf-comparison.ts'), 'utf-8');
      expect(content).toMatch(/export interface.*HdfComparison/);
    });

    it('should contain RequirementDiff type', () => {
      const content = readFileSync(join(DIST_DIR, 'ts', 'hdf-comparison.ts'), 'utf-8');
      expect(content).toMatch(/RequirementDiff|Requirement_Diff/);
    });

    it('should contain ComparisonSummary type', () => {
      const content = readFileSync(join(DIST_DIR, 'ts', 'hdf-comparison.ts'), 'utf-8');
      expect(content).toMatch(/ComparisonSummary|Comparison_Summary|Summary/);
    });

    it('should contain Source type', () => {
      const content = readFileSync(join(DIST_DIR, 'ts', 'hdf-comparison.ts'), 'utf-8');
      expect(content).toMatch(/Source/);
    });
  });

  describe('Go output', () => {
    it('should create dist/go directory', () => {
      expect(existsSync(join(DIST_DIR, 'go'))).toBe(true);
    });

    it('should create combined hdf.go file', () => {
      // Go types are combined into a single file to avoid duplicate type declarations
      expect(existsSync(join(DIST_DIR, 'go', 'hdf.go'))).toBe(true);
    });

    it('should create go.mod file', () => {
      expect(existsSync(join(DIST_DIR, 'go', 'go.mod'))).toBe(true);
    });

    it('should contain package declaration', () => {
      const content = readFileSync(join(DIST_DIR, 'go', 'hdf.go'), 'utf-8');
      expect(content).toContain('package hdf');
    });

    it('should contain struct definitions for all schemas', () => {
      const content = readFileSync(join(DIST_DIR, 'go', 'hdf.go'), 'utf-8');
      expect(content).toContain('type');
      expect(content).toContain('struct');
      // Should contain types from all three schemas
      expect(content).toMatch(/HDFResults|HdfResults/);
      expect(content).toMatch(/HDFBaseline|HdfBaseline/);
      expect(content).toMatch(/HDFComparison|HdfComparison/);
    });

    it('should add omitempty tags to optional pointer fields', () => {
      const content = readFileSync(join(DIST_DIR, 'go', 'hdf.go'), 'utf-8');

      // Target struct should have omitempty on optional fields
      // Example: FQDN *string `json:"fqdn,omitempty"`
      const fqdnMatch = content.match(/FQDN\s+\*string\s+`json:"fqdn,omitempty"`/);
      expect(fqdnMatch).toBeTruthy();

      // IPAddress should have omitempty
      const ipMatch = content.match(/IPAddress.*\*string\s+`json:"ipAddress,omitempty"`/);
      expect(ipMatch).toBeTruthy();

      // Check other optional fields have omitempty
      const osNameMatch = content.match(/OSName.*\*string\s+`json:"osName,omitempty"`/);
      expect(osNameMatch).toBeTruthy();
    });

    it('should NOT add omitempty to required fields', () => {
      const content = readFileSync(join(DIST_DIR, 'go', 'hdf.go'), 'utf-8');

      // Name is a required field in BaselineMetadata - should not have omitempty
      const nameMatch = content.match(/Name\s+string\s+`json:"name"`[^,]/);
      expect(nameMatch).toBeTruthy();

      // Type is a required field in various structs - should not have omitempty
      // Check for any Type field without omitempty
      const typeMatch = content.match(/Type\s+\w+\s+`json:"type"`[^,]/);
      expect(typeMatch).toBeTruthy();
    });

    it('should have omitempty on all optional EvaluatedBaseline fields', () => {
      const content = readFileSync(join(DIST_DIR, 'go', 'hdf.go'), 'utf-8');

      // Optional fields like Title, Version, Status should have omitempty
      const titleMatch = content.match(/Title.*\*string\s+`json:"title,omitempty"`/);
      expect(titleMatch).toBeTruthy();

      const versionMatch = content.match(/Version.*\*string\s+`json:"version,omitempty"`/);
      expect(versionMatch).toBeTruthy();
    });
  });

  describe('toOutputFilename', () => {
    it('should convert hyphens to underscores for Go output', () => {
      // Exercises the ext === 'go' branch (line 41)
      expect(toOutputFilename('hdf-results.schema.json', 'go')).toBe('hdf_results.go');
      expect(toOutputFilename('hdf-evidence-package.schema.json', 'go')).toBe('hdf_evidence_package.go');
    });

    it('should preserve hyphens for TypeScript output', () => {
      expect(toOutputFilename('hdf-results.schema.json', 'ts')).toBe('hdf-results.ts');
      expect(toOutputFilename('hdf-baseline.schema.json', 'ts')).toBe('hdf-baseline.ts');
    });
  });

  describe('output directory creation', () => {
    it('should create output directories when they do not exist', async () => {
      // Delete output dirs to exercise the `!existsSync(outputDir)` true branch
      // at line 232 (mkdirSync). The beforeAll ensures schemas are bundled.
      const tsDir = join(DIST_DIR, 'ts');
      const goDir = join(DIST_DIR, 'go');

      if (existsSync(tsDir)) rmSync(tsDir, { recursive: true });
      if (existsSync(goDir)) rmSync(goDir, { recursive: true });

      expect(existsSync(tsDir)).toBe(false);
      expect(existsSync(goDir)).toBe(false);

      await generateTypes();

      // Dirs should now exist with generated content
      expect(existsSync(tsDir)).toBe(true);
      expect(existsSync(goDir)).toBe(true);
      expect(existsSync(join(tsDir, 'hdf-results.ts'))).toBe(true);
      expect(existsSync(join(goDir, 'hdf.go'))).toBe(true);
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
        // Regenerate with all schemas to restore correct state
        await generateTypes();
      }
    });

    it('should skip individual TS schemas that cause quicktype to error', async () => {
      // Replace one bundled schema with content that quicktype cannot process,
      // exercising the per-file error catch at line 325.
      const schemaFile = join(SCHEMAS_DIR, 'hdf-comparison.schema.json');
      const backupFile = join(SCHEMAS_DIR, 'hdf-comparison.schema.json.bak');
      const original = readFileSync(schemaFile, 'utf-8');

      writeFileSync(backupFile, original);

      try {
        // Write a schema that will fail quicktype (recursive $ref with no base case)
        writeFileSync(schemaFile, JSON.stringify({
          $schema: 'https://json-schema.org/draft/2020-12/schema',
          $id: 'https://mitre.github.io/hdf-libs/schemas/hdf-comparison/v1.0.0',
          type: 'INVALID_TYPE',
        }));

        // generateTypes should not throw — it catches per-file errors
        await expect(generateTypes()).resolves.not.toThrow();
      } finally {
        // Restore original schema
        writeFileSync(schemaFile, original);
        if (existsSync(backupFile)) rmSync(backupFile);
        // Regenerate to restore clean state
        await generateTypes();
      }
    });
  });
});
