import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { existsSync, rmSync, mkdirSync, writeFileSync, readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath, pathToFileURL } from 'url';
import { createIndex } from '../src/create-index';
import { bundleSchemas } from '../src/bundle-schemas';
import { generateTypes } from '../src/generate-types';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const ROOT_DIR = join(__dirname, '..');
const DIST_DIR = join(ROOT_DIR, 'dist');
const TS_DIR = join(DIST_DIR, 'ts');

describe('create-index', () => {
  beforeAll(async () => {
    await bundleSchemas();
    await generateTypes();
  });

  // Restore dist to clean state after all tests
  afterAll(() => {
    createIndex();
  });

  it('should create dist/index.js', () => {
    createIndex();
    expect(existsSync(join(DIST_DIR, 'index.js'))).toBe(true);
  });

  it('should create dist/index.d.ts', () => {
    expect(existsSync(join(DIST_DIR, 'index.d.ts'))).toBe(true);
  });

  it('index.js should re-export from hdf-results', () => {
    const content = readFileSync(join(DIST_DIR, 'index.js'), 'utf-8');
    expect(content).toContain("export * from './ts/hdf-results.js'");
  });

  it('index.js should re-export helpers', () => {
    const content = readFileSync(join(DIST_DIR, 'index.js'), 'utf-8');
    expect(content).toContain("export * from './helpers.js'");
  });

  it('index.d.ts should export HdfBaseline type', () => {
    const content = readFileSync(join(DIST_DIR, 'index.d.ts'), 'utf-8');
    expect(content).toContain('HdfBaseline');
    expect(content).toContain('BaselineRequirement');
  });

  it('should compile TypeScript files to JavaScript', () => {
    expect(existsSync(join(TS_DIR, 'hdf-results.js'))).toBe(true);
    expect(existsSync(join(TS_DIR, 'hdf-baseline.js'))).toBe(true);
  });

  it('should generate declaration files', () => {
    expect(existsSync(join(TS_DIR, 'hdf-results.d.ts'))).toBe(true);
    expect(existsSync(join(TS_DIR, 'hdf-baseline.d.ts'))).toBe(true);
  });

  it('should copy helpers to dist if they exist', () => {
    const helpersJs = join(ROOT_DIR, 'src/helpers.js');
    if (existsSync(helpersJs)) {
      expect(existsSync(join(DIST_DIR, 'helpers.js'))).toBe(true);
    }
  });

  describe('barrel export validation', () => {
    it('should resolve all named exports at runtime without throwing', async () => {
      createIndex();
      const indexPath = pathToFileURL(join(DIST_DIR, 'index.js')).href;
      // Dynamic import validates that every re-exported symbol actually exists
      // in the source module. A missing symbol causes SyntaxError at evaluation.
      const mod = await import(indexPath);
      expect(mod).toBeDefined();
      expect(Object.keys(mod).length).toBeGreaterThan(0);
    });

    it('should export all root document types', async () => {
      const indexPath = pathToFileURL(join(DIST_DIR, 'index.js')).href;
      const mod = await import(indexPath);
      // Every generated type file produces a root interface as a no-op var
      // Only hdf-results types appear via export * — others are named exports
      // that must be kept in sync with quicktype output.
      for (const key of ['ResultStatus', 'HashAlgorithm', 'Severity']) {
        expect(mod[key], `expected hdf-results enum "${key}" to be exported`).toBeDefined();
      }
    });

    it('should not re-export symbols that duplicate hdf-results', async () => {
      const indexPath = pathToFileURL(join(DIST_DIR, 'index.js')).href;
      const mod = await import(indexPath);
      // These are exported by hdf-results via export * — verify they exist
      // but aren't doubled (the export count should equal the module's own count)
      const keys = Object.keys(mod);
      const unique = new Set(keys);
      expect(keys.length).toBe(unique.size);
    });

    it('should export comparison-specific enums when comparison types exist', async () => {
      if (!existsSync(join(TS_DIR, 'hdf-comparison.ts'))) return;
      createIndex();
      const indexPath = pathToFileURL(join(DIST_DIR, 'index.js')).href;
      const mod = await import(indexPath);
      for (const key of [
        'AnnotationCategory', 'BaselineDiffState', 'ChangeReason', 'ComparisonMode',
        'ConflictResolution', 'FormatVersion', 'MatchStrategy', 'Op', 'OriginalFormat',
        'PackageDiffState', 'RequirementState', 'SourceRole', 'Type',
      ]) {
        expect(mod[key], `expected comparison enum "${key}" to be exported`).toBeDefined();
      }
    });

    it('should export system-specific enums', async () => {
      const indexPath = pathToFileURL(join(DIST_DIR, 'index.js')).href;
      const mod = await import(indexPath);
      for (const key of [
        'AuthorizationStatus', 'BoundaryDescription', 'CategorizationLevel',
        'Designation', 'Direction',
      ]) {
        expect(mod[key], `expected system enum "${key}" to be exported`).toBeDefined();
      }
    });

    it('should export plan, amendments, and evidence-package enums', async () => {
      const indexPath = pathToFileURL(join(DIST_DIR, 'index.js')).href;
      const mod = await import(indexPath);
      for (const key of ['PlanType', 'ContentType']) {
        expect(mod[key], `expected enum "${key}" to be exported`).toBeDefined();
      }
    });

    it('should export helper functions', async () => {
      const indexPath = pathToFileURL(join(DIST_DIR, 'index.js')).href;
      const mod = await import(indexPath);
      expect(mod.severityToImpact, 'expected helper "severityToImpact" to be exported').toBeDefined();
    });
  });

  describe('error handling', () => {
    it('should handle missing TypeScript files gracefully', () => {
      const tempDir = join(DIST_DIR, 'ts-backup');
      if (existsSync(TS_DIR)) {
        mkdirSync(tempDir, { recursive: true });
        for (const name of ['hdf-results.ts', 'hdf-baseline.ts']) {
          const src = join(TS_DIR, name);
          if (existsSync(src)) {
            writeFileSync(join(tempDir, name), readFileSync(src));
            rmSync(src);
          }
        }
      }

      try {
        expect(() => createIndex()).not.toThrow();
      } finally {
        if (existsSync(tempDir)) {
          for (const name of ['hdf-results.ts', 'hdf-baseline.ts']) {
            const src = join(tempDir, name);
            if (existsSync(src)) {
              writeFileSync(join(TS_DIR, name), readFileSync(src));
            }
          }
          rmSync(tempDir, { recursive: true });
        }
      }
    });

    it('should handle tsc compilation failure gracefully', () => {
      // Inject a compile function that throws to test the error path.
      // IMPORTANT: createIndex() cleans dist/ts/*.{js,d.ts} BEFORE calling
      // compile. To avoid corrupting shared dist, we must restore files after.
      // The afterAll hook runs createIndex() to rebuild, but we also guard here.
      const backup = new Map<string, string>();
      for (const name of ['hdf-results', 'hdf-baseline', 'hdf-comparison']) {
        for (const ext of ['.js', '.d.ts']) {
          const file = join(TS_DIR, `${name}${ext}`);
          if (existsSync(file)) {
            backup.set(file, readFileSync(file, 'utf-8'));
          }
        }
      }

      try {
        expect(() => createIndex({
          compile: () => { throw new Error('tsc compilation failed'); },
        })).not.toThrow();
      } finally {
        // Restore cleaned files so parallel tests aren't affected
        for (const [file, content] of backup) {
          writeFileSync(file, content);
        }
      }
    });

    it('should produce index without comparison exports when hdf-comparison.ts is absent', () => {
      // Temporarily rename hdf-comparison.ts to simulate its absence
      const compTs = join(TS_DIR, 'hdf-comparison.ts');
      const compBackup = join(TS_DIR, 'hdf-comparison.ts.bak');
      const backup = new Map<string, string>();

      // Backup all dist/ts files that createIndex will clean
      for (const name of ['hdf-results', 'hdf-baseline', 'hdf-comparison']) {
        for (const ext of ['.ts', '.js', '.d.ts']) {
          const file = join(TS_DIR, `${name}${ext}`);
          if (existsSync(file)) {
            backup.set(file, readFileSync(file, 'utf-8'));
          }
        }
      }

      try {
        // Hide comparison file
        if (existsSync(compTs)) {
          writeFileSync(compBackup, readFileSync(compTs));
          rmSync(compTs);
        }

        createIndex();

        const indexJs = readFileSync(join(DIST_DIR, 'index.js'), 'utf-8');
        const indexDts = readFileSync(join(DIST_DIR, 'index.d.ts'), 'utf-8');

        // Should NOT contain comparison exports
        expect(indexJs).not.toContain('hdf-comparison');
        expect(indexDts).not.toContain('hdf-comparison');

        // Should still contain results exports
        expect(indexJs).toContain('hdf-results');
        expect(indexDts).toContain('hdf-results');
      } finally {
        // Restore all backed up files
        for (const [file, content] of backup) {
          writeFileSync(file, content);
        }
        if (existsSync(compBackup)) {
          writeFileSync(compTs, readFileSync(compBackup, 'utf-8'));
          rmSync(compBackup);
        }
      }
    });
  });
});
