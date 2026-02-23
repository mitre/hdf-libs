import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { existsSync, rmSync, mkdirSync, writeFileSync, readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
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
      // Inject a compile function that throws to test the error path
      // without corrupting shared dist files
      expect(() => createIndex({
        compile: () => { throw new Error('tsc compilation failed'); },
      })).not.toThrow();
    });
  });
});
