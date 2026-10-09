import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { existsSync, rmSync, writeFileSync, readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath, pathToFileURL } from 'url';
import { createIndex } from '../src/create-index';
import { bundleSchemas } from '../src/bundle-schemas';
import { generateTypes } from '../src/generate-types';
import ts from 'typescript';

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

  it('index.js should re-export from combined hdf.js (deduplicated types)', () => {
    const content = readFileSync(join(DIST_DIR, 'index.js'), 'utf-8');
    expect(content).toContain("export * from './ts/hdf.js'");
  });

  it('index.js should re-export helpers', () => {
    const content = readFileSync(join(DIST_DIR, 'index.js'), 'utf-8');
    expect(content).toContain("export * from './helpers.js'");
  });

  it('index.d.ts should contain deprecated aliases and re-export chain', () => {
    const content = readFileSync(join(DIST_DIR, 'index.d.ts'), 'utf-8');
    expect(content).toContain('HDFBaseline');
    expect(content).toContain("from './ts/hdf.js'");
  });

  it('should export BaselineRequirement at runtime via combined hdf.js', async () => {
    const indexPath = pathToFileURL(join(DIST_DIR, 'index.js')).href;
    const mod = await import(indexPath + '?t=baseline' + Date.now());
    expect(mod['BaselineRequirement']).toBeUndefined();
    // BaselineRequirement is an interface (not an enum/const), so it doesn't exist at runtime.
    // Verify it exists in the .d.ts type declarations via hdf.d.ts
    const dts = readFileSync(join(TS_DIR, 'hdf.d.ts'), 'utf-8');
    expect(dts).toContain('BaselineRequirement');
  });

  it('should compile combined hdf.ts to JavaScript', () => {
    expect(existsSync(join(TS_DIR, 'hdf.js'))).toBe(true);
  });

  it('should generate combined declaration file', () => {
    expect(existsSync(join(TS_DIR, 'hdf.d.ts'))).toBe(true);
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
      const mod = await import(indexPath + '?t=' + Date.now());
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

    it('should export comparison-specific enums from combined output', async () => {
      createIndex();
      const indexPath = pathToFileURL(join(DIST_DIR, 'index.js')).href;
      const mod = await import(indexPath);
      for (const key of [
        'AnnotationCategory', 'BaselineDiffState', 'ChangeReason', 'ComparisonMode',
        'ConflictResolution', 'FormatVersion', 'MatchStrategy', 'Op', 'OriginalFormat',
        'PackageDiffState', 'RequirementState', 'SourceRole',
      ]) {
        expect(mod[key], `expected comparison enum "${key}" to be exported`).toBeDefined();
      }
    });

    it('should export system-specific enums', async () => {
      const indexPath = pathToFileURL(join(DIST_DIR, 'index.js')).href;
      const mod = await import(indexPath);
      for (const key of [
        'AuthorizationStatus', 'TargetType', 'CategorizationLevel',
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
    it('should handle missing combined hdf.ts gracefully', () => {
      const hdfTs = join(TS_DIR, 'hdf.ts');
      const backupPath = join(TS_DIR, 'hdf.ts.bak');

      if (existsSync(hdfTs)) {
        writeFileSync(backupPath, readFileSync(hdfTs));
        rmSync(hdfTs);
      }

      try {
        // createIndex returns early with a warning when hdf.ts is absent
        expect(() => createIndex()).not.toThrow();
      } finally {
        if (existsSync(backupPath)) {
          writeFileSync(hdfTs, readFileSync(backupPath));
          rmSync(backupPath);
        }
      }
    });

    it('should handle tsc compilation failure gracefully', () => {
      // Inject a compile function that throws to test the error path.
      // IMPORTANT: createIndex() cleans dist/ts/*.{js,d.ts} BEFORE calling
      // compile. To avoid corrupting shared dist, we must restore files after.
      // The afterAll hook runs createIndex() to rebuild, but we also guard here.
      const backup = new Map<string, string>();
      for (const ext of ['.js', '.d.ts']) {
        const file = join(TS_DIR, `hdf${ext}`);
        if (existsSync(file)) {
          backup.set(file, readFileSync(file, 'utf-8'));
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

    it('should not produce per-file re-exports (combined hdf.js only)', () => {
      createIndex();

      const indexJs = readFileSync(join(DIST_DIR, 'index.js'), 'utf-8');
      const indexDts = readFileSync(join(DIST_DIR, 'index.d.ts'), 'utf-8');

      // With combined output, no per-file re-exports should exist
      expect(indexJs).not.toMatch(/from ['"]\.\/ts\/hdf-results\.js['"]/);
      expect(indexJs).not.toMatch(/from ['"]\.\/ts\/hdf-baseline\.js['"]/);
      expect(indexJs).not.toMatch(/from ['"]\.\/ts\/hdf-comparison\.js['"]/);
      expect(indexDts).not.toMatch(/from ['"]\.\/ts\/hdf-results\.js['"]/);

      // Should export from combined hdf.js
      expect(indexJs).toContain("from './ts/hdf.js'");
      expect(indexDts).toContain("from './ts/hdf.js'");
    });
  });

  // Consumers compile against the barrel with skipLibCheck enabled, which turns
  // an unresolved name inside a .d.ts into `any` instead of an error. Check the
  // emitted declarations with lib checks ON so a broken alias or an ambiguous
  // re-export fails here instead of silently widening a consumer's types.
  describe('emitted declarations type-check', () => {
    const DTS_OPTIONS: ts.CompilerOptions = {
      noEmit: true,
      skipLibCheck: false,
      strict: true,
      module: ts.ModuleKind.NodeNext,
      moduleResolution: ts.ModuleResolutionKind.NodeNext,
      target: ts.ScriptTarget.ES2022,
      types: [],
    };

    function ownDiagnostics(program: ts.Program): string[] {
      return ts
        .getPreEmitDiagnostics(program)
        .filter((d) => d.file !== undefined && !d.file.fileName.includes('/node_modules/'))
        .map((d) => {
          const file = d.file!;
          const { line, character } = file.getLineAndCharacterOfPosition(d.start ?? 0);
          const message = ts.flattenDiagnosticMessageText(d.messageText, '\n');
          return `${file.fileName}(${line + 1},${character + 1}): TS${d.code} ${message}`;
        });
    }

    // Both tests compile a program over the full generated declarations, which
    // takes seconds under coverage with the other packages' suites running
    // alongside; vitest's five-second default is sized for unit assertions.
    it('dist/index.d.ts has no diagnostics with skipLibCheck disabled', { timeout: 30_000 }, () => {
      createIndex();
      const program = ts.createProgram([join(DIST_DIR, 'index.d.ts')], DTS_OPTIONS);
      expect(ownDiagnostics(program)).toEqual([]);
    });

    it('deprecated Hdf* aliases resolve to their HDF* types, not any', { timeout: 30_000 }, () => {
      createIndex();
      const aliases = [
        'HdfResults',
        'HdfBaseline',
        'HdfComparison',
        'HdfSystem',
        'HdfPlan',
        'HdfAmendments',
        'HdfEvidencePackage',
      ];
      // One assignment per alias, each of which must be rejected. An alias that
      // degraded to `any` accepts the number and produces no diagnostic.
      // TypeScript normalizes every path to forward slashes before it asks the
      // host, so on Windows a path.join result never matches and the probe is
      // never served; compare in the compiler's own form.
      const probePath = join(DIST_DIR, '__alias-probe__.ts').replace(/\\/g, '/');
      const isProbe = (f: string): boolean => f.replace(/\\/g, '/') === probePath;
      const probeSource = [
        `import type { ${aliases.join(', ')} } from './index.js';`,
        ...aliases.map((name, i) => `export const v${i}: ${name} = 42;`),
        '',
      ].join('\n');

      const host = ts.createCompilerHost(DTS_OPTIONS);
      const { fileExists, readFile, getSourceFile } = host;
      host.fileExists = (f) => isProbe(f) || fileExists.call(host, f);
      host.readFile = (f) => (isProbe(f) ? probeSource : readFile.call(host, f));
      host.getSourceFile = (f, lang, onError, shouldCreate) =>
        isProbe(f)
          ? ts.createSourceFile(f, probeSource, lang)
          : getSourceFile.call(host, f, lang, onError, shouldCreate);

      // skipLibCheck stays on here: this test is about alias resolution only.
      const program = ts.createProgram([probePath], { ...DTS_OPTIONS, skipLibCheck: true }, host);
      const rejectedLines = ts
        .getPreEmitDiagnostics(program)
        .filter((d) => d.file !== undefined && isProbe(d.file.fileName) && d.code === 2322)
        .map((d) => d.file!.getLineAndCharacterOfPosition(d.start ?? 0).line + 1)
        .sort((a, b) => a - b);

      // Line 1 is the import; lines 2..8 are the seven assignments.
      expect(rejectedLines).toEqual(aliases.map((_, i) => i + 2));
    });
  });
});
