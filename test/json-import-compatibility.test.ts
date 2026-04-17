/**
 * JSON Import Compatibility Tests
 *
 * Every package that has JSON imports is built with tsdown so the JSON
 * gets inlined as JS object literals at build time. The published
 * artifacts contain no unresolved JSON imports and work in any
 * consumer — raw Node.js ESM, Vite/Nuxt, webpack, esbuild, Bun — with
 * no noExternal / bundler-inline configuration required.
 *
 * Packages that don't have JSON imports in their sources (hdf-schema,
 * hdf-utilities, hdf-parsers, hdf-diff, hdf-generators,
 * hdf-extension-graph, hdf-converters) stay on tsc-only builds; their
 * dist is already raw-Node-compatible because the JSON problem never
 * existed there. Bundling them would only add tooling-consistency
 * benefit, not functional benefit, and is left as follow-up work.
 *
 * Rules below apply to every package, bundled or not:
 *
 * 1. NO Node-only APIs (`createRequire`, `fs`, `path`) in any SOURCE
 *    file imported by consumers. Those crash browser bundles with
 *    "Module has been externalized for browser compatibility."
 *
 * 2. NO `with { type: 'json' }` import attributes in source files.
 *    Vite strips these during plugin analysis (Vite RFC #18534),
 *    leaving bare imports that raw Node.js then rejects. Bundled
 *    packages resolve JSON at build time so the question doesn't come
 *    up at consume time; unbundled packages must not introduce this
 *    syntax in source.
 *
 * 3. `tsconfig.base.json` must NOT have `verbatimModuleSyntax: true`
 *    (would force tsc to emit the import attribute).
 */

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'fs';
import { resolve } from 'path';
import { fileURLToPath } from 'url';
import { dirname } from 'path';

const __dirname = dirname(fileURLToPath(import.meta.url));

describe('JSON import compatibility', () => {
  describe('tsconfig.base.json must not have verbatimModuleSyntax', () => {
    it('should not contain verbatimModuleSyntax', () => {
      const tsconfig = JSON.parse(
        readFileSync(resolve(__dirname, '..', 'tsconfig.base.json'), 'utf-8')
      );
      expect(tsconfig.compilerOptions.verbatimModuleSyntax).toBeUndefined();
    });
  });

  describe('source files must not use Node-only createRequire', () => {
    const sourceFiles = [
      'hdf-mappings/src/cci/index.ts',
      'hdf-mappings/src/nikto/index.ts',
      'hdf-mappings/src/awsconfig/index.ts',
      'hdf-mappings/src/owasp/index.ts',
      'hdf-mappings/src/nist/index.ts',
      'hdf-mappings/src/scoutsuite/index.ts',
      'hdf-mappings/src/cwe/index.ts',
      'hdf-mappings/src/nessus/index.ts',
      'hdf-validators/typescript/index.ts',
      'hdf-converters/converters/nessus-to-hdf/typescript/converter.ts'
    ];

    for (const file of sourceFiles) {
      it(`${file} must not use createRequire`, () => {
        const content = readFileSync(resolve(__dirname, '..', file), 'utf-8');
        expect(content).not.toContain('createRequire');
      });
    }
  });

  describe('source files must not use import attributes (with { type })', () => {
    const sourceFiles = [
      'hdf-mappings/src/cci/index.ts',
      'hdf-mappings/src/nikto/index.ts',
      'hdf-mappings/src/awsconfig/index.ts',
      'hdf-mappings/src/owasp/index.ts',
      'hdf-mappings/src/nist/index.ts',
      'hdf-mappings/src/scoutsuite/index.ts',
      'hdf-mappings/src/cwe/index.ts',
      'hdf-mappings/src/nessus/index.ts',
      'hdf-validators/typescript/index.ts',
      'hdf-converters/converters/nessus-to-hdf/typescript/converter.ts'
    ];

    for (const file of sourceFiles) {
      it(`${file} must not use import attributes`, () => {
        const content = readFileSync(resolve(__dirname, '..', file), 'utf-8');
        expect(content).not.toMatch(/with\s*\{\s*type:\s*['"]json['"]\s*\}/);
      });
    }
  });

  describe('bundled packages: dist/index.js must be self-contained', () => {
    // Packages built with tsdown: JSON data is inlined as JS objects, so
    // the artifact has no unresolved JSON imports at all and works in
    // raw Node ESM as well as any bundler without consumer configuration.
    const bundledPackages = [
      'hdf-mappings',
      'hdf-validators',
    ];

    for (const pkg of bundledPackages) {
      const distFile = `${pkg}/dist/index.js`;

      it(`${distFile} must not use createRequire`, () => {
        const content = readFileSync(resolve(__dirname, '..', distFile), 'utf-8');
        expect(content).not.toContain('createRequire');
      });

      it(`${distFile} must not use import attributes`, () => {
        const content = readFileSync(resolve(__dirname, '..', distFile), 'utf-8');
        expect(content).not.toMatch(/with\s*\{\s*type:\s*['"]json['"]\s*\}/);
      });

      it(`${distFile} must not import any .json files (data must be inlined)`, () => {
        const content = readFileSync(resolve(__dirname, '..', distFile), 'utf-8');
        expect(content).not.toMatch(/from\s+['"][^'"]+\.json['"]/);
      });
    }
  });

  describe('JSON data loads correctly through package exports', () => {
    it('hdf-mappings: CCI data loads and has entries', async () => {
      const { getAllCCIIds } = await import('../hdf-mappings/src/cci/index.js');
      const ids = getAllCCIIds();
      expect(ids.length).toBeGreaterThan(0);
      expect(ids).toContain('CCI-000001');
    });

    it('hdf-mappings: NIST data loads and has entries', async () => {
      const { getAllNISTIds } = await import('../hdf-mappings/src/nist/index.js');
      const ids = getAllNISTIds();
      expect(ids.length).toBeGreaterThan(0);
    });

    it('hdf-mappings: CWE data loads and has entries', async () => {
      const { getAllCweIds } = await import('../hdf-mappings/src/cwe/index.js');
      const ids = getAllCweIds();
      expect(ids.length).toBeGreaterThan(0);
    });

    it('hdf-mappings: OWASP data loads and has entries', async () => {
      const { getAllOwaspIds } = await import('../hdf-mappings/src/owasp/index.js');
      const ids = getAllOwaspIds();
      expect(ids.length).toBeGreaterThan(0);
    });

    it('hdf-mappings: Nessus data loads and has entries', async () => {
      const { getAllNessusPluginFamilies } = await import('../hdf-mappings/src/nessus/index.js');
      const families = getAllNessusPluginFamilies();
      expect(families.length).toBeGreaterThan(0);
    });

    it('hdf-mappings: Nikto data loads and has entries', async () => {
      const { getAllNiktoIds } = await import('../hdf-mappings/src/nikto/index.js');
      const ids = getAllNiktoIds();
      expect(ids.length).toBeGreaterThan(0);
    });

    it('hdf-validators: schema validation works (requires JSON schema loading)', async () => {
      const { validateResults } = await import('../hdf-validators/typescript/index.js');
      // Empty object should fail validation but NOT crash — proves schemas loaded
      const result = validateResults({});
      expect(result.valid).toBe(false);
      expect(result.errors.length).toBeGreaterThan(0);
    });
  });
});
