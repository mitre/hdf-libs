/**
 * JSON Import Compatibility Tests
 *
 * Two architectures coexist in this repo, both of which need to remain
 * consumable by Nuxt/Vite apps (browser + SSR) AND raw Node.js ESM
 * scripts:
 *
 * (A) BUNDLED packages — JSON is inlined into a single dist/index.js
 *     by esbuild at build time. The artifact contains no JSON imports
 *     at all and works in any consumer (raw Node, Vite, webpack, etc.)
 *     with no special configuration.
 *
 *     Currently bundled: @mitre/hdf-mappings.
 *
 * (B) UNBUNDLED packages — tsc-only build, source-style bare JSON
 *     imports survive into dist. Consumer MUST run them through a
 *     bundler (Vite/Nuxt/webpack/esbuild) that resolves bare JSON
 *     imports natively. Raw Node ESM consumers will fail with
 *     ERR_IMPORT_ATTRIBUTE_MISSING. To use these in Vite/Nuxt, set
 *     `vite.ssr.noExternal: ['@mitre/hdf-…']` so they get inlined
 *     into the consumer's bundle.
 *
 *     Currently unbundled: @mitre/hdf-validators, @mitre/hdf-parsers,
 *     @mitre/hdf-converters, @mitre/hdf-diff. Goal is to migrate these
 *     to architecture (A) too, by having them import from
 *     @mitre/hdf-schema's JS entry point instead of its raw .json
 *     sub-paths (which requires bundling hdf-schema first).
 *
 * Shared rules for BOTH architectures:
 *
 * 1. NO Node-only APIs (`createRequire`, `fs`, `path`) in any SOURCE
 *    file imported by consumers. Crashes browser bundles.
 *
 * 2. NO `with { type: 'json' }` in source files. Vite strips these
 *    during plugin analysis (Vite RFC #18534), leaving bare imports
 *    that Node.js then rejects.
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

  describe('unbundled packages: dist must not contain createRequire or import attributes', () => {
    const distFiles = [
      'hdf-validators/dist/index.js',
    ];

    for (const file of distFiles) {
      it(`${file} must not use createRequire`, () => {
        const content = readFileSync(resolve(__dirname, '..', file), 'utf-8');
        expect(content).not.toContain('createRequire');
      });

      it(`${file} must not use import attributes`, () => {
        const content = readFileSync(resolve(__dirname, '..', file), 'utf-8');
        expect(content).not.toMatch(/with\s*\{\s*type:\s*['"]json['"]\s*\}/);
      });
    }
  });

  describe('bundled packages: dist/index.js must be self-contained', () => {
    // Packages built with esbuild --bundle: JSON data is inlined as JS
    // objects, so the artifact has no JSON imports at all and works in
    // raw Node ESM as well as any bundler.
    const bundledPackages = [
      'hdf-mappings',
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
