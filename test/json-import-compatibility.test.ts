/**
 * JSON Import Compatibility Tests
 *
 * REQUIREMENTS:
 * hdf-libs packages are consumed by Nuxt/Vite applications that bundle them
 * for BOTH browser (client) and Node.js (server/SSR). This means:
 *
 * 1. NO Node-only APIs (e.g., `createRequire`, `fs`, `path`) in any source
 *    file that gets imported by consumers. `module.createRequire` crashes
 *    in the browser with "Module has been externalized for browser compatibility."
 *
 * 2. NO `with { type: 'json' }` import attributes. Vite strips these during
 *    its plugin analysis phase (see Vite RFC #18534), leaving bare imports
 *    that Node.js then rejects with "needs an import attribute of type json."
 *
 * 3. USE bare `import ... from '...json'` (no `with` clause). This works
 *    because the consumer configures `vite.ssr.noExternal` and
 *    `nitro.noExternal` to force Vite to bundle hdf-libs packages.
 *    Vite natively handles JSON imports in its bundler.
 *
 * 4. `tsconfig.base.json` must NOT have `verbatimModuleSyntax: true`.
 *    That flag forces TypeScript to emit `with { type: 'json' }` for
 *    JSON imports, which triggers problem #2.
 *
 * CONSUMER CONFIGURATION (nuxt.config.ts):
 *   vite: { ssr: { noExternal: ['@mitre/hdf-mappings', ...] } }
 *   nitro: { externals: { inline: ['@mitre/hdf-mappings', ...] } }
 *
 * If these tests fail, the fix is NOT to add createRequire or import
 * attributes — it's to ensure bare JSON imports are used and the consumer
 * has the noExternal configuration.
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

  describe('compiled dist must not contain createRequire or import attributes', () => {
    const distFiles = [
      'hdf-mappings/dist/cci/index.js',
      'hdf-mappings/dist/nikto/index.js',
      'hdf-mappings/dist/awsconfig/index.js',
      'hdf-mappings/dist/owasp/index.js',
      'hdf-mappings/dist/nist/index.js',
      'hdf-mappings/dist/scoutsuite/index.js',
      'hdf-mappings/dist/cwe/index.js',
      'hdf-mappings/dist/nessus/index.js',
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
