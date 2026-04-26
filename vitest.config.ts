import { defineConfig } from 'vitest/config';

// Root-level vitest config — runs every test file under the repo-root test/
// directory (currently the export-contract gate plus json-import-compatibility).
// Per-package tests use their own vitest.config.ts.
export default defineConfig({
  test: {
    include: ['test/**/*.test.ts'],
    exclude: ['**/node_modules/**', '**/dist/**', '**/.stryker-tmp/**'],
    testTimeout: 30000,
  },
});
