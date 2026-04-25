import { defineConfig } from 'vitest/config';

// Root-level vitest config — targets the monorepo-wide export-contract test only.
// Per-package tests use their own vitest.config.ts.
export default defineConfig({
  test: {
    include: ['test/**/*.test.ts'],
    exclude: ['**/node_modules/**', '**/dist/**', '**/.stryker-tmp/**'],
    testTimeout: 30000,
  },
});
