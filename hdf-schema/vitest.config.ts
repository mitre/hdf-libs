import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    globals: true,
    environment: 'node',
    include: ['test/**/*.test.ts', 'test/**/*.spec.ts'],
    // Run test files sequentially — create-index.test.ts and generate-types.test.ts
    // both mutate the shared dist/ directory (bundleSchemas, generateTypes, createIndex).
    // Running them in parallel causes race conditions where one test cleans files
    // that another test is reading.
    fileParallelism: false,
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json', 'html'],
      include: ['src/**/*.ts'],
      exclude: ['src/**/*.d.ts', 'src/generated/**'],
      // Note: CLI entry points excluded with c8 ignore comments
      thresholds: {
        statements: 90,
        branches: 90,
        functions: 90,
        lines: 90,
      },
    },
  },
});
