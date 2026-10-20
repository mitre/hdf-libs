import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    // JUnit is configured here, not on the CLI: `pnpm -r run test:ts` appends its
    // arguments to every package's script, including ones that do not run vitest.
    reporters: ['default', 'junit'],
    outputFile: { junit: 'test-results/junit.xml' },
    exclude: ['**/node_modules/**', '**/dist/**'],
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json', 'html', 'lcov'],
      thresholds: {
        statements: 90,
        branches: 90,
        functions: 90,
        lines: 90,
      },
      exclude: ['dist/**', 'test/**', '**/*.config.*', '**/node_modules/**'],
    },
  },
});
