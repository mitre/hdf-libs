import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    // JUnit is configured here, not passed on the CLI: `pnpm -r run test:ts`
    // appends its arguments to EVERY package's script, including the ones that
    // do not run vitest (site runs node --test, two others are `echo`), which
    // fails those packages. See hdf-libs-8zvp.
    reporters: ['default', 'junit'],
    outputFile: { junit: 'test-results/junit.xml' },
    exclude: [
      '**/node_modules/**',
      '**/dist/**',
      '**/.stryker-tmp/**',
    ],
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json', 'html', 'lcov'],
      thresholds: {
        statements: 90,
        branches: 90,
        functions: 90,
        lines: 90,
      },
      exclude: [
        'dist/**',
        'test/**',
        '**/*.config.*',
        '**/node_modules/**',
        '**/.stryker-tmp/**',
      ],
    },
  },
});
