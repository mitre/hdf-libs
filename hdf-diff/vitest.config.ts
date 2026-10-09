import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    // Program-compiling and corpus suites exceed vitest's 5s default under parallel coverage.
    testTimeout: 20_000,
    // JUnit is configured here, not passed on the CLI: `pnpm -r run test:ts`
    // appends its arguments to EVERY package's script, including the ones that
    // do not run vitest (site runs node --test, two others are `echo`), which
    // fails those packages. See hdf-libs-8zvp.
    reporters: ['default', 'junit'],
    outputFile: { junit: 'test-results/junit.xml' },
    exclude: [
      '**/node_modules/**',
      '**/dist/**',
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
        'src/types.ts',
        'src/index.ts',
        'src/**/types.ts',
      ],
    },
  },
});
