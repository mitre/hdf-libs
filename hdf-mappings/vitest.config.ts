import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    // JUnit is configured here, not passed on the CLI: `pnpm -r run test:ts`
    // appends its arguments to EVERY package's script, including the ones that
    // do not run vitest (site runs node --test, two others are `echo`), which
    // fails those packages. See hdf-libs-8zvp.
    reporters: ['default', 'junit'],
    outputFile: { junit: 'test-results/junit.xml' },
    globals: true,
    environment: 'node',
    include: ['test/**/*.test.ts', 'test/**/*.spec.ts'],
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json', 'html', 'lcov'],
      include: ['src/**/*.ts'],
      exclude: ['src/**/*.d.ts', 'src/**/types.ts', 'dist/**', 'test/**', '**/*.config.*', '**/node_modules/**'],
      thresholds: {
        statements: 90,
        branches: 90,
        functions: 90,
        lines: 90,
      },
    },
  },
});
