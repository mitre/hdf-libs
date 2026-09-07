import { defineConfig } from 'vitest/config';

export default defineConfig({
  resolve: {
    extensions: ['.ts', '.js', '.json'],
  },
  test: {
    // JUnit is configured here, not passed on the CLI: `pnpm -r run test:ts`
    // appends its arguments to EVERY package's script, including the ones that
    // do not run vitest (site runs node --test, two others are `echo`), which
    // fails those packages. See hdf-libs-8zvp.
    reporters: ['default', 'junit'],
    outputFile: { junit: 'test-results/junit.xml' },
    globals: true,
    environment: 'node',
    include: [
      'test/**/*.test.ts',
      'test/**/*.spec.ts',
      'converters/**/*.test.ts',
      'converters/**/*.spec.ts',
      'shared/**/*.test.ts',
      'shared/**/*.spec.ts',
      'fetchers/**/*.test.ts',
      'fetchers/**/*.spec.ts',
    ],
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json', 'html', 'lcov'],
      include: ['src/**/*.ts', 'converters/**/*.ts', 'fetchers/**/*.ts'],
      exclude: [
        'src/**/*.d.ts',
        'dist/**',
        'test/**',
        '**/*.config.*',
        '**/node_modules/**',
        '**/*.test.ts',
        '**/*.spec.ts',
      ],
      thresholds: {
        statements: 90,
        branches: 90,
        functions: 90,
        lines: 90,
      },
    },
  },
});
