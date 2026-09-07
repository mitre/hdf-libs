import { defineConfig } from 'vitest/config';

export default defineConfig({
  // Resolve workspace packages to source (not stale dist/) during tests.
  // The 'development' condition in each package's exports map points to
  // the TypeScript source. This prevents stale-dist bugs.
  ssr: {
    resolve: {
      conditions: ['development', 'import', 'default'],
    },
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
    exclude: [
      '**/node_modules/**',
      '**/dist/**',
      '**/.stryker-tmp/**',
    ],
    // Inline workspace packages so Vite resolves them directly instead of
    // relying on Node module resolution (which breaks on Windows with pnpm).
    deps: {
      inline: ['@mitre/hdf-validators'],
    },
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json', 'html', 'lcov'],
      exclude: [
        'node_modules/**',
        'dist/**',
        'go/**',
        '**/*.test.ts',
        'vitest.config.ts'
      ]
    }
  }
});
