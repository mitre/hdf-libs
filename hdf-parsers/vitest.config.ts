import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
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
      reporter: ['text', 'json', 'html'],
      exclude: [
        'node_modules/**',
        'dist/**',
        'go/**',
        '**/*.test.ts',
        'vitest.config.ts',
        'eslint.config.js'
      ]
    }
  }
});
