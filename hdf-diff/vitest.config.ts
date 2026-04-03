import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    exclude: [
      '**/node_modules/**',
      '**/dist/**',
    ],
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json', 'html'],
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
