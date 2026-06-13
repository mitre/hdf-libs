import { defineConfig } from 'vitest/config';

export default defineConfig({
  resolve: {
    extensions: ['.ts', '.js', '.json'],
  },
  test: {
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
      reporter: ['text', 'json', 'html'],
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
