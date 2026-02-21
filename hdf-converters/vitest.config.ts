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
    ],
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json', 'html'],
      include: ['src/**/*.ts', 'converters/**/*.ts'],
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
        statements: 95,
        branches: 95,
        functions: 95,
        lines: 95,
      },
    },
  },
});
