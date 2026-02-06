import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    globals: true,
    environment: 'node',
    coverage: {
      provider: 'v8',
      reporter: ['text', 'html'],
      include: ['typescript/**/*.ts'],
      exclude: ['typescript/**/*.d.ts', 'typescript/**/*.test.ts', 'go/**']
    }
  }
});
