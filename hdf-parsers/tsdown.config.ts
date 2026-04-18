import { defineConfig } from 'tsdown';

export default defineConfig({
  entry: ['typescript/index.ts'],
  format: 'esm',
  dts: true,
  sourcemap: true,
  clean: true,
  target: 'node20',
  platform: 'neutral',
});
