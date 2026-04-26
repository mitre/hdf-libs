import { defineConfig } from 'tsdown';

export default defineConfig({
  entry: ['typescript/index.ts'],
  format: 'esm',
  dts: true,
  sourcemap: true,
  clean: true,
  target: 'node24',
  platform: 'neutral',
});
