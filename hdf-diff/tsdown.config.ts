import { defineConfig } from 'tsdown';

export default defineConfig({
  entry: [
    'src/index.ts',
    'src/matching/index.ts',
    'src/renderers/index.ts',
  ],
  format: 'esm',
  dts: true,
  sourcemap: true,
  clean: true,
  target: 'node24',
  platform: 'neutral',
});
