import { defineConfig } from 'tsdown';

export default defineConfig({
  entry: [
    'src/index.ts',
    'src/json/index.ts',
    'src/hash/index.ts',
    'src/xml/index.ts',
    'src/csv/index.ts',
    'src/object/index.ts',
    'src/string/index.ts',
  ],
  format: 'esm',
  dts: true,
  sourcemap: true,
  clean: true,
  target: 'node20',
  platform: 'neutral',
});
