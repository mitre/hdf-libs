import { defineConfig } from 'tsdown';

export default defineConfig({
  entry: ['typescript/index.ts'],
  format: 'esm',
  dts: true,
  sourcemap: true,
  clean: true,
  target: 'node20',
  platform: 'neutral',
  // Schemas are now imported by name from @mitre/hdf-schema's main entry
  // (which inlines them into its own dist/index.js). So @mitre/hdf-schema
  // stays externalized as a normal runtime dep — no alwaysBundle rule
  // needed, no duplication.
});
