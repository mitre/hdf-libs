import { defineConfig } from 'tsdown';

export default defineConfig({
  entry: ['typescript/index.ts'],
  format: 'esm',
  dts: true,
  sourcemap: true,
  clean: true,
  // Below engines.node (>=24) deliberately, and not because it buys a consumer
  // anything — engines already declares older runtimes unsupported. Downlevelling is
  // simply harmless, so the target is left alone rather than churned every LTS bump.
  // What we support is the engines field's statement, never this one.
  target: 'node20',
  platform: 'neutral',
  // Schemas are now imported by name from @mitre/hdf-schema's main entry
  // (which inlines them into its own dist/index.js). So @mitre/hdf-schema
  // stays externalized as a normal runtime dep — no alwaysBundle rule
  // needed, no duplication.
});
