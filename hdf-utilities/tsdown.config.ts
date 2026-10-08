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
  // Below engines.node (>=24) deliberately, and not because it buys a consumer
  // anything — engines already declares older runtimes unsupported. Downlevelling is
  // simply harmless, so the target is left alone rather than churned every LTS bump.
  // What we support is the engines field's statement, never this one.
  target: 'node20',
  platform: 'neutral',
});
