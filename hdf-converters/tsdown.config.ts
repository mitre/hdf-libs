import { defineConfig } from 'tsdown';

export default defineConfig({
  entry: {
    index: 'src/index.ts',
    detect: 'src/detect.ts',
    registry: 'shared/typescript/registry.ts',
  },
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
