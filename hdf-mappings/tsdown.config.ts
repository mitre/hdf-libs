import { defineConfig } from 'tsdown';

export default defineConfig({
  entry: ['src/index.ts'],
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
  // tsdown auto-externalizes `dependencies` and `peerDependencies` from
  // package.json, so workspace-sibling @mitre/* packages stay as imports
  // (resolved at consumer install time) and are never inlined into this
  // tarball. hdf-mappings currently has no @mitre runtime deps so nothing
  // is externalized, but keeping the implicit behavior documented here.
});
