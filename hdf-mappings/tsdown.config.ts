import { defineConfig } from 'tsdown';

export default defineConfig({
  entry: [
    'src/index.ts',
    'src/awsconfig/index.ts',
    'src/cci/index.ts',
    'src/cwe/index.ts',
    'src/nessus/index.ts',
    'src/nikto/index.ts',
    'src/nist/index.ts',
    'src/owasp/index.ts',
    'src/scoutsuite/index.ts',
  ],
  format: 'esm',
  dts: true,
  sourcemap: true,
  clean: true,
  target: 'node20',
  platform: 'neutral',
  // tsdown auto-externalizes `dependencies` and `peerDependencies` from
  // package.json, so workspace-sibling @mitre/* packages stay as imports
  // (resolved at consumer install time) and are never inlined into this
  // tarball. hdf-mappings currently has no @mitre runtime deps so nothing
  // is externalized, but keeping the implicit behavior documented here.
});
