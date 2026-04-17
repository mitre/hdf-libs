import { defineConfig } from 'tsdown';

export default defineConfig({
  entry: ['typescript/index.ts'],
  format: 'esm',
  dts: true,
  sourcemap: true,
  clean: true,
  target: 'node20',
  platform: 'neutral',
  // tsdown auto-externalizes `dependencies` entries in package.json — that's
  // what keeps ajv/ajv-formats and @mitre/hdf-schema's JS entry as runtime
  // imports (no duplication). But the JSON sub-paths @mitre/hdf-schema/schemas/*
  // need to be INLINED at build time, otherwise raw-Node consumers of this
  // package hit ERR_IMPORT_ATTRIBUTE_MISSING when they try to load us.
  // noExternal overrides the default to bundle those specific paths.
  deps: { alwaysBundle: [/^@mitre\/hdf-schema\/schemas\//] },
});
