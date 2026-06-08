// @mitre/hdf-fixtures — shared real-world HDF reference data for cross-package
// consumers (parsers, validators, hdf-extension-graph). Each entry exposes the
// on-disk path AND a read() helper. Both Go and TS test code reach the same
// physical files via the parallel APIs (this module + ../fixtures.go).
//
// Boundary rule (per bead hdf-libs-e95o): converter fixtures stay with the
// converter as its tested contract; files here are wild-data references for
// cross-cutting tests. Inclusion requires the fixture is actually consumed
// by more than one workspace package — not just "might be useful someday."
//
// Layout: top-level directories are by HDF document type (`results/`,
// `baseline/`) plus `inspec/` for legacy InSpec runner output (non-HDF;
// kept for cross-language parser parity tests verifying both languages
// reject non-HDF inputs the same way).
//
// Provenance for every fixture is documented in ../README.md.
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// Compute paths relative to the package root, not the dist/ output dir, so
// fixtures resolve correctly both in dev (running tsx) and after bundling.
const PACKAGE_ROOT = path.resolve(__dirname, '..');

interface FixtureRef {
  path: string;
  read: () => string;
}

function fixture(category: string, name: string): FixtureRef {
  const filePath = path.join(PACKAGE_ROOT, category, name);
  return {
    path: filePath,
    read: () => readFileSync(filePath, 'utf-8'),
  };
}

// HDF Results documents.
export const results = {
  inspecMultilayered: fixture('results', 'inspec-multilayered.json'),
} as const;

// HDF Baseline documents.
export const baseline = {
  win2022Stig: fixture('baseline', 'win2022-stig.json'),
} as const;

// Legacy InSpec runner output — NOT HDF. Kept here for cross-language parser
// parity tests that verify both Go and TS parsers reject non-HDF inputs the
// same way, and for the legacyhdf-to-hdf converter (its tests load these too).
export const inspec = {
  ubi9Scan: fixture('inspec', 'ubi9-scan.json'),
  containerScan: fixture('inspec', 'container-scan.json'),
  threeLayerOverlay: fixture('inspec', 'three-layer-overlay.json'),
  threeLayerRhel7: fixture('inspec', 'three-layer-rhel7.json'),
  wrapper: fixture('inspec', 'wrapper.json'),
} as const;

export const all = {
  results,
  baseline,
  inspec,
} as const;
