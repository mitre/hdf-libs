// Copy the MCP contract goldens from hdf-cli into src/, the same way hdf-validators
// carries a committed copy of the bundled schemas.
//
// Why a copy and not a read across packages: this package publishes to npm and its
// generator must run from the published tarball, which cannot reach hdf-cli's internal
// testdata. The copies are TRACKED and this script is the only thing that writes them —
// a drift step in CI regenerates and fails on a diff, so they cannot go stale silently.
//
// Run: node scripts/sync-mcp-golden.mjs   (--check to verify without writing)

import { readFileSync, writeFileSync } from 'fs';
import { dirname, join } from 'path';
import { fileURLToPath } from 'url';

const here = dirname(fileURLToPath(import.meta.url));
const SRC = join(here, '..', 'src');
const FROM = join(here, '..', '..', 'hdf-cli', 'internal', 'mcp', 'evalharness', 'testdata');

const GOLDENS = [
  'mcp-contract.golden.json',
  'tools-list.golden.json',
  'mcp-envelopes.golden.json',
];

export function syncGoldens({ check = false } = {}) {
  const drifted = [];
  for (const name of GOLDENS) {
    const source = readFileSync(join(FROM, name), 'utf-8');
    const target = join(SRC, name);
    let current = null;
    try {
      current = readFileSync(target, 'utf-8');
    } catch {
      /* first sync */
    }
    if (current === source) continue;
    if (check) {
      drifted.push(name);
      continue;
    }
    writeFileSync(target, source);
  }
  return drifted;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const check = process.argv.includes('--check');
  const drifted = syncGoldens({ check });
  if (drifted.length > 0) {
    process.stderr.write(
      `sync-mcp-golden: ${drifted.join(', ')} differ from hdf-cli's goldens — run ` +
        `\`pnpm run sync:golden\` and commit the result.\n`,
    );
    process.exit(1);
  }
  process.stdout.write(`sync-mcp-golden: ${GOLDENS.length} golden(s) in sync\n`);
}
