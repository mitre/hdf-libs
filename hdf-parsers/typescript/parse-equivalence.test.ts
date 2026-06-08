// Pins behavioral parity between the TypeScript and Go implementations of
// parseResults against the shared real-world InSpec fixture corpus. Spawns
// the Go dumper binary (../go/cmd/parse-equivalence-dump) and the TS dumper
// (./parse-equivalence-dump.ts) on the same fixture, then deep-equals the
// canonical outputs. Catches drift like: one parser accepts a real fixture
// the other rejects, error-format divergence, or future normalizers added
// on one side but not the other.
//
// Skipped when `go` is unavailable on PATH so dev-environments without a
// Go toolchain don't fail. CI must have Go (the Go test suite requires it).
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { baseline, inspec, results } from '@mitre/hdf-fixtures';
import { beforeAll, describe, expect, it } from 'vitest';
import { dumpParseResults } from './parse-equivalence-dump.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const packageRoot = path.resolve(__dirname, '..');
const goCmdDir = path.join(packageRoot, 'go', 'cmd', 'parse-equivalence-dump');

function hasGo(): boolean {
  try {
    execFileSync('go', ['version'], { stdio: 'ignore' });
    return true;
  } catch {
    return false;
  }
}

// Built once in beforeAll and reused across fixtures, matching the pattern
// in hdf-extension-graph/test/cross-language-equivalence.test.ts.
let goBinary = '';

function runGoDumper(fixturePath: string): unknown {
  const out = execFileSync(goBinary, [fixturePath], {
    encoding: 'utf-8',
    maxBuffer: 64 * 1024 * 1024,
  });
  return JSON.parse(out);
}

// Real-world HDF Results (bug-exhibiting bare-timestamp case) + HDF Baseline
// + three legacy InSpec inputs (non-HDF). Both parsers should accept the
// first two and reject the inspec ones the same way. The fixture set is
// intentionally narrow — additional Results from other producer families
// don't add bug-catching signal (see hdf-libs-e95o bead discussion).
const FIXTURES = [
  { name: 'results inspec-multilayered (bare timestamps)', path: results.inspecMultilayered.path },
  { name: 'baseline win2022-stig', path: baseline.win2022Stig.path },
  { name: 'inspec legacy ubi9-scan (non-HDF — both should reject)', path: inspec.ubi9Scan.path },
  { name: 'inspec legacy container-scan (non-HDF)', path: inspec.containerScan.path },
  { name: 'inspec legacy three-layer-overlay (non-HDF)', path: inspec.threeLayerOverlay.path },
];

describe.skipIf(!hasGo())('parser cross-language equivalence (Go ↔ TS)', () => {
  beforeAll(() => {
    const tmp = mkdtempSync(path.join(tmpdir(), 'parse-equivalence-dump-'));
    goBinary = path.join(
      tmp,
      process.platform === 'win32' ? 'parse-equivalence-dump.exe' : 'parse-equivalence-dump',
    );
    execFileSync('go', ['build', '-o', goBinary, '.'], { cwd: goCmdDir });
  }, 120_000);

  for (const { name, path: fixturePath } of FIXTURES) {
    it(`Go and TS parsers agree on ${name}`, () => {
      const raw = readFileSync(fixturePath, 'utf-8');
      const tsOutput = dumpParseResults(raw);
      const goOutput = runGoDumper(fixturePath);
      expect(goOutput).toEqual(tsOutput);
    });
  }
});
