// Pins behavioral parity between the TypeScript and Go implementations of
// buildExtensionGraph + the five derived ContextualizedRequirement properties
// (root, isRedundant, fullCode, extensionChain, modifications). Spawns the Go
// dumper binary (../go/cmd/equivalence-dump) and the TS dumper (./equivalence-
// dump.ts) on the same fixture, then deep-equals the canonical JSON each
// produces. Catches drift like: parent-pointer mis-linking, sort-order
// divergence, undefined-vs-null serialization, fullCode header formatting.
//
// Skipped when `go` is unavailable on PATH so dev-environments without a Go
// toolchain don't fail. CI must have Go (the Go test suite requires it).
import { execFileSync } from 'node:child_process';
import { existsSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { beforeAll, describe, expect, it } from 'vitest';
import { dump, loadFixture } from './equivalence-dump.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(__dirname, '..');
const goCmdDir = path.join(repoRoot, 'go', 'cmd', 'equivalence-dump');

function hasGo(): boolean {
  try {
    execFileSync('go', ['version'], { stdio: 'ignore' });
    return true;
  } catch {
    return false;
  }
}

// Built once in beforeAll and reused across fixtures. Using `go run` per
// invocation re-links every time and blew past the default 5s vitest timeout
// on cold CI runners.
let goBinary = '';

function runGoDumper(fixturePath: string): unknown {
  const out = execFileSync(goBinary, [fixturePath], {
    encoding: 'utf-8',
    maxBuffer: 64 * 1024 * 1024,
  });
  return JSON.parse(out);
}

const FIXTURES = [
  'multilayered-inspec.json',
  'equivalence-modifications.json',
];

describe.skipIf(!hasGo())('cross-language equivalence (Go ↔ TS)', () => {
  beforeAll(() => {
    const tmp = mkdtempSync(path.join(tmpdir(), 'equivalence-dump-'));
    goBinary = path.join(
      tmp,
      process.platform === 'win32' ? 'equivalence-dump.exe' : 'equivalence-dump',
    );
    execFileSync('go', ['build', '-o', goBinary, '.'], { cwd: goCmdDir });
  }, 120_000);

  for (const name of FIXTURES) {
    const fixturePath = path.join(repoRoot, 'test', 'fixtures', name);

    it(`produces identical canonical dumps on ${name}`, () => {
      expect(existsSync(fixturePath), `fixture missing: ${fixturePath}`).toBe(true);
      const tsOutput = dump(loadFixture(fixturePath));
      const goOutput = runGoDumper(fixturePath);
      expect(goOutput).toEqual(tsOutput);
    });
  }
});
