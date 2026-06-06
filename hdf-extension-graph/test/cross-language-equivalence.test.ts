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
import { existsSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
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

function runGoDumper(fixturePath: string): unknown {
  const out = execFileSync('go', ['run', '.', fixturePath], {
    cwd: goCmdDir,
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
