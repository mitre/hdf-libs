import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { checksumHex, engineVersion } from '../src/index.js';

// The README lists checksumHex as public, so it must be reachable from the entry
// point, and it must agree with Go's ChecksumHex on the vectors both suites read.
describe('checksumHex from the package entry point', () => {
  it('matches the shared BLAKE3 reference vectors Go is also held to', async () => {
    const { cases } = JSON.parse(
      readFileSync(new URL('../testdata/blake3-vectors.json', import.meta.url), 'utf8'),
    ) as { cases: { input_len: number; hash: string }[] };
    expect(cases.length).toBeGreaterThan(0);
    for (const c of cases) {
      const input = Uint8Array.from({ length: c.input_len }, (_, i) => i % 251);
      expect(await checksumHex('blake3', input)).toBe(c.hash.slice(0, 64));
    }
  });
});

describe('@mitre/hdf-engine scaffold', () => {
  // Mirror of the Go TestVersion: assert against package.json rather than a
  // literal, so a sweep that misses one of the three constants fails here.
  it('exports the version its package.json declares', () => {
    const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')) as {
      version?: string;
    };
    expect(pkg.version).toBeTruthy();
    expect(engineVersion).toBe(pkg.version);
  });
});
