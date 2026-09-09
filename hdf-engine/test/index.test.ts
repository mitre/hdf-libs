import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { engineVersion } from '../src/index.js';

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
