import { describe, it, expect } from 'vitest';
import { transformHDF, detectHDFVersion } from './hdf-version.js';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const fixturesDir = join(__dirname, '..', '..', 'converters', 'legacyhdf-to-hdf', 'fixtures', 'input');

function readFixture(name: string): string {
  return readFileSync(join(fixturesDir, name), 'utf-8');
}

describe('transformHDF', () => {
  it('upgrades v1 to v2', () => {
    const v1 = readFixture('minimal.json');
    const v2 = transformHDF(v1, '1', '2');
    const parsed = JSON.parse(v2);
    expect(parsed).toHaveProperty('baselines');
    expect(parsed).toHaveProperty('components');
    expect(parsed).not.toHaveProperty('profiles');
    expect(parsed).not.toHaveProperty('platform');
  });

  it('downgrades v2 to v1', () => {
    const v1 = readFixture('minimal.json');
    const v2 = transformHDF(v1, '1', '2');
    const v1Again = transformHDF(v2, '2', '1');
    const parsed = JSON.parse(v1Again);
    expect(parsed).toHaveProperty('profiles');
    expect(parsed).toHaveProperty('platform');
    expect(parsed).not.toHaveProperty('baselines');
    expect(parsed).not.toHaveProperty('components');
  });

  it('returns input unchanged for same version', () => {
    const v1 = readFixture('minimal.json');
    const output = transformHDF(v1, '1', '1');
    expect(output).toBe(v1);
  });

  it('throws for unknown version pair', () => {
    expect(() => transformHDF('{}', '3', '2')).toThrow('No HDF transform');
  });

  it('round-trip preserves profile count', () => {
    const v1 = readFixture('minimal.json');
    const v2 = transformHDF(v1, '1', '2');
    const v1Again = transformHDF(v2, '2', '1');
    const original = JSON.parse(v1);
    const roundTripped = JSON.parse(v1Again);
    expect(roundTripped.profiles.length).toBe(original.profiles.length);
  });
});

describe('detectHDFVersion', () => {
  it('detects v1', () => {
    expect(detectHDFVersion('{"profiles":[],"platform":{"name":"test"}}')).toBe('1');
  });

  it('detects v2 with components', () => {
    expect(detectHDFVersion('{"baselines":[],"components":[]}')).toBe('2');
  });

  it('throws for ambiguous input', () => {
    expect(() => detectHDFVersion('{"version":"1.0"}')).toThrow('Cannot determine HDF version');
  });

  it('throws for invalid JSON', () => {
    expect(() => detectHDFVersion('not json')).toThrow();
  });
});
