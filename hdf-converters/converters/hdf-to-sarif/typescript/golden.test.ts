import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { results as sharedResults } from '@mitre/hdf-fixtures';
import { describe, expect, it } from 'vitest';
import { resultsCorpus } from '../../../shared/typescript/schema-corpus.js';
import { convertHdfToSarif } from './converter.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const fixtures = join(__dirname, '..', 'fixtures');

/** Matches the Go peer's testVersion so both languages freeze the same bytes. */
const TEST_VERSION = '0.0.0';

const goldenInputs = ['flawfinder', 'grype-cve', 'minimal'] as const;

function loadInput(name: string): string {
  if (name === 'minimal') return sharedResults.minimal.read();
  return readFileSync(join(fixtures, 'input', `${name}.hdf.json`), 'utf-8');
}

// Byte-for-byte equality with the SAME goldens the Go TestGoldenParity froze.
// Go owns regeneration (UPDATE_GOLDEN=1 go test ./converters/hdf-to-sarif/go/);
// TypeScript only verifies, which is what makes the parity claim an assertion.
describe('hdf-to-sarif golden parity (TS↔Go)', () => {
  it.each(goldenInputs)('matches the %s golden byte-for-byte', (name) => {
    const golden = readFileSync(join(fixtures, 'expected', `${name}.sarif.json`), 'utf-8');
    expect(convertHdfToSarif(loadInput(name), TEST_VERSION)).toBe(golden);
  });
});

// The adversarial corpus is where two implementations drift: sparse and
// malformed inputs no happy-path golden reaches. The goldens pin both languages'
// output AND which inputs each refuses.
describe('hdf-to-sarif corpus output parity (TS↔Go)', () => {
  const golden = JSON.parse(
    readFileSync(join(fixtures, 'expected', 'corpus-outputs.json'), 'utf-8'),
  ) as Record<string, string>;

  it('covers every corpus case', () => {
    expect(Object.keys(golden).sort()).toEqual(resultsCorpus().map((c) => c.name).sort());
  });

  it.each(resultsCorpus().map((c) => [c.name, c] as const))('emits what Go emits for %s', (name, c) => {
    let actual: string;
    try {
      actual = convertHdfToSarif(c.input, TEST_VERSION);
    } catch {
      actual = 'REJECTED';
    }
    expect(actual, `TypeScript and Go diverged on corpus case ${name}`).toBe(golden[name] ?? '');
  });
});
