import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, it, expect } from 'vitest';
import { resultsCorpus, canonicalJSON } from '../../../shared/typescript/schema-corpus.js';
import { convertHdfToCklb } from './converter.js';

const __dirname = dirname(fileURLToPath(import.meta.url));

// The Go peer generates fixtures/expected/corpus-outputs.json for every corpus
// input; this verifies TypeScript emits the same DOCUMENT, including agreeing on
// which inputs are rejected. Go owns regeneration:
//   go test ./converters/hdf-to-cklb/go/ -update
describe('hdf-to-cklb Go/TypeScript corpus output parity', () => {
  const golden = JSON.parse(
    readFileSync(join(__dirname, '..', 'fixtures', 'expected', 'corpus-outputs.json'), 'utf-8'),
  ) as Record<string, string>;

  it('covers every corpus case', () => {
    expect(Object.keys(golden).sort()).toEqual(resultsCorpus().map((c) => c.name).sort());
  });

  it.each(resultsCorpus().map((c) => [c.name, c] as const))(
    'emits what the Go peer emits for %s',
    (name, c) => {
      let actual: string;
      try {
        actual = convertHdfToCklb(c.input);
      } catch {
        actual = 'REJECTED';
      }
      // Compared through the shared canonicalizer, not raw bytes: Go marshals
      // struct fields in declaration order and escapes <, > and & where
      // JSON.stringify does not, and preserves -0 where JSON.stringify renders 0.
      // internal/corpus names all three as language artifacts. A key present as ""
      // versus absent is NOT one of them and still fails here.
      const norm = (s: string): string => (s === 'REJECTED' ? s : canonicalJSON(s));
      expect(norm(actual), `TypeScript and Go diverged on corpus case ${name}`).toBe(
        norm(golden[name] ?? ''),
      );
    },
  );
});
