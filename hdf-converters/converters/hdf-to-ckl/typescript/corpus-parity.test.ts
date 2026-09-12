import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, it, expect } from 'vitest';
import { resultsCorpus } from '../../../shared/typescript/schema-corpus.js';
import { normalizeXmlForGolden } from '../../../shared/typescript/xml-golden.js';
import { convertHdfToCkl } from './converter.js';

const __dirname = dirname(fileURLToPath(import.meta.url));

// The Go peer generates fixtures/expected/corpus-outputs.json for every corpus
// input; this verifies TypeScript emits the same DOCUMENT, including agreeing on
// which inputs are rejected. Go owns regeneration:
//   go test ./converters/hdf-to-ckl/go/ -update
describe('hdf-to-ckl Go/TypeScript corpus output parity', () => {
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
        actual = convertHdfToCkl(c.input);
      } catch {
        actual = 'REJECTED';
      }
      // Compared through the shared XML normalizer, not raw bytes: Go's
      // encoding/xml emits numeric character references where this builder emits
      // named entities, and Go's escaping is not configurable. Byte equality
      // therefore cannot hold for any document needing escaping — see
      // shared/typescript/xml-golden.ts. What must agree is the document.
      const norm = (s: string): string => (s === 'REJECTED' ? s : normalizeXmlForGolden(s));
      expect(norm(actual), `TypeScript and Go diverged on corpus case ${name}`).toBe(
        norm(golden[name] ?? ''),
      );
    },
  );
});
