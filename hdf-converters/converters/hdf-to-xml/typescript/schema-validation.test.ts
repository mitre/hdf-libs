import { describe, it, expect } from 'vitest';
import { isValidXml } from '@mitre/hdf-utilities';
import { resultsCorpus, runSchemaCorpus } from '../../../shared/typescript/schema-corpus.js';
import { convertHdfToXml } from './converter.js';

// NO TARGET SCHEMA EXISTS, and none can. This converter is a generic
// JSON-to-XML serializer of HDF itself, not an exporter to a third-party format,
// so there is no external specification to validate against — the "schema" for
// its output is the HDF schema the input already satisfied.
//
// What remains checkable is well-formedness: output no XML parser can read is
// malformed in the way a schema would catch, and it is reachable, since element
// names are derived from arbitrary HDF keys. A no-op validator would make every
// MustConvert contract pass vacuously. Mirrors the Go peer.
const xmlWellFormed = (doc: unknown): string | null => {
  const text = typeof doc === 'string' ? doc : '';
  if (text === '') return null;
  return isValidXml(text) ? null : 'output is not well-formed XML';
};

describe('hdf-to-xml adversarial corpus', () => {
  it('satisfies every contract for every case', async () => {
    const cases = resultsCorpus();
    expect(cases.length, 'an empty corpus would pass vacuously').toBeGreaterThan(0);
    await runSchemaCorpus(xmlWellFormed, cases, (input) => convertHdfToXml(input));
  });
});
