import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, it, expect } from 'vitest';
import { loadSchemaValidatorWithResources, assertSchemaValid } from '../../../shared/typescript/schema-validation.js';
import {
  amendmentsCorpus,
  runSchemaCorpus,
  jsonDocumentValidator,
} from '../../../shared/typescript/schema-corpus.js';
import { convertHdfToCyclonedxVex } from './converter.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const schemas = join(__dirname, '..', 'schemas');
// The url fields are `format: iri-reference` and contacts `idn-email`, neither of
// which ajv-formats implements, so a green run here says nothing about them. The
// Go peer asserts both; see shared/testdata/format-assertion-cases.json.
const validate = loadSchemaValidatorWithResources(join(schemas, 'bom-1.4.schema.json'), {
  'http://cyclonedx.org/schema/spdx.schema.json': join(schemas, 'spdx.schema.json'),
  'http://cyclonedx.org/schema/jsf-0.82.schema.json': join(schemas, 'jsf-0.82.schema.json'),
});
const loadInput = (name: string): string =>
  readFileSync(join(__dirname, '..', 'fixtures', 'input', name), 'utf-8');

describe('hdf-to-cyclonedx-vex output validates against CycloneDX v1.4 schema', () => {
  it.each(['case1-fixed-amendments.json', 'case1-not_affected-amendments.json'])('%s', async (name) => {
    const out = JSON.parse(await convertHdfToCyclonedxVex(loadInput(name), '1.0.0')) as unknown;
    assertSchemaValid(validate, name, out);
  });
});

// The shared corpus holds this converter to both contracts an exporter owes,
// rather than only to fully-populated fixtures. Every MustConvert case names no
// product, which is the path the happy-path fixtures never reach.
describe('hdf-to-cyclonedx-vex against the adversarial corpus', () => {
  it('satisfies both corpus contracts', async () => {
    await runSchemaCorpus(jsonDocumentValidator(validate), amendmentsCorpus(), (input) =>
      convertHdfToCyclonedxVex(input, '1.0.0'),
    );
  });
});

// Byte-for-byte equality with the SAME corpus goldens the Go TestCorpusGoldenParity
// freezes, so the two exporters' answer to "nothing identifies a product" is
// asserted against one file rather than two implementations. serialNumber is the
// one field masked: with no amendmentId it hashes the input bytes, and the Go and
// TS corpus builders serialize the same case to different bytes, so it can never
// agree across languages. It is still asserted to be a well-formed urn:uuid.
const SERIAL_NUMBER = /"serialNumber": "urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"/;
const maskSerialNumber = (doc: string): string =>
  doc.replace(SERIAL_NUMBER, '"serialNumber": "urn:uuid:<input-hash>"');

describe('hdf-to-cyclonedx-vex corpus golden parity (TS↔Go)', () => {
  it.each(
    amendmentsCorpus()
      .filter((c) => c.contract === 'MustConvert')
      .map((c) => [c.name, c] as const),
  )('%s matches the Go-frozen golden', async (name, c) => {
    const golden = readFileSync(
      join(__dirname, '..', 'fixtures', 'expected', `corpus-${name}.cdx.json`),
      'utf-8',
    );
    const out = await convertHdfToCyclonedxVex(c.input, '1.0.0');
    expect(out).toMatch(SERIAL_NUMBER);
    expect(maskSerialNumber(out)).toBe(maskSerialNumber(golden));
    expect(out).not.toContain('HDFPID');
  });
});
