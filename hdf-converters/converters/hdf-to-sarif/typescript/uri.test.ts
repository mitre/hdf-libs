import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import Ajv from 'ajv';
import addFormats from 'ajv-formats';
import { describe, expect, it } from 'vitest';
import { absoluteUri, encodeUriReference } from './uri.js';

const __dirname = dirname(fileURLToPath(import.meta.url));

interface UriCase {
  input: string;
  reference: string;
  absolute: string;
  why: string;
}

// The Go peer reads the same table, which is what stops the two languages
// drifting on a value no fixture happens to carry.
const cases = (
  JSON.parse(
    readFileSync(join(__dirname, '..', 'fixtures', 'uri-reference-cases.json'), 'utf-8'),
  ) as { cases: UriCase[] }
).cases;

const ajv = new Ajv({ strict: false });
addFormats(ajv);
const validReference = ajv.compile({ type: 'string', format: 'uri-reference' });
const validAbsolute = ajv.compile({ type: 'string', format: 'uri' });

describe('hdf-to-sarif URI rendering', () => {
  it('has a table worth reading', () => {
    expect(cases.length).toBeGreaterThan(10);
  });

  it.each(cases.map((c) => [c.input, c] as const))('renders %j as the table says', (_input, c) => {
    expect(encodeUriReference(c.input), c.why).toBe(c.reference);
    expect(absoluteUri(c.input), c.why).toBe(c.absolute);
  });

  // The table's point is that the output satisfies the formats the SARIF schema
  // asserts, so the validator itself is the judge rather than the expectation.
  it.each(cases.map((c) => [c.input, c] as const))('satisfies the schema formats for %j', (_input, c) => {
    expect(validReference(encodeUriReference(c.input)), c.why).toBe(true);
    const abs = absoluteUri(c.input);
    if (abs !== '') expect(validAbsolute(abs), c.why).toBe(true);
  });

  // Encoding is reversible: that is what makes it a rendering rather than a
  // rewrite of the value.
  it.each(cases.map((c) => [c.input, c] as const))('is idempotent on %j', (_input, c) => {
    const once = encodeUriReference(c.input);
    expect(encodeUriReference(once), c.why).toBe(once);
  });
});
