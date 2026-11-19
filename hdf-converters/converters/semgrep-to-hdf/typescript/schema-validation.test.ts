import { readFileSync, readdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { loadSchemaValidator, schemaErrors } from '../../../shared/typescript/schema-validation.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const FIXTURES = join(__dirname, '..', 'fixtures');

// Every input fixture must satisfy the semgrep output schema for the release it
// declares. The Go suite validates the 1.183.0 capture and the adapted cases through
// the shared validator; this file covers every file fixture, the 1.174.0 ones included.
describe('semgrep-to-hdf fixtures validate against the vendored schema', () => {
  const inputs = readdirSync(join(FIXTURES, 'input')).filter((f) => f.endsWith('.json')).sort();

  it('has input fixtures to check', () => {
    expect(inputs.length).toBeGreaterThan(0);
  });

  it.each(inputs)('%s validates against semgrep_output_v1 for its declared version', (name) => {
    const doc = JSON.parse(readFileSync(join(FIXTURES, 'input', name), 'utf-8')) as { version?: string };
    expect(doc.version, 'fixture declares no semgrep version').toBeTruthy();
    const schema = join(FIXTURES, `semgrep_output_v1-${doc.version}.schema.json`);
    const validate = loadSchemaValidator(schema);
    expect(schemaErrors(validate, doc), `${name} fails ${schema}`).toBeNull();
  });
});
