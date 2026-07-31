/**
 * Shared JSON Schema validation for converter output tests.
 *
 * Converters that emit a format with a published schema MUST validate their
 * output against it in tests: golden fixtures alone silently encode whatever the
 * converter emits, so schema-invalid output ships unnoticed (see the
 * hdf-to-oscal-sar regression in GitHub #184, which declared OSCAL 1.1.2
 * conformance while failing that schema on four counts).
 *
 * Picks the ajv dialect from the schema's `$schema` so both draft-07 (OSCAL) and
 * 2020-12 (CSAF, OpenVEX) validate through one helper, matching the Go harness.
 */
import { readFileSync } from 'node:fs';
import Ajv, { type ValidateFunction } from 'ajv';
import Ajv2020 from 'ajv/dist/2020.js';
import addFormats from 'ajv-formats';

/**
 * Compile a JSON Schema from a file path for reuse across a converter's tests.
 * strict:false — validate data against the schema, not lint the external schema.
 */
export function loadSchemaValidator(schemaPath: string): ValidateFunction {
  const schema = JSON.parse(readFileSync(schemaPath, 'utf-8')) as { $schema?: string };
  const dialect = typeof schema.$schema === 'string' ? schema.$schema : '';
  const modern = dialect.includes('2019-09') || dialect.includes('2020-12');
  const ajv = modern
    ? new Ajv2020({ allErrors: true, strict: false })
    : new Ajv({ allErrors: true, strict: false });
  addFormats(ajv);
  return ajv.compile(schema);
}

/**
 * Assert that a document satisfies the schema, reporting every violation on
 * failure so a red run pinpoints exactly what is wrong.
 */
export function assertSchemaValid(validate: ValidateFunction, label: string, doc: unknown): void {
  if (validate(doc)) return;
  const errors = (validate.errors ?? [])
    .map((e) => `  ${e.instancePath || '/'} ${e.message ?? ''}`)
    .join('\n');
  throw new Error(`${label}: document does not satisfy the schema:\n${errors}`);
}
