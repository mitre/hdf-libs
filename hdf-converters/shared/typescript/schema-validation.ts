/**
 * Shared JSON Schema validation for converter output tests.
 *
 * Converters that emit a format with a published schema MUST validate their
 * output against it in tests: golden fixtures alone silently encode whatever the
 * converter emits, so schema-invalid output ships unnoticed — as an oscal-sar
 * regression once did, declaring OSCAL 1.1.2 conformance while failing that
 * schema.
 *
 * Picks the ajv dialect from the schema's `$schema` so both draft-07 (OSCAL) and
 * 2020-12 (CSAF, OpenVEX) validate through one helper, matching the Go harness.
 */
import { readFileSync } from 'node:fs';
import Ajv, { type ValidateFunction } from 'ajv';
import Ajv2020 from 'ajv/dist/2020.js';
import addFormats from 'ajv-formats';

/**
 * Compile a self-contained JSON Schema from a file path. For schemas that $ref
 * external schemas by URL, use loadSchemaValidatorWithResources.
 */
export function loadSchemaValidator(schemaPath: string): ValidateFunction {
  return loadSchemaValidatorWithResources(schemaPath, {});
}

/**
 * Compile a JSON Schema, pre-registering companion schemas so a main schema that
 * $refs external schemas by URL (e.g. CycloneDX → SPDX/JSF) compiles offline.
 * `companions` maps each $ref URL exactly as it appears in the main schema to
 * the vendored file that satisfies it. strict:false — validate data against the
 * schema, not lint the external schema.
 */
export function loadSchemaValidatorWithResources(
  schemaPath: string,
  companions: Record<string, string>,
): ValidateFunction {
  const schema = JSON.parse(readFileSync(schemaPath, 'utf-8')) as { $schema?: string };
  const dialect = typeof schema.$schema === 'string' ? schema.$schema : '';
  const modern = dialect.includes('2019-09') || dialect.includes('2020-12');
  const ajv = modern
    ? new Ajv2020({ allErrors: true, strict: false })
    : new Ajv({ allErrors: true, strict: false });
  addFormats(ajv);
  for (const [url, path] of Object.entries(companions)) {
    ajv.addSchema(JSON.parse(readFileSync(path, 'utf-8')) as object, url);
  }
  return ajv.compile(schema);
}

/**
 * Report a document's schema violations, or null when it is valid.
 *
 * Callers that need to assert a document is *invalid* — the corpus tier-B
 * contract — cannot use assertSchemaValid, which throws on exactly the outcome
 * they are asserting.
 */
export function schemaErrors(validate: ValidateFunction, doc: unknown): string | null {
  if (validate(doc)) return null;
  return (validate.errors ?? [])
    .map((e) => `  ${e.instancePath || '/'} ${e.message ?? ''}`)
    .join('\n');
}

/**
 * Assert that a document satisfies the schema, reporting every violation on
 * failure so a red run pinpoints exactly what is wrong.
 */
export function assertSchemaValid(validate: ValidateFunction, label: string, doc: unknown): void {
  const errors = schemaErrors(validate, doc);
  if (errors === null) return;
  throw new Error(`${label}: document does not satisfy the schema:\n${errors}`);
}
