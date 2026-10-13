// Validate a schema's own `examples` against it, with a 2020-12 engine.
//
// ADR-0008 §2 makes this a condition of the conventions privilege: a hand-authored
// component may exist only if its example is CHECKED. Exported rather than written inside
// a test so the check and the published helper are the same code — a consumer authoring a
// conventions component can run exactly what the suite runs.

import Ajv2020 from 'ajv/dist/2020.js';
import addFormats from 'ajv-formats';

export interface ExampleFault {
  index: number;
  errors: string;
}

/**
 * Faults in a schema's own examples. An empty array means every example validates.
 *
 * `references` supplies the components an example's schema may `$ref` — the ingest request
 * points at the eight document roots, so without them it cannot compile.
 */
export function validateExample(
  schema: Record<string, unknown>,
  references: Record<string, unknown> = {},
): ExampleFault[] {
  const examples = schema.examples;
  if (!Array.isArray(examples)) return [];

  const ajv = new Ajv2020({ strict: false, allErrors: true });
  addFormats(ajv);
  for (const [name, referenced] of Object.entries(references)) {
    ajv.addSchema(referenced as object, `#/components/schemas/${name}`);
  }
  const validate = ajv.compile(schema);

  const faults: ExampleFault[] = [];
  examples.forEach((example, index) => {
    if (!validate(example)) {
      faults.push({ index, errors: JSON.stringify(validate.errors) });
    }
  });
  return faults;
}
