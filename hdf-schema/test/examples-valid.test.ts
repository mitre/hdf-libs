import { describe, expect, it } from 'vitest';
import { readdirSync, readFileSync } from 'fs';
import { dirname, join } from 'path';
import { fileURLToPath } from 'url';
import { createAjvWithPrimitives } from './setup';

// Derived rather than relying on __dirname: these run as ES modules, and the
// neighbouring suites (setup.ts, bundle-schemas-noid.test.ts) do the same.
const here = dirname(fileURLToPath(import.meta.url));

// Every `examples` entry must validate against the definition it illustrates.
// The bundler ships examples into dist, where IDE tooltips offer them to
// consumers as model documents — an invalid example teaches the wrong shape.
//
// This guard exists because the convention drifted: examples carried a
// `$comment` key describing what they demonstrate, but an example is DATA, not
// a schema, so on any definition that forbids undeclared properties that key
// made the example invalid. 56 example-level comments were relocated to a
// `$comment` on the owning definition, where the keyword is legal; 26 of those
// examples had been outright invalid.

interface Node {
  examples?: unknown[];
  [key: string]: unknown;
}

function sourceSchemas(): string[] {
  const found: string[] = [];
  const walk = (dir: string) => {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const path = join(dir, entry.name);
      if (entry.isDirectory()) walk(path);
      else if (entry.name.endsWith('.schema.json')) found.push(path);
    }
  };
  walk(join(here, '..', 'src', 'schemas'));
  return found.sort();
}

describe('schema examples', () => {
  const files = sourceSchemas();

  // Counted up front rather than accumulated across the per-file tests, so the
  // floor below does not depend on test execution order.
  const countExamples = (node: unknown): number => {
    if (!node || typeof node !== 'object') return 0;
    const obj = node as Node;
    let n = Array.isArray(obj.examples) ? obj.examples.length : 0;
    for (const [key, value] of Object.entries(obj)) {
      if (key !== 'examples') n += countExamples(value);
    }
    return n;
  };
  const totalExamples = files.reduce(
    (sum, f) => sum + countExamples(JSON.parse(readFileSync(f, 'utf-8'))),
    0,
  );

  it('finds schemas to check, so a walk failure cannot read as a pass', () => {
    expect(files.length).toBeGreaterThan(5);
  });

  // Three source files legitimately carry no examples, so a per-file minimum
  // cannot be asserted. A repo-wide floor is what stops the walk silently
  // finding nothing and every per-file check passing vacuously.
  it('checks a realistic number of examples overall', () => {
    expect(totalExamples).toBeGreaterThan(100);
  });

  for (const file of files) {
    const label = file.split('/schemas/')[1]!;

    it(`every example in ${label} validates against its own definition`, () => {
      const schema = JSON.parse(readFileSync(file, 'utf-8')) as Node & { $id?: string };
      const ajv = createAjvWithPrimitives();
      const failures: string[] = [];
      let checked = 0;

      // Validate each example through a $ref into the REGISTERED document, so a
      // definition's local refs (#/$defs/...) still resolve. Compiling a
      // detached subschema breaks them and reports a harness error that reads
      // like a schema defect.
      // Register every source schema, not just this one: a document may $ref a
      // sibling (hdf-plan -> primitives/plan, requirement-change-event ->
      // hdf-results), and an unresolved ref is a harness gap that would
      // otherwise read as a schema defect.
      for (const other of files) {
        const doc = JSON.parse(readFileSync(other, 'utf-8')) as { $id?: string };
        if (doc.$id && !ajv.getSchema(doc.$id)) ajv.addSchema(doc);
      }
      const id = schema.$id;
      expect(id, `${label} has no $id`).toBeTruthy();

      const visit = (node: unknown, pointer: string) => {
        if (!node || typeof node !== 'object') return;
        const obj = node as Node;
        if (Array.isArray(obj.examples)) {
          const validate = ajv.compile({ $ref: `${id}#${pointer}` });
          for (const [i, example] of obj.examples.entries()) {
            checked++;
            if (!validate(example)) {
              const why = (validate.errors ?? [])
                .map((e) => `${e.instancePath || '/'} ${e.message}`)
                .join('; ');
              failures.push(`${pointer}/examples[${i}]: ${why}`);
            }
          }
        }
        for (const [key, value] of Object.entries(obj)) {
          if (key === 'examples') continue;
          const escaped = key.replace(/~/g, '~0').replace(/\//g, '~1');
          visit(value, `${pointer}/${escaped}`);
        }
      };
      visit(schema, '');
      expect(failures, `${checked} examples checked in ${label}`).toEqual([]);
    });
  }
});
