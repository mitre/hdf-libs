import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, '../..');
const SPEC = fs.readFileSync(
  path.join(REPO_ROOT, 'site/docs/specification/hdf-specification.md'),
  'utf8',
);
const PRIMITIVES = path.join(REPO_ROOT, 'hdf-schema/src/schemas/primitives');

function schemaDef(file, name) {
  const doc = JSON.parse(fs.readFileSync(path.join(PRIMITIVES, file), 'utf8'));
  const def = doc.$defs[name];
  assert.ok(def, `${file} has no $defs.${name}`);
  return def;
}

// The body of `### <heading>` (version marker allowed), up to the next heading.
function section(heading) {
  const lines = SPEC.split('\n');
  const start = lines.findIndex((l) => l === `### ${heading}` || l.startsWith(`### ${heading} *(`));
  assert.notEqual(start, -1, `the spec has no "### ${heading}" section`);
  const rest = lines.slice(start + 1);
  const end = rest.findIndex((l) => /^#{1,3} /.test(l));
  return end === -1 ? rest : rest.slice(0, end);
}

// Field column of the section's table, and the rows whose Required column is bold yes.
function tableFields(heading) {
  const rows = section(heading)
    .filter((l) => l.startsWith('|'))
    .slice(2)
    .map((l) => l.split('|').map((c) => c.trim()));
  return {
    fields: rows.map((r) => r[1]),
    required: rows.filter((r) => r[3] === '**yes**').map((r) => r[1]),
  };
}

// A minor that adds a field must add it to the spec too; these tables are held to their
// definitions in both directions, so neither a missing nor a stale row survives.
for (const [heading, file, def] of [
  ['RequirementResult', 'result.schema.json', 'Requirement_Result'],
  ['Raw_Source_Record', 'result.schema.json', 'Raw_Source_Record'],
  ['External_Reference', 'common.schema.json', 'External_Reference'],
]) {
  test(`spec table "${heading}" lists exactly the fields of ${def}`, () => {
    const schema = schemaDef(file, def);
    const { fields, required } = tableFields(heading);
    assert.deepEqual([...fields].sort(), Object.keys(schema.properties).sort());
    assert.deepEqual([...required].sort(), [...(schema.required ?? [])].sort());
  });
}

// Raw_Source_Artifact declares no properties: it is External_Reference with members
// forbidden and others made conditionally required, so the table is derived from that.
test('spec table "Raw_Source_Artifact" lists External_Reference minus what it forbids', () => {
  const parts = schemaDef('extensions.schema.json', 'Raw_Source_Artifact').allOf;
  const ref = parts.find((p) => p.$ref).$ref;
  const [, primitive, name] = ref.match(/primitives\/([a-z]+)\/[^#]+#\/\$defs\/(\w+)$/);
  const base = schemaDef(`${primitive}.schema.json`, name);
  const forbidden = parts.flatMap((p) => p.not?.required ?? []);
  const { fields, required } = tableFields('Raw_Source_Artifact');
  const expected = Object.keys(base.properties).filter((f) => !forbidden.includes(f));
  assert.deepEqual([...fields].sort(), expected.sort());
  assert.deepEqual([...required].sort(), [...base.required].sort());

  // A member the composition requires only alongside another must say so in its row.
  const rows = section('Raw_Source_Artifact').filter((l) => l.startsWith('|'));
  for (const rule of parts.filter((p) => p.if)) {
    const [trigger] = rule.if.required;
    for (const field of rule.then.required) {
      const row = rows.find((l) => l.startsWith(`| ${field} |`));
      assert.match(row, new RegExp(`Required whenever \`${trigger}\` is present`), field);
    }
  }
});

test('spec enumeration ExternalReferenceEncoding lists the schema enum', () => {
  const values = schemaDef('common.schema.json', 'External_Reference_Encoding').enum;
  const body = section('ExternalReferenceEncoding').join('\n');
  const listed = [...body.matchAll(/`([^`]+)`/g)].map((m) => m[1]);
  assert.deepEqual(listed.sort(), [...values].sort());
});
