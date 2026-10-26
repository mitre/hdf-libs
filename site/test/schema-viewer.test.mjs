import test from 'node:test';
import assert from 'node:assert/strict';
import { schemaSections } from '../.vitepress/theme/schema-viewer.mjs';

test('section navigation preserves bundled definition keys containing slashes, dots and tildes', () => {
  const schema = { properties: { name: { type: 'string' } }, $defs: {
    'https://example.org/common/v3.8.0': { title: 'Common', $defs: {
      'name/with~punctuation': { type: 'string' },
    } },
    Local: false,
  } };
  const sections = schemaSections(schema);
  assert.equal(sections[0].value, schema);
  assert.equal(sections[1].value, schema.properties);
  assert.deepEqual(sections.slice(2).map((s) => s.label), ['Common', 'Common / name/with~punctuation', 'Local']);
  assert.equal(sections[3].value, schema.$defs['https://example.org/common/v3.8.0'].$defs['name/with~punctuation']);
  assert.equal(sections[4].value, false);
});

test('section navigation supports historical definitions and schemas without definitions', () => {
  const legacy = { definitions: { Thing: { type: 'object' } } };
  assert.equal(schemaSections(legacy)[1].value, legacy.definitions.Thing);
  assert.deepEqual(schemaSections({}), [{ label: 'Full schema', value: {} }]);
});
