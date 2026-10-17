import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import path from 'path';
import { execFileSync } from 'child_process';
import { fileURLToPath } from 'url';
import { resolveTypeName, anchorId, renderEnumValues, mdCell } from '../schema-render.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

test('anchorId slugifies type names deterministically (underscore -> hyphen, lowercased)', () => {
  assert.equal(anchorId('Content_Type'), 'content-type');
  assert.equal(anchorId('External_Evidence_Reference'), 'external-evidence-reference');
  assert.equal(anchorId('Checksum'), 'checksum');
});

test('resolveTypeName linkifies a local $ref to a known on-page type', () => {
  const known = new Set(['Content_Type']);
  assert.equal(
    resolveTypeName({ $ref: '#/$defs/Content_Type' }, known),
    '[`Content_Type`](#content-type)',
  );
});

test('resolveTypeName linkifies an embedded-primitive $ref to a known type', () => {
  const known = new Set(['Checksum']);
  assert.equal(
    resolveTypeName(
      { $ref: 'https://mitre.github.io/hdf-libs/schemas/primitives/common/v3.4.0#/$defs/Checksum' },
      known,
    ),
    '[`Checksum`](#checksum)',
  );
});

test('resolveTypeName falls back to plain code when the ref target is not on the page', () => {
  assert.equal(resolveTypeName({ $ref: '#/$defs/Nowhere' }, new Set()), '`Nowhere`');
});

test('resolveTypeName links array item refs via recursion', () => {
  const known = new Set(['Content_Reference']);
  assert.equal(
    resolveTypeName({ type: 'array', items: { $ref: '#/$defs/Content_Reference' } }, known),
    '[`Content_Reference`](#content-reference)[]',
  );
});

test('resolveTypeName links oneOf member refs via recursion', () => {
  const known = new Set(['Signature']);
  assert.equal(
    resolveTypeName({ oneOf: [{ $ref: '#/$defs/Signature' }, { type: 'string' }] }, known),
    '[`Signature`](#signature) \\| `string`',
  );
});

test('resolveTypeName renders inline enums as values (unchanged behavior)', () => {
  assert.equal(resolveTypeName({ enum: ['a', 'b'] }, new Set()), '`"a"` \\| `"b"`');
});

test('resolveTypeName renders a scalar type with format (unchanged behavior)', () => {
  assert.equal(
    resolveTypeName({ type: 'string', format: 'uri-reference' }, new Set()),
    '`string` (uri-reference)',
  );
});

test('renderEnumValues emits the allowed-values block in exact order', () => {
  const lines = [];
  renderEnumValues({ type: 'string', enum: ['x', 'y'] }, lines);
  assert.deepEqual(lines, [
    '**Enum** (`string`) — allowed values:',
    '',
    '- `"x"`',
    '- `"y"`',
    '',
  ]);
});

test('renderEnumValues emits nothing for a non-enum def', () => {
  const lines = [];
  renderEnumValues({ type: 'object' }, lines);
  assert.equal(lines.length, 0);
});

test('mdCell flattens paragraph breaks and escapes table-breaking pipes', () => {
  assert.equal(mdCell('one\n\ntwo'), 'one<br><br>two');
  assert.equal(mdCell('wrapped\nline'), 'wrapped line');
  assert.equal(mdCell('a | b'), 'a \\| b');
  assert.equal(mdCell(undefined), '');
});

test('mdCell escapes emphasis characters so data renders literally', () => {
  // A CPE wildcard tail is the real-world case: markdown emphasis would
  // otherwise pair the asterisks and eat six of the seven wildcards.
  assert.equal(
    mdCell("Example: 'cpe:2.3:a:openssl:openssl:1.1.1k:*:*:*:*:*:*:*'."),
    "Example: 'cpe:2.3:a:openssl:openssl:1.1.1k:\\*:\\*:\\*:\\*:\\*:\\*:\\*'.",
  );
  assert.equal(mdCell("'0 2 1 * *'"), "'0 2 1 \\* \\*'");
  assert.equal(mdCell('base_model_relation'), 'base\\_model\\_relation');
  assert.equal(mdCell('see boms[] on hdf-system'), 'see boms\\[\\] on hdf-system');
});

test('mdCell leaves code spans untouched — a backslash inside one would render literally', () => {
  assert.equal(
    mdCell('Example: `cpe:2.3:a:openssl:openssl:1.1.1k:*:*:*:*:*:*:*`.'),
    'Example: `cpe:2.3:a:openssl:openssl:1.1.1k:*:*:*:*:*:*:*`.',
  );
  assert.equal(mdCell('`snake_case_id`'), '`snake_case_id`');
  assert.equal(mdCell('`boms[]`'), '`boms[]`');
});

test('mdCell escapes outside code spans while preserving the spans between', () => {
  assert.equal(
    mdCell('VEX `affects[]` / `products[]`, OSCAL subjects[] here'),
    'VEX `affects[]` / `products[]`, OSCAL subjects\\[\\] here',
  );
  assert.equal(mdCell('*emph* then `a*b` then *more*'), '\\*emph\\* then `a*b` then \\*more\\*');
});

test('mdCell escapes backslashes before adding its own, and tolerates an unmatched backtick', () => {
  // The pre-existing backslash is doubled; the escapes added afterwards are not
  // themselves re-escaped.
  assert.equal(mdCell('a\\b *c*'), 'a\\\\b \\*c\\*');
  // An unmatched backtick must not swallow the rest of the string.
  assert.equal(mdCell('open ` then *x*'), 'open ` then \\*x\\*');
});

// The schema index states how many document types HDF defines and then lists them.
// Those two were allowed to disagree: the sentence hardcoded 7 while the list was
// rendered from the built schemas, so the page contradicted itself. The count is now
// derived from the same array that builds the list, and this pins them together.
//
// The partial-build case — fewer types rendered with a matching lower number, which is
// self-consistent and still wrong — is handled by building the bundles first, below.
test('the schema index states the same number of document types that it lists', () => {
  const siteDir = path.resolve(__dirname, '..');
  const repoRoot = path.resolve(siteDir, '..');
  // The generator reads a BUILD DIRECTORY, and a partial one renders fewer types with a
  // matching lower number — self-consistent, passing, and wrong. Build when the bundles
  // are missing or short, so this cannot pass locally for the wrong reason. Same reasoning
  // as the sibling openapi-render test, which builds its artifact when absent.
  const srcRoots = fs.readdirSync(path.join(repoRoot, 'hdf-schema/src/schemas'))
    .filter((f) => f.endsWith('.schema.json')).length;
  const bundled = path.join(repoRoot, 'hdf-schema/dist/schemas');
  const built = fs.existsSync(bundled)
    ? fs.readdirSync(bundled).filter((f) => f.endsWith('.schema.json')).length
    : 0;
  if (built < srcRoots) {
    execFileSync('pnpm', ['--filter', '@mitre/hdf-schema', 'run', 'build:schemas'], {
      cwd: repoRoot,
      stdio: 'inherit',
    });
  }
  execFileSync('node', ['generate-schema-docs.mjs'], { cwd: siteDir, stdio: 'ignore' });
  const page = fs.readFileSync(path.join(siteDir, 'schemas', 'index.md'), 'utf-8');
  const stated = page.match(/defines (\d+) JSON document types/);
  assert.ok(stated, 'the index no longer states a document-type count');
  const listed = (page.match(/^### \[/gm) ?? []).length;
  assert.ok(listed > 0, 'the index lists no document types, so this check could not fail');
  assert.equal(Number(stated[1]), listed);
});
