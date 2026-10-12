import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import path from 'path';
import os from 'os';
import { fileURLToPath } from 'url';
import { generateProblemPages, PROBLEM_TABLE } from '../generate-problem-pages.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, '../..');
const PAGES_DIR = path.resolve(__dirname, '../problems');

const table = JSON.parse(fs.readFileSync(path.resolve(REPO_ROOT, PROBLEM_TABLE), 'utf-8'));

test('generate the problem-type pages', () => {
  generateProblemPages();
});

test('every documented type publishes a page', () => {
  const types = Object.keys(table);
  assert.ok(types.length > 10, 'the table documents almost nothing, so this could not fail');
  for (const type of types) {
    // A directory index, not <type>.md: the declared URI has no extension, and VitePress
    // would publish <type>.html for a flat page.
    assert.ok(
      fs.existsSync(path.join(PAGES_DIR, type, 'index.md')),
      `${type} has no page at problems/${type}/index.md`,
    );
  }
});

// The document-derived half of this chain lives in hdf-openapi/test/problem-docs.test.ts,
// which asserts every type the API declares has a table entry. It cannot live here: a
// sibling test in this suite renames hdf-openapi/dist/hdf-api.oas.json aside to exercise an
// optional-document path, and node:test runs files concurrently, so reading it here is an
// ENOENT waiting to happen (hdf-libs-sp84s). Composed, the two halves are document -> table
// -> page; this file owns the second.
test('each page states its status and links the RFC', () => {
  for (const [type, entry] of Object.entries(table)) {
    const page = fs.readFileSync(path.join(PAGES_DIR, type, 'index.md'), 'utf-8');
    assert.match(page, new RegExp(`HTTP status ${entry.status}`), `${type} omits its status`);
    assert.match(page, /rfc9457/, `${type} does not cite RFC 9457`);
  }
});

test('the index lists every type', () => {
  const index = fs.readFileSync(path.join(PAGES_DIR, 'index.md'), 'utf-8');
  for (const type of Object.keys(table)) {
    assert.ok(index.includes(`\`${type}\``), `the index omits ${type}`);
  }
});

test('the generated pages carry no emoji', () => {
  for (const type of Object.keys(table)) {
    const page = fs.readFileSync(path.join(PAGES_DIR, type, 'index.md'), 'utf-8');
    const emoji = page.match(/\p{Extended_Pictographic}/gu) ?? [];
    assert.deepEqual(emoji, [], `${type} contains emoji: ${emoji.join(' ')}`);
  }
});

// Pointed at a missing path rather than renaming hdf-openapi/dist/problems.json: that file
// is read at module scope by that package's own suite, and pnpm runs the two concurrently.
test('an unbuilt table fails loudly rather than publishing nothing', () => {
  assert.throws(() => generateProblemPages('hdf-openapi/dist/absent.json'), /is not built/);
});

test('a table documenting nothing fails rather than publishing an empty set', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hdf-problems-'));
  try {
    const empty = path.join(dir, 'problems.json');
    fs.writeFileSync(empty, '{}');
    assert.throws(() => generateProblemPages(path.relative(REPO_ROOT, empty)), /documents no problem types/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// The one page string not drawn from problems.yaml is the per-owner note, so the rendered
// page is checked too rather than only the table the MCP-vocabulary guard in hdf-openapi reads.
test('no rendered page carries MCP vocabulary', () => {
  for (const type of Object.keys(table)) {
    const page = fs.readFileSync(path.join(PAGES_DIR, type, 'index.md'), 'utf-8');
    assert.doesNotMatch(page, /HDF_MCP_|\bhdf_[a-z]+/, `${type} names an MCP tool or variable`);
  }
});
