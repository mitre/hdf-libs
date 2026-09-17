import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { workspacePackages } from '../generate-packages.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, '../..');
const PAGES_DIR = path.resolve(__dirname, '../docs/packages');

function renderedPages() {
  if (!fs.existsSync(PAGES_DIR)) return [];
  return fs
    .readdirSync(PAGES_DIR)
    .filter((f) => f.endsWith('.md') && f !== 'index.md')
    .map((f) => f.replace(/\.md$/, ''))
    .sort();
}

// The expected set is derived from the workspace, never restated here. A
// hand-kept list is the failure this guard exists to prevent: it would happily
// agree with itself while a new package went unrendered.
test('every workspace package with a README is rendered to the site', () => {
  const expected = workspacePackages();
  assert.ok(expected.length > 0, 'workspace discovery returned nothing');
  assert.deepEqual(
    renderedPages(),
    expected,
    'run `pnpm generate` in site/ — the rendered package pages no longer match the workspace',
  );
});

// A package directory that exists but carries no README is invisible to the
// site. That is a documentation gap, not a rendering bug, so it is named here
// rather than silently skipped by the generator.
test('no hdf-* workspace package is missing a README', () => {
  const missing = fs
    .readdirSync(REPO_ROOT, { withFileTypes: true })
    .filter((e) => e.isDirectory() && e.name.startsWith('hdf-'))
    .map((e) => e.name)
    .filter((name) => !fs.existsSync(path.join(REPO_ROOT, name, 'README.md')))
    .sort();
  assert.deepEqual(missing, [], 'these packages have no README and so cannot reach the site');
});

// The index is the nav's entry point; a package absent from it is reachable
// only by guessing the URL.
test('the packages index links every rendered page', () => {
  const index = fs.readFileSync(path.join(PAGES_DIR, 'index.md'), 'utf8');
  for (const pkg of renderedPages()) {
    assert.ok(index.includes(`](./${pkg})`), `packages index does not link ${pkg}`);
  }
});

// A README link written for the repository 404s on the site unless rewritten,
// and a silent 404 is exactly what nobody notices.
test('no rendered page carries an unrewritten repo-relative link', () => {
  for (const pkg of renderedPages()) {
    const body = fs.readFileSync(path.join(PAGES_DIR, `${pkg}.md`), 'utf8');
    const relative = [...body.matchAll(/\]\((\.\.?\/[^)]+)\)/g)].map((m) => m[1]);
    const unresolved = relative.filter((l) => !/^\.\/hdf-[a-z-]+(#|$)/.test(l));
    assert.deepEqual(unresolved, [], `${pkg}.md has repo-relative links the generator did not rewrite`);
  }
});
