import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { execFileSync } from 'child_process';
import { workspacePackages } from '../generate-packages.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, '../..');
const PAGES_DIR = path.resolve(__dirname, '../docs/packages');

// The rendered pages are git-ignored and produced by `pnpm generate`, which
// runs before `dev` and `build` — so they are never committed and cannot go
// stale in the repository. Generate them here rather than reading whatever a
// previous local run happened to leave behind: without this the suite fails in
// CI, where nothing has generated yet, and passes locally for the wrong reason.
//
// What that leaves these checks catching is a GENERATOR fault — a package it
// silently skips, an index entry it omits, a link it fails to rewrite — not a
// forgotten regeneration, which the build already makes impossible.
test('generate the package pages', () => {
  // Into an empty directory: a page left by an earlier run would otherwise
  // stand in for one this run failed to produce, and the checks below would
  // pass on stale output. Verified by mutation — skipping a package in the
  // generator goes unnoticed without this.
  fs.rmSync(PAGES_DIR, { recursive: true, force: true });
  execFileSync(process.execPath, [path.resolve(__dirname, '../generate-packages.mjs')], {
    cwd: path.resolve(__dirname, '..'),
    stdio: 'pipe',
  });
});

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
test('the generator renders every workspace package with a README', () => {
  const expected = workspacePackages();
  assert.ok(expected.length > 0, 'workspace discovery returned nothing');
  assert.deepEqual(
    renderedPages(),
    expected,
    'the generator did not render one page per workspace package with a README',
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
