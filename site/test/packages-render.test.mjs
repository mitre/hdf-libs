import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { workspacePackages, generatePackages } from '../generate-packages.mjs';

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
  generatePackages();
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

// The two transitions the clean render cannot see. Regenerating into an emptied
// directory is right for CI, but it erases exactly the states these describe —
// so they are exercised against the generator's own prune loop instead, WITHOUT
// the wipe. That loop is what removes a dropped or renamed package's page in
// normal use, and nothing else covers it.
test('the generator prunes a page whose package no longer exists', () => {
  const ghost = path.join(PAGES_DIR, 'hdf-ghost-not-a-package.md');
  fs.writeFileSync(ghost, '# ghost\n');
  generatePackages();
  assert.equal(fs.existsSync(ghost), false, 'a page with no matching package must be pruned');
});

test('the generator prunes the old page when a package is renamed', () => {
  // A rename presents as the old name's page lingering beside the new one.
  const old = path.join(PAGES_DIR, 'hdf-former-name.md');
  fs.writeFileSync(old, '# former\n');
  generatePackages();
  assert.equal(fs.existsSync(old), false, 'the pre-rename page must not survive');
  assert.deepEqual(renderedPages(), workspacePackages(), 'and the set must match the workspace');
});

// The index is the nav's entry point, so a run that does not produce it breaks
// navigation silently. Note this cannot test the prune loop's index.md
// exemption: the index is rewritten after pruning, so deleting it mid-run is
// unobservable — the exemption is belt-and-braces, not load-bearing.
test('every run produces the packages index', () => {
  fs.rmSync(PAGES_DIR, { recursive: true, force: true });
  generatePackages();
  assert.ok(fs.existsSync(path.join(PAGES_DIR, 'index.md')), 'the run must write index.md');
});

// site is a workspace package (pnpm-workspace.yaml) that is deliberately not
// rendered — it is the site itself, not a library. The exclusion is implicit in
// the hdf- prefix filter, so state it here; otherwise the generator and the
// check agree by construction and neither records the intent.
test('site is excluded from the rendered set, deliberately', () => {
  assert.ok(!workspacePackages().includes('site'), 'site must not be rendered as a package page');
  assert.equal(fs.existsSync(path.join(PAGES_DIR, 'site.md')), false);
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
