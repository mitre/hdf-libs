import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import path from 'path';
import { execFileSync } from 'child_process';
import { fileURLToPath } from 'url';
import { DOCUMENTS, generateOpenapiDocs, COMPONENTS_DOCUMENT } from '../generate-openapi-docs.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, '../..');
const PAGES_DIR = path.resolve(__dirname, '../openapi');
const PUBLIC_DIR = path.resolve(__dirname, '../public/openapi');
const BASELINE = path.resolve(REPO_ROOT, 'hdf-openapi/test/baseline/keywords.json');

// The generator reads a BUILD ARTIFACT. Generate it here rather than trusting
// whatever a previous local run left behind: without this the suite fails in CI,
// where nothing has built yet, and passes locally for the wrong reason.
test('generate the openapi pages and archive', () => {
  const built = path.resolve(REPO_ROOT, COMPONENTS_DOCUMENT);
  if (!fs.existsSync(built)) {
    execFileSync('pnpm', ['run', 'build:components'], {
      cwd: path.resolve(REPO_ROOT, 'hdf-openapi'),
      stdio: 'inherit',
    });
  }
  // Into empty directories: output left by an earlier run would otherwise stand
  // in for output this run failed to produce. PUBLIC_DIR holds the TRACKED
  // per-version archive, so a generator that throws after the delete would leave
  // a tracked file missing from the working tree — restore it in that case rather
  // than leaving the repo dirty for whoever runs the suite next.
  fs.rmSync(PAGES_DIR, { recursive: true, force: true });
  fs.rmSync(PUBLIC_DIR, { recursive: true, force: true });
  try {
    generateOpenapiDocs();
  } catch (err) {
    // Best-effort: `git checkout` cannot restore the archive while it is still
    // untracked, and its failure must not replace the generator's real error.
    try {
      execFileSync('git', ['checkout', '--', 'site/public/openapi'], { cwd: REPO_ROOT, stdio: 'ignore' });
    } catch {
      /* nothing to restore */
    }
    throw err;
  }
});

// The archive path is derived from the document's own info.version, never
// restated here — a hand-kept version would agree with itself while the
// generator wrote somewhere else.
test('the archive follows the schema archive convention: <name>/v<version>/index.json', () => {
  const doc = JSON.parse(fs.readFileSync(path.resolve(REPO_ROOT, COMPONENTS_DOCUMENT), 'utf-8'));
  const archived = path.join(PUBLIC_DIR, 'hdf-components', `v${doc.info.version}`, 'index.json');
  assert.ok(fs.existsSync(archived), `expected the archive at ${archived}`);
  assert.deepEqual(JSON.parse(fs.readFileSync(archived, 'utf-8')), doc);
});

test('the page renders every tool the baseline measured', () => {
  const page = fs.readFileSync(path.join(PAGES_DIR, 'index.md'), 'utf-8');
  const tools = Object.keys(JSON.parse(fs.readFileSync(BASELINE, 'utf-8')).tools);
  assert.ok(tools.length > 0, 'the baseline names no tools, so this check could not fail');
  for (const tool of tools) {
    assert.ok(page.includes(tool), `the compatibility table omits ${tool}`);
  }
});

test('the page offers the document for download and embeds a renderer', () => {
  const page = fs.readFileSync(path.join(PAGES_DIR, 'index.md'), 'utf-8');
  assert.match(page, /hdf-components\.oas\.json/, 'no download link for the JSON document');
  assert.match(page, /redoc/i, 'no rendered view of the document');
});

// The docs site is a technical reference; CLAUDE.md forbids pictographic emoji.
// Monochrome check marks and arrows are typography, not emoji, and are allowed.
test('the generated page carries no emoji', () => {
  const page = fs.readFileSync(path.join(PAGES_DIR, 'index.md'), 'utf-8');
  const emoji = page.match(/\p{Extended_Pictographic}/gu) ?? [];
  assert.deepEqual(emoji, [], `generated page contains emoji: ${emoji.join(' ')}`);
});

// ADR-0008 ships two documents, and the first version of this generator carried one
// document's name as a constant — which is what made adding the second a rewrite rather
// than a row. These derive from the generator's own list so a third needs no test edit.
test('every published document is archived and rendered', () => {
  const built = DOCUMENTS.filter((d) => fs.existsSync(path.resolve(REPO_ROOT, d.json)));
  assert.ok(built.length >= 2, `expected both documents built, got ${built.length}`);

  const page = fs.readFileSync(path.join(PAGES_DIR, 'index.md'), 'utf-8');
  for (const document of built) {
    const version = JSON.parse(fs.readFileSync(path.resolve(REPO_ROOT, document.json), 'utf-8'))
      .info.version;
    const archived = path.join(PUBLIC_DIR, document.name, `v${version}`, 'index.json');
    assert.ok(fs.existsSync(archived), `expected the archive at ${archived}`);
    assert.ok(
      fs.existsSync(path.join(PUBLIC_DIR, `viewer-${document.name}.html`)),
      `${document.name} has no rendered view`,
    );
    assert.match(page, new RegExp(`## ${document.title}`), `the page has no ${document.title} section`);
  }
});

// The reference API document arrives with Phase 2, so the components document must still
// publish on its own — a required/optional distinction that only matters if it is tested.
test('an unbuilt optional document is skipped rather than failing the build', () => {
  const optional = DOCUMENTS.find((d) => d.required === false);
  assert.ok(optional, 'no optional document to exercise the skip path');
  const target = path.resolve(REPO_ROOT, optional.json);
  const stashed = `${target}.stashed`;
  fs.renameSync(target, stashed);
  try {
    fs.rmSync(PAGES_DIR, { recursive: true, force: true });
    generateOpenapiDocs();
    const page = fs.readFileSync(path.join(PAGES_DIR, 'index.md'), 'utf-8');
    assert.doesNotMatch(page, new RegExp(`## ${optional.title}`));
    assert.match(page, /## Components/);
  } finally {
    fs.renameSync(stashed, target);
    generateOpenapiDocs();
  }
});

// A required document missing is a build fault, not something to paper over.
test('an unbuilt required document fails loudly', () => {
  const required = DOCUMENTS.find((d) => d.required === true);
  const target = path.resolve(REPO_ROOT, required.json);
  const stashed = `${target}.stashed`;
  fs.renameSync(target, stashed);
  try {
    assert.throws(() => generateOpenapiDocs(), /is missing/);
  } finally {
    fs.renameSync(stashed, target);
    generateOpenapiDocs();
  }
});
