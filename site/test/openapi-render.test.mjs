import test, { after } from 'node:test';
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
const BASELINE = path.resolve(REPO_ROOT, 'hdf-openapi-components/test/baseline/keywords.json');

// A version directory this build never writes, standing in for a released
// version's frozen archive. Planted at module scope so the suite's own setup
// runs against it, and not read from whatever archives exist, so it cannot go
// vacuous when the oldest one is removed.
const PROBE = path.join(PUBLIC_DIR, 'hdf-components', 'v0.0.0-frozen-archive-probe');
fs.mkdirSync(PROBE, { recursive: true });
fs.writeFileSync(path.join(PROBE, 'index.json'), '{}');
after(() => fs.rmSync(PROBE, { recursive: true, force: true }));

// The generator reads a BUILD ARTIFACT. Generate it here rather than trusting
// whatever a previous local run left behind: without this the suite fails in CI,
// where nothing has built yet, and passes locally for the wrong reason.
/** Every path the generator writes, derived from the documents it will read. */
function rewrittenByThisRun() {
  const targets = [];
  for (const document of DOCUMENTS) {
    const built = path.resolve(REPO_ROOT, document.json);
    if (!fs.existsSync(built)) continue;
    const { version } = JSON.parse(fs.readFileSync(built, 'utf-8')).info;
    targets.push(
      path.join(PUBLIC_DIR, `${document.name}.oas.json`),
      path.join(PUBLIC_DIR, `${document.name}.oas.yaml`),
      path.join(PUBLIC_DIR, `viewer-${document.name}.html`),
      path.join(PUBLIC_DIR, document.name, `v${version}`),
    );
  }
  return targets;
}

test('generate the openapi pages and archive', () => {
  const built = path.resolve(REPO_ROOT, COMPONENTS_DOCUMENT);
  if (!fs.existsSync(built)) {
    execFileSync('pnpm', ['run', 'build:components'], {
      cwd: path.resolve(REPO_ROOT, 'hdf-openapi-components'),
      stdio: 'inherit',
    });
  }
  // Output left by an earlier run would otherwise stand in for output this run
  // failed to produce, so remove it first — but only what this run rewrites.
  // PUBLIC_DIR also holds the tracked archives of past releases, which this
  // build cannot reproduce, so wiping the tree deleted them for good.
  fs.rmSync(PAGES_DIR, { recursive: true, force: true });
  for (const target of rewrittenByThisRun()) {
    fs.rmSync(target, { recursive: true, force: true });
  }
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

test('the suite leaves a frozen archive it cannot reproduce in place', () => {
  assert.ok(
    fs.existsSync(path.join(PROBE, 'index.json')),
    `the suite removed ${path.relative(REPO_ROOT, PROBE)}, a tracked archive of a past release`,
  );
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

// The generator's first version carried one document's name as a constant, which is what
// made adding a second a rewrite rather than a row. These still derive from its list, so a
// second document returning needs no test edit — the reference API left for the sibling
// repository, and the components document is what remains.
test('every published document is archived and rendered', () => {
  const built = DOCUMENTS.filter((d) => fs.existsSync(path.resolve(REPO_ROOT, d.json)));
  assert.ok(built.length >= 1, `expected the components document built, got ${built.length}`);

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
