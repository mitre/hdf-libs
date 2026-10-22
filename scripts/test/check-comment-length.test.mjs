import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';

import { scanTypeScript, scanGo, thresholds } from '../check-comment-length.mjs';

const ROOT = fileURLToPath(new URL('../../', import.meta.url));
const CORPUS = join(ROOT, 'scripts', 'comment-length', 'testdata');

const corpus = JSON.parse(await readFile(join(CORPUS, 'cases.json'), 'utf8'));

/** The kinds a scan reported, deduped and sorted, so order never matters. */
const kinds = (violations) => [...new Set(violations.map((v) => v.kind))].sort();

/** Every violation as kind:count, sorted — so three `line` never equals one. */
const detail = (violations) => violations.map((v) => `${v.kind}:${v.count}`).sort();

test('the corpus is not empty — a vacuous pass is not a pass', () => {
  assert.ok(corpus.cases.length >= 8, `only ${corpus.cases.length} cases`);
  assert.ok(corpus.cases.some((c) => c.expect.length > 0), 'no case expects a violation');
});

test('thresholds come from the shared config, not from the checker', () => {
  assert.deepEqual(thresholds(), { doc: 10, inline: 5, line: 90 });
});

for (const c of corpus.cases) {
  test(`TypeScript: ${c.name}`, async () => {
    const found = await scanTypeScript([join(CORPUS, c.ts)]);
    assert.deepEqual(kinds(found), [...c.expect].sort());
  });

  test(`Go: ${c.name}`, async () => {
    const found = await scanGo([join(CORPUS, c.go)]);
    assert.deepEqual(kinds(found), [...c.expect].sort());
  });

  test(`both languages agree: ${c.name}`, async () => {
    const ts = kinds(await scanTypeScript([join(CORPUS, c.ts)]));
    const go = kinds(await scanGo([join(CORPUS, c.go)]));
    assert.deepEqual(ts, go, `TS reported ${ts} and Go reported ${go}`);
  });

  test(`both languages agree on COUNT too: ${c.name}`, async () => {
    const ts = detail(await scanTypeScript([join(CORPUS, c.ts)]));
    const go = detail(await scanGo([join(CORPUS, c.go)]));
    assert.deepEqual(ts, go, `TS reported ${ts} and Go reported ${go}`);
  });
}

// ── the ratchet, the allowlist and what gets scanned ────────────────────────
import { judge, isGenerated, sourceFiles } from '../check-comment-length.mjs';

const v = (file, kind = 'doc') => ({ file, line: 1, kind, count: 99 });

test('ratchet: a file at its recorded baseline passes', () => {
  const { problems } = judge([v('a.ts'), v('a.ts')], { 'a.ts': 2 }, []);
  assert.deepEqual(problems, []);
});

test('ratchet: a file ABOVE its recorded baseline fails, and says both numbers', () => {
  const { problems } = judge([v('a.ts'), v('a.ts'), v('a.ts')], { 'a.ts': 2 }, []);
  assert.equal(problems.length, 1);
  assert.match(problems[0].message, /3/);
  assert.match(problems[0].message, /2/);
});

test('ratchet: a file BELOW its baseline passes, and is reported as tightenable', () => {
  const { problems, tightened } = judge([v('a.ts')], { 'a.ts': 2 }, []);
  assert.deepEqual(problems, []);
  assert.deepEqual(tightened, [{ file: 'a.ts', was: 2, now: 1 }]);
});

test('ratchet: a file ABSENT from the baseline fails on any violation', () => {
  const { problems } = judge([v('new.ts')], {}, []);
  assert.equal(problems.length, 1);
  assert.match(problems[0].message, /not in the baseline/i);
});

test('a clean file absent from the baseline is fine', () => {
  assert.deepEqual(judge([], {}, []).problems, []);
});

test('allowlist: an entry exempts a file', () => {
  const { problems } = judge([v('a.ts')], {}, [{ file: 'a.ts', reason: 'vendored table' }]);
  assert.deepEqual(problems, []);
});

test('allowlist: an entry WITHOUT a reason is itself a failure', () => {
  const { problems } = judge([], {}, [{ file: 'a.ts' }]);
  assert.equal(problems.length, 1);
  assert.match(problems[0].message, /reason/i);
});

test('allowlist: a blank reason does not count as a reason', () => {
  const { problems } = judge([], {}, [{ file: 'a.ts', reason: '   ' }]);
  assert.equal(problems.length, 1);
});

test('generated files are detected by their own header', async () => {
  const real = join(ROOT, 'hdf-converters', 'converters', 'oscal-to-hdf', 'typescript', 'types.ts');
  assert.equal(isGenerated(await readFile(real, 'utf8')), true, 'the real quicktype file must be detected');
  assert.equal(isGenerated('// a normal file\nexport const x = 1;\n'), false);
});

test('the scanned set excludes generated, vendored and build output', async () => {
  const files = await sourceFiles();
  assert.ok(files.length > 500, `only ${files.length} files found`);
  for (const bad of ['node_modules', '/dist/', '/coverage/', '/testdata/', '.d.ts']) {
    assert.ok(!files.some((f) => f.includes(bad)), `${bad} leaked into the scanned set`);
  }
  assert.ok(files.some((f) => f.endsWith('.go')), 'no Go files');
  assert.ok(files.some((f) => f.endsWith('.ts')), 'no TypeScript files');
});

import { repoRelative, scanAll } from '../check-comment-length.mjs';

test("repoRelative strips the checkout, so a baseline carries nobody's home directory", () => {
  assert.equal(repoRelative(join(ROOT, 'hdf-cli', 'x.go')), 'hdf-cli/x.go');
  assert.equal(repoRelative('hdf-cli/x.go'), 'hdf-cli/x.go');
});

test('the recorded baseline is keyed repo-relative — an absolute key is not portable', async () => {
  const baseline = JSON.parse(await readFile(join(ROOT, 'scripts', 'comment-length-baseline.json'), 'utf8'));
  const keys = Object.keys(baseline);
  assert.ok(keys.length > 0, 'baseline is empty');
  for (const k of keys) {
    assert.ok(!k.startsWith('/') && !k.startsWith('Users/') && !k.includes(':\\'), `absolute baseline key: ${k}`);
  }
});

test('every violation scanAll reports is keyed the same way the baseline is', async () => {
  const violations = await scanAll();
  assert.ok(violations.length > 0, 'nothing scanned');
  for (const v of violations.slice(0, 50)) {
    assert.equal(v.file, repoRelative(v.file), `not normalized: ${v.file}`);
  }
});

// CRLF lives here rather than in the corpus: a checked-in CRLF fixture is at the
// mercy of git's line-ending normalization, so a row could silently become LF.
import { commentGroups } from '../check-comment-length.mjs';

test('a carriage return is not charged against the width cap', async () => {
  const { mkdtemp, writeFile: wf } = await import('node:fs/promises');
  const { tmpdir } = await import('node:os');
  const dir = await mkdtemp(join(tmpdir(), 'cl-crlf-'));
  const at90 = 'x'.repeat(90);
  // A block comment: for `//` the scanner already excludes the CR, so only this
  // shape proves the strip is doing work.
  const file = join(dir, 'crlf.ts');
  await wf(file, `/*\r\n${at90}\r\n*/\r\nexport function a() {}\r\n`);
  const found = await scanTypeScript([file]);
  assert.deepEqual(found.filter((v) => v.kind === 'line'), [], `CR counted: ${JSON.stringify(found)}`);

  // and one character more must still be caught, so the test is not passing vacuously
  const over = join(dir, 'crlf-over.ts');
  await wf(over, `/*\r\n${at90}y\r\n*/\r\nexport function a() {}\r\n`);
  assert.equal((await scanTypeScript([over])).filter((v) => v.kind === 'line').length, 1);
});

test('the Go checker refuses to run without a config — the numbers have one source', async () => {
  const { execFile } = await import('node:child_process');
  const { promisify } = await import('node:util');
  const { mkdtemp } = await import('node:fs/promises');
  const { tmpdir } = await import('node:os');
  const run2 = promisify(execFile);
  const dir = await mkdtemp(join(tmpdir(), 'cl-cfg-'));
  const bin = join(dir, 'cl');
  await run2('go', ['build', '-o', bin, join(ROOT, 'scripts', 'comment-length', 'main.go')], { cwd: ROOT });
  await assert.rejects(
    () => run2(bin, [join(CORPUS, 'go', 'clean.go')], { cwd: ROOT }),
    (e) => /-config is required/.test(String(e.stderr)),
  );
});

test('a Go overview BELOW the package clause is not a doc comment — godoc would not show it either', async () => {
  const { mkdtemp, writeFile: wf } = await import('node:fs/promises');
  const { tmpdir } = await import('node:os');
  const dir = await mkdtemp(join(tmpdir(), 'cl-pos-'));
  const six = Array.from({ length: 6 }, (_, i) => `// l${i + 1}`).join('\n');

  const below = join(dir, 'below.go');
  await wf(below, `package td\n\nimport "fmt"\n\n${six}\n\nvar _ = fmt.Sprint\n`);
  assert.deepEqual((await scanGo([below])).map((v) => v.kind), ['inline'], 'below the package clause is not doc');

  const above = join(dir, 'above.go');
  await wf(above, `${six}\npackage td\n`);
  assert.deepEqual((await scanGo([above])).map((v) => v.kind), [], 'above the package clause is doc, so 6 lines is fine');
});

test('the Go corpus is gofmt-clean, so a tree-wide gofmt cannot silently alter a fixture', async () => {
  const { execFile } = await import('node:child_process');
  const { promisify } = await import('node:util');
  const { stdout } = await promisify(execFile)('gofmt', ['-l', join(CORPUS, 'go')], { cwd: ROOT });
  assert.equal(stdout.trim(), '', `gofmt would rewrite: ${stdout.trim()}`);
});

test('allowlist: an entry naming a path nothing scans is a failure, not a silent no-op', () => {
  const scanned = ['a.ts', 'b.go'];
  const ok = judge([], {}, [{ file: 'a.ts', reason: 'why' }], scanned);
  assert.deepEqual(ok.problems, []);

  const typo = judge([], {}, [{ file: 'nope/typo.ts', reason: 'why' }], scanned);
  assert.equal(typo.problems.length, 1);
  assert.match(typo.problems[0].message, /matches no scanned file/);
});

test('allowlist: a stale path is still caught when the entry also lacks a reason', () => {
  const { problems } = judge([], {}, [{ file: 'nope/typo.ts' }], ['a.ts']);
  assert.equal(problems.length, 1);
  assert.match(problems[0].message, /reason/i);
});

test('a comment ending on the SAME line as a declaration is not its doc, in both languages', async () => {
  // Not a corpus row: gofmt will not preserve a multi-line block comment ending on
  // a declaration's line, so a checked-in Go fixture cannot hold the shape.
  const { mkdtemp, writeFile: wf } = await import('node:fs/promises');
  const { tmpdir } = await import('node:os');
  const dir = await mkdtemp(join(tmpdir(), 'cl-same-'));
  const eleven = Array.from({ length: 11 }, (_, i) => `l${i + 1}`).join('\n');

  const tsFile = join(dir, 'same.ts');
  await wf(tsFile, `export const z = 0;\n\n/* ${eleven} */ export const X = 1;\n`);
  const goFile = join(dir, 'same.go');
  await wf(goFile, `package td\n\nvar Z = 0\n\n/* ${eleven} */ var X = 1\n`);

  const tsKinds = (await scanTypeScript([tsFile])).map((v) => `${v.kind}:${v.count}`);
  const goKinds = (await scanGo([goFile])).map((v) => `${v.kind}:${v.count}`);
  assert.deepEqual(tsKinds, ['inline:11'], 'same line is not a doc comment');
  assert.deepEqual(goKinds, tsKinds, `go ${goKinds} vs ts ${tsKinds}`);

  // and the line ABOVE still is, in both — so this is not passing by accident
  const tsAbove = join(dir, 'above.ts');
  await wf(tsAbove, `export const z = 0;\n\n/* ${eleven} */\nexport const X = 1;\n`);
  const goAbove = join(dir, 'above.go');
  await wf(goAbove, `package td\n\nvar Z = 0\n\n/* ${eleven} */\nvar X = 1\n`);
  assert.deepEqual((await scanTypeScript([tsAbove])).map((v) => `${v.kind}:${v.count}`), ['doc:11']);
  assert.deepEqual((await scanGo([goAbove])).map((v) => `${v.kind}:${v.count}`), ['doc:11']);
});
