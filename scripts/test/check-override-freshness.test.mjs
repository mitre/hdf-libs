import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, writeFile, mkdir, cp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';

import { parseOverrides, checkOverrides } from '../check-override-freshness.mjs';

const ROOT = join(fileURLToPath(new URL('../../', import.meta.url)));
const WORKSPACE = join(ROOT, 'pnpm-workspace.yaml');
const SCRIPT = join(ROOT, 'scripts', 'check-override-freshness.mjs');
const run = promisify(execFile);

/** Minimal workspace file carrying just an overrides block. */
function workspace(block, trailing = 'auditConfig:\n  ignoreGhsas: []\n') {
  return `packages:\n  - 'hdf-*'\nminimumReleaseAge: 10080\noverrides:\n${block}${trailing}`;
}

const check = (text) => checkOverrides(parseOverrides(text));

test('parseOverrides reads package, vulnerable range and target', () => {
  const { entries } = parseOverrides(workspace('  # why\n  "esbuild@<0.25.0": "^0.25.0"\n'));
  assert.equal(entries.length, 1);
  assert.deepEqual(
    { pkg: entries[0].pkg, range: entries[0].range, target: entries[0].target, comment: entries[0].comment },
    { pkg: 'esbuild', range: '<0.25.0', target: '^0.25.0', comment: 'why' },
  );
});

test('a scoped package splits on the LAST @, not the leading one', () => {
  const { entries } = parseOverrides(workspace('  # why\n  "@babel/core@<7.29.1": "^7.29.7"\n'));
  assert.equal(entries[0].pkg, '@babel/core');
  assert.equal(entries[0].range, '<7.29.1');
});

test('an exact-version target is FLAGGED — it becomes the vulnerable floor when the advisory moves', () => {
  const { offenders } = check(workspace('  # why\n  "fast-uri@<3.1.6": "3.1.6"\n'));
  assert.equal(offenders.length, 1);
  assert.equal(offenders[0].pkg, 'fast-uri');
  assert.match(offenders[0].reason, /exact/i);
});

test('a range target PASSES', () => {
  assert.deepEqual(check(workspace('  # why\n  "fast-uri@<3.1.6": "^3.1.7"\n')).offenders, []);
});

test('tilde and comparator targets also pass', () => {
  for (const target of ['~3.1.7', '>=3.1.7', '>=3.1.7 <4.0.0']) {
    assert.deepEqual(
      check(workspace(`  # why\n  "fast-uri@<3.1.6": "${target}"\n`)).offenders,
      [],
      `${target} is a range and must pass`,
    );
  }
});

test('an undocumented entry is FLAGGED — a pin nobody can tell is load-bearing is worse than none', () => {
  const { offenders } = check(workspace('  "qs@<6.16.0": "^6.16.0"\n'));
  assert.equal(offenders.length, 1);
  assert.match(offenders[0].reason, /comment/i);
});

test('one entry can be flagged for both reasons at once', () => {
  const { offenders } = check(workspace('  "qs@<6.16.0": "6.16.0"\n'));
  assert.equal(offenders.length, 1);
  assert.match(offenders[0].reason, /exact/i);
  assert.match(offenders[0].reason, /comment/i);
});

test('a comment above a preceding entry does not count as documenting the next one', () => {
  const { offenders } = check(
    workspace('  # documents the first\n  "qs@<6.16.0": "^6.16.0"\n  "yaml@<2.8.3": "^2.8.3"\n'),
  );
  assert.equal(offenders.length, 1);
  assert.equal(offenders[0].pkg, 'yaml');
});

test('a blank line breaks the comment-to-entry association', () => {
  const { offenders } = check(workspace('  # orphaned by the blank line\n\n  "qs@<6.16.0": "^6.16.0"\n'));
  assert.equal(offenders.length, 1);
  assert.match(offenders[0].reason, /comment/i);
});

// The spellings below are all YAML-legal. A line-based reader that skips what it
// does not recognise reports a file full of exact pins as clean, so each one must
// be READ (and judged) rather than ignored.
test('an exact pin is caught however the YAML is spelled', () => {
  const spellings = {
    'single-quoted key and value': `  # why\n  '@babel/core@<7.29.1': '7.29.7'\n`,
    'unquoted key and value': '  # why\n  fast-uri@<3.1.6: 3.1.6\n',
    'four-space indent': '    # why\n    "qs@<6.16.0": "6.16.0"\n',
    'trailing inline comment': '  # why\n  "qs@<6.16.0": "6.16.0" # oops\n',
    'extra spacing around the colon': '  # why\n  "qs@<6.16.0"   :   "6.16.0"\n',
  };
  for (const [name, block] of Object.entries(spellings)) {
    const { entries } = parseOverrides(workspace(block));
    assert.equal(entries.length, 1, `${name}: the entry must be read, not skipped`);
    const { offenders } = checkOverrides(parseOverrides(workspace(block)));
    assert.equal(offenders.length, 1, `${name}: the exact pin must be flagged`);
    assert.match(offenders[0].reason, /exact/i, name);
  }
});

test('a line inside the block that cannot be read at all is FLAGGED, not skipped', () => {
  const { offenders } = check(workspace('  # why\n  this is not a mapping at all\n'));
  assert.equal(offenders.length, 1);
  assert.match(offenders[0].reason, /cannot be read/i);
});

test('a key with no @ separator is FLAGGED rather than parsed into nonsense', () => {
  const { offenders } = check(workspace('  # why\n  "justapackage": "^1.0.0"\n'));
  assert.equal(offenders.length, 1);
  assert.match(offenders[0].reason, /cannot be read/i);
});

// The block boundary is load-bearing: `patchedDependencies` entries are mapping
// lines whose values are file paths, so a reader that runs past the end of
// `overrides:` would report them as exact-version pins.
test('parsing stops at the end of the overrides block', () => {
  const trailing = 'patchedDependencies:\n  "left-pad@1.3.0": "patches/left-pad.patch"\n';
  const { entries, unparsed } = parseOverrides(workspace('  # why\n  "qs@<6.16.0": "^6.16.0"\n', trailing));
  assert.equal(entries.length, 1, 'only the overrides entry is read');
  assert.equal(entries[0].pkg, 'qs');
  assert.deepEqual(unparsed, [], 'the patchedDependencies line is outside the block, not an unreadable line');
});

test('a file with no overrides block yields nothing rather than throwing', () => {
  const { entries, unparsed } = parseOverrides("packages:\n  - 'hdf-*'\n");
  assert.deepEqual(entries, []);
  assert.deepEqual(unparsed, []);
});

test("the repository's own overrides block satisfies the guard", async () => {
  const { offenders } = check(await readFile(WORKSPACE, 'utf8'));
  assert.deepEqual(
    offenders.map((o) => `${o.pkg}: ${o.reason}`),
    [],
    'pnpm-workspace.yaml must pass the guard it ships with',
  );
});

// The executable path is what the gate actually depends on: a non-zero exit and
// a message naming the file, line and package.
test('run against the repository, the script exits 0 and reports the count', async () => {
  const { stdout } = await run(process.execPath, [SCRIPT]);
  assert.match(stdout, /pnpm-workspace\.yaml: \d+ overrides, all range-targeted and documented/);
});

test('run against a workspace carrying an exact pin, the script exits 1 and names it', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'hdf-override-guard-'));
  try {
    await mkdir(join(dir, 'scripts'), { recursive: true });
    await cp(SCRIPT, join(dir, 'scripts', 'check-override-freshness.mjs'));
    await writeFile(join(dir, 'pnpm-workspace.yaml'), workspace('  # why\n  "fast-uri@<3.1.6": "3.1.6"\n'));
    await assert.rejects(
      () => run(process.execPath, [join(dir, 'scripts', 'check-override-freshness.mjs')]),
      (err) => {
        assert.equal(err.code, 1, 'a stale pin must fail the gate');
        assert.match(err.stderr, /pnpm-workspace\.yaml:6\s+fast-uri@<3\.1\.6/);
        assert.match(err.stderr, /is an exact version/);
        assert.match(err.stderr, /developer-guide\.md/);
        return true;
      },
    );
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
