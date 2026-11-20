import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile, rm, copyFile, symlink, cp } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { checkPackage, auditWorkspace, PACKAGE_FLOOR } from '../check-side-effects.mjs';

/** Build a throwaway workspace root holding one package dir per manifest. */
async function makeWorkspace(manifests) {
  const root = await mkdtemp(join(tmpdir(), 'hdf-sidefx-'));
  for (const [dir, manifest] of Object.entries(manifests)) {
    await mkdir(join(root, dir), { recursive: true });
    await writeFile(join(root, dir, 'package.json'), JSON.stringify(manifest, null, 2));
  }
  return root;
}

test('checkPackage FLAGS a publishable package that omits sideEffects', async () => {
  const root = await makeWorkspace({ 'hdf-thing': { name: '@mitre/hdf-thing', type: 'module' } });
  try {
    const result = checkPackage(root, 'hdf-thing');
    assert.equal(result.published, true);
    assert.equal(result.declared, false);
    assert.match(result.fault, /sideEffects/);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('checkPackage PASSES a publishable package declaring sideEffects: false', async () => {
  const root = await makeWorkspace({
    'hdf-thing': { name: '@mitre/hdf-thing', type: 'module', sideEffects: false },
  });
  try {
    const result = checkPackage(root, 'hdf-thing');
    assert.equal(result.declared, true);
    assert.equal(result.fault, null);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

// An array is the correct declaration for a package that HAS module-scope effects,
// so the guard must accept it rather than demanding `false` and pushing an author
// toward a wrong `false` to get past the gate.
test('checkPackage PASSES a publishable package declaring a sideEffects array', async () => {
  const root = await makeWorkspace({
    'hdf-thing': { name: '@mitre/hdf-thing', type: 'module', sideEffects: ['./dist/polyfill.js'] },
  });
  try {
    const result = checkPackage(root, 'hdf-thing');
    assert.equal(result.declared, true);
    assert.equal(result.fault, null);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('checkPackage SKIPS a private package that omits sideEffects', async () => {
  const root = await makeWorkspace({ 'hdf-tool': { name: '@mitre/hdf-tool', private: true } });
  try {
    const result = checkPackage(root, 'hdf-tool');
    assert.equal(result.published, false);
    assert.equal(result.fault, null);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('auditWorkspace collects one fault per offending publishable package', async () => {
  const root = await makeWorkspace({
    'hdf-a': { name: '@mitre/hdf-a', type: 'module' },
    'hdf-b': { name: '@mitre/hdf-b', type: 'module', sideEffects: false },
    'hdf-c': { name: '@mitre/hdf-c', type: 'module' },
    'hdf-private': { name: '@mitre/hdf-private', private: true },
  });
  try {
    const { published, faults } = auditWorkspace(root, 0);
    assert.equal(published, 3);
    assert.equal(faults.length, 2);
    assert.ok(faults.every((f) => /hdf-[ac]\/package\.json/.test(f)));
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

// A guard that finds nothing must fail, not pass quietly — the failure mode that
// makes a gate worthless is scanning zero packages and reporting success.
test('auditWorkspace FAILS when it finds fewer packages than the floor', async () => {
  const root = await makeWorkspace({
    'hdf-a': { name: '@mitre/hdf-a', type: 'module', sideEffects: false },
  });
  try {
    const { faults } = auditWorkspace(root, 13);
    assert.ok(
      faults.some((f) => /expected at least 13/.test(f)),
      `expected a too-few-packages fault, got ${JSON.stringify(faults)}`,
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('checkPackage FLAGS a declared sideEffects of the wrong shape', async () => {
  const root = await makeWorkspace({
    'hdf-str': { name: '@mitre/hdf-str', type: 'module', sideEffects: 'false' },
    'hdf-null': { name: '@mitre/hdf-null', type: 'module', sideEffects: null },
    'hdf-mixed': { name: '@mitre/hdf-mixed', type: 'module', sideEffects: ['./a.js', 7] },
    'hdf-true': { name: '@mitre/hdf-true', type: 'module', sideEffects: true },
  });
  try {
    for (const dir of ['hdf-str', 'hdf-null', 'hdf-mixed']) {
      const result = checkPackage(root, dir);
      assert.equal(result.declared, true, `${dir} declares the key`);
      assert.match(result.fault, /must be false, true, or an array of paths/, dir);
    }
    // `true` is a legitimate bundler value: everything in the package has effects.
    assert.equal(checkPackage(root, 'hdf-true').fault, null);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('checkPackage reports a non-package directory without counting it', async () => {
  const root = await makeWorkspace({ 'hdf-real': { name: '@mitre/hdf-real', sideEffects: false } });
  await mkdir(join(root, 'not-a-package'), { recursive: true });
  try {
    const result = checkPackage(root, 'not-a-package');
    assert.equal(result.isPackage, false);
    assert.equal(result.fault, null);
    assert.equal(auditWorkspace(root, 0).published, 1);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

/**
 * Seed a workspace that clears PACKAGE_FLOOR, with `offenders` of them missing
 * the field, and drop a copy of the guard at <ws>/scripts/ so its ROOT resolves
 * to the seeded workspace rather than this repo.
 */
async function seedRunnableWorkspace(offenders) {
  const ws = await mkdtemp(join(tmpdir(), 'hdf-sidefx-cli-'));
  for (let i = 0; i < PACKAGE_FLOOR; i += 1) {
    const manifest = { name: `@mitre/pkg${i}`, type: 'module', files: ['dist'] };
    if (i >= offenders) manifest.sideEffects = false;
    await mkdir(join(ws, `pkg${i}`), { recursive: true });
    await writeFile(join(ws, `pkg${i}`, 'package.json'), JSON.stringify(manifest, null, 2));
  }
  await mkdir(join(ws, 'scripts'), { recursive: true });
  await copyFile(
    fileURLToPath(new URL('../check-side-effects.mjs', import.meta.url)),
    join(ws, 'scripts', 'check-side-effects.mjs'),
  );
  return ws;
}

function runGuard(scriptPath) {
  const proc = spawnSync(process.execPath, [scriptPath], { encoding: 'utf-8' });
  return { code: proc.status, stdout: proc.stdout, stderr: proc.stderr };
}

test('run as a script: EXITS 1 and names the offender', async () => {
  const ws = await seedRunnableWorkspace(1);
  try {
    const { code, stderr } = runGuard(join(ws, 'scripts', 'check-side-effects.mjs'));
    assert.equal(code, 1);
    assert.match(stderr, /pkg0\/package\.json declares no "sideEffects"/);
  } finally {
    await rm(ws, { recursive: true, force: true });
  }
});

test('run as a script: EXITS 0 when every publishable package declares it', async () => {
  const ws = await seedRunnableWorkspace(0);
  try {
    const { code, stdout } = runGuard(join(ws, 'scripts', 'check-side-effects.mjs'));
    assert.equal(code, 0);
    assert.match(stdout, new RegExp(`${PACKAGE_FLOOR} publishable packages`));
  } finally {
    await rm(ws, { recursive: true, force: true });
  }
});

// The main-entry check compares import.meta.url, which Node resolves to a
// realpath-based, percent-encoded URL. Comparing it to a raw argv[1] string made
// the guard exit 0 having scanned nothing whenever the path was reached through a
// symlink or contained a space — a gate that cannot fail is not a gate.
test('run as a script: still fails through a symlinked path', async () => {
  const ws = await seedRunnableWorkspace(1);
  const linkDir = await mkdtemp(join(tmpdir(), 'hdf-sidefx-link-'));
  const link = join(linkDir, 'linked');
  try {
    await symlink(ws, link, 'dir');
    const { code, stderr } = runGuard(join(link, 'scripts', 'check-side-effects.mjs'));
    assert.equal(code, 1, `expected failure through the symlink, got ${code}`);
    assert.match(stderr, /declares no "sideEffects"/);
  } finally {
    await rm(linkDir, { recursive: true, force: true });
    await rm(ws, { recursive: true, force: true });
  }
});

test('run as a script: still fails from a path containing a space', async () => {
  const parent = await mkdtemp(join(tmpdir(), 'hdf-sidefx-sp-'));
  const ws = join(parent, 'sp ace');
  try {
    const seeded = await seedRunnableWorkspace(1);
    await cp(seeded, ws, { recursive: true });
    await rm(seeded, { recursive: true, force: true });
    const { code, stderr } = runGuard(join(ws, 'scripts', 'check-side-effects.mjs'));
    assert.equal(code, 1, `expected failure from a spaced path, got ${code}`);
    assert.match(stderr, /declares no "sideEffects"/);
  } finally {
    await rm(parent, { recursive: true, force: true });
  }
});

// The suite seeds PACKAGE_FLOOR packages, so it stays self-consistent with any
// floor value and pins none. A downward typo would pass both the suite and the
// live run; this is the one assertion that keeps the floor near the real count.
test('PACKAGE_FLOOR stays within one of the real publishable count', () => {
  assert.ok(
    PACKAGE_FLOOR >= 11,
    `PACKAGE_FLOOR is ${PACKAGE_FLOOR}; a floor far below the real publishable ` +
      'count lets the guard pass having scanned almost nothing',
  );
});
