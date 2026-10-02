import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  packageNameFromSpecifier,
  checkPackage,
} from '../check-published-deps.mjs';

/** Build a throwaway package dir with a package.json and dist files. */
async function makePackage(pkgJson, distFiles) {
  const dir = await mkdtemp(join(tmpdir(), 'hdf-guard-'));
  await writeFile(join(dir, 'package.json'), JSON.stringify(pkgJson, null, 2));
  await mkdir(join(dir, 'dist'), { recursive: true });
  for (const [rel, source] of Object.entries(distFiles)) {
    const full = join(dir, 'dist', rel);
    await mkdir(join(full, '..'), { recursive: true });
    await writeFile(full, source);
  }
  return dir;
}

test('packageNameFromSpecifier reduces sub-path specifiers to the package name', () => {
  assert.equal(packageNameFromSpecifier('ajv'), 'ajv');
  assert.equal(packageNameFromSpecifier('ajv/dist/2020.js'), 'ajv');
  assert.equal(packageNameFromSpecifier('@scope/name'), '@scope/name');
  assert.equal(packageNameFromSpecifier('@scope/name/sub/deep.js'), '@scope/name');
});

test('checkPackage FLAGS a dist import of an undeclared module', async () => {
  const dir = await makePackage(
    { name: '@mitre/hdf-synthetic', type: 'module', dependencies: {} },
    { 'index.js': "import x from 'undeclared-pkg';\nexport default x;\n" },
  );
  try {
    const result = await checkPackage(dir);
    const names = result.offenders.map((o) => o.packageName);
    assert.ok(
      names.includes('undeclared-pkg'),
      `expected undeclared-pkg to be flagged, got ${JSON.stringify(names)}`,
    );
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('checkPackage PASSES when every dist import is declared, a builtin, self, or relative', async () => {
  const dir = await makePackage(
    {
      name: '@mitre/hdf-synthetic',
      type: 'module',
      dependencies: { ajv: '^8.17.1' },
      peerDependencies: { 'peer-pkg': '^1' },
      optionalDependencies: { 'opt-pkg': '^1' },
    },
    {
      'index.js':
        "import { readFileSync } from 'node:fs';\n" +
        "import path from 'path';\n" +
        "import Ajv from 'ajv';\n" +
        "import formats from 'ajv-formats/dist/2020.js';\n" + // sub-path of... see below
        "import peer from 'peer-pkg';\n" +
        "import opt from 'opt-pkg';\n" +
        "import self from '@mitre/hdf-synthetic/other';\n" +
        "import rel from './util.js';\n" +
        "export { readFileSync, path, Ajv, formats, peer, opt, self, rel };\n",
    },
  );
  try {
    const result = await checkPackage(dir);
    // ajv-formats is NOT declared here, so it MUST be flagged — proves sub-path
    // reduction plus the declared-set check are both live.
    const names = result.offenders.map((o) => o.packageName);
    assert.deepEqual(names, ['ajv-formats'], `unexpected offenders: ${JSON.stringify(names)}`);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('checkPackage PASSES cleanly when nothing external is undeclared', async () => {
  const dir = await makePackage(
    { name: '@mitre/hdf-synthetic', type: 'module', dependencies: { ajv: '^8.17.1' } },
    {
      'index.js':
        "import { readFileSync } from 'node:fs';\n" +
        "import Ajv from 'ajv';\n" +
        "import Ajv2020 from 'ajv/dist/2020.js';\n" +
        "const dyn = await import('ajv');\n" +
        "export { readFileSync, Ajv, Ajv2020, dyn };\n",
    },
  );
  try {
    const result = await checkPackage(dir);
    assert.equal(result.offenders.length, 0, `unexpected offenders: ${JSON.stringify(result.offenders)}`);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('checkPackage detects re-export (export ... from) specifiers', async () => {
  const dir = await makePackage(
    { name: '@mitre/hdf-synthetic', type: 'module', dependencies: {} },
    { 'index.js': "export { thing } from 'reexported-undeclared';\n" },
  );
  try {
    const result = await checkPackage(dir);
    const names = result.offenders.map((o) => o.packageName);
    assert.ok(names.includes('reexported-undeclared'), `got ${JSON.stringify(names)}`);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
