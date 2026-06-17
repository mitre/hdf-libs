#!/usr/bin/env node
/**
 * Seed the per-version raw schema archive at site/public/schemas/<name>/<version>/.
 *
 * For each historical release, extracts the bundled schemas as they shipped
 * (or bundles from source if dist was not committed at that tag) and writes
 * them under the archive path keyed by the $id URL the schema declares.
 *
 * Archive key invariant: the path /schemas/<name>/v<X>.<Y>.<Z>/ MUST match
 * what the schema's own $id field claims. Consumer documents reference the
 * $id URL; the archive serves whatever shipped under that URL.
 *
 * Historical note: the v3.0.0 release shipped schemas declaring $id=v2.0.0
 * (release-process bug — package.json bumped, schema $id URLs forgotten).
 * v3.0.1 was the URL-cleanup release that finished the bump. So the archive
 * is keyed by the $id, NOT the git tag: the v2.0.0 archive entry comes from
 * v2.0.0 (or equivalently v3.0.0; same content), and the v3.0.0 archive
 * entry comes from v3.0.1.
 *
 * Idempotent: existing archive entries are not overwritten. Re-run safely.
 *
 * Run: node site/seed-archive.mjs
 */

import { execSync, spawnSync } from 'node:child_process';
import { readFileSync, writeFileSync, mkdirSync, existsSync, readdirSync, rmSync, cpSync } from 'node:fs';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { tmpdir } from 'node:os';

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(__dirname, '..');
const ARCHIVE_ROOT = join(__dirname, 'public', 'schemas');

const MAIN_SCHEMAS = [
  'hdf-results.schema.json',
  'hdf-baseline.schema.json',
  'hdf-comparison.schema.json',
  'hdf-system.schema.json',
  'hdf-plan.schema.json',
  'hdf-amendments.schema.json',
  'hdf-evidence-package.schema.json',
];

/**
 * Releases to seed. Each entry names a git tag and which path within
 * that tag's tree carries usable (bundled) schemas.
 *
 * - 'dist': the tag committed bundled schemas at hdf-schema/dist/schemas/
 *   (true for v2.0.0, v3.0.0, v3.0.1). git show + write directly.
 * - 'src': the tag committed source schemas at hdf-schema/src/schemas/
 *   but NOT bundled dist (true for v3.1.0 onward). We extract src into
 *   a temp dir and invoke the bundle-schemas.ts script with env vars to
 *   override its input/output paths.
 *
 * For the current branch (v3.3.0+), seedCurrent() pulls from the
 * already-built hdf-schema/dist/schemas/.
 */
const HISTORICAL_RELEASES = [
  { tag: 'v2.0.0', source: 'dist' },
  // v3.0.0 schemas are byte-identical to v2.0.0 (release-bug: only
  // package.json bumped). Don't double-archive.
  // v3.0.1 schemas declare $id=v3.0.0 — they're the canonical v3.0.0
  // archive entry.
  { tag: 'v3.0.1', source: 'dist' },
  { tag: 'v3.1.0', source: 'src' },
  { tag: 'v3.2.0', source: 'src' },
];

/**
 * Extract a single file from a git tag. Returns the file contents as a string.
 */
function gitShow(tag, path) {
  return execSync(`git show ${tag}:${path}`, {
    cwd: REPO_ROOT,
    encoding: 'utf-8',
    maxBuffer: 10 * 1024 * 1024,
  });
}

/**
 * List files in a git tag's tree under a path.
 */
function gitLsTree(tag, path) {
  const out = execSync(`git ls-tree -r --name-only ${tag} ${path}`, {
    cwd: REPO_ROOT,
    encoding: 'utf-8',
  });
  return out.split('\n').filter(Boolean);
}

/**
 * Read the $id from a JSON Schema blob and extract the trailing version
 * segment (e.g. 'v3.2.0' from '.../hdf-amendments/v3.2.0').
 */
function extractVersionFromId(schemaJson) {
  const $id = schemaJson.$id;
  if (!$id) throw new Error('schema has no $id');
  const match = $id.match(/\/v\d+\.\d+\.\d+$/);
  if (!match) throw new Error(`schema $id does not end in /vX.Y.Z: ${$id}`);
  return match[0].slice(1); // drop the leading '/'
}

/**
 * Write a bundled schema to the archive under the version its $id declares.
 * Skips if the destination already exists (idempotent).
 */
function writeToArchive(bundledJson, schemaFile) {
  const name = schemaFile.replace(/\.schema\.json$/, '');
  const version = extractVersionFromId(bundledJson);
  const dir = join(ARCHIVE_ROOT, name, version);
  const dest = join(dir, 'index.json');

  if (existsSync(dest)) {
    console.log(`  = ${name}/${version}/index.json (exists; skipping)`);
    return;
  }

  mkdirSync(dir, { recursive: true });
  writeFileSync(dest, JSON.stringify(bundledJson, null, 2) + '\n');
  console.log(`  + ${name}/${version}/index.json`);
}

/**
 * Seed from a 'dist' release: bundled schemas exist at the tag.
 */
function seedFromDist(tag) {
  console.log(`Seeding from ${tag} (bundled schemas committed at tag)...`);
  for (const schemaFile of MAIN_SCHEMAS) {
    const tagPath = `hdf-schema/dist/schemas/${schemaFile}`;
    let raw;
    try {
      raw = gitShow(tag, tagPath);
    } catch (err) {
      console.warn(`  ! ${schemaFile} not found at ${tag}: ${err.message.split('\n')[0]}`);
      continue;
    }
    const json = JSON.parse(raw);
    writeToArchive(json, schemaFile);
  }
}

/**
 * Seed from a 'src' release: bundled schemas were not committed; bundle from
 * source by extracting into a temp dir and invoking bundle-schemas.ts with
 * env overrides.
 */
function seedFromSrc(tag) {
  console.log(`Seeding from ${tag} (bundling from source)...`);

  const stage = join(tmpdir(), `hdf-seed-${tag.replace(/\W/g, '_')}`);
  const srcStage = join(stage, 'src', 'schemas');
  const distStage = join(stage, 'dist', 'schemas');
  mkdirSync(join(srcStage, 'primitives'), { recursive: true });
  mkdirSync(distStage, { recursive: true });

  // Extract all schema source files from the tag into the temp staging dir.
  const sourceFiles = gitLsTree(tag, 'hdf-schema/src/schemas/').filter((p) => p.endsWith('.schema.json'));
  for (const path of sourceFiles) {
    const relative = path.replace('hdf-schema/src/schemas/', '');
    const dest = join(srcStage, relative);
    mkdirSync(dirname(dest), { recursive: true });
    writeFileSync(dest, gitShow(tag, path));
  }

  // Invoke bundle-schemas.ts with the env overrides. The bundler reads
  // primitives from SCHEMAS_DIR/primitives/ and main schemas from
  // SCHEMAS_DIR/, writes to DIST_DIR.
  const bundlerPath = join(REPO_ROOT, 'hdf-schema', 'src', 'bundle-schemas.ts');
  const result = spawnSync('node', ['--import', 'tsx', bundlerPath], {
    cwd: join(REPO_ROOT, 'hdf-schema'),
    env: {
      ...process.env,
      HDF_SCHEMA_SCHEMAS_DIR: srcStage,
      HDF_SCHEMA_DIST_DIR: distStage,
    },
    stdio: 'pipe',
    encoding: 'utf-8',
  });
  if (result.status !== 0) {
    console.error(result.stderr || result.stdout);
    throw new Error(`bundle-schemas.ts failed for ${tag} (exit ${result.status})`);
  }

  // Write each bundled output to the archive.
  for (const schemaFile of MAIN_SCHEMAS) {
    const bundledPath = join(distStage, schemaFile);
    if (!existsSync(bundledPath)) {
      console.warn(`  ! ${schemaFile} not produced by bundler for ${tag}`);
      continue;
    }
    const json = JSON.parse(readFileSync(bundledPath, 'utf-8'));
    writeToArchive(json, schemaFile);
  }

  rmSync(stage, { recursive: true, force: true });
}

/**
 * Seed the CURRENT branch's bundled schemas. Reads from the already-built
 * hdf-schema/dist/schemas/. Caller must ensure dist/schemas is fresh
 * (`cd hdf-schema && pnpm build:schemas`).
 */
function seedCurrent() {
  console.log('Seeding current branch...');
  const distDir = join(REPO_ROOT, 'hdf-schema', 'dist', 'schemas');
  if (!existsSync(distDir)) {
    throw new Error(`current dist not found at ${distDir} — run 'cd hdf-schema && pnpm build:schemas' first`);
  }
  for (const schemaFile of MAIN_SCHEMAS) {
    const path = join(distDir, schemaFile);
    if (!existsSync(path)) {
      console.warn(`  ! ${schemaFile} missing from current dist`);
      continue;
    }
    const json = JSON.parse(readFileSync(path, 'utf-8'));
    writeToArchive(json, schemaFile);
  }
}

function main() {
  mkdirSync(ARCHIVE_ROOT, { recursive: true });

  for (const release of HISTORICAL_RELEASES) {
    if (release.source === 'dist') {
      seedFromDist(release.tag);
    } else if (release.source === 'src') {
      seedFromSrc(release.tag);
    }
  }

  seedCurrent();

  console.log('Archive seeded.');
}

main();
