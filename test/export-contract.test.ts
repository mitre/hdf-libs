/**
 * Export-contract regression test.
 *
 * Enforces the three-artifact rule across the hdf-libs monorepo: for every
 * subpath-exportable directory under a package's src/, the source file, the
 * tsdown.config.ts entry array, and the package.json exports map MUST
 * agree. Drift between any of the three leaves utilities present in source
 * but unreachable from any consumer of the published package — the bug
 * class behind mitre/hdf-libs#43, #44, #45.
 *
 * The test runs against built dist/ output. Run after `pnpm build`.
 */

import { describe, it, expect } from 'vitest';
import { readFile, readdir } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');

// Discovered at runtime from repo-root directories matching
// pnpm-workspace.yaml's `hdf-*` glob, minus hdf-cli (Go-only). Auto-covers
// any future hdf-* TS package added to the workspace — eliminates the
// failure mode where a new package is added and someone forgets to wire
// it into the gate, silently reintroducing the drift class this gate
// exists to prevent.
async function discoverTsPackages(): Promise<string[]> {
  const entries = await readdir(REPO_ROOT, { withFileTypes: true });
  return entries
    .filter(
      (entry) =>
        entry.isDirectory() &&
        entry.name.startsWith('hdf-') &&
        entry.name !== 'hdf-cli' &&
        existsSync(join(REPO_ROOT, entry.name, 'package.json')),
    )
    .map((entry) => entry.name)
    .sort();
}

const TS_PACKAGES = await discoverTsPackages();
if (TS_PACKAGES.length === 0) {
  throw new Error(
    'export-contract gate discovered no hdf-* TS packages — is REPO_ROOT correct?',
  );
}

// Subdirs under src/ that are not subpath-export candidates (data, types, internal helpers, etc.).
// Hand-maintained opt-out list. The opt-out integrity check below fails the
// gate if any of these dirs is also partially wired as a public subpath
// (tsdown entry or package.json exports key) — the silent-failure mode of
// the opt-out model. Future work: replace with per-dir marker files
// (`src/<dir>/.internal`) so adding an internal dir is an explicit opt-out
// at the dir itself, not a central list update.
const INTERNAL_SRC_SUBDIRS = new Set([
  '__tests__',
  '_internal',
  'data',
  'helpers',
  'schemas',
  'tests',
  'types',
]);

interface ExportEntry {
  types?: string;
  import?: string;
  default?: string;
  require?: string;
}

interface PackageJson {
  name: string;
  type?: string;
  exports?: Record<string, ExportEntry | string>;
  main?: string;
  types?: string;
}

async function loadPackageJson(pkg: string): Promise<PackageJson> {
  const raw = await readFile(join(REPO_ROOT, pkg, 'package.json'), 'utf8');
  return JSON.parse(raw) as PackageJson;
}

/**
 * Read the tsdown.config.ts for a package and extract the `entry` value as a
 * normalized array of source-relative paths. Supports both array form
 * (`entry: ['src/a.ts', 'src/b.ts']`) and object form
 * (`entry: { a: 'src/a.ts', b: 'src/b.ts' }`).
 *
 * Returns `null` if the package has no tsdown.config.ts.
 */
async function loadTsdownEntries(pkg: string): Promise<string[] | null> {
  const cfgPath = join(REPO_ROOT, pkg, 'tsdown.config.ts');
  if (!existsSync(cfgPath)) return null;
  const mod = await import(pathToFileURL(cfgPath).href);
  const config = mod.default;
  const cfg = Array.isArray(config) ? config[0] : config;
  const entry = cfg?.entry;
  if (Array.isArray(entry)) {
    return entry.filter((e: unknown): e is string => typeof e === 'string');
  }
  if (typeof entry === 'string') return [entry];
  if (entry && typeof entry === 'object') {
    return Object.values(entry).filter((v): v is string => typeof v === 'string');
  }
  return [];
}

async function findSrcSubdirs(pkg: string): Promise<string[]> {
  const srcRoot = join(REPO_ROOT, pkg, 'src');
  if (!existsSync(srcRoot)) return [];
  const entries = await readdir(srcRoot, { withFileTypes: true });
  const subdirs: string[] = [];
  for (const entry of entries) {
    if (!entry.isDirectory()) continue;
    if (INTERNAL_SRC_SUBDIRS.has(entry.name)) continue;
    if (existsSync(join(srcRoot, entry.name, 'index.ts'))) {
      subdirs.push(entry.name);
    }
  }
  return subdirs.sort();
}


/**
 * Parse src/index.ts and find every value re-export from a relative path.
 * Returns a map of relative-path-string → list of named value exports.
 *
 * Matches any `export { ... } from './X'` or `'../X'` — including deeper
 * paths like `./matching/strategies.js`, not just `./<subdir>/index.js`.
 * Skips `export type { ... } from ...` (types do not exist at runtime) and
 * non-relative paths (externals are not part of the package-boundary gate).
 * Handles `export { x as y }` (the exported name is `y`).
 */
function findValueReExports(srcIndex: string): Map<string, string[]> {
  const result = new Map<string, string[]>();
  const re = /export\s+(?!type\b)\{\s*([^}]*)\}\s+from\s+['"](\.\.?\/[^'"]+)['"]/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(srcIndex)) !== null) {
    const reExportPath = m[2];
    const names = m[1]
      .split(',')
      .map((s) => s.trim())
      .filter((s) => s.length > 0)
      .filter((s) => !/^type\s/.test(s))
      .map((s) => {
        const asMatch = s.match(/(\S+)\s+as\s+(\S+)/);
        return asMatch ? asMatch[2] : s;
      });
    if (names.length === 0) continue;
    const existing = result.get(reExportPath) ?? [];
    result.set(reExportPath, [...existing, ...names]);
  }
  return result;
}

interface PackageContractData {
  pkg: string;
  pkgJson: PackageJson;
  tsdownEntries: string[] | null;
  srcSubdirs: string[];
  valueReExports: Map<string, string[]>;
}

const packageData: PackageContractData[] = await Promise.all(
  TS_PACKAGES.map(async (pkg) => {
    const pkgJson = await loadPackageJson(pkg);
    const tsdownEntries = await loadTsdownEntries(pkg);
    const srcSubdirs = await findSrcSubdirs(pkg);
    const srcIndexPath = join(REPO_ROOT, pkg, 'src', 'index.ts');
    const srcIndex = existsSync(srcIndexPath) ? await readFile(srcIndexPath, 'utf8') : '';
    const valueReExports = findValueReExports(srcIndex);
    return { pkg, pkgJson, tsdownEntries, srcSubdirs, valueReExports };
  }),
);

describe('export-contract', () => {
  for (const { pkg, pkgJson, tsdownEntries, srcSubdirs, valueReExports } of packageData) {
    describe(`@mitre/${pkg}`, () => {
      it('package.json declares an exports map with a main entry', () => {
        expect(pkgJson.exports, `${pkg}/package.json must declare an exports field`).toBeDefined();
        expect(
          pkgJson.exports?.['.'],
          `${pkg}/package.json exports must declare main entry "."`,
        ).toBeDefined();
      });

      // Opt-out integrity: an INTERNAL_SRC_SUBDIRS dir must not also appear
      // as a public subpath. The opt-out model's failure mode is a
      // maintainer adding `src/internal/index.ts` intending it to be
      // public, then having the gate silently drop it because `internal`
      // happens to match the excludes list. This catches the contradiction.
      it('excluded internal subdirs are not partially wired as public exports', async () => {
        const srcRoot = join(REPO_ROOT, pkg, 'src');
        if (!existsSync(srcRoot)) return;
        const violations: string[] = [];
        const entries = await readdir(srcRoot, { withFileTypes: true });
        for (const entry of entries) {
          if (!entry.isDirectory()) continue;
          if (!INTERNAL_SRC_SUBDIRS.has(entry.name)) continue;
          if (!existsSync(join(srcRoot, entry.name, 'index.ts'))) continue;
          const tsdownEntry = `src/${entry.name}/index.ts`;
          if (tsdownEntries?.includes(tsdownEntry)) {
            violations.push(`tsdown.config.ts entry includes "${tsdownEntry}"`);
          }
          if (pkgJson.exports?.[`./${entry.name}`]) {
            violations.push(`package.json exports declares "./${entry.name}"`);
          }
        }
        expect(
          violations,
          `${pkg}: subdir(s) in INTERNAL_SRC_SUBDIRS are partially wired as public exports — either remove from INTERNAL_SRC_SUBDIRS or unwire: ${violations.join('; ')}`,
        ).toHaveLength(0);
      });

      // Three-artifact rule: every src/<subdir>/index.ts must be in tsdown entries AND exports map.
      for (const subdir of srcSubdirs) {
        it(`src/${subdir}/index.ts is listed in tsdown.config.ts entry`, () => {
          if (tsdownEntries === null) return; // package has no tsdown config — skip
          const expected = `src/${subdir}/index.ts`;
          expect(
            tsdownEntries,
            `${pkg}/tsdown.config.ts entry is missing "${expected}" — three-artifact rule violated`,
          ).toContain(expected);
        });

        it(`src/${subdir}/index.ts has matching package.json exports key "./${subdir}"`, () => {
          expect(
            pkgJson.exports?.[`./${subdir}`],
            `${pkg}/package.json exports map is missing "./${subdir}" — three-artifact rule violated`,
          ).toBeDefined();
        });
      }

      // Every declared exports subpath must point to a file that exists in dist/ and is runtime-importable.
      const exportsMap = pkgJson.exports ?? {};
      for (const [subpath, entry] of Object.entries(exportsMap)) {
        if (subpath === './package.json') continue;
        const importTarget = typeof entry === 'string' ? entry : entry?.import;
        if (!importTarget) continue;
        const distFile = join(REPO_ROOT, pkg, importTarget);

        it(`exports "${subpath}" points to a file that exists in dist/`, () => {
          expect(
            existsSync(distFile),
            `${pkg}: exports "${subpath}" → ${importTarget} but ${distFile} does not exist (build missing or stale?)`,
          ).toBe(true);
        });

        it(`exports "${subpath}" is runtime-importable and exposes named exports`, async () => {
          if (!existsSync(distFile)) {
            expect.fail(`${pkg}: cannot test import — ${distFile} does not exist`);
          }
          const mod = await import(pathToFileURL(distFile).href);
          const named = Object.keys(mod).filter((k) => k !== 'default');
          expect(
            named.length,
            `${pkg}: runtime import of "${subpath}" returned no named exports`,
          ).toBeGreaterThan(0);
        });
      }

      // Main-entry value re-exports from src/index.ts must all be reachable in the built main entry.
      if (valueReExports.size > 0) {
        it('main entry runtime-bundles every value re-exported from src/index.ts', async () => {
          const mainEntry = exportsMap['.'];
          const importTarget =
            typeof mainEntry === 'string' ? mainEntry : (mainEntry as ExportEntry | undefined)?.import;
          if (!importTarget) {
            expect.fail(`${pkg}: no main entry import target declared`);
          }
          const distFile = join(REPO_ROOT, pkg, importTarget);
          if (!existsSync(distFile)) {
            expect.fail(`${pkg}: dist main entry ${distFile} does not exist`);
          }
          const mod = await import(pathToFileURL(distFile).href);
          const missing: string[] = [];
          for (const [reExportPath, names] of valueReExports) {
            for (const name of names) {
              if (!(name in mod)) {
                missing.push(`${name} (re-exported from ${reExportPath})`);
              }
            }
          }
          expect(
            missing,
            `${pkg}: main entry is missing names re-exported from src/index.ts: ${missing.join(', ')}`,
          ).toHaveLength(0);
        });
      }
    });
  }
});
