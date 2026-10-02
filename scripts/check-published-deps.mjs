/**
 * Guard: every external import in a publishable package's built output must be
 * declared in that package's manifest, so a published package never imports a
 * module a consumer cannot resolve.
 *
 * We scan `dist/` rather than a packed tarball: every publishable @mitre/hdf-*
 * package ships exactly `dist` (its `files` field), so the built dist is the
 * shipped surface, and scanning it needs no `npm pack` per package.
 *
 * The extractor is es-module-lexer (a real parser), not a regex: a regex over
 * source misfires on template literals and string contents. All publishable
 * packages are ESM (`type: module`, `.js` = ESM), which es-module-lexer covers
 * completely — static imports, dynamic `import()` with a literal specifier, and
 * `export ... from`. A CommonJS file (a `.cjs`, or any file whose requires
 * es-module-lexer cannot see) is reported as unsupported so the guard fails
 * loudly rather than skipping it silently.
 */
import { readFile, readdir } from 'node:fs/promises';
import { join, dirname, extname } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { builtinModules } from 'node:module';
import { init, parse } from 'es-module-lexer';

const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const BUILTINS = new Set(builtinModules);

/** Reduce an import specifier to its package name (`@scope/name` or `name`). */
export function packageNameFromSpecifier(specifier) {
  if (specifier.startsWith('@')) {
    const parts = specifier.split('/');
    return parts.slice(0, 2).join('/');
  }
  return specifier.split('/')[0];
}

function isRelativeOrAbsolute(specifier) {
  return specifier.startsWith('.') || specifier.startsWith('/');
}

function isBuiltin(specifier) {
  if (specifier.startsWith('node:')) return true;
  return BUILTINS.has(specifier);
}

/** Recursively collect dist files with a JS-family extension. */
async function collectDistFiles(distDir) {
  const out = [];
  let entries;
  try {
    entries = await readdir(distDir, { withFileTypes: true });
  } catch {
    return out; // no dist -> nothing to scan
  }
  for (const entry of entries) {
    const full = join(distDir, entry.name);
    if (entry.isDirectory()) {
      out.push(...(await collectDistFiles(full)));
    } else if (['.js', '.mjs', '.cjs'].includes(extname(entry.name))) {
      out.push(full);
    }
  }
  return out;
}

/**
 * Check one package directory. Returns { name, offenders, files, scanned }.
 * `offenders` = [{ package, file, specifier, packageName, reason }].
 */
export async function checkPackage(pkgDir) {
  await init;
  const pkg = JSON.parse(await readFile(join(pkgDir, 'package.json'), 'utf8'));
  const declared = new Set([
    pkg.name,
    ...Object.keys(pkg.dependencies ?? {}),
    ...Object.keys(pkg.peerDependencies ?? {}),
    ...Object.keys(pkg.optionalDependencies ?? {}),
  ]);

  const files = await collectDistFiles(join(pkgDir, 'dist'));
  const offenders = [];

  for (const file of files) {
    const source = await readFile(file, 'utf8');
    let imports;
    try {
      [imports] = parse(source, file);
    } catch (err) {
      offenders.push({
        package: pkg.name,
        file,
        specifier: null,
        packageName: null,
        reason: `unparseable by es-module-lexer (CommonJS?): ${err.message}`,
      });
      continue;
    }
    for (const imp of imports) {
      const specifier = imp.n;
      if (specifier === undefined) continue; // dynamic import with non-literal specifier
      if (isRelativeOrAbsolute(specifier) || isBuiltin(specifier)) continue;
      const packageName = packageNameFromSpecifier(specifier);
      if (declared.has(packageName)) continue;
      offenders.push({
        package: pkg.name,
        file,
        specifier,
        packageName,
        reason: 'external import not declared in dependencies/peerDependencies/optionalDependencies',
      });
    }
  }

  return { name: pkg.name, offenders, files, scanned: files.length };
}

/** Discover publishable @mitre/hdf-* packages that have a dist/ directory. */
async function discoverPackages(repoRoot) {
  const entries = await readdir(repoRoot, { withFileTypes: true });
  const dirs = [];
  for (const entry of entries) {
    if (!entry.isDirectory() || !entry.name.startsWith('hdf-')) continue;
    const pkgDir = join(repoRoot, entry.name);
    let pkg;
    try {
      pkg = JSON.parse(await readFile(join(pkgDir, 'package.json'), 'utf8'));
    } catch {
      continue;
    }
    if (pkg.private) continue;
    if (!(pkg.name ?? '').startsWith('@mitre/hdf-')) continue;
    const dist = await collectDistFiles(join(pkgDir, 'dist'));
    if (dist.length === 0) continue;
    dirs.push(pkgDir);
  }
  return dirs;
}

/** Run the guard across the repo. Returns { ok, offenders, results }. */
export async function checkPublishedDeps(repoRoot = REPO_ROOT) {
  const pkgDirs = await discoverPackages(repoRoot);
  const results = [];
  const offenders = [];
  for (const pkgDir of pkgDirs) {
    const result = await checkPackage(pkgDir);
    results.push(result);
    offenders.push(...result.offenders);
  }
  return { ok: offenders.length === 0, offenders, results };
}

async function main() {
  const { ok, offenders, results } = await checkPublishedDeps();
  const scanned = results.map((r) => r.name).sort();
  console.log(`check-published-deps: scanned ${results.length} package(s): ${scanned.join(', ')}`);
  if (ok) {
    console.log('check-published-deps: OK — every external dist import is declared.');
    return;
  }
  console.error('check-published-deps: FAIL — undeclared external imports in published output:');
  for (const o of offenders) {
    const spec = o.specifier ? ` '${o.specifier}' (${o.packageName})` : '';
    console.error(`  ${o.package}:${spec} in ${o.file}\n    ${o.reason}`);
  }
  process.exitCode = 1;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  await main();
}
