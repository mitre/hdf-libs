// Every publishable workspace package declares `sideEffects`.
//
// Without it a bundler must assume any module may mutate global state when it is
// evaluated, so it can drop none of them: one named import pulls the whole
// package — over 100 KB gzip on hdf-engine, against single digits once declared.
//
// `false` is correct only for a package with no module-scope effects, so an array
// naming the effectful files is accepted too — demanding `false` would push an
// author toward a wrong one, which silently deletes needed initialization.
import { readFileSync, readdirSync, realpathSync } from 'fs';
import { dirname, join } from 'path';
import { fileURLToPath } from 'url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');

// Publishable packages only: 12 of the 14 today, since hdf-cli and site are
// private. One unit of slack, as scripts/check-package-names.mjs keeps 13 of 14 —
// the floor is here to catch a scan that found nothing, not to pin the count, and
// making a package private should not read as a missing declaration.
export const PACKAGE_FLOOR = 11;

/** Read one directory's manifest, or null when the directory is not a package. */
function manifestOf(root, dir) {
  try {
    return JSON.parse(readFileSync(join(root, dir, 'package.json'), 'utf-8'));
  } catch {
    return null;
  }
}

// A bundler reads `false`, `true`, or an array of paths. Anything else is a typo
// that reads as declared while meaning nothing, which is what this gate exists
// to catch — so the shape is checked, not merely the key's presence.
function declaredShape(value) {
  if (typeof value === 'boolean') return null;
  if (Array.isArray(value) && value.every((entry) => typeof entry === 'string')) return null;
  return `must be false, true, or an array of paths, not ${JSON.stringify(value)}`;
}

export function checkPackage(root, dir) {
  const manifest = manifestOf(root, dir);
  if (manifest === null) {
    return { dir, isPackage: false, published: false, declared: false, fault: null };
  }
  const published = manifest.private !== true;
  const declared = Object.hasOwn(manifest, 'sideEffects');
  const base = { dir, isPackage: true, published, declared };

  if (!published) {
    return { ...base, fault: null };
  }
  if (!declared) {
    return {
      ...base,
      fault:
        `${dir}/package.json declares no "sideEffects" — a bundler cannot tree-shake it. ` +
        'Add "sideEffects": false once the package is audited for module-scope effects, ' +
        'or an array naming the files that have them.',
    };
  }
  const malformed = declaredShape(manifest.sideEffects);
  if (malformed !== null) {
    return { ...base, fault: `${dir}/package.json "sideEffects" ${malformed}` };
  }
  return { ...base, fault: null };
}

export function auditWorkspace(root, floor = PACKAGE_FLOOR) {
  const faults = [];
  let published = 0;

  for (const entry of readdirSync(root, { withFileTypes: true })) {
    if (!entry.isDirectory()) continue;
    const result = checkPackage(root, entry.name);
    if (!result.isPackage) continue;
    if (result.published) published += 1;
    if (result.fault !== null) faults.push(result.fault);
  }

  // A guard that finds no packages passes for the wrong reason.
  if (published < floor) {
    faults.push(`only ${published} publishable packages found; expected at least ${floor}`);
  }
  return { published, faults };
}

// Compare realpaths, as scripts/check-comment-length.mjs does. import.meta.url is
// already realpath-resolved and percent-encoded, so comparing it to argv[1] — raw
// or even via pathToFileURL — misses whenever the path holds a space or is reached
// through a symlink, and the gate then exits 0 having scanned nothing.
const invokedDirectly =
  process.argv[1] && realpathSync(fileURLToPath(import.meta.url)) === realpathSync(process.argv[1]);
if (invokedDirectly) {
  const { published, faults } = auditWorkspace(ROOT);
  if (faults.length > 0) {
    process.stderr.write(`${faults.join('\n')}\n`);
    process.exit(1);
  }
  process.stdout.write(
    `side effects: ${published} publishable packages, each declaring sideEffects\n`,
  );
}
