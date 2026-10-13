// Every publishable workspace package's name is `@mitre/` plus its directory.
//
// The convention held for 12 of 13 and then did not: when the reference API moved to the
// sibling repository and took the bare `@mitre/hdf-openapi` name with it, this package's
// manifest was renamed and its directory was not — leaving a directory named after a
// package that lives in another repository. That is the class this checks.
//
// `site` is the one deliberate exception: it is private, never published, and its name
// describes what it builds rather than where it sits.
import { readFileSync, readdirSync } from 'fs';
import { dirname, join } from 'path';
import { fileURLToPath } from 'url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const EXEMPT = new Map([['site', '@mitre/hdf-schema-site']]);

const faults = [];
let checked = 0;

for (const entry of readdirSync(ROOT, { withFileTypes: true })) {
  if (!entry.isDirectory()) continue;
  let manifest;
  try {
    manifest = JSON.parse(readFileSync(join(ROOT, entry.name, 'package.json'), 'utf-8'));
  } catch {
    continue; // not a package
  }
  checked += 1;
  const exempt = EXEMPT.get(entry.name);
  const expected = exempt ?? `@mitre/${entry.name}`;
  if (manifest.name !== expected) {
    faults.push(
      `${entry.name}/package.json declares "${manifest.name}", expected "${expected}" — ` +
        'rename the directory or the package so the two agree, or record a deliberate ' +
        'exception in scripts/check-package-names.mjs',
    );
  }
}

// A guard that finds no packages passes for the wrong reason.
if (checked < 13) {
  faults.push(`only ${checked} workspace packages found; expected at least 13`);
}

if (faults.length > 0) {
  process.stderr.write(`${faults.join('\n')}\n`);
  process.exit(1);
}
process.stdout.write(`package names: ${checked} packages, each matching its directory\n`);
