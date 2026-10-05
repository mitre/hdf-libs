// Generate the hdf-to-html converter's TypeScript assets module from the asset
// files the Go peer embeds, so the stylesheet and script exist once in the
// repository instead of as two hand-kept string constants.
//
// Source: converters/hdf-to-html/go/assets/{blades.min.css,report.css,report.js}
// Output: converters/hdf-to-html/typescript/assets.ts (committed, drift-guarded by
// converters/hdf-to-html/go/assets_test.go and typescript/assets.test.ts)
//
// Run: node scripts/generate-html-assets.mjs

import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const CONVERTER = path.resolve(__dirname, '../converters/hdf-to-html');
const ASSETS = path.join(CONVERTER, 'go', 'assets');
const OUTPUT = path.join(CONVERTER, 'typescript', 'assets.ts');

function readAsset(name) {
  return readFileSync(path.join(ASSETS, name), 'utf8');
}

/** The CSP source expression for the script element, whose content is the newline after <script> plus the script. */
export function scriptHash(script) {
  return `sha256-${createHash('sha256').update(`\n${script}`, 'utf8').digest('base64')}`;
}

export function renderModule(blades, report, script) {
  const constant = (name, value) => `export const ${name} = ${JSON.stringify(value)};`;
  return [
    '/*',
    ' * GENERATED FILE — do not edit.',
    ' *',
    ' * Written by scripts/generate-html-assets.mjs from the asset files the Go peer',
    ' * embeds (../go/assets/). Edit those, then regenerate:',
    ' *   pnpm --filter @mitre/hdf-converters run generate',
    ' */',
    '',
    '/** The vendored Pico+Blades stylesheet, byte-exact. See ../go/assets/provenance.txt. */',
    constant('BLADES_CSS', blades),
    '',
    '/** The report layer: status and severity tokens, the dashboard, and the print rules. */',
    constant('REPORT_CSS', report),
    '',
    '/** The vendored file carries no trailing newline, so one separates it from the report layer. */',
    "export const STYLESHEET = BLADES_CSS + '\\n' + REPORT_CSS;",
    '',
    '/** The only script the report carries. */',
    constant('SCRIPT', script),
    '',
    '/** The CSP source expression for SCRIPT; a test recomputes it from the file. */',
    constant('SCRIPT_HASH', scriptHash(script)),
    '',
  ].join('\n');
}

// Only writing when run as a command; the drift test imports renderModule to
// compare against the committed file, which regenerating would defeat.
if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const module = renderModule(readAsset('blades.min.css'), readAsset('report.css'), readAsset('report.js'));
  writeFileSync(OUTPUT, module);
  console.log(`Wrote ${path.relative(path.resolve(__dirname, '..'), OUTPUT)}`);
}
