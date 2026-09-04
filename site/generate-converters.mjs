// Generate the converter catalog page (docs/guides/converters.md) from the
// registry manifest at data/converters.json.
//
// The manifest is produced and drift-guarded by a Go golden test in hdf-cli
// (TestConverterCatalogManifest): adding or removing a converter fails that
// test until the manifest is regenerated, so this page can never claim a
// converter the CLI does not ship, or omit one it does. This script only
// renders — it never invents data. Wired into `pnpm generate`; the output is
// git-ignored and rebuilt at site-build time, like the schema pages.
//
// Run: node generate-converters.mjs

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const MANIFEST = path.resolve(__dirname, 'data/converters.json');
const OUTPUT = path.resolve(__dirname, 'docs/guides/converters.md');

const AMENDMENTS_SOURCE = 'hdf-amendments';

// Render a markdown table of `format → converter name` rows. The Empty-input
// column is only meaningful for imports (it never applies to HDF export), so it
// is opt-in via `withEmpty`.
function table(headerFormat, rows, withEmpty) {
  const head = withEmpty
    ? `| ${headerFormat} | Converter | Empty input OK |`
    : `| ${headerFormat} | Converter |`;
  const rule = withEmpty ? '| --- | --- | --- |' : '| --- | --- |';
  const lines = [head, rule];
  for (const r of rows) {
    lines.push(
      withEmpty
        ? `| \`${r.format}\` | ${r.name} | ${r.acceptsEmpty ? '✓' : '✗'} |`
        : `| \`${r.format}\` | ${r.name} |`,
    );
  }
  return lines.join('\n');
}

// Friendly label for each `hdf system create --from` token. The token list is
// registry-derived (golden-tested); an unknown token still renders, falling back
// to the token itself so a newly-added format is never silently dropped.
const BOM_FORMAT_LABELS = {
  cyclonedx: 'plain CycloneDX SBOM',
  spdx: 'plain SPDX 2.x SBOM',
  'cyclonedx-mlbom': 'CycloneDX ML-BOM (AIBOM — a machine-learning-model component)',
  'spdx-ai': 'SPDX 3.0 AI/Dataset document (AIBOM)',
};

function main() {
  const manifest = JSON.parse(fs.readFileSync(MANIFEST, 'utf-8'));
  const entries = manifest.converters;
  const bomFormats = manifest.systemBomFormats ?? [];

  // Import: anything → hdf that is not itself an HDF-family source.
  const imports = entries
    .filter((e) => e.dest === 'hdf' && e.source !== 'hdf' && e.source !== AMENDMENTS_SOURCE)
    .map((e) => ({ format: e.source, name: e.name, acceptsEmpty: e.acceptsEmpty }));

  // Export: hdf → anything.
  const exports = entries
    .filter((e) => e.source === 'hdf')
    .map((e) => ({ format: e.dest, name: e.name, acceptsEmpty: e.acceptsEmpty }));

  // Amendments export: hdf-amendments → anything.
  const amendments = entries
    .filter((e) => e.source === AMENDMENTS_SOURCE)
    .map((e) => ({ format: e.dest, name: e.name, acceptsEmpty: e.acceptsEmpty }));

  const bomRows = bomFormats.map((f) => `| \`${f}\` | ${BOM_FORMAT_LABELS[f] ?? f} |`);
  const bomTable = ['| Format token | Input |', '| --- | --- |', ...bomRows].join('\n');

  const md = `# Converter Catalog

The \`hdf\` CLI converts security assessment data between formats. This page lists
every converter that ships in this build. It is generated from the live
converter registry, so it always matches what \`hdf convert --help\` reports.

Convert to HDF with an auto-detected input format:

\`\`\`bash
hdf convert scan.json -o results.json
\`\`\`

or name the format explicitly with \`--from\` / \`--to\` using the format token in
the tables below (e.g. \`--from nessus\`, \`--to splunk\`):

\`\`\`bash
hdf convert --from nessus --to hdf scan.nessus -o results.json
\`\`\`

The **Empty input OK** column marks converters that treat empty input as a valid
"no findings" signal (exit-code-first scanners) rather than an error; these must
be paired with an explicit \`--from\` because empty input carries nothing to
auto-detect.

## Import to HDF (${imports.length})

Source formats that convert **into** HDF. Pass the format token to \`--from\`.

${table('Source format', imports, true)}

## Export from HDF (${exports.length})

Formats that HDF Results convert **out** to. Pass the format token to \`--to\`.

${table('Target format', exports, false)}

## Amendments export (${amendments.length})

Formats produced from an HDF amendments document (waivers, attestations, POA&Ms).

${table('Target format', amendments, false)}

## Ingesting SBOMs (inventory) — \`hdf system create\`

Software Bill of Materials **inventory** documents are not in the tables above:
they carry no assessment results, so they are not converters. They build an HDF
**System** document (its \`components[]\`) through \`hdf system create\` (or
\`hdf system add-component\`), not the converter registry. If you are looking for
**SPDX** or an **AIBOM**, this is the path.

\`hdf system create --from <format>\` accepts (omit \`--from\` to auto-detect):

${bomTable}

**Vulnerability-bearing CycloneDX is a converter, not this path.** A CycloneDX
document that carries \`vulnerabilities\` (or VEX) converts to HDF **Results** via
\`cyclonedx\` / \`cyclonedx-vex\` in the tables above; \`cyclonedx\` (to HDF Results)
rejects a no-vulnerability inventory SBOM and points you here instead. SPDX has no
vulnerability-to-Results path — it only ever flows to the System model.
`;

  fs.mkdirSync(path.dirname(OUTPUT), { recursive: true });
  fs.writeFileSync(OUTPUT, md);
  console.log(
    `Generated ${path.relative(process.cwd(), OUTPUT)} — ` +
      `${imports.length} import, ${exports.length} export, ${amendments.length} amendments.`,
  );
}

main();
