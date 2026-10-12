// Generate the VitePress page and the published archive for the OpenAPI documents.
//
// Reads the BUILT components document from hdf-openapi/dist/ and the tracked
// tooling baseline, then produces:
//
// - openapi/index.md — the reference page (rendered view, downloads, the
//   measured tooling-compatibility matrix)
// - public/openapi/<name>.oas.{json,yaml} — current-version raw documents
// - public/openapi/<name>/v<version>/index.json — the per-version archive,
//   the same layout the schema archive uses
// - public/openapi/viewer.html — a standalone Redoc page the markdown embeds.
//   Standalone rather than a script tag in markdown: VitePress server-renders
//   the page, and Redoc wants a browser.
//
// Run: node generate-openapi-docs.mjs

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, '..');

// Repo-relative so a test can resolve the same artifacts without restating them.
export const COMPONENTS_DOCUMENT = 'hdf-openapi/dist/hdf-components.oas.json';
const BASELINE = 'hdf-openapi/test/baseline/keywords.json';

/**
 * The documents this publishes. Derived rather than hardcoded: ADR-0008 ships two, and the
 * first version of this generator carried one document's name as a constant, which is what
 * made adding the second a rewrite instead of a row.
 *
 * `required` distinguishes them: the components document is built by Phase 1 and must be
 * present, while the reference API document arrives with Phase 2 and is skipped with a
 * notice if its build has not run — the page then simply does not offer it.
 */
export const DOCUMENTS = [
  {
    name: 'hdf-components',
    title: 'Components',
    json: 'hdf-openapi/dist/hdf-components.oas.json',
    yaml: 'hdf-openapi/dist/hdf-components.oas.yaml',
    required: true,
    blurb:
      'The data types, generated from the HDF schema bundles. Components-only: it describes the documents, not an API surface.',
  },
  {
    name: 'hdf-api',
    title: 'Reference API',
    json: 'hdf-openapi/dist/hdf-api.oas.json',
    required: false,
    blurb:
      'The HTTP surface, generated from the MCP contract and the binding table. Every operation, parameter and response shape is derived; none is hand-authored.',
  },
];

const PAGES_DIR = path.resolve(__dirname, 'openapi');
const PUBLIC_DIR = path.resolve(__dirname, 'public/openapi');

const read = (rel) => fs.readFileSync(path.resolve(REPO_ROOT, rel), 'utf-8');

/** The support matrix, rendered from what the matrix script measured. */
function compatibilitySection(baseline) {
  const tools = Object.entries(baseline.tools);
  const docSupport = baseline.codegen.document;
  const keywords = baseline.codegen.keywords;

  // Every generator ignores these, which is why the contract is enforced by the
  // derived validators rather than by generated types. Listed once rather than
  // per-tool: a keyword no tool honors is the interesting row.
  const names = Object.keys(keywords).sort();
  const generators = Object.keys(docSupport);

  const rows = names.map((kw) => {
    const cells = generators.map((g) => (keywords[kw][g] === 'honored' ? '✓' : '✗'));
    return `| \`${kw}\` | ${cells.join(' | ')} |`;
  });

  const loadRows = generators.map((g) => {
    const entry = docSupport[g];
    const verdict = entry.consumes ? 'loads the document' : 'cannot load the document';
    const why = entry.error ? ` — \`${entry.error.split(':').slice(-1)[0].trim()}\`` : '';
    return `| \`${g}\` | ${verdict}${why} |`;
  });

  return `## Tooling compatibility

Measured, not documented: the matrix generates with each keyword and without it, then
compares the bytes. Versions below are the ones the baseline was recorded against.

| Tool | Version |
|---|---|
${tools.map(([n, v]) => `| \`${n}\` | ${v} |`).join('\n')}

### Can the generator load this document?

| Generator | Result |
|---|---|
${loadRows.join('\n')}

### Which keywords survive code generation?

A ✗ means the keyword is dropped from the generated types, so it constrains nothing at
runtime. Every validation keyword is dropped by every generator — generated types carry
shape only, and the contract is enforced by validators derived from this document.

| Keyword | ${generators.map((g) => `\`${g}\``).join(' | ')} |
|---|${generators.map(() => '---').join('|')}|
${rows.join('\n')}
`;
}

// The page links this with a raw anchor rather than markdown: VitePress normalizes a
// .html link to a page route and reports the viewer — a public asset, not a page — as a
// dead link, which fails the build.
function viewerHtml(jsonHref) {
  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>HDF OpenAPI components</title>
    <style>body { margin: 0; }</style>
  </head>
  <body>
    <redoc spec-url="${jsonHref}"></redoc>
    <script src="https://cdn.redoc.ly/redoc/latest/bundles/redoc.standalone.js"></script>
  </body>
</html>
`;
}

export function generateOpenapiDocs() {
  const published = [];
  const skipped = [];

  fs.mkdirSync(PUBLIC_DIR, { recursive: true });
  for (const document of DOCUMENTS) {
    const jsonPath = path.resolve(REPO_ROOT, document.json);
    if (!fs.existsSync(jsonPath)) {
      if (document.required) {
        throw new Error(
          `${document.json} is missing — build it first with \`pnpm --filter @mitre/hdf-openapi run build\``,
        );
      }
      skipped.push(document);
      continue;
    }
    const raw = read(document.json);
    const version = JSON.parse(raw).info.version;

    fs.writeFileSync(path.join(PUBLIC_DIR, `${document.name}.oas.json`), raw);
    if (document.yaml && fs.existsSync(path.resolve(REPO_ROOT, document.yaml))) {
      fs.writeFileSync(path.join(PUBLIC_DIR, `${document.name}.oas.yaml`), read(document.yaml));
    }

    // Same shape as the schema archive: <name>/v<version>/index.json.
    // The archive freezes one document per RELEASED version, and only the release knows
    // which those are — refusing every overwrite here blocked iterating on an unreleased
    // version, which is the ordinary case. The immutability check is a release step; what
    // stops two different contracts sharing a version is hdf-openapi's contract digest.
    const archiveDir = path.join(PUBLIC_DIR, document.name, `v${version}`);
    fs.mkdirSync(archiveDir, { recursive: true });
    fs.writeFileSync(path.join(archiveDir, 'index.json'), raw);

    const base = '/hdf-libs/openapi';
    fs.writeFileSync(
      path.join(PUBLIC_DIR, `viewer-${document.name}.html`),
      viewerHtml(`${base}/${document.name}.oas.json`),
    );
    published.push({ ...document, version, raw });
  }

  const baseline = JSON.parse(read(BASELINE));
  const base = '/hdf-libs/openapi';

  const section = (d) => {
    const parsed = JSON.parse(d.raw);
    const count = Object.keys(parsed.components?.schemas ?? {}).length;
    const paths = Object.keys(parsed.paths ?? {}).length;
    const scale = paths > 0 ? `${paths} paths and ${count} component schemas` : `${count} component schemas`;
    return `## ${d.title}

\`${parsed.info.title}\` v${d.version} — ${scale}. ${d.blurb}

- [Download JSON](${base}/${d.name}.oas.json)${d.yaml ? `\n- [Download YAML](${base}/${d.name}.oas.yaml)` : ''}
- <a href="${base}/viewer-${d.name}.html">Open the rendered reference</a>
- Archive: [v${d.version}](${base}/${d.name}/v${d.version}/index.json)

<iframe src="${base}/viewer-${d.name}.html" title="${parsed.info.title}" style="width:100%;height:70vh;border:1px solid var(--vp-c-divider);border-radius:8px;"></iframe>
`;
  };

  const page = `---
title: OpenAPI Documents
---

# OpenAPI documents

Generated from the HDF schema bundles and the MCP contract on every build, so neither can
drift from its source.

${published.map(section).join('\n')}
${compatibilitySection(baseline)}`;

  fs.mkdirSync(PAGES_DIR, { recursive: true });
  fs.writeFileSync(path.join(PAGES_DIR, 'index.md'), page);

  const names = published.map((d) => `${d.name}@v${d.version}`).join(', ');
  const note = skipped.length > 0 ? ` (skipped ${skipped.map((d) => d.name).join(', ')}: not built)` : '';
  console.log(`Generated openapi/index.md — ${published.length} document(s): ${names}${note}.`);
}

if (import.meta.url === `file://${process.argv[1]}`) generateOpenapiDocs();
