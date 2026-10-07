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

// Repo-relative so a test can resolve the same artifact without restating it.
export const COMPONENTS_DOCUMENT = 'hdf-openapi/dist/hdf-components.oas.json';
const COMPONENTS_YAML = 'hdf-openapi/dist/hdf-components.oas.yaml';
const BASELINE = 'hdf-openapi/test/baseline/keywords.json';

const PAGES_DIR = path.resolve(__dirname, 'openapi');
const PUBLIC_DIR = path.resolve(__dirname, 'public/openapi');
const DOCUMENT_NAME = 'hdf-components';

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
  const docPath = path.resolve(REPO_ROOT, COMPONENTS_DOCUMENT);
  if (!fs.existsSync(docPath)) {
    throw new Error(
      `${COMPONENTS_DOCUMENT} is missing — build it first with \`pnpm --filter @mitre/hdf-openapi run build:components\``,
    );
  }
  const raw = read(COMPONENTS_DOCUMENT);
  const doc = JSON.parse(raw);
  const baseline = JSON.parse(read(BASELINE));
  const version = doc.info.version;

  fs.mkdirSync(PUBLIC_DIR, { recursive: true });
  fs.writeFileSync(path.join(PUBLIC_DIR, `${DOCUMENT_NAME}.oas.json`), raw);
  if (fs.existsSync(path.resolve(REPO_ROOT, COMPONENTS_YAML))) {
    fs.writeFileSync(path.join(PUBLIC_DIR, `${DOCUMENT_NAME}.oas.yaml`), read(COMPONENTS_YAML));
  }

  // Same shape as the schema archive: <name>/v<version>/index.json.
  const archiveDir = path.join(PUBLIC_DIR, DOCUMENT_NAME, `v${version}`);
  fs.mkdirSync(archiveDir, { recursive: true });
  fs.writeFileSync(path.join(archiveDir, 'index.json'), raw);

  const base = '/hdf-libs/openapi';
  fs.writeFileSync(path.join(PUBLIC_DIR, 'viewer.html'), viewerHtml(`${base}/${DOCUMENT_NAME}.oas.json`));

  const schemaCount = Object.keys(doc.components?.schemas ?? {}).length;
  const page = `---
title: OpenAPI Components
---

# OpenAPI components

\`${doc.info.title}\` v${version} — ${schemaCount} component schemas generated from the HDF
schema bundles. The document is components-only: it describes the data types, not an API
surface. It is regenerated from the built components document on every site build.

- [Download JSON](${base}/${DOCUMENT_NAME}.oas.json) — \`${DOCUMENT_NAME}.oas.json\`
- [Download YAML](${base}/${DOCUMENT_NAME}.oas.yaml)
- <a href="${base}/viewer.html">Open the rendered reference</a>

<iframe src="${base}/viewer.html" title="HDF OpenAPI components" style="width:100%;height:70vh;border:1px solid var(--vp-c-divider);border-radius:8px;"></iframe>

## Versions

| Version | Document |
|---|---|
| v${version} (latest) | [index.json](${base}/${DOCUMENT_NAME}/v${version}/index.json) |

${compatibilitySection(baseline)}`;

  fs.mkdirSync(PAGES_DIR, { recursive: true });
  fs.writeFileSync(path.join(PAGES_DIR, 'index.md'), page);

  console.log(`Generated openapi/index.md — ${schemaCount} schemas at v${version}.`);
}

if (import.meta.url === `file://${process.argv[1]}`) generateOpenapiDocs();
