// RFC 9457 §3.1.1: a problem type's URI SHOULD dereference to human-readable documentation.
// ADR-0008 §3 chose site-hosted type URIs over about:blank for exactly that, so these pages
// are part of the contract. Generated from hdf-openapi's published table, never hand-edited.
//
// One directory per type, because the declared URI carries no extension and GitHub Pages
// redirects an extensionless path to its directory index (measured: /hdf-libs/schemas 301s
// to /hdf-libs/schemas/). A flat <type>.md would publish <type>.html and leave every
// declared URI a 404.
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, '..');
export const PROBLEM_TABLE = 'hdf-openapi/dist/problems.json';
const PAGES_DIR = path.resolve(__dirname, 'problems');

const OWNER_NOTE = {
  taxonomy: 'Raised by the HDF document taxonomy, which every HDF interface shares.',
  convention: 'Owned by the API conventions in ADR-0008 §3 rather than by any one operation.',
  service: 'Raised by the service that stores the documents, not by document content.',
};

function page(type, entry) {
  const owned = OWNER_NOTE[entry.owner];
  if (owned === undefined) throw new Error(`${type}: no note for owner ${entry.owner}`);
  return `---
title: ${type}
---

# \`${type}\`

**HTTP status ${entry.status}** · problem type \`https://mitre.github.io/hdf-libs/problems/${type}\`

${owned}

## Cause

${entry.cause}

## What to do

${entry.remedy}

## Shape

An error response carries this type in the \`type\` member of an [RFC 9457](https://www.rfc-editor.org/rfc/rfc9457)
problem document, served as \`application/problem+json\`:

\`\`\`json
{
  "type": "https://mitre.github.io/hdf-libs/problems/${type}",
  "title": "${type.toUpperCase().replace(/-/g, '_')}",
  "status": ${entry.status}
}
\`\`\`

Clients branch on \`type\`, not on the status: several types share a status, and the status
alone does not say which condition occurred.
`;
}

function indexPage(table) {
  const rows = Object.entries(table)
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([type, e]) => `| [\`${type}\`](./${type}/) | ${e.status} | ${e.cause} |`)
    .join('\n');
  return `---
title: Problem Types
---

# Problem types

Every error the reference API returns is an [RFC 9457](https://www.rfc-editor.org/rfc/rfc9457)
problem document whose \`type\` is one of the URIs below. Branch on \`type\` rather than on the
HTTP status: several types share a status.

| Type | Status | Cause |
|---|---|---|
${rows}
`;
}

export function generateProblemPages(table = PROBLEM_TABLE) {
  const source = path.resolve(REPO_ROOT, table);
  if (!fs.existsSync(source)) {
    throw new Error(`${table} is not built; run hdf-openapi's build first`);
  }
  const docs = JSON.parse(fs.readFileSync(source, 'utf-8'));
  const types = Object.keys(docs);
  if (types.length === 0) throw new Error(`${table} documents no problem types`);

  fs.rmSync(PAGES_DIR, { recursive: true, force: true });
  for (const [type, entry] of Object.entries(docs)) {
    const dir = path.join(PAGES_DIR, type);
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, 'index.md'), page(type, entry));
  }
  fs.mkdirSync(PAGES_DIR, { recursive: true });
  fs.writeFileSync(path.join(PAGES_DIR, 'index.md'), indexPage(docs));
  console.log(`Generated problems/ — ${types.length} problem type pages.`);
}

if (import.meta.url === `file://${process.argv[1]}`) generateProblemPages();
