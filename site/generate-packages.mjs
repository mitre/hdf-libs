// Generate the package reference pages (docs/packages/*.md) from each
// workspace package's README.
//
// The READMEs are the canonical API reference and stay in the packages, where
// npm and GitHub surface them. This script renders them onto the site so a
// visitor can reach them at all — it never restates their content, so there is
// exactly one copy to keep current. Wired into `pnpm generate`; the output is
// git-ignored and rebuilt at site-build time, like the schema and converter
// pages.
//
// The rendered set is drift-guarded by site/test/packages-render.test.mjs: a
// package added to the workspace without a README, or a stale page left behind,
// fails that test.
//
// Run: node generate-packages.mjs

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, '..');
const OUTPUT_DIR = path.resolve(__dirname, 'docs/packages');
const BLOB = 'https://github.com/mitre/hdf-libs/blob/main';

// The workspace glob is 'hdf-*' (pnpm-workspace.yaml). Deriving the set from
// the filesystem rather than a hand-kept list is what keeps a new package from
// silently missing the site.
export function workspacePackages() {
  return fs
    .readdirSync(REPO_ROOT, { withFileTypes: true })
    .filter((e) => e.isDirectory() && e.name.startsWith('hdf-'))
    .map((e) => e.name)
    .filter((name) => fs.existsSync(path.join(REPO_ROOT, name, 'README.md')))
    .sort();
}

// A README's links are written for the repository. Rewrite the two shapes that
// resolve differently on the site, and send anything else to GitHub rather than
// leaving a link that 404s.
function rewriteLinks(markdown) {
  // One pass, so a rule cannot rewrite what an earlier rule just produced —
  // chained .replace() calls turned ./hdf-cli back into a GitHub URL.
  return markdown.replace(/\]\((\.\.?\/[^)]+)\)/g, (_m, target) => {
    const sibling = target.match(/^\.\.\/(hdf-[a-z-]+)\/README\.md(#.*)?$/);
    if (sibling) return `](./${sibling[1]}${sibling[2] ?? ''})`;
    const sitePage = target.match(/^\.\.\/site\/docs\/(.+?)\.md(#.*)?$/);
    if (sitePage) return `](/docs/${sitePage[1]}${sitePage[2] ?? ''})`;
    return `](${BLOB}/${target.replace(/^\.\//, '')})`;
  });
}

function render(pkg) {
  const readme = fs.readFileSync(path.join(REPO_ROOT, pkg, 'README.md'), 'utf8');
  const source = `${BLOB}/${pkg}/README.md`;
  const note = `::: tip Package reference\nRendered from [\`${pkg}/README.md\`](${source}) in the repository, which is the canonical source.\n:::\n\n`;
  const body = rewriteLinks(readme).trimEnd();
  // Keep the README's own h1 as the page title, with the provenance note
  // directly beneath it so the reader knows where to send a correction.
  const lines = body.split('\n');
  const h1 = lines.findIndex((l) => l.startsWith('# '));
  if (h1 === -1) return `${note}${body}\n`;
  return `${lines.slice(0, h1 + 1).join('\n')}\n\n${note}${lines.slice(h1 + 1).join('\n').trimStart()}\n`;
}

function main() {
  fs.mkdirSync(OUTPUT_DIR, { recursive: true });
  const packages = workspacePackages();

  // Remove stale pages so a renamed or dropped package cannot linger.
  for (const f of fs.readdirSync(OUTPUT_DIR)) {
    if (f.endsWith('.md') && f !== 'index.md' && !packages.includes(f.replace(/\.md$/, ''))) {
      fs.unlinkSync(path.join(OUTPUT_DIR, f));
    }
  }

  for (const pkg of packages) {
    fs.writeFileSync(path.join(OUTPUT_DIR, `${pkg}.md`), render(pkg));
  }

  const index = [
    '# Packages',
    '',
    'The libraries that make up this repository. Each page is rendered from that',
    "package's README, which is the canonical reference and lives alongside the code.",
    '',
    ...packages.map((p) => `- [${p}](./${p})`),
    '',
  ].join('\n');
  fs.writeFileSync(path.join(OUTPUT_DIR, 'index.md'), index);

  console.log(`Generated docs/packages — ${packages.length} package pages.`);
}

if (import.meta.url === `file://${process.argv[1]}`) main();
