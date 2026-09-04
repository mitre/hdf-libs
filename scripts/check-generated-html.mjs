#!/usr/bin/env node
/**
 * Guard against VitePress build output landing in the site source tree.
 *
 * `vitepress build` writes to site/.vitepress/dist. An invocation that points
 * outDir at the source directory instead mirrors the whole rendered site next
 * to the markdown it was built from, which is commit-eligible noise. This
 * scans the filesystem rather than asking git, because git cannot report the
 * strays that land in an ignored output directory, and it collapses a
 * directory with no tracked files into one status line — which is how a
 * previous cleanup missed most of them.
 */
import { readdirSync } from 'node:fs';
import { join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO_ROOT = fileURLToPath(new URL('..', import.meta.url));
const SITE_DIR = join(REPO_ROOT, 'site');
// The build output directories are the only places rendered HTML belongs, plus
// site/public, which holds hand-authored static assets that VitePress copies
// verbatim and which may legitimately include HTML. The rest of .vitepress is
// tracked source and IS scanned.
const EXEMPT_DIRS = new Set(['.vitepress/dist', '.vitepress/cache', 'public']);

function findHtml(dir, out = []) {
  let entries;
  try {
    entries = readdirSync(dir, { withFileTypes: true });
  } catch {
    return out;
  }
  for (const entry of entries) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) {
      // node_modules is skipped at any depth; the rest are exact paths under site/.
      if (entry.name === 'node_modules') continue;
      if (EXEMPT_DIRS.has(relative(SITE_DIR, full))) continue;
      findHtml(full, out);
    } else if (entry.name.endsWith('.html')) {
      out.push(relative(REPO_ROOT, full));
    }
  }
  return out;
}

const strays = findHtml(SITE_DIR).sort();

if (strays.length > 0) {
  console.error(
    `Found ${strays.length} generated HTML file(s) in the site source tree:\n` +
      strays.map((f) => `  ${f}`).join('\n') +
      '\n\nVitePress output belongs in site/.vitepress/dist. Delete these and\n' +
      'rebuild with `cd site && pnpm generate && pnpm exec vitepress build`.',
  );
  process.exit(1);
}

console.log('No generated HTML in the site source tree.');
