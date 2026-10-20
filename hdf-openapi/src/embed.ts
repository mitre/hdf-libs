import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { MAIN_SCHEMAS } from './components.js';
import type { JsonSchema } from './components.js';

const HERE = dirname(fileURLToPath(import.meta.url));

/**
 * The tracked embed, not `hdf-schema/dist/` — dist is gitignored, so a glob of it
 * silently yields whatever the last local build left behind. The embed is the
 * copy `build:schemas` writes and CI reviews.
 */
export const EMBED_DIR = join(HERE, '..', '..', 'hdf-validators', 'go', 'schemas');

/**
 * Reads the eight bundles. The file set must equal MAIN_SCHEMAS exactly: a bundle
 * that appeared or vanished changes which document types the contract covers, and
 * that is a reviewed change, never an inferred one.
 */
export function loadBundles(embedDir: string): Map<string, JsonSchema> {
  if (!existsSync(embedDir)) {
    throw new Error(`embed directory does not exist: ${embedDir}`);
  }
  const found = readdirSync(embedDir)
    .filter((f) => f.endsWith('.schema.json'))
    .sort();
  const expected = [...MAIN_SCHEMAS].sort();
  const missing = expected.filter((f) => !found.includes(f));
  const extra = found.filter((f) => !expected.includes(f as (typeof MAIN_SCHEMAS)[number]));
  if (missing.length > 0 || extra.length > 0) {
    throw new Error(
      `embed at ${embedDir} does not match the bundler MAIN_SCHEMAS set` +
        (missing.length > 0 ? `; missing: ${missing.join(', ')}` : '') +
        (extra.length > 0 ? `; unexpected: ${extra.join(', ')}` : ''),
    );
  }
  const bundles = new Map<string, JsonSchema>();
  for (const file of MAIN_SCHEMAS) {
    bundles.set(file, JSON.parse(readFileSync(join(embedDir, file), 'utf8')) as JsonSchema);
  }
  return bundles;
}
