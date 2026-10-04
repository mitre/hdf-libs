/**
 * Copy the bundled schemas into the Go validator's //go:embed directory.
 *
 * Runs immediately after bundle-schemas.ts in `build:schemas`, because the
 * validator embed must always reflect the latest bundled output.
 */
import { readdirSync, readFileSync, writeFileSync, mkdirSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath, pathToFileURL } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Deliberately not HDF_SCHEMA_DIST_DIR: site/seed-archive.mjs points that at a
// staging dir to bundle *older* releases, and honouring it here would overwrite
// the embed with an archived version's schemas.
export const DIST_DIR = join(__dirname, '..', 'dist', 'schemas');
export const EMBED_DIR = join(__dirname, '..', '..', 'hdf-validators', 'go', 'schemas');

export function syncValidatorSchemas(distDir = DIST_DIR, embedDir = EMBED_DIR): string[] {
  const files = readdirSync(distDir)
    .filter((f) => f.endsWith('.schema.json'))
    .sort();

  if (files.length === 0) {
    throw new Error(`No bundled schemas found in ${distDir}; run bundle-schemas.ts first`);
  }

  mkdirSync(embedDir, { recursive: true });

  for (const file of files) {
    writeFileSync(join(embedDir, file), readFileSync(join(distDir, file)));
  }

  return files;
}

/* c8 ignore start */
if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  try {
    const files = syncValidatorSchemas();
    console.log(`Synced ${files.length} schema(s) to hdf-validators/go/schemas/`);
  } catch (err) {
    console.error('Validator schema sync failed:', err);
    process.exit(1);
  }
}
/* c8 ignore stop */
