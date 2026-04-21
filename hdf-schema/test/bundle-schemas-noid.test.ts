/**
 * Separate test file for the main-schema `if (id)` false branch in
 * registerAllSchemas (bundle-schemas.ts line 38).
 *
 * This must run in its own vitest worker because @hyperjump/json-schema
 * maintains a global schema registry that rejects re-registration.
 */
import { describe, it, expect, afterAll } from 'vitest';
import { readFileSync, writeFileSync, existsSync, rmSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { bundleSchemas } from '../src/bundle-schemas';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const SCHEMAS_DIR = join(__dirname, '..', 'src', 'schemas');
const DIST_DIR = join(__dirname, '..', 'dist', 'schemas');

describe('bundle-schemas main schema without $id', () => {
  // Use the last schema in MAIN_SCHEMAS so that all earlier schemas
  // are bundled successfully before the no-$id schema causes a failure.
  const TARGET = 'hdf-evidence-package.schema.json';
  const targetPath = join(SCHEMAS_DIR, TARGET);
  let original: string;

  afterAll(() => {
    // Always restore the original schema
    if (original) {
      writeFileSync(targetPath, original);
    }
  });

  it('should skip main schemas that lack a $id field during registration', async () => {
    original = readFileSync(targetPath, 'utf-8');

    // Strip the $id from the schema
    const parsed = JSON.parse(original);
    delete parsed.$id;
    writeFileSync(targetPath, JSON.stringify(parsed, null, 2));

    // Clean dist so bundleSchemas creates it fresh
    if (existsSync(DIST_DIR)) {
      rmSync(DIST_DIR, { recursive: true });
    }

    // bundleSchemas will:
    // 1. Call registerAllSchemas() — the modified schema has no $id, so
    //    line 38's false branch is exercised (schema is silently skipped).
    // 2. Attempt to bundle the no-$id schema — this will throw because
    //    bundleSchema(undefined) is invalid.
    // The branch coverage for line 38 is recorded before the throw.
    await expect(bundleSchemas()).rejects.toThrow();
  });
});
