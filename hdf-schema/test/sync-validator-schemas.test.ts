import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, readdirSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join, dirname, resolve } from 'path';
import { fileURLToPath } from 'url';
import { syncValidatorSchemas, DIST_DIR, EMBED_DIR } from '../src/sync-validator-schemas';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

describe('syncValidatorSchemas', () => {
  let root: string;
  let distDir: string;
  let embedDir: string;

  beforeEach(() => {
    root = mkdtempSync(join(tmpdir(), 'hdf-sync-'));
    distDir = join(root, 'dist', 'schemas');
    embedDir = join(root, 'embed');
    mkdirSync(distDir, { recursive: true });
  });

  afterEach(() => {
    rmSync(root, { recursive: true, force: true });
  });

  it('copies every bundled schema byte-for-byte and creates the embed dir', () => {
    // Trailing newline, CRLF and a non-ASCII char: a copy that re-serialized
    // or re-encoded the JSON would not survive these.
    const payloads: Record<string, string> = {
      'a.schema.json': '{\r\n  "title": "ä"\r\n}\n',
      'b.schema.json': '{"$id":"https://example.test/b"}',
    };
    for (const [name, body] of Object.entries(payloads)) {
      writeFileSync(join(distDir, name), body);
    }

    const copied = syncValidatorSchemas(distDir, embedDir);

    expect(copied).toEqual(['a.schema.json', 'b.schema.json']);
    for (const [name, body] of Object.entries(payloads)) {
      expect(readFileSync(join(embedDir, name)).equals(Buffer.from(body))).toBe(true);
    }
  });

  it('copies only *.schema.json, leaving other dist artifacts behind', () => {
    writeFileSync(join(distDir, 'kept.schema.json'), '{}');
    writeFileSync(join(distDir, 'index.json'), '{}');
    writeFileSync(join(distDir, 'notes.txt'), 'x');

    expect(syncValidatorSchemas(distDir, embedDir)).toEqual(['kept.schema.json']);
    expect(readdirSync(embedDir)).toEqual(['kept.schema.json']);
  });

  it('overwrites a stale embed copy', () => {
    writeFileSync(join(distDir, 'a.schema.json'), '{"fresh":true}');
    mkdirSync(embedDir, { recursive: true });
    writeFileSync(join(embedDir, 'a.schema.json'), '{"stale":true}');

    syncValidatorSchemas(distDir, embedDir);

    expect(readFileSync(join(embedDir, 'a.schema.json'), 'utf-8')).toBe('{"fresh":true}');
  });

  it('throws rather than silently emptying the embed when nothing was bundled', () => {
    expect(() => syncValidatorSchemas(distDir, embedDir)).toThrow(/No bundled schemas found/);
  });

  it('defaults to the in-tree dist and the Go validator embed dir', () => {
    // The embed is a tracked, //go:embed-ed directory, and the bundler's
    // HDF_SCHEMA_DIST_DIR override is deliberately not honoured here: either
    // default drifting would write the bundle where nothing reads it.
    expect(DIST_DIR).toBe(resolve(__dirname, '..', 'dist', 'schemas'));
    expect(EMBED_DIR).toBe(resolve(__dirname, '..', '..', 'hdf-validators', 'go', 'schemas'));
  });

  // The assertion above cannot catch the mistake its own comment warns against:
  // an implementation that DID honour HDF_SCHEMA_DIST_DIR still satisfies it
  // whenever the variable is unset, which is how CI, the pre-commit hook and
  // vitest all run. So the invariant is checked with the variable SET.
  //
  // It matters because site/seed-archive.mjs points that variable at a staging
  // dir to bundle v3.1.0 and v3.2.0 — honouring it here would write an archived
  // release's schemas into the tracked //go:embed dir, and the Go validator
  // would then validate every document against the wrong contract.
  it('ignores HDF_SCHEMA_DIST_DIR even when it is set', async () => {
    const archived = join(root, 'archived-release');
    mkdirSync(archived, { recursive: true });
    writeFileSync(join(archived, 'hdf-results.schema.json'), '{"$id":"https://archived.test/v1"}');

    vi.stubEnv('HDF_SCHEMA_DIST_DIR', archived);
    vi.resetModules();
    try {
      const fresh = await import('../src/sync-validator-schemas');
      expect(fresh.DIST_DIR).toBe(resolve(__dirname, '..', 'dist', 'schemas'));
      expect(fresh.DIST_DIR).not.toBe(archived);

      // And prove it through behaviour, not just the constant: syncing from the
      // archived dir must copy nothing, because the script never looks there.
      const dest = join(root, 'embed-env');
      mkdirSync(dest, { recursive: true });
      fresh.syncValidatorSchemas(archived, dest);
      expect(readdirSync(dest)).toEqual(['hdf-results.schema.json']);
      expect(readFileSync(join(dest, 'hdf-results.schema.json'), 'utf-8')).toBe(
        '{"$id":"https://archived.test/v1"}'
      );
    } finally {
      vi.unstubAllEnvs();
      vi.resetModules();
    }
  });
});
