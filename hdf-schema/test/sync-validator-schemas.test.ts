import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, readdirSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join, dirname, resolve } from 'path';
import { fileURLToPath } from 'url';
import { syncValidatorSchemas, DIST_DIR, EMBED_DIR } from '../src/sync-validator-schemas';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// A filename the real bundler can never emit, so "did it read the archived dir"
// has an unambiguous answer rather than depending on file contents.
const ARCHIVED_ONLY = 'zzz-archived-only.schema.json';

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
    writeFileSync(join(archived, ARCHIVED_ONLY), '{"$id":"https://archived.test/v1"}');

    vi.stubEnv('HDF_SCHEMA_DIST_DIR', archived);
    vi.resetModules();
    try {
      const fresh = await import('../src/sync-validator-schemas');
      expect(fresh.DIST_DIR).toBe(resolve(__dirname, '..', 'dist', 'schemas'));
      expect(fresh.DIST_DIR).not.toBe(archived);

      // And through behaviour, exercising the DEFAULT source path — passing
      // `archived` explicitly would only prove the function copies from the
      // directory it was handed, and would still pass an implementation that
      // read the env var at CALL time rather than at module load. So distDir is
      // left to its default and only the destination is redirected, so the
      // tracked embed dir is never written.
      const dest = join(root, 'embed-env');
      mkdirSync(dest, { recursive: true });
      try {
        fresh.syncValidatorSchemas(undefined, dest);
        expect(readdirSync(dest)).not.toContain(ARCHIVED_ONLY);
      } catch (err) {
        // An empty in-tree dist throws, and that is itself proof the archived
        // dir was not read — that one is deliberately non-empty. The suite can
        // leave dist partial, so this branch is reachable and must not fail.
        expect(String(err)).toMatch(/No bundled schemas found/);
      }
    } finally {
      vi.unstubAllEnvs();
      vi.resetModules();
    }
  });
});
