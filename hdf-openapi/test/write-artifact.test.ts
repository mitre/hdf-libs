import { spawn } from 'node:child_process';
import { chmodSync, closeSync, mkdtempSync, openSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { platform, tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { renameWithRetry, writeArtifact } from '../src/write-artifact.js';

// A reader in another process, parsing the target for a fixed window. Every
// version written is valid JSON, so a parse failure can only be a partial read.
const READER = `
const fs = require('fs');
const [target, windowMs] = process.argv.slice(2);
let reads = 0;
let torn = 0;
const until = Date.now() + Number(windowMs);
while (Date.now() < until) {
  try {
    JSON.parse(fs.readFileSync(target, 'utf8'));
    reads++;
  } catch (err) {
    if (err.code !== 'ENOENT') torn++;
  }
}
process.stdout.write(JSON.stringify({ reads, torn }));
`;

const WINDOW_MS = 700;

/** Rewrites `target` through `write` while a child process reads it. */
async function observeConcurrentReads(
  write: (target: string, contents: string) => void,
): Promise<{ reads: number; torn: number }> {
  const dir = mkdtempSync(join(tmpdir(), 'hdf-artifact-'));
  try {
    const target = join(dir, 'document.json');
    const reader = join(dir, 'reader.cjs');
    writeFileSync(reader, READER);
    // Many filesystem pages per write, which is what opens the window; a short
    // document is replaced too fast for a reader to land inside one.
    const wide = `${JSON.stringify({ rows: Array.from({ length: 20000 }, (_, i) => ({ i })) })}\n`;
    const narrow = `${JSON.stringify({ rows: [] })}\n`;
    write(target, wide);

    const child = spawn(process.execPath, [reader, target, String(WINDOW_MS)]);
    let stdout = '';
    child.stdout.setEncoding('utf-8');
    child.stdout.on('data', (chunk: string) => {
      stdout += chunk;
    });
    const closed = new Promise<void>((resolve) => child.on('close', () => resolve()));

    const until = Date.now() + WINDOW_MS;
    while (Date.now() < until) {
      write(target, wide);
      write(target, narrow);
    }
    await closed;
    return JSON.parse(stdout) as { reads: number; torn: number };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

describe('writeArtifact', () => {
  it('writes the exact contents', () => {
    const dir = mkdtempSync(join(tmpdir(), 'hdf-artifact-'));
    try {
      const target = join(dir, 'out.json');
      writeArtifact(target, '{"a":1}\n');
      expect(readFileSync(target, 'utf-8')).toBe('{"a":1}\n');
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('replaces an existing artifact and leaves no temporary behind', () => {
    const dir = mkdtempSync(join(tmpdir(), 'hdf-artifact-'));
    try {
      const target = join(dir, 'out.json');
      writeArtifact(target, '{"v":1}\n');
      writeArtifact(target, '{"v":2}\n');
      expect(readFileSync(target, 'utf-8')).toBe('{"v":2}\n');
      expect(readdirSync(dir)).toEqual(['out.json']);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  // The defect this exists for: sibling suites read these documents in other
  // vitest workers while one regenerates them. Skipped on Windows for the same
  // reason as the Go writer's loop-reader test: a reader reopening the file with
  // no gap can refuse every replacement within the retry budget, so success there
  // is a race. The Windows outcome is pinned deterministically below.
  it.skipIf(platform() === 'win32')('is never observed partially written by a concurrent reader', async () => {
    const observed = await observeConcurrentReads(writeArtifact);
    expect(observed.reads, 'the reader never read the file, so this could not fail').toBeGreaterThan(0);
    expect(observed.torn).toBe(0);
  }, 20000);

  // What the two platforms actually guarantee when a handle is open for the whole
  // write, which is the one case that is deterministic rather than a race.
  it('a handle held open through the write never sees a partial file', () => {
    const dir = mkdtempSync(join(tmpdir(), 'hdf-artifact-'));
    let held: number | undefined;
    try {
      const target = join(dir, 'doc.json');
      const before = '{"v":1}\n';
      const after = `${JSON.stringify({ rows: Array.from({ length: 20000 }, (_, i) => ({ i })) })}\n`;
      writeArtifact(target, before);
      held = openSync(target, 'r');

      if (platform() === 'win32') {
        // MoveFileEx must delete the destination and Node opens without
        // FILE_SHARE_DELETE, so the retry budget expires and the write reports.
        expect(() => writeArtifact(target, after)).toThrow();
        expect(readFileSync(target, 'utf-8')).toBe(before);
      } else {
        writeArtifact(target, after);
        expect(readFileSync(target, 'utf-8')).toBe(after);
        expect(readFileSync(held, 'utf-8')).toBe(before);
      }
      expect(readdirSync(dir)).toEqual(['doc.json']);
    } finally {
      if (held !== undefined) closeSync(held);
      rmSync(dir, { recursive: true, force: true });
    }
  }, 20000);

  // The retry exists for Windows, where an open reader makes the replacement fail
  // rather than tear. A read-only directory reproduces the same refusal on POSIX,
  // so the three paths through it are reachable without a Windows runner.
  describe('the rename retry', () => {
    const withReadOnlyDir = (body: (dir: string, from: string, to: string) => void): void => {
      const dir = mkdtempSync(join(tmpdir(), 'hdf-artifact-'));
      const from = join(dir, 'staged.tmp');
      const to = join(dir, 'doc.json');
      writeFileSync(from, '{"v":2}\n');
      writeFileSync(to, '{"v":1}\n');
      try {
        body(dir, from, to);
      } finally {
        chmodSync(dir, 0o700);
        rmSync(dir, { recursive: true, force: true });
      }
    };

    // chmod on a directory does not restrict writes on Windows, so these two cannot
    // provoke a refusal there. The exhaustion path is covered on Windows by the
    // held-handle test above, where the open handle refuses every attempt.
    it.skipIf(platform() === 'win32')('gives up when the refusal outlasts the budget, leaving the old version', () => {
      withReadOnlyDir((dir, from, to) => {
        chmodSync(dir, 0o500);
        expect(() => renameWithRetry(from, to, 50)).toThrow();
        expect(readFileSync(to, 'utf-8')).toBe('{"v":1}\n');
      });
    });

    it.skipIf(platform() === 'win32')('succeeds when the refusal clears inside the budget', () => {
      withReadOnlyDir((dir, from, to) => {
        const unlock = join(dir, 'unlock.cjs');
        writeFileSync(unlock, `require('fs').chmodSync(process.argv[2], 0o700);`);
        chmodSync(dir, 0o500);
        // The retry spins synchronously, so only another process can clear it.
        spawn(process.execPath, [unlock, dir], { detached: true, stdio: 'ignore' }).unref();
        renameWithRetry(from, to, 10000);
        expect(readFileSync(to, 'utf-8')).toBe('{"v":2}\n');
      });
    }, 20000);

    it('reports a refusal that is not retryable without waiting out the budget', () => {
      const dir = mkdtempSync(join(tmpdir(), 'hdf-artifact-'));
      try {
        const from = join(dir, 'staged.tmp');
        writeFileSync(from, '{}\n');
        const started = Date.now();
        // ENOENT: a destination directory that does not exist is never retryable.
        expect(() => renameWithRetry(from, join(dir, 'missing', 'doc.json'), 5000)).toThrow();
        expect(Date.now() - started).toBeLessThan(2000);
        expect(readdirSync(dir), 'a refused rename must leave nothing staged').toEqual([]);
      } finally {
        rmSync(dir, { recursive: true, force: true });
      }
    });
  });

  // The control. Without it the test above cannot tell "atomic" from "the window was
  // never hit", and would pass against the plain write it exists to rule out.
  it('the same harness does observe a plain write partially', async () => {
    const observed = await observeConcurrentReads((target, contents) =>
      writeFileSync(target, contents),
    );
    expect(observed.torn, 'the harness caught no tear, so the check above proves nothing').toBeGreaterThan(0);
  }, 20000);
});
