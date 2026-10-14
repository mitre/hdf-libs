import { renameSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';

/**
 * Writes a build artifact so a concurrent reader never observes a partial one.
 * matrix.test.ts regenerates the components document at module scope while
 * examples.test.ts reads it from disk in another vitest worker, and a plain write
 * truncates before it fills. The other suites build the document in process and
 * never touch the file. Measured: 1320 torn reads against a plain write, none against
 * the rename.
 */
/**
 * Windows refuses the replacement outright while another handle has the
 * destination open, rather than tearing it: MoveFileEx must delete the
 * destination and Node opens files without FILE_SHARE_DELETE. A sibling worker
 * reading the document is exactly the case this writer exists for, and its
 * handle is gone microseconds later, so the refusal is retried briefly before
 * being reported.
 */
const RETRY_CODES = new Set(['EPERM', 'EACCES', 'EBUSY']);
const RETRY_BUDGET_MS = 2000;

function renameWithRetry(from: string, to: string): void {
  const deadline = Date.now() + RETRY_BUDGET_MS;
  for (;;) {
    try {
      renameSync(from, to);
      return;
    } catch (err) {
      const code = (err as { code?: string }).code;
      if (code === undefined || !RETRY_CODES.has(code) || Date.now() >= deadline) throw err;
      // Synchronous by necessity: the callers are module-scope test setup.
      const until = Date.now() + 5;
      while (Date.now() < until) {
        /* hold */
      }
    }
  }
}

export function writeArtifact(target: string, contents: string): void {
  // Same directory, so the rename is a metadata operation on one filesystem.
  const temporary = join(dirname(target), `.${process.pid}.${Date.now()}.tmp`);
  writeFileSync(temporary, contents);
  renameWithRetry(temporary, target);
}
