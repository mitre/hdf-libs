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
export function writeArtifact(target: string, contents: string): void {
  // Same directory, so the rename is a metadata operation on one filesystem.
  const temporary = join(dirname(target), `.${process.pid}.${Date.now()}.tmp`);
  writeFileSync(temporary, contents);
  renameSync(temporary, target);
}
