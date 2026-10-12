import { renameSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';

/**
 * Writes a build artifact so a concurrent reader never observes a partial one.
 * The tests regenerate these documents while sibling suites read them in other
 * vitest workers, and a plain write truncates before it fills.
 */
export function writeArtifact(target: string, contents: string): void {
  // Same directory, so the rename is a metadata operation on one filesystem.
  const temporary = join(dirname(target), `.${process.pid}.${Date.now()}.tmp`);
  writeFileSync(temporary, contents);
  renameSync(temporary, target);
}
