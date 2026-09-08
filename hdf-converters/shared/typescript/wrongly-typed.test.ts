/**
 * Pins TypeScript to its Go peer on HDF documents carrying a wrongly-typed field.
 *
 * Go decodes into generated structs, so encoding/json rejects these outright.
 * TypeScript parsed untyped and cast, and `as T` is erased at runtime, so the
 * same bytes converted and the bad value reached the output — as a wrong title,
 * a silently zeroed impact, or a dropped reference. Both languages read
 * ../testdata/wrongly-typed-cases.json so they cannot drift apart again.
 */
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, it, expect } from 'vitest';
import { requireHdfResults } from './converterutil.js';

interface WronglyTypedCase {
  name: string;
  accept: boolean;
  path: Array<string | number>;
  value: unknown;
  why?: string;
}

const table = JSON.parse(
  readFileSync(
    join(dirname(fileURLToPath(import.meta.url)), '..', 'testdata', 'wrongly-typed-cases.json'),
    'utf-8',
  ),
) as { base: Record<string, unknown>; cases: WronglyTypedCase[] };

/**
 * Walks path into a deep copy of base and sets the final key. An empty path
 * leaves the document untouched, which is how the table spells its accept case.
 */
function applyMutation(tc: WronglyTypedCase): string {
  const doc = structuredClone(table.base) as Record<string, unknown>;
  if (tc.path.length > 0) {
    let node: unknown = doc;
    for (const step of tc.path.slice(0, -1)) {
      node = (node as Record<string | number, unknown>)[step];
    }
    (node as Record<string | number, unknown>)[tc.path[tc.path.length - 1]!] = tc.value;
  }
  return JSON.stringify(doc);
}

describe('wrongly-typed HDF is rejected in both languages', () => {
  it.each(table.cases.map((c) => [c.name, c] as const))('%s', (_name, tc) => {
    const run = () => requireHdfResults(applyMutation(tc), 'test');
    if (tc.accept) {
      expect(run, `valid HDF must still convert. ${tc.why ?? ''}`).not.toThrow();
    } else {
      expect(run, `a wrongly-typed field must be rejected. ${tc.why ?? ''}`).toThrow();
    }
  });
});
