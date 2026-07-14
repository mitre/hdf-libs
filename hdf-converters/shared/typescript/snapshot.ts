/**
 * TypeScript mirror of the Go snapshot harness (shared/go/testing.go).
 *
 * Both languages assert their converter output against the SAME
 * `fixtures/expected/<input>.hdf.json` goldens under the SAME volatile-field
 * normalization. That symmetry is the entire point: without it a TS converter
 * can drift arbitrarily from its Go twin and every test still passes.
 *
 * Keep `VOLATILE_KEYS` and `normalizeVolatileFields` in lockstep with
 * `volatileKeys` / `normalizeValue` in shared/go/testing.go.
 */
import { readdirSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

const GOLDEN_SUFFIX = '.hdf.json';

/**
 * Keys whose values genuinely cannot be derived from the input, so both
 * languages blank them before comparing. Every entry needs a stated reason it is
 * not input-derivable — a masked key that CAN be derived from the input is a
 * hidden bug, not volatility. Kept in lockstep with `volatileKeys` in
 * shared/go/testing.go.
 *
 *   - timestamp: the document write/conversion time.
 *   - startTime: falls back to conversion time for importers whose source
 *     carries no scan time (input-derived for those that do — follow-up to make
 *     this per-converter).
 *
 * resultsChecksum is intentionally NOT masked: it is sha256(input), deterministic
 * and identical across Go/TS, so asserting it catches real checksum divergence.
 */
export const VOLATILE_KEYS = new Set(['timestamp', 'startTime']);

/** Path to converters/, resolved from this module's location. */
export function convertersDir(): string {
  return join(dirname(fileURLToPath(import.meta.url)), '..', '..', 'converters');
}

/**
 * Replace volatile values with "(normalized)" at any depth. Mirrors
 * normalizeValue() in shared/go/testing.go.
 */
export function normalizeVolatileFields(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(normalizeVolatileFields);
  if (value !== null && typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      out[k] = VOLATILE_KEYS.has(k) ? '(normalized)' : normalizeVolatileFields(v);
    }
    return out;
  }
  return value;
}

/** Converter output may be a JSON string or an already-parsed document. */
export type SnapshotConvertFn = (input: string) => unknown | Promise<unknown>;

function toDocument(result: unknown): unknown {
  const parsed = typeof result === 'string' ? JSON.parse(result) : result;
  // Round-trip so Dates and other non-JSON values serialize exactly as they
  // would on the wire — the same thing Go's json.Marshal does to its output.
  return JSON.parse(JSON.stringify(parsed)) as unknown;
}

/**
 * Assert the converter reproduces every golden in fixtures/expected/.
 *
 * A golden is only asserted when it is named `<input>.hdf.json`. Anything else
 * would be silently ignored, leaving a green suite that proves nothing, so
 * mis-named goldens and empty golden sets are hard failures — matching the Go
 * harness.
 */
export function runSnapshotTests(converterName: string, convertFn: SnapshotConvertFn): void {
  const expectedDir = join(convertersDir(), converterName, 'fixtures', 'expected');
  const inputDir = join(convertersDir(), converterName, 'fixtures', 'input');

  const entries = readdirSync(expectedDir).filter((f) => f.endsWith('.json'));
  const goldens = entries.filter((f) => f.endsWith(GOLDEN_SUFFIX));
  const misnamed = entries.filter((f) => !f.endsWith(GOLDEN_SUFFIX));

  describe(`${converterName} golden snapshots (TS↔Go parity)`, () => {
    it('every golden is named <input>.hdf.json, and at least one exists', () => {
      expect(misnamed, `golden(s) nothing asserts; rename to <input>.hdf.json or delete`).toEqual([]);
      expect(goldens.length, `no golden in ${expectedDir}`).toBeGreaterThan(0);
    });

    for (const golden of goldens) {
      const inputName = golden.slice(0, -GOLDEN_SUFFIX.length);
      it(inputName, async () => {
        const input = readFileSync(join(inputDir, inputName), 'utf-8');
        const actual = normalizeVolatileFields(toDocument(await convertFn(input)));
        const expectedDoc = normalizeVolatileFields(
          JSON.parse(readFileSync(join(expectedDir, golden), 'utf-8')),
        );
        expect(actual).toEqual(expectedDoc);
      });
    }
  });
}
