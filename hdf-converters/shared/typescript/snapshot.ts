/**
 * TypeScript mirror of the Go snapshot harness (shared/go/testing.go).
 *
 * Both languages assert their converter output against the SAME
 * `fixtures/expected/<input>.hdf.json` goldens under the SAME volatile-field
 * normalization. That symmetry is the entire point: without it a TS converter
 * can drift arbitrarily from its Go twin and every test still passes.
 *
 * Keep the masking discipline in lockstep with shared/go/testing.go:
 *   - timestamp (the document write/conversion time) is ALWAYS masked.
 *   - startTime is masked PER-FIXTURE via the maskStartTime argument — only for
 *     fixtures whose source carries no scan time. A fixture whose source DOES
 *     carry a scan time asserts startTime against the input-derived value; a
 *     masked-but-derivable startTime is a hidden wrong-time bug (the u6j3 axis).
 *   - resultsChecksum is intentionally NOT masked: it is sha256(input),
 *     deterministic and identical across Go/TS, so asserting it catches drift.
 */
import { readdirSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { serializeHdf } from './converterutil.js';

const GOLDEN_SUFFIX = '.hdf.json';

/** timestamp is always volatile; startTime volatility is decided per fixture. */
const ALWAYS_MASK = new Set(['timestamp']);

/** Path to converters/, resolved from this module's location. */
export function convertersDir(): string {
  return join(dirname(fileURLToPath(import.meta.url)), '..', '..', 'converters');
}

/**
 * Replace the keys in `mask` with "(normalized)" at any depth. Mirrors
 * normalizeValue() in shared/go/testing.go.
 */
export function normalizeVolatileFields(value: unknown, mask: Set<string>): unknown {
  if (Array.isArray(value)) return value.map((v) => normalizeVolatileFields(v, mask));
  if (value !== null && typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      out[k] = mask.has(k) ? '(normalized)' : normalizeVolatileFields(v, mask);
    }
    return out;
  }
  return value;
}

/** Converter output may be a JSON string or an already-parsed document. */
export type SnapshotConvertFn = (input: string) => unknown | Promise<unknown>;

function toDocument(result: unknown): unknown {
  const parsed = typeof result === 'string' ? JSON.parse(result) : result;
  // Serialize through the canonical HDF serializer so Date fields are trimmed to
  // RFC3339 (no trailing-zero fraction) exactly as real output and Go's
  // json.Marshal are — otherwise an object-returning converter's Date startTime
  // serializes as `...000Z` here while its real (serializeHdf) output and the
  // Go-generated golden are trimmed.
  return JSON.parse(serializeHdf(parsed)) as unknown;
}

/**
 * Assert the converter reproduces every golden in fixtures/expected/.
 *
 * `maskStartTime` lists the input-fixture names whose startTime the converter
 * synthesizes (source carries no scan time) and so must be masked; the sentinel
 * `'*'` masks every fixture. Fixtures not listed have startTime asserted.
 *
 * A golden is only asserted when it is named `<input>.hdf.json`. Anything else
 * would be silently ignored, leaving a green suite that proves nothing, so
 * mis-named goldens and empty golden sets are hard failures — matching the Go
 * harness.
 */
/**
 * Supplies input content for a fixture whose source lives outside fixtures/input/
 * (e.g. a shared @mitre/hdf-fixtures fixture); returns undefined to fall back to
 * fixtures/input/<inputName>. Keeps the harness decoupled from the fixtures package.
 */
export type SnapshotInputResolver = (inputName: string) => string | undefined;

export function runSnapshotTests(
  converterName: string,
  convertFn: SnapshotConvertFn,
  maskStartTime: string[] = [],
  resolveInput?: SnapshotInputResolver,
  extraMask: string[] = [],
): void {
  const expectedDir = join(convertersDir(), converterName, 'fixtures', 'expected');
  const inputDir = join(convertersDir(), converterName, 'fixtures', 'input');
  const synthetic = new Set(maskStartTime);

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
        const mask = new Set(ALWAYS_MASK);
        if (synthetic.has('*') || synthetic.has(inputName)) mask.add('startTime');
        // extraMask lets a converter mask fields with no deterministic source value
        // (e.g. SARIF suppression overrides carry no owner/date → appliedAt/expiresAt
        // are conversion-time). Opt-in and scoped; other converters are unaffected.
        for (const k of extraMask) mask.add(k);
        const input = resolveInput?.(inputName) ?? readFileSync(join(inputDir, inputName), 'utf-8');
        const actual = normalizeVolatileFields(toDocument(await convertFn(input)), mask);
        const expectedDoc = normalizeVolatileFields(
          JSON.parse(readFileSync(join(expectedDir, golden), 'utf-8')),
          mask,
        );
        expect(actual).toEqual(expectedDoc);
      });
    }
  });
}
