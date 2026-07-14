/**
 * Ground-truth anchors — the TypeScript mirror of shared/go/anchor.go.
 *
 * Golden parity proves the Go and TS converters AGREE; it cannot prove either is
 * CORRECT. When both misread a format the same way their goldens match and the
 * defect is invisible. An anchor asserts the converter reproduces an item count
 * derived INDEPENDENTLY from the source document, so a silent under-extraction
 * fails even when Go and TS agree.
 *
 * The count helpers deliberately do NOT use any converter's parser or typed
 * model: reusing the converter's traversal would let the same bug corrupt the
 * ground-truth count. Keep in lockstep with anchor.go.
 */
import { expect } from 'vitest';

/**
 * Count opening tags with the given local name in raw XML, ignoring namespace
 * prefixes (matches both <Rule> and <xccdf:Rule>, but not </Rule> or
 * <RuleResult>). A pure text scan — maximally independent of any converter's
 * parser, mirroring the generic token walk in anchor.go. localName must be a
 * plain element name (no regex metacharacters), which holds for every format.
 */
export function countXmlElements(input: string, localName: string): number {
  const re = new RegExp(`<(?:[\\w.-]+:)?${localName}(?=[\\s/>])`, 'g');
  return (input.match(re) ?? []).length;
}

/**
 * Count, across the whole document at any depth, the array entries held under
 * the given object key (e.g. every "controls" array's elements, including
 * nested ones). Generic walk, independent of converter structs.
 */
export function countJsonItemsUnderKey(input: string, key: string): number {
  return countUnderKey(JSON.parse(input), key);
}

function countUnderKey(value: unknown, key: string): number {
  let n = 0;
  if (Array.isArray(value)) {
    for (const item of value) n += countUnderKey(item, key);
    return n;
  }
  if (value !== null && typeof value === 'object') {
    for (const [k, child] of Object.entries(value as Record<string, unknown>)) {
      if (k === key && Array.isArray(child)) n += child.length;
      n += countUnderKey(child, key);
    }
  }
  return n;
}

/**
 * Count the requirements a converter emitted, across both output shapes:
 * HDFResults carries them under baselines[].requirements; HDFBaseline (e.g. a
 * benchmark-only XCCDF) carries them at the top level. A document has one shape
 * or the other, so summing both is safe. Input may be a JSON string or an
 * already-parsed document.
 */
function totalRequirements(result: unknown): number {
  const doc = (typeof result === 'string' ? JSON.parse(result) : result) as {
    requirements?: unknown[];
    baselines?: Array<{ requirements?: unknown[] }>;
  };
  const top = doc.requirements?.length ?? 0;
  return top + (doc.baselines ?? []).reduce((sum, b) => sum + (b.requirements?.length ?? 0), 0);
}

/**
 * Assert the converter emitted exactly want requirements — the ground-truth
 * anchor. want must come from a source-derived count (the count* helpers above),
 * never from converter output. msg states the source-derived relationship.
 */
export function assertRequirementCount(result: unknown, want: number, msg: string): void {
  expect(
    want,
    `anchor proves nothing with want=0 — use a fixture with >=1 source unit: ${msg}`,
  ).toBeGreaterThan(0);
  expect(totalRequirements(result), msg).toBe(want);
}

/**
 * Count the amendment overrides a VEX importer emitted (top-level overrides[]).
 * VEX importers produce HDF Amendments, not requirements.
 */
function totalOverrides(result: unknown): number {
  const doc = (typeof result === 'string' ? JSON.parse(result) : result) as { overrides?: unknown[] };
  return doc.overrides?.length ?? 0;
}

/**
 * Amendment-output analogue of assertRequirementCount for VEX importers: assert
 * overrides[] length equals a source-derived count.
 */
export function assertOverrideCount(result: unknown, want: number, msg: string): void {
  expect(
    want,
    `anchor proves nothing with want=0 — use a fixture with >=1 source unit: ${msg}`,
  ).toBeGreaterThan(0);
  expect(totalOverrides(result), msg).toBe(want);
}
