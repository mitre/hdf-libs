// Document-type detection — the TypeScript peer of hdf-engine/go/detect.go.
// Fingerprints an HDF document by its root keys and returns the schema type
// string. Kept at behavioural parity with the Go implementation (see
// go/detect_test.go and src/detect.test.ts, which assert both against the same
// bundled schema examples).

/** The eight HDF document type strings, matching validators.Type* in Go. */
export type HdfDocType =
  | 'results'
  | 'baseline'
  | 'system'
  | 'plan'
  | 'amendments'
  | 'evidence-package'
  | 'comparison'
  | 'requirement-change-event'
  | '';

/**
 * Detect fingerprints an HDF document by its root keys and returns the schema
 * type string, or '' when the input is not a JSON object or matches no known
 * HDF document type.
 */
export function detect(input: string): HdfDocType {
  let parsed: unknown;
  try {
    parsed = JSON.parse(input);
  } catch {
    return '';
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    return '';
  }
  const doc = parsed as Record<string, unknown>;
  const has = (...keys: string[]): boolean =>
    keys.every((k) => Object.prototype.hasOwnProperty.call(doc, k));

  // Most specific first. A requirement-change-event carries the singular
  // requirementId together with the state/before/after triad — a combination
  // no other HDF document type has — so it is checked ahead of the rest.
  if (has('requirementId', 'state', 'before', 'after')) return 'requirement-change-event';

  if (has('contents')) return 'evidence-package';
  if (has('overrides')) return 'amendments';
  if (has('assessments')) return 'plan';
  if (has('comparisonMode')) return 'comparison';
  if (has('baselines')) return 'results';
  if (has('components')) return 'system';
  if (has('requirements')) return 'baseline';
  return '';
}
