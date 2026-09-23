// The closed vocabularies a filter value may name, and the aliases accepted for
// them — the TypeScript peer of hdf-engine/go/vocabulary.go, pinned at parity by
// testdata/filter-vocabulary-cases.json, which both suites read.

import { DISPOSITION_VALUES, POAM_VALID, POAM_NONE_VALID, validPoamFilter } from './query.js';

/**
 * The closed vocabulary a status filter may name: the schema's Result_Status
 * enum. It is the EFFECTIVE status that is compared — the resolver a caller
 * injects runs the override ladder first — so these are the values a requirement
 * can present after its amendments are applied.
 */
export const STATUS_VALUES = ['passed', 'failed', 'notApplicable', 'notReviewed', 'error'] as const;

/** The schema's Severity enum, which is also what deriveSeverity returns. */
export const SEVERITY_VALUES = ['critical', 'high', 'medium', 'low', 'informational'] as const;

/**
 * The spellings a value has legitimately arrived under, enumerated rather than
 * derived. An earlier version stripped separators to fold spellings together,
 * which also silently repaired typos: 'wai-ver' became 'waiver'. A closed
 * vocabulary that quietly corrects a misspelling is not closed.
 */
const STATUS_ALIASES: Record<string, string> = {
  not_applicable: 'notApplicable',
  not_reviewed: 'notReviewed',
};
const SEVERITY_ALIASES: Record<string, string> = { none: 'informational' };
const DISPOSITION_ALIASES: Record<string, string> = { false_positive: 'falsePositive' };

/**
 * Folds a value to the form comparisons use. Case only: two spellings are the
 * same value because this file says so, not because enough punctuation was
 * removed to make them collide.
 */
export function normalizeKey(s: string): string {
  return s.trim().toLowerCase();
}

function canonical(
  vocabulary: readonly string[],
  aliases: Record<string, string> | null,
  value: string
): string {
  const key = normalizeKey(value);
  if (aliases && aliases[key]) return aliases[key];
  return vocabulary.find((member) => normalizeKey(member) === key) ?? '';
}

/** Whether s names a status the filter understands, under any accepted spelling. */
export function validStatus(s: string): boolean {
  return canonical(STATUS_VALUES, STATUS_ALIASES, s) !== '';
}

/** Whether s names an override type the filter understands, under any accepted spelling. */
export function validDisposition(s: string): boolean {
  return canonical(DISPOSITION_VALUES, DISPOSITION_ALIASES, s) !== '';
}

/** Whether s names a severity the filter understands, under any accepted spelling. */
export function validSeverity(s: string): boolean {
  return canonical(SEVERITY_VALUES, SEVERITY_ALIASES, s) !== '';
}

/**
 * The canonical spelling of a filter value for the named field, or the value
 * unchanged when the field has no closed vocabulary or the value names no
 * member. Normalizing here rather than in one caller is what makes a threshold
 * rule and an `hdf query` invocation mean the same thing.
 */
export function normalizeFilterValue(field: string, value: string): string {
  switch (field) {
    case 'status':
      return canonical(STATUS_VALUES, STATUS_ALIASES, value) || value;
    case 'severity':
      return canonical(SEVERITY_VALUES, SEVERITY_ALIASES, value) || value;
    case 'disposition':
      return canonical(DISPOSITION_VALUES, DISPOSITION_ALIASES, value) || value;
    case 'poams':
      if (!validPoamFilter(value)) return value;
      return normalizeKey(value) === normalizeKey(POAM_VALID) ? POAM_VALID : POAM_NONE_VALID;
    default:
      return value;
  }
}
