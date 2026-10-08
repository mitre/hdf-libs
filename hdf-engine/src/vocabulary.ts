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
 * The forms a value has legitimately arrived under, enumerated rather than
 * derived. An earlier version stripped separators to fold them together, which
 * also silently repaired typos: 'wai-ver' became 'waiver'. A closed vocabulary
 * that quietly corrects a misspelling is not closed.
 *
 * The status and disposition entries are separator variants of one name. The
 * severity entry is not: 3.7.0 renamed the bucket, and 'none' is the name it had
 * before, kept so a command line or spec written against the old vocabulary
 * selects what it always did.
 */
/**
 * `advertise` records which forms help text should TEACH, so that is a property of
 * the entry rather than of whichever string literal a command happens to hold. A
 * separator variant is part of the CLI's display vocabulary and is taught; a
 * retired name is honoured and never taught, because advertising it would hand a
 * new user the name a release replaced. Parity: FilterAlias in go/vocabulary.go.
 */
export interface FilterAlias {
  form: string;
  means: string;
  advertise: boolean;
}

const STATUS_ALIAS_LIST: FilterAlias[] = [
  { form: 'not_applicable', means: 'notApplicable', advertise: true },
  { form: 'not_reviewed', means: 'notReviewed', advertise: true },
];
const SEVERITY_ALIAS_LIST: FilterAlias[] = [{ form: 'none', means: 'informational', advertise: false }];
const DISPOSITION_ALIAS_LIST: FilterAlias[] = [
  { form: 'false_positive', means: 'falsePositive', advertise: true },
];

/** Derived from the lists, so an alias cannot be accepted without declaring whether it is advertised. */
function aliasMap(aliases: FilterAlias[]): Record<string, string> {
  return Object.fromEntries(aliases.map((a) => [a.form, a.means]));
}

const STATUS_ALIASES = aliasMap(STATUS_ALIAS_LIST);
const SEVERITY_ALIASES = aliasMap(SEVERITY_ALIAS_LIST);
const DISPOSITION_ALIASES = aliasMap(DISPOSITION_ALIAS_LIST);

/** The accepted non-canonical forms for a field, or undefined when it has no closed vocabulary. */
export function filterAliases(field: string): FilterAlias[] | undefined {
  switch (field) {
    case 'status':
      return STATUS_ALIAS_LIST;
    case 'severity':
      return SEVERITY_ALIAS_LIST;
    case 'disposition':
      return DISPOSITION_ALIAS_LIST;
    default:
      return undefined;
  }
}

/** The canonical vocabulary for a field, or undefined when it has no closed one. */
export function filterValues(field: string): readonly string[] | undefined {
  switch (field) {
    case 'status':
      return STATUS_VALUES;
    case 'severity':
      return SEVERITY_VALUES;
    case 'disposition':
      return DISPOSITION_VALUES;
    default:
      return undefined;
  }
}

/**
 * The forms a help string or tool schema should name for a field: the canonical
 * vocabulary, then the aliases marked for teaching. Every value here is accepted,
 * but not everything accepted is here — a retired name is deliberately absent.
 * Parity: AdvertisedFilterValues in go/vocabulary.go.
 */
export function advertisedFilterValues(field: string): string[] | undefined {
  const canonical = filterValues(field);
  if (!canonical) return undefined;
  return [...canonical, ...(filterAliases(field) ?? []).filter((a) => a.advertise).map((a) => a.form)];
}

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

/** Whether s names a status the filter understands, in any accepted form. */
export function validStatus(s: string): boolean {
  return canonical(STATUS_VALUES, STATUS_ALIASES, s) !== '';
}

/** Whether s names an override type the filter understands, in any accepted form. */
export function validDisposition(s: string): boolean {
  return canonical(DISPOSITION_VALUES, DISPOSITION_ALIASES, s) !== '';
}

/** Whether s names a severity the filter understands, in any accepted form. */
export function validSeverity(s: string): boolean {
  return canonical(SEVERITY_VALUES, SEVERITY_ALIASES, s) !== '';
}

/**
 * The canonical form of a filter value for the named field, or the value
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
