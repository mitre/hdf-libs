/**
 * A predicate field's value set, and the normalizer that accepts the three
 * spellings a policy may use for it: a bare scalar for the common single-value
 * case, a list, and a `{not: [...]}` object for exclusion.
 *
 * Negation is PURE: `not` means "does not match any of these", and a requirement
 * whose field is ABSENT satisfies it. The alternative — requiring the field to
 * be present — silently weakens gates, because the requirement a gate most needs
 * to catch is usually the one nobody has touched. `{status: [failed],
 * disposition: {not: [waiver]}}` with `max: 0` must catch a failure nobody
 * adjudicated; under a presence-requiring reading that requirement is excluded
 * and the bound passes.
 *
 * Parity: Values in go/values.go.
 */
/**
 * What a policy may write for a multi-value field: a scalar, a list, or a
 * {not: [...]} object. Normalized to Values before it reaches a matcher.
 */
export type PredicateValue = string | string[] | { not: string | string[] };

export interface Values {
  in: string[];
  not: string[];
}

// NOTE: there is deliberately no exported constructor for a Values here. One
// existed and was a trap: {in: [...]} is the decoder's OUTPUT shape and is
// refused as a policy form, so its result threw when passed back to filter().
// TypeScript callers pass the policy spellings — a scalar, a list, or
// {not: [...]} — and normalizeValues turns them into this. Go's In() is safe
// because Go reaches the decoder by type rather than by normalizing a literal.

/** Whether the field constrains anything at all. */
export function valuesActive(v: Values | undefined): boolean {
  return v !== undefined && (v.in.length > 0 || v.not.length > 0);
}

/**
 * Every value the field names, in either mode, for callers that validate the
 * vocabulary — a value inside `not` must be refused exactly as one outside it
 * is, or a typo there excludes nothing and the predicate matches everything.
 */
export function valuesAll(v: Values | undefined): string[] {
  return v === undefined ? [] : [...v.in, ...v.not];
}

/**
 * Applies the field's own per-value test. `test` reports whether the requirement
 * matches ONE named value; this combines those the way the vocabulary always has
 * — values within a field OR — and then applies the exclusion.
 */
export function valuesMatch(v: Values, test: (value: string) => boolean): boolean {
  if (v.in.length > 0 && !v.in.some(test)) return false;
  if (v.not.length > 0 && v.not.some(test)) return false;
  return true;
}

/**
 * Normalizes whatever a policy carried into a Values. Throws on a shape that is
 * none of the three, so a malformed predicate is refused rather than silently
 * asserting nothing. Parity: Values.UnmarshalYAML / UnmarshalJSON in
 * go/values.go, and the shared case table pins the accepted forms.
 */
export function normalizeValues(raw: unknown): Values {
  if (raw === undefined || raw === null) return { in: [], not: [] };
  if (typeof raw === 'string') return { in: [raw], not: [] };
  if (Array.isArray(raw)) {
    if (!raw.every((v) => typeof v === 'string')) {
      throw new Error('a predicate value is a value, a list, or {not: ...}');
    }
    return { in: raw as string[], not: [] };
  }
  if (typeof raw === 'object') {
    const keys = Object.keys(raw as Record<string, unknown>);
    const other = keys.find((k) => k !== 'not');
    if (other !== undefined) {
      throw new Error(`field "${other}" is not a known form; a predicate value is a value, a list, or {not: ...}`);
    }
    const inner = normalizeValues((raw as { not?: unknown }).not);
    if (inner.not.length > 0) throw new Error('not cannot be nested inside not');
    if (inner.in.length === 0) {
      throw new Error('not excludes nothing; a predicate that asserts nothing is refused');
    }
    return { in: [], not: inner.in };
  }
  throw new Error('a predicate value is a value, a list, or {not: ...}');
}
