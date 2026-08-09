/**
 * Canonical HDF result-status ordering and effective-status computation.
 *
 * This is the single source of truth for worst-wins roll-up and
 * effective-status selection across hdf-libs (mirrored in Go as
 * hdf-utilities/go status.go). The precedence rules are published in
 * site/docs/architecture/status-determination.md; do not re-implement them.
 */

import { parseTimestamp } from '../string/index.js';

/** Canonical worst-wins ordering, worst first. */
export const STATUS_SEVERITY_ORDER: readonly string[] = [
  'error',
  'failed',
  'passed',
  'notApplicable',
  'notReviewed',
];

/** Severity rank of a status: higher = worse. Unknown statuses rank -1. */
export function statusRank(status: string): number {
  const idx = STATUS_SEVERITY_ORDER.indexOf(status);
  return idx === -1 ? -1 : STATUS_SEVERITY_ORDER.length - 1 - idx;
}

/**
 * Rolls a list of result statuses up to the worst one. An empty list (or a
 * list of only unknown statuses) rolls up to "notReviewed".
 */
export function worstStatus(statuses: readonly string[]): string {
  let worst = 'notReviewed';
  let worstRank = -1;
  for (const s of statuses) {
    const r = statusRank(s);
    if (r > worstRank) {
      worstRank = r;
      worst = s;
    }
  }
  return worst;
}

/**
 * Neutral shape of a status override for effective-status computation.
 * Callers map their concrete types (schema objects or raw JSON) onto it.
 */
export interface StatusOverrideInput {
  /** Empty/undefined means the override carries no status and never governs. */
  status?: string;
  /** RFC3339 timestamp; undefined sorts earliest. */
  appliedAt?: string;
  /** RFC3339 timestamp; undefined means the override never expires. */
  expiresAt?: string;
}

function isExpired(override: StatusOverrideInput, ref: Date): boolean {
  if (!override.expiresAt) return false;
  // parseTimestamp normalizes zone-less values to UTC (a raw `new Date` would
  // read them as host-local and make expiry host-timezone-dependent).
  const expires = parseTimestamp(override.expiresAt);
  return expires !== null && expires <= ref;
}

/**
 * Selects the override that governs a requirement: the most recently applied
 * (by appliedAt) non-expired override that carries a status — matching the
 * schema's definition of disposition ("the most recent non-expired
 * override"). Returns undefined when no override governs.
 */
export function governingStatusOverride(
  overrides: readonly StatusOverrideInput[],
  referenceTimestamp?: string
): StatusOverrideInput | undefined {
  const i = governingStatusOverrideIndex(overrides, referenceTimestamp);
  return i >= 0 ? overrides[i] : undefined;
}

/**
 * Returns the index of the most recently applied (by appliedAt) non-expired
 * override among those for which `eligible` returns true, or -1 when none
 * qualifies. Generalizes governing-override selection to per-field
 * eligibility: the schema defines effectiveStatus, effectiveImpact, and
 * disposition each as "the most recent non-expired override" carrying the
 * relevant field, so callers pass the field-presence check as the predicate.
 */
export function governingOverrideIndex(
  overrides: readonly StatusOverrideInput[],
  eligible: (index: number) => boolean,
  referenceTimestamp?: string
): number {
  const ref = refTime(referenceTimestamp);
  let governing = -1;
  for (let i = 0; i < overrides.length; i++) {
    const override = overrides[i];
    if (!override || !eligible(i) || isExpired(override, ref)) continue;
    if (governing === -1 || appliedTime(override) > appliedTime(overrides[governing]!)) {
      governing = i;
    }
  }
  return governing;
}

/**
 * Index variant of {@link governingStatusOverride}: returns -1 when no
 * override governs. Callers holding richer concrete override types use the
 * index to recover their own object.
 */
export function governingStatusOverrideIndex(
  overrides: readonly StatusOverrideInput[],
  referenceTimestamp?: string
): number {
  return governingOverrideIndex(overrides, (i) => !!overrides[i]?.status, referenceTimestamp);
}

function appliedTime(override: StatusOverrideInput): number {
  if (!override.appliedAt) return Number.NEGATIVE_INFINITY;
  return parseTimestamp(override.appliedAt)?.getTime() ?? Number.NEGATIVE_INFINITY;
}

function refTime(referenceTimestamp?: string): Date {
  const parsed = referenceTimestamp ? parseTimestamp(referenceTimestamp) : null;
  return parsed ?? new Date();
}

/** Neutral shape of a requirement for effective-status computation. */
export interface EffectiveStatusInput {
  impact: number;
  /** The stored effectiveStatus field; undefined means unset. */
  effectiveStatus?: string;
  resultStatuses?: readonly string[];
  overrides?: readonly StatusOverrideInput[];
}

/**
 * Determines a requirement's effective status — the single canonical
 * implementation of the precedence in status-determination.md:
 *
 * 1. impact === 0 → "notApplicable", regardless of results or overrides
 * 2. the governing (most recent non-expired) status override's status
 * 3. the stored effectiveStatus, honored only when NO overrides are present —
 *    effectiveStatus is state derived from overrides, so when every override
 *    has expired it is stale and the result roll-up wins
 * 4. worst-wins roll-up of the result statuses
 * 5. no results → "notReviewed"
 */
export function computeEffectiveStatus(
  input: EffectiveStatusInput,
  referenceTimestamp?: string
): string {
  if (input.impact === 0) {
    return 'notApplicable';
  }
  const overrides = input.overrides ?? [];
  if (overrides.length > 0) {
    const governing = governingStatusOverride(overrides, referenceTimestamp);
    if (governing?.status) return governing.status;
    return worstStatus(input.resultStatuses ?? []);
  }
  if (input.effectiveStatus) {
    return input.effectiveStatus;
  }
  return worstStatus(input.resultStatuses ?? []);
}
