// Amendments-layer resolution for schema-typed requirements: the engine's bridge
// onto the canonical ladders in @mitre/hdf-utilities. Its own module because
// query.ts and compliance.ts both need it and query.ts already imports
// compliance.ts — putting it in either would either fork the mapping or make the
// two import each other. Parity: EffectiveImpactOf and statusOverrideInputs in
// go/filter.go.

import type { EvaluatedRequirement } from '@mitre/hdf-schema';
import { computeEffectiveImpact, parseTimestamp, type StatusOverrideInput, isGoZeroTime } from '@mitre/hdf-utilities';

/**
 * Maps a requirement's schema overrides onto the shared helper's neutral shape,
 * whose timestamps are the RFC3339 strings the schema's Date fields came from.
 */
export function overrideInputs(control: EvaluatedRequirement): StatusOverrideInput[] {
  // One entry per override, slot preserved even for a member that carries
  // nothing: governingPoamType reads the index past this array's length as a
  // poam index, so dropping a slot would name the wrong poam.
  return (control.statusOverrides ?? []).map((o) => ({
    status: o?.status as string | undefined,
    appliedAt: rfc3339(o?.appliedAt),
    expiresAt: rfc3339(o?.expiresAt),
    // Carried so effective IMPACT resolves from the same overrides; eligibility
    // is per-field, so one override may govern one and not the other.
    impact: o?.impact?.value,
  }));
}

/**
 * The schema types these as Date, but a parsed document carries the RFC3339
 * strings they came from, so both shapes arrive here. A string passes through
 * for the helper's parseTimestamp to read, which keeps a zone-less value UTC
 * instead of host-local.
 *
 * Absent, unparseable, and Go's zero time all yield undefined, matching Go:
 * its timestamps are non-pointer time.Time, so an unset one round-trips as
 * 0001-01-01T00:00:00Z and decodes back to IsZero, and its ladder reads that as
 * never expiring rather than as a real instant in year 1.
 */
function rfc3339(value: Date | string | undefined): string | undefined {
  if (!value) return undefined;
  const parsed = typeof value === 'string' ? parseTimestamp(value) : value;
  if (parsed === null || Number.isNaN(parsed.getTime())) return undefined;
  if (isGoZeroTime(parsed)) return undefined;
  return typeof value === 'string' ? value : parsed.toISOString();
}

/**
 * The requirement's impact after its governing non-expired impact override, else
 * its own. Computed rather than injected the way status is, because impact has
 * no competing display conventions to reconcile — the ladder in hdf-utilities is
 * canonical. An undefined reference means now.
 */
export function effectiveImpactOf(control: EvaluatedRequirement, now?: string): number {
  return computeEffectiveImpact({ impact: control.impact, overrides: overrideInputs(control) }, now);
}
