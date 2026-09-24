// Amendments-layer resolution for schema-typed requirements: the engine's bridge
// onto the canonical ladders in @mitre/hdf-utilities. Its own module because
// query.ts and compliance.ts both need it and query.ts already imports
// compliance.ts — putting it in either would either fork the mapping or make the
// two import each other. Parity: EffectiveImpactOf and statusOverrideInputs in
// go/filter.go.

import type { EvaluatedRequirement } from '@mitre/hdf-schema';
import { computeEffectiveImpact, type StatusOverrideInput } from '@mitre/hdf-utilities';

/**
 * Maps a requirement's schema overrides onto the shared helper's neutral shape.
 * The schema types render timestamps as Date; the helper takes the RFC3339
 * strings they came from, so convert rather than widening it.
 */
export function overrideInputs(control: EvaluatedRequirement): StatusOverrideInput[] {
  return (control.statusOverrides ?? []).map((o) => ({
    status: o.status as string | undefined,
    appliedAt: new Date(o.appliedAt).toISOString(),
    expiresAt: new Date(o.expiresAt).toISOString(),
    // Carried so effective IMPACT resolves from the same overrides; eligibility
    // is per-field, so one override may govern one and not the other.
    impact: o.impact?.value,
  }));
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
