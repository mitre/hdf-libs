/**
 * Bridge from schema-typed requirements onto the canonical effective-status
 * helper in @mitre/hdf-utilities, so every consumer computes status through
 * the single shared implementation (twin of shared/go/status.go). The stored
 * effectiveStatus field is never read — it is an output cache (see
 * status-determination.md).
 */

import {
  computeEffectiveStatus,
  computeEffectiveImpact,
  type EffectiveStatusInput,
  type StatusOverrideInput,
} from '@mitre/hdf-utilities';
import type { EvaluatedRequirement } from '@mitre/hdf-schema';

/** RFC3339 string from a schema timestamp (quicktype Date or raw string). */
function stamp(v: unknown): string | undefined {
  if (v instanceof Date) return v.toISOString();
  if (typeof v === 'string' && v !== '') return v;
  return undefined;
}

/** Maps a requirement onto the canonical effective-status input shape. */
export function requirementStatusInput(req: EvaluatedRequirement): EffectiveStatusInput {
  return {
    // Go's typed decode gives an absent impact the zero value, so the ladder
    // there reads it as notApplicable; without the same defaulting here the two
    // languages disagree on a document that omits impact.
    impact: req.impact ?? 0,
    resultStatuses: (req.results ?? []).filter((r) => r != null).map((r) => String(r.status)),
    // A null entry inside the array is valid JSON that Go's typed decode turns
    // into a zero-value struct; reading through it here crashed the converter
    // where the Go peer emitted a row.
    overrides: (req.statusOverrides ?? []).filter((o) => o != null).map(
      (o): StatusOverrideInput => ({
        status: o.status ? String(o.status) : undefined,
        appliedAt: stamp(o.appliedAt),
        expiresAt: stamp(o.expiresAt),
        // Carried so effective IMPACT resolves from the same overrides;
        // eligibility is per-field, so an override may govern one and not the
        // other.
        impact: o.impact?.value,
      })
    ),
  };
}

/** The requirement's canonical effective status via the shared ladder. */
export function requirementEffectiveStatus(req: EvaluatedRequirement): string {
  return computeEffectiveStatus(requirementStatusInput(req));
}

/**
 * The requirement's canonical effective impact via the shared ladder: the
 * governing non-expired impact override's value, else the requirement's own. The
 * stored effectiveImpact field is an output cache and is never read, exactly as
 * effectiveStatus is not. Parity: RequirementEffectiveImpact in shared/go.
 */
export function requirementEffectiveImpact(req: EvaluatedRequirement): number {
  return computeEffectiveImpact(requirementStatusInput(req));
}
