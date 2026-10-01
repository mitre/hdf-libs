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
  governingOverrideIndex,
  governingImpactOverrideIndex,
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

/**
 * The override that governs a requirement — the most recently applied
 * non-expired one, whatever it carries — or undefined when none does.
 *
 * Resolution is by appliedAt, never by array position. The schema's description
 * says the most recent override "should be first in array", but nothing in this
 * repo sorts and both writers append, so on a document our own tooling amended
 * twice the newest override is LAST and statusOverrides[0] is the oldest.
 *
 * Parity: GoverningOverride in shared/go/status.go.
 */
export function governingOverride(
  req: EvaluatedRequirement,
  now?: string
): NonNullable<EvaluatedRequirement['statusOverrides']>[number] | undefined {
  const overrides = (req.statusOverrides ?? []).filter((o) => o != null);
  const i = governingOverrideIndex(
    overrides.map((o) => ({
      status: o.status ? String(o.status) : undefined,
      appliedAt: stamp(o.appliedAt),
      expiresAt: stamp(o.expiresAt),
    })),
    () => true,
    now
  );
  return i >= 0 ? overrides[i] : undefined;
}

/**
 * The override that governs a requirement's IMPACT — the most recently applied
 * non-expired one CARRYING an impact — or undefined when none does. Eligibility
 * is per field, so a newer override that says nothing about impact does not
 * displace an older re-score.
 *
 * Parity: GoverningImpactOverrideIndex usage in shared/go/checklist.
 */
export function governingImpactOverride(
  req: EvaluatedRequirement,
  now?: string
): NonNullable<EvaluatedRequirement['statusOverrides']>[number] | undefined {
  const overrides = (req.statusOverrides ?? []).filter((o) => o != null);
  const i = governingImpactOverrideIndex(
    overrides.map((o) => ({
      appliedAt: stamp(o.appliedAt),
      expiresAt: stamp(o.expiresAt),
      impact: o.impact?.value,
    })),
    now
  );
  return i >= 0 ? overrides[i] : undefined;
}

/**
 * The type of the override that governs a requirement, or '' when none does —
 * the disposition twin of requirementEffectiveStatus and
 * requirementEffectiveImpact.
 *
 * Whenever the requirement carries overrides, they decide: the stored
 * disposition field is an output cache that can disagree with them, or be stale,
 * and it is not read. The one exception is a requirement carrying NO overrides
 * at all, where the stored field is the only evidence in the document.
 *
 * Parity: RequirementDisposition in shared/go/status.go.
 */
export function requirementDisposition(req: EvaluatedRequirement, now?: string): string {
  const governing = governingOverride(req, now);
  // `?? ''` matters: a type-less override is schema-invalid but reaches here,
  // because the converters structurally check their input rather than
  // schema-validate it. String(undefined) would emit the literal "undefined".
  if (governing) return String(governing.type ?? '');
  // The one exception: with NO overrides the stored field is the only evidence
  // the document carries, so passing it through preserves information an export
  // would otherwise drop. See the Go twin for why this is a fallback, not a
  // source, and why hdf-engine's filter deliberately does not take it.
  const overrides = (req.statusOverrides ?? []).filter((o) => o != null);
  if (overrides.length === 0 && req.disposition) return String(req.disposition);
  return '';
}
