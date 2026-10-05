/**
 * Bridge from schema-typed requirements onto the canonical effective-status
 * helper in @mitre/hdf-utilities, so every consumer computes status through
 * the single shared implementation (twin of shared/go/status.go). The stored
 * effectiveStatus field is never read — it is an output cache (see
 * status-determination.md).
 */

import {
  computeEffectiveStatus,
  parseTimestamp,
  type EffectiveStatusInput,
  type StatusOverrideInput,
} from '@mitre/hdf-utilities';
import type { EvaluatedRequirement } from '@mitre/hdf-schema';

const GO_ZERO_TIME_MS = new Date('0001-01-01T00:00:00Z').getTime();

/**
 * Normalizes Go's zero time to absent — the single rule every consumer of a
 * schema timestamp in this package shares. StatusOverride's timestamps are
 * non-pointer time.Time in Go, so an unset one round-trips as
 * 0001-01-01T00:00:00Z and decodes back to IsZero — "never set", which is what
 * the Go peers report. Carried through raw it would instead read here as a real
 * instant in year 1, before every reference time.
 */
export function absentIfGoZeroTime(value: string | undefined): string | undefined {
  if (value === undefined) return undefined;
  const parsed = parseTimestamp(value);
  return parsed !== null && parsed.getTime() === GO_ZERO_TIME_MS ? undefined : value;
}

/**
 * RFC3339 string from a schema timestamp (quicktype Date or raw string), with
 * Go's zero time read as absent.
 */
export function schemaTimestamp(v: unknown): string | undefined {
  if (v instanceof Date) return absentIfGoZeroTime(v.toISOString());
  if (typeof v === 'string' && v !== '') return absentIfGoZeroTime(v);
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
        appliedAt: schemaTimestamp(o.appliedAt),
        expiresAt: schemaTimestamp(o.expiresAt),
      })
    ),
  };
}

/** The requirement's canonical effective status via the shared ladder. */
export function requirementEffectiveStatus(req: EvaluatedRequirement): string {
  return computeEffectiveStatus(requirementStatusInput(req));
}
