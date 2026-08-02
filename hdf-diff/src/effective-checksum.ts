import { governingOverrideIndex, sha256, type StatusOverrideInput } from '@mitre/hdf-utilities';
import { computeEffectiveStatus } from './status.js';

interface ImpactOverrideLike {
  value: number;
}

interface OverrideLike {
  type?: string;
  status?: string;
  impact?: ImpactOverrideLike;
  appliedAt?: string;
  expiresAt: string;
}

export interface EffectiveChecksum {
  algorithm: 'sha256';
  value: string;
}

/** Maps overrides onto the shared neutral selection shape (applied/expiry
 * window only; eligibility is passed separately). */
function overrideWindows(overrides: readonly OverrideLike[]): StatusOverrideInput[] {
  return overrides.map((o) => ({ appliedAt: o.appliedAt, expiresAt: o.expiresAt }));
}

/**
 * Determine the effective impact of a requirement: the most recently applied
 * non-expired override carrying an impact value wins (the schema's definition
 * of effectiveImpact, selected by the shared governing helper); with no
 * overrides, a stored effectiveImpact field is honored; otherwise the base
 * impact. (Go parity: ComputeEffectiveImpact in hdf-diff/go/effective_checksum.go.)
 */
export function computeEffectiveImpact(
  requirement: Record<string, unknown>,
  referenceTimestamp?: string,
): number {
  const baseImpact = (requirement['impact'] as number | undefined) ?? 0;
  const overrides = requirement['statusOverrides'] as OverrideLike[] | undefined;

  if (overrides && overrides.length > 0) {
    const i = governingOverrideIndex(
      overrideWindows(overrides),
      (idx) => overrides[idx]?.impact !== undefined,
      referenceTimestamp,
    );
    if (i >= 0) {
      return overrides[i]!.impact!.value;
    }
    return baseImpact;
  }

  const effectiveImpact = requirement['effectiveImpact'] as number | undefined;
  if (effectiveImpact !== undefined) {
    return effectiveImpact;
  }
  return baseImpact;
}

/**
 * Return the Override_Type of the governing (most recently applied
 * non-expired) override, a stored disposition field when no overrides are
 * present, or null. (Go parity: ComputeDisposition.)
 */
export function computeDisposition(
  requirement: Record<string, unknown>,
  referenceTimestamp?: string,
): string | null {
  const overrides = requirement['statusOverrides'] as OverrideLike[] | undefined;

  if (overrides && overrides.length > 0) {
    const i = governingOverrideIndex(overrideWindows(overrides), () => true, referenceTimestamp);
    if (i >= 0) {
      return overrides[i]?.type ?? null;
    }
    return null;
  }

  const disposition = requirement['disposition'] as string | undefined;
  return disposition ?? null;
}

/**
 * Hash the resolved effective posture of a requirement: sha256 over the
 * canonical JSON {"status":<resolved>,"impact":<resolved>,"disposition":<type|null>}.
 * Flips exactly when the operative status, impact, or disposition changes;
 * stable under all other document churn. Byte-identical with the Go
 * implementation (ComputeEffectiveChecksum) — the key order of the canonical
 * object is part of the contract. Pass the document timestamp as
 * referenceTimestamp for determinism. A missing or unparseable reference
 * falls back to the wall clock inside the shared governing-override helper,
 * so callers that need reproducible output must always supply a valid
 * timestamp.
 */
export async function computeEffectiveChecksum(
  requirement: Record<string, unknown>,
  referenceTimestamp?: string,
): Promise<EffectiveChecksum> {
  const canonical = JSON.stringify({
    status: computeEffectiveStatus(requirement, referenceTimestamp),
    impact: computeEffectiveImpact(requirement, referenceTimestamp),
    disposition: computeDisposition(requirement, referenceTimestamp),
  });
  return { algorithm: 'sha256', value: await sha256(canonical) };
}
