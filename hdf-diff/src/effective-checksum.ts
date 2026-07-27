import { sha256 } from '@mitre/hdf-utilities';
import { computeEffectiveStatus } from './status.js';

interface ImpactOverrideLike {
  value: number;
}

interface OverrideLike {
  type?: string;
  status?: string;
  impact?: ImpactOverrideLike;
  expiresAt: string;
}

export interface EffectiveChecksum {
  algorithm: 'sha256';
  value: string;
}

function referenceTimeMs(referenceTimestamp?: string): number {
  return referenceTimestamp ? new Date(referenceTimestamp).getTime() : Date.now();
}

/**
 * Determine the effective impact of a requirement: the first non-expired
 * override carrying an impact value wins; with no overrides, a stored
 * effectiveImpact field is honored; otherwise the base impact.
 * Mirrors computeEffectiveStatus's resolution priority (Go parity:
 * ComputeEffectiveImpact in hdf-diff/go/effective_checksum.go).
 */
export function computeEffectiveImpact(
  requirement: Record<string, unknown>,
  referenceTimestamp?: string,
): number {
  const baseImpact = (requirement['impact'] as number | undefined) ?? 0;
  const overrides = requirement['statusOverrides'] as OverrideLike[] | undefined;

  if (overrides && overrides.length > 0) {
    const refTime = referenceTimeMs(referenceTimestamp);
    for (const override of overrides) {
      const expiresAt = new Date(override.expiresAt).getTime();
      if (expiresAt > refTime && override.impact) {
        return override.impact.value;
      }
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
 * Return the Override_Type of the governing (first non-expired) override,
 * a stored disposition field when no overrides are present, or null.
 * Mirrors computeEffectiveStatus's governing-override selection (Go parity:
 * ComputeDisposition).
 */
export function computeDisposition(
  requirement: Record<string, unknown>,
  referenceTimestamp?: string,
): string | null {
  const overrides = requirement['statusOverrides'] as OverrideLike[] | undefined;

  if (overrides && overrides.length > 0) {
    const refTime = referenceTimeMs(referenceTimestamp);
    for (const override of overrides) {
      const expiresAt = new Date(override.expiresAt).getTime();
      if (expiresAt > refTime && override.type) {
        return override.type;
      }
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
 * referenceTimestamp, never wall clock, for determinism.
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
