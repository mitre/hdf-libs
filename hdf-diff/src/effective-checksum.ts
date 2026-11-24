import {
  governingOverrideIndex,
  sha256,
  worstStatus,
  type StatusOverrideInput,
} from '@mitre/hdf-utilities';
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
 * Resolves a requirement's impact for the effective checksum: the governing impact
 * override when one exists, else the requirement's own. With no overrides at all it
 * honours a stored effectiveImpact — deliberately, and unlike computeEffectiveImpact in
 * @mitre/hdf-utilities, which never reads the cache. The checksum is an epoch-sensitive
 * contract: a document whose producer recorded a re-score without the override detail
 * would otherwise change its checksum on upgrade with nothing in it having changed. The
 * field is a fallback, not a source: any override at all makes it unread. Pinned by the
 * "stored fallback" test. (Go parity: ComputeEffectiveImpact in
 * go/effective_checksum.go.)
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
  // Overrides and POA&Ms are ONE ordered set compared on appliedAt, not two
  // tiers — the schema defines disposition as 'the most recent non-expired
  // override or POAM governing this requirement', and both carry the same two
  // timestamp fields. Only the override half was ever implemented.
  // Parity: ComputeDisposition in hdf-diff/go/effective_checksum.go.
  const overrides = (requirement['statusOverrides'] as OverrideLike[] | undefined) ?? [];
  const poams = (requirement['poams'] as OverrideLike[] | undefined) ?? [];

  if (overrides.length > 0 || poams.length > 0) {
    const windows = [...overrideWindows(overrides), ...overrideWindows(poams)];
    const i = governingOverrideIndex(windows, () => true, referenceTimestamp);
    if (i < 0) return null;
    if (i < overrides.length) return overrides[i]?.type ?? null;
    // A POA&M's own kind is not a member of Override_Type, which disposition is
    // typed as, so every governing POA&M reports the flat 'poam'.
    return 'poam';
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

/** The folded posture of every entry one requirement id carries. */
export interface FoldedState {
  effectiveStatus: string;
  effectiveImpact: number;
  checksum: EffectiveChecksum;
}

/**
 * Folds every entry an id carries into the single state an event is keyed on. The
 * status is worstStatus over the entries — the roll-up hdf-engine already applies to a
 * requirement's results — the impact is the highest, and the checksum covers each
 * entry's own checksum in document order. A single entry keeps exactly the checksum
 * computeEffectiveChecksum gives it, so a document without repeated ids produces the
 * same stream as before the fold. Peer of the Go FoldEffectiveState.
 */
export async function foldEffectiveState(
  requirements: readonly Record<string, unknown>[],
  referenceTimestamp?: string,
): Promise<FoldedState | null> {
  if (requirements.length === 0) {
    return null;
  }
  const statuses: string[] = [];
  const values: string[] = [];
  let impact = 0;
  for (const requirement of requirements) {
    statuses.push(computeEffectiveStatus(requirement, referenceTimestamp));
    const own = computeEffectiveImpact(requirement, referenceTimestamp);
    if (own > impact) {
      impact = own;
    }
    values.push((await computeEffectiveChecksum(requirement, referenceTimestamp)).value);
  }
  const value = values.length === 1 ? values[0]! : await sha256(JSON.stringify(values));
  return {
    effectiveStatus: worstStatus(statuses),
    effectiveImpact: impact,
    checksum: { algorithm: 'sha256', value },
  };
}
