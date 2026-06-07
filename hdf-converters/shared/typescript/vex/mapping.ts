/**
 * Shared mapping between VEX (OpenVEX, CSAF VEX, CycloneDX VEX) and HDF
 * Amendments. Importers normalize ecosystem-specific statuses + justifications
 * to the canonical forms here; exporters render HDF override state back to
 * the canonical VEX shape.
 *
 * Synthesis happens only where the consumer has explicitly acted. The
 * helper never invents amendments from raw findings, and never claims a
 * real system is patched without a closure amendment chained on top of an
 * open POA&M (real-system vs abstract-vuln distinction).
 */

import type { Evidence, StandaloneOverride } from '@mitre/hdf-schema';
import {
  EvidenceType,
  Justification,
  OverrideType,
  ResultStatus,
} from '@mitre/hdf-schema';

/** Canonical VEX status across OpenVEX / CSAF / CycloneDX. */
export const VexStatus = {
  NotAffected: 'not_affected',
  Affected: 'affected',
  Fixed: 'fixed',
  UnderInvestigation: 'under_investigation',
} as const;

export type VexStatus = (typeof VexStatus)[keyof typeof VexStatus];

/**
 * Map an ecosystem-specific status string to the canonical VexStatus.
 * Returns undefined for values without a clean mapping — caller should warn
 * and skip, not guess.
 */
export function normalizeStatus(raw: string): VexStatus | undefined {
  switch (raw.trim().toLowerCase()) {
    case 'not_affected':
    case 'known_not_affected':
    case 'false_positive':
      return VexStatus.NotAffected;
    case 'affected':
    case 'known_affected':
    case 'exploitable':
      return VexStatus.Affected;
    case 'fixed':
    case 'first_fixed':
    case 'resolved':
    case 'resolved_with_pedigree':
      return VexStatus.Fixed;
    case 'under_investigation':
    case 'in_triage':
      return VexStatus.UnderInvestigation;
    default:
      return undefined;
  }
}

/**
 * Map an ecosystem-specific justification string to the canonical HDF
 * Justification enum. Returns undefined for unknown values; callers SHOULD
 * preserve the original string in evidence[] or reason instead of dropping
 * it (the schema spec wants pass-through on unknown values, not rejection).
 *
 * CycloneDX adds vocabulary HDF does not yet model (requires_configuration,
 * protected_by_compiler, etc.); those are deliberately returned as unknown
 * so the converter has a chance to log + preserve the raw value.
 */
export function normalizeJustification(raw: string): Justification | undefined {
  switch (raw.trim().toLowerCase()) {
    case 'component_not_present':
    case 'code_not_present':
      return Justification.ComponentNotPresent;
    case 'vulnerable_code_not_present':
      return Justification.VulnerableCodeNotPresent;
    case 'vulnerable_code_not_in_execute_path':
    case 'code_not_reachable':
      return Justification.VulnerableCodeNotInExecutePath;
    case 'vulnerable_code_cannot_be_controlled_by_adversary':
      return Justification.VulnerableCodeCannotBeControlledByAdversary;
    case 'inline_mitigations_already_exist':
    case 'protected_by_mitigating_control':
      return Justification.InlineMitigationsAlreadyExist;
    default:
      return undefined;
  }
}

export interface ImportTarget {
  overrideType: OverrideType;
  status?: ResultStatus;
  /** True when the canonical VEX status implies the importer should
   *  populate justification on the synthesized override (not_affected). */
  setJustification: boolean;
  /** POAM action_statement template for the "fixed" path. Empty otherwise. */
  poamActionTemplate: string;
}

/**
 * Return the amendment shape an importer should produce for a canonical VEX
 * status. Returns undefined for "affected" and "under_investigation" — those
 * are informational; the consumer creates an amendment later if they act.
 */
export function importTargetFor(status: VexStatus): ImportTarget | undefined {
  switch (status) {
    case VexStatus.NotAffected:
      return {
        overrideType: OverrideType.FalsePositive,
        status: ResultStatus.Passed,
        setJustification: true,
        poamActionTemplate: '',
      };
    case VexStatus.Fixed:
      return {
        overrideType: OverrideType.Poam,
        // Status stays 'failed' on the open POA&M: VEX 'fixed' is an
        // abstract supplier claim about a product version, not evidence
        // the assessed system has the patch. Re-scan is required to change
        // the effective status.
        status: ResultStatus.Failed,
        setJustification: false,
        poamActionTemplate:
          'vendor reports fix; apply and re-scan to verify',
      };
    case VexStatus.Affected:
    case VexStatus.UnderInvestigation:
      return undefined;
    default:
      return undefined;
  }
}

/**
 * Return the canonical VEX status an exporter should emit for an HDF
 * override. Returns undefined when no VEX statement should be emitted —
 * the consumer has not acted, and VEX requires a deliberate statement.
 *
 * `allMilestonesCompleted` and `closureChained` are consulted only for
 * POA&M overrides. Closure is signalled by BOTH flags being true; either
 * alone is insufficient.
 */
export function exportStatusFor(
  override: StandaloneOverride | undefined,
  allMilestonesCompleted: boolean,
  closureChained: boolean,
): VexStatus | undefined {
  if (!override) {
    return undefined;
  }
  if (override.justification) {
    return VexStatus.NotAffected;
  }
  switch (override.type) {
    case OverrideType.FalsePositive:
    case OverrideType.Attestation:
    case OverrideType.Inherited:
      return VexStatus.NotAffected;
    case OverrideType.Waiver:
    case OverrideType.RiskAdjustment:
    case OverrideType.OperationalRequirement:
      return VexStatus.Affected;
    case OverrideType.Poam:
      return allMilestonesCompleted && closureChained
        ? VexStatus.Fixed
        : VexStatus.Affected;
    default:
      return undefined;
  }
}

/**
 * Build an HDF Evidence entry pointing at the upstream VEX document. Used by
 * importers to preserve provenance even though we lose the structured
 * statement_id. Returns undefined when sourceURI is empty — don't fabricate.
 */
export function supplierEvidence(
  sourceURI: string,
  description?: string,
): Evidence | undefined {
  if (!sourceURI.trim()) {
    return undefined;
  }
  return {
    type: EvidenceType.URL,
    data: sourceURI,
    description: description?.trim() ? description : 'Upstream VEX statement',
  };
}
