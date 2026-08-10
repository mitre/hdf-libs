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

import type { AffectedPackage, Evidence, StandaloneOverride } from '@mitre/hdf-schema';
import {
  Ecosystem,
  EvidenceType,
  Justification,
  OverrideType,
  ResultStatus,
} from '@mitre/hdf-schema';
import { parsePurl } from '@mitre/hdf-utilities';

/** Canonical VEX status across OpenVEX / CSAF / CycloneDX. */
export const VexStatus = {
  NotAffected: 'not_affected',
  Affected: 'affected',
  Fixed: 'fixed',
  UnderInvestigation: 'under_investigation',
} as const;

export type VexStatus = (typeof VexStatus)[keyof typeof VexStatus];

/**
 * Normalize a justification token to snake_case lowercase so both the
 * snake_case vocabularies (OpenVEX / CSAF / CycloneDX) and the SPDX-3
 * camelCase vocabulary (vulnerableCodeNotInExecutePath) match the same switch
 * arm. Snake_case input is unchanged (no camelCase boundary to split), so the
 * transform is a superset — existing callers are unaffected.
 */
function canonicalizeJustification(raw: string): string {
  return raw
    .trim()
    .replace(/([a-z0-9])([A-Z])/g, '$1_$2')
    .toLowerCase();
}

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
 * log unknown values rather than silently dropping (the schema spec wants
 * pass-through, but practically we expect the enum to be extended when a
 * new vocabulary is integrated rather than carrying raw labels
 * indefinitely).
 *
 * The HDF Justification enum (v3.2.x) covers:
 *   - the original OpenVEX / CSAF VEX five values
 *   - CycloneDX-specific reachability values (requires_*, protected_*)
 *     that describe why a vulnerable code path is unreachable in the
 *     deployed configuration.
 *
 * Accepts both snake_case (OpenVEX/CSAF/CycloneDX) and camelCase (SPDX-3
 * security profile, e.g. vulnerableCodeNotInExecutePath) spellings.
 */
export function normalizeJustification(raw: string): Justification | undefined {
  switch (canonicalizeJustification(raw)) {
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
    case 'requires_configuration':
      return Justification.RequiresConfiguration;
    case 'requires_dependency':
      return Justification.RequiresDependency;
    case 'requires_environment':
      return Justification.RequiresEnvironment;
    case 'protected_by_compiler':
      return Justification.ProtectedByCompiler;
    case 'protected_at_runtime':
      return Justification.ProtectedAtRuntime;
    case 'protected_at_perimeter':
      return Justification.ProtectedAtPerimeter;
    default:
      return undefined;
  }
}

/**
 * Render an HDF Justification value as the CycloneDX-native vocabulary.
 * CycloneDX uses short-form names (code_not_present, code_not_reachable,
 * protected_by_mitigating_control) for the three justifications shared
 * with OpenVEX/CSAF, and shares the six CycloneDX-specific reachability
 * values verbatim.
 *
 * Returns undefined when the HDF value has no equivalent in CycloneDX's
 * enum (vulnerable_code_not_present and
 * vulnerable_code_cannot_be_controlled_by_adversary). Callers should
 * omit the justification field in that case.
 */
export function justificationForCycloneDX(j: Justification): string | undefined {
  switch (j) {
    case Justification.ComponentNotPresent:
      return 'code_not_present';
    case Justification.VulnerableCodeNotInExecutePath:
      return 'code_not_reachable';
    case Justification.InlineMitigationsAlreadyExist:
      return 'protected_by_mitigating_control';
    case Justification.RequiresConfiguration:
    case Justification.RequiresDependency:
    case Justification.RequiresEnvironment:
    case Justification.ProtectedByCompiler:
    case Justification.ProtectedAtRuntime:
    case Justification.ProtectedAtPerimeter:
      return String(j);
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
    /* c8 ignore next 2 — every VexStatus has a case above */
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
    /* c8 ignore next 2 — every OverrideType has a case above */
    default:
      return undefined;
  }
}

// Maps PURL `type` segment → AffectedPackage.ecosystem. Unknown types fall
// back to `generic`, which the schema enum permits as a catch-all.
const ECOSYSTEM_FROM_PURL_TYPE: Record<string, Ecosystem> = {
  npm: Ecosystem.Npm,
  pypi: Ecosystem.Pypi,
  rpm: Ecosystem.RPM,
  deb: Ecosystem.Deb,
  maven: Ecosystem.Maven,
  gem: Ecosystem.Gem,
  nuget: Ecosystem.Nuget,
  golang: Ecosystem.Go,
  go: Ecosystem.Go,
  cargo: Ecosystem.Cargo,
};

/**
 * Build an AffectedPackage from a single product identifier string emitted
 * by a VEX format. Recognizes PURLs and CPE 2.3 strings; returns undefined
 * for opaque identifiers (importer should drop the entry — schema additions
 * forbid fabricating name+version).
 */
export function affectedPackageFromIdentifier(
  identifier: string,
): AffectedPackage | undefined {
  if (!identifier) return undefined;
  if (identifier.startsWith('pkg:')) {
    const parsed = parsePurl(identifier);
    if (parsed) {
      const pkg: AffectedPackage = { purl: identifier };
      /* c8 ignore next 2 — parsePurl populates name/version when the
         identifier was a well-formed purl; the absent branches require a
         malformed-but-prefixed input that loses these fields without
         triggering the outer null return. Defensive. */
      if (parsed.name) pkg.name = parsed.name;
      if (parsed.version) pkg.version = parsed.version;
      pkg.ecosystem = ECOSYSTEM_FROM_PURL_TYPE[parsed.type] ?? Ecosystem.Generic;
      return pkg;
    }
    // Malformed purl with the prefix — preserve as purl-only.
    return { purl: identifier };
  }
  if (identifier.startsWith('cpe:2.3:')) {
    return { cpe: identifier };
  }
  return undefined;
}

/**
 * Build a unique list of AffectedPackage entries from a sequence of product
 * identifier strings. Empty / unresolvable identifiers are dropped; duplicate
 * purls/cpes/names are collapsed.
 */
export function affectedPackagesFromIdentifiers(
  identifiers: readonly string[],
): AffectedPackage[] {
  const out: AffectedPackage[] = [];
  const seen = new Set<string>();
  for (const id of identifiers) {
    const pkg = affectedPackageFromIdentifier(id);
    if (!pkg) continue;
    /* c8 ignore next — affectedPackageFromIdentifier always emits either
       purl or cpe, so the name fallback branch isn't reachable through
       this caller. Kept for safety if a hand-built AffectedPackage flows
       through a future caller. */
    const key = pkg.purl ?? pkg.cpe ?? `${pkg.name ?? ''}@${pkg.version ?? ''}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(pkg);
  }
  return out;
}

/**
 * Render an AffectedPackage as a single identifier string suitable for
 * round-tripping into a VEX format. Prefers purl > cpe > name@version.
 * Returns undefined when nothing identifying is set.
 */
export function affectedPackageToIdentifier(
  pkg: AffectedPackage,
): string | undefined {
  if (pkg.purl) return pkg.purl;
  if (pkg.cpe) return pkg.cpe;
  if (pkg.name && pkg.version) return `${pkg.name}@${pkg.version}`;
  if (pkg.name) return pkg.name;
  return undefined;
}

/** Replace the `@version` segment of a purl (between `@` and `?`/`#`), inserting one if absent. */
export function swapPurlVersion(purl: string, version: string): string {
  const at = purl.indexOf('@');
  if (at >= 0) {
    const rest = purl.slice(at + 1);
    const end = rest.search(/[?#]/);
    const tail = end >= 0 ? rest.slice(end) : '';
    return `${purl.slice(0, at)}@${version}${tail}`;
  }
  const end = purl.search(/[?#]/);
  return end >= 0 ? `${purl.slice(0, end)}@${version}${purl.slice(end)}` : `${purl}@${version}`;
}

/**
 * Identifier for the FIXED version of a package (purl with the version swapped
 * to fixedInVersion, or name@fixedInVersion). Undefined when there is no
 * fixedInVersion or no purl/name to anchor it (a bare cpe cannot be swapped).
 */
export function fixedPackageIdentifier(pkg: AffectedPackage): string | undefined {
  if (!pkg.fixedInVersion) return undefined;
  if (pkg.purl) return swapPurlVersion(pkg.purl, pkg.fixedInVersion);
  if (pkg.name) return `${pkg.name}@${pkg.fixedInVersion}`;
  return undefined;
}

/**
 * `vers` (Package URL version-range) type for a package, from its ecosystem or
 * the purl type. Returns undefined when neither is known (so callers avoid
 * emitting an invalid range).
 */
export function versTypeFor(pkg: AffectedPackage): string | undefined {
  if (pkg.ecosystem) return String(pkg.ecosystem).toLowerCase();
  if (pkg.purl) {
    const m = /^pkg:([^/]+)\//.exec(pkg.purl);
    if (m?.[1]) return m[1].toLowerCase();
  }
  return undefined;
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
