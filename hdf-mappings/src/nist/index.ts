/**
 * NIST SP 800-53 control description functions
 */

import type { NISTDescriptions } from './types.js';
import rawNistDataRev4 from '../data/nist-descriptions.json';
import rawNistDataRev5 from '../data/nist-descriptions-rev5.json';

// Descriptions are revision-specific: Rev 5 renamed titles ("... POLICY AND
// PROCEDURES" -> "Policy and Procedures"), added the SR and PT families, and
// withdrew Rev 4 controls (AU-15, IR-10, SA-12, ...). Each revision has its own
// dataset; lookups select by the (optionally overridden) global revision.
const nistDataByRev: Record<number, NISTDescriptions> = {
  4: rawNistDataRev4 as NISTDescriptions,
  5: rawNistDataRev5 as NISTDescriptions,
};

/**
 * NIST SP 800-53 revision selection.
 *
 * The revision is a module-global default that every NIST-emitting mapping
 * consults through its default lookups. Set it once at startup (the CLI's
 * `--nist-rev` flag does this) to switch the catalog all converters target.
 * For explicit, side-effect-free per-call selection, pass an explicit `rev` to
 * the mapping lookups instead of mutating this.
 */

/** The revision mappings emit when nothing overrides it. */
export const DEFAULT_NIST_REVISION = 5;

/**
 * The description dataset for a revision, falling back to the default revision's
 * data (then an empty set) for an unsupported revision.
 */
function descriptionsFor(rev: number): NISTDescriptions {
  return nistDataByRev[rev] ?? nistDataByRev[DEFAULT_NIST_REVISION] ?? {};
}

/** Revisions every NIST-emitting mapping table has rows for. */
export const SUPPORTED_NIST_REVISIONS: readonly number[] = [4, 5];

let currentNistRevision = DEFAULT_NIST_REVISION;

/** Get the module-global default NIST revision. */
export function getCurrentNistRevision(): number {
  return currentNistRevision;
}

/**
 * Set the module-global default NIST revision. Throws (without mutating state)
 * if the revision has no mapping data.
 */
export function setCurrentNistRevision(rev: number): void {
  if (!SUPPORTED_NIST_REVISIONS.includes(rev)) {
    throw new Error(
      `unsupported NIST revision ${rev} (supported: ${SUPPORTED_NIST_REVISIONS.join(', ')})`
    );
  }
  currentNistRevision = rev;
}

/** Restore the default revision. Intended for cleanup and tests. */
export function resetNistRevision(): void {
  currentNistRevision = DEFAULT_NIST_REVISION;
}

let nistStrict = false;

/** Report whether strict NIST revision alignment is enabled. */
export function isNistStrict(): boolean {
  return nistStrict;
}

/**
 * Toggle strict NIST revision alignment. When enabled, revision-divergent
 * mappings treat a rule mapped only at another revision as a hard error rather
 * than a silent omission.
 */
export function setNistStrict(strict: boolean): void {
  nistStrict = strict;
}

/**
 * Get the description for a NIST control ID at the selected revision.
 *
 * @param nistId - The NIST control ID (e.g., 'AC-01', 'AC-01 a', 'AC-02 01')
 * @param rev - NIST revision to look up; defaults to the module-global revision
 * @returns The control's Rev-specific description, or undefined if not found at
 *   that revision (e.g. a Rev 5-only SR/PT control at Rev 4, or a Rev 4 control
 *   withdrawn in Rev 5)
 *
 * @example
 * ```typescript
 * getNISTDescription('AC-01');    // Rev 5 default -> "Policy and Procedures"
 * getNISTDescription('AC-01', 4); // -> "ACCESS CONTROL POLICY AND PROCEDURES"
 * ```
 */
export function getNISTDescription(
  nistId: string,
  rev: number = getCurrentNistRevision()
): string | undefined {
  if (!nistId || typeof nistId !== 'string') {
    return undefined;
  }

  return descriptionsFor(rev)[nistId];
}

/**
 * Get all NIST control IDs present at the selected revision.
 *
 * @param rev - NIST revision to enumerate; defaults to the module-global revision
 * @returns Array of NIST control IDs for that revision (Rev 5 includes the
 *   SR/PT families; Rev 4 includes controls withdrawn in Rev 5)
 *
 * @example
 * ```typescript
 * const ids = getAllNISTIds();
 * // Returns: ['AC-01', 'AC-01 a', 'AC-02', ...]
 * ```
 */
export function getAllNISTIds(rev: number = getCurrentNistRevision()): string[] {
  return Object.keys(descriptionsFor(rev));
}

/**
 * Check if a NIST control ID exists at the selected revision.
 *
 * @param nistId - The NIST control ID to check
 * @param rev - NIST revision to check against; defaults to the module-global revision
 * @returns true if the control exists at that revision (e.g. an SR/PT control is
 *   present at Rev 5 but not Rev 4)
 *
 * @example
 * ```typescript
 * if (nistExists('AC-01')) {
 *   console.log('NIST control found');
 * }
 * ```
 */
export function nistExists(nistId: string, rev: number = getCurrentNistRevision()): boolean {
  if (!nistId || typeof nistId !== 'string') {
    return false;
  }

  return nistId in descriptionsFor(rev);
}

/**
 * Extract the NIST family from a NIST control ID, if that family exists at the
 * selected revision.
 *
 * @param nistId - The NIST control ID (e.g., 'AC-01', 'AC-01 a')
 * @param rev - NIST revision to validate against; defaults to the module-global revision
 * @returns The NIST family code (e.g., 'AC'), or undefined if invalid or the
 *   family is absent at that revision (the SR/PT families are Rev 5-only)
 *
 * @example
 * ```typescript
 * const family = getNISTFamily('AC-01');
 * // Returns: 'AC'
 *
 * const family2 = getNISTFamily('AC-01 a 01');
 * // Returns: 'AC'
 * ```
 */
export function getNISTFamily(
  nistId: string,
  rev: number = getCurrentNistRevision()
): string | undefined {
  if (!nistId || typeof nistId !== 'string') {
    return undefined;
  }

  // Extract family from format like "AC-01" or "AC-01 a"
  const match = nistId.match(/^([A-Z]{2})-/);
  if (!match) {
    return undefined;
  }

  const family = match[1];

  // Validate that this family exists at the selected revision by checking
  // if any controls start with this family (the SR/PT families are Rev 5-only).
  const familyPrefix = `${family}-`;
  const hasFamily = Object.keys(descriptionsFor(rev)).some((key) => key.startsWith(familyPrefix));

  return hasFamily ? family : undefined;
}

/**
 * Canonical NIST 800-53 fallback tags for converters when a finding has no
 * CWE or the CWE has no NIST mapping. Categories match heimdall2's global.ts.
 *
 * - SA-11: Developer Security Testing and Evaluation
 * - RA-5: Vulnerability Monitoring and Scanning
 * - SI-2: Flaw Remediation
 * - CM-8: System Component Inventory
 */

/** Static analysis and vulnerability scanning tools (SA-11 + RA-5). */
export const DEFAULT_STATIC_ANALYSIS_NIST_TAGS: string[] = ['SA-11', 'RA-5'];

/** Tools that identify outdated packages or flaws requiring patching (SI-2 + RA-5). */
export const DEFAULT_REMEDIATION_NIST_TAGS: string[] = ['SI-2', 'RA-5'];

/** Dependency/inventory management tools (CM-8). */
export const DEFAULT_COMPONENT_MANAGEMENT_NIST_TAGS: string[] = ['CM-8'];

/** Configuration-compliance checks with no specific mapping (CM-6: Configuration Settings). */
export const DEFAULT_CONFIG_MANAGEMENT_NIST_TAGS: string[] = ['CM-6'];

// Rev 4 <-> Rev 5 crosswalk
export {
  translateNistControl,
  translateNistControls,
  nistRosterSize,
  nistControlsAtRevision,
} from './crosswalk.js';
export type { NistControlTranslation, NistCrosswalkRelation } from './crosswalk.js';

// Re-export types
export type { NISTDescriptions } from './types.js';
