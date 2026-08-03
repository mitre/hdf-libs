/**
 * Shared utilities for TypeScript HDF converters.
 *
 * Provides common patterns used across all converter implementations:
 * - Input checksum computation
 * - Re-exports of shared constants and utilities
 */

import { sha256, trimUtcFraction, parseJSON, normalizeHdfTimestamps, parseTimestamp } from '@mitre/hdf-utilities';
import type { AffectedPackage, Checksum, Component, EvaluatedBaseline, EvaluatedRequirement, HDFResults, Integrity, Statistics } from '@mitre/hdf-schema';
import { ControlType, Ecosystem, HashAlgorithm, ResultStatus, VerificationMethodEnum } from '@mitre/hdf-schema';
import { getCweNistControl, DEFAULT_STATIC_ANALYSIS_NIST_TAGS } from '@mitre/hdf-mappings';

export { DEFAULT_STATIC_ANALYSIS_NIST_TAGS };

/**
 * Compute a SHA-256 checksum of raw converter input.
 *
 * Wraps the common 3-line pattern used in every converter into a single call.
 * The returned Checksum is suitable for the EvaluatedBaseline.resultsChecksum field.
 *
 * @param input - Raw input string (JSON, XML, etc.)
 * @returns Checksum with algorithm set to SHA-256
 */
export async function inputChecksum(input: string): Promise<Checksum> {
  return {
    algorithm: HashAlgorithm.Sha256,
    value: await sha256(input),
  };
}

/**
 * Compute an Integrity object (for root-level document integrity) from raw input.
 *
 * Returns an Integrity with algorithm and checksum fields, suitable for
 * HDFBaseline.integrity, HDFSystem.integrity, HDFPlan.integrity, etc.
 *
 * @param input - Raw input string (JSON, XML, etc.)
 * @returns Integrity object with SHA-256 algorithm and checksum
 */
export async function inputIntegrity(input: string): Promise<Integrity> {
  const checksum = await inputChecksum(input);
  return { algorithm: checksum.algorithm, checksum: checksum.value };
}

/**
 * Build a tags object with NIST controls and optional CCI mappings.
 *
 * If cci is empty, the "cci" key is omitted from the result.
 * Additional key-value pairs can be passed via extras.
 *
 * @param nist - NIST 800-53 control identifiers
 * @param cci - CCI identifiers (omitted if empty)
 * @param extras - Additional tag key-value pairs
 * @returns Tags object for HDF requirement
 */
export function buildNistCciTags(
  nist: string[],
  cci: string[],
  extras?: Record<string, unknown>,
): Record<string, unknown> {
  const tags: Record<string, unknown> = { nist };
  if (cci.length > 0) {
    tags.cci = cci;
  }
  if (extras) {
    Object.assign(tags, extras);
  }
  return tags;
}

/** Maximum number of items processed from any single input array. */
const DEFAULT_MAX_ITEMS = 100_000;

/**
 * Limit an array to at most maxItems elements.
 *
 * Returns the (possibly truncated) array and a flag indicating whether
 * truncation occurred. When truncated, callers should log a warning.
 *
 * @param items - Array to limit
 * @param maxItems - Maximum items (defaults to DEFAULT_MAX_ITEMS)
 * @returns Object with limited items array and truncated flag
 */
export function limitArray<T>(
  items: T[],
  maxItems = DEFAULT_MAX_ITEMS,
): { items: T[]; truncated: boolean } {
  if (items.length <= maxItems) {
    return { items, truncated: false };
  }
  return { items: items.slice(0, maxItems), truncated: true };
}

// Re-export stripHTML from @mitre/hdf-utilities (canonical location).
// Named stripHTML (uppercase H) for backwards compatibility with existing
// converter imports; hdf-utilities exports stripHtml (lowercase h).
export { stripHtml as stripHTML } from '@mitre/hdf-utilities';

/**
 * Limit an array and log a warning if truncated.
 *
 * Wraps {@link limitArray} with a console.warn call when items are truncated.
 *
 * @param items - Array to limit
 * @param label - Item type label for warning message (e.g., "vulnerability")
 * @param maxItems - Maximum items (defaults to DEFAULT_MAX_ITEMS)
 * @returns Limited array (original if within limit)
 */
export function limitArrayWithWarning<T>(
  items: T[],
  label: string,
  maxItems = DEFAULT_MAX_ITEMS,
): T[] {
  const { items: limited, truncated } = limitArray(items, maxItems);
  if (truncated) {
    // eslint-disable-next-line no-console -- Intentional warning for truncated input
    console.warn(`WARNING: Input truncated at ${limited.length} ${label} items (original: ${items.length})`);
  }
  return limited;
}

/**
 * Map CWE identifiers to NIST 800-53 controls.
 *
 * Looks up each CWE ID, deduplicates, sorts, and falls back to the provided
 * default when no CWE has a mapping. CWE IDs may optionally have a "CWE-"
 * prefix (e.g., "CWE-79" or "79").
 *
 * @param cweIDs - CWE identifiers (e.g., ["CWE-79", "89"])
 * @param fallback - Default NIST controls when no mapping is found
 * @returns Sorted, deduplicated NIST control identifiers
 */
export function mapCWEToNIST(
  cweIDs: string[],
  fallback: string[],
): string[] {
  const controls = new Set<string>();
  for (const id of cweIDs) {
    const numericStr = id.replace(/^CWE-/i, '');
    const numericId = parseInt(numericStr, 10);
    if (!isNaN(numericId)) {
      const nistControl = getCweNistControl(numericId);
      if (nistControl) {
        controls.add(nistControl);
      }
    }
  }
  return controls.size > 0 ? [...controls].sort() : fallback;
}

/** Matches CWE identifiers like "CWE-79", "CWE 89", "cwe22". */
const CWE_PATTERN = /CWE[- ]?(\d+)/gi;

/**
 * Extract all numeric CWE IDs from text.
 * Returns deduplicated sorted array of numeric ID strings (e.g., ["79", "89"]).
 *
 * @param text - Text potentially containing CWE identifiers
 * @returns Sorted, deduplicated numeric CWE ID strings
 */
export function extractCWEIDs(text: string): string[] {
  const matches = [...text.matchAll(CWE_PATTERN)];
  if (matches.length === 0) return [];
  const ids = [...new Set(matches.map(m => m[1]!))];
  ids.sort();
  return ids;
}

/** Default maximum input size for converters (50MB) */
export const DEFAULT_MAX_INPUT_SIZE = 50 * 1024 * 1024;

/**
 * Validates that input string doesn't exceed maximum allowed size.
 *
 * Note: string.length gives char count, not bytes. For multi-byte chars this
 * underestimates. This is acceptable as a coarse safety check — exact byte
 * counting would require TextEncoder.
 *
 * @param input - Raw input string to validate
 * @param converterName - Name of the converter (used in error message)
 * @param maxSize - Maximum allowed character count (defaults to DEFAULT_MAX_INPUT_SIZE)
 * @throws Error if input exceeds maxSize
 */
export function validateInputSize(
  input: string,
  converterName: string,
  maxSize = DEFAULT_MAX_INPUT_SIZE,
): void {
  // Mirror Go's ValidateJSONSize: a non-positive limit means "use the default"
  // (so an explicitly-passed 0 or negative never rejects all non-empty input).
  if (maxSize <= 0) {
    maxSize = DEFAULT_MAX_INPUT_SIZE;
  }
  if (input.length > maxSize) {
    throw new Error(
      `${converterName}: input exceeds maximum allowed size of ${maxSize} characters`,
    );
  }
}

/**
 * Parse an HDF document. The single ingest point for every HDF-consuming
 * converter: real HDF carries zone-less timestamps (InSpec emits startTime with
 * no offset), so the raw JSON is normalized to canonical trimmed-UTC RFC3339
 * before parsing — otherwise the non-canonical value is laundered into the
 * converter's output (and Go, whose schema types decode date-time into
 * time.Time, rejects the document outright).
 */
export function parseHdf<T>(input: string): T {
  return parseJSON<T>(normalizeHdfTimestamps(input));
}

/**
 * Read a timestamp field off a parsed HDF document.
 *
 * The generated schema types these as `Date` (startTime, appliedAt, ...), but
 * JSON.parse does not revive Dates, so at runtime they are strings. Reaching for
 * `new Date(value)` to bridge that gap reads a zone-less timestamp as host-local,
 * where Go reads it as UTC — so the same document converts differently depending
 * on the machine. parseTimestamp reads it as UTC, matching Go.
 *
 * Returns null when the field is absent or unparseable; callers decide the
 * fallback, since a missing time is not the same as the epoch.
 */
export function hdfTime(value: unknown): Date | null {
  if (value instanceof Date) return value;
  if (value === undefined || value === null || value === '') return null;
  return parseTimestamp(String(value));
}

/**
 * Normalise a value that may be a single item, an array, undefined, or null
 * into a guaranteed array.
 *
 * XML-to-JSON parsers often produce a single object when there is one child
 * element and an array when there are multiple. This helper smooths that out.
 *
 * @param value - A single item, an array of items, undefined, or null
 * @returns An array (empty if the input was nullish)
 */
export function ensureArray<T>(value: T | T[] | undefined | null): T[] {
  if (value === undefined || value === null) return [];
  return Array.isArray(value) ? value : [value];
}


/**
 * Default NIST 800-53 fallback for tools that identify outdated packages or
 * flaws requiring patching (SI-2: Flaw Remediation, RA-5: Vulnerability
 * Monitoring and Scanning).
 *
 * Mirrors Go shared.DefaultRemediationNIST.
 */
export const DEFAULT_REMEDIATION_NIST_TAGS = ['SI-2', 'RA-5'];

/**
 * Map a PURL `type` segment to the AffectedPackage `ecosystem` enum.
 * Unknown types fall back to `generic`, which the schema enum permits
 * as a catch-all.
 */
const PURL_TYPE_TO_ECOSYSTEM: Record<string, Ecosystem> = {
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
 * Resolve an Ecosystem from a PURL type string. Returns `generic` for
 * unknown types so callers can keep the schema's name+version+ecosystem
 * triple valid without inventing a synthetic ecosystem.
 */
export function ecosystemFromPurlType(type: string | undefined): Ecosystem {
  if (!type) return Ecosystem.Generic;
  return PURL_TYPE_TO_ECOSYSTEM[type.toLowerCase()] ?? Ecosystem.Generic;
}

/**
 * Build an Affected_Package primitive from any combination of the
 * vocabulary the schema accepts (purl / cpe / name+version+ecosystem).
 * Returns undefined when no identifier or full triple is present —
 * callers should skip the entry rather than emit a schema-invalid
 * AffectedPackage. Empty strings are treated as missing.
 *
 * The schema's anyOf requires at least one of:
 *   - name + version + ecosystem
 *   - purl alone
 *   - cpe alone
 */
export function buildAffectedPackage(opts: {
  name?: string;
  version?: string;
  ecosystem?: Ecosystem;
  purl?: string;
  cpe?: string;
  fixedInVersion?: string;
}): AffectedPackage | undefined {
  const pkg: AffectedPackage = {};
  if (opts.purl) pkg.purl = opts.purl;
  if (opts.cpe) pkg.cpe = opts.cpe;
  if (opts.name) pkg.name = opts.name;
  if (opts.version) pkg.version = opts.version;
  if (opts.ecosystem) pkg.ecosystem = opts.ecosystem;
  if (opts.fixedInVersion) pkg.fixedInVersion = opts.fixedInVersion;

  const hasTriple = Boolean(pkg.name && pkg.version && pkg.ecosystem);
  if (!hasTriple && !pkg.purl && !pkg.cpe) return undefined;
  return pkg;
}

/**
 * Options for building an HDF Results document.
 * Mirrors the Go shared.HDFResultsOptions struct.
 */
export interface HdfResultsOptions {
  /** Name of the converter that produced this HDF file (e.g., 'grype-to-hdf') */
  generatorName: string;
  /** Version of the converter */
  converterVersion: string;
  /** Name of the source security tool (e.g., 'Grype', 'Nessus') */
  toolName?: string;
  /** Version of the source tool */
  toolVersion?: string;
  /** Output format of the source tool (e.g., 'SARIF', 'XCCDF') */
  toolFormat?: string;
  /** Evaluated baselines with findings */
  baselines: EvaluatedBaseline[];
  /** Components that were assessed */
  components?: Component[];
  /** When the assessment was executed */
  timestamp?: Date;
  /** Assessment statistics */
  statistics?: Statistics;
}

/**
 * Build an HDF Results document from options.
 *
 * Eliminates the repeated boilerplate of constructing generator, tool,
 * and assembling the top-level HDFResults in every converter. Mirrors
 * the Go shared.BuildHDFResults() function.
 *
 * @returns JSON string of the HDF Results document (pretty-printed)
 */
export function buildHdfResults(opts: HdfResultsOptions): string {
  const hdf: HDFResults = {
    baselines: opts.baselines,
    generator: {
      name: opts.generatorName,
      version: opts.converterVersion,
    },
  };

  if (opts.toolName || opts.toolVersion || opts.toolFormat) {
    hdf.tool = {};
    if (opts.toolName) hdf.tool.name = opts.toolName;
    if (opts.toolVersion) hdf.tool.version = opts.toolVersion;
    if (opts.toolFormat) hdf.tool.format = opts.toolFormat;
  }

  if (opts.components) hdf.components = opts.components;
  if (opts.timestamp) hdf.timestamp = opts.timestamp;
  if (opts.statistics) hdf.statistics = opts.statistics;

  return serializeHdf(hdf);
}

// Full-match ISO-8601 UTC datetime carrying a fractional-second part. Date
// values serialize via toISOString() as `...sssZ` (fixed 3-digit ms); Go emits
// RFC3339Nano (trailing zeros trimmed). The replacer rewrites the former into
// the latter so the two languages produce byte-identical output.
const ISO_UTC_WITH_FRACTION = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z$/;

function hdfTimestampReplacer(_key: string, value: unknown): unknown {
  if (typeof value === 'string' && ISO_UTC_WITH_FRACTION.test(value)) {
    return trimUtcFraction(value);
  }
  return value;
}

/**
 * Serialize an HDF document to pretty-printed JSON, normalizing Date-derived
 * timestamps to canonical trimmed-UTC RFC3339 (byte-identical to the Go
 * converters). Use this instead of a bare `JSON.stringify` for any HDF output
 * so the fractional-second trim is applied consistently.
 */
export function serializeHdf(doc: unknown, space = 2): string {
  return JSON.stringify(doc, hdfTimestampReplacer, space);
}

/**
 * Captures a NIST 800-53 control identifier and its base sub-control number,
 * ignoring enhancement suffixes like "(1)" or ".1". Mirrors the Go pattern
 * in shared/go/converterutil.go.
 */
const NIST_TAG_PATTERN = /^([A-Z]{2})-(\d+)/;

/**
 * Maps each recognized NIST 800-53 Rev 5 family to its HDF controlType per
 * SP 800-53 Appendix C / SP 800-53A classification. Unknown families resolve
 * to undefined.
 */
const NIST_FAMILY_CONTROL_TYPE: Record<string, ControlType> = {
  AC: ControlType.Technical,
  AT: ControlType.Operational,
  AU: ControlType.Operational,
  CA: ControlType.Management,
  CM: ControlType.Operational,
  CP: ControlType.Operational,
  IA: ControlType.Technical,
  IR: ControlType.Operational,
  MA: ControlType.Operational,
  MP: ControlType.Operational,
  PE: ControlType.Operational,
  PL: ControlType.Management,
  PM: ControlType.Management,
  PS: ControlType.Operational,
  PT: ControlType.Operational,
  RA: ControlType.Management,
  SA: ControlType.Management,
  SC: ControlType.Technical,
  SI: ControlType.Technical,
  SR: ControlType.Management,
};

/**
 * Derive the HDF `controlType` for a single NIST 800-53 control identifier
 * using a family-prefix heuristic. Returns undefined when the family is
 * unrecognized or the tag is not a NIST control identifier.
 *
 * Heuristic, per NIST SP 800-53 Rev 5 Appendix C and SP 800-53A:
 * - Management: PM, RA, CA, PL, SA, SR families
 * - Operational: AT, AU, CM, CP, IR, MA, MP, PE, PS, PT families
 * - Technical:  AC, IA, SC, SI families
 * - Policy:     any "-1" sub-control (the per-family policy/procedure
 *   document, regardless of which family it belongs to). Enhancements of
 *   -1 controls (e.g., AC-1(1)) also resolve to policy.
 *
 * The "-1" rule takes precedence over the family rule because the per-family
 * policy/procedure document is more usefully classified by its document
 * nature than by the family it documents.
 *
 * @example
 *   deriveControlType("AC-3")      // ControlType.Technical
 *   deriveControlType("AC-1")      // ControlType.Policy   (any *-1 is policy)
 *   deriveControlType("AC-3(1)")   // ControlType.Technical (enhancement of AC-3)
 *   deriveControlType("PM-2")      // ControlType.Management
 *   deriveControlType("SV-238196") // undefined            (not a NIST tag)
 */
function deriveControlType(nistTag: string): ControlType | undefined {
  const match = NIST_TAG_PATTERN.exec(nistTag.trim().toUpperCase());
  if (!match || match[1] === undefined || match[2] === undefined) return undefined;
  const family = match[1];
  const subControl = match[2];
  const familyClass = NIST_FAMILY_CONTROL_TYPE[family];
  if (familyClass === undefined) return undefined;
  if (subControl === '1') return ControlType.Policy;
  return familyClass;
}

/**
 * NIST tag sets this package uses as per-converter static fallbacks when no
 * real per-finding mapping is available. When deriveControlTypeFromTags sees
 * an input that exactly matches one of these bundles, it returns undefined —
 * the input carries no real per-finding signal, and stamping every
 * requirement with the same derived controlType is misleading.
 *
 * Keep in sync with DEFAULT_STATIC_ANALYSIS_NIST_TAGS, DEFAULT_REMEDIATION_NIST_TAGS.
 */
const NIST_FALLBACK_BUNDLES: string[][] = [
  ['RA-5', 'SA-11'], // DEFAULT_STATIC_ANALYSIS_NIST_TAGS (sorted)
  ['RA-5', 'SI-2'],  // DEFAULT_REMEDIATION_NIST_TAGS (sorted)
  ['CM-8'],          // DEFAULT_COMPONENT_MANAGEMENT_NIST_TAGS
];

function tagsMatchFallback(tags: string[]): boolean {
  if (tags.length === 0) return false;
  const sorted = [...new Set(tags)].sort();
  return NIST_FALLBACK_BUNDLES.some(
    (bundle) =>
      bundle.length === sorted.length &&
      bundle.every((b, i) => b === sorted[i]),
  );
}

/**
 * Derive the HDF `controlType` for a slice of NIST tags. Resolves each tag
 * via {@link deriveControlType}, then picks the most-specific class by
 * precedence: technical > operational > management > policy > procedure.
 * The rationale is that a control enforced via configuration (technical)
 * is more actionable than the same control's management/policy framing.
 *
 * Returns undefined when no tag resolves to a known classification, OR when
 * the input exactly matches a converter-level static-fallback bundle (e.g.
 * the DEFAULT_STATIC_ANALYSIS_NIST_TAGS set). The fallback gate prevents
 * converters that have no per-finding NIST signal from stamping every
 * requirement with the same misleading controlType.
 */
export function deriveControlTypeFromTags(tags: string[]): ControlType | undefined {
  if (tagsMatchFallback(tags)) return undefined;
  const rank: Record<ControlType, number> = {
    [ControlType.Technical]: 0,
    [ControlType.Operational]: 1,
    [ControlType.Management]: 2,
    [ControlType.Policy]: 3,
    [ControlType.Procedure]: 4,
  };
  let best: ControlType | undefined;
  let bestRank = Number.POSITIVE_INFINITY;
  for (const tag of tags) {
    const ct = deriveControlType(tag);
    if (ct === undefined) continue;
    const r = rank[ct];
    if (r < bestRank) {
      bestRank = r;
      best = ct;
    }
  }
  return best;
}

/**
 * Derive the HDF `verificationMethod` for a requirement based on whether
 * check code is present. Returns `automated` when code is non-empty (a check
 * exists and runs without operator action), and undefined otherwise — the
 * converter is responsible for distinguishing manual-by-design (statement-form,
 * e.g. FedRAMP 20x KSI) from manual-pending-automation (a check that could
 * be automated but isn't yet) when it has the source-format context to do so.
 */
export function deriveVerificationMethod(code: string | undefined | null): VerificationMethodEnum | undefined {
  if (code === undefined || code === null || code === '') return undefined;
  return VerificationMethodEnum.Automated;
}

// Synthesized passed placeholder for tools that ran clean. Required because
// the HDF schema enforces requirements.minItems=1.
export function buildNoFindingsRequirement(
  id: string,
  codeDesc: string,
  startTime: Date,
): EvaluatedRequirement {
  return {
    id,
    title: 'No findings reported',
    impact: 0,
    descriptions: [{ label: 'default', data: codeDesc }],
    results: [
      {
        status: ResultStatus.Passed,
        codeDesc,
        startTime,
      },
    ],
    tags: {},
  };
}
