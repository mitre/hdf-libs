/**
 * SBOM comparison for the HDF diff engine.
 *
 * Compares two SBOM documents (CycloneDX or SPDX JSON) and produces
 * package-level diffs: added, removed, updated, unchanged packages.
 *
 * Format auto-detection:
 * - CycloneDX: has `bomFormat: "CycloneDX"`, packages in `components[]`
 * - SPDX: has `spdxVersion`, packages in `packages[]`
 */

/**
 * The comparison result for a single package between two SBOMs.
 */
export interface PackageDiff {
  purl: string;
  name: string;
  state: 'added' | 'removed' | 'updated' | 'unchanged';
  oldVersion?: string;
  newVersion?: string;
  licenses?: string[];
}

/**
 * The complete result of comparing two SBOM documents.
 */
export interface SbomDiffResult {
  packageDiffs: PackageDiff[];
  added: number;
  removed: number;
  updated: number;
  unchanged: number;
}

/**
 * Internal representation of a parsed package from any SBOM format.
 */
interface ParsedPackage {
  purl: string;
  name: string;
  version: string;
  licenses: string[];
}

/**
 * Compare two SBOM documents (CycloneDX or SPDX JSON strings) and return
 * package-level diffs.
 *
 * @param oldJson - JSON string of the old SBOM document
 * @param newJson - JSON string of the new SBOM document
 * @returns Structured diff result with per-package state and aggregate counts
 * @throws Error if either input is not valid JSON or not a recognized SBOM format
 */
export function diffSboms(oldJson: string, newJson: string): SbomDiffResult {
  const oldParsed = JSON.parse(oldJson) as Record<string, unknown>;
  const newParsed = JSON.parse(newJson) as Record<string, unknown>;

  const oldPackages = extractPackages(oldParsed);
  const newPackages = extractPackages(newParsed);

  const oldMap = buildPackageMap(oldPackages);
  const newMap = buildPackageMap(newPackages);

  const diffs: PackageDiff[] = [];
  const seen = new Set<string>();

  // Check old packages against new
  for (const [key, oldPkg] of oldMap) {
    seen.add(key);
    const newPkg = newMap.get(key);
    if (newPkg) {
      if (oldPkg.version !== newPkg.version) {
        diffs.push({
          purl: newPkg.purl || newPkg.name,
          name: newPkg.name,
          state: 'updated',
          oldVersion: oldPkg.version,
          newVersion: newPkg.version,
          licenses: newPkg.licenses.length > 0 ? newPkg.licenses : undefined,
        });
      } else {
        diffs.push({
          purl: oldPkg.purl || oldPkg.name,
          name: oldPkg.name,
          state: 'unchanged',
        });
      }
    } else {
      diffs.push({
        purl: oldPkg.purl || oldPkg.name,
        name: oldPkg.name,
        state: 'removed',
        oldVersion: oldPkg.version,
      });
    }
  }

  // Check for added packages
  for (const [key, newPkg] of newMap) {
    if (!seen.has(key)) {
      diffs.push({
        purl: newPkg.purl || newPkg.name,
        name: newPkg.name,
        state: 'added',
        newVersion: newPkg.version,
        licenses: newPkg.licenses.length > 0 ? newPkg.licenses : undefined,
      });
    }
  }

  // Sort by name for deterministic output
  diffs.sort((a, b) => a.name.localeCompare(b.name));

  // Count states
  let added = 0;
  let removed = 0;
  let updated = 0;
  let unchanged = 0;
  for (const d of diffs) {
    switch (d.state) {
      case 'added': added++; break;
      case 'removed': removed++; break;
      case 'updated': updated++; break;
      case 'unchanged': unchanged++; break;
    }
  }

  return { packageDiffs: diffs, added, removed, updated, unchanged };
}

/**
 * Extract packages from an SBOM document, auto-detecting the format.
 */
function extractPackages(doc: Record<string, unknown>): ParsedPackage[] {
  if (doc['bomFormat'] === 'CycloneDX') {
    return extractCycloneDXPackages(doc);
  }
  if (typeof doc['spdxVersion'] === 'string') {
    return extractSPDXPackages(doc);
  }
  throw new Error(
    'Unrecognized SBOM format: expected CycloneDX (bomFormat) or SPDX (spdxVersion)',
  );
}

/**
 * Extract packages from a CycloneDX document.
 * Reads components[] with purl, name, version fields.
 */
function extractCycloneDXPackages(doc: Record<string, unknown>): ParsedPackage[] {
  const components = doc['components'] as Array<Record<string, unknown>> | undefined;
  if (!Array.isArray(components)) {
    return [];
  }

  return components.map((comp): ParsedPackage => {
    const licenses = extractCycloneDXLicenses(comp);
    return {
      purl: (comp['purl'] as string) ?? '',
      name: (comp['name'] as string) ?? '',
      version: (comp['version'] as string) ?? '',
      licenses,
    };
  });
}

/**
 * Extract license strings from a CycloneDX component.
 * CycloneDX licenses can be in `licenses[].license.id` or `licenses[].license.name`.
 */
function extractCycloneDXLicenses(comp: Record<string, unknown>): string[] {
  const licensesArr = comp['licenses'] as Array<Record<string, unknown>> | undefined;
  if (!Array.isArray(licensesArr)) {
    return [];
  }
  const result: string[] = [];
  for (const entry of licensesArr) {
    const license = entry['license'] as Record<string, unknown> | undefined;
    if (license) {
      const id = license['id'] as string | undefined;
      const name = license['name'] as string | undefined;
      if (id) {
        result.push(id);
      } else if (name) {
        result.push(name);
      }
    }
  }
  return result;
}

/**
 * Extract packages from an SPDX document.
 * Reads packages[] with name, versionInfo, and externalRefs (for PURL).
 */
function extractSPDXPackages(doc: Record<string, unknown>): ParsedPackage[] {
  const packages = doc['packages'] as Array<Record<string, unknown>> | undefined;
  if (!Array.isArray(packages)) {
    return [];
  }

  return packages.map((pkg): ParsedPackage => {
    const purl = extractSPDXPurl(pkg);
    const license = (pkg['licenseConcluded'] as string) ?? (pkg['licenseDeclared'] as string) ?? '';
    return {
      purl,
      name: (pkg['name'] as string) ?? '',
      version: (pkg['versionInfo'] as string) ?? '',
      licenses: license && license !== 'NOASSERTION' ? [license] : [],
    };
  });
}

/**
 * Extract a PURL from an SPDX package's externalRefs array.
 */
function extractSPDXPurl(pkg: Record<string, unknown>): string {
  const refs = pkg['externalRefs'] as Array<Record<string, unknown>> | undefined;
  if (!Array.isArray(refs)) {
    return '';
  }
  for (const ref of refs) {
    const refType = ref['referenceType'] as string | undefined;
    if (refType === 'purl') {
      return (ref['referenceLocator'] as string) ?? '';
    }
  }
  return '';
}

/**
 * Build a lookup map of packages indexed by name (version-independent key).
 */
function buildPackageMap(packages: ParsedPackage[]): Map<string, ParsedPackage> {
  const map = new Map<string, ParsedPackage>();
  for (const pkg of packages) {
    const key = pkg.name || pkg.purl;
    if (key) {
      map.set(key, pkg);
    }
  }
  return map;
}
