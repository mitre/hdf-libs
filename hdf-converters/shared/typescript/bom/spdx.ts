/**
 * SPDX SBOM -> normalized HDF BillOfMaterials.
 *
 * Maps packages[] to normalized SBOM packages. purl comes from an externalRefs
 * entry with referenceType 'purl'; licenses come from licenseConcluded /
 * licenseDeclared with NOASSERTION/NONE sentinels filtered out.
 */

import {
  BOMType,
  type NormalizedBom,
  type SBOMPackage,
} from './model.js';
import {
  asRecord,
  asString,
  buildBom,
  cleanLicense,
  enrichFromPurl,
} from './normalize.js';
import { limitArrayWithWarning } from '../converterutil.js';

const SPDX_LICENSE_FIELDS = ['licenseConcluded', 'licenseDeclared'] as const;

/** First externalRefs[].referenceLocator whose referenceType is 'purl'. */
function purlFromExternalRefs(refs: unknown): string | undefined {
  if (!Array.isArray(refs)) return undefined;
  for (const ref of refs) {
    const r = asRecord(ref);
    if (r?.referenceType === 'purl') {
      const locator = asString(r.referenceLocator);
      if (locator) return locator;
    }
  }
  return undefined;
}

function extractLicenses(pkg: Record<string, unknown>): string[] {
  const out: string[] = [];
  for (const field of SPDX_LICENSE_FIELDS) {
    const license = cleanLicense(pkg[field]);
    if (license && !out.includes(license)) out.push(license);
  }
  return out;
}

function packageToPackage(source: unknown): SBOMPackage | undefined {
  const p = asRecord(source);
  const name = p ? asString(p.name) : undefined;
  if (!p || !name) return undefined;

  const pkg: SBOMPackage = { name };
  const version = asString(p.versionInfo);
  if (version) pkg.version = version;
  const purl = purlFromExternalRefs(p.externalRefs);
  if (purl) pkg.purl = purl;
  const licenses = extractLicenses(p);
  if (licenses.length > 0) pkg.licenses = licenses;

  enrichFromPurl(pkg);
  return pkg;
}

export function parseSPDX(obj: Record<string, unknown>): NormalizedBom {
  const sourcePackages = Array.isArray(obj.packages) ? obj.packages : [];
  const packages: SBOMPackage[] = [];
  for (const source of sourcePackages) {
    const pkg = packageToPackage(source);
    if (pkg) packages.push(pkg);
  }

  const uniqueId = asString(obj.documentNamespace);
  return buildBom({
    bomType: BOMType.Sbom,
    format: 'spdx',
    packages: limitArrayWithWarning(packages, 'package'),
    uniqueId,
  });
}
