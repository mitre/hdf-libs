/**
 * CycloneDX SBOM -> normalized HDF BillOfMaterials.
 *
 * Flattens the top-level components[] into SBOM packages. Nested subcomponents
 * (metadata.component.components[]) are the tool's own assembly tree and are
 * intentionally not treated as inventory packages here.
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
  enrichFromPurl,
} from './normalize.js';
import { limitArrayWithWarning } from '../converterutil.js';

/** Extract license identifiers/expressions from a CycloneDX licenses[] array. */
function extractLicenses(raw: unknown): string[] {
  if (!Array.isArray(raw)) return [];
  const out: string[] = [];
  for (const entry of raw) {
    const e = asRecord(entry);
    if (!e) continue;
    const license = asRecord(e.license);
    const id = license ? (asString(license.id) ?? asString(license.name)) : undefined;
    const value = id ?? asString(e.expression);
    if (value) out.push(value);
  }
  return out;
}

function componentToPackage(component: unknown): SBOMPackage | undefined {
  const c = asRecord(component);
  const name = c ? asString(c.name) : undefined;
  if (!c || !name) return undefined;

  const pkg: SBOMPackage = { name };
  const version = asString(c.version);
  if (version) pkg.version = version;
  const purl = asString(c.purl);
  if (purl) pkg.purl = purl;
  const licenses = extractLicenses(c.licenses);
  if (licenses.length > 0) pkg.licenses = licenses;

  enrichFromPurl(pkg);
  return pkg;
}

export function parseCycloneDX(obj: Record<string, unknown>): NormalizedBom {
  const components = Array.isArray(obj.components) ? obj.components : [];
  const packages: SBOMPackage[] = [];
  for (const component of components) {
    const pkg = componentToPackage(component);
    if (pkg) packages.push(pkg);
  }

  const uniqueId = asString(obj.serialNumber);
  return buildBom({
    bomType: BOMType.Sbom,
    format: 'cyclonedx',
    packages: limitArrayWithWarning(packages, 'package'),
    uniqueId,
  });
}
