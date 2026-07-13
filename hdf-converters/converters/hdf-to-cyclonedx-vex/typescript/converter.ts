/**
 * HDF Amendments to CycloneDX VEX converter (export side).
 *
 * Reverse direction of cyclonedx-vex-to-hdf. Step 4f amendment-output
 * pattern, partial-fidelity by design — consumer-action-bearing fields
 * (CVE id, status, justification) survive round-trip; the rest collapse
 * into the available CycloneDX VEX fields.
 */

import {
  IdentityType,
  MilestoneStatus,
  OverrideType,
  type AffectedPackage,
  type HDFAmendments,
  type StandaloneOverride,
} from '@mitre/hdf-schema';
import { sha256, formatTimestampSeconds } from '@mitre/hdf-utilities';
import { validateInputSize, parseHdf } from '../../../shared/typescript/converterutil.js';
import {
  affectedPackageToIdentifier,
  versTypeFor,
  exportStatusFor,
  justificationForCycloneDX,
  VexStatus,
} from '../../../shared/typescript/vex/mapping.js';

const CVE_ID_PATTERN = /^CVE-\d{4}-\d{4,}$/;
const PRODUCTS_LINE = /^Products:\s*(.+)$/m;
const RAW_JUST_LINE = /^VEX justification:\s*(.+)$/m;
const RESPONSE_LINE = /^Response:.*$/gm;
const DEFAULT_PRODUCT_ID = 'HDFPID-0001';

interface Component {
  type: string;
  name: string;
  'bom-ref': string;
  version?: string;
  purl?: string;
  cpe?: string;
}

interface BOM {
  bomFormat: 'CycloneDX';
  specVersion: '1.4';
  serialNumber: string;
  version: number;
  metadata: {
    timestamp: string;
    tools?: { vendor?: string; name?: string; version?: string }[];
    authors?: { name?: string; email?: string }[];
  };
  components?: Component[];
  vulnerabilities: Vulnerability[];
}

interface Rating {
  source?: { name?: string };
  score?: number;
  severity?: string;
  method?: string;
  vector?: string;
}

interface Vulnerability {
  id: string;
  source?: { name?: string; url: string };
  references?: { id: string; source: { name?: string; url: string } }[];
  ratings?: Rating[];
  recommendation?: string;
  analysis: {
    state: string;
    justification?: string;
    response?: string[];
    detail?: string;
  };
  affects: { ref: string; versions?: CdxVersion[] }[];
}

interface CdxVersion {
  version?: string;
  range?: string;
  status: string;
}

/**
 * Build CycloneDX affects[].versions[] for a package with a fixedInVersion:
 * the current version is `affected`, and `>= fixedInVersion` is `unaffected`,
 * expressed as a `vers` range. Undefined when there is no vers type to key the
 * range (caller falls back to a free-text recommendation).
 */
function buildCdxAffectsVersions(pkg?: AffectedPackage): CdxVersion[] | undefined {
  if (!pkg?.fixedInVersion) return undefined;
  const t = versTypeFor(pkg);
  if (!t) return undefined;
  const versions: CdxVersion[] = [];
  if (pkg.version) versions.push({ version: pkg.version, status: 'affected' });
  versions.push({ range: `vers:${t}/>=${pkg.fixedInVersion}`, status: 'unaffected' });
  return versions;
}

/** Map an HDF Cvss block to a CycloneDX rating. */
function buildCdxRating(cvss: NonNullable<StandaloneOverride['cvss']>): Rating | undefined {
  const rating: Rating = {};
  if (typeof cvss.baseScore === 'number') rating.score = cvss.baseScore;
  if (cvss.baseSeverity) rating.severity = cvss.baseSeverity;
  if (cvss.baseVector) rating.vector = cvss.baseVector;
  const v = cvss.version;
  rating.method = v === '4.0' ? 'CVSSv4' : v === '3.1' ? 'CVSSv31' : v === '3.0' ? 'CVSSv3' : v === '2.0' ? 'CVSSv2' : 'other';
  if (rating.score === undefined && rating.vector === undefined) return undefined;
  return rating;
}

export async function convertHdfToCyclonedxVex(
  input: string,
  converterVersion: string,
): Promise<string> {
  validateInputSize(input, 'hdf-to-cyclonedx-vex');
  const amendments = parseHdf<HDFAmendments>(input);

  const componentRegistry = new Map<string, Component>();
  const vulnerabilities: Vulnerability[] = [];
  let earliest: Date | undefined;

  for (const o of amendments.overrides ?? []) {
    if (!CVE_ID_PATTERN.test(o.requirementId)) continue;
    const v = overrideToVulnerability(o, componentRegistry);
    if (!v) continue;
    vulnerabilities.push(v);
    const t = new Date(o.appliedAt);
    if (!earliest || t < earliest) earliest = t;
  }

  if (vulnerabilities.length === 0) {
    throw new Error(
      'hdf-to-cyclonedx-vex: no overrides with CVE-shaped requirementIds; nothing to emit',
    );
  }

  vulnerabilities.sort((a, b) => a.id.localeCompare(b.id));
  const components = [...componentRegistry.values()].sort((a, b) =>
    a['bom-ref'].localeCompare(b['bom-ref']),
  );

  const bom: BOM = {
    bomFormat: 'CycloneDX',
    specVersion: '1.4',
    serialNumber: await buildSerialNumber(input, amendments),
    version: 1,
    metadata: buildMetadata(amendments, earliest ?? new Date(), converterVersion),
    components,
    vulnerabilities,
  };

  return JSON.stringify(bom, null, 2);
}

function overrideToVulnerability(
  o: StandaloneOverride,
  componentRegistry: Map<string, Component>,
): Vulnerability | undefined {
  let canonical = exportStatusFor(o, allMilestonesCompleted(o), false);
  if (!canonical) return undefined;
  if (
    o.type === OverrideType.Poam &&
    canonical === VexStatus.Affected &&
    allMilestonesCompleted(o)
  ) {
    canonical = VexStatus.Fixed;
  }

  // Pair each emitted product id back to the AffectedPackage it came from
  // so we can preserve name/version/purl/cpe in the CycloneDX component.
  // Falls back to a pid-only component for legacy paths (componentRef or
  // 'Products:' reason annotation) where no structured entry exists.
  const pids = productIDsFor(o);
  const pkgById = new Map<string, AffectedPackage>();
  for (const p of o.affectedPackages ?? []) {
    const id = affectedPackageToIdentifier(p);
    if (id) pkgById.set(id, p);
  }
  for (const pid of pids) {
    componentRegistry.set(pid, componentFor(pid, pkgById.get(pid)));
  }

  const analysis: Vulnerability['analysis'] = { state: canonicalToCycloneDXState(canonical) };
  // HDF Justification uses long-form names from OpenVEX/CSAF; CycloneDX
  // uses short-form names for the same concepts. Translate via the
  // shared helper.
  if (o.justification) {
    const cdxJust = justificationForCycloneDX(o.justification);
    if (cdxJust) analysis.justification = cdxJust;
  }
  if (canonical === VexStatus.Fixed) {
    analysis.response = ['update'];
  } else if (canonical === VexStatus.Affected && o.type === OverrideType.Poam) {
    analysis.response = ['workaround_available'];
  }
  const detail = stripReasonAnnotations(o.reason ?? '');
  if (detail) analysis.detail = detail;

  const references: NonNullable<Vulnerability['references']> = [];
  for (const e of o.evidence ?? []) {
    if (e.type !== 'url' || !e.data) continue;
    references.push({
      id: o.requirementId,
      source: { name: e.description ?? '', url: e.data },
    });
  }

  // Emit consumer-supplied CVSS enrichment as a CycloneDX rating.
  const rating = o.cvss ? buildCdxRating(o.cvss) : undefined;

  // A fixedInVersion we could not express as a vers range (no ecosystem/purl to
  // key the range) becomes a free-text recommendation instead of an invalid range.
  const unranged = (o.affectedPackages ?? []).find((p) => p.fixedInVersion && !versTypeFor(p));

  // Key order mirrors the Go BOM structs so both languages emit identical bytes.
  return {
    id: o.requirementId,
    source: { name: 'NVD', url: `https://nvd.nist.gov/vuln/detail/${o.requirementId}` },
    ...(references.length > 0 && { references }),
    ...(rating && { ratings: [rating] }),
    ...(unranged && { recommendation: `Upgrade to ${unranged.fixedInVersion}` }),
    analysis,
    affects: pids.map((pid) => {
      const versions = buildCdxAffectsVersions(pkgById.get(pid));
      return versions ? { ref: pid, versions } : { ref: pid };
    }),
  };
}

function canonicalToCycloneDXState(canonical: VexStatus): string {
  switch (canonical) {
    case VexStatus.NotAffected:
      return 'not_affected';
    case VexStatus.Fixed:
      return 'resolved';
    case VexStatus.Affected:
      return 'exploitable';
    /* c8 ignore next 2 — defensive: every VexStatus has a case above */
    default:
      return canonical;
  }
}

function componentFor(pid: string, pkg?: AffectedPackage): Component {
  const c: Component = {
    type: 'application',
    name: pkg?.name ?? pid,
    'bom-ref': pid,
  };
  if (pkg?.version) c.version = pkg.version;
  if (pkg?.purl ?? (pid.startsWith('pkg:') ? pid : undefined)) {
    c.purl = pkg?.purl ?? pid;
  }
  if (pkg?.cpe ?? (pid.startsWith('cpe:2.3:') ? pid : undefined)) {
    c.cpe = pkg?.cpe ?? pid;
  }
  return c;
}

export function productIDsFor(o: StandaloneOverride): string[] {
  // Structured affectedPackages is the source of truth (v3.2.x and later).
  if (o.affectedPackages && o.affectedPackages.length > 0) {
    const ids = o.affectedPackages
      .map((p) => affectedPackageToIdentifier(p))
      .filter((id): id is string => Boolean(id));
    if (ids.length > 0) return ids;
  }
  // Backward-compat fallbacks for pre-affectedPackages HDF inputs.
  if (o.componentRef) return [o.componentRef];
  const m = PRODUCTS_LINE.exec(o.reason ?? '');
  if (m && m[1]) {
    const parts = m[1].split(',').map((s) => s.trim()).filter(Boolean);
    if (parts.length > 0) return parts;
  }
  return [DEFAULT_PRODUCT_ID];
}

// stripReasonAnnotations removes the 'Products: …' tail line that
// import-side converters append, so analysis.detail carries only the
// prose. (The 'VEX justification:' and 'Response:' annotations were
// removed when the Justification enum was extended to cover the full
// CycloneDX vocabulary; this stripper also handles any legacy reason
// strings that still carry them.)
export function stripReasonAnnotations(reason: string): string {
  return reason
    .replace(PRODUCTS_LINE, '')
    .replace(RAW_JUST_LINE, '')
    .replace(RESPONSE_LINE, '')
    .trim();
}

export function allMilestonesCompleted(o: StandaloneOverride): boolean {
  if (!o.milestones || o.milestones.length === 0) return false;
  return o.milestones.every((m) => m.status === MilestoneStatus.Completed);
}

function buildMetadata(
  a: HDFAmendments,
  docTime: Date,
  converterVersion: string,
): BOM['metadata'] {
  const metadata: BOM['metadata'] = {
    timestamp: formatTimestampSeconds(docTime),
    tools: [{ vendor: 'mitre', name: 'hdf-to-cyclonedx-vex', version: converterVersion }],
  };
  if (a.appliedBy?.identifier) {
    const author: { name?: string; email?: string } = {};
    if (a.appliedBy.type === IdentityType.Email) {
      author.email = a.appliedBy.identifier;
    } else {
      author.name = a.appliedBy.identifier;
    }
    metadata.authors = [author];
  }
  return metadata;
}

// The serial number is the first 16 bytes of the input's SHA-256, matching the
// Go exporter byte-for-byte.
async function buildSerialNumber(input: string, a: HDFAmendments): Promise<string> {
  if (a.amendmentId) return `urn:uuid:${a.amendmentId}`;
  return `urn:uuid:${(await sha256(input)).slice(0, 32)}`;
}

