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
  type HDFAmendments,
  type StandaloneOverride,
} from '@mitre/hdf-schema';
import { validateInputSize } from '../../../shared/typescript/converterutil.js';
import { exportStatusFor, VexStatus } from '../../../shared/typescript/vex/mapping.js';

const CVE_ID_PATTERN = /^CVE-\d{4}-\d{4,}$/;
const PRODUCTS_LINE = /^Products:\s*(.+)$/m;
const RAW_JUST_LINE = /^VEX justification:\s*(.+)$/m;
const RESPONSE_LINE = /^Response:.*$/gm;
const DEFAULT_PRODUCT_ID = 'HDFPID-0001';

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
  components?: { type: string; name: string; 'bom-ref': string; purl?: string }[];
  vulnerabilities: Vulnerability[];
}

interface Vulnerability {
  id: string;
  source?: { name?: string; url: string };
  references?: { id: string; source: { name?: string; url: string } }[];
  analysis: {
    state: string;
    justification?: string;
    response?: string[];
    detail?: string;
  };
  affects: { ref: string }[];
}

export function convertHdfToCyclonedxVex(input: string, converterVersion: string): string {
  validateInputSize(input, 'hdf-to-cyclonedx-vex');
  const amendments = JSON.parse(input) as HDFAmendments;

  const componentRegistry = new Map<string, { type: string; name: string; 'bom-ref': string; purl?: string }>();
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
    serialNumber: buildSerialNumberSync(input, amendments),
    version: 1,
    metadata: buildMetadata(amendments, earliest ?? new Date(), converterVersion),
    components,
    vulnerabilities,
  };

  return JSON.stringify(bom, null, 2);
}

function overrideToVulnerability(
  o: StandaloneOverride,
  componentRegistry: Map<string, { type: string; name: string; 'bom-ref': string; purl?: string }>,
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

  const pids = productIDsFor(o);
  for (const pid of pids) {
    componentRegistry.set(pid, componentFor(pid));
  }

  const analysis: Vulnerability['analysis'] = { state: canonicalToCycloneDXState(canonical) };
  const rawJ = extractRawJustification(o.reason ?? '');
  if (rawJ) {
    analysis.justification = rawJ;
  } else if (o.justification) {
    analysis.justification = String(o.justification);
  }
  const detail = stripReasonAnnotations(o.reason ?? '');
  if (detail) analysis.detail = detail;
  if (canonical === VexStatus.Fixed) {
    analysis.response = ['update'];
  } else if (canonical === VexStatus.Affected && o.type === OverrideType.Poam) {
    analysis.response = ['workaround_available'];
  }

  const v: Vulnerability = {
    id: o.requirementId,
    source: { name: 'NVD', url: `https://nvd.nist.gov/vuln/detail/${o.requirementId}` },
    analysis,
    affects: pids.map((p) => ({ ref: p })),
  };

  for (const e of o.evidence ?? []) {
    if (e.type !== 'url' || !e.data) continue;
    v.references = v.references ?? [];
    v.references.push({
      id: o.requirementId,
      source: { name: e.description ?? '', url: e.data },
    });
  }

  return v;
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

function componentFor(pid: string): { type: string; name: string; 'bom-ref': string; purl?: string } {
  const c: { type: string; name: string; 'bom-ref': string; purl?: string } = {
    type: 'application',
    name: pid,
    'bom-ref': pid,
  };
  if (pid.startsWith('pkg:')) c.purl = pid;
  return c;
}

export function productIDsFor(o: StandaloneOverride): string[] {
  if (o.componentRef) return [o.componentRef];
  const m = PRODUCTS_LINE.exec(o.reason ?? '');
  if (m && m[1]) {
    const parts = m[1].split(',').map((s) => s.trim()).filter(Boolean);
    if (parts.length > 0) return parts;
  }
  return [DEFAULT_PRODUCT_ID];
}

export function extractRawJustification(reason: string): string {
  const m = RAW_JUST_LINE.exec(reason);
  return m && m[1] ? m[1].trim() : '';
}

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
    timestamp: docTime.toISOString().replace(/\.\d+Z$/, 'Z'),
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

// sha256() is async but we want JSON.stringify to be synchronous; pre-hash
// the input bytes once at the top of convertHdfToCyclonedxVex via a tiny
// non-cryptographic FNV digest. The CycloneDX serialNumber is opaque to
// consumers — it only needs to be stable per input.
function buildSerialNumberSync(input: string, a: HDFAmendments): string {
  if (a.amendmentId) return `urn:uuid:${a.amendmentId}`;
  return `urn:uuid:${fnv1a(input)}`;
}

function fnv1a(s: string): string {
  let h = 0x811c9dc5;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 0x01000193) >>> 0;
  }
  // Pad to a 32-hex-char string (UUID-ish length) by repeating the
  // 8-hex-char digest. Not cryptographically meaningful — see note above.
  const d = h.toString(16).padStart(8, '0');
  return (d + d + d + d).slice(0, 32);
}

