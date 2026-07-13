/**
 * HDF Amendments to OpenVEX converter.
 *
 * Reverse direction of openvex-to-hdf. Step 4f amendment-output pattern,
 * partial-fidelity by design — consumer-action-bearing fields (CVE id,
 * status, justification) survive round-trip; the rest collapse.
 */

import { sha256, formatTimestampSeconds } from '@mitre/hdf-utilities';
import {
  MilestoneStatus,
  OverrideType,
  type HDFAmendments,
  type StandaloneOverride,
} from '@mitre/hdf-schema';
import { validateInputSize, parseHdf, hdfTime } from '../../../shared/typescript/converterutil.js';
import {
  affectedPackageToIdentifier,
  exportStatusFor,
  VexStatus,
} from '../../../shared/typescript/vex/mapping.js';

// Go's zero time.Time, which the Go converter emits when appliedAt is absent.
// TypeScript would otherwise build an Invalid Date here and throw on format.
const GO_ZERO_TIME = new Date('0001-01-01T00:00:00Z');

const CVE_ID_PATTERN = /^CVE-\d{4}-\d{4,}$/;
const PRODUCTS_LINE = /^Products:\s*(.+)$/m;
const OPENVEX_CONTEXT = 'https://openvex.dev/ns/v0.2.0';
const OPENVEX_NAMESPACE = 'https://openvex.dev/docs/public/';
const DEFAULT_PRODUCT_ID = 'HDFPID-0001';

interface Document {
  '@context': string;
  '@id': string;
  author: string;
  role?: string;
  timestamp: string;
  version: number;
  statements: Statement[];
}

interface Statement {
  vulnerability: { '@id'?: string; name: string };
  products?: { '@id': string }[];
  status: string;
  justification?: string;
  impact_statement?: string;
  action_statement?: string;
  timestamp?: string;
}

export async function convertHdfToOpenVex(
  input: string,
  converterVersion: string,
): Promise<string> {
  validateInputSize(input, 'hdf-to-openvex');
  const amendments = parseHdf<HDFAmendments>(input);

  const statements: Statement[] = [];
  let earliest: Date | undefined;
  for (const o of amendments.overrides ?? []) {
    const s = overrideToStatement(o);
    if (!s) continue;
    statements.push(s);
    const t = hdfTime(o.appliedAt);
    if (!t) continue;
    if (!earliest || t < earliest) earliest = t;
  }

  if (statements.length === 0) {
    throw new Error(
      'hdf-to-openvex: no overrides with CVE-shaped requirementIds; nothing to emit',
    );
  }

  statements.sort((a, b) => a.vulnerability.name.localeCompare(b.vulnerability.name));

  const author = amendments.appliedBy?.identifier || 'HDF Amendments Export';
  const role = amendments.appliedBy?.description;

  const doc: Document = {
    '@context': OPENVEX_CONTEXT,
    '@id': await buildDocumentID(input, amendments),
    author,
    role,
    timestamp: formatTimestampSeconds(earliest ?? new Date()),
    version: 1,
    statements,
  };

  void converterVersion; // OpenVEX has no generator field; version is unused here
  return JSON.stringify(doc, null, 2);
}

function overrideToStatement(o: StandaloneOverride): Statement | undefined {
  if (!CVE_ID_PATTERN.test(o.requirementId)) return undefined;
  let canonical = exportStatusFor(o, allMilestonesCompleted(o), false);
  if (!canonical) return undefined;
  if (
    o.type === OverrideType.Poam &&
    canonical === VexStatus.Affected &&
    allMilestonesCompleted(o)
  ) {
    canonical = VexStatus.Fixed;
  }

  const notAffected = canonical === VexStatus.NotAffected;
  const justification = notAffected && o.justification ? String(o.justification) : '';
  const impact = notAffected ? stripProductsLine(o.reason ?? '') : '';
  let action = '';
  if (canonical === VexStatus.Fixed) {
    action = firstMilestoneAction(o) || 'Fix applied; consumer re-scan confirmed clean.';
  } else if (canonical === VexStatus.Affected) {
    action = firstMilestoneAction(o) || stripProductsLine(o.reason ?? '');
  }

  // Key order mirrors the Go Statement struct so both languages emit identical bytes.
  return {
    vulnerability: {
      '@id': `https://nvd.nist.gov/vuln/detail/${o.requirementId}`,
      name: o.requirementId,
    },
    products: productsFor(o),
    status: String(canonical),
    ...(justification && { justification }),
    ...(impact && { impact_statement: impact }),
    ...(action && { action_statement: action }),
    timestamp: formatTimestampSeconds(hdfTime(o.appliedAt) ?? GO_ZERO_TIME),
  };
}

export function productsFor(o: StandaloneOverride): { '@id': string }[] {
  // Structured affectedPackages is the source of truth (v3.2.x and later).
  if (o.affectedPackages && o.affectedPackages.length > 0) {
    const ids = o.affectedPackages
      .map((p) => affectedPackageToIdentifier(p))
      .filter((id): id is string => Boolean(id));
    if (ids.length > 0) return ids.map((id) => ({ '@id': id }));
  }
  // Backward-compat fallbacks for pre-affectedPackages HDF inputs:
  // 1. componentRef (HDF-internal UUID — emit verbatim)
  // 2. legacy 'Products:' reason-line annotation
  let ids: string[] = [];
  if (o.componentRef) {
    ids = [o.componentRef];
  } else {
    const m = PRODUCTS_LINE.exec(o.reason ?? '');
    if (m && m[1]) {
      ids = m[1].split(',').map((s) => s.trim()).filter(Boolean);
    }
  }
  if (ids.length === 0) ids = [DEFAULT_PRODUCT_ID];
  return ids.map((id) => ({ '@id': id }));
}

function firstMilestoneAction(o: StandaloneOverride): string {
  for (const m of o.milestones ?? []) {
    if (m.description) return m.description;
  }
  return '';
}

function allMilestonesCompleted(o: StandaloneOverride): boolean {
  if (!o.milestones || o.milestones.length === 0) return false;
  return o.milestones.every((m) => m.status === MilestoneStatus.Completed);
}

export function stripProductsLine(reason: string): string {
  return reason.replace(PRODUCTS_LINE, '').replace(/\n+$/, '');
}

async function buildDocumentID(input: string, a: HDFAmendments): Promise<string> {
  if (a.amendmentId) return `${OPENVEX_NAMESPACE}vex-${a.amendmentId}`;
  const digest = await sha256(input);
  return `${OPENVEX_NAMESPACE}vex-${digest}`;
}
