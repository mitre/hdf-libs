/**
 * HDF Amendments to OpenVEX converter.
 *
 * Reverse direction of openvex-to-hdf. Step 4f amendment-output pattern,
 * partial-fidelity by design — consumer-action-bearing fields (CVE id,
 * status, justification) survive round-trip; the rest collapse.
 */

import { parseJSON, sha256 } from '@mitre/hdf-utilities';
import {
  MilestoneStatus,
  OverrideType,
  type HDFAmendments,
  type StandaloneOverride,
} from '@mitre/hdf-schema';
import { validateInputSize } from '../../../shared/typescript/converterutil.js';
import {
  affectedPackageToIdentifier,
  exportStatusFor,
  VexStatus,
} from '../../../shared/typescript/vex/mapping.js';

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
  const amendments = parseJSON<HDFAmendments>(input);

  const statements: Statement[] = [];
  let earliest: Date | undefined;
  for (const o of amendments.overrides ?? []) {
    const s = overrideToStatement(o);
    if (!s) continue;
    statements.push(s);
    const t = new Date(o.appliedAt);
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
    timestamp: (earliest ?? new Date()).toISOString().replace(/\.\d+Z$/, 'Z'),
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

  const stmt: Statement = {
    vulnerability: {
      name: o.requirementId,
      '@id': `https://nvd.nist.gov/vuln/detail/${o.requirementId}`,
    },
    status: String(canonical),
    timestamp: new Date(o.appliedAt).toISOString().replace(/\.\d+Z$/, 'Z'),
    products: productsFor(o),
  };

  if (canonical === VexStatus.NotAffected) {
    if (o.justification) stmt.justification = String(o.justification);
    const impact = stripProductsLine(o.reason ?? '');
    if (impact) stmt.impact_statement = impact;
  } else if (canonical === VexStatus.Fixed) {
    stmt.action_statement =
      firstMilestoneAction(o) || 'Fix applied; consumer re-scan confirmed clean.';
  } else if (canonical === VexStatus.Affected) {
    stmt.action_statement = firstMilestoneAction(o) || stripProductsLine(o.reason ?? '');
  }

  return stmt;
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
