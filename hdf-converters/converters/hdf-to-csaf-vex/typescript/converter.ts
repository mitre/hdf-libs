/**
 * HDF Amendments to CSAF VEX (csaf_vex profile) converter.
 *
 * Reverse direction of csaf-vex-to-hdf. Intentionally partial-fidelity:
 * fields the shared VEX mapping considers consumer-action-bearing survive
 * round-trip; the rest collapse into the available CSAF fields.
 */

import {
  Justification,
  MilestoneStatus,
  OverrideType,
  type HDFAmendments,
  type StandaloneOverride,
} from '@mitre/hdf-schema';
import { parseJSON } from '@mitre/hdf-utilities';
import { validateInputSize } from '../../../shared/typescript/converterutil.js';
import {
  affectedPackageToIdentifier,
  exportStatusFor,
  VexStatus,
} from '../../../shared/typescript/vex/mapping.js';

const CVE_ID_PATTERN = /^CVE-\d{4}-\d{4,}$/;
const PRODUCTS_LINE = /^Products:\s*(.+)$/m;
const DEFAULT_PRODUCT_ID = 'HDFPID-0001';

interface CSAFVexDocument {
  document: {
    category: 'csaf_vex';
    csaf_version: '2.0';
    title?: string;
    notes?: { category: string; text: string; title?: string }[];
    publisher: { category: string; name: string; namespace?: string };
    tracking: {
      id: string;
      status: 'final';
      version: string;
      current_release_date: string;
      initial_release_date: string;
      revision_history: { date: string; number: string; summary: string }[];
      generator?: { engine: { name: string; version: string }; date: string };
    };
  };
  product_tree: { full_product_names: { name: string; product_id: string }[] };
  vulnerabilities: Vulnerability[];
}

interface Vulnerability {
  cve: string;
  notes?: { category: string; text: string }[];
  product_status?: {
    fixed?: string[];
    known_affected?: string[];
    known_not_affected?: string[];
  };
  flags?: { label: string; date?: string; product_ids: string[] }[];
  threats?: { category: string; details: string; product_ids?: string[] }[];
  remediations?: { category: string; details: string; product_ids?: string[] }[];
  references?: { category?: string; summary?: string; url: string }[];
}

export function convertHdfToCsafVex(input: string, converterVersion: string): string {
  validateInputSize(input, 'hdf-to-csaf-vex');
  const amendments = parseJSON<HDFAmendments>(input);
  const groups = groupByCVE(amendments.overrides ?? []);
  const productSet = new Map<string, true>();
  const vulnerabilities: Vulnerability[] = [];

  for (const group of groups) {
    const v = buildVulnerability(group);
    if (!v) continue;
    vulnerabilities.push(v);
    for (const p of productIDsForGroup(group)) productSet.set(p, true);
  }

  if (vulnerabilities.length === 0) {
    throw new Error(
      'hdf-to-csaf-vex: no overrides with CVE-shaped requirementIds; nothing to emit',
    );
  }

  const products = [...productSet.keys()].sort();
  const doc = buildDocument(amendments, converterVersion);
  doc.vulnerabilities = vulnerabilities;
  doc.product_tree.full_product_names =
    products.length > 0
      ? products.map((p) => ({ name: p, product_id: p }))
      : [{ name: DEFAULT_PRODUCT_ID, product_id: DEFAULT_PRODUCT_ID }];

  return JSON.stringify(doc, null, 2);
}

interface CveGroup {
  cve: string;
  overrides: StandaloneOverride[];
}

function groupByCVE(overrides: StandaloneOverride[]): CveGroup[] {
  const groups = new Map<string, CveGroup>();
  for (const o of overrides) {
    if (!CVE_ID_PATTERN.test(o.requirementId)) continue;
    let g = groups.get(o.requirementId);
    if (!g) {
      g = { cve: o.requirementId, overrides: [] };
      groups.set(o.requirementId, g);
    }
    g.overrides.push(o);
  }
  return [...groups.values()].sort((a, b) => a.cve.localeCompare(b.cve));
}

function productIDsForGroup(group: CveGroup): string[] {
  const seen = new Set<string>();
  for (const o of group.overrides) {
    for (const p of productIDsFor(o)) seen.add(p);
  }
  return [...seen].sort();
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
    const parts = m[1]
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean);
    if (parts.length > 0) return parts;
  }
  return [DEFAULT_PRODUCT_ID];
}

export function stripProductsLine(reason: string): string {
  return reason.replace(PRODUCTS_LINE, '').replace(/\n+$/, '');
}

function allMilestonesCompleted(o: StandaloneOverride): boolean {
  if (!o.milestones || o.milestones.length === 0) return false;
  return o.milestones.every((m) => m.status === MilestoneStatus.Completed);
}

function buildVulnerability(group: CveGroup): Vulnerability | undefined {
  const v: Vulnerability = { cve: group.cve };
  const status: NonNullable<Vulnerability['product_status']> = {};
  let emitted = false;

  for (const o of group.overrides) {
    const pids = productIDsFor(o);
    let canonical = exportStatusFor(o, allMilestonesCompleted(o), false);
    if (!canonical) continue;

    // exportStatusFor returns Fixed only when closureChained is true,
    // which a one-shot export doesn't know. Promote poam-with-all-complete
    // to Fixed here so the obvious case round-trips.
    if (
      o.type === OverrideType.Poam &&
      canonical === VexStatus.Affected &&
      allMilestonesCompleted(o)
    ) {
      canonical = VexStatus.Fixed;
    }

    if (canonical === VexStatus.NotAffected) {
      status.known_not_affected = (status.known_not_affected ?? []).concat(pids);
      if (o.justification) {
        v.flags = v.flags ?? [];
        v.flags.push({
          label: String(o.justification as Justification),
          product_ids: pids,
          date: new Date(o.appliedAt).toISOString().replace(/\.\d+Z$/, 'Z'),
        });
      }
      emitted = true;
    } else if (canonical === VexStatus.Fixed) {
      status.fixed = (status.fixed ?? []).concat(pids);
      for (const m of o.milestones ?? []) {
        if (!m.description) continue;
        v.remediations = v.remediations ?? [];
        v.remediations.push({ category: 'vendor_fix', details: m.description, product_ids: pids });
      }
      emitted = true;
    } else if (canonical === VexStatus.Affected) {
      status.known_affected = (status.known_affected ?? []).concat(pids);
      if (o.reason) {
        v.threats = v.threats ?? [];
        v.threats.push({
          category: 'impact',
          details: stripProductsLine(o.reason),
          product_ids: pids,
        });
      }
      if (o.type === OverrideType.Poam) {
        for (const m of o.milestones ?? []) {
          if (!m.description) continue;
          v.remediations = v.remediations ?? [];
          v.remediations.push({
            category: 'workaround',
            details: m.description,
            product_ids: pids,
          });
        }
      }
      emitted = true;
    }

    for (const e of o.evidence ?? []) {
      if (e.type !== 'url' || !e.data) continue;
      v.references = v.references ?? [];
      v.references.push({ category: 'external', summary: e.description ?? '', url: e.data });
    }
  }

  // emitted is false only if every override in the group returned an
  // unmappable canonical status — defensive guard, not reachable from the
  // current shared mapping (which handles every override type).
  /* c8 ignore next */
  if (!emitted) return undefined;

  if (status.fixed) status.fixed = [...new Set(status.fixed)];
  if (status.known_affected) status.known_affected = [...new Set(status.known_affected)];
  if (status.known_not_affected) status.known_not_affected = [...new Set(status.known_not_affected)];
  v.product_status = status;

  if (v.references) {
    const seen = new Set<string>();
    v.references = v.references.filter((r) => {
      if (seen.has(r.url)) return false;
      seen.add(r.url);
      return true;
    });
  }

  return v;
}

function buildDocument(
  amendments: HDFAmendments,
  converterVersion: string,
): CSAFVexDocument {
  const now = new Date().toISOString().replace(/\.\d+Z$/, 'Z');
  const publisherName = amendments.appliedBy?.identifier || 'HDF Amendments Export';
  const trackingId = amendments.amendmentId || 'HDF-VEX-EXPORT';
  const docVersion = amendments.version || '1';
  const title = amendments.name || 'HDF Amendments exported as CSAF VEX';
  const notes: { category: string; text: string; title?: string }[] = [];
  if (amendments.description) {
    notes.push({ category: 'summary', text: amendments.description, title: 'Description' });
  }
  return {
    document: {
      category: 'csaf_vex',
      csaf_version: '2.0',
      title,
      notes,
      publisher: { category: 'other', name: publisherName },
      tracking: {
        id: trackingId,
        status: 'final',
        version: docVersion,
        current_release_date: now,
        initial_release_date: now,
        revision_history: [
          { date: now, number: docVersion, summary: 'Generated by hdf-to-csaf-vex from HDF Amendments.' },
        ],
        generator: { engine: { name: 'hdf-to-csaf-vex', version: converterVersion }, date: now },
      },
    },
    product_tree: { full_product_names: [] },
    vulnerabilities: [],
  };
}
