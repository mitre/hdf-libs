import { parseHdf, hdfTime } from '../converterutil.js';
import type {
  HDFResults,
  EvaluatedBaseline,
  EvaluatedRequirement,
  Description,
  ResultStatus,
  StatusOverride,
} from '@mitre/hdf-schema';
import { nistToCci } from '@mitre/hdf-mappings';
import { formatTimestamp } from '@mitre/hdf-utilities';
import { Asset, Checklist, Stig, Vuln } from './model.js';
import { statusFromHdf } from './status.js';

/**
 * Map HDF Results back to the format-neutral Checklist model. When the HDF
 * carries checklist passthrough (extensions/tags from checklistToHdf), the
 * original fields are reproduced losslessly; otherwise required checklist
 * fields are synthesized best-effort so any HDF yields a valid checklist.
 */
export function hdfToChecklist(input: string): Checklist {
  const hdf = parseHdf<HDFResults>(input);
  if (!hdf || !Array.isArray(hdf.baselines) || hdf.baselines.length === 0) {
    throw new Error('hdf to checklist: HDF has no baselines');
  }

  const ext = (hdf.extensions ?? {}) as Record<string, unknown>;
  const format = strVal(ext, 'checklistFormat') || 'ckl';
  const cklbVersion = strVal(ext, 'cklbVersion');

  const asset = buildAsset(hdf, ext);
  const stigs = hdf.baselines.map(baselineToStig);

  return {
    format,
    cklbVersion: cklbVersion || undefined,
    active: boolVal(ext, 'cklbActive'),
    hasPath: boolVal(ext, 'cklbHasPath'),
    mode: numVal(ext, 'cklbMode'),
    asset,
    stigs,
  };
}

function buildAsset(hdf: HDFResults, ext: Record<string, unknown>): Asset {
  const asset: Asset = {};
  const comp = hdf.components?.[0];
  if (comp) {
    // Prefer the dedicated hostname. For HDF produced before hostname existed,
    // fall back to Name — but only when Name holds a real short name, not when
    // it merely mirrors the fqdn/ip fallback the old converter stored there
    // (which would fabricate a HOST_NAME the source never had).
    if (comp.hostname) {
      asset.hostName = comp.hostname;
    } else if (comp.name && comp.name !== comp.fqdn && comp.name !== comp.ipAddress) {
      asset.hostName = comp.name;
    }
    asset.hostIP = comp.ipAddress;
    asset.hostFQDN = comp.fqdn;
    asset.hostMAC = comp.macAddress;
  }
  const ax = ext['assetExtras'];
  if (ax && typeof ax === 'object') {
    const a = ax as Record<string, unknown>;
    asset.role = strVal(a, 'role');
    asset.assetType = strVal(a, 'assetType');
    asset.marking = strVal(a, 'marking');
    asset.targetKey = strVal(a, 'targetKey');
    asset.techArea = strVal(a, 'techArea');
    asset.targetComment = strVal(a, 'targetComment');
    asset.webDBSite = strVal(a, 'webDbSite');
    asset.webDBInstance = strVal(a, 'webDbInstance');
    asset.classification = strVal(a, 'classification');
    asset.webOrDatabase = a['webOrDatabase'] === true;
  }
  return asset;
}

function baselineToStig(bl: EvaluatedBaseline): Stig {
  const ext = (bl.extensions ?? {}) as Record<string, unknown>;
  const stigID = strVal(ext, 'stigid') || bl.title || '';
  return {
    stigID,
    title: bl.title,
    version: bl.version,
    uuid: strVal(ext, 'uuid'),
    releaseInfo: strVal(ext, 'releaseInfo'),
    displayName: strVal(ext, 'displayName'),
    referenceIdentifier: strVal(ext, 'referenceIdentifier'),
    classification: strVal(ext, 'classification'),
    vulns: bl.requirements.map(requirementToVuln),
  };
}

function requirementToVuln(req: EvaluatedRequirement): Vuln {
  const tags = (req.tags ?? {}) as Record<string, unknown>;
  const descs = req.descriptions ?? [];
  const sev = overrideSeverity(req);
  return {
    vulnNum: req.id,
    ruleID: strVal(tags, 'rid'),
    ruleVer: strVal(tags, 'stig_id'),
    groupID: strVal(tags, 'group_id') || req.id,
    groupTitle: strVal(tags, 'gtitle'),
    ruleTitle: req.title,
    weight: strVal(tags, 'weight'),
    severity: resolveSeverity(req, tags),
    vulnDiscuss: descData(descs, 'default'),
    checkContent: descData(descs, 'check'),
    fixText: descData(descs, 'fix'),
    ccis: resolveCcis(tags),
    legacyIDs: strSlice(tags, 'legacy_ids'),
    status: statusFromHdf(effectiveOrRawStatus(req)),
    findingDetails: composeFindingDetails(req),
    comments: composeComments(tags, req),
    severityOverride: sev.severity,
    severityJustification: sev.justification,
    extra: extractCklMetadata(tags),
  };
}

// effectiveOrRawStatus drives the exported STATUS from the resolved
// post-override status when present, falling back to the raw first result.
function effectiveOrRawStatus(req: EvaluatedRequirement): ResultStatus | undefined {
  return req.effectiveStatus ?? req.results?.[0]?.status;
}

// composeFindingDetails builds finding_details from every result's status,
// codeDesc, and message — not just results[0].message.
function composeFindingDetails(req: EvaluatedRequirement): string {
  const results = req.results ?? [];
  if (results.length === 0) return '';
  return results
    .map((r) => {
      const body: string[] = [];
      const cd = (r.codeDesc ?? '').trim();
      if (cd) body.push(cd);
      const msg = (r.message ?? '').trim();
      if (msg && (body.length === 0 || msg !== body[0])) body.push(msg);
      let seg = `[${r.status}]`;
      if (body.length > 0) seg += ' ' + body.join('\n');
      return seg;
    })
    .join('\n\n');
}

// composeComments merges the round-tripped comments (tags.comments) with the
// provenance of any status overrides / disposition governing this requirement.
function composeComments(tags: Record<string, unknown>, req: EvaluatedRequirement): string {
  const parts: string[] = [];
  const existing = strVal(tags, 'comments');
  if (existing) parts.push(existing);
  const prov = overrideProvenance(req);
  if (prov) parts.push(prov);
  return parts.join('\n\n');
}

function overrideProvenance(req: EvaluatedRequirement): string {
  const overrides = req.statusOverrides ?? [];
  if (overrides.length > 0) {
    return overrides.map(formatOverride).join('\n');
  }
  if (req.disposition) return `Disposition: ${req.disposition}`;
  return '';
}

function formatOverride(o: StatusOverride): string {
  let s = `Override [${o.type}]`;
  if (o.reason) s += `: ${o.reason}`;
  const meta: string[] = [];
  if (o.appliedBy?.identifier) meta.push(`by ${o.appliedBy.identifier}`);
  const applied = hdfTime(o.appliedAt);
  if (applied) meta.push(`applied ${formatTimestamp(applied)}`);
  const expires = hdfTime(o.expiresAt);
  if (expires) meta.push(`expires ${formatTimestamp(expires)}`);
  if (meta.length > 0) s += ` (${meta.join(', ')})`;
  return s;
}

// overrideSeverity derives the checklist severity override from the first
// impact-bearing status override (a risk adjustment).
function overrideSeverity(req: EvaluatedRequirement): { severity: string; justification: string } {
  for (const o of req.statusOverrides ?? []) {
    if (o.impact) {
      return { severity: qualSeverityFromImpact(o.impact.value), justification: o.reason ?? '' };
    }
  }
  return { severity: '', justification: '' };
}

function qualSeverityFromImpact(impact: number): string {
  if (impact >= 0.7) return 'high';
  if (impact >= 0.4) return 'medium';
  return 'low';
}

function resolveSeverity(req: EvaluatedRequirement, tags: Record<string, unknown>): string {
  const tagSev = strVal(tags, 'severity');
  if (tagSev) return tagSev;
  if (req.severity) return String(req.severity).toLowerCase();
  const i = req.impact ?? 0;
  if (i >= 0.7) return 'high';
  if (i >= 0.4) return 'medium';
  if (i > 0) return 'low';
  return '';
}

function resolveCcis(tags: Record<string, unknown>): string[] {
  const direct = strSlice(tags, 'cci');
  if (direct.length > 0) return direct;
  const nist = strSlice(tags, 'nist');
  if (nist.length > 0) {
    const ccis = nistToCci(nist);
    if (ccis.length > 0) return ccis;
  }
  return [];
}

function extractCklMetadata(tags: Record<string, unknown>): Record<string, string> | undefined {
  const meta = tags['cklMetadata'];
  if (!meta || typeof meta !== 'object') return undefined;
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(meta as Record<string, unknown>)) {
    if (typeof v === 'string') out[k] = v;
  }
  return Object.keys(out).length > 0 ? out : undefined;
}

function descData(descs: Description[], label: string): string {
  return descs.find((d) => d.label === label)?.data ?? '';
}

function strVal(m: Record<string, unknown>, key: string): string {
  const v = m[key];
  return typeof v === 'string' ? v : '';
}

function boolVal(m: Record<string, unknown>, key: string): boolean {
  return m[key] === true;
}

function numVal(m: Record<string, unknown>, key: string): number {
  const v = m[key];
  return typeof v === 'number' ? v : 0;
}

function strSlice(m: Record<string, unknown>, key: string): string[] {
  const v = m[key];
  if (Array.isArray(v)) return v.filter((e): e is string => typeof e === 'string');
  return [];
}
