import { parseJSON } from '@mitre/hdf-utilities';
import type {
  HDFResults,
  EvaluatedBaseline,
  EvaluatedRequirement,
  Description,
} from '@mitre/hdf-schema';
import { nistToCci } from '@mitre/hdf-mappings';
import { Asset, Checklist, Stig, Vuln } from './model.js';
import { statusFromHdf } from './status.js';

/**
 * Map HDF Results back to the format-neutral Checklist model. When the HDF
 * carries checklist passthrough (extensions/tags from checklistToHdf), the
 * original fields are reproduced losslessly; otherwise required checklist
 * fields are synthesized best-effort so any HDF yields a valid checklist.
 */
export function hdfToChecklist(input: string): Checklist {
  const hdf = parseJSON<HDFResults>(input);
  if (!hdf || !Array.isArray(hdf.baselines) || hdf.baselines.length === 0) {
    throw new Error('hdf to checklist: HDF has no baselines');
  }

  const ext = (hdf.extensions ?? {}) as Record<string, unknown>;
  const format = strVal(ext, 'checklistFormat') || 'ckl';
  const cklbVersion = strVal(ext, 'cklbVersion');

  const asset = buildAsset(hdf, ext);
  const stigs = hdf.baselines.map(baselineToStig);

  return { format, cklbVersion: cklbVersion || undefined, asset, stigs };
}

function buildAsset(hdf: HDFResults, ext: Record<string, unknown>): Asset {
  const asset: Asset = {};
  const comp = hdf.components?.[0];
  if (comp) {
    asset.hostName = comp.name;
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
    status: statusFromHdf(req.results?.[0]?.status),
    findingDetails: req.results?.[0]?.message,
    extra: extractCklMetadata(tags),
  };
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

function strSlice(m: Record<string, unknown>, key: string): string[] {
  const v = m[key];
  if (Array.isArray(v)) return v.filter((e): e is string => typeof e === 'string');
  return [];
}
