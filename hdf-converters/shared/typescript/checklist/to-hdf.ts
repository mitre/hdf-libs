import type {
  HdfResults,
  EvaluatedBaseline,
  EvaluatedRequirement,
  Checksum,
  Component,
  Description,
} from '@mitre/hdf-schema';
import {
  Copyright,
  Severity,
  createMinimalBaseline,
  createRequirement,
  createResult,
  severityToImpact,
} from '@mitre/hdf-schema';
import { getCCINistMappings } from '@mitre/hdf-mappings';
import { deriveControlTypeFromTags, stripHTML } from '../converterutil.js';
import { Asset, Checklist, Stig, Vuln } from './model.js';
import { statusToHdf } from './status.js';

const CONVERTER_VERSION = '1.0.0';

/**
 * Map the format-neutral Checklist model to an HDF Results object.
 * controlType is derived per-Vuln from CCI->NIST; verificationMethod and
 * applicability are omitted (the checklist format cannot substantiate them).
 * Original-format metadata is stashed in extensions/tags for round-trip.
 */
export function checklistToHdf(cl: Checklist, resultsChecksum: Checksum): HdfResults {
  const baselines = cl.stigs.map((s) => stigToBaseline(s, resultsChecksum));

  const hdf: HdfResults = {
    baselines,
    generator: { name: 'hdf-converters', version: CONVERTER_VERSION },
    tool: { name: 'DISA STIG Viewer', format: cl.format === 'cklb' ? 'CKLB' : 'CKL' },
    timestamp: new Date(),
  };

  const component = assetToComponent(cl.asset);
  if (component) hdf.components = [component];

  const ext = rootExtensions(cl);
  if (Object.keys(ext).length > 0) hdf.extensions = ext;
  return hdf;
}

function stigToBaseline(s: Stig, resultsChecksum: Checksum): EvaluatedBaseline {
  const requirements = s.vulns.map(vulnToRequirement);
  const baseline = createMinimalBaseline('STIG Checklist Scan', requirements, {
    resultsChecksum,
  }) as EvaluatedBaseline;
  if (s.title) baseline.title = s.title;
  if (s.version) baseline.version = s.version;
  const ext = baselineExtensions(s);
  if (Object.keys(ext).length > 0) baseline.extensions = ext;
  return baseline;
}

function vulnToRequirement(v: Vuln): EvaluatedRequirement {
  const severity = (v.severity ?? '').toLowerCase();
  const impact = severity ? severityToImpact(severity) : 0.5;

  // stripHTML for parity with the Go mapping (CKL text can embed markup).
  const descriptions: Description[] = [
    { label: 'default', data: stripHTML(v.vulnDiscuss ?? '') },
  ];
  if (v.checkContent) descriptions.push({ label: 'check', data: stripHTML(v.checkContent) });
  if (v.fixText) descriptions.push({ label: 'fix', data: stripHTML(v.fixText) });

  const message = [v.findingDetails, v.comments]
    .map((s) => (s ?? '').trim())
    .filter(Boolean)
    .join('\n\n');
  const result = createResult(statusToHdf(v.status), message, {
    codeDesc: `STIG rule ${v.ruleVer ?? ''}`,
  });

  const tags: Record<string, unknown> = {};
  let nistTags: string[] = [];
  if (v.ccis.length > 0) {
    tags['cci'] = v.ccis;
    nistTags = [...new Set(v.ccis.flatMap((c) => getCCINistMappings(c) ?? []))].sort();
    tags['nist'] = nistTags;
  } else {
    tags['nist'] = [];
  }
  setIf(tags, 'rid', v.ruleID);
  setIf(tags, 'stig_id', v.ruleVer);
  setIf(tags, 'gtitle', v.groupTitle);
  setIf(tags, 'group_id', v.groupID);
  setIf(tags, 'weight', v.weight);
  setIf(tags, 'severity', severity);
  if (v.legacyIDs && v.legacyIDs.length) tags['legacy_ids'] = v.legacyIDs;
  if (v.extra && Object.keys(v.extra).length > 0) tags['cklMetadata'] = { ...v.extra };

  const req = createRequirement(
    v.vulnNum,
    v.ruleTitle ?? v.vulnNum,
    descriptions,
    impact,
    [result],
    { tags }
  ) as EvaluatedRequirement;
  if (severity) req.severity = severity as Severity;

  const controlType = deriveControlTypeFromTags(nistTags);
  if (controlType !== undefined) req.controlType = controlType;
  return req;
}

function assetToComponent(a: Asset): Component | undefined {
  if (!a.hostName && !a.hostIP && !a.hostFQDN) return undefined;
  // Name falls back to FQDN then IP so the component always has a usable
  // identity (a checklist may carry only HOST_IP / HOST_FQDN).
  const name = a.hostName || a.hostFQDN || a.hostIP || '';
  const c: Component = { name, type: Copyright.Host };
  if (a.hostIP) c.ipAddress = a.hostIP;
  if (a.hostFQDN) c.fqdn = a.hostFQDN;
  if (a.hostMAC) c.macAddress = a.hostMAC;
  return c;
}

function rootExtensions(cl: Checklist): Record<string, unknown> {
  const ext: Record<string, unknown> = { checklistFormat: cl.format || 'ckl' };
  if (cl.cklbVersion) ext['cklbVersion'] = cl.cklbVersion;
  const ax: Record<string, unknown> = {};
  setIf(ax, 'role', cl.asset.role);
  setIf(ax, 'assetType', cl.asset.assetType);
  setIf(ax, 'marking', cl.asset.marking);
  setIf(ax, 'targetKey', cl.asset.targetKey);
  setIf(ax, 'techArea', cl.asset.techArea);
  setIf(ax, 'targetComment', cl.asset.targetComment);
  setIf(ax, 'webDbSite', cl.asset.webDBSite);
  setIf(ax, 'webDbInstance', cl.asset.webDBInstance);
  setIf(ax, 'classification', cl.asset.classification);
  if (cl.asset.webOrDatabase) ax['webOrDatabase'] = true;
  if (Object.keys(ax).length > 0) ext['assetExtras'] = ax;
  return ext;
}

function baselineExtensions(s: Stig): Record<string, unknown> {
  const ext: Record<string, unknown> = {};
  setIf(ext, 'stigid', s.stigID);
  setIf(ext, 'uuid', s.uuid);
  setIf(ext, 'releaseInfo', s.releaseInfo);
  setIf(ext, 'displayName', s.displayName);
  setIf(ext, 'referenceIdentifier', s.referenceIdentifier);
  setIf(ext, 'classification', s.classification);
  return ext;
}

function setIf(m: Record<string, unknown>, key: string, val: string | undefined): void {
  if (val) m[key] = val;
}
