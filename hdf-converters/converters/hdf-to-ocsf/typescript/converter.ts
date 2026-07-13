import {
  type Obj,
  asMap,
  asArr,
  getStr,
  setIf,
  statusOf,
  stringSlice,
  firstResultStartTime,
  defaultDescription,
  firstRefURL,
  runExport,
  firstCVE,
  epochMillis,
  floatNumber,
} from '../../../shared/typescript/exportmap.js';
import { impactToSeverity } from '@mitre/hdf-utilities';

/**
 * HDF Results -> OCSF (Open Cybersecurity Schema Framework) Finding NDJSON.
 * See the ADR-0002 addendum (HDF -> OCSF, wvc3.5). Pinned to OCSF v1.8.0.
 *
 * One Finding per requirement: a CVE finding -> Vulnerability Finding
 * (class_uid 2002), any other -> Compliance Finding (class_uid 2003), both in
 * the Findings category (2). Status model is raw-primary: compliance.status_id
 * carries the RAW verdict (a failed control stays Fail even when waived). The
 * acceptance axis rides the base finding status_id: a raw-failing finding that
 * an override drove non-failing (waiver/falsePositive/attestation) -> 3
 * Suppressed, everything else -> 1 New; a riskAdjustment/operationalRequirement/
 * poam that leaves the finding failing stays New (actionable, only re-scored).
 * The exact override chain is preserved in unmapped.hdf_requirement (+ comment).
 * Canonical "still actionable" query: compliance.status_id=3 AND status_id=1.
 *
 * Shares the generic access / status roll-up / field extraction / canonical
 * line serialization with the other exporters via exportmap; output is held
 * byte-identical with the Go implementation.
 */

const OCSF_VERSION = '1.8.0';
const CATEGORY_FINDINGS = 2;
const CLASS_COMPLIANCE = 2003;
const CLASS_VULNERABILITY = 2002;
const ACTIVITY_CREATE = 1;
const STATUS_NEW = 1;
const STATUS_SUPPRESSED = 3;

export function convertHdfToOcsf(input: string, converterVersion = '0.1.0'): string {
  return runExport(input, 'hdf-to-ocsf', (req, baseline, docTimestamp, tool, generator, component) =>
    buildFinding(req, baseline, docTimestamp, tool, generator, component, converterVersion),
  );
}

function buildFinding(
  req: Obj,
  baseline: Obj,
  docTimestamp: string,
  tool: Obj | undefined,
  generator: Obj | undefined,
  component: Obj | undefined,
  converterVersion: string,
): Obj {
  const st = statusOf(req);
  const cvssList = asArr(req.cvss);
  const hasCVSS = cvssList !== undefined && cvssList.length > 0;
  const title = getStr(req, 'title');
  const controlID = getStr(req, 'id');

  const cls = hasCVSS ? CLASS_VULNERABILITY : CLASS_COMPLIANCE;

  const findingInfo: Obj = { uid: controlID };
  setIf(findingInfo, 'title', title);
  setIf(findingInfo, 'desc', defaultDescription(req));
  // A Vulnerability Finding (class 2002) has no compliance.checks[] field, so a
  // CVE that also carries NIST/CCI framework tags would otherwise lose that
  // mapping to unmapped only. Surface it on finding_info.tags (OCSF's queryable
  // key/value tag surface). Compliance Findings keep the native compliance.checks[].
  if (hasCVSS) {
    const tags = frameworkTags(req);
    if (tags.length > 0) findingInfo.tags = tags;
  }

  const finding: Obj = {
    category_uid: CATEGORY_FINDINGS,
    class_uid: cls,
    type_uid: cls * 100 + ACTIVITY_CREATE,
    activity_id: ACTIVITY_CREATE,
    severity_id: severityID(req),
    status_id: st.suppressed ? STATUS_SUPPRESSED : STATUS_NEW,
    metadata: buildMetadata(tool, generator, converterVersion),
    finding_info: findingInfo,
    unmapped: { hdf_requirement: req },
  };
  // time is OCSF-required: fall back to 0 (epoch sentinel) when the source
  // carries no parseable timestamp, so the record stays schema-valid.
  finding.time = epochMillis(firstResultStartTime(req, docTimestamp)) ?? 0;
  setIf(finding, 'comment', overrideComment(req));
  const device = buildDevice(component);
  if (device) finding.device = device;

  if (hasCVSS) {
    finding.vulnerabilities = buildVulnerabilities(cvssList!, req);
  } else {
    finding.compliance = buildCompliance(req, baseline, title, st.raw);
  }
  return finding;
}

function severityID(req: Obj): number {
  if (typeof req.impact === 'number') {
    return severityIDFromString(impactToSeverity(req.impact));
  }
  return severityIDFromString(getStr(req, 'severity'));
}

function severityIDFromString(s: string): number {
  switch (s.toLowerCase()) {
    case 'critical':
      return 5;
    case 'high':
      return 4;
    case 'medium':
      return 3;
    case 'low':
      return 2;
    case 'informational':
    case 'info':
    case 'none':
      return 1;
    default:
      return 0;
  }
}

function complianceStatusID(rawStatus: string): number {
  switch (rawStatus) {
    case 'passed':
      return 1;
    case 'failed':
      return 3;
    default: // error, notApplicable, notReviewed
      return 2;
  }
}

// OCSF caption for a compliance.status_id, carried in the sibling
// compliance.status string (OCSF convention: the enum sibling string is the
// caption of the enum value). HDF-native status — which distinguishes
// notApplicable/notReviewed/error, all -> Warning — stays in unmapped.
function complianceStatusCaption(statusID: number): string {
  switch (statusID) {
    case 1:
      return 'Pass';
    case 3:
      return 'Fail';
    default:
      return 'Warning';
  }
}

// Builds a human-readable governance note from the disposition (override type)
// and the governing override's required free-text `reason`.
// (Status_Override.justification is an optional structured controlled-vocabulary
// object, not the human rationale — reason is the field to surface.)
function overrideComment(req: Obj): string {
  const disposition = getStr(req, 'disposition');
  const overrides = asArr(req.statusOverrides) ?? [];
  if (disposition === '' && overrides.length === 0) return '';
  let reason = '';
  if (overrides.length > 0) reason = getStr(asMap(overrides[0]), 'reason');
  if (disposition !== '' && reason !== '') return `${disposition}: ${reason}`;
  if (disposition !== '') return disposition;
  return reason;
}

// metadata.product is OCSF-required: identify the source scanning tool when
// present, else fall back to this exporter's own identity (never omitted).
function buildMetadata(tool: Obj | undefined, generator: Obj | undefined, converterVersion: string): Obj {
  const metadata: Obj = { version: OCSF_VERSION };
  let name = getStr(tool, 'name');
  let version = getStr(tool, 'version');
  let vendor = getStr(tool, 'format');
  if (name === '' && generator) {
    name = getStr(generator, 'name');
    version = getStr(generator, 'version');
  }
  if (name === '') {
    name = 'hdf-to-ocsf';
    version = converterVersion;
    vendor = '';
  }
  const product: Obj = { name };
  setIf(product, 'version', version);
  setIf(product, 'vendor_name', vendor);
  metadata.product = product;
  return metadata;
}

function buildDevice(component: Obj | undefined): Obj | undefined {
  if (!component) return undefined;
  const device: Obj = { type_id: 0 };
  setIf(device, 'name', getStr(component, 'name'));
  setIf(device, 'hostname', getStr(component, 'fqdn'));
  setIf(device, 'ip', getStr(component, 'ipAddress'));
  setIf(device, 'uid', getStr(component, 'componentId'));
  const osName = getStr(component, 'osName');
  if (osName !== '') {
    const os: Obj = { name: osName, type_id: osTypeID(osName) };
    setIf(os, 'version', getStr(component, 'osVersion'));
    device.os = os;
  }
  // device requires at least one identifying attribute (beyond type_id)
  return Object.keys(device).length === 1 ? undefined : device;
}

const OS_LINUX = ['linux', 'rhel', 'red hat', 'ubuntu', 'centos', 'debian', 'fedora', 'suse'];
const OS_MAC = ['mac', 'darwin', 'os x'];

function osTypeID(osName: string): number {
  const n = osName.toLowerCase();
  if (n.includes('windows')) return 100;
  if (OS_LINUX.some((k) => n.includes(k))) return 200;
  if (OS_MAC.some((k) => n.includes(k))) return 300;
  return 0;
}

// frameworkTags builds OCSF finding_info.tags (a key_value_object list) from the
// requirement's NIST/CCI mappings, e.g. {name:'nist', values:['SI-2','RA-5']}.
// Only non-empty mappings are emitted.
function frameworkTags(req: Obj): Obj[] {
  const tags = asMap(req.tags);
  const out: Obj[] = [];
  for (const key of ['nist', 'cci']) {
    const vals = stringSlice(tags?.[key]);
    if (vals.length > 0) out.push({ name: key, values: vals });
  }
  return out;
}

function buildCompliance(req: Obj, baseline: Obj, title: string, rawStatus: string): Obj {
  const statusID = complianceStatusID(rawStatus);
  const compliance: Obj = { status_id: statusID, status: complianceStatusCaption(statusID) };
  const controlID = getStr(req, 'id');
  setIf(compliance, 'control', controlID);

  const baselineName = getStr(baseline, 'name');
  const tags = asMap(req.tags);
  const nist = stringSlice(tags?.nist);
  const cci = stringSlice(tags?.cci);

  const standards: unknown[] = [];
  if (baselineName !== '') standards.push(baselineName);
  if (nist.length > 0) standards.push('NIST SP 800-53');
  if (cci.length > 0) standards.push('CCI');
  if (standards.length > 0) compliance.standards = standards;

  const checks: unknown[] = [];
  if (controlID !== '') {
    const check: Obj = { uid: controlID, status_id: statusID };
    setIf(check, 'name', title);
    if (baselineName !== '') check.standards = [baselineName];
    checks.push(check);
  }
  for (const id of nist) checks.push({ uid: id, standards: ['NIST SP 800-53'] });
  for (const id of cci) checks.push({ uid: id, standards: ['CCI'] });
  if (checks.length > 0) compliance.checks = checks;
  return compliance;
}

function buildVulnerabilities(cvssList: unknown[], req: Obj): unknown[] {
  const cve: Obj = {};
  cve.uid = firstCVE(cvssList) || getStr(req, 'id');

  const cvssArr: unknown[] = [];
  for (const c of cvssList) {
    const m = asMap(c);
    if (!m) continue;
    const entry: Obj = {};
    if (typeof m.baseScore === 'number') entry.base_score = floatNumber(m.baseScore); // OCSF cvss.base_score is float_t
    setIf(entry, 'version', getStr(m, 'version'));
    setIf(entry, 'vector_string', getStr(m, 'baseVector'));
    setIf(entry, 'severity', getStr(m, 'baseSeverity'));
    cvssArr.push(entry);
  }
  if (cvssArr.length > 0) cve.cvss = cvssArr;
  const cwes = stringSlice(req.cwe);
  if (cwes.length > 0) cve.related_cwes = cwes.map((id) => ({ uid: id }));

  const vuln: Obj = { cve };
  setIf(vuln, 'title', getStr(req, 'title'));
  setIf(vuln, 'desc', defaultDescription(req));
  const ref = firstRefURL(req);
  if (ref !== '') vuln.references = [ref];
  return [vuln];
}

