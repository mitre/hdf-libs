import {
  type Obj,
  asMap,
  asArr,
  getStr,
  setIf,
  stringSlice,
  statusOf,
  defaultDescription,
  firstResultStartTime,
  firstRefURL,
  firstComponent,
  canonicalize,
  stringifyLine,
} from '../../../shared/typescript/exportmap.js';
import {validateInputSize, parseHdf} from '../../../shared/typescript/converterutil.js';
import {impactToSeverity, parseTimestamp} from '@mitre/hdf-utilities';

/**
 * HDF Results -> AWS Security Finding Format (ASFF), the reverse of
 * asff-to-hdf. Output is the standard {"Findings": [...]} envelope that
 * BatchImportFindings accepts and asff-to-hdf reads back.
 *
 * One finding per requirement (matching hdf-to-ocsf): a requirement's results
 * roll up to one Compliance.Status via the shared statusOf. The mapping is
 * deliberately LOSSY and standard-compliant — HDF structure ASFF cannot hold is
 * dropped, NOT crammed into Types[] (heimdall2's rejected Types-string
 * encoding). Provenance rides ProductFields (ASFF's official string map).
 *
 * ProductArn / AwsAccountId / Region are ASFF-required but absent from HDF: the
 * account is recovered from a cloudAccount component when present, otherwise a
 * placeholder is emitted; the push path overrides all three. Output is held
 * byte-identical with the Go implementation via canonicalize + stringifyLine.
 */

const ASFF_SCHEMA_VERSION = '2018-10-08';
const PLACEHOLDER_REGION = 'us-east-1';
const PLACEHOLDER_ACCOUNT_ID = '000000000000';
// Matches the arn:aws:... ProductArn; the push path overrides it (with Region)
// for aws-cn / aws-us-gov targets.
const DEFAULT_PARTITION = 'aws';
const MAX_TITLE = 256;
const MAX_DESCRIPTION = 1024;
const EPOCH_SENTINEL = '1970-01-01T00:00:00Z';

export function convertHdfToAsff(input: string, converterVersion = '0.1.0'): string {
  const name = 'hdf-to-asff';
  validateInputSize(input, name);
  const doc = parseHdf<Obj>(input);

  const baselines = asArr(doc.baselines);
  if (!baselines) {
    throw new Error(`${name}: invalid HDF structure: missing baselines field`);
  }

  const docTimestamp = getStr(doc, 'timestamp');
  const component = firstComponent(doc);
  const toolName = getStr(asMap(doc.tool), 'name');
  const generatorName = getStr(asMap(doc.generator), 'name');
  const accountID = recoverAccountID(doc);
  const productArn = `arn:aws:securityhub:${PLACEHOLDER_REGION}:${accountID}:product/${accountID}/default`;

  const findings: Obj[] = [];
  for (const bRaw of baselines) {
    const baseline = asMap(bRaw);
    if (!baseline) continue;
    const baselineName = getStr(baseline, 'name');
    const baselineVersion = getStr(baseline, 'version');
    const reqs = asArr(baseline.requirements) ?? [];
    for (const rRaw of reqs) {
      const req = asMap(rRaw);
      if (!req) continue;
      findings.push(buildFinding(req, {
        baselineName,
        baselineVersion,
        toolName,
        generatorName,
        docTimestamp,
        component,
        accountID,
        productArn,
        exporterVersion: converterVersion,
      }));
    }
  }
  return stringifyLine(canonicalize({Findings: findings})) + '\n';
}

// FindingContext carries the doc-/baseline-level values one finding needs beyond
// its own requirement, keeping buildFinding's signature stable as fields grow.
interface FindingContext {
  baselineName: string;
  baselineVersion: string;
  toolName: string;
  generatorName: string;
  docTimestamp: string;
  component: Obj | undefined;
  accountID: string;
  productArn: string;
  exporterVersion: string;
}

// recoverAccountID reads AwsAccountId back out of a cloudAccount component (the
// reverse of asff-to-hdf's AwsAccountId -> component mapping).
function recoverAccountID(doc: Obj): string {
  for (const cRaw of asArr(doc.components) ?? []) {
    const c = asMap(cRaw);
    if (!c || getStr(c, 'type') !== 'cloudAccount') continue;
    const id = getStr(c, 'accountId') || getStr(c, 'name');
    if (id) return id;
  }
  return PLACEHOLDER_ACCOUNT_ID;
}

function buildFinding(req: Obj, ctx: FindingContext): Obj {
  const controlID = getStr(req, 'id');
  const st = statusOf(req);

  const title = getStr(req, 'title') || controlID;
  const desc = defaultDescription(req) || title;

  const cvssList = asArr(req.cvss);
  const hasCVSS = cvssList !== undefined && cvssList.length > 0;

  const ts = canonicalTime(firstResultStartTime(req, ctx.docTimestamp));
  const id = findingID(ctx.accountID, ctx.baselineName, controlID);

  const finding: Obj = {
    SchemaVersion: ASFF_SCHEMA_VERSION,
    Id: id,
    ProductArn: ctx.productArn,
    GeneratorId: controlID,
    AwsAccountId: ctx.accountID,
    CreatedAt: ts,
    UpdatedAt: ts,
    Title: truncate(title, MAX_TITLE),
    Description: truncate(desc, MAX_DESCRIPTION),
    Types: asffTypes(hasCVSS),
    Severity: severity(req),
    Resources: resources(ctx.component, id),
    RecordState: 'ACTIVE',
    Compliance: complianceBlock(req, st.rollup),
  };
  if (st.suppressed) {
    finding.Workflow = {Status: 'SUPPRESSED'};
  }
  const pf = productFields(ctx, controlID);
  if (Object.keys(pf).length > 0) {
    finding.ProductFields = pf;
  }
  const rem = remediation(req);
  if (rem) {
    finding.Remediation = rem;
  }
  // Vulnerabilities[] carries the structured CVSS/CVE data (and any additional
  // reference URLs) so asff-to-hdf reconstructs requirement.cvss[], the CVE, and
  // the full refs[]. Extra refs ride the first vuln's ReferenceUrls; when a
  // requirement carries refs but no CVSS, the first ref falls back to SourceUrl.
  const vulns = vulnerabilities(req);
  const refs = allRefURLs(req);
  if (refs.length > 0) {
    if (vulns.length > 0) {
      vulns[0]!.ReferenceUrls = refs;
    } else {
      finding.SourceUrl = refs[0];
    }
  }
  if (vulns.length > 0) {
    finding.Vulnerabilities = vulns;
  }
  return finding;
}

// complianceBlock builds the ASFF Compliance object: the rolled-up status, the
// NIST/CCI control ids as RelatedRequirements, and the parsed status-reason
// message as StatusReasons (the reverse of asff-to-hdf's statusReason flatten).
function complianceBlock(req: Obj, rollup: string): Obj {
  const comp: Obj = {Status: complianceStatus(rollup)};
  const rr = relatedRequirements(req);
  if (rr.length > 0) comp.RelatedRequirements = rr;
  const sr = statusReasons(req);
  if (sr.length > 0) comp.StatusReasons = sr;
  return comp;
}

// relatedRequirements collects a requirement's NIST controls and CCI ids (in that
// order) for ASFF Compliance.RelatedRequirements.
function relatedRequirements(req: Obj): string[] {
  const tags = asMap(req.tags);
  if (!tags) return [];
  const out: string[] = [];
  for (const key of ['nist', 'cci']) {
    for (const id of stringSlice(tags[key])) {
      if (id !== '') out.push(id);
    }
  }
  return out;
}

// statusReasons parses the first result message shaped as "ReasonCode: X" /
// "Description: Y" lines back into ASFF Compliance.StatusReasons[] — the exact
// inverse of asff-to-hdf's statusReason flatten. A free-form message yields nothing.
function statusReasons(req: Obj): Obj[] {
  const msg = firstResultMessage(req);
  if (msg === '') return [];
  const out: Obj[] = [];
  let cur: Obj | undefined;
  for (const line of msg.split('\n')) {
    if (line.startsWith('ReasonCode: ')) {
      cur = {ReasonCode: line.slice('ReasonCode: '.length)};
      out.push(cur);
    } else if (line.startsWith('Description: ')) {
      const desc = line.slice('Description: '.length);
      if (!cur) {
        cur = {};
        out.push(cur);
      }
      cur.Description = desc;
    }
  }
  return out;
}

// firstResultMessage returns the first non-empty results[].message.
function firstResultMessage(req: Obj): string {
  for (const rRaw of asArr(req.results) ?? []) {
    const m = getStr(asMap(rRaw), 'message');
    if (m !== '') return m;
  }
  return '';
}

// vulnerabilities builds ASFF Vulnerabilities[] from requirement.cvss[]: one
// vulnerability per CVSS entry, its Id the CVSS source (the CVE id) and its
// Cvss[] the structured version/base-score/vector/source. asff-to-hdf reads these
// back into requirement.cvss[] and the CVE, closing the round-trip.
function vulnerabilities(req: Obj): Obj[] {
  const out: Obj[] = [];
  for (const cRaw of asArr(req.cvss) ?? []) {
    const c = asMap(cRaw);
    if (!c) continue;
    const cvssEntry: Obj = {};
    setIf(cvssEntry, 'Version', getStr(c, 'version'));
    if (c.baseScore !== undefined && c.baseScore !== null) cvssEntry.BaseScore = c.baseScore;
    setIf(cvssEntry, 'BaseVector', getStr(c, 'baseVector'));
    setIf(cvssEntry, 'Source', getStr(c, 'source'));
    const vuln: Obj = {Cvss: [cvssEntry]};
    setIf(vuln, 'Id', getStr(c, 'source'));
    out.push(vuln);
  }
  return out;
}

// allRefURLs returns every requirement.refs[].url (deduped, source order).
function allRefURLs(req: Obj): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  for (const rRaw of asArr(req.refs) ?? []) {
    const url = getStr(asMap(rRaw), 'url');
    if (url !== '' && !seen.has(url)) {
      seen.add(url);
      out.push(url);
    }
  }
  return out;
}

function findingID(accountID: string, baselineName: string, controlID: string): string {
  return [accountID, PLACEHOLDER_REGION, baselineName, controlID].join('/');
}

function asffTypes(hasCVSS: boolean): string[] {
  return hasCVSS
    ? ['Software and Configuration Checks/Vulnerabilities/CVE']
    : ['Software and Configuration Checks'];
}

function complianceStatus(status: string): string {
  switch (status) {
    case 'passed':
      return 'PASSED';
    case 'failed':
      return 'FAILED';
    case 'notApplicable':
      return 'NOT_AVAILABLE';
    default:
      return 'WARNING';
  }
}

function severity(req: Obj): Obj {
  let label = 'INFORMATIONAL';
  let normalized = 0;
  if (typeof req.impact === 'number') {
    label = impactToSeverity(req.impact).toUpperCase();
    normalized = Math.trunc(req.impact * 100);
  }
  return {Label: label, Normalized: normalized};
}

function resources(component: Obj | undefined, id: string): Obj[] {
  const res: Obj = {Type: 'Other', Id: id, Partition: DEFAULT_PARTITION, Region: PLACEHOLDER_REGION};
  if (component) {
    const details: Obj = {};
    setIf(details, 'Name', getStr(component, 'name'));
    setIf(details, 'Type', getStr(component, 'type'));
    setIf(details, 'IpAddress', getStr(component, 'ipAddress'));
    setIf(details, 'OsName', getStr(component, 'osName'));
    if (Object.keys(details).length > 0) {
      res.Details = {Other: details};
    }
  }
  return [res];
}

function productFields(ctx: FindingContext, controlID: string): Obj {
  const pf: Obj = {};
  setIf(pf, 'hdf/baseline', ctx.baselineName);
  setIf(pf, 'hdf/baseline_version', ctx.baselineVersion);
  setIf(pf, 'hdf/control_id', controlID);
  setIf(pf, 'hdf/exporter_version', ctx.exporterVersion);
  setIf(pf, 'hdf/generator', ctx.generatorName);
  setIf(pf, 'hdf/tool', ctx.toolName);
  return pf;
}

function remediation(req: Obj): Obj | undefined {
  let fix = '';
  for (const dRaw of asArr(req.descriptions) ?? []) {
    const d = asMap(dRaw);
    if (d && getStr(d, 'label') === 'fix') {
      fix = getStr(d, 'data');
      break;
    }
  }
  const url = firstRefURL(req);
  if (fix === '' && url === '') return undefined;
  const rec: Obj = {};
  setIf(rec, 'Text', truncate(fix, MAX_DESCRIPTION));
  setIf(rec, 'Url', url);
  return {Recommendation: rec};
}

// canonicalTime passes an already-canonical HDF timestamp through unchanged
// (byte-identical with the Go side, which also passes through); an unparseable/
// absent time falls back to the epoch sentinel so the required field stays valid.
function canonicalTime(s: string): string {
  return parseTimestamp(s) ? s : EPOCH_SENTINEL;
}

// truncate caps s at max Unicode code points (matching Go's []rune slice).
function truncate(s: string, max: number): string {
  const r = [...s];
  return r.length <= max ? s : r.slice(0, max).join('');
}
