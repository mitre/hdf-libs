import {
  type Obj,
  asMap,
  asArr,
  getStr,
  setIf,
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
  const accountID = recoverAccountID(doc);
  const productArn = `arn:aws:securityhub:${PLACEHOLDER_REGION}:${accountID}:product/${accountID}/default`;

  const findings: Obj[] = [];
  for (const bRaw of baselines) {
    const baseline = asMap(bRaw);
    if (!baseline) continue;
    const baselineName = getStr(baseline, 'name');
    const reqs = asArr(baseline.requirements) ?? [];
    for (const rRaw of reqs) {
      const req = asMap(rRaw);
      if (!req) continue;
      findings.push(buildFinding(req, baselineName, docTimestamp, component, accountID, productArn, converterVersion));
    }
  }
  return stringifyLine(canonicalize({Findings: findings})) + '\n';
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

function buildFinding(
  req: Obj,
  baselineName: string,
  docTimestamp: string,
  component: Obj | undefined,
  accountID: string,
  productArn: string,
  converterVersion: string,
): Obj {
  const controlID = getStr(req, 'id');
  const st = statusOf(req);

  const title = getStr(req, 'title') || controlID;
  const desc = defaultDescription(req) || title;

  const cvssList = asArr(req.cvss);
  const hasCVSS = cvssList !== undefined && cvssList.length > 0;

  const ts = canonicalTime(firstResultStartTime(req, docTimestamp));
  const id = findingID(accountID, baselineName, controlID);

  const finding: Obj = {
    SchemaVersion: ASFF_SCHEMA_VERSION,
    Id: id,
    ProductArn: productArn,
    GeneratorId: controlID,
    AwsAccountId: accountID,
    CreatedAt: ts,
    UpdatedAt: ts,
    Title: truncate(title, MAX_TITLE),
    Description: truncate(desc, MAX_DESCRIPTION),
    Types: asffTypes(hasCVSS),
    Severity: severity(req),
    Resources: resources(component, id),
    RecordState: 'ACTIVE',
    Compliance: {Status: complianceStatus(st.rollup)},
  };
  if (st.suppressed) {
    finding.Workflow = {Status: 'SUPPRESSED'};
  }
  const pf = productFields(baselineName, controlID, converterVersion);
  if (Object.keys(pf).length > 0) {
    finding.ProductFields = pf;
  }
  const rem = remediation(req);
  if (rem) {
    finding.Remediation = rem;
  }
  return finding;
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
    if (label === 'NONE') label = 'INFORMATIONAL';
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

function productFields(baselineName: string, controlID: string, converterVersion: string): Obj {
  const pf: Obj = {};
  setIf(pf, 'hdf/baseline', baselineName);
  setIf(pf, 'hdf/control_id', controlID);
  setIf(pf, 'hdf/exporter_version', converterVersion);
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
