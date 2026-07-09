import { parseJSON, parseTimestamp } from '@mitre/hdf-utilities';
import { validateInputSize } from '../../../shared/typescript/converterutil.js';
import {
  type Obj,
  asMap,
  asArr,
  getStr,
  setIf,
  statusOf,
  firstComponent,
  firstResultStartTime,
  buildHDFBlock,
  canonicalize,
  stringifyLine,
} from '../../../shared/typescript/exportmap.js';

/**
 * HDF Results -> Splunk HEC-envelope NDJSON, normalized to the Common
 * Information Model (CIM). See ADR-0004.
 *
 * One HEC event per Evaluated_Requirement, hybrid shape: flat CIM-named scalars
 * (signature/signature_id/cve/cvss/severity/dest/vendor_product/category)
 * promoted to the top of the event payload and mirrored into the HEC indexed
 * `fields`, plus a lossless hdf.* block. Every result carries hdf_status so the
 * full pass/fail posture survives (CIM has no verdict field); the companion TA
 * (Splunk_TA_hdf) tags failed/CVE findings into the Vulnerabilities data model.
 *
 * Generic access, the status roll-up, field extraction, the lossless hdf.*
 * block, and the canonical line serialization are shared with the other
 * exporters via exportmap; output is held byte-identical with the Go side.
 */

const SOURCETYPE = 'hdf:results';
const SOURCE = 'hdf-exporter';

export function convertHdfToSplunk(input: string, converterVersion = '0.1.0'): string {
  validateInputSize(input, 'hdf-to-splunk');
  const doc = parseJSON<Obj>(input);

  const baselines = asArr(doc.baselines);
  if (!baselines) {
    throw new Error('hdf-to-splunk: invalid HDF structure: missing baselines field');
  }

  const docTimestamp = getStr(doc, 'timestamp');
  const tool = asMap(doc.tool);
  const generator = asMap(doc.generator);
  const component = firstComponent(doc);

  const lines: string[] = [];
  for (const bRaw of baselines) {
    const baseline = asMap(bRaw);
    if (!baseline) continue;
    const reqs = asArr(baseline.requirements) ?? [];
    for (const rRaw of reqs) {
      const req = asMap(rRaw);
      if (!req) continue;
      const hec = buildHECEvent(req, baseline, docTimestamp, tool, generator, component, converterVersion);
      lines.push(stringifyLine(canonicalize(hec)));
    }
  }
  return lines.length === 0 ? '' : lines.join('\n') + '\n';
}

function buildHECEvent(
  req: Obj,
  baseline: Obj,
  docTimestamp: string,
  tool: Obj | undefined,
  generator: Obj | undefined,
  component: Obj | undefined,
  converterVersion: string,
): Obj {
  const st = statusOf(req);
  const title = getStr(req, 'title');
  const controlID = getStr(req, 'id');

  const signature = title !== '' ? title : controlID;
  const dest = destHost(component);
  const sev = severity(req);
  const [cvss, hasCVSS] = maxCVSS(req);
  const cve = firstCVE(req);
  const category = firstCWE(req);
  const vendorProduct = getStr(tool, 'name');

  const event: Obj = {
    signature,
    hdf_status: st.rollup,
    hdf: buildHDFBlock(req, baseline, st.raw, st.overridden, generator, tool, converterVersion),
  };
  setIf(event, 'signature_id', controlID);
  setIf(event, 'dest', dest);
  setIf(event, 'severity', sev);
  setIf(event, 'cve', cve);
  setIf(event, 'category', category);
  setIf(event, 'vendor_product', vendorProduct);
  if (hasCVSS) event.cvss = cvss;

  const fields: Obj = { signature, hdf_status: st.rollup };
  setIf(fields, 'signature_id', controlID);
  setIf(fields, 'dest', dest);
  setIf(fields, 'severity', sev);
  setIf(fields, 'cve', cve);
  if (hasCVSS) fields.cvss = cvss;

  const hec: Obj = {
    source: SOURCE,
    sourcetype: SOURCETYPE,
    event,
    fields,
  };
  const t = epochSeconds(firstResultStartTime(req, docTimestamp));
  if (t !== undefined) hec.time = t;
  setIf(hec, 'host', dest);
  return hec;
}

function destHost(component: Obj | undefined): string {
  if (!component) return '';
  return getStr(component, 'fqdn') || getStr(component, 'name') || getStr(component, 'ipAddress');
}

function severity(req: Obj): string {
  if (typeof req.impact === 'number') {
    const impact = req.impact;
    if (impact >= 0.9) return 'critical';
    if (impact >= 0.7) return 'high';
    if (impact >= 0.4) return 'medium';
    if (impact >= 0.1) return 'low';
    return 'informational';
  }
  return normalizeSeverity(getStr(req, 'severity'));
}

function normalizeSeverity(s: string): string {
  switch (s) {
    case 'critical':
    case 'high':
    case 'medium':
    case 'low':
    case 'informational':
      return s;
    default:
      return 'informational';
  }
}

function maxCVSS(req: Obj): [number, boolean] {
  const list = asArr(req.cvss) ?? [];
  let max = 0;
  let found = false;
  for (const c of list) {
    const m = asMap(c);
    if (m && typeof m.baseScore === 'number') {
      if (!found || m.baseScore > max) max = m.baseScore;
      found = true;
    }
  }
  return [max, found];
}

function firstCVE(req: Obj): string {
  const list = asArr(req.cvss) ?? [];
  for (const c of list) {
    const src = getStr(asMap(c), 'source');
    if (src.toUpperCase().startsWith('CVE-')) return src;
  }
  return '';
}

function firstCWE(req: Obj): string {
  const list = asArr(req.cwe) ?? [];
  for (const c of list) {
    if (typeof c === 'string' && c !== '') return c;
  }
  return '';
}

/**
 * Parse an HDF RFC3339 timestamp into integer epoch seconds via the canonical
 * parser, returning undefined when empty/unparseable (HEC then stamps
 * receive-time). Integer seconds keep Go and TypeScript byte-identical.
 */
function epochSeconds(s: string): number | undefined {
  const d = parseTimestamp(s);
  if (d === null) return undefined;
  return Math.floor(d.getTime() / 1000);
}
