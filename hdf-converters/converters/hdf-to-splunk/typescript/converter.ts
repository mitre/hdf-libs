import {
  type Obj,
  asMap,
  asArr,
  getStr,
  setIf,
  statusOf,
  firstResultStartTime,
  buildHDFBlock,
  runExport,
  firstCVE,
  epochSeconds,
} from '../../../shared/typescript/exportmap.js';
import { impactToSeverity } from '@mitre/hdf-utilities';

/**
 * HDF Results -> Splunk HEC-envelope NDJSON, normalized to the Common
 * Information Model (CIM). See ADR-0004.
 *
 * One HEC event per Evaluated_Requirement, hybrid shape: flat CIM-named scalars
 * (signature/signature_id/cve/cvss/severity/dest/vendor_product/category) are
 * promoted to the top of the event payload; the hot query scalars among them
 * (signature/signature_id/dest/severity/cve/cvss + hdf_status + suppressed) are
 * additionally mirrored into the HEC indexed `fields` (surviving Splunk's
 * ~5000-char cutoff), plus a lossless hdf.* block.
 *
 * Status is raw-primary: hdf_status carries the RAW verdict (a waived failure is
 * still failed) and suppressed is the separate acceptance axis. The companion TA
 * (Splunk_TA_hdf) tags failed/error/CVE findings into the CIM Vulnerabilities
 * data model but excludes suppressed=true, so a waived control drops out while a
 * risk-adjusted still-failing control stays in. Canonical "still actionable"
 * query: hdf_status=failed suppressed=false.
 *
 * Generic access, the status roll-up, field extraction, the lossless hdf.*
 * block, and the canonical line serialization are shared with the other
 * exporters via exportmap; output is held byte-identical with the Go side.
 */

const SOURCETYPE = 'hdf:results';
const SOURCE = 'hdf-exporter';

export function convertHdfToSplunk(input: string, converterVersion = '0.1.0'): string {
  return runExport(input, 'hdf-to-splunk', (req, baseline, docTimestamp, tool, generator, component) =>
    buildHECEvent(req, baseline, docTimestamp, tool, generator, component, converterVersion),
  );
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
  const cve = firstCVE(asArr(req.cvss) ?? []);
  const category = firstCWE(req);
  const vendorProduct = getStr(tool, 'name');

  const event: Obj = {
    signature,
    hdf_status: st.raw,
    suppressed: st.suppressed,
    hdf: buildHDFBlock(req, baseline, st.raw, st.overridden, st.suppressed, generator, tool, converterVersion),
  };
  setIf(event, 'signature_id', controlID);
  setIf(event, 'dest', dest);
  setIf(event, 'severity', sev);
  setIf(event, 'cve', cve);
  setIf(event, 'category', category);
  setIf(event, 'vendor_product', vendorProduct);
  if (hasCVSS) event.cvss = cvss;

  const fields: Obj = { signature, hdf_status: st.raw, suppressed: st.suppressed };
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
    return impactToSeverity(req.impact);
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

function firstCWE(req: Obj): string {
  const list = asArr(req.cwe) ?? [];
  for (const c of list) {
    if (typeof c === 'string' && c !== '') return c;
  }
  return '';
}

