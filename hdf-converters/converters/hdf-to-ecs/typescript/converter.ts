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
  eventID,
  buildHDFBlock,
  runExport,
} from '../../../shared/typescript/exportmap.js';

/**
 * HDF Results -> Elastic Common Schema (ECS) NDJSON exporter.
 *
 * One ECS event per Evaluated_Requirement, in the hybrid shape from ADR-0002:
 * a core-ECS-native projection plus a lossless hdf.* block, hot filter scalars
 * promoted flat. Output is plain NDJSON (LF-delimited, trailing newline), ECS
 * 9.4.0.
 *
 * Status is effective-primary: event.outcome carries the GOVERNING verdict
 * (effectiveStatus when present, else the raw results roll-up), while hdf.status
 * preserves the RAW verdict and hdf.suppressed is the separate acceptance axis.
 * Override provenance (disposition/type/reason/approver/dates) is surfaced under
 * labels.*. The canonical "still actionable" query is
 * event.outcome:"failure" AND hdf.suppressed:false.
 *
 * Generic JSON access, the status roll-up, requirement/document field
 * extraction, and the canonical line serialization are shared with the other
 * export converters via ../../../shared/typescript/exportmap.js; only
 * ECS-specific event shaping lives here. Output is held byte-identical with the
 * Go implementation via key-sorted, HTML-unescaped compact JSON.
 */

const ECS_VERSION = '9.4.0';

export function convertHdfToEcs(input: string, converterVersion = '0.1.0'): string {
  return runExport(input, 'hdf-to-ecs', (req, baseline, docTimestamp, tool, generator, component) =>
    buildEvent(req, baseline, docTimestamp, tool, generator, component, converterVersion),
  );
}

function buildEvent(
  req: Obj,
  baseline: Obj,
  docTimestamp: string,
  tool: Obj | undefined,
  generator: Obj | undefined,
  component: Obj | undefined,
  converterVersion: string,
): Obj {
  const st = statusOf(req);
  const outcome = statusToOutcome(st.rollup);
  const controlID = getStr(req, 'id');
  const baselineName = getStr(baseline, 'name');
  const title = getStr(req, 'title');

  const cvssList = asArr(req.cvss);
  const hasCVSS = cvssList !== undefined && cvssList.length > 0;

  const categories: unknown[] = ['configuration'];
  if (hasCVSS) categories.push('vulnerability');

  const event: Obj = {
    kind: 'state',
    category: categories,
    type: ['info'],
    outcome,
    id: eventID(component, baselineName, controlID),
    dataset: 'hdf.findings',
    module: 'hdf',
  };
  const start = firstRawStartTime(req);
  if (start !== '') event.start = start;
  const runTime = firstRunTime(req);
  if (runTime !== undefined) event.duration = Math.round(runTime * 1e9); // ECS event.duration is nanoseconds

  const obj: Obj = {
    '@timestamp': firstResultStartTime(req, docTimestamp),
    ecs: { version: ECS_VERSION },
    event,
    message: (title + ' — ' + st.raw).trim(),
  };

  const observer = buildObserver(tool, generator);
  if (observer) obj.observer = observer;

  const host = buildHost(component);
  if (host) {
    obj.host = host;
    const related = buildRelated(component);
    if (related) obj.related = related;
  }

  obj.rule = buildRule(req, baseline, controlID, title);

  if (hasCVSS) {
    obj.vulnerability = buildVulnerability(cvssList!, req, tool);
  }

  const threat = buildThreat(req);
  if (threat) obj.threat = threat;

  const sl = asMap(req.sourceLocation);
  if (sl) {
    const file: Obj = {};
    setIf(file, 'name', getStr(sl, 'ref'));
    if ('line' in sl) file.line = sl.line;
    if (Object.keys(file).length > 0) obj.log = { origin: { file } };
  }

  const labels = buildLabels(req);
  if (labels) obj.labels = labels;

  // hdf.* lossless block, plus the requirement/baseline fields the shared
  // allowlist omits (control classification, verification method, baseline
  // title and integrity checksum) so the block stays genuinely lossless.
  const hdf = buildHDFBlock(req, baseline, st.raw, st.overridden, st.suppressed, generator, tool, converterVersion);
  if ('controlType' in req) hdf.control_type = req.controlType;
  if ('verificationMethod' in req) hdf.verification_method = req.verificationMethod;
  if ('title' in baseline) hdf.baseline_title = baseline.title;
  if ('checksum' in baseline) hdf.baseline_checksum = baseline.checksum;
  obj.hdf = hdf;

  return obj;
}

/**
 * Surface override provenance into ECS labels.* (keyword bag): the disposition
 * plus the governing statusOverrides[0] fields. Returns undefined when the
 * requirement carries no disposition or overrides.
 */
function buildLabels(req: Obj): Obj | undefined {
  const labels: Obj = {};
  setIf(labels, 'hdf_disposition', getStr(req, 'disposition'));
  const overrides = asArr(req.statusOverrides);
  if (overrides && overrides.length > 0) {
    const ov = asMap(overrides[0]);
    if (ov) {
      setIf(labels, 'hdf_override_type', getStr(ov, 'type'));
      setIf(labels, 'hdf_override_reason', getStr(ov, 'reason'));
      const by = asMap(ov.appliedBy);
      if (by) setIf(labels, 'hdf_override_applied_by', getStr(by, 'identifier'));
      setIf(labels, 'hdf_override_applied_at', getStr(ov, 'appliedAt'));
      setIf(labels, 'hdf_override_expires_at', getStr(ov, 'expiresAt'));
    }
  }
  return Object.keys(labels).length === 0 ? undefined : labels;
}

/** results[0].startTime with no fallback, or ''. */
function firstRawStartTime(req: Obj): string {
  const results = asArr(req.results) ?? [];
  return results.length > 0 ? getStr(asMap(results[0]), 'startTime') : '';
}

/** results[0].runTime (seconds), or undefined when absent. */
function firstRunTime(req: Obj): number | undefined {
  const results = asArr(req.results) ?? [];
  const rt = results.length > 0 ? asMap(results[0])?.runTime : undefined;
  return typeof rt === 'number' ? rt : undefined;
}

/** Every non-empty refs[].url, preserving order. */
function allRefURLs(req: Obj): string[] {
  const refs = asArr(req.refs) ?? [];
  const urls: string[] = [];
  for (const rRaw of refs) {
    const url = getStr(asMap(rRaw), 'url');
    if (url !== '') urls.push(url);
  }
  return urls;
}

function buildObserver(tool: Obj | undefined, generator: Obj | undefined): Obj | undefined {
  let name = getStr(tool, 'name');
  let version = getStr(tool, 'version');
  if (name === '' && generator) {
    name = getStr(generator, 'name');
    version = getStr(generator, 'version');
  }
  if (name === '') return undefined;
  const observer: Obj = { name, type: 'scanner' };
  if (version !== '') observer.version = version;
  const product = getStr(tool, 'format');
  if (product !== '') observer.product = product;
  return observer;
}

function buildHost(component: Obj | undefined): Obj | undefined {
  if (!component) return undefined;
  const host: Obj = {};
  const name = getStr(component, 'fqdn') || getStr(component, 'name');
  if (name !== '') host.name = name;
  setIf(host, 'id', getStr(component, 'componentId'));
  setIf(host, 'ip', getStr(component, 'ipAddress'));
  setIf(host, 'mac', getStr(component, 'macAddress'));
  const os: Obj = {};
  setIf(os, 'name', getStr(component, 'osName'));
  setIf(os, 'version', getStr(component, 'osVersion'));
  if (Object.keys(os).length > 0) host.os = os;
  return Object.keys(host).length === 0 ? undefined : host;
}

function buildRelated(component: Obj | undefined): Obj | undefined {
  const related: Obj = {};
  const name = getStr(component, 'fqdn') || getStr(component, 'name');
  if (name !== '') related.hosts = [name];
  const ip = getStr(component, 'ipAddress');
  if (ip !== '') related.ip = [ip];
  return Object.keys(related).length === 0 ? undefined : related;
}

function buildRule(req: Obj, baseline: Obj, controlID: string, title: string): Obj {
  const rule: Obj = { id: controlID };
  if (title !== '') rule.name = title;
  setIf(rule, 'description', defaultDescription(req));
  setIf(rule, 'ruleset', getStr(baseline, 'name'));
  setIf(rule, 'version', getStr(baseline, 'version'));
  const refs = allRefURLs(req);
  if (refs.length > 0) rule.reference = refs;
  return rule;
}

function buildVulnerability(cvssList: unknown[], req: Obj, tool: Obj | undefined): Obj {
  const first = asMap(cvssList[0]) ?? {};
  const vuln: Obj = {};
  const source = getStr(first, 'source');
  if (source !== '') {
    vuln.id = source;
    if (source.toUpperCase().startsWith('CVE-')) vuln.enumeration = 'CVE';
  } else {
    setIf(vuln, 'id', getStr(req, 'id'));
  }
  const version = getStr(first, 'version');
  vuln.classification = version !== '' ? `CVSS v${version}` : 'CVSS'; // derived from the real cvss[] scoring version
  const score: Obj = {};
  if ('baseScore' in first) score.base = first.baseScore;
  setIf(score, 'version', version);
  if (Object.keys(score).length > 0) vuln.score = score;
  const severity = getStr(first, 'baseSeverity') || getStr(req, 'severity');
  if (severity !== '') vuln.severity = severity;
  const vendor = getStr(tool, 'name');
  if (vendor !== '') vuln.scanner = { vendor };
  const refs = allRefURLs(req);
  if (refs.length > 0) vuln.reference = refs;
  setIf(vuln, 'description', defaultDescription(req));
  return vuln;
}

function buildThreat(req: Obj): Obj | undefined {
  const tags = asMap(req.tags);
  if (!tags) return undefined;
  const techniques: unknown[] = [];
  for (const key of ['mitre_attack', 'attack', 'mitre_techniques']) {
    for (const id of stringSlice(tags[key])) {
      techniques.push({ id });
    }
  }
  if (techniques.length === 0) return undefined;
  return { framework: 'MITRE ATT&CK', technique: techniques };
}

function statusToOutcome(status: string): string {
  switch (status) {
    case 'passed':
      return 'success';
    case 'failed':
      return 'failure';
    default:
      return 'unknown';
  }
}
