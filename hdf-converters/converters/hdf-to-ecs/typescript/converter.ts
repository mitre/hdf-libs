import { parseJSON } from '@mitre/hdf-utilities';
import { validateInputSize } from '../../../shared/typescript/converterutil.js';

/**
 * HDF Results -> Elastic Common Schema (ECS) NDJSON exporter.
 *
 * One ECS event per Evaluated_Requirement, in the hybrid shape from ADR-0002:
 * a core-ECS-native projection plus a lossless hdf.* block, hot filter scalars
 * promoted flat. Output is plain NDJSON (LF-delimited, trailing newline), ECS
 * 9.4.0.
 *
 * To stay byte-identical with the Go implementation, this operates on
 * generically-parsed JSON and emits alphabetically key-sorted, HTML-unescaped
 * compact JSON; timestamps pass through as raw source strings.
 */

const ECS_VERSION = '9.4.0';

type Obj = Record<string, unknown>;

function asMap(v: unknown): Obj | undefined {
  return v !== null && typeof v === 'object' && !Array.isArray(v) ? (v as Obj) : undefined;
}
function asArr(v: unknown): unknown[] | undefined {
  return Array.isArray(v) ? v : undefined;
}
function getStr(m: Obj | undefined, key: string): string {
  const v = m?.[key];
  return typeof v === 'string' ? v : '';
}
function setIf(m: Obj, key: string, val: string): void {
  if (val !== '') m[key] = val;
}

export function convertHdfToEcs(input: string, converterVersion = '0.1.0'): string {
  validateInputSize(input, 'hdf-to-ecs');
  const doc = parseJSON<Obj>(input);

  const baselines = asArr(doc.baselines);
  if (!baselines) {
    throw new Error('hdf-to-ecs: invalid HDF structure: missing baselines field');
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
      const event = buildEvent(req, baseline, docTimestamp, tool, generator, component, converterVersion);
      lines.push(stringifyLine(canonicalize(event)));
    }
  }
  return lines.length === 0 ? '' : lines.join('\n') + '\n';
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
  const rawStatus = worstOfResults(req);
  const effStatus = getStr(req, 'effectiveStatus');
  const rollup = effStatus !== '' ? effStatus : rawStatus;
  const outcome = statusToOutcome(rollup);
  const controlID = getStr(req, 'id');
  const baselineName = getStr(baseline, 'name');
  const title = getStr(req, 'title');

  const cvssList = asArr(req.cvss);
  const overrides = asArr(req.statusOverrides);
  const overridden = (overrides !== undefined && overrides.length > 0) || 'effectiveStatus' in req;
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

  const obj: Obj = {
    '@timestamp': firstResultStartTime(req, docTimestamp),
    ecs: { version: ECS_VERSION },
    event,
    message: (title + ' — ' + rollup).trim(),
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

  obj.hdf = buildHDFBlock(req, baseline, rawStatus, overridden, generator, tool, converterVersion);

  return obj;
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
  setIf(rule, 'reference', firstRefURL(req));
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
  vuln.classification = 'CVSS';
  const score: Obj = {};
  if ('baseScore' in first) score.base = first.baseScore;
  setIf(score, 'version', getStr(first, 'version'));
  if (Object.keys(score).length > 0) vuln.score = score;
  const severity = getStr(first, 'baseSeverity') || getStr(req, 'severity');
  if (severity !== '') vuln.severity = severity;
  const vendor = getStr(tool, 'name');
  if (vendor !== '') vuln.scanner = { vendor };
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

function buildHDFBlock(
  req: Obj,
  baseline: Obj,
  rawStatus: string,
  overridden: boolean,
  generator: Obj | undefined,
  tool: Obj | undefined,
  converterVersion: string,
): Obj {
  const hdf: Obj = {
    status: rawStatus,
    overridden,
    exporter_version: converterVersion,
  };
  setIf(hdf, 'control_id', getStr(req, 'id'));
  setIf(hdf, 'baseline', getStr(baseline, 'name'));
  if ('effectiveStatus' in req) hdf.effective_status = req.effectiveStatus;
  if ('effectiveImpact' in req) hdf.effective_impact = req.effectiveImpact;
  if ('impact' in req) hdf.impact = req.impact;
  if ('severity' in req) hdf.severity = req.severity;
  if ('disposition' in req) hdf.disposition = req.disposition;
  const tags = asMap(req.tags);
  if (tags?.nist !== undefined) hdf.nist = tags.nist;
  if (tags?.cci !== undefined) hdf.cci = tags.cci;

  const passthrough: Record<string, string> = {
    tags: 'tags',
    cvss: 'cvss',
    cwe: 'cwe',
    epss: 'epss',
    kev: 'kev',
    affectedPackages: 'affected_packages',
    descriptions: 'descriptions',
    results: 'results',
    statusOverrides: 'status_overrides',
    poams: 'poams',
    code: 'code',
    refs: 'refs',
  };
  for (const [src, dst] of Object.entries(passthrough)) {
    if (src in req) hdf[dst] = req[src];
  }
  if (generator) hdf.generator = generator;
  if (tool) hdf.tool = tool;
  return hdf;
}

function worstOfResults(req: Obj): string {
  const results = asArr(req.results) ?? [];
  const precedence = ['failed', 'error', 'passed', 'notReviewed', 'notApplicable'];
  const present = new Set<string>();
  for (const rRaw of results) {
    const r = asMap(rRaw);
    if (r) present.add(getStr(r, 'status'));
  }
  for (const s of precedence) {
    if (present.has(s)) return s;
  }
  return 'notReviewed';
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

function eventID(component: Obj | undefined, baselineName: string, controlID: string): string {
  let comp = '';
  if (component) {
    comp = getStr(component, 'componentId') || getStr(component, 'name');
  }
  return [comp, baselineName, controlID].join('|');
}

function firstComponent(doc: Obj): Obj | undefined {
  const comps = asArr(doc.components);
  if (!comps || comps.length === 0) return undefined;
  return asMap(comps[0]);
}

function firstResultStartTime(req: Obj, fallback: string): string {
  const results = asArr(req.results) ?? [];
  if (results.length > 0) {
    const r = asMap(results[0]);
    const st = getStr(r, 'startTime');
    if (st !== '') return st;
  }
  return fallback;
}

function defaultDescription(req: Obj): string {
  const descs = asArr(req.descriptions) ?? [];
  for (const dRaw of descs) {
    const d = asMap(dRaw);
    if (d && getStr(d, 'label') === 'default') return getStr(d, 'data');
  }
  return '';
}

function firstRefURL(req: Obj): string {
  const refs = asArr(req.refs) ?? [];
  for (const rRaw of refs) {
    const r = asMap(rRaw);
    const url = getStr(r, 'url');
    if (url !== '') return url;
  }
  return '';
}

function stringSlice(v: unknown): string[] {
  if (typeof v === 'string') return [v];
  if (Array.isArray(v)) return v.filter((e): e is string => typeof e === 'string');
  return [];
}

// stringifyLine emits compact JSON matching Go's encoder byte-for-byte. Go's
// encoding/json escapes U+2028/U+2029 (JSONP safety) while JSON.stringify emits
// them raw, so we escape them here to preserve parity. (Object keys are ASCII
// or schema-defined tag keys, all within the BMP, where JS's UTF-16 sort order
// agrees with Go's byte-wise sort — astral-plane keys are not a concern.)
function stringifyLine(v: unknown): string {
  return JSON.stringify(v).replace(/\u2028/g, '\\u2028').replace(/\u2029/g, '\\u2029');
}

// canonicalize recursively sorts object keys (matching Go's map-key ordering)
// so the emitted JSON is byte-identical to the Go encoder.
function canonicalize(v: unknown): unknown {
  if (Array.isArray(v)) return v.map(canonicalize);
  const m = asMap(v);
  if (m) {
    const out: Obj = {};
    for (const k of Object.keys(m).sort()) {
      out[k] = canonicalize(m[k]);
    }
    return out;
  }
  return v;
}
