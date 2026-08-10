import {
  type Checksum,
  createMinimalBaseline,
  TargetType,
  type Tool,
  type EvaluatedBaseline,
  type EvaluatedRequirement,
  type Reference,
  type RequirementResult,
  type SourceLocation,
  type HDFResults,
  ResultStatus,
  VerificationMethodEnum,
} from '@mitre/hdf-schema';
import {
  getCweNistControl,
  nistToCci,
  DEFAULT_STATIC_ANALYSIS_NIST_TAGS,
} from '@mitre/hdf-mappings';
import {parseJSON, parseTimestamp} from '@mitre/hdf-utilities';
import {detectConverter} from '../../../shared/typescript/fingerprint.js';
import {registerAllFingerprints} from '../../../shared/typescript/register-all.js';
import {convertSarifToHdf} from '../../sarif-to-hdf/typescript/converter.js';
import {buildNoFindingsRequirement, deriveControlTypeFromTags, inputChecksum, buildNistCciTags, limitArray, stripHTML, validateInputSize, serializeHdf} from '../../../shared/typescript/converterutil.js';

// --- ZAP JSON input types ---

interface ZapReport {
  '@generated'?: string;
  '@version'?: string;
  site?: ZapSite[];
}

interface ZapSite {
  '@host'?: string;
  '@name'?: string;
  '@port'?: string;
  '@ssl'?: string;
  alerts?: ZapAlert[];
}

interface ZapAlert {
  pluginid: string;
  name: string;
  alert?: string;
  cweid?: string;
  wascid?: string;
  riskcode?: string;
  riskdesc?: string;
  confidence?: string;
  count?: string;
  desc?: string;
  solution?: string;
  otherinfo?: string;
  reference?: string;
  sourceid?: string;
  instances?: ZapInstance[];
}

interface ZapInstance {
  uri?: string;
  method?: string;
  param?: string;
  evidence?: string;
  attack?: string;
}

// --- Risk code to impact ---

function riskCodeToImpact(riskCode: string): number {
  switch (riskCode) {
    case '0':
    case '1':
      return 0.3;
    case '2':
      return 0.5;
    case '3':
      return 0.7;
    default:
      return 0.5;
  }
}

// --- NIST tag building ---

function buildNistTags(cweid: string): string[] {
  if (cweid && cweid !== '0') {
    const cweNum = parseInt(cweid, 10);
    if (!isNaN(cweNum)) {
      const control = getCweNistControl(cweNum);
      if (control) {
        return [control];
      }
    }
  }
  return [...DEFAULT_STATIC_ANALYSIS_NIST_TAGS];
}

// buildCwe promotes a ZAP alert cweid to a first-class requirement.cwe entry
// in the canonical "CWE-N" form (no leading zeros). Returns undefined when the
// alert carries no usable CWE ('', '0', or a non-numeric value).
function buildCwe(cweid: string | undefined): string[] | undefined {
  if (!cweid || cweid === '0') {
    return undefined;
  }
  const cweNum = parseInt(cweid, 10);
  if (isNaN(cweNum)) {
    return undefined;
  }
  return [`CWE-${cweNum}`];
}

// --- Instance to code desc ---

function buildCodeDesc(instance: ZapInstance): string {
  const parts: string[] = [];
  if (instance.uri) {
    parts.push(`URI: ${instance.uri}`);
  }
  if (instance.method) {
    parts.push(`Method: ${instance.method}`);
  }
  if (instance.param) {
    parts.push(`Param: ${instance.param}`);
  }
  if (instance.evidence) {
    parts.push(`Evidence: ${instance.evidence}`);
  }
  return parts.join(' | ');
}

// --- Requirement code (CODE tab) synthesis ---

// representativeInstance picks the instance best representing the alert for the
// CODE tab: the first instance carrying an attack payload, falling back to the
// first instance when none do. Returns undefined when there are no instances.
function representativeInstance(instances: ZapInstance[] | undefined): ZapInstance | undefined {
  if (!instances || instances.length === 0) {
    return undefined;
  }
  return instances.find(inst => inst.attack) ?? instances[0];
}

// buildRequirementCode synthesizes requirement.code for a DAST finding from the
// HTTP request context of the representative instance: "<METHOD> <uri>" plus an
// optional "Param:" line and an optional "Attack:" line. ZAP has no source code,
// so this reconstructs the request/payload that triggered the alert. Returns
// undefined when the alert carries no instances or no request context.
function buildRequirementCode(alert: ZapAlert): string | undefined {
  const inst = representativeInstance(alert.instances);
  if (!inst) {
    return undefined;
  }
  const parts: string[] = [];
  const requestLine = `${inst.method ?? ''} ${inst.uri ?? ''}`.trim();
  if (requestLine) {
    parts.push(requestLine);
  }
  if (inst.param) {
    parts.push(`Param: ${inst.param}`);
  }
  if (inst.attack) {
    parts.push(`Attack: ${inst.attack}`);
  }
  if (parts.length === 0) {
    return undefined;
  }
  return parts.join('\n');
}

// --- Source location ---

// buildSourceLocation promotes the affected URL of the alert's primary instance
// into the structured requirement.sourceLocation. ZAP is a DAST tool, so the
// locus is a URL (ref) with no line number — line is always omitted. The primary
// instance is the first instance carrying a uri. Returns undefined when no
// instance carries a uri, so the field is omitted rather than emitted empty.
function buildSourceLocation(alert: ZapAlert): SourceLocation | undefined {
  const inst = (alert.instances ?? []).find(i => i.uri);
  if (!inst || !inst.uri) {
    return undefined;
  }
  return {ref: inst.uri};
}

// --- External references ---

// REF_URL_RE extracts http(s) URLs from a ZAP alert's reference field. ZAP ships
// reference as HTML — URLs wrapped in <p> tags, occasionally anchor tags — or as
// whitespace-separated plain URLs; excluding whitespace, angle brackets and
// quotes stops each match at the surrounding markup so the same pattern pulls the
// real URIs from any of those shapes (including hrefs).
const REF_URL_RE = /https?:\/\/[^\s<>"']+/g;

// buildRefs turns a ZAP alert's reference field into one Reference per external
// URL. Returns undefined when the field carries no URL (empty, absent, or markup
// with no link), so refs[] is omitted rather than emitted empty.
function buildRefs(reference: string | undefined): Reference[] | undefined {
  if (!reference) {
    return undefined;
  }
  const urls = reference.match(REF_URL_RE);
  if (!urls || urls.length === 0) {
    return undefined;
  }
  return urls.map(url => ({url}));
}

// --- Per-site labeling ---

// siteLabel returns a stable, human-readable label identifying a site, used to
// build a unique per-site baseline name. Prefers the host, then the site name
// (URL), then a positional fallback so a nameless site still gets a unique name.
function siteLabel(site: ZapSite, index: number): string {
  return site['@host'] || site['@name'] || `site ${index + 1}`;
}

// buildSiteRequirements converts one site's alerts into requirements, applying
// the per-site pluginid dedup (duplicates within the site get .1, .2, ...).
// Dedup is scoped to the site so the same pluginid on two different hosts stays
// intact in each host's baseline.
function buildSiteRequirements(site: ZapSite): EvaluatedRequirement[] {
  const alerts = site.alerts ?? [];
  const pluginIdCount = new Map<string, number>();
  const {items: limitedAlerts, truncated} = limitArray(alerts);
  /* v8 ignore next -- truncation only triggers with >100K items */
  if (truncated) {
    // eslint-disable-next-line no-console
    console.warn(`WARNING: Input truncated at ${limitedAlerts.length} alert items (original: ${alerts.length})`);
  }

  const requirements: EvaluatedRequirement[] = [];
  for (const alert of limitedAlerts) {
    // Deduplicate pluginid
    const count = pluginIdCount.get(alert.pluginid) ?? 0;
    pluginIdCount.set(alert.pluginid, count + 1);
    const reqId = count === 0 ? alert.pluginid : `${alert.pluginid}.${count}`;

    // Build NIST tags
    const nistTags = buildNistTags(alert.cweid ?? '');
    const cciTags = nistToCci(nistTags);

    // Build extra tags. The CWE is promoted to first-class requirement.cwe[]
    // below and no longer duplicated into tags; wascid stays a tag.
    const extras: Record<string, unknown> = {};
    if (alert.wascid) {
      extras.wascid = alert.wascid;
    }
    if (alert.riskdesc) {
      extras.riskdesc = alert.riskdesc;
    }
    if (alert.confidence) {
      extras.confidence = alert.confidence;
    }
    const tags = buildNistCciTags(nistTags, cciTags, Object.keys(extras).length > 0 ? extras : undefined);

    // Build results from instances
    const results: RequirementResult[] = [];
    if (alert.instances && alert.instances.length > 0) {
      const {items: limitedInstances, truncated: instTruncated} = limitArray(alert.instances);
      if (instTruncated) {
        // eslint-disable-next-line no-console
        console.warn(`WARNING: Instances truncated at ${limitedInstances.length} for alert ${alert.pluginid}`);
      }
      for (const instance of limitedInstances) {
        const result: RequirementResult = {
          status: ResultStatus.Failed,
          codeDesc: buildCodeDesc(instance),
          startTime: new Date('0001-01-01T00:00:00Z'),
        };
        if (instance.attack) {
          result.message = instance.attack;
        }
        results.push(result);
      }
    }

    // Build descriptions. solution is ZAP's remediation guidance (its own
    // "solution" label); otherinfo is supplementary detail (kept as "check").
    const descriptions: Array<{label: string; data: string}> = [];
    if (alert.desc) {
      descriptions.push({label: 'default', data: stripHTML(alert.desc)});
    }
    const solution = alert.solution ? stripHTML(alert.solution) : '';
    if (solution) {
      descriptions.push({label: 'solution', data: solution});
    }
    const otherInfo = alert.otherinfo ? stripHTML(alert.otherinfo) : '';
    if (otherInfo) {
      descriptions.push({label: 'check', data: otherInfo});
    }

    const impact = riskCodeToImpact(alert.riskcode ?? '');

    const req: EvaluatedRequirement = {
      id: reqId,
      title: alert.name,
      impact,
      results,
      tags,
      descriptions,
      verificationMethod: VerificationMethodEnum.Automated,
    };

    const cwe = buildCwe(alert.cweid);
    if (cwe !== undefined) {
      req.cwe = cwe;
    }

    const controlType = deriveControlTypeFromTags(nistTags);
    if (controlType !== undefined) {
      req.controlType = controlType;
    }

    const code = buildRequirementCode(alert);
    if (code !== undefined) {
      req.code = code;
    }

    const sourceLocation = buildSourceLocation(alert);
    if (sourceLocation !== undefined) {
      req.sourceLocation = sourceLocation;
    }

    const refs = buildRefs(alert.reference);
    if (refs !== undefined) {
      req.refs = refs;
    }

    requirements.push(req);
  }
  return requirements;
}

// ZAP emits a zone-less RFC1123-like timestamp ("Thu, 6 Dec 2018 10:53:11");
// parse it as UTC to match the Go peer's parseZapTimestamp and stay host-independent.
const ZAP_RFC1123_LIKE = /^[A-Za-z]{3}, \d{1,2} [A-Za-z]{3} \d{4} \d{2}:\d{2}:\d{2}$/;

function parseZapTimestamp(s: string): Date | undefined {
  const trimmed = s.trim();
  if (ZAP_RFC1123_LIKE.test(trimmed)) {
    // Appending GMT forces UTC interpretation, so this new Date() is
    // host-independent and safe — unlike a bare tool value.
    // eslint-disable-next-line no-restricted-syntax
    const d = new Date(`${trimmed} GMT`);
    if (!isNaN(d.getTime())) {
      return d;
    }
  }
  return parseTimestamp(s) ?? undefined;
}

// --- Main converter ---

// Every site[] entry is converted to its own baseline plus an Application
// component; multi-host ZAP reports are represented as multiple baselines (one
// per host) rather than a single merged baseline. HDF Results carries no
// per-requirement componentId, and ZAP reuses pluginids across hosts (e.g. the
// same informational alert on several origins), so a single merged baseline
// could neither attribute a finding to its host nor keep the per-site dedup
// intact. One baseline per host — linked to its component via the "component"
// label — is the lossless, attributable representation.
export async function convertZapToHdf(input: string, converterVersion = '1.0.0'): Promise<string> {
  validateInputSize(input, 'zap');
  // SARIF routing — delegate to the shared SARIF converter
  registerAllFingerprints();
  const detected = detectConverter(input);
  if (detected && detected.fingerprint.id === 'sarif-to-hdf') {
    return convertSarifToHdf(input, converterVersion);
  }

  const resultsChecksum: Checksum = await inputChecksum(input);

  const zapData = parseJSON<ZapReport>(input);

  const sites = Array.isArray(zapData.site) ? zapData.site : [];
  const multiSite = sites.length > 1;
  const summary = `ZAP Version ${zapData['@version'] ?? 'unknown'}`;

  const baselines: EvaluatedBaseline[] = [];
  const components: Array<{name: string; type: TargetType; url?: string; labels?: Record<string, string>}> = [];

  sites.forEach((site, i) => {
    const targetName = site['@host'] ?? 'Unknown Host';
    const siteName = site['@name'] ?? '';

    const requirements = buildSiteRequirements(site);
    if (requirements.length === 0) {
      let target = siteName || targetName;
      if (!target || target === 'Unknown Host') {
        target = 'the target site';
      }
      requirements.push(buildNoFindingsRequirement(
        'zap-no-findings',
        `OWASP ZAP scanned ${target} and reported zero findings.`,
        new Date(),
      ));
    }

    const baselineTitle = site['@name'] || site['@host']
      ? `OWASP ZAP Scan of ${site['@name'] ?? targetName}`
      : 'OWASP ZAP Scan';

    // Single-site reports keep the legacy fixed baseline name; multi-site
    // reports get a host-scoped, unique name so baselines stay identifiable.
    const scanLabel = multiSite ? `OWASP ZAP Scan: ${siteLabel(site, i)}` : 'OWASP ZAP Scan';

    const baseline: EvaluatedBaseline = createMinimalBaseline(scanLabel, requirements, {
      resultsChecksum,
      title: baselineTitle,
      summary,
    }) as EvaluatedBaseline;
    // Link the baseline to its host component for explicit attribution.
    if (site['@host']) {
      baseline.labels = {component: site['@host']};
    }
    baselines.push(baseline);

    // Build the component — ZAP is a DAST tool scanning web applications.
    if (site['@name']) {
      components.push({name: targetName, type: TargetType.Application, url: site['@name']});
    } else if (targetName !== 'Unknown Host') {
      components.push({name: targetName, type: TargetType.Application});
    }
  });

  // No sites at all — synthesize a single no-findings baseline.
  if (baselines.length === 0) {
    const requirements = [buildNoFindingsRequirement(
      'zap-no-findings',
      'OWASP ZAP scanned the target site and reported zero findings.',
      new Date(),
    )];
    baselines.push(createMinimalBaseline('OWASP ZAP Scan', requirements, {
      resultsChecksum,
      title: 'OWASP ZAP Scan',
      summary,
    }) as EvaluatedBaseline);
  }

  const tool: Tool = {
    name: 'OWASP ZAP',
  };
  if (zapData['@version']) {
    tool.version = zapData['@version'];
  }

  const hdf: HDFResults = {
    baselines,
    components,
    generator: {
      name: 'zap-to-hdf',
      version: converterVersion,
    },
    tool,
  };

  if (zapData['@generated']) {
    const ts = parseZapTimestamp(zapData['@generated']);
    if (ts) {
      hdf.timestamp = ts;
    }
  }

  return serializeHdf(hdf);
}
