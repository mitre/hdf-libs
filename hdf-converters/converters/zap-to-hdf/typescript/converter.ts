import {
  type Checksum,
  createMinimalBaseline,
  Copyright,
  type Tool,
  type EvaluatedBaseline,
  type EvaluatedRequirement,
  type RequirementResult,
  type HdfResults,
  ResultStatus,
  VerificationMethodEnum,
} from '@mitre/hdf-schema';
import {
  getCweNistControl,
  nistToCci,
  DEFAULT_STATIC_ANALYSIS_NIST_TAGS,
} from '@mitre/hdf-mappings';
import {parseJSON} from '@mitre/hdf-utilities';
import {detectConverter} from '../../../shared/typescript/fingerprint.js';
import {registerAllFingerprints} from '../../../shared/typescript/register-all.js';
import {convertSarifToHdf} from '../../sarif-to-hdf/typescript/converter.js';
import {deriveControlTypeFromTags, inputChecksum, buildNistCciTags, limitArray, stripHTML, validateInputSize} from '../../../shared/typescript/converterutil.js';

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

// --- Build check description ---

function buildCheckDescription(alert: ZapAlert): string {
  const parts: string[] = [];
  if (alert.solution) {
    const stripped = stripHTML(alert.solution);
    if (stripped) {
      parts.push(stripped);
    }
  }
  if (alert.otherinfo) {
    const stripped = stripHTML(alert.otherinfo);
    if (stripped) {
      parts.push(stripped);
    }
  }
  return parts.join('\n');
}

// --- Select site with most alerts ---

function selectSite(sites: ZapSite[]): ZapSite | undefined {
  if (sites.length === 0) return undefined;
  let best = sites[0]!;
  for (let i = 1; i < sites.length; i++) {
    const site = sites[i]!;
    if ((site.alerts?.length ?? 0) > (best.alerts?.length ?? 0)) {
      best = site;
    }
  }
  return best;
}

// --- Main converter ---

export async function convertZapToHdf(input: string): Promise<string> {
  validateInputSize(input, 'zap');
  // SARIF routing — delegate to the shared SARIF converter
  registerAllFingerprints();
  const detected = detectConverter(input);
  if (detected && detected.fingerprint.id === 'sarif-to-hdf') {
    return convertSarifToHdf(input);
  }

  const resultsChecksum: Checksum = await inputChecksum(input);

  const zapData = parseJSON<ZapReport>(input);

  // Validate basic structure
  if (!zapData.site || !Array.isArray(zapData.site)) {
    // Empty report — produce empty HDF
    const baseline: EvaluatedBaseline = createMinimalBaseline('OWASP ZAP Scan', [], {
      resultsChecksum,
      title: 'OWASP ZAP Scan',
      summary: '',
    }) as EvaluatedBaseline;

    const hdf: HdfResults = {
      baselines: [baseline],
      generator: {name: 'zap-to-hdf', version: 'unknown'},
      tool: {name: 'OWASP ZAP', format: 'JSON'},
    };
    return JSON.stringify(hdf, null, 2);
  }

  // Select site with most alerts
  const site = selectSite(zapData.site);
  if (!site) {
    // Empty site array — produce empty HDF
    const baseline: EvaluatedBaseline = createMinimalBaseline('OWASP ZAP Scan', [], {
      resultsChecksum,
      title: 'OWASP ZAP Scan',
      summary: `ZAP Version ${zapData['@version'] ?? 'unknown'}`,
    }) as EvaluatedBaseline;

    const hdf: HdfResults = {
      baselines: [baseline],
      generator: {name: 'zap-to-hdf', version: 'unknown'},
      tool: {name: 'OWASP ZAP', format: 'JSON'},
    };
    if (zapData['@generated']) {
      hdf.timestamp = new Date(zapData['@generated']);
    }
    return JSON.stringify(hdf, null, 2);
  }

  const alerts = site.alerts ?? [];

  // Deduplicate by pluginid — append .1, .2 for duplicates
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

    // Build extra tags
    const extras: Record<string, unknown> = {};
    if (alert.cweid) {
      extras.cweid = alert.cweid;
    }
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

    // Build descriptions
    const descriptions: Array<{label: string; data: string}> = [];
    if (alert.desc) {
      descriptions.push({label: 'default', data: stripHTML(alert.desc)});
    }
    const checkDesc = buildCheckDescription(alert);
    if (checkDesc) {
      descriptions.push({label: 'check', data: checkDesc});
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

    const controlType = deriveControlTypeFromTags(nistTags);
    if (controlType !== undefined) {
      req.controlType = controlType;
    }

    requirements.push(req);
  }

  const targetName = site['@host'] ?? 'Unknown Host';
  const siteName = site['@name'] ?? targetName;
  const baselineName = `OWASP ZAP Scan of ${siteName}`;

  const baseline: EvaluatedBaseline = createMinimalBaseline('OWASP ZAP Scan', requirements, {
    resultsChecksum,
    title: baselineName,
    summary: `ZAP Version ${zapData['@version'] ?? 'unknown'}`,
  }) as EvaluatedBaseline;

  const tool: Tool = {
    name: 'OWASP ZAP',
    format: 'JSON',
  };
  if (zapData['@version']) {
    tool.version = zapData['@version'];
  }

  // Build components — ZAP is a DAST tool scanning web applications
  const components: Array<{name: string; type: Copyright; url?: string; labels?: Record<string, string>}> = [];
  if (site['@name']) {
    components.push({name: targetName, type: Copyright.Application, url: site['@name']});
  } else if (targetName !== 'Unknown Host') {
    components.push({name: targetName, type: Copyright.Application});
  }

  const hdf: HdfResults = {
    baselines: [baseline],
    components,
    generator: {
      name: 'zap-to-hdf',
      version: 'unknown',
    },
    tool,
  };

  if (zapData['@generated']) {
    hdf.timestamp = new Date(zapData['@generated']);
  }

  return JSON.stringify(hdf, null, 2);
}
