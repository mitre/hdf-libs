import {
  type Checksum,
  Copyright,
  createMinimalBaseline,
  type EvaluatedBaseline,
  type EvaluatedRequirement,
  type RequirementResult,
  ResultStatus,
  VerificationMethodEnum,
} from '@mitre/hdf-schema';
import {
  getNiktoNistControl,
  nistToCci,
  DEFAULT_STATIC_ANALYSIS_NIST_TAGS,
} from '@mitre/hdf-mappings';
import {parseJSON} from '@mitre/hdf-utilities';
import {deriveControlTypeFromTags, inputChecksum, buildNistCciTags, limitArray, validateInputSize, buildHdfResults} from '../../../shared/typescript/converterutil.js';

// Nikto JSON input types

interface NiktoReport {
  banner?: string;
  host?: string;
  ip?: string;
  port?: string;
  vulnerabilities: NiktoVulnerability[];
}

interface NiktoVulnerability {
  OSVDB?: string;
  id: string;
  method?: string;
  msg: string;
  url?: string;
}

function buildNistTags(niktoId: string): string[] {
  const control = getNiktoNistControl(niktoId);
  if (control) {
    return [control];
  }
  return [...DEFAULT_STATIC_ANALYSIS_NIST_TAGS];
}

function buildCodeDesc(vuln: NiktoVulnerability): string {
  const parts: string[] = [];
  if (vuln.url) {
    parts.push(`URL: ${vuln.url}`);
  }
  if (vuln.method) {
    parts.push(`Method: ${vuln.method}`);
  }
  return parts.join(' ');
}

function convertVulnToRequirement(vuln: NiktoVulnerability): EvaluatedRequirement {
  const nistTags = buildNistTags(vuln.id);
  const cciTags = nistToCci(nistTags);

  const result: RequirementResult = {
    status: ResultStatus.Failed,
    codeDesc: buildCodeDesc(vuln),
    startTime: new Date('0001-01-01T00:00:00Z'),
  };

  const extras: Record<string, unknown> = {};
  if (vuln.OSVDB && vuln.OSVDB !== '0') {
    extras.osvdb = vuln.OSVDB;
  }
  const tags = buildNistCciTags(nistTags, cciTags, Object.keys(extras).length > 0 ? extras : undefined);

  const req: EvaluatedRequirement = {
    id: vuln.id,
    title: vuln.msg,
    impact: 0.5,
    results: [result],
    tags,
    descriptions: [
      {label: 'default', data: vuln.msg},
    ],
  };
  const controlType = deriveControlTypeFromTags(nistTags);
  if (controlType !== undefined) {
    req.controlType = controlType;
  }
  req.verificationMethod = VerificationMethodEnum.Automated;
  return req;
}

export async function convertNiktoToHdf(input: string): Promise<string> {
  validateInputSize(input, 'nikto');
  const resultsChecksum: Checksum = await inputChecksum(input);

  const niktoData = parseJSON<NiktoReport>(input);

  // Group vulnerabilities by ID to handle duplicates
  const vulnGroups = new Map<string, NiktoVulnerability[]>();
  if (niktoData.vulnerabilities) {
    const { items: limitedVulns, truncated: truncatedVulns } = limitArray(niktoData.vulnerabilities);
    /* v8 ignore next -- truncation only triggers with >100K items */
    if (truncatedVulns) {
      // eslint-disable-next-line no-console
      console.warn(`WARNING: Input truncated at ${limitedVulns.length} vulnerability items (original: ${niktoData.vulnerabilities.length})`);
    }
    for (const vuln of limitedVulns) {
      const existing = vulnGroups.get(vuln.id);
      if (existing) {
        existing.push(vuln);
      } else {
        vulnGroups.set(vuln.id, [vuln]);
      }
    }
  }

  const requirements: EvaluatedRequirement[] = [];
  for (const [, vulns] of vulnGroups) {
    // Use first vuln for the requirement definition
    const primary = vulns[0]!;
    const req = convertVulnToRequirement(primary);

    // Add results from duplicate IDs
    if (vulns.length > 1) {
      for (let i = 1; i < vulns.length; i++) {
        req.results.push({
          status: ResultStatus.Failed,
          codeDesc: buildCodeDesc(vulns[i]!),
          startTime: new Date('0001-01-01T00:00:00Z'),
        });
      }
    }

    requirements.push(req);
  }

  const targetParts: string[] = [];
  if (niktoData.host) {
    targetParts.push(`Host: ${niktoData.host}`);
  }
  if (niktoData.port) {
    targetParts.push(`Port: ${niktoData.port}`);
  }
  const targetName = targetParts.length > 0 ? targetParts.join(' ') : 'Nikto Scan';

  const baseline: EvaluatedBaseline = createMinimalBaseline(targetName, requirements, {
    resultsChecksum,
    title: `Nikto Target: ${targetName}`,
    summary: niktoData.banner || '',
  }) as EvaluatedBaseline;

  return buildHdfResults({
    generatorName: 'nikto-to-hdf',
    converterVersion: 'unknown',
    toolName: 'Nikto',
    toolFormat: 'JSON',
    baselines: [baseline],
    components: [{
      type: Copyright.Application,
      name: targetName,
    }],
  });
}
