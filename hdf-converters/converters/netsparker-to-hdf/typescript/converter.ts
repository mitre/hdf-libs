import { parseXmlWithArrays } from '@mitre/hdf-utilities';
import {
  nistToCci,
  DEFAULT_STATIC_ANALYSIS_NIST_TAGS,
  getOwaspNistControl,
  getCweNistControl,
} from '@mitre/hdf-mappings';
import {
  deriveControlTypeFromTags,
  inputChecksum,
  buildNistCciTags,
  limitArray,
  stripHTML,
  validateInputSize,
  buildHdfResults,
} from '../../../shared/typescript/converterutil.js';
import type {
  EvaluatedBaseline,
  EvaluatedRequirement,
  RequirementResult,
  Checksum,
  Description,
} from '@mitre/hdf-schema';
import {
  ResultStatus,
  Copyright,
  VerificationMethodEnum,
  createMinimalBaseline,
} from '@mitre/hdf-schema';

// --- Netsparker/Invicti XML input types ---

interface NetsparkerXml {
  'netsparker-enterprise'?: NetsparkerEnterprise;
  'invicti-enterprise'?: NetsparkerEnterprise;
}

interface NetsparkerEnterprise {
  generated?: string;
  target?: NetsparkerTarget;
  vulnerabilities?: {
    vulnerability?: NetsparkerVuln[];
  };
}

interface NetsparkerTarget {
  'scan-id'?: string;
  url?: string;
  initiated?: string;
  duration?: string;
}

interface NetsparkerVuln {
  LookupId?: string;
  url?: string;
  type?: string;
  name?: string;
  severity?: string;
  certainty?: string;
  confirmed?: string;
  state?: string;
  FirstSeenDate?: string;
  LastSeenDate?: string;
  classification?: NetsparkerClassification;
  'http-request'?: NetsparkerHttpRequest;
  'http-response'?: NetsparkerHttpResponse;
  description?: string;
  impact?: string;
  'remedial-actions'?: string;
  'exploitation-skills'?: string;
  'remedial-procedure'?: string;
  'remedy-references'?: string;
  'external-references'?: string;
  'proof-of-concept'?: string;
}

interface NetsparkerClassification {
  owasp?: string;
  wasc?: string;
  cwe?: string;
  capec?: string;
  iso27001?: string;
}

interface NetsparkerHttpRequest {
  method?: string;
  content?: string;
}

interface NetsparkerHttpResponse {
  'status-code'?: string;
  duration?: string;
  content?: string;
}

// --- Severity to impact mapping ---

const IMPACT_MAPPING: Record<string, number> = {
  'critical': 1.0,
  'high': 0.7,
  'medium': 0.5,
  'low': 0.3,
  'best_practice': 0.0,
  'information': 0.0,
};

function getImpact(severity: string): number {
  return IMPACT_MAPPING[severity.toLowerCase()] ?? 0.5;
}

// --- Format helpers ---

function formatCodeDesc(request: NetsparkerHttpRequest | undefined): string {
  const parts: string[] = [];
  parts.push(`http-request : ${request?.content ?? ''}`);
  parts.push(`method : ${request?.method ?? ''}`);
  return parts.join('\n');
}

function formatMessage(response: NetsparkerHttpResponse | undefined): string {
  const parts: string[] = [];
  parts.push(`http-response : ${response?.content ?? ''}`);
  parts.push(`duration : ${response?.duration ?? ''}`);
  parts.push(`status-code  : ${response?.['status-code'] ?? ''}`);
  return parts.join('\n');
}

function formatControlDesc(vuln: NetsparkerVuln): string {
  const parts: string[] = [];
  if (vuln.description) {
    parts.push(stripHTML(vuln.description));
  }
  if (vuln['exploitation-skills']) {
    parts.push(`Exploitation-skills: ${vuln['exploitation-skills']}`);
  }
  const cweVal = vuln.classification?.cwe ?? '';
  const owaspVal = vuln.classification?.owasp ?? '';
  if (cweVal || owaspVal) {
    parts.push(`Classification: cwe=>${cweVal}, owasp=>${owaspVal}`);
  }
  if (vuln.impact) {
    parts.push(`Impact: ${stripHTML(vuln.impact)}`);
  }
  if (vuln.FirstSeenDate) {
    parts.push(`FirstSeenDate: ${vuln.FirstSeenDate}`);
  }
  if (vuln.LastSeenDate) {
    parts.push(`LastSeenDate: ${vuln.LastSeenDate}`);
  }
  if (vuln.certainty) {
    parts.push(`Certainty: ${vuln.certainty}`);
  }
  if (vuln.type) {
    parts.push(`Type: ${vuln.type}`);
  }
  if (vuln.confirmed) {
    parts.push(`Confirmed: ${vuln.confirmed}`);
  }
  return parts.join('\n');
}

/**
 * Performs dual NIST mapping from both CWE and OWASP IDs.
 * Returns a deduplicated sorted list of NIST controls, falling back to
 * DEFAULT_STATIC_ANALYSIS_NIST_TAGS if no mappings are found.
 */
function mapNISTFromCWEAndOWASP(cweID: string, owaspID: string): string[] {
  const controls = new Set<string>();

  // CWE -> NIST
  if (cweID) {
    const numericId = parseInt(cweID, 10);
    if (!isNaN(numericId)) {
      const nistControl = getCweNistControl(numericId);
      if (nistControl) {
        controls.add(nistControl);
      }
    }
  }

  // OWASP -> NIST
  if (owaspID) {
    const nistControl = getOwaspNistControl(owaspID);
    if (nistControl) {
      controls.add(nistControl);
    }
  }

  return controls.size > 0
    ? [...controls].sort()
    : [...DEFAULT_STATIC_ANALYSIS_NIST_TAGS];
}

/**
 * Builds a single EvaluatedRequirement from a vulnerability.
 */
function buildRequirement(
  vuln: NetsparkerVuln,
  initiated: string,
): EvaluatedRequirement {
  const cweID = vuln.classification?.cwe ?? '';
  const owaspID = vuln.classification?.owasp ?? '';

  const nist = mapNISTFromCWEAndOWASP(cweID, owaspID);
  const cciTags = nistToCci(nist);

  const extras: Record<string, unknown> = {};
  if (cweID) {
    extras.cweid = cweID;
  }
  if (owaspID) {
    extras.owasp = owaspID;
  }

  const tags = buildNistCciTags(nist, cciTags, Object.keys(extras).length > 0 ? extras : undefined);

  // Default description
  const defaultDesc = formatControlDesc(vuln);
  const descriptions: Description[] = [
    { label: 'default', data: defaultDesc || vuln.name || '' },
  ];

  // Check description
  const checkParts: string[] = [];
  if (vuln['exploitation-skills']) {
    checkParts.push(`Exploitation-skills: ${vuln['exploitation-skills']}`);
  }
  if (vuln['proof-of-concept']) {
    checkParts.push(`Proof-of-concept: ${stripHTML(vuln['proof-of-concept'])}`);
  }
  if (checkParts.length > 0) {
    descriptions.push({ label: 'check', data: stripHTML(checkParts.join('\n')) });
  }

  // Fix description
  const fixParts: string[] = [];
  if (vuln['remedial-actions']) {
    fixParts.push(`Remedial-actions: ${stripHTML(vuln['remedial-actions'])}`);
  }
  if (vuln['remedial-procedure']) {
    fixParts.push(`Remedial-procedure: ${stripHTML(vuln['remedial-procedure'])}`);
  }
  if (vuln['remedy-references']) {
    fixParts.push(`Remedy-references: ${stripHTML(vuln['remedy-references'])}`);
  }
  if (fixParts.length > 0) {
    descriptions.push({ label: 'fix', data: fixParts.join('\n') });
  }

  // Result
  const codeDesc = formatCodeDesc(vuln['http-request']);
  const message = formatMessage(vuln['http-response']);

  const startTime = initiated ? new Date(initiated) : new Date('0001-01-01T00:00:00Z');

  const results: RequirementResult[] = [{
    status: ResultStatus.Failed,
    codeDesc,
    message,
    startTime,
  }];

  const impact = getImpact(vuln.severity ?? '');

  const req: EvaluatedRequirement = {
    id: vuln.LookupId ?? '',
    title: vuln.name ?? undefined,
    impact,
    tags,
    descriptions,
    results,
  };
  const controlType = deriveControlTypeFromTags(nist);
  if (controlType !== undefined) {
    req.controlType = controlType;
  }
  req.verificationMethod = VerificationMethodEnum.Automated;
  return req;
}

/**
 * Converts Netsparker/Invicti XML scan results to HDF format.
 * Handles both <netsparker-enterprise> and <invicti-enterprise> root elements.
 *
 * @param input - Netsparker/Invicti XML string
 * @returns HDF JSON string
 */
export async function convertNetsparkerToHdf(input: string): Promise<string> {
  if (!input || input.trim().length === 0) {
    throw new Error('netsparker: empty input');
  }
  validateInputSize(input, 'netsparker');

  const resultsChecksum: Checksum = await inputChecksum(input);

  // Parse XML — ensure vulnerability is always treated as array
  const parsed = parseXmlWithArrays(input, ['vulnerability']) as unknown as NetsparkerXml;

  // Detect root element
  const isInvicti = !!parsed['invicti-enterprise'];
  const data: NetsparkerEnterprise = parsed['invicti-enterprise'] ?? parsed['netsparker-enterprise'] ?? {};

  if (!data.vulnerabilities && !data.target) {
    throw new Error('netsparker: invalid XML — missing expected root element');
  }

  const toolName = isInvicti ? 'Invicti' : 'Netsparker';
  const vulns = data.vulnerabilities?.vulnerability ?? [];
  const target = data.target ?? {};
  const initiated = target.initiated ?? '';

  const { items: limitedVulns, truncated } = limitArray(vulns);
  /* v8 ignore next -- truncation only triggers with >100K items */
  if (truncated) {
    // eslint-disable-next-line no-console
    console.warn(`WARNING: Input truncated at ${limitedVulns.length} vulnerability items (original: ${vulns.length})`);
  }

  // Build one requirement per vulnerability
  const requirements: EvaluatedRequirement[] = limitedVulns.map(
    vuln => buildRequirement(vuln, initiated),
  );

  const title = `${toolName} Enterprise Scan ID: ${target['scan-id'] ?? ''} URL: ${target.url ?? ''}`;

  const baseline: EvaluatedBaseline = createMinimalBaseline(
    'Netsparker Scan',
    requirements,
    {
      resultsChecksum,
      title,
    },
  ) as EvaluatedBaseline;

  const targetName = target.url ?? 'Unknown';

  return buildHdfResults({
    generatorName: 'netsparker-to-hdf',
    converterVersion: '1.0.0',
    toolName,
    toolFormat: 'XML',
    baselines: [baseline],
    components: [
      {
        name: targetName,
        type: Copyright.Application,
      },
    ],
  });
}
