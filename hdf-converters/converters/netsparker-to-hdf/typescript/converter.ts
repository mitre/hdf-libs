import { parseXmlWithArrays, parseTimestamp, severityToImpactWithAliases } from '@mitre/hdf-utilities';
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
  markUnratedSeverity,
  stripHTML,
  validateInputSize,
  buildHdfResults,
  buildNoFindingsRequirement,
} from '../../../shared/typescript/converterutil.js';
import { buildCvss, cvssVersionFromVector } from '../../../shared/typescript/cvss.js';
import type {
  EvaluatedBaseline,
  EvaluatedRequirement,
  RequirementResult,
  Checksum,
  Cvss,
  Description,
  Reference,
} from '@mitre/hdf-schema';
import {
  ResultStatus,
  TargetType,
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
  'extra-information'?: NetsparkerExtraInfoBlock;
}

interface NetsparkerExtraInfoBlock {
  info?: NetsparkerExtraInfo[];
}

interface NetsparkerExtraInfo {
  name?: string;
  value?: string;
}

interface NetsparkerClassification {
  owasp?: string;
  wasc?: string;
  cwe?: string;
  capec?: string;
  pci32?: string;
  iso27001?: string;
  cvss?: NetsparkerCvssBlock;
  cvss31?: NetsparkerCvssBlock;
}

interface NetsparkerCvssBlock {
  vector?: string;
  score?: NetsparkerCvssScore[];
}

interface NetsparkerCvssScore {
  type?: string;
  value?: string;
  severity?: string;
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
// Mirrors the Go twin: "best_practice" is the only Netsparker-specific alias;
// standard levels + "information" come from the shared standard map.

const NETSPARKER_ALIASES: Record<string, number> = {
  best_practice: 0.0,
};

function getImpact(severity: string): number {
  return severityToImpactWithAliases(severity, NETSPARKER_ALIASES, 0.5);
}

// Netsparker <initiated> uses the US format "MM/DD/YYYY hh:mm AM/PM"
// (e.g. "05/05/2023 04:57 PM"), which the shared parseTimestamp does not
// recognize — so it would fall to host-local `new Date()`. Parse it explicitly
// as UTC (mirroring the Go converter's parseNetsparkerTimestamp + UTC
// normalization); fall back to the shared parser for any other shape.
const NETSPARKER_US_DATETIME = /^\d{2}\/\d{2}\/\d{4} \d{1,2}:\d{2} (AM|PM)$/;

function parseNetsparkerTimestamp(s: string): Date | null {
  const trimmed = s.trim();
  if (NETSPARKER_US_DATETIME.test(trimmed)) {
    // Appending GMT forces UTC interpretation (the whole point of this parser),
    // so this new Date() is host-independent and safe — unlike a bare value.
    // eslint-disable-next-line no-restricted-syntax
    const d = new Date(`${trimmed} GMT`);
    if (!isNaN(d.getTime())) return d;
  }
  return parseTimestamp(s);
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

// parseXmlWithArrays runs with processEntities:false (a security default we do
// not override), so XML entities in attribute values arrive raw. Go's
// encoding/xml decodes entities inside attributes, so decode here to preserve
// Go/TS byte parity. &amp; is decoded last to avoid re-expanding its output.
export function decodeXmlEntities(s: string): string {
  return s
    .replace(/&#x([0-9a-fA-F]+);/g, (_m, h) => String.fromCodePoint(parseInt(h, 16)))
    .replace(/&#(\d+);/g, (_m, d) => String.fromCodePoint(parseInt(d, 10)))
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'")
    .replace(/&amp;/g, '&');
}

// Renders the <extra-information> info entries as "name=>value" pairs joined by
// ", ", mirroring the converter's Classification line style. Returns "" when
// there are no entries.
function formatExtraInformation(extra: NetsparkerExtraInfoBlock | undefined): string {
  const info = extra?.info ?? [];
  if (info.length === 0) {
    return '';
  }
  return info
    .map(i => `${decodeXmlEntities(i.name ?? '')}=>${decodeXmlEntities(i.value ?? '')}`)
    .join(', ');
}

function formatControlDesc(vuln: NetsparkerVuln): string {
  const parts: string[] = [];
  if (vuln.description) {
    parts.push(stripHTML(vuln.description));
  }
  if (vuln['exploitation-skills']) {
    parts.push(`Exploitation-skills: ${vuln['exploitation-skills']}`);
  }
  const extra = formatExtraInformation(vuln['extra-information']);
  if (extra) {
    parts.push(`Extra-information: ${extra}`);
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
 * Returns the parsed Base-metric score from a CVSS block, or undefined when
 * there is no Base score or its value does not parse as a finite number.
 */
function baseScoreFromBlock(block: NetsparkerCvssBlock | undefined): number | undefined {
  const scores = block?.score ?? [];
  for (const s of scores) {
    if ((s.type ?? '').toLowerCase() === 'base') {
      const v = parseFloat((s.value ?? '').trim());
      return Number.isFinite(v) ? v : undefined;
    }
  }
  return undefined;
}

/**
 * Assembles the structured cvss[] from the <cvss> (3.0) and <cvss31> (3.1)
 * classification blocks. Each block carrying a vector or a Base score becomes
 * one entry; the schema version derives from the vector prefix.
 */
export function buildNetsparkerCvss(classification: NetsparkerClassification | undefined): Cvss[] {
  const out: Cvss[] = [];
  for (const block of [classification?.cvss, classification?.cvss31]) {
    const baseScore = baseScoreFromBlock(block);
    const vector = block?.vector ?? '';
    if (!vector && baseScore === undefined) {
      continue;
    }
    out.push(buildCvss({
      version: cvssVersionFromVector(vector),
      baseScore,
      baseVector: vector,
    }));
  }
  return out;
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

// Extracts the URL from each anchor tag in Netsparker's <external-references>
// HTML blob (single- or double-quoted href).
const HREF_PATTERN = /href=['"]([^'"]+)['"]/g;

/**
 * Turns Netsparker's <external-references> HTML anchor blob into one Reference
 * per external URL. Returns undefined when the field is empty or carries no
 * links, so refs[] is omitted entirely.
 */
function buildRefs(externalReferences: string | undefined): Reference[] | undefined {
  if (!externalReferences) {
    return undefined;
  }
  const refs: Reference[] = [];
  for (const match of externalReferences.matchAll(HREF_PATTERN)) {
    // Reference.url is schema-constrained to format "uri"; only emit absolute
    // hrefs (a scheme is present), skipping empty/relative/fragment.
    const url = match[1]?.trim() ?? '';
    if (!url.includes('://')) {
      continue;
    }
    refs.push({ url });
  }
  return refs.length > 0 ? refs : undefined;
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
  // Source-native categorization strings Netsparker/Invicti carries in
  // <classification>. Each is single-valued; omit the tag when empty.
  const capec = vuln.classification?.capec;
  if (capec) {
    extras.capec = capec;
  }
  const wasc = vuln.classification?.wasc;
  if (wasc) {
    extras.wasc = wasc;
  }
  const iso27001 = vuln.classification?.iso27001;
  if (iso27001) {
    extras.iso27001 = iso27001;
  }
  const pci32 = vuln.classification?.pci32;
  if (pci32) {
    extras.pci32 = pci32;
  }

  const tags = buildNistCciTags(nist, cciTags, Object.keys(extras).length > 0 ? extras : undefined);
  markUnratedSeverity(tags, vuln.severity);

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

  const startTime = (initiated ? parseNetsparkerTimestamp(initiated) : null) ?? new Date('0001-01-01T00:00:00Z');

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

  // requirement.code = the raw HTTP request that triggered the finding — the
  // natural CODE-tab fill for a DAST tool. Leave unset when absent.
  const rawRequest = vuln['http-request']?.content;
  if (rawRequest) {
    req.code = rawRequest;
  }

  const cvss = buildNetsparkerCvss(vuln.classification);
  if (cvss.length > 0) {
    req.cvss = cvss;
  }

  // requirement.refs = external reference links Netsparker carries in the
  // <external-references> HTML blob. Left unset when the vuln carries none.
  const refs = buildRefs(vuln['external-references']);
  if (refs !== undefined) {
    req.refs = refs;
  }

  return req;
}

/**
 * Converts Netsparker/Invicti XML scan results to HDF format.
 * Handles both <netsparker-enterprise> and <invicti-enterprise> root elements.
 *
 * @param input - Netsparker/Invicti XML string
 * @returns HDF JSON string
 */
export async function convertNetsparkerToHdf(input: string, converterVersion = '1.0.0'): Promise<string> {
  if (!input || input.trim().length === 0) {
    throw new Error('netsparker: empty input');
  }
  validateInputSize(input, 'netsparker');

  const resultsChecksum: Checksum = await inputChecksum(input);

  // Parse XML — ensure vulnerability is always treated as array
  const parsed = parseXmlWithArrays(input, ['vulnerability', 'score', 'info']) as unknown as NetsparkerXml;

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
  const generated = data.generated ?? '';

  // Top-level timestamp is the report's `generated` attribute (parsed as UTC,
  // mirroring the Go converter). Fall back to now() only when the source omits
  // or malforms it, so a source with `generated` converts deterministically.
  const timestamp = (generated ? parseNetsparkerTimestamp(generated) : null) ?? new Date();

  const { items: limitedVulns, truncated } = limitArray(vulns);
  /* v8 ignore next -- truncation only triggers with >100K items */
  if (truncated) {
    // eslint-disable-next-line no-console
    console.warn(`WARNING: Input truncated at ${limitedVulns.length} vulnerability items (original: ${vulns.length})`);
  }

  const targetName = target.url ?? 'Unknown';

  // Build one requirement per vulnerability
  const requirements: EvaluatedRequirement[] = limitedVulns.map(
    vuln => buildRequirement(vuln, initiated),
  );

  if (requirements.length === 0) {
    const startTime = (initiated ? parseNetsparkerTimestamp(initiated) : null) ?? new Date();
    requirements.push(buildNoFindingsRequirement(
      'netsparker-no-findings',
      `${toolName} scanned ${targetName} and reported zero findings.`,
      startTime,
    ));
  }

  const title = `${toolName} Enterprise Scan ID: ${target['scan-id'] ?? ''} URL: ${target.url ?? ''}`;

  const baseline: EvaluatedBaseline = createMinimalBaseline(
    'Netsparker Scan',
    requirements,
    {
      resultsChecksum,
      title,
    },
  ) as EvaluatedBaseline;

  return buildHdfResults({
    generatorName: 'netsparker-to-hdf',
    converterVersion,
    toolName,
    timestamp,
    baselines: [baseline],
    components: [
      {
        name: targetName,
        type: TargetType.Application,
      },
    ],
  });
}
