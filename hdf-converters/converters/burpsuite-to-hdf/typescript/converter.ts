import { parseXmlWithArrays, parseTimestamp } from '@mitre/hdf-utilities';
import {
  nistToCci,
  DEFAULT_STATIC_ANALYSIS_NIST_TAGS,
} from '@mitre/hdf-mappings';
import {
  buildNoFindingsRequirement,
  deriveControlTypeFromTags,
  inputChecksum,
  buildNistCciTags,
  limitArray,
  stripHTML,
  mapCWEToNIST,
  extractCWEIDs,
  validateInputSize,
  serializeHdf,
} from '../../../shared/typescript/converterutil.js';
import type {
  HDFResults,
  EvaluatedBaseline,
  EvaluatedRequirement,
  RequirementResult,
  Checksum,
  Tool,
  Description,
} from '@mitre/hdf-schema';
import {
  ResultStatus,
  TargetType,
  VerificationMethodEnum,
  createMinimalBaseline,
} from '@mitre/hdf-schema';

// --- BurpSuite XML input types ---

interface BurpIssuesXml {
  issues: {
    burpVersion?: string;
    exportTime?: string;
    issue?: BurpIssueXml[];
  };
}

interface BurpIssueXml {
  serialNumber?: string;
  type?: string;
  name?: string;
  host?: BurpHostXml;
  path?: string;
  location?: string;
  severity?: string;
  confidence?: string;
  issueBackground?: string;
  remediationBackground?: string;
  references?: string;
  vulnerabilityClassifications?: string;
  issueDetail?: string;
}

interface BurpHostXml {
  ip?: string;
  '#text'?: string;
}

// --- Impact mapping ---

const IMPACT_MAPPING: Record<string, number> = {
  'high': 0.7,
  'medium': 0.5,
  'low': 0.3,
  'information': 0.3,
};

function getImpact(severity: string): number {
  return IMPACT_MAPPING[severity.toLowerCase()] ?? 0.3;
}

// --- CWE parsing ---

/**
 * Extract CWE identifiers from HTML text.
 * Returns CWE-prefixed IDs (e.g., ["CWE-79"]) for use in tags and mapCWEToNIST.
 */
function parseCWEIDs(html: string): string[] {
  if (!html) return [];
  return extractCWEIDs(html).map(id => `CWE-${id}`);
}

// --- Format code desc ---

function formatCodeDesc(
  hostIP: string,
  hostURL: string,
  location: string,
  issueDetail: string,
  confidence: string,
): string {
  const parts: string[] = [];
  parts.push(`Host: ip: ${hostIP}, url: ${hostURL}`);
  parts.push(`Location: ${stripHTML(location)}`);
  if (issueDetail) {
    parts.push(`issueDetail: ${stripHTML(issueDetail)}`);
  }
  parts.push(`confidence: ${confidence}`);
  return parts.join('\n') + '\n';
}

// --- Main converter ---

/**
 * Converts BurpSuite Pro XML export to HDF format.
 *
 * Issues are grouped by `<type>` — each unique type becomes one requirement,
 * with one result per individual issue instance.
 *
 * @param input - BurpSuite XML string
 * @returns HDF JSON string
 */
export async function convertBurpsuiteToHdf(input: string): Promise<string> {
  if (!input || input.trim().length === 0) {
    throw new Error('burpsuite: empty input');
  }
  validateInputSize(input, 'burpsuite');

  const resultsChecksum: Checksum = await inputChecksum(input);

  // Parse XML — ensure issue is always treated as array
  const parsed = parseXmlWithArrays(input, ['issue']) as unknown as BurpIssuesXml;

  if (!parsed.issues) {
    throw new Error('burpsuite: invalid XML — missing <issues> root element');
  }

  const issues = parsed.issues.issue ?? [];
  const burpVersion = parsed.issues.burpVersion ?? '';
  const exportTime = parsed.issues.exportTime ?? '';

  const { items: limitedIssues, truncated } = limitArray(issues);
  /* v8 ignore next -- truncation only triggers with >100K items */
  if (truncated) {
    // eslint-disable-next-line no-console
    console.warn(`WARNING: Input truncated at ${limitedIssues.length} issue items (original: ${issues.length})`);
  }

  // Group issues by type (preserving insertion order)
  const groups = new Map<string, BurpIssueXml[]>();
  for (const issue of limitedIssues) {
    const issueType = issue.type ?? 'unknown';
    const existing = groups.get(issueType);
    if (existing) {
      existing.push(issue);
    } else {
      groups.set(issueType, [issue]);
    }
  }

  // Build requirements from grouped issues
  const requirements: EvaluatedRequirement[] = [];
  for (const [issueType, groupIssues] of groups) {
    requirements.push(buildRequirement(issueType, groupIssues));
  }

  // Determine target from the first issue's host
  const targetName = limitedIssues.length > 0
    ? (limitedIssues[0]!.host?.['#text'] ?? 'Unknown').trim()
    : 'Unknown';

  if (requirements.length === 0) {
    requirements.push(buildNoFindingsRequirement(
      'burpsuite-no-findings',
      `Burp Suite scanned ${targetName} and reported zero findings.`,
      new Date(),
    ));
  }

  const title = `BurpSuite Scan: ${targetName}`;

  const baseline: EvaluatedBaseline = createMinimalBaseline(
    'BurpSuite Scan',
    requirements,
    {
      resultsChecksum,
      title,
    },
  ) as EvaluatedBaseline;

  const tool: Tool = {
    name: 'BurpSuite',
    format: 'XML',
  };
  if (burpVersion) {
    tool.version = burpVersion;
  }

  const hdf: HDFResults = {
    baselines: [baseline],
    components: [
      {
        name: targetName,
        type: TargetType.Application,
      },
    ],
    generator: {
      name: 'burpsuite-to-hdf',
      version: '1.0.0',
    },
    tool,
  };

  if (exportTime) {
    hdf.timestamp = parseTimestamp(exportTime) ?? undefined;
  }

  return serializeHdf(hdf);
}

// --- Build requirement ---

function buildRequirement(
  issueType: string,
  issues: BurpIssueXml[],
): EvaluatedRequirement {
  const rep = issues[0]!;

  // Parse CWE IDs from vulnerabilityClassifications HTML
  const cweIDs = parseCWEIDs(rep.vulnerabilityClassifications ?? '');

  // Map CWE to NIST
  const nist = mapCWEToNIST(cweIDs, [...DEFAULT_STATIC_ANALYSIS_NIST_TAGS]);
  const cciTags = nistToCci(nist);

  // Build extra tags
  const extras: Record<string, unknown> = {};
  if (cweIDs.length > 0) {
    extras.cweid = cweIDs.join(', ');
  }
  if (rep.confidence) {
    extras.confidence = rep.confidence;
  }
  const tags = buildNistCciTags(nist, cciTags, Object.keys(extras).length > 0 ? extras : undefined);

  // Build descriptions
  const descriptions: Description[] = [];

  // Default description (required minimum 1 with "default" label)
  const defaultData = rep.issueBackground
    ? stripHTML(rep.issueBackground)
    : (rep.name ?? issueType);
  descriptions.push({ label: 'default', data: defaultData });

  // Check description from issueBackground
  if (rep.issueBackground) {
    descriptions.push({ label: 'check', data: stripHTML(rep.issueBackground) });
  }

  // Fix description from remediationBackground
  if (rep.remediationBackground) {
    descriptions.push({ label: 'fix', data: stripHTML(rep.remediationBackground) });
  }

  // Build results — one per issue in the group
  const results: RequirementResult[] = issues.map(issue => {
    const codeDesc = formatCodeDesc(
      issue.host?.ip ?? '',
      (issue.host?.['#text'] ?? '').trim(),
      issue.location ?? '',
      issue.issueDetail ?? '',
      issue.confidence ?? '',
    );
    return {
      status: ResultStatus.Failed,
      codeDesc,
      startTime: new Date('0001-01-01T00:00:00Z'),
    };
  });

  const impact = getImpact(rep.severity ?? 'information');

  const req: EvaluatedRequirement = {
    id: issueType,
    title: rep.name ?? undefined,
    impact,
    tags,
    descriptions,
    results,
    verificationMethod: VerificationMethodEnum.Automated,
  };

  const controlType = deriveControlTypeFromTags(nist);
  if (controlType !== undefined) {
    req.controlType = controlType;
  }

  return req;
}
