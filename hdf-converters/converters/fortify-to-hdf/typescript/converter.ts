import { parseXml } from '@mitre/hdf-utilities';
import { nistToCci } from '@mitre/hdf-mappings';
import {
  inputChecksum,
  buildNistCciTags,
  limitArray,
  stripHTML,
  ensureArray,
  DEFAULT_STATIC_ANALYSIS_NIST_TAGS,
  validateInputSize,
} from '../../../shared/typescript/converterutil.js';
import type {
  HdfResults,
  EvaluatedBaseline,
  EvaluatedRequirement,
  RequirementResult,
  Checksum,
  DataSource,
  Description,
} from '@mitre/hdf-schema';
import {
  ResultStatus,
  Copyright,
  createMinimalBaseline,
} from '@mitre/hdf-schema';

// NIST 800-53 reference name used by Fortify in Description.References
const NIST_REFERENCE_NAME =
  'Standards Mapping - NIST Special Publication 800-53 Revision 4';


// Regex to match NIST control identifiers like SI-10, AC-2
const NIST_PATTERN = /[a-zA-Z]{2}-\d+/g;

// --- FVDL XML types ---

interface FVDLParsed {
  FVDL: {
    CreatedTS?: { date?: string; time?: string };
    UUID?: string;
    Build?: {
      BuildID?: string;
      NumberFiles?: string;
      SourceBasePath?: string;
    };
    Vulnerabilities?: {
      Vulnerability?: FVDLVulnerability | FVDLVulnerability[];
    };
    Description?: FVDLDescription | FVDLDescription[];
    Snippets?: {
      Snippet?: FVDLSnippet | FVDLSnippet[];
    };
    EngineData?: {
      EngineVersion?: string;
    };
  };
}

interface FVDLVulnerability {
  ClassInfo?: {
    ClassID?: string;
    Kingdom?: string;
    Type?: string;
    Subtype?: string;
    AnalyzerName?: string;
    DefaultSeverity?: string;
  };
  InstanceInfo?: {
    InstanceID?: string;
    InstanceSeverity?: string;
    Confidence?: string;
  };
  AnalysisInfo?: {
    Unified?: {
      Trace?: {
        Primary?: {
          Entry?: FVDLEntry | FVDLEntry[];
        };
      };
    };
  };
}

interface FVDLEntry {
  NodeRef?: { id?: string };
  Node?: {
    isDefault?: string;
    SourceLocation?: {
      path?: string;
      line?: string;
      lineEnd?: string;
      colStart?: string;
      colEnd?: string;
      contextId?: string;
      snippet?: string;
    };
  };
}

interface FVDLDescription {
  classID?: string;
  contentType?: string;
  Abstract?: string;
  Explanation?: string;
  Recommendations?: string;
  References?: {
    Reference?: FVDLReference | FVDLReference[];
  };
}

interface FVDLReference {
  Title?: string;
  Author?: string;
  Publisher?: string;
  Source?: string;
}

interface FVDLSnippet {
  id?: string;
  File?: string;
  StartLine?: string;
  EndLine?: string;
  Text?: string;
}

// --- Helpers ---

function buildSnippetMap(snippets: FVDLSnippet[]): Map<string, FVDLSnippet> {
  const map = new Map<string, FVDLSnippet>();
  for (const s of snippets) {
    if (s.id) {
      map.set(s.id, s);
    }
  }
  return map;
}

function groupVulnsByClassID(vulns: FVDLVulnerability[]): Map<string, FVDLVulnerability[]> {
  const groups = new Map<string, FVDLVulnerability[]>();
  for (const vuln of vulns) {
    const classID = vuln.ClassInfo?.ClassID ?? 'unknown';
    const existing = groups.get(classID);
    if (existing) {
      existing.push(vuln);
    } else {
      groups.set(classID, [vuln]);
    }
  }
  return groups;
}

function extractNISTFromReferences(refs: FVDLReference[]): string[] {
  for (const ref of refs) {
    if (ref.Author === NIST_REFERENCE_NAME) {
      const matches = ref.Title?.match(NIST_PATTERN);
      if (matches && matches.length > 0) {
        return matches;
      }
    }
  }
  return [];
}

function formatSnippet(snippet: FVDLSnippet): string {
  const text = (snippet.Text ?? '').trim();
  return `Path: ${snippet.File ?? ''}\nStartLine: ${snippet.StartLine ?? ''}, EndLine: ${snippet.EndLine ?? ''}\nCode:\n${text}`;
}

function buildCodeDesc(
  vuln: FVDLVulnerability,
  snippetMap: Map<string, FVDLSnippet>,
): string {
  const parts: string[] = [];
  const entries = ensureArray(vuln.AnalysisInfo?.Unified?.Trace?.Primary?.Entry);

  for (const entry of entries) {
    if (!entry.Node) continue;

    const snippetID = entry.Node.SourceLocation?.snippet;
    if (!snippetID) {
      const path = entry.Node.SourceLocation?.path;
      const line = entry.Node.SourceLocation?.line;
      if (path) {
        parts.push(`Path: ${path}\nLine: ${line ?? ''}`);
      }
      continue;
    }

    const snippet = snippetMap.get(snippetID);
    if (snippet) {
      parts.push(formatSnippet(snippet));
    }
  }

  if (parts.length === 0) {
    return `ClassID: ${vuln.ClassInfo?.ClassID ?? ''}, InstanceID: ${vuln.InstanceInfo?.InstanceID ?? ''}`;
  }

  return parts.join('\n');
}

function buildRequirement(
  desc: FVDLDescription,
  vulns: FVDLVulnerability[],
  snippetMap: Map<string, FVDLSnippet>,
  startTimeStr: string,
): EvaluatedRequirement {
  // Extract NIST tags from Description References
  const refs = ensureArray(desc.References?.Reference);
  let nistTags = extractNISTFromReferences(refs);
  if (nistTags.length === 0) {
    nistTags = [...DEFAULT_STATIC_ANALYSIS_NIST_TAGS];
  }
  const cciTags = nistToCci(nistTags);
  const tags = buildNistCciTags(nistTags, cciTags);

  // Title from Abstract (HTML stripped)
  const title = stripHTML(desc.Abstract ?? '');

  // Default description from Explanation (HTML stripped)
  let explanationText = stripHTML(desc.Explanation ?? '');
  if (!explanationText) {
    explanationText = title;
  }
  const descriptions: Description[] = [
    { label: 'default', data: explanationText },
  ];

  // Fix description from Recommendations
  if (desc.Recommendations) {
    descriptions.push({
      label: 'fix',
      data: stripHTML(desc.Recommendations),
    });
  }

  // Impact from the first vulnerability's DefaultSeverity / 5
  let impact = 0;
  if (vulns.length > 0) {
    const severity = parseFloat(vulns[0]!.ClassInfo?.DefaultSeverity ?? '0');
    impact = severity / 5.0;
  }

  // Build results — one per vulnerability instance
  const { items: limitedVulns, truncated } = limitArray(vulns);
  /* v8 ignore next -- truncation only triggers with >100K items */
  if (truncated) {
    // eslint-disable-next-line no-console
    console.warn(`WARNING: Input truncated at ${limitedVulns.length} vulnerability items (original: ${vulns.length})`);
  }

  const results: RequirementResult[] = limitedVulns.map(vuln => ({
    status: ResultStatus.Failed,
    codeDesc: buildCodeDesc(vuln, snippetMap),
    startTime: new Date(startTimeStr),
  }));

  return {
    id: desc.classID ?? 'unknown',
    title,
    impact,
    tags,
    descriptions,
    results,
  };
}

// --- Main converter ---

/**
 * Converts Fortify FVDL XML to HDF format.
 *
 * Descriptions are used as requirements (one per unique classID).
 * Vulnerabilities are mapped to results under their corresponding Description.
 * Snippets provide code context for result code descriptions.
 *
 * @param input - Fortify FVDL XML string
 * @returns HDF JSON string
 */
export async function convertFortifyToHdf(input: string): Promise<string> {
  if (!input || input.trim().length === 0) {
    throw new Error('fortify: empty input');
  }
  validateInputSize(input, 'fortify');

  const resultsChecksum: Checksum = await inputChecksum(input);

  // Parse FVDL XML — use stopNodes to preserve embedded HTML in Abstract/Explanation
  const parsed = parseXml(input, {
    stopNodes: ['FVDL.Description.Abstract', 'FVDL.Description.Explanation'],
  }) as unknown as FVDLParsed;

  if (!parsed.FVDL) {
    throw new Error('fortify: invalid FVDL — missing <FVDL> root element');
  }

  const fvdl = parsed.FVDL;

  // Build snippet map
  const snippets = ensureArray(fvdl.Snippets?.Snippet);
  const snippetMap = buildSnippetMap(snippets);

  // Get vulnerabilities grouped by ClassID
  const vulns = ensureArray(fvdl.Vulnerabilities?.Vulnerability);
  const vulnGroups = groupVulnsByClassID(vulns);

  // Get descriptions
  const descriptions = ensureArray(fvdl.Description);
  const { items: limitedDescs, truncated: truncatedDescs } = limitArray(descriptions);
  /* v8 ignore next -- truncation only triggers with >100K items */
  if (truncatedDescs) {
    // eslint-disable-next-line no-console
    console.warn(`WARNING: Input truncated at ${limitedDescs.length} Description items (original: ${descriptions.length})`);
  }

  // Build timestamp string from CreatedTS
  const createdDate = fvdl.CreatedTS?.date ?? '';
  const createdTime = fvdl.CreatedTS?.time ?? '';
  const startTimeStr = `${createdDate}T${createdTime}`;

  // Build requirements — one per Description classID
  const requirements: EvaluatedRequirement[] = limitedDescs.map(desc => {
    const classVulns = vulnGroups.get(desc.classID ?? '') ?? [];
    return buildRequirement(desc, classVulns, snippetMap, startTimeStr);
  });

  // Build baseline
  const title = 'Fortify Static Analyzer Scan';
  const summary = `Fortify Static Analyzer Scan of UUID: ${fvdl.UUID ?? ''}`;
  const version = fvdl.EngineData?.EngineVersion ?? '';

  const baseline: EvaluatedBaseline = createMinimalBaseline(
    'Fortify Scan',
    requirements,
    {
      resultsChecksum,
      title,
      summary,
      version,
      status: 'loaded',
    },
  ) as EvaluatedBaseline;

  // Target name from SourceBasePath
  const targetName = fvdl.Build?.SourceBasePath ?? fvdl.Build?.BuildID ?? 'Unknown';

  const dataSource: DataSource = {
    name: 'Fortify',
    format: 'FVDL',
  };

  const hdfResult: HdfResults = {
    baselines: [baseline],
    targets: [
      {
        name: targetName,
        type: Copyright.Repository,
      },
    ],
    generator: {
      name: 'fortify-to-hdf',
      version: '1.0.0',
    },
    dataSource,
  };

  // Set timestamp from CreatedTS
  if (createdDate) {
    hdfResult.timestamp = new Date(startTimeStr);
  }

  return JSON.stringify(hdfResult, null, 2);
}
