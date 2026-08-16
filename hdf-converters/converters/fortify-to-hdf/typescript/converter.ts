import { parseXml, parseTimestamp, roundImpact } from '@mitre/hdf-utilities';
import { nistToCci } from '@mitre/hdf-mappings';
import {
  buildNoFindingsRequirement,
  deriveControlTypeFromTags,
  inputChecksum,
  buildNistCciTags,
  mapCWEToNIST,
  limitArray,
  markUnratedSeverity,
  stripHTML,
  ensureArray,
  DEFAULT_STATIC_ANALYSIS_NIST_TAGS,
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
  Reference,
  SourceLocation,
} from '@mitre/hdf-schema';
import {
  ResultStatus,
  TargetType,
  VerificationMethodEnum,
  createMinimalBaseline,
} from '@mitre/hdf-schema';

// NIST 800-53 reference name used by Fortify in Description.References
const NIST_REFERENCE_NAME =
  'Standards Mapping - NIST Special Publication 800-53 Revision 4';

// CWE reference name used by Fortify in Description.References
const CWE_REFERENCE_NAME =
  'Standards Mapping - Common Weakness Enumeration';

// Regex to match NIST control identifiers like SI-10, AC-2
const NIST_PATTERN = /[a-zA-Z]{2}-\d+/g;

// Regex to match the numeric CWE IDs in a title like "CWE ID 22, CWE ID 73"
const CWE_ID_PATTERN = /\d+/g;

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
  Tips?: {
    Tip?: string | string[];
  };
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

const NAMED_ENTITIES: Record<string, string> = {
  lt: '<',
  gt: '>',
  quot: '"',
  apos: "'",
  amp: '&',
};

// FVDL stores its description markup entity-escaped, and the shared XML parser
// leaves entities encoded (processEntities is off as XXE defense-in-depth), so the
// markup must be decoded before stripHTML can see it — this is what Go's XML
// decoder does for free. Only the predefined and numeric character references are
// decoded; document-defined entities stay untouched.
function decodeXmlEntities(s: string): string {
  return s.replace(
    /&(?:#(\d+)|#[xX]([0-9a-fA-F]+)|(lt|gt|quot|apos|amp));/g,
    (match, dec: string | undefined, hex: string | undefined, name: string | undefined) => {
      if (dec !== undefined) return String.fromCodePoint(Number.parseInt(dec, 10));
      if (hex !== undefined) return String.fromCodePoint(Number.parseInt(hex, 16));
      return name !== undefined ? NAMED_ENTITIES[name] ?? match : match;
    },
  );
}

function stripFvdlMarkup(s: string): string {
  return stripHTML(decodeXmlEntities(s));
}

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

// Pull CWE identifiers from the Common Weakness Enumeration reference, returning
// them in "CWE-NN" form (e.g. ["CWE-22","CWE-73"]).
function extractCWEFromReferences(refs: FVDLReference[]): string[] {
  for (const ref of refs) {
    if (ref.Author === CWE_REFERENCE_NAME) {
      const matches = ref.Title?.match(CWE_ID_PATTERN);
      if (matches && matches.length > 0) {
        return matches.map(m => `CWE-${m}`);
      }
    }
  }
  return [];
}

// Append the NIST controls implied by cweIDs to the native NIST tags, preserving
// native order and skipping duplicates.
function mergeCweNist(nist: string[], cweIDs: string[]): string[] {
  const merged = [...nist];
  for (const ctrl of mapCWEToNIST(cweIDs, [])) {
    if (!merged.includes(ctrl)) {
      merged.push(ctrl);
    }
  }
  return merged;
}

// Strip markup from each <Tip> and join the non-empty tips into a single
// description body. Returns '' when there are no usable tips.
function buildTipsData(tips: string[]): string {
  const parts: string[] = [];
  for (const tip of tips) {
    const text = stripFvdlMarkup(tip);
    if (text) parts.push(text);
  }
  return parts.join('\n\n');
}

// Reports whether s is an http(s) URL.
function isExternalURL(s: string): boolean {
  return s.startsWith('http://') || s.startsWith('https://');
}

// Emit one Reference{url} per distinct external URL carried in a Description's
// References (<Source> element), preserving first-seen order. Returns undefined
// when no reference carries an external URL.
function buildRefs(refs: FVDLReference[]): Reference[] | undefined {
  const hdfRefs: Reference[] = [];
  const seen = new Set<string>();
  for (const ref of refs) {
    const url = (ref.Source ?? '').trim();
    if (!isExternalURL(url)) continue;
    if (seen.has(url)) continue;
    seen.add(url);
    hdfRefs.push({ url });
  }
  return hdfRefs.length > 0 ? hdfRefs : undefined;
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

// requirement.code = raw source snippet from the representative finding's
// primary trace (Heimdall CODE tab). Returns undefined when no snippet exists.
function buildRequirementCode(
  vulns: FVDLVulnerability[],
  snippetMap: Map<string, FVDLSnippet>,
): string | undefined {
  if (vulns.length === 0) return undefined;

  const parts: string[] = [];
  const entries = ensureArray(vulns[0]!.AnalysisInfo?.Unified?.Trace?.Primary?.Entry);
  for (const entry of entries) {
    if (!entry.Node) continue;
    const snippetID = entry.Node.SourceLocation?.snippet;
    if (!snippetID) continue;
    const snippet = snippetMap.get(snippetID);
    if (!snippet) continue;
    const text = (snippet.Text ?? '').trim();
    if (text) parts.push(text);
  }

  if (parts.length === 0) return undefined;
  return parts.join('\n');
}

// requirement.sourceLocation = machine-addressable file/line locus of the
// representative finding, promoted from the primary trace's first node carrying
// a path (the default/sink node in every observed FVDL). Line is a number,
// omitted when the source line is absent or non-numeric. Returns undefined when
// no trace node carries a path.
function buildSourceLocation(
  vulns: FVDLVulnerability[],
): SourceLocation | undefined {
  if (vulns.length === 0) return undefined;
  const entries = ensureArray(vulns[0]!.AnalysisInfo?.Unified?.Trace?.Primary?.Entry);
  for (const entry of entries) {
    const path = entry.Node?.SourceLocation?.path;
    if (!path) continue;
    const sl: SourceLocation = { ref: path };
    const lineStr = entry.Node?.SourceLocation?.line;
    if (lineStr !== undefined && lineStr !== '') {
      const line = Number(lineStr);
      if (!Number.isNaN(line)) sl.line = line;
    }
    return sl;
  }
  return undefined;
}

// Copy the Fortify ClassInfo categorization from the representative finding into
// tags. Keys: kingdom (Seven Pernicious Kingdoms), class_type (vulnerability
// class — "class_type" avoids colliding with any generic "type" tag), subtype,
// analyzer. Absent source fields are omitted.
function addClassInfoTags(
  tags: Record<string, unknown>,
  vulns: FVDLVulnerability[],
): void {
  if (vulns.length === 0) return;
  const ci = vulns[0]!.ClassInfo;
  if (ci?.Kingdom) tags.kingdom = ci.Kingdom;
  if (ci?.Type) tags.class_type = ci.Type;
  if (ci?.Subtype) tags.subtype = ci.Subtype;
  if (ci?.AnalyzerName) tags.analyzer = ci.AnalyzerName;
}

function buildRequirement(
  desc: FVDLDescription,
  vulns: FVDLVulnerability[],
  snippetMap: Map<string, FVDLSnippet>,
  startTimeStr: string,
): EvaluatedRequirement {
  // Extract NIST tags from Description References, then merge in the NIST
  // controls implied by the CWE mapping so tags.nist reflects both sources.
  const refs = ensureArray(desc.References?.Reference);
  const cweIDs = extractCWEFromReferences(refs);
  let nistTags = mergeCweNist(extractNISTFromReferences(refs), cweIDs);
  if (nistTags.length === 0) {
    nistTags = [...DEFAULT_STATIC_ANALYSIS_NIST_TAGS];
  }
  const cciTags = nistToCci(nistTags);
  const tags = buildNistCciTags(nistTags, cciTags);

  // Surface the Fortify ClassInfo categorization (Seven Pernicious Kingdoms
  // category, vulnerability class/subtype, analyzer) from the representative
  // finding. These are parsed but were otherwise dropped. Emit each only when
  // present in the source.
  addClassInfoTags(tags, vulns);

  // Title from Abstract (HTML stripped)
  const title = stripFvdlMarkup(desc.Abstract ?? '');

  // Default description from Explanation (HTML stripped)
  let explanationText = stripFvdlMarkup(desc.Explanation ?? '');
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
      data: stripFvdlMarkup(desc.Recommendations),
    });
  }

  // Tips description from the Description's <Tips><Tip> guidance text.
  const tipsData = buildTipsData(ensureArray(desc.Tips?.Tip));
  if (tipsData) {
    descriptions.push({ label: 'tips', data: tipsData });
  }

  // Impact from the representative instance's per-instance severity / 5.
  // Fortify's InstanceSeverity is numeric on a 1.0-5.0 scale; zero means the
  // attribute was absent, i.e. the finding carries no rating at all.
  // A non-numeric value parses to NaN (where Go hard-errors during unmarshal);
  // guard so impact stays schema-valid: anything not a positive number is 0.0
  // and lands in the unrated branch below.
  const instanceSeverity = parseFloat(vulns[0]?.InstanceInfo?.InstanceSeverity ?? '0');
  const impact = instanceSeverity > 0 ? roundImpact(instanceSeverity / 5.0) : 0;
  if (!(instanceSeverity > 0)) {
    markUnratedSeverity(tags, '');
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
    startTime: parseTimestamp(startTimeStr) ?? new Date(),
  }));

  const req: EvaluatedRequirement = {
    id: desc.classID ?? 'unknown',
    title,
    impact,
    tags,
    descriptions,
    results,
    verificationMethod: VerificationMethodEnum.Automated,
  };

  if (cweIDs.length > 0) {
    req.cwe = cweIDs;
  }

  // External reference links from Description References (<Source> URL).
  const refsList = buildRefs(refs);
  if (refsList !== undefined) {
    req.refs = refsList;
  }

  const controlType = deriveControlTypeFromTags(nistTags);
  if (controlType !== undefined) {
    req.controlType = controlType;
  }

  const code = buildRequirementCode(vulns, snippetMap);
  if (code !== undefined) {
    req.code = code;
  }

  const sourceLocation = buildSourceLocation(vulns);
  if (sourceLocation !== undefined) {
    req.sourceLocation = sourceLocation;
  }

  return req;
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
export async function convertFortifyToHdf(input: string, converterVersion = '1.0.0'): Promise<string> {
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

  const targetName = fvdl.Build?.SourceBasePath ?? fvdl.Build?.BuildID ?? 'Unknown';

  if (requirements.length === 0) {
    requirements.push(buildNoFindingsRequirement(
      'fortify-no-findings',
      `Fortify scanned ${targetName} and reported zero findings.`,
      new Date(),
    ));
  }

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

  const tool: Tool = {
    name: 'Fortify',
    format: 'FVDL',
  };

  const hdfResult: HDFResults = {
    baselines: [baseline],
    components: [
      {
        name: targetName,
        type: TargetType.Repository,
      },
    ],
    generator: {
      name: 'fortify-to-hdf',
      version: converterVersion,
    },
    tool,
  };

  // Set timestamp from CreatedTS
  if (createdDate) {
    hdfResult.timestamp = parseTimestamp(startTimeStr) ?? new Date();
  }

  return serializeHdf(hdfResult);
}
