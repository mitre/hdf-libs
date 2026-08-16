import { parseJSON, parseTimestamp, formatTimestamp } from '@mitre/hdf-utilities';
import {
  DEFAULT_STATIC_ANALYSIS_NIST_TAGS,
  nistToCci,
} from '@mitre/hdf-mappings';
import { buildNoFindingsRequirement, deriveControlTypeFromTags, inputChecksum, buildNistCciTags, validateInputSize, buildHdfResults } from '../../../shared/typescript/converterutil.js';
import type {
  EvaluatedBaseline,
  EvaluatedRequirement,
  Checksum,
  RequirementResult,
} from '@mitre/hdf-schema';
import {
  ResultStatus,
  createResult,
  TargetType,
  VerificationMethodEnum,
  createMinimalBaseline,
  createRequirement,
  type Description,
} from '@mitre/hdf-schema';

/** Maximum Conveyor score (used for normalization). */
const CONVEYOR_MAX_SCORE = 1000;

/** Top-level Conveyor JSON output structure. */
interface ConveyorData {
  api_error_message?: string;
  api_response?: ConveyorAPIResp;
  api_server_version?: string;
}

interface ConveyorAPIResp {
  file_tree?: Record<string, FileTreeNode>;
  results?: Record<string, ConveyorResult>;
  params?: Record<string, unknown>;
  times?: ConveyorTimes;
  max_score?: number;
}

interface ConveyorTimes {
  completed?: string;
  submitted?: string;
}

interface FileTreeNode {
  name?: string[];
  sha256?: string;
  children?: Record<string, FileTreeNode>;
  score?: number;
  size?: number;
  type?: string;
}

interface ConveyorResult {
  sha256: string;
  classification?: string;
  created?: string;
  expiry_ts?: string;
  response: ConveyorResp;
  result: ConveyorScore;
  size?: number | null;
  type?: string | null;
}

interface ConveyorResp {
  service_name: string;
  service_version?: string;
  service_context?: unknown;
  service_debug_info?: unknown;
  service_tool_version?: unknown;
  supplementary?: unknown;
  milestones?: ConveyorMilestone;
}

interface ConveyorMilestone {
  service_started?: string;
  service_completed?: string;
}

interface ConveyorScore {
  score: number;
  sections: ConveyorSection[];
}

interface ConveyorSection {
  title_text?: string;
  body?: unknown;
  body_format?: string;
  classification?: string;
  depth?: number;
  heuristic?: Heuristic | null;
}

interface Heuristic {
  heur_id?: string;
  name?: string;
  score?: number;
}

/**
 * Recursively walks the file tree, collecting sha256 -> filename mappings.
 */
function collateSHAAndFilenames(tree: Record<string, FileTreeNode>): Map<string, string> {
  const result = new Map<string, string>();
  for (const [sha, node] of Object.entries(tree)) {
    if (node.name && node.name.length > 0) {
      result.set(sha, node.name[0]!);
    }
    if (node.children && Object.keys(node.children).length > 0) {
      for (const [childSha, childName] of collateSHAAndFilenames(node.children)) {
        result.set(childSha, childName);
      }
    }
  }
  return result;
}

/**
 * Maps a Conveyor score to an HDF result status.
 * Score 0 = Passed, non-zero = Failed.
 */
function determineStatus(score: number): ResultStatus {
  return score === 0 ? ResultStatus.Passed : ResultStatus.Failed;
}

/**
 * Normalizes a Conveyor score (0-1000) to HDF impact (0.0-1.0).
 */
function scoreToImpact(score: number): number {
  if (score <= 0) return 0.0;
  if (score >= CONVEYOR_MAX_SCORE) return 1.0;
  return score / CONVEYOR_MAX_SCORE;
}

/**
 * Extracts a string from a body field that may be null or a string.
 */
function bodyToString(body: unknown): string {
  if (body === null || body === undefined) return '';
  if (typeof body === 'string') return body;
  return String(body);
}

/**
 * Creates the code_desc field content from a Conveyor section.
 */
function buildCodeDesc(section: ConveyorSection, scannerName: string): string {
  const parts: string[] = [];

  if (scannerName === 'Moldy' || scannerName === 'Stigma' || scannerName === 'Clamav') {
    parts.push(`title_text:${section.title_text ?? ''}`);
    parts.push(`body:${bodyToString(section.body)}`);
    parts.push(`body_format:${section.body_format ?? ''}`);
    parts.push(`classification:${section.classification ?? ''}`);
    parts.push(`depth:${section.depth ?? 0}`);
    if (section.heuristic) {
      parts.push(`heuristic_heur_id:${section.heuristic.heur_id ?? ''}`);
      parts.push(`heuristic_score:${section.heuristic.score ?? 0}`);
      parts.push(`heuristic_name:${section.heuristic.name ?? ''}`);
    }
  } else if (scannerName === 'CodeQuality') {
    parts.push(`body:${bodyToString(section.body)}`);
    parts.push(`body_format:${section.body_format ?? ''}`);
    parts.push(`classification:${section.classification ?? ''}`);
    parts.push(`depth:${section.depth ?? 0}`);
    parts.push(`title_text:${section.title_text ?? ''}`);
  } else {
    return JSON.stringify(section);
  }

  return parts.join('\n');
}

/**
 * Groups Conveyor results by their service (scanner) name.
 */
function groupResultsByScanner(
  results: Record<string, ConveyorResult>,
): { scanners: string[]; groups: Map<string, ConveyorResult[]> } {
  const groups = new Map<string, ConveyorResult[]>();
  for (const result of Object.values(results)) {
    const name = result.response.service_name;
    const existing = groups.get(name);
    if (existing) {
      existing.push(result);
    } else {
      groups.set(name, [result]);
    }
  }
  const scanners = [...groups.keys()].sort();
  return { scanners, groups };
}

/**
 * Returns the scanner version to record as tool.version. Conveyor's
 * service_tool_version is null in observed output, so the value comes from
 * response.service_version. That version is per-scanner (it varies across
 * results), so the first entry in sorted result-key order is taken, matching the
 * Go side for deterministic Go/TS parity. Returns undefined when none is present.
 */
function firstServiceVersion(results: Record<string, ConveyorResult>): string | undefined {
  for (const key of Object.keys(results).sort()) {
    const version = results[key]!.response.service_version;
    if (version) return version;
  }
  return undefined;
}

/**
 * Elapsed seconds between a service's start and completion milestones, or
 * undefined when either is missing/unparseable.
 */
function computeRunTime(startedStr?: string, completedStr?: string): number | undefined {
  const started = startedStr ? parseTimestamp(startedStr) : null;
  const completed = completedStr ? parseTimestamp(completedStr) : null;
  if (!started || !completed) return undefined;
  return (completed.getTime() - started.getTime()) / 1000;
}

/**
 * Normalizes a Conveyor timestamp string to HDF's canonical trimmed-UTC RFC3339
 * form (millisecond precision), matching the Go converter byte-for-byte. Returns
 * undefined when the source is absent or unparseable so the caller can omit it.
 */
function canonicalTimestampTag(s?: string): string | undefined {
  const t = s ? parseTimestamp(s) : null;
  return t ? formatTimestamp(t) : undefined;
}

/**
 * Collects the tool-specific typed tags Conveyor carries per result
 * (created/classification/expiry_ts/size/type), omitting any the source leaves
 * null or empty. Timestamp tags are canonicalized so Go and TS agree.
 */
function scannerTagExtras(result: ConveyorResult): Record<string, unknown> {
  const extras: Record<string, unknown> = {};
  const created = canonicalTimestampTag(result.created);
  if (created) extras.created = created;
  if (result.classification) extras.classification = result.classification;
  const expiry = canonicalTimestampTag(result.expiry_ts);
  if (expiry) extras.expiry_ts = expiry;
  if (result.size != null) extras.size = result.size;
  if (typeof result.type === 'string' && result.type) extras.type = result.type;
  return extras;
}

/**
 * Builds an HDF requirement from a single Conveyor result.
 */
function buildRequirementFromResult(
  result: ConveyorResult,
  filename: string,
): EvaluatedRequirement {
  const nist = DEFAULT_STATIC_ANALYSIS_NIST_TAGS;
  const cciTags = nistToCci(nist);
  const extras = scannerTagExtras(result);
  const tags = buildNistCciTags([...nist], cciTags, Object.keys(extras).length > 0 ? extras : undefined);

  // Build description from sections
  let descText = '';
  if (result.result.sections.length > 0) {
    descText = result.result.sections
      .map(s => s.title_text ?? '')
      .filter(t => t.length > 0)
      .join('; ');
  }
  if (!descText) {
    descText = `Conveyor scan result for ${result.sha256}`;
  }

  const descriptions: Description[] = [
    { label: 'default', data: descText },
  ];

  const scannerName = result.response.service_name;
  // start_time is when the scan started (service_started); fall back to the zero
  // sentinel when the source omits it (mirrors Go's zero time.Time). run_time is
  // the scan's elapsed seconds (service_completed − service_started).
  const startTimeStr = result.response.milestones?.service_started ?? '';
  const startTime = (startTimeStr ? parseTimestamp(startTimeStr) : null) ?? new Date('0001-01-01T00:00:00Z');
  const runTime = computeRunTime(result.response.milestones?.service_started, result.response.milestones?.service_completed);
  const score = result.result.score;
  const status = determineStatus(score);

  // Conveyor carries no per-section explanation, so results carry no message key.
  const toResult = (codeDesc: string): RequirementResult => createResult(status, undefined, { codeDesc, startTime, runTime });

  const results = result.result.sections.length > 0
    ? result.result.sections.map(section => toResult(buildCodeDesc(section, scannerName)))
    : [toResult(`No sections reported by ${scannerName}`)];

  const req = createRequirement(
    result.sha256,
    filename,
    descriptions,
    scoreToImpact(score),
    results,
    { tags },
  ) as EvaluatedRequirement;
  req.verificationMethod = VerificationMethodEnum.Automated;

  const controlType = deriveControlTypeFromTags([...nist]);
  if (controlType !== undefined) {
    req.controlType = controlType;
  }

  return req;
}

/**
 * Builds an HDF baseline for a single scanner's results.
 */
function buildScannerBaseline(
  scannerName: string,
  results: ConveyorResult[],
  shaMap: Map<string, string>,
  resultsChecksum: Checksum,
): EvaluatedBaseline {
  const requirements: EvaluatedRequirement[] = results.map(result => {
    const filename = shaMap.get(result.sha256) ?? '';
    return buildRequirementFromResult(result, filename);
  });

  const title = `Conveyor Scan (${scannerName})`;

  return createMinimalBaseline(
    'Conveyor Scan',
    requirements,
    {
      resultsChecksum,
      title,
    },
  ) as EvaluatedBaseline;
}

/**
 * Converts Conveyor scan results to HDF format.
 * Results are grouped by scanner name, producing one baseline per scanner.
 *
 * @param input - Conveyor JSON string
 * @returns HDF JSON string
 */
export async function convertConveyorToHdf(input: string, converterVersion = '1.0.0'): Promise<string> {
  if (!input || input.trim().length === 0) {
    throw new Error('conveyor: empty input');
  }
  validateInputSize(input, 'conveyor');

  const data = parseJSON<ConveyorData>(input);

  if (!data || typeof data !== 'object') {
    throw new Error('conveyor: invalid JSON');
  }

  if (!data.api_response) {
    throw new Error('conveyor: missing api_response field');
  }

  if (!data.api_response.results) {
    throw new Error('conveyor: missing api_response.results field');
  }

  const resultsChecksum: Checksum = await inputChecksum(input);

  // Build SHA -> filename mapping from file tree
  const shaMap = data.api_response.file_tree
    ? collateSHAAndFilenames(data.api_response.file_tree)
    : new Map<string, string>();

  // Group results by scanner
  const { scanners, groups } = groupResultsByScanner(data.api_response.results);

  const baselines: EvaluatedBaseline[] = scanners.map(scannerName =>
    buildScannerBaseline(
      scannerName,
      groups.get(scannerName)!,
      shaMap,
      resultsChecksum,
    ),
  );

  // Build target name from params.description
  let targetName = 'Conveyor Scan';
  if (data.api_response.params) {
    const desc = data.api_response.params['description'];
    if (typeof desc === 'string' && desc.length > 0) {
      targetName = desc;
    }
  }

  if (baselines.length === 0) {
    baselines.push(createMinimalBaseline(
      'Conveyor Scan',
      [
        buildNoFindingsRequirement(
          'conveyor-no-findings',
          `Conveyor scanned ${targetName} and reported zero findings.`,
          new Date(),
        ),
      ],
      {
        resultsChecksum,
        title: 'Conveyor Scan (no findings)',
      },
    ) as EvaluatedBaseline);
  }

  // Prefer the submission's overall completion time; fall back to now() only
  // when the source omits it, so the document timestamp is source-anchored.
  const completedStr = data.api_response.times?.completed ?? '';
  const timestamp = (completedStr ? parseTimestamp(completedStr) : null) ?? new Date();

  return buildHdfResults({
    generatorName: 'conveyor-to-hdf',
    converterVersion,
    toolName: 'Conveyor',
    toolVersion: firstServiceVersion(data.api_response.results),
    baselines,
    components: [{ name: targetName, type: TargetType.Application }],
    timestamp,
  });
}
