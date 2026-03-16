import { parseJSON } from '@mitre/hdf-utilities';
import {
  DEFAULT_STATIC_ANALYSIS_NIST_TAGS,
  nistToCci,
} from '@mitre/hdf-mappings';
import { inputChecksum, buildNistCciTags, validateInputSize } from '../../../shared/typescript/converterutil.js';
import type {
  HdfResults,
  EvaluatedBaseline,
  EvaluatedRequirement,
  Checksum,
  DataSource,
} from '@mitre/hdf-schema';
import {
  ResultStatus,
  Copyright,
  createMinimalBaseline,
  createRequirement,
  createResult,
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
  max_score?: number;
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
 * Builds an HDF requirement from a single Conveyor result.
 */
function buildRequirementFromResult(
  result: ConveyorResult,
  filename: string,
): EvaluatedRequirement {
  const nist = DEFAULT_STATIC_ANALYSIS_NIST_TAGS;
  const cciTags = nistToCci(nist);
  const tags = buildNistCciTags(nist, cciTags);

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
  const startTimeStr = result.response.milestones?.service_started ?? '';
  const startTime = startTimeStr ? new Date(startTimeStr) : new Date();
  const score = result.result.score;
  const status = determineStatus(score);

  let results;
  if (result.result.sections.length > 0) {
    results = result.result.sections.map(section => {
      const codeDesc = buildCodeDesc(section, scannerName);
      return createResult(status, undefined, {
        codeDesc,
        startTime,
      });
    });
  } else {
    results = [
      createResult(status, undefined, {
        codeDesc: `No sections reported by ${scannerName}`,
        startTime,
      }),
    ];
  }

  return createRequirement(
    result.sha256,
    filename,
    descriptions,
    scoreToImpact(score),
    results,
    { tags },
  );
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
export async function convertConveyorToHdf(input: string): Promise<string> {
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

  const dataSource: DataSource = { name: 'Conveyor', format: 'JSON' };

  const hdf: HdfResults = {
    baselines,
    generator: {
      name: 'conveyor-to-hdf',
      version: '1.0.0',
    },
    dataSource,
    targets: [{ name: targetName, type: Copyright.Application }],
    timestamp: new Date(),
  };

  return JSON.stringify(hdf, null, 2);
}
