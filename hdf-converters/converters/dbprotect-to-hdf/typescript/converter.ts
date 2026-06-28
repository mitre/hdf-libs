import { parseXmlWithArrays, parseTimestamp } from '@mitre/hdf-utilities';
import {
  DEFAULT_STATIC_ANALYSIS_NIST_TAGS,
  nistToCci,
} from '@mitre/hdf-mappings';
import { deriveControlTypeFromTags, inputChecksum, buildNistCciTags, limitArray, validateInputSize, buildHdfResults } from '../../../shared/typescript/converterutil.js';
import type {
  EvaluatedBaseline,
  EvaluatedRequirement,
  Checksum,
  Description,
} from '@mitre/hdf-schema';
import {
  ResultStatus,
  TargetType,
  VerificationMethodEnum,
  createMinimalBaseline,
  createRequirement,
  createResult,
} from '@mitre/hdf-schema';

/** Impact mapping from heimdall2 DBProtect mapper */
const IMPACT_MAPPING: Record<string, number> = {
  high: 0.7,
  medium: 0.5,
  low: 0.3,
  informational: 0.0,
};

/** Parsed DBProtect XML dataset structure */
interface DatasetXml {
  dataset: {
    metadata: {
      item: MetadataItem[];
    };
    data: {
      row: DataRow[];
    };
  };
}

interface MetadataItem {
  name: string;
  type: string;
}

interface DataRow {
  value: Array<string | { nil: string } | null>;
}

/** A single compiled finding, mapping column names to string values */
type Finding = Record<string, string>;

/**
 * Maps metadata column names to row values by position index.
 * Mirrors the heimdall2 compileFindings function.
 */
function compileFindings(parsed: DatasetXml): Finding[] {
  const items = parsed.dataset.metadata.item;
  const rows = parsed.dataset.data.row;

  const colNames = items.map((item: MetadataItem) => item['name']);

  return rows.map((row: DataRow) => {
    const finding: Finding = {};
    const values = row.value;
    colNames.forEach((name: string, i: number) => {
      const val = values[i];
      if (val === null || val === undefined || typeof val === 'object') {
        finding[name] = '';
      } else {
        finding[name] = String(val);
      }
    });
    return finding;
  });
}

/** Check if the dataset has a "Result Status" column */
function hasResultStatusColumn(parsed: DatasetXml): boolean {
  return parsed.dataset.metadata.item.some(
    (item: MetadataItem) => item['name'] === 'Result Status',
  );
}

/** Maps DBProtect result status strings to HDF ResultStatus */
function getStatus(status: string): ResultStatus {
  switch (status) {
    case 'Fact':
      return ResultStatus.NotReviewed;
    case 'Failed':
      return ResultStatus.Failed;
    case 'Finding':
      return ResultStatus.Failed;
    case 'Not A Finding':
      return ResultStatus.Passed;
    default:
      // Includes "Skipped" and any unknown status
      return ResultStatus.NotReviewed;
  }
}

/** Maps DBProtect risk level to HDF impact value */
function getImpact(riskDV: string): number {
  const impact = IMPACT_MAPPING[riskDV.toLowerCase()];
  return impact !== undefined ? impact : 0.5;
}

/** Creates a description string from a finding's task and check category */
function formatDesc(f: Finding): string {
  return `Task : ${f['Task'] ?? ''}; Check Category : ${f['Check Category'] ?? ''}`;
}

/** Creates a summary string from a finding's metadata */
function formatSummary(f: Finding): string {
  return [
    `Organization : ${f['Organization'] ?? ''}`,
    `Asset : ${f['Asset'] ?? ''}`,
    `Asset Type : ${f['Asset Type'] ?? ''}`,
    `IP Address, Port, Instance : ${f['IP Address, Port, Instance'] ?? ''}`,
  ].join('\n');
}

const MONTH_ABBR: Record<string, string> = {
  Jan: '01', Feb: '02', Mar: '03', Apr: '04', May: '05', Jun: '06',
  Jul: '07', Aug: '08', Sep: '09', Oct: '10', Nov: '11', Dec: '12',
};

/**
 * Parses DBProtect date formats ("Feb 18 2021 15:57" or "2021-02-18 15:55").
 * Month-name values are normalized to ISO so parseTimestamp interprets them as
 * UTC, matching the Go peer and keeping output host-timezone-independent.
 */
function parseDate(dateStr: string): Date {
  const trimmed = dateStr.trim();
  if (!trimmed) {
    return new Date();
  }
  const month = /^([A-Z][a-z]{2}) (\d{1,2}) (\d{4}) (\d{2}:\d{2})$/.exec(trimmed);
  const normalized = month
    ? `${month[3]}-${MONTH_ABBR[month[1]!] ?? '00'}-${month[2]!.padStart(2, '0')} ${month[4]}`
    : trimmed;
  return parseTimestamp(normalized) ?? new Date();
}

/**
 * Builds a single EvaluatedRequirement from a group of findings sharing a Check ID.
 */
function buildRequirement(
  checkID: string,
  findings: Finding[],
  hasStatus: boolean,
): EvaluatedRequirement {
  const rep = findings[0]!;

  const nist = DEFAULT_STATIC_ANALYSIS_NIST_TAGS;
  const cciTags = nistToCci(nist);
  const tags = buildNistCciTags(nist, cciTags);

  const descriptions: Description[] = [
    { label: 'default', data: formatDesc(rep) },
  ];

  const results = findings.map((f) => {
    const status = hasStatus
      ? getStatus(f['Result Status'] ?? '')
      : ResultStatus.Failed;

    return createResult(status, undefined, {
      codeDesc: f['Details'] ?? '',
      startTime: parseDate(f['Date'] ?? ''),
    });
  });

  const req = createRequirement(
    checkID,
    rep['Check'] ?? '',
    descriptions,
    getImpact(rep['Risk DV'] ?? ''),
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
 * Converts DBProtect Cognos XML output to HDF format.
 * Supports both "Check Results Details" (has Result Status) and "Findings Detail"
 * (no Result Status; all rows are findings) report formats.
 *
 * @param input - DBProtect XML string
 * @returns HDF JSON string
 */
export async function convertDbprotectToHdf(input: string): Promise<string> {
  if (!input || input.trim().length === 0) {
    throw new Error('dbprotect: empty input');
  }
  validateInputSize(input, 'dbprotect');

  const resultsChecksum: Checksum = await inputChecksum(input);

  const parsed = parseXmlWithArrays(input, ['item', 'row', 'value']) as unknown as DatasetXml;

  if (!parsed?.dataset?.data?.row || parsed.dataset.data.row.length === 0) {
    throw new Error('dbprotect: no data rows found');
  }

  const findings = compileFindings(parsed);
  const { items: limitedFindings, truncated } = limitArray(findings);
  /* v8 ignore next -- truncation only triggers with >100K items */
  if (truncated) {
    // eslint-disable-next-line no-console
    console.warn(
      `WARNING: Input truncated at ${limitedFindings.length} finding items (original: ${findings.length})`,
    );
  }

  const hasStatus = hasResultStatusColumn(parsed);

  // Group findings by Check ID, preserving insertion order
  const groups = new Map<string, Finding[]>();
  for (const f of limitedFindings) {
    const checkID = (f['Check ID'] ?? '').trim();
    const existing = groups.get(checkID);
    if (existing) {
      existing.push(f);
    } else {
      groups.set(checkID, [f]);
    }
  }

  const requirements: EvaluatedRequirement[] = [];
  for (const [checkID, findingGroup] of groups) {
    requirements.push(buildRequirement(checkID, findingGroup, hasStatus));
  }

  // Use first finding for metadata
  const firstFinding = limitedFindings[0]!;
  const title = firstFinding['Job Name'] ?? '';
  const summary = formatSummary(firstFinding);
  const targetName = firstFinding['Asset'] ?? '';

  const baseline = createMinimalBaseline('DBProtect Scan', requirements, {
    resultsChecksum,
    title,
    summary,
  }) as EvaluatedBaseline;

  return buildHdfResults({
    generatorName: 'dbprotect-to-hdf',
    converterVersion: '1.0.0',
    toolName: 'DBProtect',
    toolFormat: 'XML',
    baselines: [baseline],
    components: [{ name: targetName, type: TargetType.Host }],
    timestamp: new Date(),
  });
}
