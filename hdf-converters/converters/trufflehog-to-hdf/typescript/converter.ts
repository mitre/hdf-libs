import { parseJSON } from '@mitre/hdf-utilities';
import { deriveControlTypeFromTags, inputChecksum, buildNistCciTags, limitArrayWithWarning, validateInputSize } from '../../../shared/typescript/converterutil.js';
import type {
  HdfResults,
  EvaluatedBaseline,
  EvaluatedRequirement,
  Tool,
  Description,
} from '@mitre/hdf-schema';
import {
  ResultStatus,
  Copyright,
  VerificationMethodEnum,
  createMinimalBaseline,
  createRequirement,
  createResult,
} from '@mitre/hdf-schema';

/**
 * TruffleHog finding structure.
 */
interface TrufflehogFinding {
  SourceMetadata?: SourceMetadata;
  SourceID?: number;
  SourceType?: number;
  SourceName?: string;
  DetectorType: number;
  DetectorName: string;
  DetectorDescription?: string;
  DecoderName: string;
  Verified: boolean;
  VerificationError?: string;
  Raw: string;
  RawV2?: string;
  Redacted: string;
  ExtraData?: Record<string, unknown> | null;
  StructuredData?: unknown;
}

interface SourceMetadata {
  Data: SourceData;
}

interface SourceData {
  Git?: GitSource;
  Filesystem?: FilesystemSource;
  Docker?: DockerSource;
}

interface GitSource {
  commit: string;
  file: string;
  email: string;
  repository: string;
  timestamp: string;
  line: number;
}

interface FilesystemSource {
  file: string;
  line: number;
}

interface DockerSource {
  image: string;
  file: string;
  line: number;
}

/** Hardcoded NIST/CCI constants for credential exposure findings. */
const TRUFFLEHOG_NIST = ['IA-5 (7)'];
const TRUFFLEHOG_CCI = ['CCI-000202', 'CCI-000203', 'CCI-002367'];

/**
 * Parse TruffleHog input as JSON array, single object, or NDJSON.
 */
function parseFindings(input: string): TrufflehogFinding[] {
  const trimmed = input.trim();

  // Try JSON array first
  try {
    const parsed = parseJSON<unknown>(trimmed);
    if (Array.isArray(parsed)) {
      return parsed as TrufflehogFinding[];
    }
    // Single JSON object
    if (typeof parsed === 'object' && parsed !== null && 'DetectorName' in parsed) {
      return [parsed as TrufflehogFinding];
    }
  } catch {
    // Not valid JSON — try NDJSON
  }

  // Try NDJSON: split on newlines, parse each line
  const lines = trimmed.split('\n').filter(line => line.trim().length > 0);
  const findings: TrufflehogFinding[] = [];
  for (const line of lines) {
    try {
      findings.push(parseJSON<TrufflehogFinding>(line.trim()));
    } catch {
      throw new Error(`trufflehog: failed to parse NDJSON line: ${line.substring(0, 80)}`);
    }
  }
  if (findings.length > 0) {
    return findings;
  }

  throw new Error('trufflehog: unable to parse input as JSON array, single object, or NDJSON');
}

/**
 * Group findings by DetectorName + DecoderName, preserving insertion order.
 */
function groupFindings(findings: TrufflehogFinding[]): Map<string, TrufflehogFinding[]> {
  const groups = new Map<string, TrufflehogFinding[]>();
  for (const f of findings) {
    const key = `${f.DetectorName} ${f.DecoderName}`;
    const existing = groups.get(key);
    if (existing) {
      existing.push(f);
    } else {
      groups.set(key, [f]);
    }
  }
  return groups;
}

/**
 * Build the Result.Message JSON from selected finding fields.
 */
function buildMessage(f: TrufflehogFinding): string {
  const msg: Record<string, unknown> = {
    Verified: f.Verified,
    Redacted: f.Redacted,
  };
  if (f.VerificationError) {
    msg.VerificationError = f.VerificationError;
  }
  if (f.ExtraData && Object.keys(f.ExtraData).length > 0) {
    msg.ExtraData = f.ExtraData;
  }
  return JSON.stringify(msg);
}

/**
 * Build the Result.CodeDesc as JSON of SourceMetadata.
 */
function buildCodeDesc(f: TrufflehogFinding): string {
  return JSON.stringify(f.SourceMetadata ?? {});
}

/**
 * Extract a timestamp from a finding's Git source metadata.
 */
function getTimestamp(f: TrufflehogFinding): Date {
  if (f.SourceMetadata?.Data?.Git?.timestamp) {
    const ts = new Date(f.SourceMetadata.Data.Git.timestamp);
    if (!isNaN(ts.getTime())) {
      return ts;
    }
  }
  return new Date();
}

/**
 * Get the source file path from any source type.
 */
function getSourceFile(f: TrufflehogFinding): string | undefined {
  return f.SourceMetadata?.Data?.Git?.file
    ?? f.SourceMetadata?.Data?.Filesystem?.file
    ?? f.SourceMetadata?.Data?.Docker?.file;
}

/**
 * Get the source line number from any source type.
 */
function getSourceLine(f: TrufflehogFinding): number | undefined {
  return f.SourceMetadata?.Data?.Git?.line
    ?? f.SourceMetadata?.Data?.Filesystem?.line
    ?? f.SourceMetadata?.Data?.Docker?.line;
}

/**
 * Find the first Git repository URL from findings.
 */
function findGitRepoURL(findings: TrufflehogFinding[]): string | undefined {
  for (const f of findings) {
    if (f.SourceMetadata?.Data?.Git?.repository) {
      return f.SourceMetadata.Data.Git.repository;
    }
  }
  return undefined;
}

/**
 * Build an EvaluatedRequirement from a group of findings sharing a detector.
 */
function buildRequirement(reqID: string, findings: TrufflehogFinding[]): EvaluatedRequirement {
  const rep = findings[0]!;
  const tags = buildNistCciTags(TRUFFLEHOG_NIST, TRUFFLEHOG_CCI);

  const title = `Found ${rep.DetectorName} secret using ${rep.DecoderName} decoder`;

  const descData = rep.DetectorDescription
    ?? `${rep.DetectorName} secret detected by ${rep.DecoderName} decoder`;
  const descriptions: Description[] = [
    { label: 'default', data: descData },
  ];

  const results = findings.map(f =>
    createResult(ResultStatus.Failed, buildMessage(f), {
      codeDesc: buildCodeDesc(f),
      startTime: getTimestamp(f),
    })
  );

  const sourceFile = getSourceFile(rep);
  const sourceLine = getSourceLine(rep);

  const req = createRequirement(
    reqID,
    title,
    descriptions,
    0.5,
    results,
    {
      tags,
      sourceLocation: sourceFile ? { ref: sourceFile, line: sourceLine } : undefined,
    }
  ) as EvaluatedRequirement;

  const controlType = deriveControlTypeFromTags(TRUFFLEHOG_NIST);
  if (controlType !== undefined) {
    req.controlType = controlType;
  }
  req.verificationMethod = VerificationMethodEnum.Automated;

  return req;
}

/**
 * Converts TruffleHog output to HDF format.
 * Accepts JSON array, single JSON object, or NDJSON input.
 *
 * @param input - TruffleHog JSON/NDJSON string
 * @returns HDF JSON string
 */
export async function convertTrufflehogToHdf(input: string): Promise<string> {
  if (!input || input.trim().length === 0) {
    throw new Error('trufflehog: empty input');
  }
  validateInputSize(input, 'trufflehog');

  const findings = parseFindings(input);
  if (findings.length === 0) {
    throw new Error('trufflehog: no findings in input');
  }

  const resultsChecksum = await inputChecksum(input);
  const limitedFindings = limitArrayWithWarning(findings, 'finding');

  const groups = groupFindings(limitedFindings);
  const requirements: EvaluatedRequirement[] = [];
  for (const [reqID, group] of groups) {
    requirements.push(buildRequirement(reqID, group));
  }

  const sourceName = limitedFindings[0]?.SourceName ?? 'trufflehog';
  const baselineTitle = `TruffleHog Scan (${sourceName})`;

  const baseline: EvaluatedBaseline = createMinimalBaseline(
    'TruffleHog Scan',
    requirements,
    {
      resultsChecksum,
      title: baselineTitle,
    }
  ) as EvaluatedBaseline;

  const tool: Tool = { name: 'TruffleHog', format: 'JSON' };

  const hdf: HdfResults = {
    baselines: [baseline],
    generator: {
      name: 'hdf-converters',
      version: '1.0.0',
    },
    tool,
    timestamp: new Date(),
  };

  // Add target only if a Git repository URL is available
  const repoURL = findGitRepoURL(limitedFindings);
  if (repoURL) {
    hdf.components = [{ name: repoURL, type: Copyright.Repository }];
  }

  return JSON.stringify(hdf, null, 2);
}
