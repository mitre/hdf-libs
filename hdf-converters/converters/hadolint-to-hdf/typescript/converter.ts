/**
 * hadolint Dockerfile linter output to HDF.
 *
 * hadolint's JSON formatter emits a bare array of flat findings, each carrying
 * only code, column, file, level, line and message. One requirement is produced
 * per distinct rule code and one result per finding, so a rule that fires on
 * several lines keeps every occurrence.
 *
 * Twin of go/converter.go.
 */

import { parseJSON } from '@mitre/hdf-utilities';
import { DEFAULT_STATIC_ANALYSIS_NIST_TAGS, getHadolintNistMapping, nistToCci } from '@mitre/hdf-mappings';
import { detectConverter } from '../../../shared/typescript/fingerprint.js';
import { registerAllFingerprints } from '../../../shared/typescript/register-all.js';
import { convertSarifToHdf } from '../../sarif-to-hdf/typescript/converter.js';
import {
  buildHdfResults,
  buildNistCciTags,
  buildNoFindingsRequirement,
  deriveControlTypeFromTags,
  inputChecksum,
  limitArray,
  validateInputSize,
} from '../../../shared/typescript/converterutil.js';
import { ruleReferenceUrl } from './rules.js';
import type { Checksum, Component, EvaluatedBaseline, EvaluatedRequirement, Reference, RequirementResult, SourceLocation } from '@mitre/hdf-schema';
import {
  ResultStatus,
  TargetType,
  VerificationMethodEnum,
  createMinimalBaseline,
  createRequirement,
  createResult,
} from '@mitre/hdf-schema';

const CONVERTER_NAME = 'hadolint';

/**
 * One entry of hadolint's JSON output. These six fields are the whole contract;
 * the formatter emits nothing else, and no run or tool metadata accompanies them.
 */
export interface HadolintFinding {
  code?: string;
  column?: number;
  file?: string;
  level?: string;
  line?: number;
  message?: string;
}

/**
 * hadolint's severity vocabulary as its JSON writer spells it. An ignored rule
 * serializes as the empty string, and anything unrecognized scores zero rather
 * than guessing.
 */
const LEVEL_IMPACT: Record<string, number> = {
  error: 0.7,
  warning: 0.5,
  info: 0.3,
  style: 0.1,
  '': 0.0,
};

function impactFor(level: string): number {
  return LEVEL_IMPACT[level] ?? 0.0;
}

/**
 * Resolves a rule's NIST controls and CCIs, falling back to the static-analysis
 * controls when the rule is unmapped. A mapped rule can still translate to
 * nothing — the table is authored at Rev 5 and SR-4 has no Rev 4 equivalent —
 * so an empty result takes the fallback too rather than leaving the finding
 * with an empty nist tag. Mirrors Go's `controlsFor`.
 */
function controlsFor(ruleId: string): {nist: string[]; cci: string[]} {
  const mapping = getHadolintNistMapping(ruleId);
  if (mapping && mapping.nist.length > 0) {
    return {nist: mapping.nist, cci: nistToCci(mapping.nist)};
  }
  const fallback = [...DEFAULT_STATIC_ANALYSIS_NIST_TAGS];
  return {nist: fallback, cci: nistToCci(fallback)};
}

function codeDescFor(f: HadolintFinding): string {
  return `File: ${f.file ?? ''} | Line: ${f.line ?? 0} | Column: ${f.column ?? 0}`;
}

function findingToResult(f: HadolintFinding, scanTime: Date): RequirementResult {
  return createResult(ResultStatus.Failed, f.message ?? '', {
    codeDesc: codeDescFor(f),
    startTime: scanTime,
  }) as RequirementResult;
}

function buildRequirement(ruleId: string, group: HadolintFinding[], scanTime: Date): EvaluatedRequirement {
  const first = group[0]!;
  const {nist, cci} = controlsFor(ruleId);
  const tags = buildNistCciTags(nist, cci);

  // The message is the rule's own text for hadolint's DL rules, but is
  // parameterized for shellcheck's SC rules. Each result carries its own, so
  // the title naming the first occurrence loses nothing.
  const message = first.message ?? '';
  const req = createRequirement(
    ruleId,
    message,
    [{label: 'default', data: message}],
    impactFor(first.level ?? ''),
    group.map((f) => findingToResult(f, scanTime)),
    {tags},
  ) as EvaluatedRequirement;

  req.verificationMethod = VerificationMethodEnum.Automated;
  const reference = ruleReferenceUrl(ruleId);
  if (reference !== '') req.refs = [{url: reference} as Reference];
  // Rebuilt field by field rather than re-serializing the parsed object, so the
  // two language twins agree regardless of how the source laid the object out.
  req.code = JSON.stringify({
    code: first.code ?? '',
    column: first.column ?? 0,
    file: first.file ?? '',
    level: first.level ?? '',
    line: first.line ?? 0,
    message: first.message ?? '',
  });
  if (first.file) {
    const location: SourceLocation = {ref: first.file};
    if (first.line !== undefined && first.line > 0) location.line = first.line;
    req.sourceLocation = location;
  }
  const controlType = deriveControlTypeFromTags(nist);
  if (controlType !== undefined) req.controlType = controlType;
  return req;
}

/**
 * Names each distinct scanned file. hadolint accepts several Dockerfiles in one
 * run and tags every finding with the file it came from.
 */
function componentsFor(findings: HadolintFinding[]): Component[] {
  const seen = new Set<string>();
  const components: Component[] = [];
  for (const f of findings) {
    if (!f.file || seen.has(f.file)) continue;
    seen.add(f.file);
    components.push({name: f.file, type: TargetType.Repository});
  }
  return components;
}

function baselineTitle(components: Component[]): string {
  if (components.length === 0) return 'Hadolint Scan';
  if (components.length === 1) return `Hadolint Scan of ${components[0]!.name}`;
  return `Hadolint Scan of ${components.length} files`;
}

const STRING_FIELDS = ['code', 'file', 'level', 'message'] as const;
const INTEGER_FIELDS = ['column', 'line'] as const;

/**
 * Parses the findings array, rejecting what the Go decoder rejects so both
 * public implementations accept the same inputs. Go decodes an absent or null
 * field to its zero value, so those stay valid; it refuses a field present
 * with the wrong type.
 */
function parseInput(input: string): HadolintFinding[] {
  const findings = parseJSON<HadolintFinding[]>(input);
  if (!Array.isArray(findings)) {
    throw new Error(`${CONVERTER_NAME}: input is not a hadolint findings array`);
  }
  for (const finding of findings) {
    if (typeof finding !== 'object' || finding === null || Array.isArray(finding)) {
      throw new Error(`${CONVERTER_NAME}: input is not a hadolint findings array`);
    }
    const fields = finding as Record<string, unknown>;
    for (const key of STRING_FIELDS) {
      const value = fields[key];
      if (value !== undefined && value !== null && typeof value !== 'string') {
        throw new Error(`${CONVERTER_NAME}: finding field ${key} is not a string`);
      }
    }
    // Go rejects a fractional value for an int field. JSON.parse cannot tell 1
    // from 1.0, so that single spelling is accepted here and refused there.
    for (const key of INTEGER_FIELDS) {
      const value = fields[key];
      if (value !== undefined && value !== null && !Number.isInteger(value)) {
        throw new Error(`${CONVERTER_NAME}: finding field ${key} is not an integer`);
      }
    }
  }
  return findings;
}

/** Converts hadolint JSON output to HDF results. */
export async function convertHadolintToHdf(input: string, converterVersion = '1.0.0'): Promise<string> {
  validateInputSize(input, CONVERTER_NAME);

  // hadolint can emit SARIF as well as JSON. Its SARIF collapses info and style
  // to "note", so the JSON path carries strictly more severity detail, but a
  // SARIF document still converts rather than failing to parse.
  registerAllFingerprints();
  const detected = detectConverter(input);
  if (detected && detected.fingerprint.id === 'sarif-to-hdf') {
    return convertSarifToHdf(input, converterVersion);
  }

  const resultsChecksum: Checksum = await inputChecksum(input);

  // hadolint reports no scan time, so the conversion time stands in for both
  // the document timestamp and every result's start time.
  const scanTime = new Date();

  const parsed = parseInput(input);
  const {items: findings, truncated} = limitArray(parsed);
  /* v8 ignore next -- truncation only triggers with >100K items */
  if (truncated) {
    // eslint-disable-next-line no-console
    console.warn(`WARNING: Input truncated at ${findings.length} finding items (original: ${parsed.length})`);
  }

  const components = componentsFor(findings);

  // Group by rule code preserving insertion order, which mirrors Go's
  // first-seen ordering.
  const groups = new Map<string, HadolintFinding[]>();
  for (const f of findings) {
    const code = f.code ?? '';
    const existing = groups.get(code);
    if (existing) existing.push(f);
    else groups.set(code, [f]);
  }

  const requirements: EvaluatedRequirement[] = [];
  for (const [ruleId, group] of groups) {
    requirements.push(buildRequirement(ruleId, group, scanTime));
  }
  if (requirements.length === 0) {
    requirements.push(
      buildNoFindingsRequirement(
        'hadolint-no-findings',
        'hadolint scanned the Dockerfile and reported zero findings.',
        scanTime,
      ) as EvaluatedRequirement,
    );
  }

  const baseline = createMinimalBaseline('Hadolint Scan', requirements, {
    title: baselineTitle(components),
    resultsChecksum,
  }) as EvaluatedBaseline;

  return buildHdfResults({
    generatorName: 'hadolint-to-hdf',
    converterVersion,
    toolName: CONVERTER_NAME,
    baselines: [baseline],
    components: components.length > 0 ? components : undefined,
    timestamp: scanTime,
  });
}
