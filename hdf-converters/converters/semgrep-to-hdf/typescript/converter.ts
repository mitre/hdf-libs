import { parseJSON, severityToImpactWithAliases } from '@mitre/hdf-utilities';
import { getCweNistControl, nistToCci } from '@mitre/hdf-mappings';
import { detectConverter } from '../../../shared/typescript/fingerprint.js';
import { registerAllFingerprints } from '../../../shared/typescript/register-all.js';
import { convertSarifToHdf } from '../../sarif-to-hdf/typescript/converter.js';
import {
  DEFAULT_STATIC_ANALYSIS_NIST_TAGS,
  buildHdfResults,
  buildNistCciTags,
  buildNoFindingsRequirement,
  deriveControlTypeFromTags,
  inputChecksum,
  markUnratedSeverity,
  validateInputSize,
} from '../../../shared/typescript/converterutil.js';
import type {
  Description,
  EvaluatedBaseline,
  EvaluatedRequirement,
  Reference,
  RequirementResult,
  SourceLocation,
} from '@mitre/hdf-schema';
import {
  ResultStatus,
  VerificationMethodEnum,
  createMinimalBaseline,
  createRequirement,
} from '@mitre/hdf-schema';

/**
 * Rule-level metadata from the Semgrep registry. Every field is optional: a
 * locally authored rule may declare none of it.
 *
 * Fields documented as arrays arrive as bare strings when a rule declares a
 * single value, so anything list-shaped is typed permissively and normalized
 * on read. All values are filtered per-field at read time — metadata is
 * arbitrary rule-author YAML, so one wrong-typed value must degrade to
 * "absent" for that field, never fail the conversion (the Go twin decodes
 * through equivalent lenient types).
 */
interface SemgrepMetadata {
  cwe?: string[] | string;
  owasp?: string[] | string;
  references?: string[] | string;
  subcategory?: string[] | string;
  technology?: string[] | string;
  vulnerability_class?: string[] | string;
  confidence?: string;
  likelihood?: string;
  /** Severity of the consequence -- NOT the HDF impact float. */
  impact?: string;
  category?: string;
  source?: string;
  shortlink?: string;
  'source-rule-url'?: string;
  'bandit-code'?: string;
  asvs?: Record<string, unknown>;
}

/**
 * Per-finding envelope. extra.lines is redacted to 'requires login' unless the
 * scan is authenticated; extra.fingerprint is equally redacted and
 * deliberately not mapped.
 */
interface SemgrepExtra {
  message?: string;
  metadata?: SemgrepMetadata;
  severity?: string;
  lines?: string;
  /** Replacement text for the matched span; only present when a rule autofixes. */
  fix?: string;
}

interface SemgrepPosition {
  line?: number;
  col?: number;
}

interface SemgrepResult {
  check_id: string;
  path?: string;
  start?: SemgrepPosition;
  end?: SemgrepPosition;
  extra?: SemgrepExtra;
}

/**
 * `type` is a heterogeneous array -- a discriminant string followed by an
 * optional payload, e.g. ['PartialParsing', [{path, start, end}]]. `level`
 * distinguishes fatal ('error') entries from advisory ('warn') ones.
 */
interface SemgrepError {
  message?: string;
  level?: string;
  type?: unknown;
  path?: string;
}

interface SemgrepReport {
  results?: SemgrepResult[];
  errors?: SemgrepError[];
  version?: string;
  paths?: { scanned?: string[]; skipped?: unknown[] };
}

/**
 * Semgrep's native three-level scale mapped onto the canonical impact tiers,
 * mirroring the sarif converter's error/warning/note aliases. INFO is
 * deliberately 0.3 (an actionable low, semgrep's analogue of SARIF 'note'),
 * not the canonical 0.0 info tier. Supply-chain severities
 * (critical/high/medium/low) resolve through the shared canonical map.
 */
const SEMGREP_SEVERITY_ALIASES: Record<string, number> = {
  error: 0.7,
  warning: 0.5,
  info: 0.3,
};

/**
 * An unrecognized or absent severity is treated as moderate; the absent case
 * additionally carries the shared unrated marker so consumers can tell a
 * defaulted 0.5 from a genuine medium.
 */
const DEFAULT_IMPACT = 0.5;

/** Fields Semgrep redacts in unauthenticated (OSS) scans. */
const REDACTED_PLACEHOLDER = 'requires login';

const SCAN_ERRORS_ID = 'semgrep-scan-errors';
const COVERAGE_ID = 'semgrep-scan-coverage';

function isPresent(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0 && value !== REDACTED_PLACEHOLDER;
}

/**
 * Array entries are filtered per-entry (non-string members dropped); a bare
 * empty string is treated as absent, matching the Go StringOrSlice decoder.
 */
function normalizeToArray(value: unknown): string[] {
  if (Array.isArray(value)) {
    return value.filter((entry): entry is string => typeof entry === 'string');
  }
  return typeof value === 'string' && value !== '' ? [value] : [];
}

function lineOf(position: SemgrepPosition | undefined): number | undefined {
  const line = position?.line;
  // Zero is semgrep's absent-line sentinel in practice and the Go twin's zero
  // value; treat it (and any non-number) as no line.
  return typeof line === 'number' && line > 0 ? line : undefined;
}

/**
 * Semgrep emits CWEs in prose form -- 'CWE-89: Improper Neutralization of ...'
 * -- while the mapping keys on the bare number.
 */
function extractCweIds(metadata: SemgrepMetadata): number[] {
  return normalizeToArray(metadata.cwe)
    .map((entry) => /CWE-(\d+)/i.exec(entry)?.[1])
    .filter((id): id is string => id !== undefined)
    .map((id) => Number.parseInt(id, 10))
    .filter((id) => Number.isFinite(id));
}

/**
 * The parsed CWE ids in the CWE-N catalog form the schema's cwe[] field asks
 * for, deduplicated in source order.
 */
function cweCatalogFor(metadata: SemgrepMetadata): string[] {
  return [...new Set(extractCweIds(metadata).map((id) => `CWE-${id}`))];
}

function nistControlsFor(metadata: SemgrepMetadata): string[] {
  const controls = extractCweIds(metadata)
    .map((cweId) => getCweNistControl(cweId))
    .filter(isPresent);
  const deduped = [...new Set(controls)];
  return deduped.length > 0 ? deduped : [...DEFAULT_STATIC_ANALYSIS_NIST_TAGS];
}

function impactFor(result: SemgrepResult): number {
  const severity = result.extra?.severity;
  if (!isPresent(severity)) {
    return DEFAULT_IMPACT;
  }
  return severityToImpactWithAliases(severity, SEMGREP_SEVERITY_ALIASES, DEFAULT_IMPACT);
}

/**
 * Semgrep rule ids are dotted paths whose final segment is the rule name. The
 * JSON output carries no human-readable rule title anywhere -- unlike the SARIF
 * output, whose rule objects have `name` and `shortDescription` -- so one is
 * derived. Separator runs collapse and only the first character of each word
 * is uppercased, matching the Go twin exactly.
 */
function titleFor(checkId: string): string {
  const segments = checkId.split('.').filter((segment) => segment.length > 0);
  const ruleName = segments[segments.length - 1] ?? checkId;
  return ruleName
    .split(/[-_]+/)
    .filter((word) => word.length > 0)
    .map((word) => word[0]!.toUpperCase() + word.slice(1))
    .join(' ');
}

function codeDescFor(result: SemgrepResult): string {
  const path = isPresent(result.path) ? result.path : 'unknown';
  const startLine = lineOf(result.start);
  const endLine = lineOf(result.end);
  if (startLine === undefined) {
    return `Path: ${path}`;
  }
  const span =
    endLine === undefined || endLine === startLine
      ? `line ${startLine}`
      : `lines ${startLine}-${endLine}`;
  return `Path: ${path}, ${span}`;
}

/**
 * Points at the first occurrence of the rule; per-occurrence locations remain
 * on each result's codeDesc.
 */
function sourceLocationFor(result: SemgrepResult): SourceLocation | undefined {
  if (!isPresent(result.path)) {
    return undefined;
  }
  const location: SourceLocation = { ref: result.path };
  const line = lineOf(result.start);
  if (line !== undefined) {
    location.line = line;
  }
  return location;
}

function messageFor(result: SemgrepResult): string {
  const parts: string[] = [];
  if (isPresent(result.extra?.lines)) {
    parts.push(`Matched code:\n${result.extra.lines}`);
  }
  // `fix` is replacement text for the matched span, not a standalone
  // instruction -- rendering it bare produces 'Suggested fix: False'.
  if (isPresent(result.extra?.fix)) {
    parts.push(`Suggested fix -- replace the matched code with:\n${result.extra.fix}`);
  }
  return parts.join('\n\n');
}

/** Documentation and cross-framework links, deduplicated. */
function referencesFor(metadata: SemgrepMetadata): string[] {
  const urls = [
    ...normalizeToArray(metadata.references),
    metadata.source,
    metadata.shortlink,
    metadata['source-rule-url'],
    typeof metadata.asvs?.control_url === 'string' ? metadata.asvs.control_url : undefined,
  ].filter(isPresent);
  return [...new Set(urls)];
}

/** The deduplicated reference URLs in refs[], their structured HDF home. */
function refsFor(metadata: SemgrepMetadata): Reference[] {
  return referencesFor(metadata).map((url) => ({ url }));
}

function asvsOf(metadata: SemgrepMetadata): Record<string, unknown> | undefined {
  const asvs = metadata.asvs;
  if (asvs && typeof asvs === 'object' && !Array.isArray(asvs) && Object.keys(asvs).length > 0) {
    return asvs;
  }
  return undefined;
}

function tagsFor(metadata: SemgrepMetadata, checkId: string, severity?: string): Record<string, unknown> {
  const nist = [...new Set(nistControlsFor(metadata))];
  const cci = nistToCci(nist);

  const extras: Record<string, unknown> = { checkId };
  const cwe = normalizeToArray(metadata.cwe);
  if (cwe.length > 0) extras.cwe = cwe;
  const owasp = normalizeToArray(metadata.owasp);
  if (owasp.length > 0) extras.owasp = owasp;
  const subcategory = normalizeToArray(metadata.subcategory);
  if (subcategory.length > 0) extras.subcategory = subcategory;
  const technology = normalizeToArray(metadata.technology);
  if (technology.length > 0) extras.technology = technology;
  const vulnerabilityClass = normalizeToArray(metadata.vulnerability_class);
  if (vulnerabilityClass.length > 0) extras.vulnerabilityClass = vulnerabilityClass;
  if (isPresent(severity)) extras.severity = severity;
  if (isPresent(metadata.confidence)) extras.confidence = metadata.confidence;
  if (isPresent(metadata.likelihood)) extras.likelihood = metadata.likelihood;
  // Renamed: semgrep's metadata.impact rates the severity of the consequence
  // and is not HDF's impact float. Tagging it as `impact` would shadow it.
  if (isPresent(metadata.impact)) extras.semgrepImpact = metadata.impact;
  if (isPresent(metadata.category)) extras.category = metadata.category;
  if (isPresent(metadata['bandit-code'])) extras.banditCode = metadata['bandit-code'];
  const asvs = asvsOf(metadata);
  if (asvs) extras.asvs = asvs;
  // Absent or redacted severity means the 0.5 impact is a default, not a
  // rating; the shared marker keeps that distinguishable downstream.
  markUnratedSeverity(extras, isPresent(severity) ? severity : '');

  return buildNistCciTags(nist, cci, extras);
}

function codePositionFor(position: SemgrepPosition | undefined): Record<string, number> | undefined {
  const line = lineOf(position);
  if (line === undefined) {
    return undefined;
  }
  const out: Record<string, number> = { line };
  const col = position?.col;
  if (typeof col === 'number' && col > 0) {
    out.col = col;
  }
  return out;
}

/**
 * Serializes the curated match envelope into requirement.code for the CODE
 * tab: the rule source itself is not present in semgrep's JSON output, and the
 * raw finding bytes are not byte-stable across the Go/TS pair (escape forms
 * differ), so both languages serialize this envelope field-for-field in the
 * same order. Rule metadata is deliberately excluded — it is already carried
 * structurally in tags, cwe[], and refs[] — and redacted fields are filtered
 * per the converter's redaction policy.
 */
function codeFor(result: SemgrepResult): string {
  const envelope: Record<string, unknown> = { check_id: result.check_id };
  if (isPresent(result.path)) envelope.path = result.path;
  const start = codePositionFor(result.start);
  if (start) envelope.start = start;
  const end = codePositionFor(result.end);
  if (end) envelope.end = end;
  const extra: Record<string, string> = {};
  if (isPresent(result.extra?.message)) extra.message = result.extra.message;
  if (isPresent(result.extra?.severity)) extra.severity = result.extra.severity;
  if (isPresent(result.extra?.lines)) extra.lines = result.extra.lines;
  if (isPresent(result.extra?.fix)) extra.fix = result.extra.fix;
  if (Object.keys(extra).length > 0) envelope.extra = extra;
  return JSON.stringify(envelope, null, 2);
}

/** Every occurrence of one rule becomes a result under a single requirement. */
function buildRequirement(
  checkId: string,
  results: SemgrepResult[],
  startTime: Date,
): EvaluatedRequirement {
  const representative = results[0]!;
  const metadata = representative.extra?.metadata ?? {};
  const message = representative.extra?.message;
  const description = typeof message === 'string' ? message : '';

  const descriptions: Description[] = [{ label: 'default', data: description }];

  const requirementResults: RequirementResult[] = results.map((result) => ({
    // Semgrep reports only violations. Findings suppressed with a `nosemgrep`
    // comment are omitted from the output entirely rather than flagged, so no
    // skipped status is derivable.
    status: ResultStatus.Failed,
    codeDesc: codeDescFor(result),
    message: messageFor(result),
    startTime,
  }));

  const tags = tagsFor(metadata, checkId, representative.extra?.severity);
  const cwe = cweCatalogFor(metadata);
  const refs = refsFor(metadata);
  const sourceLocation = sourceLocationFor(representative);

  const requirement = createRequirement(
    checkId,
    titleFor(checkId),
    descriptions,
    impactFor(representative),
    requirementResults,
    {
      tags,
      code: codeFor(representative),
      ...(cwe.length > 0 ? { cwe } : {}),
      ...(refs.length > 0 ? { refs } : {}),
      ...(sourceLocation ? { sourceLocation } : {}),
    },
  ) as EvaluatedRequirement;

  requirement.verificationMethod = VerificationMethodEnum.Automated;
  const controlType = deriveControlTypeFromTags(tags.nist as string[]);
  if (controlType !== undefined) {
    requirement.controlType = controlType;
  }
  return requirement;
}

/**
 * Scan failures become their own requirement so a file that failed to parse is
 * visible rather than buried: absence of findings in it is not evidence of
 * compliance. errors[].level drives the status: level 'error' entries are scan
 * failures (status error), while level 'warn' entries are advisory (e.g.
 * PartialParsing — the file was partially analyzed), a genuine non-evaluation
 * of those paths that must not dominate worst-wins rollups, so they map to
 * notReviewed.
 */
function buildErrorsRequirement(errors: SemgrepError[], startTime: Date): EvaluatedRequirement {
  const results: RequirementResult[] = errors.map((error) => {
    const kind = Array.isArray(error.type) ? String(error.type[0]) : String(error.type ?? 'Unknown');
    const level = isPresent(error.level) ? error.level : '';
    const message = typeof error.message === 'string' ? error.message : '';
    return {
      status: level.toLowerCase() === 'warn' ? ResultStatus.NotReviewed : ResultStatus.Error,
      codeDesc: `Path: ${isPresent(error.path) ? error.path : 'unknown'}`,
      message: level === '' ? `${kind}: ${message}` : `${kind} [${level}]: ${message}`,
      startTime,
    };
  });

  // The 0.5 impact on this synthesized requirement is a default, not a
  // severity rating from the tool.
  const tags = buildNistCciTags([...DEFAULT_STATIC_ANALYSIS_NIST_TAGS], []);
  markUnratedSeverity(tags, '');

  const requirement = createRequirement(
    SCAN_ERRORS_ID,
    'Semgrep scan errors',
    [
      {
        label: 'default',
        data: 'Errors reported by Semgrep while scanning. A file that failed to parse was not fully analyzed.',
      },
    ],
    DEFAULT_IMPACT,
    results,
    { tags },
  ) as EvaluatedRequirement;
  requirement.verificationMethod = VerificationMethodEnum.Automated;
  return requirement;
}

/**
 * Records the scan's denominator. Semgrep reports violations only, so a
 * converted profile is failures-only by construction and its compliance ratio
 * is not a pass rate; this record carries the scanned count and the caveat.
 * Impact 0 makes the effective-status layer derive notApplicable — the only
 * status the compliance rollup excludes — and the raw status matches so
 * raw-status consumers (and CKL export, where Passed would render NotAFinding)
 * agree with the effective view. Mirrors kics-scan-coverage.
 */
function scannedCount(report: SemgrepReport): number {
  return Array.isArray(report.paths?.scanned) ? report.paths.scanned.length : 0;
}

function buildCoverageRequirement(
  report: SemgrepReport,
  ruleCount: number,
  startTime: Date,
): EvaluatedRequirement {
  const filesScanned = scannedCount(report);
  const errorCount = report.errors?.length ?? 0;
  const summary =
    `Semgrep scanned ${filesScanned} file(s); ${ruleCount} rule(s) produced findings and ` +
    `${errorCount} scan error(s) were reported. Semgrep reports violations only and does not ` +
    `enumerate the rules that ran without finding anything, so no passing requirements can be ` +
    `derived from its output and the compliance ratio should not be read as a pass rate.`;

  return createRequirement(
    COVERAGE_ID,
    'Semgrep scan coverage',
    [{ label: 'default', data: summary }],
    0,
    [
      {
        status: ResultStatus.NotApplicable,
        codeDesc: summary,
        startTime,
      },
    ],
    {
      tags: {
        filesScanned,
        rulesWithFindings: ruleCount,
        scanErrors: errorCount,
      },
    },
  ) as EvaluatedRequirement;
}

/**
 * Converts native `semgrep scan --json` output to HDF Results. SARIF input is
 * detected and delegated to the SARIF converter.
 *
 * Native JSON is converted here because SARIF keeps the rule metadata only as
 * untyped prose tags on the rule object and drops impact, likelihood, the ASVS
 * control mapping, reference URLs and vulnerability_class outright.
 *
 * @param input - Semgrep JSON report string
 * @returns HDF JSON string
 */
export async function convertSemgrepToHdf(
  input: string,
  converterVersion = '1.0.0',
): Promise<string> {
  validateInputSize(input, 'semgrep');
  if (!input || input.trim().length === 0) {
    throw new Error('semgrep: empty input');
  }

  // Format routing: semgrep also emits SARIF; delegate transparently.
  registerAllFingerprints();
  const detected = detectConverter(input);
  if (detected && detected.fingerprint.id === 'sarif-to-hdf') {
    return convertSarifToHdf(input, converterVersion);
  }

  const report = parseJSON<SemgrepReport>(input);
  if (
    report === null ||
    typeof report !== 'object' ||
    !Array.isArray(report.results) ||
    !Array.isArray(report.errors)
  ) {
    throw new Error('semgrep: input does not look like a Semgrep report');
  }

  const startTime = new Date();

  // Group by rule, preserving the order rules were first seen.
  const groups = new Map<string, SemgrepResult[]>();
  for (const result of report.results) {
    if (typeof result?.check_id !== 'string' || result.check_id === '') {
      continue;
    }
    const existing = groups.get(result.check_id);
    if (existing) {
      existing.push(result);
    } else {
      groups.set(result.check_id, [result]);
    }
  }

  const requirements: EvaluatedRequirement[] = [];
  for (const [checkId, results] of groups) {
    requirements.push(buildRequirement(checkId, results, startTime));
  }
  if (groups.size === 0) {
    const scanned = scannedCount(report);
    requirements.push(
      buildNoFindingsRequirement(
        'semgrep-no-findings',
        `Semgrep scanned ${scanned} file(s) and reported no findings.`,
        startTime,
      ),
    );
  }
  if (report.errors.length > 0) {
    requirements.push(buildErrorsRequirement(report.errors, startTime));
  }
  requirements.push(buildCoverageRequirement(report, groups.size, startTime));

  const resultsChecksum = await inputChecksum(input);
  const baseline: EvaluatedBaseline = createMinimalBaseline('Semgrep Scan', requirements, {
    title: 'Semgrep static analysis scan',
    resultsChecksum,
  }) as EvaluatedBaseline;

  return buildHdfResults({
    generatorName: 'semgrep-to-hdf',
    converterVersion,
    toolName: 'Semgrep',
    toolVersion: typeof report.version === 'string' ? report.version : undefined,
    baselines: [baseline],
    timestamp: startTime,
  });
}
