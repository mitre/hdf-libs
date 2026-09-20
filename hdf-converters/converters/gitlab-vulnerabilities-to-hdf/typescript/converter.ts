/**
 * GitLab Vulnerability Report (GraphQL) to HDF Results — TypeScript twin of
 * go/converter.go. Converts the envelope the gitlab-vulnerabilities fetcher
 * assembles for one project into HDF, keeping triage state lossless.
 *
 * Status is raw-primary: results[].status is what the scanner last reported on
 * the default branch, and every human triage decision rides as an attributed,
 * expiring Status_Override so effectiveStatus, effectiveImpact and disposition
 * are computed through the shared ladder rather than assigned.
 */

import {
  type Component,
  type Description,
  type EvaluatedBaseline,
  type EvaluatedRequirement,
  type Identity,
  IdentityType,
  Justification,
  OverrideType,
  type Reference,
  type RequirementResult,
  ResultStatus,
  type SourceLocation,
  type StatusOverride,
  TargetType,
  severityToImpact,
} from '@mitre/hdf-schema';
import { getCweNistControl, nistToCci, DEFAULT_STATIC_ANALYSIS_NIST_TAGS } from '@mitre/hdf-mappings';
import { parseJSON, parseTimestamp, computeEffectiveStatus, governingOverrideIndex } from '@mitre/hdf-utilities';
import {
  buildHdfResults,
  buildNistCciTags,
  buildNoFindingsRequirement,
  defaultOverrideExpiry,
  deriveControlTypeFromTags,
  deriveVerificationMethod,
  inputChecksum,
  limitArrayWithWarning,
  markUnratedSeverity,
  validateInputSize,
} from '../../../shared/typescript/converterutil.js';
import { requirementStatusInput } from '../../../shared/typescript/status.js';

const CONVERTER_NAME = 'gitlab-vulnerabilities';
const SOURCE_NAME = 'GitLab Vulnerability Report';
const GENERATOR_NAME = 'gitlab-vulnerabilities-to-hdf';

// --- Envelope: the fetcher's assembled document ---

export interface Envelope {
  metadata?: Metadata;
  project?: Project;
  vulnerabilities?: Vulnerability[];
  fetchedAt?: string;
}

interface Metadata {
  enterprise?: boolean;
  version?: string;
}

interface Project {
  id?: string;
  fullPath?: string;
  name?: string;
  webUrl?: string;
  archived?: boolean;
  repository?: { rootRef?: string } | null;
  securityScanners?: { available?: string[]; enabled?: string[]; pipelineRun?: string[] } | null;
  vulnerabilityStatistic?: Statistic | null;
  latestDefaultBranchPipeline?: Pipeline | null;
}

interface Statistic {
  total?: number;
}

interface Pipeline {
  iid?: string;
  sha?: string;
  ref?: string;
  status?: string;
  createdAt?: string;
  finishedAt?: string;
  securityReportSummary?: Record<string, SummarySection | null> | null;
}

interface SummarySection {
  vulnerabilitiesCount?: number;
  scans?: { nodes?: Scan[] };
}

interface Scan {
  name?: string;
  status?: string;
  errors?: string[];
  warnings?: string[];
}

interface User {
  username?: string;
  name?: string;
  publicEmail?: string | null;
}

interface Identifier {
  externalType?: string;
  externalId?: string;
  name?: string;
  url?: string | null;
}

interface Location {
  __typename?: string;
  file?: string;
  startLine?: string | null;
  endLine?: string | null;
  blobPath?: string | null;
  vulnerableClass?: string | null;
  vulnerableMethod?: string | null;
  dependency?: { version?: string; package?: { name?: string } } | null;
  image?: string;
  operatingSystem?: string;
  hostname?: string;
  path?: string;
  param?: string;
  requestMethod?: string;
}

interface PipelineRef {
  iid?: string;
  sha?: string;
  ref?: string;
  createdAt?: string;
}

interface Transition {
  fromState?: string;
  toState?: string;
  createdAt?: string;
  comment?: string | null;
  dismissalReason?: string | null;
  author?: User | null;
}

interface SeverityChange {
  originalSeverity?: string;
  newSeverity?: string;
  createdAt?: string;
  author?: User | null;
}

export interface Vulnerability {
  id?: string;
  uuid?: string;
  title?: string;
  description?: string;
  severity?: string;
  reportType?: string;
  state?: string;
  detectedAt?: string;
  confirmedAt?: string | null;
  dismissedAt?: string | null;
  resolvedAt?: string | null;
  updatedAt?: string;
  falsePositive?: boolean;
  presentOnDefaultBranch?: boolean;
  resolvedOnDefaultBranch?: boolean;
  dismissalReason?: string | null;
  stateComment?: string | null;
  confirmedBy?: User | null;
  dismissedBy?: User | null;
  resolvedBy?: User | null;
  solution?: string | null;
  vulnerabilityPath?: string;
  webUrl?: string;
  scanner?: { name?: string; vendor?: string; externalId?: string; reportType?: string } | null;
  primaryIdentifier?: Identifier | null;
  identifiers?: Identifier[];
  links?: Array<{ name?: string | null; url?: string }>;
  location?: Location | null;
  initialDetectedPipeline?: PipelineRef | null;
  latestDetectedPipeline?: PipelineRef | null;
  stateTransitions?: { nodes?: Transition[] };
  severityOverrides?: { nodes?: SeverityChange[] };
}

// --- Parsing ---

function parseInput(input: string): Envelope {
  if (!input || input.trim() === '') {
    throw new Error(`${CONVERTER_NAME}: empty input`);
  }
  validateInputSize(input, CONVERTER_NAME);
  let env: Envelope;
  try {
    env = parseJSON<Envelope>(input);
  } catch (e) {
    throw new Error(`${CONVERTER_NAME}: invalid envelope JSON: ${(e as Error).message}`);
  }
  if (typeof env !== 'object' || env === null || Array.isArray(env)) {
    throw new Error(`${CONVERTER_NAME}: input is not a Vulnerability Report envelope (project.fullPath missing)`);
  }
  if (!env.project?.fullPath) {
    throw new Error(`${CONVERTER_NAME}: input is not a Vulnerability Report envelope (project.fullPath missing)`);
  }
  if (!env.metadata?.enterprise) {
    throw new Error(`${CONVERTER_NAME}: GitLab Community Edition has no Vulnerability Report; use the gitlab (CI artifact) converter instead`);
  }
  return env;
}

function sortedSectionKeys(pipeline: Pipeline): string[] {
  const summary = pipeline.securityReportSummary ?? {};
  return Object.keys(summary).filter((k) => summary[k] != null).sort();
}

function scansOf(pipeline: Pipeline, key: string): Scan[] {
  return pipeline.securityReportSummary?.[key]?.scans?.nodes ?? [];
}

// An empty vulnerability list on a report that ingestion never populated is an
// error, not a clean document: a no-findings pass there would be the one truly
// silent false pass.
function ingestionError(env: Envelope): Error | undefined {
  const project = env.project!;
  if (project.vulnerabilityStatistic != null) return undefined;
  const pipeline = project.latestDefaultBranchPipeline;
  if (!pipeline) {
    return new Error(`${CONVERTER_NAME}: ${project.fullPath} has no default-branch pipeline; no security scanner has run`);
  }
  const created: string[] = [];
  const failed: string[] = [];
  let succeeded = false;
  for (const reportType of sortedSectionKeys(pipeline)) {
    for (const scan of scansOf(pipeline, reportType)) {
      switch (scan.status ?? '') {
        case 'SUCCEEDED':
          succeeded = true;
          break;
        case 'CREATED':
        case 'PREPARING':
          created.push(reportType);
          break;
        case '':
          failed.push(`${reportType}: status unknown`);
          break;
        default: {
          let desc = `${reportType}: ${scan.status}`;
          if (scan.errors && scan.errors.length > 0) desc += ` (${scan.errors.join('; ')})`;
          failed.push(desc);
        }
      }
    }
  }
  if (succeeded) return undefined;
  if (failed.length > 0) {
    return new Error(`${CONVERTER_NAME}: scanner jobs on the default branch of ${project.fullPath} produced no usable report: ${failed.join(', ')}`);
  }
  if (created.length > 0) {
    return new Error(`${CONVERTER_NAME}: security reports for ${project.fullPath} were produced but never ingested (${created.join(', ')} stuck at CREATED); the Vulnerability Report requires GitLab Ultimate`);
  }
  return new Error(`${CONVERTER_NAME}: no security scanner has run on the default branch of ${project.fullPath}`);
}

function ingestedReportTypes(pipeline: Pipeline | null | undefined): string[] {
  if (!pipeline) return [];
  return sortedSectionKeys(pipeline).filter((key) => scansOf(pipeline, key).some((s) => s.status === 'SUCCEEDED'));
}

// --- Conversion ---

export async function convertGitlabVulnerabilitiesToHdf(input: string, converterVersion = '1.0.0'): Promise<string> {
  const env = parseInput(input);
  const fetchedAt = parseTimestamp(env.fetchedAt ?? '');
  if (!fetchedAt) {
    throw new Error(`${CONVERTER_NAME}: envelope fetchedAt "${env.fetchedAt ?? ''}" is not a valid timestamp`);
  }
  const resultsChecksum = await inputChecksum(input);
  const project = env.project!;
  const vulnerabilities = env.vulnerabilities ?? [];

  let baselines: EvaluatedBaseline[];
  if (vulnerabilities.length === 0) {
    const err = ingestionError(env);
    if (err) throw err;
    baselines = noFindingsBaselines(project, fetchedAt, resultsChecksum);
  } else {
    baselines = findingBaselines(vulnerabilities, project, fetchedAt, resultsChecksum);
  }

  return buildHdfResults({
    generatorName: GENERATOR_NAME,
    converterVersion,
    toolName: SOURCE_NAME,
    toolVersion: env.metadata?.version,
    baselines,
    components: [buildComponent(project)],
    timestamp: fetchedAt,
  });
}

type Checksum = Awaited<ReturnType<typeof inputChecksum>>;

function findingBaselines(vulnerabilities: Vulnerability[], project: Project, fetchedAt: Date, checksum: Checksum): EvaluatedBaseline[] {
  const limited = limitArrayWithWarning(vulnerabilities, 'vulnerability');
  const byType = new Map<string, EvaluatedRequirement[]>();
  const scanners = new Map<string, Set<string>>();
  for (const v of limited) {
    const reportType = v.reportType || 'GENERIC';
    if (!byType.has(reportType)) {
      byType.set(reportType, []);
      scanners.set(reportType, new Set());
    }
    if (v.scanner?.name) scanners.get(reportType)!.add(v.scanner.name);
    byType.get(reportType)!.push(convertVulnerability(v, project, fetchedAt));
  }
  return [...byType.keys()].sort().map((reportType) => {
    const title = reportTypeLabel(reportType);
    const names = [...scanners.get(reportType)!].sort();
    return {
      name: `${SOURCE_NAME}: ${title}`,
      title,
      summary: names.length > 0 ? `Scanner: ${names.join(', ')}` : 'Scanner: unknown',
      requirements: byType.get(reportType)!,
      resultsChecksum: checksum,
    };
  });
}

function noFindingsBaselines(project: Project, fetchedAt: Date, checksum: Checksum): EvaluatedBaseline[] {
  let types = ingestedReportTypes(project.latestDefaultBranchPipeline);
  if (types.length === 0) types = ['generic'];
  const requirements = types.map((key) => {
    const reportType = summaryKeyToReportType(key);
    return buildNoFindingsRequirement(
      `gitlab-vulnerability-report-no-findings-${reportType.toLowerCase()}`,
      `GitLab Vulnerability Report for ${project.fullPath} lists zero ${reportTypeLabel(reportType)} vulnerabilities after a successful scan ingestion.`,
      fetchedAt,
    );
  });
  return [{
    name: SOURCE_NAME,
    title: 'No findings',
    summary: `Ingested scanner types: ${types.join(', ')}`,
    requirements,
    resultsChecksum: checksum,
  }];
}

function summaryKeyToReportType(key: string): string {
  return key.replace(/([A-Z])/g, '_$1').toUpperCase();
}

const REPORT_TYPE_LABELS: Record<string, string> = {
  SAST: 'SAST',
  DEPENDENCY_SCANNING: 'Dependency Scanning',
  CONTAINER_SCANNING: 'Container Scanning',
  CONTAINER_SCANNING_FOR_REGISTRY: 'Container Scanning for Registry',
  DAST: 'DAST',
  SECRET_DETECTION: 'Secret Detection',
  COVERAGE_FUZZING: 'Coverage Fuzzing',
  API_FUZZING: 'API Fuzzing',
  CLUSTER_IMAGE_SCANNING: 'Cluster Image Scanning',
  GENERIC: 'Generic',
};

function reportTypeLabel(reportType: string): string {
  return REPORT_TYPE_LABELS[reportType] ?? reportType;
}

// The provenance the issue asked the fetcher to pre-fill: the repository the
// report describes, the branch it reflects and the commit its latest
// default-branch pipeline scanned.
function buildComponent(project: Project): Component {
  const c: Component = {
    name: project.fullPath ?? '',
    type: TargetType.Repository,
    labels: {
      'gitlab/project-id': project.id ?? '',
      'gitlab/full-path': project.fullPath ?? '',
    },
  };
  if (project.webUrl) c.url = project.webUrl;
  if (project.repository?.rootRef) c.branch = project.repository.rootRef;
  if (project.latestDefaultBranchPipeline?.sha) c.commit = project.latestDefaultBranchPipeline.sha;
  return c;
}

// --- Per-vulnerability conversion ---

function convertVulnerability(v: Vulnerability, project: Project, fetchedAt: Date): EvaluatedRequirement {
  const { original, current } = severityPair(v);
  const code = JSON.stringify(v, null, 2);
  const tags = buildTags(v, project, original, current);

  const result: RequirementResult = {
    status: rawStatus(v),
    codeDesc: buildCodeDesc(v),
    startTime: resultStartTime(v, fetchedAt),
  };

  const req: EvaluatedRequirement = {
    id: v.uuid ?? '',
    title: v.title ?? '',
    descriptions: buildDescriptions(v),
    impact: severityToImpact(original),
    tags,
    code,
    results: [result],
  };
  const refs = buildRefs(v);
  if (refs.length > 0) req.refs = refs;
  const sourceLocation = buildSourceLocation(v.location);
  if (sourceLocation) req.sourceLocation = sourceLocation;
  const verificationMethod = deriveVerificationMethod(code);
  if (verificationMethod !== undefined) req.verificationMethod = verificationMethod;
  const controlType = deriveControlTypeFromTags((tags.nist as string[]) ?? []);
  if (controlType !== undefined) req.controlType = controlType;

  const overrides = [...buildStatusOverrides(v, fetchedAt), ...buildSeverityOverrides(v, fetchedAt)];
  if (overrides.length > 0) {
    sortMostRecentFirst(overrides);
    req.statusOverrides = overrides;
    applyEffectivePosture(req, fetchedAt);
  }
  return req;
}

// What the scanner last said on the default branch: the finding is present
// unless GitLab has both stopped detecting it and a human marked it resolved.
function rawStatus(v: Vulnerability): ResultStatus {
  if (v.state === 'RESOLVED' && v.resolvedOnDefaultBranch) return ResultStatus.Passed;
  return ResultStatus.Failed;
}

// GitLab's `severity` already reflects human overrides, so the scanner's
// original is recovered from the oldest override when there is one.
function severityPair(v: Vulnerability): { original: string; current: string } {
  const current = v.severity ?? '';
  const first = v.severityOverrides?.nodes?.[0];
  const original = first?.originalSeverity ? first.originalSeverity : current;
  return { original, current };
}

function resultStartTime(v: Vulnerability, fetchedAt: Date): Date {
  return firstTime(v.latestDetectedPipeline?.createdAt, v.detectedAt) ?? fetchedAt;
}

function buildDescriptions(v: Vulnerability): Description[] {
  const descriptions: Description[] = [{ label: 'default', data: v.description || v.title || '' }];
  if (v.solution) descriptions.push({ label: 'fix', data: v.solution });
  return descriptions;
}

function buildTags(v: Vulnerability, project: Project, original: string, current: string): Record<string, unknown> {
  const nist = buildNistTags(v.identifiers ?? []);
  const tags = buildNistCciTags(nist, nistToCci(nist), collectIdentifierExtras(v.identifiers ?? []));
  markUnratedSeverity(tags, current);

  const transitions = v.stateTransitions?.nodes ?? [];
  tags['gitlab/id'] = v.id ?? '';
  tags['gitlab/uuid'] = v.uuid ?? '';
  tags['gitlab/webUrl'] = v.webUrl ?? '';
  tags['gitlab/project'] = project.fullPath ?? '';
  tags['gitlab/reportType'] = v.reportType ?? '';
  tags['gitlab/severity'] = current;
  tags['gitlab/originalSeverity'] = original;
  tags['gitlab/state'] = v.state ?? '';
  tags['gitlab/dismissalReason'] = v.dismissalReason ?? null;
  tags['gitlab/stateComment'] = v.stateComment ?? null;
  tags['gitlab/falsePositive'] = v.falsePositive ?? false;
  tags['gitlab/presentOnDefaultBranch'] = v.presentOnDefaultBranch ?? false;
  tags['gitlab/resolvedOnDefaultBranch'] = v.resolvedOnDefaultBranch ?? false;
  tags['gitlab/detectedAt'] = v.detectedAt ?? '';
  tags['gitlab/updatedAt'] = v.updatedAt ?? '';
  tags['gitlab/confirmedAt'] = v.confirmedAt ?? null;
  tags['gitlab/confirmedBy'] = userTag(v.confirmedBy);
  tags['gitlab/dismissedAt'] = v.dismissedAt ?? null;
  tags['gitlab/dismissedBy'] = userTag(v.dismissedBy);
  tags['gitlab/resolvedAt'] = v.resolvedAt ?? null;
  tags['gitlab/resolvedBy'] = userTag(v.resolvedBy);
  tags['gitlab/initialDetectedPipeline'] = pipelineTag(v.initialDetectedPipeline);
  tags['gitlab/latestDetectedPipeline'] = pipelineTag(v.latestDetectedPipeline);
  tags['gitlab/scanner'] = v.scanner ? { name: v.scanner.name ?? '', vendor: v.scanner.vendor ?? '', externalId: v.scanner.externalId ?? '' } : null;
  tags['gitlab/stateTransitionCount'] = transitions.length;
  if (transitions.length > 0 && transitions[transitions.length - 1]!.toState !== v.state) {
    tags['gitlab/stateHistoryInconsistent'] = true;
  }
  return tags;
}

function userTag(u: User | null | undefined): string | null {
  return u ? (u.username ?? '') : null;
}

function pipelineTag(p: PipelineRef | null | undefined): Record<string, string> | null {
  if (!p) return null;
  return { iid: p.iid ?? '', sha: p.sha ?? '', ref: p.ref ?? '', createdAt: p.createdAt ?? '' };
}

function buildNistTags(identifiers: Identifier[]): string[] {
  const seen = new Set<string>();
  const controls: string[] = [];
  for (const id of identifiers) {
    if ((id.externalType ?? '').toLowerCase() !== 'cwe' || !id.externalId) continue;
    const cweId = parseInt(id.externalId.replace(/^CWE-/i, ''), 10);
    if (Number.isNaN(cweId)) continue;
    const control = getCweNistControl(cweId);
    if (control && !seen.has(control)) {
      seen.add(control);
      controls.push(control);
    }
  }
  return controls.length > 0 ? controls : DEFAULT_STATIC_ANALYSIS_NIST_TAGS;
}

function collectIdentifierExtras(identifiers: Identifier[]): Record<string, unknown> {
  const grouped: Record<string, string[]> = {};
  for (const id of identifiers) {
    if (!id.externalType || !id.externalId) continue;
    const key = id.externalType.toLowerCase();
    (grouped[key] ??= []).push(id.externalId);
  }
  return grouped;
}

// The finding's own page plus every identifier and link URL, de-duplicated.
function buildRefs(v: Vulnerability): Reference[] {
  const refs: Reference[] = [];
  const seen = new Set<string>();
  const add = (url: string | null | undefined): void => {
    if (!url || seen.has(url)) return;
    seen.add(url);
    refs.push({ url });
  };
  add(v.webUrl);
  for (const id of v.identifiers ?? []) add(id.url);
  for (const link of v.links ?? []) add(link.url);
  return refs;
}

function parseLine(s: string | null | undefined): number | undefined {
  if (!s) return undefined;
  const n = parseInt(s, 10);
  return Number.isNaN(n) || String(n) !== s ? undefined : n;
}

function buildSourceLocation(loc: Location | null | undefined): SourceLocation | undefined {
  if (!loc || !loc.file) return undefined;
  const sl: SourceLocation = { ref: loc.file };
  const line = parseLine(loc.startLine) ?? parseLine(loc.endLine);
  if (line !== undefined) sl.line = line;
  return sl;
}

function packageLabel(d: Location['dependency']): string {
  if (!d?.package?.name) return '';
  return d.version ? `${d.package.name}@${d.version}` : d.package.name;
}

function buildCodeDesc(v: Vulnerability): string {
  const loc = v.location;
  if (!loc) return `Report type: ${v.reportType ?? ''}`;
  const parts: string[] = [];
  switch (loc.__typename) {
    case 'VulnerabilityLocationSast':
    case 'VulnerabilityLocationSecretDetection':
    case 'VulnerabilityLocationCoverageFuzzing':
    case 'VulnerabilityLocationGeneric':
      if (loc.file) parts.push(`File: ${loc.file}`);
      if (loc.startLine) {
        if (loc.endLine && loc.endLine !== loc.startLine) parts.push(`Line: ${loc.startLine}-${loc.endLine}`);
        else parts.push(`Line: ${loc.startLine}`);
      }
      if (loc.vulnerableClass) parts.push(`Class: ${loc.vulnerableClass}`);
      if (loc.vulnerableMethod) parts.push(`Method: ${loc.vulnerableMethod}`);
      break;
    case 'VulnerabilityLocationDependencyScanning': {
      if (loc.file) parts.push(`File: ${loc.file}`);
      const pkg = packageLabel(loc.dependency);
      if (pkg) parts.push(`Package: ${pkg}`);
      break;
    }
    case 'VulnerabilityLocationContainerScanning':
    case 'VulnerabilityLocationClusterImageScanning': {
      if (loc.image) parts.push(`Image: ${loc.image}`);
      if (loc.operatingSystem) parts.push(`OS: ${loc.operatingSystem}`);
      const pkg = packageLabel(loc.dependency);
      if (pkg) parts.push(`Package: ${pkg}`);
      break;
    }
    case 'VulnerabilityLocationDast':
      if (loc.hostname) parts.push(`URL: ${loc.hostname}${loc.path ?? ''}`);
      if (loc.requestMethod) parts.push(`Method: ${loc.requestMethod}`);
      if (loc.param) parts.push(`Param: ${loc.param}`);
      break;
    default:
      return `Location: ${JSON.stringify(loc)}`;
  }
  return parts.length > 0 ? parts.join(' | ') : `Report type: ${v.reportType ?? ''}`;
}

// --- Triage state → overrides ---

interface Decision {
  overrideType: OverrideType;
  status: ResultStatus;
  justification?: Justification;
  defaultReason: string;
}

// Maps a transition into a triage state onto an override, or undefined when
// the state carries none (DETECTED, CONFIRMED, and RESOLVED once the scanner
// itself no longer reports the finding).
function decisionFor(toState: string | undefined, dismissalReason: string | null | undefined, scannerResolved: boolean): Decision | undefined {
  switch (toState) {
    case 'DISMISSED':
      return dismissalDecision(dismissalReason ?? '');
    case 'RESOLVED':
      if (scannerResolved) return undefined;
      return { overrideType: OverrideType.Attestation, status: ResultStatus.Passed, defaultReason: 'Marked resolved in GitLab' };
    default:
      return undefined;
  }
}

function dismissalDecision(reason: string): Decision {
  switch (reason) {
    case 'FALSE_POSITIVE':
      return { overrideType: OverrideType.FalsePositive, status: ResultStatus.NotApplicable, defaultReason: 'Dismissed as FALSE_POSITIVE in GitLab' };
    case 'ACCEPTABLE_RISK':
      return { overrideType: OverrideType.Waiver, status: ResultStatus.Passed, defaultReason: 'Dismissed as ACCEPTABLE_RISK in GitLab' };
    case 'MITIGATING_CONTROL':
      return { overrideType: OverrideType.Waiver, status: ResultStatus.Passed, justification: Justification.InlineMitigationsAlreadyExist, defaultReason: 'Dismissed as MITIGATING_CONTROL in GitLab' };
    case 'USED_IN_TESTS':
      return { overrideType: OverrideType.Waiver, status: ResultStatus.NotApplicable, justification: Justification.VulnerableCodeNotInExecutePath, defaultReason: 'Dismissed as USED_IN_TESTS in GitLab' };
    case 'NOT_APPLICABLE':
    case '':
      return { overrideType: OverrideType.Waiver, status: ResultStatus.NotApplicable, defaultReason: 'Dismissed as NOT_APPLICABLE in GitLab' };
    default:
      return { overrideType: OverrideType.Waiver, status: ResultStatus.NotApplicable, defaultReason: `Dismissed as ${reason} in GitLab` };
  }
}

// Replays the full state history: one override per transition into a mapped
// state, oldest first. A revert (back to DETECTED) creates no override; it
// closes the previous one by setting its expiry to the revert time. When
// GitLab returned no history for a triaged finding, the governing override is
// synthesized from the current-state fields.
function buildStatusOverrides(v: Vulnerability, fetchedAt: Date): StatusOverride[] {
  const scannerResolved = v.state === 'RESOLVED' && !!v.resolvedOnDefaultBranch;
  const overrides: StatusOverride[] = [];
  const transitions = v.stateTransitions?.nodes ?? [];
  for (const tr of transitions) {
    if (tr.toState === 'DETECTED') {
      const at = firstTime(tr.createdAt);
      if (overrides.length > 0 && at) overrides[overrides.length - 1]!.expiresAt = at;
      continue;
    }
    const d = decisionFor(tr.toState, tr.dismissalReason, scannerResolved);
    if (!d) continue;
    const appliedAt = firstTime(tr.createdAt, v.updatedAt, v.detectedAt) ?? fetchedAt;
    overrides.push(newOverride(v, d, appliedAt, tr.comment, tr.author));
  }
  if (transitions.length > 0 && transitions[transitions.length - 1]!.toState === v.state) {
    return overrides;
  }
  const d = decisionFor(v.state, v.dismissalReason, scannerResolved);
  if (d) {
    const { at, by } = currentDecisionProvenance(v);
    overrides.push(newOverride(v, d, at ?? fetchedAt, v.stateComment, by));
  }
  return overrides;
}

function currentDecisionProvenance(v: Vulnerability): { at: Date | undefined; by: User | null | undefined } {
  switch (v.state) {
    case 'DISMISSED':
      return { at: firstTime(v.dismissedAt, v.updatedAt, v.detectedAt), by: v.dismissedBy };
    case 'RESOLVED':
      return { at: firstTime(v.resolvedAt, v.updatedAt, v.detectedAt), by: v.resolvedBy };
    default:
      // Only dismissals and resolutions synthesize an override; anything else
      // reaching here is dated but unattributed.
      return { at: firstTime(v.updatedAt, v.detectedAt), by: undefined };
  }
}

// The first candidate that is a valid timestamp; undefined means the source
// has nothing, and callers fall back to the fetch time so an override always
// has a real, deterministic date and both language twins agree on it.
function firstTime(...candidates: Array<string | null | undefined>): Date | undefined {
  for (const c of candidates) {
    if (!c) continue;
    const ts = parseTimestamp(c);
    if (ts) return ts;
  }
  return undefined;
}

function newOverride(v: Vulnerability, d: Decision, appliedAt: Date, comment: string | null | undefined, author: User | null | undefined): StatusOverride {
  const o: StatusOverride = {
    type: d.overrideType,
    status: d.status,
    reason: comment && comment.trim() !== '' ? comment : d.defaultReason,
    appliedBy: identityFor(author),
    appliedAt,
    expiresAt: defaultOverrideExpiry(appliedAt),
  };
  if (d.justification !== undefined) o.justification = d.justification;
  if (v.webUrl) o.externalReferences = [{ sourceName: SOURCE_NAME, href: v.webUrl }];
  return o;
}

// Prefers a public email, then the username; a decision GitLab recorded
// without an author is attributed to the system, never to a fabricated person.
function identityFor(u: User | null | undefined): Identity {
  if (u) {
    const description = u.name ? u.name : undefined;
    if (u.publicEmail) {
      const id: Identity = { type: IdentityType.Email, identifier: u.publicEmail };
      if (description) id.description = description;
      return id;
    }
    if (u.username) {
      const id: Identity = { type: IdentityType.Username, identifier: u.username };
      if (description) id.description = description;
      return id;
    }
  }
  return { type: IdentityType.System, identifier: 'gitlab', description: 'GitLab automatic state change' };
}

// Each human severity change becomes an impact-only riskAdjustment;
// requirement.impact keeps the scanner's original severity.
function buildSeverityOverrides(v: Vulnerability, fetchedAt: Date): StatusOverride[] {
  return (v.severityOverrides?.nodes ?? []).map((sc) => {
    const appliedAt = firstTime(sc.createdAt, v.updatedAt, v.detectedAt) ?? fetchedAt;
    const o: StatusOverride = {
      type: OverrideType.RiskAdjustment,
      impact: { value: severityToImpact(sc.newSeverity ?? '') },
      reason: `Severity changed from ${sc.originalSeverity ?? ''} to ${sc.newSeverity ?? ''} in GitLab`,
      appliedBy: identityFor(sc.author),
      appliedAt,
      expiresAt: defaultOverrideExpiry(appliedAt),
    };
    if (v.webUrl) o.externalReferences = [{ sourceName: SOURCE_NAME, href: v.webUrl }];
    return o;
  });
}

// Newest first. GitLab timestamps have second resolution, so decisions made in
// the same second tie on appliedAt; reversing the oldest-first history before
// the stable sort keeps the later decision ahead of the one it superseded.
function sortMostRecentFirst(overrides: StatusOverride[]): void {
  overrides.reverse();
  overrides.sort((a, b) => b.appliedAt.getTime() - a.appliedAt.getTime());
}

// effectiveStatus, effectiveImpact and disposition from the shared ladder,
// judged at the fetch time so the output is deterministic for an envelope.
function applyEffectivePosture(req: EvaluatedRequirement, fetchedAt: Date): void {
  const overrides = req.statusOverrides ?? [];
  const ref = fetchedAt.toISOString();
  const inputs = requirementStatusInput(req).overrides ?? [];

  req.effectiveStatus = computeEffectiveStatus(requirementStatusInput(req), ref) as ResultStatus;

  const impactIdx = governingOverrideIndex(inputs, (i) => overrides[i]?.impact !== undefined, ref);
  if (impactIdx >= 0) req.effectiveImpact = overrides[impactIdx]!.impact!.value;

  const dispositionIdx = governingOverrideIndex(inputs, (i) => overrides[i]?.status !== undefined || overrides[i]?.impact !== undefined, ref);
  if (dispositionIdx >= 0) req.disposition = overrides[dispositionIdx]!.type;
}
