import {
  type AffectedPackage,
  type Description,
  type EvaluatedBaseline,
  type EvaluatedRequirement,
  type ExternalReference,
  type Reference,
  type RequirementResult,
  ExternalReferenceEncoding,
  ResultStatus,
  TargetType,
  VerificationMethodEnum,
} from '@mitre/hdf-schema';
import {
  DEFAULT_COMPONENT_MANAGEMENT_NIST_TAGS,
  DEFAULT_REMEDIATION_NIST_TAGS,
  nistToCci,
} from '@mitre/hdf-mappings';
import { parseJSON } from '@mitre/hdf-utilities';
import {
  buildAffectedPackage,
  buildHdfResults,
  buildNistCciTags,
  buildNoFindingsRequirement,
  deriveControlTypeFromTags,
  ecosystemFromPurlType,
  inputChecksum,
  packageInstanceId,
  validateInputSize,
} from '../../../shared/typescript/converterutil.js';

interface ComponentIdentifier {
  format?: string;
  coordinates?: Record<string, unknown>;
}

interface ConditionFact {
  conditionTypeId?: string;
  summary?: string;
  reason?: string;
  reference?: { value?: string; type?: string } | null;
}

interface ConstraintFact {
  constraintId?: string;
  constraintName?: string;
  conditionFacts?: ConditionFact[];
}

interface ComponentFact {
  /** Null for a component IQ could not identify (the "Unknown Component" policy). */
  componentIdentifier?: ComponentIdentifier | null;
  hash?: string;
  constraintFacts?: ConstraintFact[];
  pathnames?: string[];
  displayName?: { name?: string } | null;
}

interface Trigger {
  policyId?: string;
  policyName?: string;
  threatLevel?: number;
  policyViolationId?: string;
  componentFacts?: ComponentFact[];
}

interface Alert {
  trigger?: Trigger;
  actions?: { actionTypeId?: string }[];
}

/**
 * The result file the Nexus IQ CLI writes with `--result-file` (`-r`).
 * prioritiesUrl is not read: it links to the IQ developer view of the same scan
 * the report URLs already identify.
 */
interface Report {
  applicationId: string;
  scanId: string;
  stage?: string;
  policyAction?: string;
  reportHtmlUrl?: string;
  reportPdfUrl?: string;
  reportDataUrl?: string;
  policyEvaluationResult: Record<string, unknown> & {
    alerts?: Alert[] | null;
    sastAlerts?: unknown[];
  };
}

const CONVERTER = 'nexusiq';
const VULNERABILITY_REF = 'SECURITY_VULNERABILITY_REFID';
const UNKNOWN_COMPONENT = 'Unknown component';
const VIOLATION_COUNTERS = [
  'criticalPolicyViolationCount',
  'severePolicyViolationCount',
  'moderatePolicyViolationCount',
];

/** The score IQ states in prose: "... with severity >= 7 (severity = 8.1)". */
const SEVERITY_IN_REASON = /\(severity = ([0-9]+(?:\.[0-9]+)?)\)/;
const PURL_SAFE = /^[A-Za-z0-9._-]+$/;

/** Sonatype's own bands for the 0-10 policy threat level. */
export function threatCategory(level: number): string {
  if (level >= 8) return 'critical';
  if (level >= 4) return 'severe';
  if (level >= 2) return 'moderate';
  if (level === 1) return 'low';
  return 'none';
}

/**
 * Scales the policy threat level onto HDF's 0-1 impact. The threat level is the
 * policy author's risk rating, so it governs every alert type, not only the ones
 * that carry a CVSS score.
 */
export function impactFor(level: number): number {
  if (level <= 0) return 0;
  if (level >= 10) return 1;
  return level / 10;
}

function conditions(trigger: Trigger): ConditionFact[] {
  return (trigger.componentFacts ?? []).flatMap((cf) =>
    (cf.constraintFacts ?? []).flatMap((k) => k.conditionFacts ?? []),
  );
}

function isSecurityAlert(trigger: Trigger): boolean {
  return conditions(trigger).some((c) => c.reference?.type === VULNERABILITY_REF);
}

/**
 * The result file carries CVE ids but no CWE, so there is nothing for the
 * CWE-to-NIST table to resolve; the controls are the static defaults for a
 * vulnerable dependency and for an inventory finding respectively.
 */
function nistFor(trigger: Trigger): string[] {
  return isSecurityAlert(trigger)
    ? [...DEFAULT_REMEDIATION_NIST_TAGS]
    : [...DEFAULT_COMPONENT_MANAGEMENT_NIST_TAGS];
}

function coordinate(id: ComponentIdentifier | null | undefined, key: string): string {
  const v = id?.coordinates?.[key];
  return typeof v === 'string' ? v : '';
}

/** The coordinate IQ uses for the format, then the display name IQ renders. */
function packageName(cf: ComponentFact): string {
  for (const key of ['name', 'packageId', 'artifactId']) {
    const v = coordinate(cf.componentIdentifier, key);
    if (v) return v;
  }
  return cf.displayName?.name ?? '';
}

/**
 * The purl spec's pypi rule (lowercase, "_" to "-"). Only pypi is built because
 * only pypi has a real fixture behind it; a name or version that would need
 * percent-encoding gets no purl rather than a guessed one.
 */
function pypiPurl(name: string, version: string): string {
  if (!PURL_SAFE.test(name) || !PURL_SAFE.test(version)) return '';
  return `pkg:pypi/${name.toLowerCase().replace(/_/g, '-')}@${version}`;
}

export function affectedPackage(cf: ComponentFact): AffectedPackage | undefined {
  const id = cf.componentIdentifier;
  if (!id) return undefined;
  const name = packageName(cf);
  const version = coordinate(id, 'version');
  const purl = (id.format ?? '').toLowerCase() === 'pypi' ? pypiPurl(name, version) : '';
  return buildAffectedPackage({
    name,
    version,
    ecosystem: ecosystemFromPurlType(id.format),
    purl,
  });
}

/** Package coordinates, or for an unidentified component, where it was found. */
function componentLabel(cf: ComponentFact): string {
  if (!cf.componentIdentifier) {
    const path = cf.pathnames?.[0];
    return path ? `${UNKNOWN_COMPONENT} ${path}` : UNKNOWN_COMPONENT;
  }
  let label = `${packageName(cf)} ${coordinate(cf.componentIdentifier, 'version')}`.trim();
  if (!label) label = UNKNOWN_COMPONENT;
  const ext = coordinate(cf.componentIdentifier, 'extension');
  if (ext) label += ` (${ext})`;
  return label;
}

function alertLabel(trigger: Trigger): string {
  const first = trigger.componentFacts?.[0];
  return first ? componentLabel(first) : UNKNOWN_COMPONENT;
}

function distinct(values: (string | undefined)[]): string[] {
  return [...new Set(values.filter((v): v is string => Boolean(v)))];
}

export function externalReferences(trigger: Trigger): ExternalReference[] {
  const ids = distinct(
    conditions(trigger)
      .filter((c) => c.reference?.type === VULNERABILITY_REF)
      .map((c) => c.reference?.value),
  );
  return ids.map((id) => ({
    sourceName: id.toUpperCase().startsWith('CVE-') ? 'cve' : 'nexus-iq',
    externalId: id,
    rel: 'definition',
  }));
}

function nvdRefs(refs: ExternalReference[]): Reference[] {
  return refs
    .filter((r) => r.sourceName === 'cve')
    .map((r) => ({ url: `https://nvd.nist.gov/vuln/detail/${r.externalId}` }));
}

function highestScore(trigger: Trigger): number | undefined {
  let best: number | undefined;
  for (const c of conditions(trigger)) {
    const score = SEVERITY_IN_REASON.exec(c.reason ?? '')?.[1];
    if (score === undefined) continue;
    const v = Number.parseFloat(score);
    if (best === undefined || v > best) best = v;
  }
  return best;
}

function tagsFor(alert: Alert, nist: string[], refs: ExternalReference[]): Record<string, unknown> {
  const t = alert.trigger ?? {};
  const facts = t.componentFacts ?? [];
  const level = t.threatLevel ?? 0;
  const extras: Record<string, unknown> = {
    nistMapping: 'static-fallback',
    policyId: t.policyId ?? '',
    policyName: t.policyName ?? '',
    threatLevel: level,
    threatCategory: threatCategory(level),
  };

  const constraints = distinct(facts.flatMap((cf) => (cf.constraintFacts ?? []).map((k) => k.constraintName)));
  if (constraints.length > 0) extras.constraints = constraints;
  const types = distinct(conditions(t).map((c) => c.conditionTypeId));
  if (types.length > 0) extras.conditionTypes = types;
  const hashes = distinct(facts.map((cf) => cf.hash));
  if (hashes.length > 0) extras.componentHash = hashes;
  const identifiers = facts
    .filter((cf) => cf.componentIdentifier)
    .map((cf) => ({ format: cf.componentIdentifier?.format ?? '', coordinates: cf.componentIdentifier?.coordinates ?? null }));
  if (identifiers.length > 0) extras.componentIdentifier = identifiers;
  const actions = distinct((alert.actions ?? []).map((a) => a.actionTypeId));
  if (actions.length > 0) extras.actions = actions;
  const score = highestScore(t);
  if (score !== undefined) extras.cvssScore = score;
  // The requirement id is IQ's violation id, so this is what a CVE gate matches.
  const cves = refs.filter((r) => r.sourceName === 'cve').map((r) => r.externalId as string);
  if (cves.length > 0) extras.cve = cves;

  return buildNistCciTags(nist, nistToCci(nist), extras);
}

function descriptionsFor(trigger: Trigger): Description[] {
  const level = trigger.threatLevel ?? 0;
  const descriptions: Description[] = [
    {
      label: 'default',
      data: `Nexus IQ policy ${trigger.policyName ?? ''} (threat level ${level}, ${threatCategory(level)}) was violated by ${alertLabel(trigger)}.`,
    },
  ];
  const blocks = (trigger.componentFacts ?? []).flatMap((cf) =>
    (cf.constraintFacts ?? []).map((k) =>
      [`${k.constraintName ?? ''}:`, ...(k.conditionFacts ?? []).map((c) => c.summary ?? '')].join('\n'),
    ),
  );
  if (blocks.length > 0) descriptions.push({ label: 'check', data: blocks.join('\n\n') });
  return descriptions;
}

function resultFor(alert: Alert, index: number, startTime: Date): RequirementResult {
  const t = alert.trigger ?? {};
  let codeDesc = distinct(conditions(t).map((c) => c.reason)).join('\n');
  if (!codeDesc) codeDesc = `${alertLabel(t)} violated ${t.policyName ?? ''}`;

  const result: RequirementResult = {
    // Every alert is a violation IQ found; the attached action (warn, fail or
    // none) is IQ's enforcement choice, not a different finding status.
    status: ResultStatus.Failed,
    codeDesc,
    startTime,
    rawSourceRecord: {
      content: JSON.stringify(alert, null, 2),
      encoding: ExternalReferenceEncoding.UTF8,
      mediaType: 'application/json',
      pointer: `/policyEvaluationResult/alerts/${index}`,
    },
  };
  const paths = distinct((t.componentFacts ?? []).flatMap((cf) => cf.pathnames ?? []));
  if (paths.length > 0) result.message = paths.join('\n');

  const first = t.componentFacts?.[0];
  const pkg = first ? affectedPackage(first) : undefined;
  if (pkg) {
    const id = packageInstanceId(pkg.purl ?? '', pkg.name ?? '', pkg.version ?? '');
    if (id) {
      result.resource = 'package';
      result.resourceId = id;
    }
  }
  return result;
}

function buildRequirement(alert: Alert, index: number, startTime: Date): EvaluatedRequirement {
  const t = alert.trigger ?? {};
  const nist = nistFor(t);
  const packages = (t.componentFacts ?? [])
    .map(affectedPackage)
    .filter((p): p is AffectedPackage => p !== undefined);
  const refs = externalReferences(t);

  const requirement: EvaluatedRequirement = {
    id: t.policyViolationId || `nexusiq-alert-${index}`,
    title: `${alertLabel(t)} — ${t.policyName ?? ''}`,
    impact: impactFor(t.threatLevel ?? 0),
    tags: tagsFor(alert, nist, refs),
    descriptions: descriptionsFor(t),
    verificationMethod: VerificationMethodEnum.Automated,
    results: [resultFor(alert, index, startTime)],
  };
  const controlType = deriveControlTypeFromTags(nist);
  if (controlType !== undefined) requirement.controlType = controlType;
  if (refs.length > 0) {
    requirement.externalReferences = refs;
    requirement.refs = nvdRefs(refs);
  }
  if (packages.length > 0) requirement.affectedPackages = packages;
  return requirement;
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

/**
 * The input guards, shared by conversion and the expected-count check so both
 * accept and reject exactly the same inputs. A document that only resembles a
 * result file is rejected rather than converted to an empty one.
 */
function parseInput(input: string): Report {
  validateInputSize(input, CONVERTER);
  if (!input || input.trim().length === 0) throw new Error(`${CONVERTER}: empty input`);

  const doc = parseJSON<unknown>(input);
  if (
    !isPlainObject(doc) ||
    typeof doc.applicationId !== 'string' ||
    typeof doc.scanId !== 'string' ||
    !isPlainObject(doc.policyEvaluationResult)
  ) {
    throw new Error(`${CONVERTER}: input does not look like a Nexus IQ policy evaluation result`);
  }
  const result = doc.policyEvaluationResult;
  if (result.alerts !== undefined && result.alerts !== null && !Array.isArray(result.alerts)) {
    throw new Error(`${CONVERTER}: policyEvaluationResult.alerts is not an array`);
  }

  // IQ's counters let a missing alerts list be told apart from a clean scan.
  if (!Array.isArray(result.alerts)) {
    const total = VIOLATION_COUNTERS.reduce((sum, key) => {
      const n = result[key];
      return sum + (typeof n === 'number' && Number.isInteger(n) ? n : 0);
    }, 0);
    if (total > 0) {
      throw new Error(`${CONVERTER}: the result reports ${total} policy violations but carries no alerts`);
    }
  }
  return doc as unknown as Report;
}

/** One requirement per alert, or the single no-findings requirement. */
export function expectedRequirementCount(input: string): number {
  const alerts = parseInput(input).policyEvaluationResult.alerts;
  return Array.isArray(alerts) && alerts.length > 0 ? alerts.length : 1;
}

function reportLinks(r: Report): ExternalReference[] {
  const links: [string | undefined, string, string][] = [
    [r.reportHtmlUrl, 'text/html', 'Nexus IQ application report'],
    [r.reportPdfUrl, 'application/pdf', 'Nexus IQ application report (PDF)'],
    [r.reportDataUrl, 'application/json', 'Nexus IQ raw report data'],
  ];
  return links
    .filter(([href]) => typeof href === 'string' && href !== '')
    .map(([href, mediaType, description]) => ({
      sourceName: 'nexus-iq',
      href,
      mediaType,
      description,
      rel: 'investigate',
    }));
}

/**
 * Converts a Nexus IQ CLI policy-evaluation result (Sonatype Lifecycle) to HDF.
 *
 * IQ's GitLab dependency-scanning and CycloneDX exports already convert through
 * the generic gitlab and cyclonedx converters. What only this native file
 * carries is the policy layer: which policy each component violated, its threat
 * level, the constraint and condition that fired, and the action IQ attached.
 */
export async function convertNexusIQToHdf(input: string, converterVersion = '1.0.0'): Promise<string> {
  const report = parseInput(input);
  const result = report.policyEvaluationResult;
  const alerts = Array.isArray(result.alerts) ? result.alerts : [];

  // The result file records no evaluation time.
  const startTime = new Date();
  const requirements = alerts.map((a, i) => buildRequirement(a, i, startTime));
  if (requirements.length === 0) {
    requirements.push(
      buildNoFindingsRequirement(
        'nexusiq-no-findings',
        `Nexus IQ evaluated ${report.applicationId} and reported no policy violations.`,
        startTime,
      ),
    );
  }

  const summary: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(result)) {
    if (key !== 'alerts' && key !== 'sastAlerts') summary[key] = value;
  }
  const context: Record<string, unknown> = {
    applicationId: report.applicationId,
    scanId: report.scanId,
    summary,
  };
  if (report.stage) context.stage = report.stage;
  if (report.policyAction) context.policyAction = report.policyAction;

  let title = `Nexus IQ policy evaluation of ${report.applicationId}`;
  if (report.stage) title += ` (${report.stage} stage)`;
  const baseline: EvaluatedBaseline = {
    name: 'Nexus IQ Policy Evaluation',
    title,
    requirements,
    resultsChecksum: await inputChecksum(input),
  };
  // No real SAST alert has been seen, so none is mapped; say so rather than let
  // them vanish.
  const sast = Array.isArray(result.sastAlerts) ? result.sastAlerts.length : 0;
  if (sast > 0) {
    context.unconvertedSastAlerts = sast;
    baseline.statusMessage = `${sast} SAST alerts in the result were not converted; this converter maps component policy alerts only.`;
  }
  baseline.extensions = { passthrough: { nexusiq: context } };

  const links = reportLinks(report);
  return buildHdfResults({
    generatorName: 'nexusiq-to-hdf',
    converterVersion,
    toolName: 'Nexus IQ Server',
    toolFormat: 'json',
    baselines: [baseline],
    components: [
      {
        type: TargetType.Application,
        name: report.applicationId,
        externalIds: { 'nexus-iq': report.applicationId },
      },
    ],
    timestamp: startTime,
    ...(links.length > 0 ? { externalReferences: links } : {}),
  });
}
