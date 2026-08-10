import { parseJSON, parseTimestamp } from '@mitre/hdf-utilities';
import type {
  EvaluatedBaseline,
  EvaluatedRequirement,
  RequirementResult,
  Checksum,
} from '@mitre/hdf-schema';
import {
  ResultStatus,
  VerificationMethodEnum,
  createMinimalBaseline,
  createRequirement,
  createDescription,
} from '@mitre/hdf-schema';
import {
  nistToCci,
  DEFAULT_COMPONENT_MANAGEMENT_NIST_TAGS,
} from '@mitre/hdf-mappings';
import {
  inputChecksum,
  buildNistCciTags,
  deriveControlTypeFromTags,
  validateInputSize,
  buildHdfResults,
} from '../../../shared/typescript/converterutil.js';

// ---- Input types ----

interface IonChannelAnalysis {
  id: string;
  analysis_id: string;
  team_id: string;
  project_id: string;
  name: string;
  text: string;
  type: string;
  source: string;
  branch: string;
  description: string;
  risk: string;
  summary: string;
  passed: boolean;
  ruleset_id: string;
  ruleset_name: string;
  status: string;
  created_at: string;
  updated_at: string;
  duration: number;
  trigger_hash: string;
  trigger_text: string;
  trigger_author: string;
  trigger: string;
  public: boolean;
  scan_summaries: ScanSummary[];
}

interface ScanSummary {
  id: string;
  team_id: string;
  project_id: string;
  analysis_id: string;
  summary: string;
  results: ScanResults;
  created_at: string;
  updated_at: string;
  duration: number;
  name: string;
  description: string;
}

interface ScanResults {
  type: string;
  // Kept as unknown so non-dependency scan types (community, vulnerability,
  // license, virus, …) are preserved verbatim rather than narrowed to the
  // dependency shape.
  data: ScanData & Record<string, unknown>;
}

interface ScanData {
  dependencies?: Dependency[];
}

interface Dependency {
  latest_version: string;
  org: string;
  name: string;
  type: string;
  package: string;
  version: string;
  scope: string;
  requirement: string;
  file: string;
  outdated_version: OutdatedVersion;
  dependencies: Dependency[];
}

interface OutdatedVersion {
  major_behind: number;
  minor_behind: number;
  patch_behind: number;
}

interface ContextualizedDependency extends Dependency {
  parentDependencies: string[];
}

// ---- Helpers ----

function extractAllDependencies(dep: Dependency): ContextualizedDependency[] {
  const result: ContextualizedDependency[] = [
    { ...dep, parentDependencies: [] },
  ];
  if (Array.isArray(dep.dependencies)) {
    for (const sub of dep.dependencies) {
      result.push(...extractAllDependencies(sub));
    }
  }
  return result;
}

function buildDependencyGraph(deps: Dependency[]): ContextualizedDependency[] {
  const graph = new Map<string, ContextualizedDependency>();

  // Flatten all dependencies
  for (const topLevel of deps) {
    for (const flat of extractAllDependencies(topLevel)) {
      const key = `${flat.org}/${flat.name}`;
      if (!graph.has(key)) {
        graph.set(key, flat);
      }
    }
  }

  // Associate parent relationships
  for (const dep of graph.values()) {
    if (Array.isArray(dep.dependencies)) {
      for (const sub of dep.dependencies) {
        const subKey = `${sub.org}/${sub.name}`;
        const child = graph.get(subKey);
        if (child) {
          const parentKey = `${dep.org}/${dep.name}`;
          child.parentDependencies.push(parentKey);
        }
      }
    }
  }

  return Array.from(graph.values());
}

function buildTitle(dep: Dependency): string {
  // Python editable install special case
  if (dep.type === 'pypi' && dep.package === 'egg' && dep.name === '-e') {
    return `Python requirements file ${dep.file}`;
  }

  let title = `Dependency ${dep.name} `;
  if (dep.org && dep.org.toLowerCase() !== 'n/a') {
    title += `from ${dep.org} `;
  }
  if (dep.version && dep.version.toLowerCase() !== 'n/a') {
    title += `@ ${dep.version} `;
  }
  if (dep.requirement && dep.requirement.toLowerCase() !== 'n/a') {
    title += `(Required ${dep.requirement}) `;
  }
  return title.trim();
}

// Analysis-level verdict metadata attached to every requirement built from the
// analysis. risk/ruleset_name/ruleset_id are omitted when the source leaves them
// empty; passed is always present as its native boolean (distinct from the
// string form carried in the baseline labels).
function analysisTags(a: IonChannelAnalysis): Record<string, unknown> {
  const tags: Record<string, unknown> = { passed: a.passed };
  if (a.risk) tags.risk = a.risk;
  if (a.ruleset_name) tags.ruleset_name = a.ruleset_name;
  if (a.ruleset_id) tags.ruleset_id = a.ruleset_id;
  return tags;
}

function buildTags(
  dep: ContextualizedDependency,
  analysis: IonChannelAnalysis,
): Record<string, unknown> {
  const nist = DEFAULT_COMPONENT_MANAGEMENT_NIST_TAGS;
  const cciTags = nistToCci(nist);

  const extras: Record<string, unknown> = {
    org: dep.org,
    name: dep.name,
    type: dep.type,
    version: dep.version,
    latest_version: dep.latest_version,
    scope: dep.scope,
    requirement: dep.requirement,
    file: dep.file,
  };

  if (Array.isArray(dep.dependencies) && dep.dependencies.length > 0) {
    extras.dependencies = dep.dependencies.map((sub) => sub.name);
  }

  if (dep.parentDependencies.length > 0) {
    extras.parentDependencies = dep.parentDependencies;
  }

  Object.assign(extras, analysisTags(analysis));

  return buildNistCciTags(nist, cciTags, extras);
}

function titleCaseFirst(s: string): string {
  return s ? s.charAt(0).toUpperCase() + s.slice(1) : s;
}

// A scan summary's start time: created_at (when the scan began), falling back to
// updated_at, then the sentinel when the source carries neither. The sentinel
// mirrors Go's zero time.Time so both languages emit the same startTime on a
// timeless scan.
function scanStartTime(scan: ScanSummary): Date {
  return (
    parseTimestamp(scan.created_at) ??
    parseTimestamp(scan.updated_at) ??
    new Date('0001-01-01T00:00:00Z')
  );
}

// The document timestamp: the analysis updated_at (completion / last-update
// time), falling back to created_at, then wall-clock now() when the source
// carries no parseable analysis time. Source-derived so converting the same
// input twice yields the same top-level timestamp.
function analysisTimestamp(a: IonChannelAnalysis): Date {
  return parseTimestamp(a.updated_at) ?? parseTimestamp(a.created_at) ?? new Date();
}

// Build the single inventory requirement for a non-dependency scan summary. The
// scan's serializable result data is preserved verbatim in the code field
// (JSON.stringify preserves source key order, matching the Go json.Indent twin).
function buildScanRequirement(
  scan: ScanSummary,
  analysis: IonChannelAnalysis,
): EvaluatedRequirement {
  const title = scan.description || `${titleCaseFirst(scan.name)} scan`;
  const desc = scan.summary || `${titleCaseFirst(scan.name)} scan summary`;

  const descriptions = [createDescription('default', desc)];
  const results: RequirementResult[] = [
    {
      status: ResultStatus.NotReviewed,
      codeDesc: `${scan.name} scan summary`,
      startTime: scanStartTime(scan),
    },
  ];

  const req = createRequirement(`scan-${scan.name}`, title, descriptions, 0.0, results, {
    tags: { name: scan.name, type: scan.results?.type ?? '', ...analysisTags(analysis) },
  }) as EvaluatedRequirement;
  req.code = JSON.stringify(scan.results?.data ?? {}, null, 2);
  req.verificationMethod = VerificationMethodEnum.Automated;
  return req;
}

// Render the analysis-level ruleset verdict as prose.
function verdictDescription(a: IonChannelAnalysis): string {
  const outcome = a.passed ? 'PASSED' : 'FAILED';
  let desc = `Ion Channel analysis verdict: ${outcome}`;
  if (a.risk) desc += ` (risk: ${a.risk})`;
  if (a.ruleset_name) {
    desc += `. Ruleset: ${a.ruleset_name}`;
    if (a.ruleset_id) desc += ` (${a.ruleset_id})`;
  }
  return `${desc}.`;
}

// Surface the structured analysis-level verdict as queryable baseline labels
// (well-known-key grouping map). Values are strings; only non-empty fields are
// included, and passed is always present.
function verdictLabels(a: IonChannelAnalysis): Record<string, string> {
  const labels: Record<string, string> = { passed: String(a.passed) };
  if (a.risk) labels.risk = a.risk;
  if (a.ruleset_name) labels.ruleset_name = a.ruleset_name;
  if (a.ruleset_id) labels.ruleset_id = a.ruleset_id;
  return labels;
}

// ---- Main converter ----

export async function convertIonchannelToHdf(input: string, converterVersion = '1.0.0'): Promise<string> {
  if (!input?.trim()) {
    throw new Error('Empty input');
  }

  validateInputSize(input, 'ionchannel');

  const analysis = parseJSON<IonChannelAnalysis>(input);

  if (!Array.isArray(analysis.scan_summaries)) {
    throw new Error(
      `Ion Channel scan_summaries invalid summary data (expecting array, got ${typeof analysis.scan_summaries})`,
    );
  }

  // Extract dependencies from dependency scan; collect every other scan summary
  // for its own baseline.
  let allDeps: Dependency[] = [];
  const nonDepScans: ScanSummary[] = [];
  let foundDep = false;
  for (const scan of analysis.scan_summaries) {
    if (scan.name === 'dependency' && !foundDep) {
      allDeps = scan.results?.data?.dependencies ?? [];
      foundDep = true;
      continue;
    }
    nonDepScans.push(scan);
  }

  // Flatten and contextualize
  const contextDeps = buildDependencyGraph(allDeps);

  // Build requirements
  const requirements: EvaluatedRequirement[] = contextDeps.map((dep) => {
    const depId = `dependency-${dep.org}/${dep.name}`;
    const title = buildTitle(dep);
    const tags = buildTags(dep, analysis);
    const code = JSON.stringify(
      {
        latest_version: dep.latest_version,
        org: dep.org,
        name: dep.name,
        type: dep.type,
        package: dep.package,
        version: dep.version,
        scope: dep.scope,
        requirement: dep.requirement,
        file: dep.file,
        outdated_version: dep.outdated_version,
        dependencies: dep.dependencies,
      } as Dependency,
      null,
      2,
    );

    const descriptions = [
      createDescription('default', `Dependency ${dep.org}/${dep.name}`),
    ];
    const results: RequirementResult[] = [
      {
        status: ResultStatus.NotReviewed,
        codeDesc: 'Dependency inventory item',
        startTime: new Date('0001-01-01T00:00:00Z'),
      },
    ];

    const req = createRequirement(depId, title, descriptions, 0.0, results, {
      tags,
    }) as EvaluatedRequirement;
    req.code = code;
    const controlType = deriveControlTypeFromTags(DEFAULT_COMPONENT_MANAGEMENT_NIST_TAGS);
    if (controlType !== undefined) {
      req.controlType = controlType;
    }
    req.verificationMethod = VerificationMethodEnum.Automated;
    return req;
  });

  const resultsChecksum: Checksum = await inputChecksum(input);

  const baseline = createMinimalBaseline(
    'Ion Channel SBOM Analysis',
    requirements,
    {
      title: `Ion Channel Analysis of ${analysis.source}`,
      summary: analysis.summary,
      integrity: { algorithm: resultsChecksum.algorithm, checksum: resultsChecksum.value },
      status: 'loaded',
    },
  ) as EvaluatedBaseline;
  baseline.maintainer = 'saf@groups.mitre.org';
  baseline.description = verdictDescription(analysis);
  baseline.labels = verdictLabels(analysis);

  const baselines: EvaluatedBaseline[] = [baseline];

  // One baseline per non-dependency scan summary, grouped by scan-summary name.
  for (const scan of nonDepScans) {
    const scanBaseline = createMinimalBaseline(
      `Ion Channel ${scan.name} Scan`,
      [buildScanRequirement(scan, analysis)],
      {
        title: `Ion Channel Analysis of ${analysis.source}`,
        summary: scan.summary,
        integrity: { algorithm: resultsChecksum.algorithm, checksum: resultsChecksum.value },
        status: 'loaded',
      },
    ) as EvaluatedBaseline;
    scanBaseline.maintainer = 'saf@groups.mitre.org';
    baselines.push(scanBaseline);
  }

  return buildHdfResults({
    generatorName: 'ionchannel-to-hdf',
    converterVersion,
    toolName: 'Ion Channel',
    baselines,
    timestamp: analysisTimestamp(analysis),
  });
}
