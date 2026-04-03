import { parseJSON } from '@mitre/hdf-utilities';
import type {
  EvaluatedBaseline,
  EvaluatedRequirement,
  Checksum,
} from '@mitre/hdf-schema';
import {
  ResultStatus,
  createMinimalBaseline,
  createRequirement,
  createDescription,
  createResult,
} from '@mitre/hdf-schema';
import {
  nistToCci,
  DEFAULT_COMPONENT_MANAGEMENT_NIST_TAGS,
} from '@mitre/hdf-mappings';
import {
  inputChecksum,
  buildNistCciTags,
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
  data: ScanData;
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

function buildTags(
  dep: ContextualizedDependency,
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

  return buildNistCciTags(nist, cciTags, extras);
}

// ---- Main converter ----

export async function convertIonchannelToHdf(input: string): Promise<string> {
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

  // Extract dependencies from dependency scan
  let allDeps: Dependency[] = [];
  for (const scan of analysis.scan_summaries) {
    if (scan.name === 'dependency') {
      allDeps = scan.results?.data?.dependencies ?? [];
      break;
    }
  }

  // Flatten and contextualize
  const contextDeps = buildDependencyGraph(allDeps);

  // Build requirements
  const requirements: EvaluatedRequirement[] = contextDeps.map((dep) => {
    const depId = `dependency-${dep.org}/${dep.name}`;
    const title = buildTitle(dep);
    const tags = buildTags(dep);
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
    const results = [
      createResult(ResultStatus.NotReviewed, 'Dependency inventory item', {
        codeDesc: 'Dependency inventory item',
        startTime: new Date('0001-01-01T00:00:00Z'),
      }),
    ];

    const req = createRequirement(depId, title, descriptions, 0.0, results, {
      tags,
    }) as EvaluatedRequirement;
    req.code = code;
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

  return buildHdfResults({
    generatorName: 'ionchannel-to-hdf',
    converterVersion: '1.0.0',
    toolName: 'Ion Channel',
    toolFormat: 'JSON',
    baselines: [baseline],
    timestamp: new Date(),
  });
}
