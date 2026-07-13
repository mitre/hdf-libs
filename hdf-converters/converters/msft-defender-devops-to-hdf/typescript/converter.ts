import { parseJSON } from '@mitre/hdf-utilities';
import { convertSarifToHdf } from '../../sarif-to-hdf/typescript/converter.js';
import { buildNoFindingsRequirement, validateInputSize } from '../../../shared/typescript/converterutil.js';
import type { HDFResults, Component } from '@mitre/hdf-schema';
import { TargetType } from '@mitre/hdf-schema';

// --- MSDO-specific SARIF type definitions ---
// These capture fields that the generic SARIF converter ignores.

interface MsdoSarif {
  runs: MsdoRun[];
}

interface MsdoRun {
  tool: {
    driver: MsdoDriver;
  };
  versionControlProvenance?: VersionControlProvenance[];
  policies?: MsdoPolicy[];
  results?: MsdoResult[];
}

interface MsdoDriver {
  name?: string;
  organization?: string;
  product?: string;
  fullName?: string;
  properties?: Record<string, unknown>;
}

interface VersionControlProvenance {
  repositoryUri: string;
  revisionId?: string;
  branch?: string;
}

interface MsdoPolicy {
  name: string;
  version: string;
}

interface MsdoResult {
  ruleId: string;
  properties?: Record<string, unknown>;
}

interface RunEnrichment {
  toolTags: Record<string, unknown>;
  policyTag: string;
  resultProps: Map<string, Record<string, unknown>[]>;
}

/**
 * Converts Microsoft Defender for DevOps SARIF output to HDF format.
 * Delegates base conversion to the generic SARIF converter and enriches
 * the output with MSDO-specific metadata.
 */
export async function convertMsftDefenderDevopsToHdf(input: string, converterVersion = '1.0.0'): Promise<string> {
  validateInputSize(input, 'msft-defender-devops');

  // 1. Parse raw SARIF to extract MSDO-specific fields
  const raw = parseJSON<MsdoSarif>(input);
  if (!raw || !Array.isArray(raw.runs)) {
    throw new Error('Invalid MSDO SARIF structure: missing or invalid runs field');
  }
  const { components, runEnrichments } = extractEnrichments(raw);

  // 2. Delegate to the generic SARIF converter for base HDF
  const hdfJson = await convertSarifToHdf(input, converterVersion);
  const result = JSON.parse(hdfJson) as HDFResults;

  // Run before applyEnrichments so synthesized reqs get the same run-level tags.
  synthesizeNoFindingsPlaceholders(result);
  applyEnrichments(result, components, runEnrichments);

  // 4. Override generator name and data source
  if (result.generator) {
    result.generator.name = 'msft-defender-devops-to-hdf';
  }
  if (result.tool) {
    result.tool.name = 'Microsoft Defender for DevOps';
  }

  return JSON.stringify(result, null, 2);
}

function extractEnrichments(raw: MsdoSarif): {
  components: Component[];
  runEnrichments: RunEnrichment[];
} {
  const components: Component[] = [];
  const seenRepos = new Set<string>();
  const runEnrichments: RunEnrichment[] = [];

  for (const run of raw.runs) {
    // Extract repository components from versionControlProvenance
    for (const vcp of run.versionControlProvenance ?? []) {
      if (vcp.repositoryUri && !seenRepos.has(vcp.repositoryUri)) {
        seenRepos.add(vcp.repositoryUri);
        const target: Component = {
          name: repoNameFromURI(vcp.repositoryUri),
          type: TargetType.Repository,
          url: vcp.repositoryUri,
        };
        if (vcp.branch) {
          target.branch = vcp.branch;
        }
        if (vcp.revisionId) {
          target.commit = vcp.revisionId;
        }
        components.push(target);
      }
    }

    // Extract tool metadata tags
    const toolTags: Record<string, unknown> = {};
    const driver = run.tool.driver;
    if (driver.organization) {
      toolTags.msdo_organization = driver.organization;
    }
    if (driver.product) {
      toolTags.msdo_product = driver.product;
    }
    if (driver.fullName) {
      toolTags.msdo_fullName = driver.fullName;
    }
    if (driver.properties?.RawName) {
      toolTags.msdo_rawName = driver.properties.RawName;
    }
    if (driver.properties?.IsPreview !== undefined) {
      toolTags.msdo_isPreview = driver.properties.IsPreview;
    }

    // Extract policy tags
    let policyTag = '';
    if (run.policies && run.policies.length > 0) {
      policyTag = run.policies.map(p => `${p.name} ${p.version}`).join(', ');
    }

    // Extract result-level properties keyed by ruleId
    const resultProps = new Map<string, Record<string, unknown>[]>();
    for (const res of run.results ?? []) {
      if (res.properties && Object.keys(res.properties).length > 0) {
        const existing = resultProps.get(res.ruleId) ?? [];
        existing.push(res.properties);
        resultProps.set(res.ruleId, existing);
      }
    }

    runEnrichments.push({ toolTags, policyTag, resultProps });
  }

  return { components, runEnrichments };
}

function applyEnrichments(
  result: HDFResults,
  components: Component[],
  runEnrichments: RunEnrichment[],
): void {
  // Add components
  if (components.length > 0) {
    result.components = components;
  }

  // Apply per-baseline (per-run) enrichments
  const baselines = result.baselines ?? [];
  for (let i = 0; i < baselines.length && i < runEnrichments.length; i++) {
    const re = runEnrichments[i]!;
    const requirements = baselines[i]!.requirements ?? [];

    for (const req of requirements) {
      const tags = (req.tags ?? {}) as Record<string, unknown>;

      // Add tool metadata tags
      for (const [k, v] of Object.entries(re.toolTags)) {
        tags[k] = v;
      }

      // Add policy tag
      if (re.policyTag) {
        tags.msdo_policy = re.policyTag;
      }

      // Add result-level properties for this requirement's ruleId
      const props = re.resultProps.get(req.id);
      if (props && props.length > 0) {
        tags.msdo_properties = props[0];
      }

      req.tags = tags;
    }
  }
}

// HDF requires requirements.minItems=1; SARIF's empty results[] means the
// scan ran clean (§3.7.2), so synthesize one passed placeholder per baseline.
function synthesizeNoFindingsPlaceholders(result: HDFResults): void {
  const startTime = result.timestamp ?? new Date();
  for (const baseline of result.baselines ?? []) {
    if (baseline.requirements && baseline.requirements.length > 0) continue;
    const tool = baseline.name;
    baseline.requirements = [
      buildNoFindingsRequirement(
        `${tool}-no-findings`,
        `Microsoft Defender for DevOps scanner "${tool}" ran and reported zero findings.`,
        startTime,
      ),
    ];
  }
}

function repoNameFromURI(uri: string): string {
  const parts = uri.split('/');
  const name = parts[parts.length - 1];
  return name || uri;
}
