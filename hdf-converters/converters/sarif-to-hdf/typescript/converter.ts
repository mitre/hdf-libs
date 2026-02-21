import { createHash } from 'crypto';
import { parseJSON } from '@mitre/hdf-utilities';
import {
  getCweNistControl,
  nistToCci,
  DEFAULT_STATIC_ANALYSIS_NIST_TAGS,
} from '@mitre/hdf-mappings';
import type { HdfResults, EvaluatedBaseline, EvaluatedRequirement, RequirementResult, Checksum, DataSource, Description } from '@mitre/hdf-schema';
import { ResultStatus, HashAlgorithm, createMinimalBaseline, createRequirement, createDescription, createResult } from '@mitre/hdf-schema';

// --- SARIF 2.1.0 type definitions ---

interface SarifFile {
  $schema?: string;
  version: string;
  runs: SarifRun[];
}

interface SarifRun {
  tool?: {
    driver?: SarifDriver;
  };
  results: SarifResult[];
  taxonomies?: SarifTaxonomy[];
}

interface SarifDriver {
  name?: string;
  version?: string;
  informationUri?: string;
  rules?: ReportingDescriptor[];
}

interface ReportingDescriptor {
  id: string;
  name?: string;
  shortDescription?: MultiformatMessage;
  fullDescription?: MultiformatMessage;
  helpUri?: string;
  help?: MultiformatMessage;
  defaultConfiguration?: ReportingConfiguration;
  relationships?: ReportingDescriptorRelation[];
  properties?: Record<string, unknown>;
}

interface MultiformatMessage {
  text: string;
  markdown?: string;
}

interface ReportingConfiguration {
  level?: string;
}

interface ReportingDescriptorRelation {
  target: DescriptorReference;
  kinds?: string[];
}

interface DescriptorReference {
  id: string;
  guid?: string;
  toolComponent?: ToolComponentReference;
}

interface ToolComponentReference {
  name: string;
  guid?: string;
}

interface SarifTaxonomy {
  name: string;
  version?: string;
  organization?: string;
  taxa?: ReportingDescriptor[];
}

interface SarifResult {
  ruleId: string;
  ruleIndex?: number;
  kind?: string;
  level?: string;
  message: {
    text: string;
  };
  locations?: SarifLocation[];
  relatedLocations?: SarifLocation[];
  suppressions?: Suppression[];
  fixes?: Fix[];
  codeFlows?: CodeFlow[];
  fingerprints?: Record<string, string>;
  partialFingerprints?: Record<string, string>;
}

interface Suppression {
  kind: string;
  status?: string;
  justification?: string;
}

interface Fix {
  description?: {
    text: string;
  };
}

interface CodeFlow {
  threadFlows: ThreadFlow[];
}

interface ThreadFlow {
  locations: ThreadFlowLocation[];
}

interface ThreadFlowLocation {
  location: SarifLocation;
  importance?: string;
}

interface SarifLocation {
  id?: number;
  physicalLocation?: {
    artifactLocation?: {
      uri?: string;
    };
    region?: {
      startLine?: number;
      startColumn?: number;
      endLine?: number;
      endColumn?: number;
      snippet?: {
        text: string;
      };
    };
  };
  message?: {
    text: string;
  };
}

// --- Impact mapping ---

const IMPACT_MAPPING: Record<string, number> = {
  error: 0.7,
  warning: 0.5,
  note: 0.3,
};

// --- Conversion entry point ---

export function convertSarifToHdf(input: string): string {
  const resultsChecksum: Checksum = {
    algorithm: HashAlgorithm.Sha256,
    value: createHash('sha256').update(input).digest('hex'),
  };

  const sarif = parseJSON<SarifFile>(input);

  if (!sarif || typeof sarif !== 'object') {
    throw new Error('Invalid SARIF structure: not a valid JSON object');
  }

  if (!Array.isArray(sarif.runs)) {
    throw new Error('Invalid SARIF structure: missing or invalid runs field');
  }

  const dataSource: DataSource = { format: 'SARIF' };
  const firstDriver = sarif.runs[0]?.tool?.driver;
  if (firstDriver) {
    if (firstDriver.name) {
      dataSource.name = firstDriver.name;
    }
    if (firstDriver.version) {
      dataSource.version = firstDriver.version;
    }
  }

  const hdf: HdfResults = {
    timestamp: new Date(),
    baselines: sarif.runs.map(run => convertRun(run, sarif.version, resultsChecksum)),
    targets: [],
    generator: {
      name: 'sarif-to-hdf',
      version: '1.0.0',
    },
    dataSource,
  };

  return JSON.stringify(hdf, null, 2);
}

// --- Run-level conversion ---

function convertRun(run: SarifRun, version: string, resultsChecksum: Checksum): EvaluatedBaseline {
  const ruleMap = buildRuleMap(run);

  const requirements = run.results.map(result => {
    const rule = ruleMap.get(result.ruleId);
    return convertResult(result, rule);
  });

  // Use tool name for baseline name if available
  const baselineName = run.tool?.driver?.name || 'SARIF';

  return createMinimalBaseline(baselineName, requirements, {
    version,
    title: 'Static Analysis Results Interchange Format',
    resultsChecksum,
  });
}

function buildRuleMap(run: SarifRun): Map<string, ReportingDescriptor> {
  const map = new Map<string, ReportingDescriptor>();
  if (run.tool?.driver?.rules) {
    for (const rule of run.tool.driver.rules) {
      map.set(rule.id, rule);
    }
  }
  return map;
}

// --- Result-level conversion ---

function convertResult(result: SarifResult, rule?: ReportingDescriptor): EvaluatedRequirement {
  const messageText = result.message.text;

  // Determine title and description
  const { title, description } = deriveMetadata(result, rule);

  // Extract CWE IDs with priority: relationships > properties.tags > message regex
  let cweIds = extractCweFromRule(rule);
  if (cweIds.length === 0) {
    cweIds = extractCweIds(messageText);
  }

  const nistControls = mapCweToNist(cweIds);
  const cciControls = nistToCci(nistControls);

  // Resolve level with fallback chain
  const resolvedLevel = resolveLevel(result, rule);

  // Map level to impact
  let impact = IMPACT_MAPPING[resolvedLevel] || 0.1;

  // Map kind to HDF status
  let status = mapKindToStatus(result.kind);

  // Handle suppressions
  let suppressionJustification = '';
  if (status === ResultStatus.Failed || status === ResultStatus.Passed) {
    const suppResult = applySuppression(result.suppressions);
    if (suppResult.suppressed) {
      status = ResultStatus.NotReviewed;
      suppressionJustification = suppResult.justification;
    }
  }

  // For non-fail kinds, impact is 0
  if (result.kind && result.kind !== 'fail') {
    impact = 0.0;
  }

  // Source location from first location
  const sourceLocation = result.locations && result.locations.length > 0
    ? extractSourceLocation(result.locations[0]!)
    : undefined;

  // Build backtrace from code flows
  const backtrace = extractBacktrace(result.codeFlows);

  // Create results for each location
  const results: RequirementResult[] = (result.locations || [])
    .filter(loc => loc.physicalLocation?.artifactLocation?.uri)
    .map(loc => createHDFResult(loc, status, backtrace, suppressionJustification));

  // Build descriptions
  const descriptions = buildDescriptions(description, rule, result);

  // Build tags
  const tags = buildTags(result, rule, resolvedLevel, cweIds, nistControls, cciControls);

  const options: {
    sourceLocation?: { ref: string; line: number };
    tags: Record<string, unknown>;
  } = { tags };

  if (sourceLocation) {
    options.sourceLocation = sourceLocation;
  }

  return createRequirement(
    result.ruleId,
    title,
    descriptions,
    impact,
    results,
    options
  );
}

// --- Metadata derivation ---

function deriveMetadata(result: SarifResult, rule?: ReportingDescriptor): { title: string; description: string } {
  if (rule?.name) {
    return { title: rule.name, description: result.message.text };
  }
  return parseMessage(result.message.text);
}

function parseMessage(text: string): { title: string; description: string } {
  const colonIndex = text.indexOf(':');
  if (colonIndex === -1) {
    return { title: text, description: '' };
  }
  return {
    title: text.substring(0, colonIndex).trim(),
    description: text.substring(colonIndex + 1).trim(),
  };
}

// --- CWE extraction with priority ---

function extractCweFromRule(rule?: ReportingDescriptor): string[] {
  if (!rule) {
    return [];
  }

  // Priority 1: rule.relationships where toolComponent.name == "CWE"
  if (rule.relationships) {
    const cweIds: string[] = [];
    for (const rel of rule.relationships) {
      if (rel.target.toolComponent?.name?.toLowerCase() === 'cwe') {
        cweIds.push(`CWE-${rel.target.id}`);
      }
    }
    if (cweIds.length > 0) {
      return cweIds;
    }
  }

  // Priority 2: rule.properties.tags containing CWE-\d+ patterns
  if (rule.properties?.tags && Array.isArray(rule.properties.tags)) {
    const cweTagPattern = /^CWE-\d+$/;
    const cweIds: string[] = [];
    for (const tag of rule.properties.tags as string[]) {
      if (typeof tag === 'string' && cweTagPattern.test(tag)) {
        cweIds.push(tag);
      }
    }
    if (cweIds.length > 0) {
      return cweIds;
    }
  }

  return [];
}

function extractCweIds(text: string): string[] {
  const cwePattern = /\(([^)]+)\)/g;
  const matches = text.match(cwePattern);

  if (!matches) {
    return [];
  }

  const cweIds: string[] = [];
  for (const match of matches) {
    const content = match.slice(1, -1);
    if (content.includes('CWE-')) {
      const parts = content.split(/,\s*|!\//);
      for (const part of parts) {
        const trimmed = part.trim();
        if (trimmed.startsWith('CWE-')) {
          cweIds.push(trimmed);
        }
      }
    }
  }

  return cweIds;
}

function mapCweToNist(cweIds: string[]): string[] {
  if (cweIds.length === 0) {
    return DEFAULT_STATIC_ANALYSIS_NIST_TAGS;
  }

  const nistSet = new Set<string>();
  for (const cweId of cweIds) {
    const numericId = parseInt(cweId.replace('CWE-', ''), 10);
    if (isNaN(numericId)) {
      continue;
    }
    const nistControl = getCweNistControl(numericId);
    if (nistControl) {
      nistSet.add(nistControl);
    }
  }

  if (nistSet.size === 0) {
    return DEFAULT_STATIC_ANALYSIS_NIST_TAGS;
  }

  return Array.from(nistSet);
}

// --- Level resolution ---

function resolveLevel(result: SarifResult, rule?: ReportingDescriptor): string {
  if (result.kind && result.kind !== 'fail') {
    return 'none';
  }
  if (result.level) {
    return result.level;
  }
  if (rule?.defaultConfiguration?.level) {
    return rule.defaultConfiguration.level;
  }
  return 'warning';
}

// --- Kind → Status mapping ---

function mapKindToStatus(kind?: string): ResultStatus {
  switch (kind) {
    case 'pass':
      return ResultStatus.Passed;
    case 'open':
      return ResultStatus.Failed;
    case 'review':
      return ResultStatus.NotReviewed;
    case 'informational':
      return ResultStatus.NotApplicable;
    case 'notApplicable':
      return ResultStatus.NotApplicable;
    default: // "fail" or undefined
      return ResultStatus.Failed;
  }
}

// --- Suppression handling ---

function applySuppression(suppressions?: Suppression[]): { suppressed: boolean; justification: string } {
  if (!suppressions || suppressions.length === 0) {
    return { suppressed: false, justification: '' };
  }

  const justifications: string[] = [];
  let hasSuppression = false;

  for (const s of suppressions) {
    if (s.status === 'rejected') {
      continue;
    }
    hasSuppression = true;
    if (s.justification) {
      justifications.push(s.justification);
    }
  }

  if (!hasSuppression) {
    return { suppressed: false, justification: '' };
  }

  return { suppressed: true, justification: justifications.join('; ') };
}

// --- Code flow → backtrace ---

function extractBacktrace(codeFlows?: CodeFlow[]): string[] {
  if (!codeFlows || codeFlows.length === 0) {
    return [];
  }

  const backtrace: string[] = [];
  for (const cf of codeFlows) {
    for (const tf of cf.threadFlows) {
      for (const tfl of tf.locations) {
        const loc = tfl.location;
        const uri = loc.physicalLocation?.artifactLocation?.uri || '';
        const line = loc.physicalLocation?.region?.startLine || 0;
        const msg = loc.message?.text || '';

        let entry = `${uri}:${line}`;
        if (msg) {
          entry = `${uri}:${line} - ${msg}`;
        }
        backtrace.push(entry);
      }
    }
  }

  return backtrace;
}

// --- Description building ---

function buildDescriptions(defaultDesc: string, rule: ReportingDescriptor | undefined, result: SarifResult): Description[] {
  const descriptions: Description[] = [
    createDescription('default', defaultDesc),
  ];

  if (rule) {
    if (rule.fullDescription?.text) {
      descriptions.push(createDescription('rationale', rule.fullDescription.text));
    } else if (rule.shortDescription?.text && !defaultDesc) {
      descriptions[0] = createDescription('default', rule.shortDescription.text);
    }

    if (rule.help?.text) {
      descriptions.push(createDescription('check', rule.help.text));
    }
  }

  if (result.fixes && result.fixes.length > 0 && result.fixes[0]?.description?.text) {
    descriptions.push(createDescription('fix', result.fixes[0].description.text));
  }

  return descriptions;
}

// --- Tag building ---

function buildTags(
  result: SarifResult,
  rule: ReportingDescriptor | undefined,
  resolvedLevel: string,
  cweIds: string[],
  nistControls: string[],
  cciControls: string[]
): Record<string, unknown> {
  const tags: Record<string, unknown> = {
    severity: resolvedLevel,
    cwe: cweIds,
    nist: nistControls,
    cci: cciControls,
  };

  if (result.kind) {
    tags.kind = result.kind;
  }

  if (rule?.helpUri) {
    tags.helpUri = rule.helpUri;
  }

  if (result.suppressions && result.suppressions.length > 0) {
    tags.suppressions = result.suppressions.map(s => {
      const entry: Record<string, string> = { kind: s.kind };
      if (s.status) {
        entry.status = s.status;
      }
      if (s.justification) {
        entry.justification = s.justification;
      }
      return entry;
    });
  }

  if ((result.fingerprints && Object.keys(result.fingerprints).length > 0) ||
      (result.partialFingerprints && Object.keys(result.partialFingerprints).length > 0)) {
    const fp: Record<string, unknown> = {};
    if (result.fingerprints && Object.keys(result.fingerprints).length > 0) {
      fp.fingerprints = result.fingerprints;
    }
    if (result.partialFingerprints && Object.keys(result.partialFingerprints).length > 0) {
      fp.partialFingerprints = result.partialFingerprints;
    }
    tags.fingerprints = fp;
  }

  return tags;
}

// --- Location helpers ---

function extractSourceLocation(location: SarifLocation): { ref: string; line: number } | undefined {
  const uri = location.physicalLocation?.artifactLocation?.uri;
  const line = location.physicalLocation?.region?.startLine;

  if (!uri || !line) {
    return undefined;
  }

  return { ref: uri, line };
}

function createHDFResult(
  location: SarifLocation,
  status: ResultStatus,
  backtrace: string[],
  suppressionMessage?: string
): RequirementResult {
  const uri = location.physicalLocation?.artifactLocation?.uri || '';
  const line = location.physicalLocation?.region?.startLine || 0;
  const column = location.physicalLocation?.region?.startColumn || 0;
  const snippet = location.physicalLocation?.region?.snippet?.text;

  let codeDesc = `URL : ${uri} LINE : ${line} COLUMN : ${column}`;
  if (snippet) {
    codeDesc = `${codeDesc}\n${snippet}`;
  }

  const message = suppressionMessage ? `Suppressed: ${suppressionMessage}` : '';

  return createResult(
    status,
    message,
    {
      codeDesc,
      startTime: new Date(),
      backtrace,
    }
  );
}
