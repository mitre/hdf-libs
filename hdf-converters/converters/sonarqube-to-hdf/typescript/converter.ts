import { parseJSON } from '@mitre/hdf-utilities';
import {
  nistToCci,
} from '@mitre/hdf-mappings';
import { deriveControlTypeFromTags, inputChecksum, limitArray, mapCWEToNIST, extractCWEIDs, validateInputSize, buildHdfResults } from '../../../shared/typescript/converterutil.js';
import type {
  EvaluatedBaseline,
  EvaluatedRequirement,
  RequirementResult,
  Checksum,
} from '@mitre/hdf-schema';
import {
  TargetType,
  ResultStatus,
  VerificationMethodEnum,
  createMinimalBaseline,
  createRequirement,
  createDescription,
  createResult,
} from '@mitre/hdf-schema';

/**
 * SonarQube /api/issues/search response structure
 */
interface SonarQubeIssuesResponse {
  total: number;
  p: number;
  ps: number;
  paging: {
    pageIndex: number;
    pageSize: number;
    total: number;
  };
  issues: SonarQubeIssue[];
  components?: SonarQubeComponent[];
  rules?: SonarQubeRule[];
}

interface SonarQubeIssue {
  key: string;
  rule: string;
  severity: 'BLOCKER' | 'CRITICAL' | 'MAJOR' | 'MINOR' | 'INFO';
  component: string;
  project: string;
  line?: number;
  hash?: string;
  textRange?: {
    startLine: number;
    endLine: number;
    startOffset: number;
    endOffset: number;
  };
  flows?: SonarQubeFlow[];
  status: 'OPEN' | 'CONFIRMED' | 'REOPENED' | 'RESOLVED' | 'CLOSED';
  message: string;
  effort?: string;
  debt?: string;
  author?: string;
  tags?: string[];
  creationDate: string;
  updateDate: string;
  type: 'CODE_SMELL' | 'BUG' | 'VULNERABILITY' | 'SECURITY_HOTSPOT';
}

interface SonarQubeFlow {
  locations: SonarQubeLocation[];
}

interface SonarQubeLocation {
  component: string;
  textRange?: {
    startLine: number;
    endLine: number;
  };
  msg?: string;
}

interface SonarQubeComponent {
  key: string;
  enabled?: boolean;
  qualifier?: string;
  name?: string;
  longName?: string;
  path?: string;
}

/**
 * A section of a SonarQube rule description.
 * SonarQube 26+ returns rule descriptions as structured sections
 * instead of monolithic htmlDesc/mdDesc fields.
 */
interface SonarQubeDescriptionSection {
  key: string;
  content: string;
}

interface SonarQubeRule {
  key: string;
  name: string;
  status?: string;
  lang?: string;
  langName?: string;
  htmlDesc?: string;
  mdDesc?: string;
  severity?: string;
  type?: string;
  tags?: string[];
  sysTags?: string[];
  scope?: string;
  descriptionSections?: SonarQubeDescriptionSection[];
}

/**
 * Severity to impact mapping.
 * Canonical reference: heimdall2 sonarqube-mapper.ts IMPACT_MAPPING.
 */
const SEVERITY_IMPACT_MAPPING: Record<string, number> = {
  BLOCKER: 1.0,
  CRITICAL: 0.7,
  MAJOR: 0.5,
  MINOR: 0.3,
  INFO: 0.0,
};

/**
 * Default NIST tag for SonarQube findings without CWE mappings.
 * SA-11 (Developer Security Testing and Evaluation) applies to all issue types —
 * SonarQube is fundamentally a static analysis tool. Matches heimdall2.
 */
const DEFAULT_NIST_TAGS = ['SA-11'];

/**
 * Convert SonarQube issues JSON to HDF format
 *
 * @param input - JSON string from SonarQube /api/issues/search endpoint
 * @returns HDF JSON string
 */
export async function convertSonarqubeToHdf(input: string): Promise<string> {
  validateInputSize(input, 'sonarqube');
  // Calculate checksum of source scan data
  const resultsChecksum: Checksum = await inputChecksum(input);

  // Parse SonarQube JSON
  const sonarData = parseJSON<SonarQubeIssuesResponse>(input);

  if (!sonarData || typeof sonarData !== 'object') {
    throw new Error('Invalid SonarQube structure: not a valid JSON object');
  }

  if (!Array.isArray(sonarData.issues)) {
    throw new Error('Invalid SonarQube structure: missing or invalid issues field');
  }

  // Create lookup maps for components and rules
  const componentMap = new Map<string, SonarQubeComponent>();
  if (sonarData.components) {
    for (const component of sonarData.components) {
      componentMap.set(component.key, component);
    }
  }

  const ruleMap = new Map<string, SonarQubeRule>();
  if (sonarData.rules) {
    for (const rule of sonarData.rules) {
      ruleMap.set(rule.key, rule);
    }
  }

  // Group issues by project (each project becomes a baseline)
  const { items: limitedIssues, truncated: truncatedIssues } = limitArray(sonarData.issues);
  /* v8 ignore next -- truncation only triggers with >100K items */
  if (truncatedIssues) {
    // eslint-disable-next-line no-console
    console.warn(`WARNING: Input truncated at ${limitedIssues.length} issue items (original: ${sonarData.issues.length})`);
  }
  const issuesByProject = new Map<string, SonarQubeIssue[]>();
  for (const issue of limitedIssues) {
    const projectKey = issue.project;
    if (!issuesByProject.has(projectKey)) {
      issuesByProject.set(projectKey, []);
    }
    issuesByProject.get(projectKey)!.push(issue);
  }

  // Convert each project to a baseline
  const baselines: EvaluatedBaseline[] = [];
  for (const [projectKey, issues] of issuesByProject) {
    const baseline = convertProjectToBaseline(
      projectKey,
      issues,
      componentMap,
      ruleMap,
      resultsChecksum
    );
    baselines.push(baseline);
  }

  // Build components from project keys
  const components = Array.from(issuesByProject.keys()).map(projectKey => ({
    type: TargetType.Application,
    name: projectKey,
  }));

  // Build HDF
  return buildHdfResults({
    generatorName: 'sonarqube-to-hdf',
    converterVersion: '1.0.0',
    toolName: 'SonarQube',
    baselines,
    components,
    timestamp: new Date(),
  });
}

function convertProjectToBaseline(
  projectKey: string,
  issues: SonarQubeIssue[],
  componentMap: Map<string, SonarQubeComponent>,
  ruleMap: Map<string, SonarQubeRule>,
  resultsChecksum: Checksum
): EvaluatedBaseline {
  // Group issues by rule (each rule becomes a requirement)
  const issuesByRule = new Map<string, SonarQubeIssue[]>();
  for (const issue of issues) {
    const ruleKey = issue.rule;
    if (!issuesByRule.has(ruleKey)) {
      issuesByRule.set(ruleKey, []);
    }
    issuesByRule.get(ruleKey)!.push(issue);
  }

  // Convert each rule to a requirement
  const requirements: EvaluatedRequirement[] = [];
  for (const [ruleKey, ruleIssues] of issuesByRule) {
    const requirement = convertRuleToRequirement(
      ruleKey,
      ruleIssues,
      componentMap,
      ruleMap
    );
    requirements.push(requirement);
  }

  return createMinimalBaseline(projectKey, requirements, {
    title: `SonarQube Analysis for ${projectKey}`,
    resultsChecksum,
  });
}

function convertRuleToRequirement(
  ruleKey: string,
  issues: SonarQubeIssue[],
  componentMap: Map<string, SonarQubeComponent>,
  ruleMap: Map<string, SonarQubeRule>
): EvaluatedRequirement {
  const rule = ruleMap.get(ruleKey);

  // Extract rule name and description
  const title = rule?.name || ruleKey;
  const description = extractDescription(rule);

  // Get impact from first issue (all issues of same rule have same severity)
  const firstIssue = issues[0]!;
  const impact = SEVERITY_IMPACT_MAPPING[firstIssue.severity] || 0.5;

  // Extract tags and mappings
  const { cweIds, owaspTags, allTags } = extractTags(rule, issues);
  const nistControls = mapCWEToNIST(cweIds, DEFAULT_NIST_TAGS);
  const cciControls = nistToCci(nistControls);

  // Create results for each issue
  const results: RequirementResult[] = issues.map(issue =>
    createResultFromIssue(issue, componentMap)
  );

  // Get source location from first issue with a line number
  const issueWithLocation = issues.find(i => i.line !== undefined);
  const sourceLocation = issueWithLocation
    ? extractSourceLocation(issueWithLocation, componentMap)
    : undefined;

  const options: {
    sourceLocation?: { ref: string; line: number };
    tags: Record<string, unknown>;
  } = {
    tags: {
      severity: firstIssue.severity.toLowerCase(),
      type: firstIssue.type.toLowerCase(),
      cwe: cweIds,
      owasp: owaspTags,
      nist: nistControls,
      cci: cciControls,
      ...allTags,
    },
  };

  if (sourceLocation) {
    options.sourceLocation = sourceLocation;
  }

  const req = createRequirement(
    ruleKey,
    title,
    [createDescription('default', description)],
    impact,
    results,
    options
  ) as EvaluatedRequirement;

  const controlType = deriveControlTypeFromTags(nistControls);
  if (controlType !== undefined) {
    req.controlType = controlType;
  }
  req.verificationMethod = VerificationMethodEnum.Automated;

  return req;
}

function extractDescription(rule: SonarQubeRule | undefined): string {
  if (!rule) {
    return '';
  }

  // Prefer markdown description, fall back to HTML (stripped), then name
  if (rule.mdDesc) {
    return rule.mdDesc;
  }

  if (rule.htmlDesc) {
    // Strip HTML tags for plain text description
    return rule.htmlDesc.replace(/<[^>]*>/g, ' ').replace(/\s+/g, ' ').trim();
  }

  // Fall back to descriptionSections (SonarQube 26+ format)
  if (rule.descriptionSections && rule.descriptionSections.length > 0) {
    // Prefer root_cause section (closest to the old monolithic description)
    const rootCause = rule.descriptionSections.find(s => s.key === 'root_cause');
    if (rootCause) {
      return rootCause.content.replace(/<[^>]*>/g, ' ').replace(/\s+/g, ' ').trim();
    }
    // If no root_cause, concatenate all sections
    const parts = rule.descriptionSections
      .map(s => s.content.replace(/<[^>]*>/g, ' ').replace(/\s+/g, ' ').trim())
      .filter(s => s.length > 0);
    if (parts.length > 0) {
      return parts.join('\n\n');
    }
  }

  return rule.name || '';
}

function extractTags(
  rule: SonarQubeRule | undefined,
  issues: SonarQubeIssue[]
): {
  cweIds: string[];
  owaspTags: string[];
  allTags: Record<string, string[]>;
} {
  const cweSet = new Set<string>();
  const owaspSet = new Set<string>();
  const allTagsMap = new Map<string, Set<string>>();

  // Extract from rule tags
  if (rule) {
    const ruleTags = [...(rule.tags || []), ...(rule.sysTags || [])];

    for (const tag of ruleTags) {
      const lowerTag = tag.toLowerCase();

      // Check for CWE tags
      if (lowerTag.startsWith('cwe-') || lowerTag.includes('cwe')) {
        for (const id of extractCWEIDs(tag)) {
          cweSet.add(`CWE-${id}`);
        }
      }

      // Check for OWASP tags
      if (lowerTag.includes('owasp')) {
        owaspSet.add(tag);
      }

      // Collect other tags by category
      const parts = tag.split(':');
      if (parts.length === 2) {
        const [category, value] = parts;
        if (!allTagsMap.has(category!)) {
          allTagsMap.set(category!, new Set());
        }
        allTagsMap.get(category!)!.add(value!);
      }
    }
  }

  // Extract from issue tags
  for (const issue of issues) {
    if (issue.tags) {
      for (const tag of issue.tags) {
        const lowerTag = tag.toLowerCase();

        if (lowerTag.startsWith('cwe-')) {
          for (const id of extractCWEIDs(tag)) {
            cweSet.add(`CWE-${id}`);
          }
        }

        if (lowerTag.includes('owasp')) {
          owaspSet.add(tag);
        }
      }
    }
  }

  // Also parse CWE from rule description
  if (rule?.htmlDesc || rule?.mdDesc) {
    const desc = (rule.htmlDesc || '') + (rule.mdDesc || '');
    for (const id of extractCWEIDs(desc)) {
      cweSet.add(`CWE-${id}`);
    }
  }

  // Parse CWE from descriptionSections (SonarQube 26+ format)
  if (rule?.descriptionSections) {
    for (const section of rule.descriptionSections) {
      for (const id of extractCWEIDs(section.content)) {
        cweSet.add(`CWE-${id}`);
      }
    }
  }

  const allTags: Record<string, string[]> = {};
  for (const [category, values] of allTagsMap) {
    allTags[category] = Array.from(values);
  }

  return {
    cweIds: Array.from(cweSet),
    owaspTags: Array.from(owaspSet),
    allTags,
  };
}

function createResultFromIssue(
  issue: SonarQubeIssue,
  componentMap: Map<string, SonarQubeComponent>
): RequirementResult {
  const status = issue.status === 'RESOLVED' || issue.status === 'CLOSED'
    ? ResultStatus.Passed
    : ResultStatus.Failed;

  const component = componentMap.get(issue.component);
  const componentPath = component?.path || component?.longName || issue.component;

  const lineInfo = issue.line ? ` LINE : ${issue.line}` : '';
  const codeDesc = `${componentPath}${lineInfo}`;

  return createResult(status, issue.message, {
    codeDesc,
    startTime: new Date(issue.creationDate),
  });
}

function extractSourceLocation(
  issue: SonarQubeIssue,
  componentMap: Map<string, SonarQubeComponent>
): { ref: string; line: number } | undefined {
  if (!issue.line) {
    return undefined;
  }

  const component = componentMap.get(issue.component);
  const ref = component?.path || component?.key || issue.component;

  return { ref, line: issue.line };
}
