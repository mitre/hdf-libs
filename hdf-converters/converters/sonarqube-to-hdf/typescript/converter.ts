import { parseJSON, sha256 } from '@mitre/hdf-utilities';
import {
  getCweNistControl,
  nistToCci,
} from '@mitre/hdf-mappings';
import type {
  HdfResults,
  EvaluatedBaseline,
  EvaluatedRequirement,
  RequirementResult,
  Checksum,
  DataSource,
} from '@mitre/hdf-schema';
import {
  ResultStatus,
  HashAlgorithm,
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
  // Calculate checksum of source scan data
  const resultsChecksum: Checksum = {
    algorithm: HashAlgorithm.Sha256,
    value: await sha256(input),
  };

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
  const issuesByProject = new Map<string, SonarQubeIssue[]>();
  for (const issue of sonarData.issues) {
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

  const dataSource: DataSource = { name: 'SonarQube' };

  // Build HDF
  const hdf: HdfResults = {
    timestamp: new Date(),
    baselines,
    targets: [],
    generator: {
      name: 'sonarqube-to-hdf',
      version: '1.0.0',
    },
    dataSource,
  };

  return JSON.stringify(hdf, null, 2);
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
  const nistControls = mapToNist(cweIds);
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

  return createRequirement(
    ruleKey,
    title,
    [createDescription('default', description)],
    impact,
    results,
    options
  );
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
        const cweMatch = tag.match(/cwe[- ]?(\d+)/i);
        if (cweMatch) {
          cweSet.add(`CWE-${cweMatch[1]}`);
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
          const cweMatch = tag.match(/cwe[- ]?(\d+)/i);
          if (cweMatch) {
            cweSet.add(`CWE-${cweMatch[1]}`);
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
    const desc = rule.htmlDesc || rule.mdDesc || '';
    const cweMatches = desc.match(/CWE[- ]?(\d+)/gi);
    if (cweMatches) {
      for (const match of cweMatches) {
        const num = match.match(/\d+/);
        if (num) {
          cweSet.add(`CWE-${num[0]}`);
        }
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

function mapToNist(
  cweIds: string[],
): string[] {
  const nistSet = new Set<string>();

  // Map CWE to NIST
  for (const cweId of cweIds) {
    const numericId = parseInt(cweId.replace('CWE-', ''), 10);
    if (!isNaN(numericId)) {
      const nistControl = getCweNistControl(numericId);
      if (nistControl) {
        nistSet.add(nistControl);
      }
    }
  }

  // If no NIST mappings found, fall back to SA-11 for all issue types
  if (nistSet.size === 0) {
    return DEFAULT_NIST_TAGS;
  }

  return Array.from(nistSet).sort();
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
