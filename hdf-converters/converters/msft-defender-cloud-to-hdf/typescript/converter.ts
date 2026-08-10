import { parseJSON } from '@mitre/hdf-utilities';
import { inputChecksum, limitArray, validateInputSize, buildHdfResults, buildNoFindingsRequirement } from '../../../shared/typescript/converterutil.js';
import type {
  EvaluatedBaseline,
  EvaluatedRequirement,
  RequirementResult,
  Checksum,
  Component,
} from '@mitre/hdf-schema';
import {
  ResultStatus,
  TargetType,
  VerificationMethodEnum,
  createMinimalBaseline,
  createRequirement,
  type Description,
} from '@mitre/hdf-schema';

/**
 * Microsoft Defender for Cloud assessment structures.
 * Derived from Azure REST API: /providers/Microsoft.Security/assessments
 * See: https://learn.microsoft.com/en-us/rest/api/defenderforcloud/assessments/list
 */
interface DefenderCloudInput {
  value: Assessment[];
}

interface Assessment {
  id: string;
  name: string;
  type: string;
  properties: AssessmentProperties;
}

interface AssessmentProperties {
  displayName: string;
  resourceDetails: ResourceDetails;
  status: StatusBlock;
  metadata: Metadata;
}

interface ResourceDetails {
  source: string;
  id: string;
}

interface StatusBlock {
  code: string;
  cause: string;
  description: string;
}

interface Metadata {
  displayName: string;
  assessmentType: string;
  policyDefinitionId: string;
  description: string;
  remediationDescription: string;
  categories: string[];
  severity: string;
  userImpact: string;
  implementationEffort: string;
  threats: string[];
  tactics: string[];
  techniques: string[];
}

/**
 * Severity to HDF impact mapping.
 */
const IMPACT_MAPPING: Record<string, number> = {
  high: 0.7,
  medium: 0.5,
  low: 0.3,
};

/**
 * Maps Azure status code to HDF ResultStatus.
 */
function mapStatus(code: string): ResultStatus {
  switch (code.toLowerCase()) {
    case 'healthy':
      return ResultStatus.Passed;
    case 'unhealthy':
      return ResultStatus.Failed;
    case 'notapplicable':
      return ResultStatus.NotApplicable;
    default:
      return ResultStatus.NotReviewed;
  }
}

/**
 * Extracts subscription ID from an Azure resource path.
 */
function extractSubscriptionID(resourcePath: string): string {
  const lower = resourcePath.toLowerCase();
  const idx = lower.indexOf('/subscriptions/');
  if (idx === -1) {
    return '';
  }
  const rest = resourcePath.substring(idx + '/subscriptions/'.length);
  const slashIdx = rest.indexOf('/');
  if (slashIdx !== -1) {
    return rest.substring(0, slashIdx);
  }
  return rest;
}

/**
 * Converts a group of assessments sharing an assessment ID into one EvaluatedRequirement.
 */
function buildRequirement(assessmentID: string, assessments: Assessment[], scanTime: Date): EvaluatedRequirement {
  const rep = assessments[0]!;
  const meta = rep.properties.metadata;

  const impact = IMPACT_MAPPING[meta.severity.toLowerCase()] ?? 0.5;

  const tags: Record<string, unknown> = {};

  if (meta.categories.length > 0) {
    tags['categories'] = meta.categories;
  }
  if (meta.tactics.length > 0) {
    tags['tactics'] = meta.tactics;
  }
  if (meta.techniques.length > 0) {
    tags['techniques'] = meta.techniques;
  }
  if (meta.threats.length > 0) {
    tags['threats'] = meta.threats;
  }

  tags['severity'] = meta.severity;
  if (meta.userImpact) {
    tags['userImpact'] = meta.userImpact;
  }
  if (meta.implementationEffort) {
    tags['implementationEffort'] = meta.implementationEffort;
  }
  if (meta.assessmentType) {
    tags['assessmentType'] = meta.assessmentType;
  }
  if (meta.policyDefinitionId) {
    tags['policy_definition_id'] = meta.policyDefinitionId;
  }

  const descriptions: Description[] = [
    { label: 'default', data: meta.description },
  ];
  if (meta.remediationDescription) {
    descriptions.push({ label: 'fix', data: meta.remediationDescription });
  }

  const results = assessments.map((a) => buildResultFromAssessment(a, scanTime));

  const req = createRequirement(assessmentID, rep.properties.displayName, descriptions, impact, results, { tags }) as EvaluatedRequirement;
  req.verificationMethod = VerificationMethodEnum.Automated;
  return req;
}

/**
 * Converts a single assessment into an HDF RequirementResult.
 */
function buildResultFromAssessment(a: Assessment, scanTime: Date): RequirementResult {
  const status = mapStatus(a.properties.status.code);
  const codeDesc = `Resource: ${a.properties.resourceDetails.id}`;
  const message = a.properties.status.description || a.properties.status.cause || undefined;

  // Healthy assessments carry no explanation, so `message` stays absent rather
  // than an empty string (createResult would default it to '').
  const result: RequirementResult = { status, codeDesc, startTime: scanTime };
  if (message !== undefined) {
    result.message = message;
  }
  return result;
}

/**
 * Converts Microsoft Defender for Cloud assessment output to HDF format.
 *
 * @param input - JSON string containing Azure Security Assessments API response
 * @returns HDF JSON string
 */
export async function convertMsftDefenderCloudToHdf(input: string, converterVersion = '1.0.0'): Promise<string> {
  validateInputSize(input, 'msft-defender-cloud');

  const scanTime = new Date();

  const resultsChecksum: Checksum = await inputChecksum(input);

  const raw = parseJSON<DefenderCloudInput>(input);

  if (!raw || typeof raw !== 'object') {
    throw new Error('Invalid Defender for Cloud structure: not a valid JSON object');
  }

  if (!Array.isArray(raw.value)) {
    throw new Error('Invalid Defender for Cloud structure: missing or invalid value array');
  }

  const { items: limitedAssessments, truncated } = limitArray(raw.value);
  /* v8 ignore next -- truncation only triggers with >100K items */
  if (truncated) {
    // eslint-disable-next-line no-console
    console.warn(`WARNING: Input truncated at ${limitedAssessments.length} assessment items (original: ${raw.value.length})`);
  }

  // Group assessments by name (GUID), preserving insertion order.
  const groups = new Map<string, Assessment[]>();
  for (const a of limitedAssessments) {
    const existing = groups.get(a.name);
    if (existing) {
      existing.push(a);
    } else {
      groups.set(a.name, [a]);
    }
  }

  const requirements: EvaluatedRequirement[] = [];
  for (const [assessmentID, assessments] of groups) {
    requirements.push(buildRequirement(assessmentID, assessments, scanTime));
  }

  const subscriptionID = limitedAssessments.length > 0
    ? extractSubscriptionID(limitedAssessments[0]!.id)
    : '';

  if (requirements.length === 0) {
    const targetName = subscriptionID || 'Unknown';
    requirements.push(buildNoFindingsRequirement(
      'msft-defender-cloud-no-findings',
      `Microsoft Defender for Cloud scanned ${targetName} and reported zero findings.`,
      scanTime,
    ));
  }

  const baseline: EvaluatedBaseline = createMinimalBaseline(
    'Microsoft Defender for Cloud Assessments',
    requirements,
    { resultsChecksum },
  ) as EvaluatedBaseline;

  const components: Component[] = [];
  if (subscriptionID) {
    components.push({
      name: `Azure Subscription ${subscriptionID}`,
      type: TargetType.CloudAccount,
      accountId: subscriptionID,
      provider: 'azure' as Component['provider'],
      labels: { account: subscriptionID, provider: 'azure' },
    });
  }

  return buildHdfResults({
    generatorName: 'msft-defender-cloud-to-hdf',
    converterVersion,
    toolName: 'Microsoft Defender for Cloud',
    baselines: [baseline],
    components,
    timestamp: scanTime,
  });
}
