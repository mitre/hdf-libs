import { parseJSON } from '@mitre/hdf-utilities';
import {
  getAwsConfigNistControlByIdentifier,
  getAwsConfigNistControlByName,
} from '@mitre/hdf-mappings';
import { inputChecksum, limitArray, validateInputSize, buildHdfResults } from '../../../shared/typescript/converterutil.js';
import {
  Copyright,
  type EvaluatedBaseline,
  type EvaluatedRequirement,
  type RequirementResult,
  type Checksum,
  type Description,
} from '@mitre/hdf-schema';
import {
  ResultStatus,
  createMinimalBaseline,
  createRequirement,
  createResult,
} from '@mitre/hdf-schema';

/**
 * AWS Config static export structures.
 * Produced by combining `aws configservice describe-config-rules` with
 * `aws configservice get-compliance-details-by-config-rule`.
 */
interface ConfigRulesFile {
  ConfigRules: ConfigRule[];
}

interface ConfigRule {
  ConfigRuleId: string;
  ConfigRuleName: string;
  ConfigRuleArn: string;
  Description: string;
  Source: ConfigRuleSource;
  InputParameters: string;
  EvaluationResults: EvaluationResult[];
}

interface ConfigRuleSource {
  Owner: string;
  SourceIdentifier: string;
}

interface EvaluationResult {
  EvaluationResultIdentifier: EvaluationResultIdentifier;
  ComplianceType: string;
  Annotation?: string;
  ConfigRuleInvokedTime: string;
  ResultRecordedTime: string;
}

interface EvaluationResultIdentifier {
  EvaluationResultQualifier: EvaluationResultQualifier;
}

interface EvaluationResultQualifier {
  ConfigRuleName: string;
  ResourceType: string;
  ResourceId: string;
}

const ARN_RE = /arn:aws[^:]*:config:([^:]+):(\d{12}):config-rule/;

function getAccountId(arn: string): string {
  const m = ARN_RE.exec(arn);
  return m ? m[2]! : 'no-account-id';
}

function getRegion(arn: string): string {
  const m = ARN_RE.exec(arn);
  return m ? m[1]! : 'unknown';
}

function mapComplianceStatus(complianceType: string): ResultStatus {
  switch (complianceType) {
    case 'COMPLIANT':       return ResultStatus.Passed;
    case 'NON_COMPLIANT':   return ResultStatus.Failed;
    case 'NOT_APPLICABLE':  return ResultStatus.NotApplicable;
    default:                return ResultStatus.NotReviewed; // INSUFFICIENT_DATA etc.
  }
}

function buildNistTags(sourceIdentifier: string, ruleName: string): string[] {
  const byIdentifier = getAwsConfigNistControlByIdentifier(sourceIdentifier);
  if (byIdentifier) return [byIdentifier];
  const byName = getAwsConfigNistControlByName(ruleName);
  if (byName) return [byName];
  return [];
}

function buildCheckText(rule: ConfigRule): string {
  const parts: string[] = [
    `ARN: ${rule.ConfigRuleArn || 'N/A'}`,
    `Source Identifier: ${rule.Source.SourceIdentifier || 'N/A'}`,
  ];
  if (rule.InputParameters && rule.InputParameters !== '{}') {
    const params = rule.InputParameters
      .replace(/[{}"]/g, '')
      .split(',')
      .map(p => p.trim())
      .filter(Boolean);
    parts.push(...params);
  }
  return parts.join('<br/>');
}

function buildCodeDesc(q: EvaluationResultQualifier): string {
  return `config_rule_name: ${q.ConfigRuleName}, resource_type: ${q.ResourceType}, resource_id: ${q.ResourceId}`;
}

function buildResultMessage(codeDesc: string, annotation: string | undefined, status: ResultStatus): string | undefined {
  if (status !== ResultStatus.Failed) return undefined;
  const text = annotation || 'Rule does not pass rule compliance';
  return `(${codeDesc}): ${text}`;
}

function buildResult(r: EvaluationResult): RequirementResult {
  const q = r.EvaluationResultIdentifier.EvaluationResultQualifier;
  const status = mapComplianceStatus(r.ComplianceType);
  const codeDesc = buildCodeDesc(q);
  const message = buildResultMessage(codeDesc, r.Annotation, status);
  const startTime = r.ConfigRuleInvokedTime ? new Date(r.ConfigRuleInvokedTime) : undefined;

  return createResult(status, message ?? codeDesc, {
    codeDesc,
    ...(startTime ? { startTime } : {}),
  });
}

function buildRequirement(rule: ConfigRule): EvaluatedRequirement {
  const nist = buildNistTags(rule.Source.SourceIdentifier, rule.ConfigRuleName);
  const tags: Record<string, unknown> = nist.length > 0 ? { nist } : {};

  const descriptions: Description[] = [
    { label: 'default', data: rule.Description },
    { label: 'check',   data: buildCheckText(rule) },
  ];

  const title = `${getAccountId(rule.ConfigRuleArn)} - ${rule.ConfigRuleName}`;
  const results = rule.EvaluationResults.map(buildResult);

  return createRequirement(
    rule.ConfigRuleId,
    title,
    descriptions,
    0.5,
    results,
    {
      tags,
      sourceLocation: { ref: rule.ConfigRuleArn, line: 1 },
    }
  );
}

/**
 * Converts an AWS Config static export (ConfigRulesFile JSON) to HDF format.
 *
 * @param input - JSON string produced by combining aws configservice describe-config-rules
 *                with get-compliance-details-by-config-rule
 * @returns HDF JSON string
 */
export async function convertAwsConfigToHdf(input: string): Promise<string> {
  validateInputSize(input, 'aws-config');
  const resultsChecksum: Checksum = await inputChecksum(input);

  const data = parseJSON<ConfigRulesFile>(input);

  if (!data || typeof data !== 'object') {
    throw new Error('Invalid AWS Config export: not a valid JSON object');
  }
  if (!Array.isArray(data.ConfigRules)) {
    throw new Error('Invalid AWS Config export: ConfigRules field is required');
  }

  const { items: limitedRules, truncated: truncatedRules } = limitArray(data.ConfigRules);
  /* v8 ignore next -- truncation only triggers with >100K items */
  if (truncatedRules) {
    // eslint-disable-next-line no-console
    console.warn(`WARNING: Input truncated at ${limitedRules.length} ConfigRule items (original: ${data.ConfigRules.length})`);
  }
  const requirements = limitedRules.map(buildRequirement);

  const baseline: EvaluatedBaseline = {
    ...createMinimalBaseline('AWS Config', requirements, { resultsChecksum }),
    title: 'AWS Config Compliance Results',
    version: '1.0.0',
    maintainer: 'Amazon Web Services',
  } as EvaluatedBaseline;

  // Extract account/region from the first rule's ARN for target labels
  const firstArn = limitedRules[0]?.ConfigRuleArn ?? '';
  const accountId = getAccountId(firstArn);
  const region = getRegion(firstArn);

  return buildHdfResults({
    generatorName: 'aws-config-to-hdf',
    converterVersion: '1.0.0',
    toolName: 'AWS Config',
    baselines: [baseline],
    components: [{
      type: Copyright.CloudAccount,
      name: `AWS Account ${accountId}`,
      labels: {
        account: accountId,
        region,
        provider: 'aws',
      },
    }],
    timestamp: new Date(),
  });
}
