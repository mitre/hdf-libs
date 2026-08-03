import { parseJSON, parseTimestamp } from '@mitre/hdf-utilities';
import {
  getAwsConfigNistControlByIdentifier,
  getAwsConfigNistControlByName,
  awsConfigMappedRevisions,
  getCurrentNistRevision,
  isNistStrict,
  DEFAULT_CONFIG_MANAGEMENT_NIST_TAGS,
} from '@mitre/hdf-mappings';
import { deriveControlTypeFromTags, inputChecksum, limitArray, validateInputSize, buildHdfResults } from '../../../shared/typescript/converterutil.js';
import {
  TargetType,
  type EvaluatedBaseline,
  type EvaluatedRequirement,
  type RequirementResult,
  type Checksum,
  type Description,
} from '@mitre/hdf-schema';
import {
  ResultStatus,
  VerificationMethodEnum,
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
  Remediation?: RemediationConfiguration;
}

// Mirrors AWS Config's RemediationConfiguration (the SSM Automation document
// Config runs to remediate a rule). Optional — present only when a remediation
// is attached, so a rule without one gets no fix description.
interface RemediationConfiguration {
  TargetType: string;    // e.g. 'SSM_DOCUMENT'
  TargetId: string;      // the automation document name
  TargetVersion?: string; // optional document version
  Automatic?: boolean;   // auto-remediate on non-compliance
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

/** Mapping values pack multiple controls into one pipe-delimited string. */
function splitControls(nistId: string): string[] {
  return nistId.split('|').map(c => c.trim()).filter(Boolean);
}

function buildNistTags(sourceIdentifier: string, ruleName: string): string[] {
  const byIdentifier = sourceIdentifier ? getAwsConfigNistControlByIdentifier(sourceIdentifier) : undefined;
  if (byIdentifier) return splitControls(byIdentifier);
  const byName = getAwsConfigNistControlByName(ruleName);
  if (byName) return splitControls(byName);
  return [];
}

/**
 * Flag rules whose NIST mappings exist at a revision other than the one
 * currently selected — they emit no NIST tags here even though a mapping
 * exists elsewhere, a likely sign of a wrong revision selection. Rules
 * unmapped at every revision are not flagged. Throws in strict mode; otherwise
 * logs a single aggregated warning.
 */
function checkRevisionAlignment(rules: ConfigRule[]): void {
  const rev = getCurrentNistRevision();
  const seen = new Set<string>();
  const lines: string[] = [];
  for (const rule of rules) {
    const covered = awsConfigMappedRevisions(rule.Source.SourceIdentifier, rule.ConfigRuleName);
    if (covered.length === 0 || covered.includes(rev) || seen.has(rule.ConfigRuleName)) continue;
    seen.add(rule.ConfigRuleName);
    lines.push(`  - ${rule.ConfigRuleName} (mapped at Rev ${covered.join(', ')})`);
  }
  if (lines.length === 0) return;

  const detail =
    `${lines.length} AWS Config rule(s) have NIST 800-53 mappings at a different revision ` +
    `than the requested Rev ${rev}; their NIST tags were omitted:\n${lines.join('\n')}`;
  if (isNistStrict()) {
    throw new Error(
      `aws-config: ${detail}\nre-run with a matching revision, or disable strict mode to convert with the gaps`
    );
  }
  // eslint-disable-next-line no-console
  console.warn(`WARNING: ${detail}`);
}

// Builds the "fix" description from a rule's attached remediation configuration
// (the SSM Automation document Config runs). Empty when the rule carries no
// remediation, so the fix description is omitted rather than fabricated.
export function buildFixText(rule: ConfigRule): string {
  const r = rule.Remediation;
  if (!r || !r.TargetId) {
    return '';
  }
  const trigger = r.Automatic ? 'automatically on non-compliance' : 'on demand';
  const doc = r.TargetVersion ? `${r.TargetId} (version ${r.TargetVersion})` : r.TargetId;
  return `Remediate via ${remediationTargetLabel(r.TargetType)} ${doc}, applied ${trigger}.`;
}

// Renders an AWS remediation TargetType as human text.
function remediationTargetLabel(targetType: string): string {
  if (targetType === 'SSM_DOCUMENT') return 'SSM Automation document';
  if (!targetType) return 'automation document';
  return `${targetType} document`;
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

/** Elapsed seconds between rule invocation and result recording; omitted if either time is unusable. */
function computeRunTime(invoked: string, recorded: string): number | undefined {
  const start = invoked ? parseTimestamp(invoked) : null;
  const end = recorded ? parseTimestamp(recorded) : null;
  if (!start || !end) return undefined;
  return (end.getTime() - start.getTime()) / 1000;
}

function buildResult(r: EvaluationResult): RequirementResult {
  const q = r.EvaluationResultIdentifier.EvaluationResultQualifier;
  const status = mapComplianceStatus(r.ComplianceType);
  const codeDesc = buildCodeDesc(q);
  const message = buildResultMessage(codeDesc, r.Annotation, status);
  const startTime = (r.ConfigRuleInvokedTime ? parseTimestamp(r.ConfigRuleInvokedTime) : null) ?? new Date('0001-01-01T00:00:00Z');
  const runTime = computeRunTime(r.ConfigRuleInvokedTime, r.ResultRecordedTime);

  // message is a failure explanation, so non-failed results carry no message key at all.
  return createResult(status, message, { codeDesc, startTime, runTime });
}

/**
 * Synthesizes a single HDF result for a Config rule whose live evaluation
 * returned zero in-scope resources. The HDF schema requires `results` to have
 * minItems >= 1; this honestly signals to auditors that the rule's check ran
 * but had no scope in this account/region rather than vacuously claiming
 * "passed".
 */
function buildNotApplicableResult(rule: ConfigRule): RequirementResult {
  const codeDesc = `AWS Config rule ${rule.ConfigRuleName} evaluated zero in-scope resources in this account/region.`;
  return createResult(ResultStatus.NotApplicable, undefined, {
    codeDesc,
    startTime: new Date(),
  });
}

function buildRequirement(rule: ConfigRule): EvaluatedRequirement {
  // A managed or custom rule the mapping tables don't cover still evaluates a
  // configuration setting — fall back to CM-6 rather than emitting no NIST context.
  const rawNist = buildNistTags(rule.Source.SourceIdentifier, rule.ConfigRuleName);
  const nist = rawNist.length > 0 ? rawNist : DEFAULT_CONFIG_MANAGEMENT_NIST_TAGS;
  const tags: Record<string, unknown> = { nist };

  const descriptions: Description[] = [
    { label: 'default', data: rule.Description },
    { label: 'check',   data: buildCheckText(rule) },
  ];
  const fix = buildFixText(rule);
  if (fix) {
    descriptions.push({ label: 'fix', data: fix });
  }

  const title = `${getAccountId(rule.ConfigRuleArn)} - ${rule.ConfigRuleName}`;
  // A Config rule that was deployed and active but evaluated
  // zero in-scope resources (e.g. rds-cluster-multi-az-enabled in an account
  // with no RDS clusters) returns an empty EvaluationResults from
  // GetComplianceDetailsByConfigRule. The HDF schema requires `results` to
  // have minItems >= 1, so synthesize one notApplicable result honestly
  // signaling that the rule had no scope rather than emitting `results: []`.
  const results = rule.EvaluationResults.length > 0
    ? rule.EvaluationResults.map(buildResult)
    : [buildNotApplicableResult(rule)];

  const req = createRequirement(
    rule.ConfigRuleId,
    title,
    descriptions,
    0.5,
    results,
    {
      tags,
      sourceLocation: { ref: rule.ConfigRuleArn, line: 1 },
    }
  ) as EvaluatedRequirement;

  const controlType = deriveControlTypeFromTags(nist);
  if (controlType !== undefined) {
    req.controlType = controlType;
  }
  req.verificationMethod = VerificationMethodEnum.Automated;

  return req;
}

/**
 * Converts an AWS Config static export (ConfigRulesFile JSON) to HDF format.
 *
 * @param input - JSON string produced by combining aws configservice describe-config-rules
 *                with get-compliance-details-by-config-rule
 * @returns HDF JSON string
 */
export async function convertAwsConfigToHdf(input: string, converterVersion = '1.0.0'): Promise<string> {
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

  checkRevisionAlignment(limitedRules);
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
    converterVersion,
    toolName: 'AWS Config',
    baselines: [baseline],
    components: [{
      type: TargetType.CloudAccount,
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
