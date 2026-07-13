import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { describe, it, expect, vi, afterEach } from 'vitest';
import { setCurrentNistRevision, resetNistRevision, setNistStrict } from '@mitre/hdf-mappings';
import { convertAwsConfigToHdf } from './converter.js';
import { runConverterContractTests } from '../../../shared/typescript/converter-contract.js';
import { expectValidResults } from '../../../test/helpers/expectValidHdf.js';
import type { HDFResults } from '@mitre/hdf-schema';

const __dirname = dirname(fileURLToPath(import.meta.url));
const FIXTURES_DIR = join(__dirname, '..', 'fixtures');

function loadFixture(name: string): string {
  return readFileSync(join(FIXTURES_DIR, 'input', name), 'utf-8');
}

runConverterContractTests({
  converterName: 'aws-config-to-hdf',
  convertFn: convertAwsConfigToHdf,
  minimalFixture: 'minimal.json',
});

describe('timestamp parse fallback', () => {
  it('falls back to a valid startTime when ConfigRuleInvokedTime is unparseable', async () => {
    const input = loadFixture('minimal.json').replace(/2021-04-09T14:39:21Z/g, 'not-a-date');
    const hdf = JSON.parse(await convertAwsConfigToHdf(input)) as HDFResults;
    expectValidResults(hdf);
  });

  it('falls back to a valid startTime when ConfigRuleInvokedTime is absent', async () => {
    const input = loadFixture('minimal.json').replace(/"ConfigRuleInvokedTime"/g, '"ConfigRuleInvokedTimeAbsent"');
    const hdf = JSON.parse(await convertAwsConfigToHdf(input)) as HDFResults;
    expectValidResults(hdf);
  });
});

// api-gw-ssl-enabled is mapped only at Rev 5; cloudtrail-enabled at both.
const REV_MIX_INPUT = JSON.stringify({
  ConfigRules: [
    {
      ConfigRuleId: 'r1',
      ConfigRuleName: 'api-gw-ssl-enabled',
      ConfigRuleArn: 'arn:aws:config:us-east-1:123456789012:config-rule/r1',
      Source: { Owner: 'AWS', SourceIdentifier: 'API_GW_SSL_ENABLED' },
      EvaluationResults: [
        {
          EvaluationResultIdentifier: {
            EvaluationResultQualifier: {
              ConfigRuleName: 'api-gw-ssl-enabled',
              ResourceType: 'AWS::ApiGateway::Stage',
              ResourceId: 's1',
            },
          },
          ComplianceType: 'NON_COMPLIANT',
          ResultRecordedTime: '2024-02-19T00:00:05Z',
          ConfigRuleInvokedTime: '2024-02-19T00:00:05Z',
        },
      ],
    },
  ],
});

describe('AWS Config revision alignment', () => {
  afterEach(() => {
    resetNistRevision();
    setNistStrict(false);
    vi.restoreAllMocks();
  });

  it('warns (without failing) when a rule is mapped only at another revision', async () => {
    setCurrentNistRevision(4);
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    await convertAwsConfigToHdf(REV_MIX_INPUT);
    const msg = warn.mock.calls.map((c) => String(c[0])).join('\n');
    expect(msg).toContain('api-gw-ssl-enabled');
    expect(msg).toContain('Rev 5');
  });

  it('throws in strict mode on a revision mismatch', async () => {
    setCurrentNistRevision(4);
    setNistStrict(true);
    await expect(convertAwsConfigToHdf(REV_MIX_INPUT)).rejects.toThrow('api-gw-ssl-enabled');
  });

  it('does not warn when every rule is mapped at the requested revision', async () => {
    setCurrentNistRevision(5);
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    await convertAwsConfigToHdf(REV_MIX_INPUT);
    expect(warn).not.toHaveBeenCalled();
  });
});

describe('AWS Config to HDF converter', async () => {
  describe('convertAwsConfigToHdf', async () => {
    it('should throw when ConfigRules field is missing', async () => {
      await expect(convertAwsConfigToHdf(JSON.stringify({ other: 'field' }))).rejects.toThrow(
        'ConfigRules field is required'
      );
    });

    it('should produce valid HDF structure from minimal fixture', async () => {
      const output = await convertAwsConfigToHdf(loadFixture('minimal.json'));
      const hdf = JSON.parse(output) as HDFResults;
      expectValidResults(hdf);

      expect(hdf.timestamp).toBeTruthy();
      expect(hdf.generator?.name).toBe('aws-config-to-hdf');
      expect(hdf.generator?.version).toBe('1.0.0');
      expect(hdf.tool?.name).toBe('AWS Config');
      expect(hdf.tool?.version).toBeUndefined();
      expect(hdf.tool?.format).toBeUndefined();
      expect(hdf.baselines).toHaveLength(1);
    });

    it('should use "AWS Config" as the baseline name', async () => {
      const hdf = JSON.parse(await convertAwsConfigToHdf(loadFixture('minimal.json'))) as HDFResults;
      expect(hdf.baselines[0]!.name).toBe('AWS Config');
    });

    it('should set baseline title and maintainer', async () => {
      const hdf = JSON.parse(await convertAwsConfigToHdf(loadFixture('minimal.json'))) as HDFResults;
      const baseline = hdf.baselines[0]!;
      expect(baseline.title).toBe('AWS Config Compliance Results');
      expect(baseline.maintainer).toBe('Amazon Web Services');
    });

    it('should include a sha256 checksum', async () => {
      const hdf = JSON.parse(await convertAwsConfigToHdf(loadFixture('minimal.json'))) as HDFResults;
      const checksum = hdf.baselines[0]!.resultsChecksum;
      expect(checksum?.algorithm).toBe('sha256');
      expect(checksum?.value).toMatch(/^[a-f0-9]{64}$/);
    });

    it('should create one requirement per config rule', async () => {
      const hdf = JSON.parse(await convertAwsConfigToHdf(loadFixture('minimal.json'))) as HDFResults;
      expect(hdf.baselines[0]!.requirements).toHaveLength(1);
    });

    it('should use ConfigRuleId as the requirement ID', async () => {
      const hdf = JSON.parse(await convertAwsConfigToHdf(loadFixture('minimal.json'))) as HDFResults;
      expect(hdf.baselines[0]!.requirements[0]!.id).toBe('config-rule-7hytm9');
    });

    it('should set impact to 0.5 for all rules', async () => {
      const hdf = JSON.parse(await convertAwsConfigToHdf(loadFixture('minimal.json'))) as HDFResults;
      expect(hdf.baselines[0]!.requirements[0]!.impact).toBe(0.5);
    });

    it('should include title with account ID and rule name', async () => {
      const hdf = JSON.parse(await convertAwsConfigToHdf(loadFixture('minimal.json'))) as HDFResults;
      const title = hdf.baselines[0]!.requirements[0]!.title as string;
      expect(title).toContain('123456789012');
      expect(title).toContain('access-keys-rotated');
    });

    it('should include default description from rule Description field', async () => {
      const hdf = JSON.parse(await convertAwsConfigToHdf(loadFixture('minimal.json'))) as HDFResults;
      const req = hdf.baselines[0]!.requirements[0]!;
      const defaultDesc = req.descriptions?.find(d => d.label === 'default');
      expect(defaultDesc?.data).toContain('active access keys are rotated');
    });

    it('should include check description with ARN and source identifier', async () => {
      const hdf = JSON.parse(await convertAwsConfigToHdf(loadFixture('minimal.json'))) as HDFResults;
      const req = hdf.baselines[0]!.requirements[0]!;
      const checkDesc = req.descriptions?.find(d => d.label === 'check');
      expect(checkDesc?.data).toContain('arn:aws:config:');
      expect(checkDesc?.data).toContain('ACCESS_KEYS_ROTATED');
    });

    it('should include check description with input parameters', async () => {
      const hdf = JSON.parse(await convertAwsConfigToHdf(loadFixture('minimal.json'))) as HDFResults;
      const req = hdf.baselines[0]!.requirements[0]!;
      const checkDesc = req.descriptions?.find(d => d.label === 'check');
      expect(checkDesc?.data).toContain('maxAccessKeyAge');
    });

    it('should include source location with ARN', async () => {
      const hdf = JSON.parse(await convertAwsConfigToHdf(loadFixture('minimal.json'))) as HDFResults;
      const req = hdf.baselines[0]!.requirements[0]!;
      expect(req.sourceLocation?.ref).toContain('arn:aws:config:');
      expect(req.sourceLocation?.line).toBe(1);
    });

    it('should look up NIST tags via source identifier', async () => {
      // ACCESS_KEYS_ROTATED should have a NIST mapping
      const hdf = JSON.parse(await convertAwsConfigToHdf(loadFixture('minimal.json'))) as HDFResults;
      const req = hdf.baselines[0]!.requirements[0]!;
      expect(req.tags?.['nist']).toBeDefined();
      expect((req.tags?.['nist'] as string[]).length).toBeGreaterThan(0);
    });

    it('should map COMPLIANT to passed', async () => {
      const hdf = JSON.parse(await convertAwsConfigToHdf(loadFixture('minimal.json'))) as HDFResults;
      const results = hdf.baselines[0]!.requirements[0]!.results;
      const compliant = results.find(r => r.status === 'passed');
      expect(compliant).toBeDefined();
    });

    it('should map NON_COMPLIANT to failed', async () => {
      const hdf = JSON.parse(await convertAwsConfigToHdf(loadFixture('minimal.json'))) as HDFResults;
      const results = hdf.baselines[0]!.requirements[0]!.results;
      const failed = results.find(r => r.status === 'failed');
      expect(failed).toBeDefined();
    });

    it('should include code_desc with rule name, resource type, resource id', async () => {
      const hdf = JSON.parse(await convertAwsConfigToHdf(loadFixture('minimal.json'))) as HDFResults;
      const result = hdf.baselines[0]!.requirements[0]!.results[0]!;
      expect(result.codeDesc).toContain('config_rule_name:');
      expect(result.codeDesc).toContain('resource_type:');
      expect(result.codeDesc).toContain('resource_id:');
    });

    it('should include failure message only for failed results', async () => {
      const hdf = JSON.parse(await convertAwsConfigToHdf(loadFixture('minimal.json'))) as HDFResults;
      const results = hdf.baselines[0]!.requirements[0]!.results;

      const failedResult = results.find(r => r.status === 'failed');
      expect(failedResult?.message).toBeTruthy();

      const passedResult = results.find(r => r.status === 'passed');
      expect(passedResult?.message).toBeUndefined();
    });

    it('should handle multiple rules from multi-rule fixture', async () => {
      const hdf = JSON.parse(await convertAwsConfigToHdf(loadFixture('multi-rule.json'))) as HDFResults;
      expect(hdf.baselines[0]!.requirements).toHaveLength(4);
    });

    it('should map NOT_APPLICABLE to notApplicable', async () => {
      const input = JSON.stringify({
        ConfigRules: [{
          ConfigRuleId: 'config-rule-test',
          ConfigRuleName: 'test-rule',
          ConfigRuleArn: 'arn:aws:config:us-east-1:123456789012:config-rule/config-rule-test',
          Description: 'Test rule',
          Source: { Owner: 'AWS', SourceIdentifier: 'TEST_RULE' },
          InputParameters: '{}',
          EvaluationResults: [{
            EvaluationResultIdentifier: {
              EvaluationResultQualifier: {
                ConfigRuleName: 'test-rule',
                ResourceType: 'AWS::S3::Bucket',
                ResourceId: 'my-bucket',
              },
            },
            ComplianceType: 'NOT_APPLICABLE',
            ConfigRuleInvokedTime: '2021-04-09T14:39:21Z',
            ResultRecordedTime: '2021-04-09T14:39:51Z',
          }],
        }],
      });
      const hdf = JSON.parse(await convertAwsConfigToHdf(input)) as HDFResults;
      expect(hdf.baselines[0]!.requirements[0]!.results[0]!.status).toBe('notApplicable');
    });

    it('should map INSUFFICIENT_DATA to notReviewed', async () => {
      const input = JSON.stringify({
        ConfigRules: [{
          ConfigRuleId: 'config-rule-test',
          ConfigRuleName: 'test-rule',
          ConfigRuleArn: 'arn:aws:config:us-east-1:123456789012:config-rule/config-rule-test',
          Description: 'Test rule',
          Source: { Owner: 'AWS', SourceIdentifier: 'TEST_RULE' },
          InputParameters: '{}',
          EvaluationResults: [{
            EvaluationResultIdentifier: {
              EvaluationResultQualifier: {
                ConfigRuleName: 'test-rule',
                ResourceType: 'AWS::S3::Bucket',
                ResourceId: 'my-bucket',
              },
            },
            ComplianceType: 'INSUFFICIENT_DATA',
            ConfigRuleInvokedTime: '2021-04-09T14:39:21Z',
            ResultRecordedTime: '2021-04-09T14:39:51Z',
          }],
        }],
      });
      const hdf = JSON.parse(await convertAwsConfigToHdf(input)) as HDFResults;
      expect(hdf.baselines[0]!.requirements[0]!.results[0]!.status).toBe('notReviewed');
    });

    it('should handle rule with no NIST mapping gracefully', async () => {
      const input = JSON.stringify({
        ConfigRules: [{
          ConfigRuleId: 'config-rule-xyz',
          ConfigRuleName: 'custom-unknown-rule',
          ConfigRuleArn: 'arn:aws:config:us-east-1:123456789012:config-rule/config-rule-xyz',
          Description: 'A custom rule with no NIST mapping',
          Source: { Owner: 'CUSTOM_LAMBDA', SourceIdentifier: 'UNKNOWN_IDENTIFIER_XYZ' },
          InputParameters: '{}',
          EvaluationResults: [],
        }],
      });
      const hdf = JSON.parse(await convertAwsConfigToHdf(input)) as HDFResults;
      const req = hdf.baselines[0]!.requirements[0]!;
      // Should not throw; nist may be empty or absent
      expect(req.id).toBe('config-rule-xyz');
    });

    // Issue #80 bug 2: a Config rule that was deployed and active but
    // evaluated zero in-scope resources (e.g. rds-cluster-multi-az-enabled in
    // an account with no RDS clusters) must still produce a schema-valid
    // requirement. The schema requires `results` to have minItems >= 1;
    // emitting an empty array fails `hdf validate`. The converter
    // synthesizes one notApplicable result with a clear codeDesc.
    it('should synthesize a notApplicable result for a rule with empty EvaluationResults', async () => {
      const input = JSON.stringify({
        ConfigRules: [{
          ConfigRuleId: 'config-rule-empty',
          ConfigRuleName: 'rds-cluster-multi-az-enabled-zerorsrc',
          ConfigRuleArn: 'arn:aws:config:us-east-1:123456789012:config-rule/config-rule-empty',
          Description: 'Checks if RDS clusters are configured for Multi-AZ.',
          Source: { Owner: 'AWS', SourceIdentifier: 'RDS_CLUSTER_MULTI_AZ_ENABLED' },
          InputParameters: '{}',
          EvaluationResults: [],
        }],
      });
      const hdf = JSON.parse(await convertAwsConfigToHdf(input)) as HDFResults;
      const req = hdf.baselines[0]!.requirements[0]!;
      expect(req.results).toHaveLength(1);
      expect(req.results![0]!.status).toBe('notApplicable');
      expect(req.results![0]!.codeDesc).toMatch(/zero/i);
      expect(req.results![0]!.startTime).toBeTruthy();
    });
  });
});
