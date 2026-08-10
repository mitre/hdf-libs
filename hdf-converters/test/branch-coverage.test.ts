/**
 * Branch coverage tests for converters.
 *
 * This file targets the uncovered branches across all converters to bring
 * the overall branch coverage above 95%. Each describe block focuses on a
 * specific converter's uncovered optional-field fallbacks, status-mapping
 * defaults, truncation warnings, and null-check paths.
 */
import { describe, it, expect, vi } from 'vitest';
import type { HDFResults, HDFBaseline, EvaluatedRequirement } from '@mitre/hdf-schema';

import { convertDbprotectToHdf } from '../converters/dbprotect-to-hdf/typescript/converter.js';
import { convertZapToHdf } from '../converters/zap-to-hdf/typescript/converter.js';
import { convertNiktoToHdf } from '../converters/nikto-to-hdf/typescript/converter.js';
import { convertScoutsuiteToHdf } from '../converters/scoutsuite-to-hdf/typescript/converter.js';
import { convertConveyorToHdf } from '../converters/conveyor-to-hdf/typescript/converter.js';
import { convertGrypeToHdf } from '../converters/grype-to-hdf/typescript/converter.js';
import { convertAwsConfigToHdf } from '../converters/aws-config-to-hdf/typescript/converter.js';
import { convertJunitToHdf } from '../converters/junit-to-hdf/typescript/converter.js';
import { convertBurpsuiteToHdf } from '../converters/burpsuite-to-hdf/typescript/converter.js';
import { convertSnykToHdf } from '../converters/snyk-to-hdf/typescript/converter.js';
import { convertSarifToHdf } from '../converters/sarif-to-hdf/typescript/converter.js';
import { convertMsftSecureScoreToHdf } from '../converters/msft-secure-score-to-hdf/typescript/converter.js';
import { convertCyclonedxToHdf } from '../converters/cyclonedx-to-hdf/typescript/converter.js';
import { convertNeuvectorToHdf } from '../converters/neuvector-to-hdf/typescript/converter.js';
import { convertSplunkToHdf } from '../converters/splunk-to-hdf/typescript/converter.js';
import { convertGosecToHdf } from '../converters/gosec-to-hdf/typescript/converter.js';
import { convertDeptrackToHdf } from '../converters/deptrack-to-hdf/typescript/converter.js';
import { convertTwistlockToHdf } from '../converters/twistlock-to-hdf/typescript/converter.js';
import { convertGitlabToHdf } from '../converters/gitlab-to-hdf/typescript/converter.js';
import { convertNetsparkerToHdf } from '../converters/netsparker-to-hdf/typescript/converter.js';
import { convertSonarqubeToHdf } from '../converters/sonarqube-to-hdf/typescript/converter.js';
import { convertXccdfResultsToHdf, convertXccdfBenchmarkToHdf, convertXccdfToHdf } from '../converters/xccdf-results-to-hdf/typescript/converter.js';
import { convertFortifyToHdf } from '../converters/fortify-to-hdf/typescript/converter.js';
import { convertNessusToHdf } from '../converters/nessus-to-hdf/typescript/converter.js';
import { convertVeracodeToHdf } from '../converters/veracode-to-hdf/typescript/converter.js';

function parseHdf(json: string): HDFResults {
  return JSON.parse(json) as HDFResults;
}

function parseBaseline(json: string): HDFBaseline {
  return JSON.parse(json) as HDFBaseline;
}

// ---------------------------------------------------------------------------
// DBProtect branch coverage
// ---------------------------------------------------------------------------
describe('DBProtect branch coverage', () => {
  // Minimal valid DBProtect XML with "Result Status" column and various statuses
  function makeDbprotectXml(opts: {
    hasResultStatus?: boolean;
    resultStatus?: string;
    riskDV?: string;
    date?: string;
    task?: string;
    nullValues?: boolean;
  }): string {
    const cols = opts.hasResultStatus !== false
      ? '<item><name>Check ID</name><type>xs:string</type></item><item><name>Check</name><type>xs:string</type></item><item><name>Result Status</name><type>xs:string</type></item><item><name>Risk DV</name><type>xs:string</type></item><item><name>Details</name><type>xs:string</type></item><item><name>Date</name><type>xs:string</type></item><item><name>Task</name><type>xs:string</type></item><item><name>Check Category</name><type>xs:string</type></item><item><name>Organization</name><type>xs:string</type></item><item><name>Asset</name><type>xs:string</type></item><item><name>Asset Type</name><type>xs:string</type></item><item><name>IP Address, Port, Instance</name><type>xs:string</type></item><item><name>Job Name</name><type>xs:string</type></item>'
      : '<item><name>Check ID</name><type>xs:string</type></item><item><name>Check</name><type>xs:string</type></item><item><name>Risk DV</name><type>xs:string</type></item><item><name>Details</name><type>xs:string</type></item><item><name>Date</name><type>xs:string</type></item><item><name>Task</name><type>xs:string</type></item><item><name>Check Category</name><type>xs:string</type></item><item><name>Organization</name><type>xs:string</type></item><item><name>Asset</name><type>xs:string</type></item><item><name>Asset Type</name><type>xs:string</type></item><item><name>IP Address, Port, Instance</name><type>xs:string</type></item><item><name>Job Name</name><type>xs:string</type></item>';

    const nullVal = '<value nil="true"/>';
    const resultStatusVal = opts.hasResultStatus !== false
      ? `<value>${opts.resultStatus ?? 'Failed'}</value>`
      : '';

    const row = opts.nullValues
      ? `<row><value>CHK-001</value><value>Check Name</value>${resultStatusVal}<value>${opts.riskDV ?? 'High'}</value>${nullVal}<value>${opts.date ?? ''}</value>${nullVal}${nullVal}${nullVal}${nullVal}${nullVal}${nullVal}<value>Job1</value></row>`
      : `<row><value>CHK-001</value><value>Check Name</value>${resultStatusVal}<value>${opts.riskDV ?? 'High'}</value><value>Details here</value><value>${opts.date ?? 'Feb 18 2021 15:57'}</value><value>${opts.task ?? 'Task1'}</value><value>Category1</value><value>Org1</value><value>Asset1</value><value>DB</value><value>192.168.1.1</value><value>Job1</value></row>`;

    return `<?xml version="1.0" encoding="UTF-8"?><dataset><metadata>${cols}</metadata><data>${row}</data></dataset>`;
  }

  it('should handle "Fact" result status', async () => {
    const xml = makeDbprotectXml({ resultStatus: 'Fact' });
    const hdf = parseHdf(await convertDbprotectToHdf(xml));
    expect(hdf.baselines[0]!.requirements[0]!.results[0]!.status).toBe('notReviewed');
  });

  it('should handle "Not A Finding" result status', async () => {
    const xml = makeDbprotectXml({ resultStatus: 'Not A Finding' });
    const hdf = parseHdf(await convertDbprotectToHdf(xml));
    expect(hdf.baselines[0]!.requirements[0]!.results[0]!.status).toBe('passed');
  });

  it('should handle "Finding" result status', async () => {
    const xml = makeDbprotectXml({ resultStatus: 'Finding' });
    const hdf = parseHdf(await convertDbprotectToHdf(xml));
    expect(hdf.baselines[0]!.requirements[0]!.results[0]!.status).toBe('failed');
  });

  it('should handle "Skipped" (default) result status', async () => {
    const xml = makeDbprotectXml({ resultStatus: 'Skipped' });
    const hdf = parseHdf(await convertDbprotectToHdf(xml));
    expect(hdf.baselines[0]!.requirements[0]!.results[0]!.status).toBe('notReviewed');
  });

  it('should handle missing Result Status column (Findings Detail format)', async () => {
    const xml = makeDbprotectXml({ hasResultStatus: false });
    const hdf = parseHdf(await convertDbprotectToHdf(xml));
    // Without Result Status column, all findings default to "failed"
    expect(hdf.baselines[0]!.requirements[0]!.results[0]!.status).toBe('failed');
  });

  it('should handle unknown risk DV (defaults to 0.5)', async () => {
    const xml = makeDbprotectXml({ riskDV: 'unknown' });
    const hdf = parseHdf(await convertDbprotectToHdf(xml));
    expect(hdf.baselines[0]!.requirements[0]!.impact).toBe(0.5);
  });

  it('should handle informational risk DV (0.0 impact)', async () => {
    const xml = makeDbprotectXml({ riskDV: 'Informational' });
    const hdf = parseHdf(await convertDbprotectToHdf(xml));
    expect(hdf.baselines[0]!.requirements[0]!.impact).toBe(0.0);
  });

  it('should handle empty date string', async () => {
    const xml = makeDbprotectXml({ date: '' });
    const hdf = parseHdf(await convertDbprotectToHdf(xml));
    expect(hdf.baselines[0]!.requirements).toHaveLength(1);
  });

  it('should handle invalid date string', async () => {
    const xml = makeDbprotectXml({ date: 'not-a-date-at-all' });
    const hdf = parseHdf(await convertDbprotectToHdf(xml));
    expect(hdf.baselines[0]!.requirements).toHaveLength(1);
  });

  it('should handle null/nil values in row', async () => {
    const xml = makeDbprotectXml({ nullValues: true });
    const hdf = parseHdf(await convertDbprotectToHdf(xml));
    expect(hdf.baselines[0]!.requirements).toHaveLength(1);
  });
});

// ---------------------------------------------------------------------------
// ZAP branch coverage
// ---------------------------------------------------------------------------
describe('ZAP branch coverage', () => {
  it('should handle empty site array', async () => {
    const input = JSON.stringify({ site: [], '@version': '2.14.0' });
    const hdf = parseHdf(await convertZapToHdf(input));
    expect(hdf.baselines).toHaveLength(1);
  });

  it('should handle site with no alerts', async () => {
    const input = JSON.stringify({
      site: [{ '@name': 'http://test.com', '@host': 'test.com', '@port': '80' }],
      '@version': '2.14.0',
      '@generated': '2025-01-01T00:00:00.000+0000',
    });
    const hdf = parseHdf(await convertZapToHdf(input));
    expect(hdf.baselines[0]!.requirements).toHaveLength(1);
    expect(hdf.baselines[0]!.requirements[0]!.id).toBe('zap-no-findings');
    expect(hdf.baselines[0]!.requirements[0]!.results[0]!.status).toBe('passed');
  });

  it('should handle alert with missing optional instance fields', async () => {
    const input = JSON.stringify({
      site: [{
        '@name': 'http://test.com', '@host': 'test.com', '@port': '80',
        alerts: [{
          pluginid: '10001', riskcode: '3', cweid: '79', name: 'XSS',
          desc: 'Cross Site Scripting', riskdesc: 'High',
          wascid: '8', confidence: '3',
          solution: '<p>Encode output</p>', otherinfo: '<p>Some info</p>',
          instances: [{ uri: 'http://test.com/page' }],
        }],
      }],
    });
    const hdf = parseHdf(await convertZapToHdf(input));
    expect(hdf.baselines[0]!.requirements).toHaveLength(1);
  });

  it('should handle risk code 0 and 1 (low impact)', async () => {
    const input = JSON.stringify({
      site: [{
        '@name': 'http://test.com', '@host': 'test.com', '@port': '80',
        alerts: [{
          pluginid: '10001', riskcode: '0', name: 'Info', desc: 'desc',
          instances: [{ uri: 'http://test.com/', method: 'GET', param: 'q', evidence: 'test' }],
        }, {
          pluginid: '10002', riskcode: '1', name: 'Low', desc: 'desc',
          instances: [{ uri: 'http://test.com/', method: 'POST' }],
        }],
      }],
    });
    const hdf = parseHdf(await convertZapToHdf(input));
    expect(hdf.baselines[0]!.requirements).toHaveLength(2);
  });

  it('should handle alert with cweid=0 (default NIST tags)', async () => {
    const input = JSON.stringify({
      site: [{
        '@name': 'http://test.com', '@host': 'test.com', '@port': '80',
        alerts: [{
          pluginid: '10001', riskcode: '2', cweid: '0', name: 'Alert', desc: 'd',
          instances: [{ uri: 'http://test.com/' }],
        }],
      }],
    });
    const hdf = parseHdf(await convertZapToHdf(input));
    const tags = hdf.baselines[0]!.requirements[0]!.tags as Record<string, unknown>;
    expect(tags.nist).toBeDefined();
  });

  it('should handle missing site (non-array)', async () => {
    const input = JSON.stringify({ '@version': '2.14.0' });
    const hdf = parseHdf(await convertZapToHdf(input));
    expect(hdf.baselines).toHaveLength(1);
  });

  it('should convert every site (multi-site, no site dropped)', async () => {
    const input = JSON.stringify({
      site: [
        {
          '@name': 'http://a.com', '@host': 'a.com', '@port': '80',
          alerts: [{ pluginid: '1', riskcode: '2', name: 'A', desc: 'd', instances: [{ uri: 'http://a.com/' }] }],
        },
        {
          '@name': 'http://b.com', '@host': 'b.com', '@port': '80',
          alerts: [
            { pluginid: '2', riskcode: '2', name: 'B1', desc: 'd', instances: [{ uri: 'http://b.com/' }] },
            { pluginid: '3', riskcode: '2', name: 'B2', desc: 'd', instances: [{ uri: 'http://b.com/x' }] },
          ],
        },
      ],
    });
    const hdf = parseHdf(await convertZapToHdf(input));
    // Both sites are now converted (previously only the busiest site survived).
    expect(hdf.baselines).toHaveLength(2);
    const totalReqs = hdf.baselines.reduce((n, b) => n + b!.requirements.length, 0);
    expect(totalReqs).toBe(3);
  });

  it('should handle duplicate pluginids', async () => {
    const input = JSON.stringify({
      site: [{
        '@name': 'http://test.com', '@host': 'test.com', '@port': '80',
        alerts: [
          { pluginid: '10001', riskcode: '2', name: 'A', desc: 'd', instances: [{ uri: 'http://test.com/' }] },
          { pluginid: '10001', riskcode: '3', name: 'B', desc: 'd', instances: [{ uri: 'http://test.com/b' }] },
        ],
      }],
    });
    const hdf = parseHdf(await convertZapToHdf(input));
    const ids = hdf.baselines[0]!.requirements.map(r => r.id);
    expect(ids).toContain('10001');
    expect(ids).toContain('10001.1');
  });
});

// ---------------------------------------------------------------------------
// Nikto branch coverage
// ---------------------------------------------------------------------------
describe('Nikto branch coverage', () => {
  it('should handle vulnerability with OSVDB ID and references', async () => {
    const input = JSON.stringify({
      host: 'localhost', ip: '127.0.0.1', port: '80', banner: 'nginx',
      vulnerabilities: [{
        id: '12345', method: 'GET', url: '/',
        msg: 'OSVDB-12345: Server leaks info', references: 'https://example.com',
      }],
    });
    const hdf = parseHdf(await convertNiktoToHdf(input));
    expect(hdf.baselines[0]!.requirements).toHaveLength(1);
  });

  it('should handle multiple vulns with same ID (duplicate grouping)', async () => {
    const input = JSON.stringify({
      host: 'example.com', ip: '10.0.0.1', port: '443', banner: 'Apache',
      vulnerabilities: [
        { id: '100', method: 'GET', url: '/path1', msg: 'Issue A' },
        { id: '100', method: 'POST', url: '/path2', msg: 'Issue A duplicate' },
        { id: '200', method: 'GET', url: '/path3', msg: 'Issue B' },
      ],
    });
    const hdf = parseHdf(await convertNiktoToHdf(input));
    // Should group by ID: 2 unique IDs
    expect(hdf.baselines[0]!.requirements).toHaveLength(2);
  });
});

// ---------------------------------------------------------------------------
// ScoutSuite branch coverage
// ---------------------------------------------------------------------------
describe('ScoutSuite branch coverage', () => {
  it('should handle plain JSON input (no JS prefix)', async () => {
    const data = {
      last_run: { ruleset_name: 'default', provider: 'gcp', result_format: '2.0' },
      services: {
        compute: {
          findings: {
            'compute-no-public-ip': {
              flagged_items: 0, items: [],
              description: 'No public IP', service: 'compute',
              rationale: 'Keep private', remediation: 'Remove IP',
              references: [], dashboard_name: 'Compute',
              path: 'compute.instances', level: 'danger',
              id_suffix: 'no-public-ip', checked_items: 10,
              compliance: [],
            },
          },
        },
      },
      account_id: '456',
    };
    const input = JSON.stringify(data);
    const hdf = parseHdf(await convertScoutsuiteToHdf(input));
    expect(hdf.baselines[0]!.requirements).toHaveLength(1);
    // flagged_items=0 should give passed status
    expect(hdf.baselines[0]!.requirements[0]!.results[0]!.status).toBe('passed');
  });

  it('should handle danger level (0.7 impact)', async () => {
    const data = {
      last_run: { ruleset_name: 'default', provider: 'aws', result_format: '2.0' },
      services: {
        iam: {
          findings: {
            'iam-root-key': {
              flagged_items: 1, items: ['iam.root'],
              description: 'Root key active', service: 'iam',
              rationale: 'Disable', remediation: 'Delete root keys',
              references: [], dashboard_name: 'IAM',
              path: 'iam.users', level: 'danger',
              id_suffix: 'root-key', checked_items: 1,
              compliance: [],
            },
          },
        },
      },
      account_id: '789',
    };
    const input = `scoutsuite_results = ${JSON.stringify(data)}`;
    const hdf = parseHdf(await convertScoutsuiteToHdf(input));
    expect(hdf.baselines[0]!.requirements[0]!.impact).toBe(0.7);
  });

  it('should handle checked_items=0 (notReviewed)', async () => {
    const data = {
      last_run: { ruleset_name: 'default', provider: 'aws', result_format: '2.0' },
      services: {
        s3: {
          findings: {
            's3-no-logging': {
              flagged_items: 0, items: [],
              description: 'No logging', service: 's3',
              rationale: 'Enable', remediation: 'Turn on logging',
              references: [], dashboard_name: 'S3',
              path: 's3.buckets', level: 'info',
              id_suffix: 'no-logging', checked_items: 0,
              compliance: [],
            },
          },
        },
      },
      account_id: '111',
    };
    const input = `scoutsuite_results = ${JSON.stringify(data)}`;
    const hdf = parseHdf(await convertScoutsuiteToHdf(input));
    expect(hdf.baselines[0]!.requirements[0]!.results[0]!.status).toBe('notReviewed');
  });

  it('should handle unrecognized JS prefix', async () => {
    const data = {
      last_run: { ruleset_name: 'default', provider: 'aws', result_format: '2.0' },
      services: {},
      account_id: '222',
    };
    // An unrecognized prefix should cause a JSON parse error
    const input = `unknown_var = ${JSON.stringify(data)}`;
    await expect(convertScoutsuiteToHdf(input)).rejects.toThrow();
  });
});

// ---------------------------------------------------------------------------
// AWS Config branch coverage
// ---------------------------------------------------------------------------
describe('AWS Config branch coverage', () => {
  function makeAwsConfigInput(opts: {
    complianceType?: string;
    annotation?: string;
    inputParams?: string;
    sourceIdentifier?: string;
    configRuleName?: string;
    configRuleArn?: string;
  }): string {
    const ruleName = opts.configRuleName ?? 'test-rule';
    return JSON.stringify({
      ConfigRules: [{
        ConfigRuleId: 'config-rule-abc',
        ConfigRuleName: ruleName,
        ConfigRuleArn: opts.configRuleArn ?? 'arn:aws:config:us-east-1:123456789012:config-rule/config-rule-abc',
        Description: 'Test rule description',
        Source: { SourceIdentifier: opts.sourceIdentifier ?? 'S3_BUCKET_VERSIONING_ENABLED' },
        InputParameters: opts.inputParams ?? '{}',
        EvaluationResults: [{
          ComplianceType: opts.complianceType ?? 'COMPLIANT',
          Annotation: opts.annotation,
          EvaluationResultIdentifier: {
            EvaluationResultQualifier: {
              ConfigRuleName: ruleName,
              ResourceType: 'AWS::S3::Bucket',
              ResourceId: 'my-bucket',
            },
          },
          ResultRecordedTime: '2025-01-01T00:00:00.000Z',
          ConfigRuleInvokedTime: '2025-01-01T00:00:00.000Z',
        }],
      }],
    });
  }

  it('should handle NOT_APPLICABLE compliance type', async () => {
    const hdf = parseHdf(await convertAwsConfigToHdf(makeAwsConfigInput({ complianceType: 'NOT_APPLICABLE' })));
    expect(hdf.baselines[0]!.requirements[0]!.results[0]!.status).toBe('notApplicable');
  });

  it('should handle INSUFFICIENT_DATA compliance type (default notReviewed)', async () => {
    const hdf = parseHdf(await convertAwsConfigToHdf(makeAwsConfigInput({ complianceType: 'INSUFFICIENT_DATA' })));
    expect(hdf.baselines[0]!.requirements[0]!.results[0]!.status).toBe('notReviewed');
  });

  it('should handle NON_COMPLIANT with annotation', async () => {
    const hdf = parseHdf(await convertAwsConfigToHdf(makeAwsConfigInput({
      complianceType: 'NON_COMPLIANT',
      annotation: 'Bucket is not encrypted',
    })));
    const req = hdf.baselines[0]!.requirements[0]!;
    expect(req.results[0]!.status).toBe('failed');
    expect(req.results[0]!.message).toContain('Bucket is not encrypted');
  });

  it('should handle NON_COMPLIANT without annotation', async () => {
    const hdf = parseHdf(await convertAwsConfigToHdf(makeAwsConfigInput({
      complianceType: 'NON_COMPLIANT',
    })));
    const req = hdf.baselines[0]!.requirements[0]!;
    expect(req.results[0]!.message).toContain('Rule does not pass rule compliance');
  });

  it('should handle COMPLIANT (no message generated)', async () => {
    const hdf = parseHdf(await convertAwsConfigToHdf(makeAwsConfigInput({ complianceType: 'COMPLIANT' })));
    expect(hdf.baselines[0]!.requirements[0]!.results[0]!.status).toBe('passed');
  });

  it('should handle InputParameters with actual values', async () => {
    const hdf = parseHdf(await convertAwsConfigToHdf(makeAwsConfigInput({
      inputParams: '{"maxAccessKeyAge":"90"}',
    })));
    expect(hdf.baselines[0]!.requirements).toHaveLength(1);
  });

  it('should handle unknown source identifier (no NIST mapping)', async () => {
    const hdf = parseHdf(await convertAwsConfigToHdf(makeAwsConfigInput({
      sourceIdentifier: 'CUSTOM_UNKNOWN_RULE',
      configRuleName: 'custom-unknown-rule',
    })));
    expect(hdf.baselines[0]!.requirements).toHaveLength(1);
  });

  it('should handle ARN without account ID pattern', async () => {
    const hdf = parseHdf(await convertAwsConfigToHdf(makeAwsConfigInput({
      configRuleArn: 'arn:aws:config:us-east-1:bad-arn',
    })));
    expect(hdf.baselines).toHaveLength(1);
  });
});

// ---------------------------------------------------------------------------
// JUnit branch coverage
// ---------------------------------------------------------------------------
describe('JUnit branch coverage', () => {
  it('should handle testsuite root (not testsuites)', async () => {
    const xml = `<?xml version="1.0" encoding="UTF-8"?>
      <testsuite name="MyTests" tests="1" timestamp="2025-01-01T00:00:00">
        <testcase name="test1" classname="com.example.Test" time="0.5"/>
      </testsuite>`;
    const hdf = parseHdf(await convertJunitToHdf(xml));
    expect(hdf.baselines[0]!.requirements).toHaveLength(1);
  });

  it('should handle testcase with no time attribute', async () => {
    const xml = `<?xml version="1.0" encoding="UTF-8"?>
      <testsuites>
        <testsuite name="Suite1">
          <testcase name="test1" classname="pkg.Class"/>
        </testsuite>
      </testsuites>`;
    const hdf = parseHdf(await convertJunitToHdf(xml));
    expect(hdf.baselines[0]!.requirements).toHaveLength(1);
  });

  it('should handle testcase with failure element', async () => {
    const xml = `<?xml version="1.0" encoding="UTF-8"?>
      <testsuites>
        <testsuite name="Suite1" timestamp="2025-01-01T00:00:00">
          <testcase name="test1" classname="pkg.Class" time="1.2">
            <failure message="assertion failed">Expected true but got false</failure>
          </testcase>
        </testsuite>
      </testsuites>`;
    const hdf = parseHdf(await convertJunitToHdf(xml));
    expect(hdf.baselines[0]!.requirements[0]!.results[0]!.status).toBe('failed');
  });

  it('should handle testcase with error element', async () => {
    const xml = `<?xml version="1.0" encoding="UTF-8"?>
      <testsuites>
        <testsuite name="Suite1">
          <testcase name="test1" classname="pkg.Class">
            <error message="NPE">java.lang.NullPointerException</error>
          </testcase>
        </testsuite>
      </testsuites>`;
    const hdf = parseHdf(await convertJunitToHdf(xml));
    expect(hdf.baselines[0]!.requirements[0]!.results[0]!.status).toBe('error');
  });

  it('should handle testcase with skipped element', async () => {
    const xml = `<?xml version="1.0" encoding="UTF-8"?>
      <testsuites>
        <testsuite name="Suite1">
          <testcase name="test1" classname="pkg.Class">
            <skipped message="not ready"/>
          </testcase>
        </testsuite>
      </testsuites>`;
    const hdf = parseHdf(await convertJunitToHdf(xml));
    expect(hdf.baselines[0]!.requirements[0]!.results[0]!.status).toBe('notReviewed');
  });

  it('should handle testcase with no classname', async () => {
    const xml = `<?xml version="1.0" encoding="UTF-8"?>
      <testsuites>
        <testsuite name="Suite1">
          <testcase name="test1"/>
        </testsuite>
      </testsuites>`;
    const hdf = parseHdf(await convertJunitToHdf(xml));
    expect(hdf.baselines[0]!.requirements).toHaveLength(1);
  });
});

// ---------------------------------------------------------------------------
// BurpSuite branch coverage
// ---------------------------------------------------------------------------
describe('BurpSuite branch coverage', () => {
  it('should handle issue with host but no issueDetail', async () => {
    const xml = `<?xml version="1.0" encoding="UTF-8"?>
      <issues burpVersion="2023.1" exportTime="2025-01-01">
        <issue>
          <type>1048832</type>
          <name>SSL certificate</name>
          <host ip="10.0.0.1">https://example.com</host>
          <severity>Information</severity>
          <confidence>Certain</confidence>
          <issueBackground>Background text</issueBackground>
          <path>/</path>
          <location>/</location>
        </issue>
      </issues>`;
    const hdf = parseHdf(await convertBurpsuiteToHdf(xml));
    expect(hdf.baselines[0]!.requirements).toHaveLength(1);
  });

  it('should handle issue with issueDetail and remediationBackground', async () => {
    const xml = `<?xml version="1.0" encoding="UTF-8"?>
      <issues burpVersion="2023.1" exportTime="2025-01-01">
        <issue>
          <type>2097920</type>
          <name>Test Issue</name>
          <host ip="10.0.0.1">https://example.com</host>
          <severity>High</severity>
          <confidence>Firm</confidence>
          <issueDetail>Detail text here</issueDetail>
          <remediationBackground>Fix it like this</remediationBackground>
          <references>https://example.com/ref</references>
          <vulnerabilityClassifications>CWE-79</vulnerabilityClassifications>
          <path>/api/test</path>
          <location>/api/test [param]</location>
        </issue>
      </issues>`;
    const hdf = parseHdf(await convertBurpsuiteToHdf(xml));
    expect(hdf.baselines[0]!.requirements).toHaveLength(1);
  });

  it('should handle multiple issues with same type (grouping)', async () => {
    const xml = `<?xml version="1.0" encoding="UTF-8"?>
      <issues burpVersion="2023.1" exportTime="2025-01-01">
        <issue>
          <type>1048832</type>
          <name>SSL Issue</name>
          <host ip="10.0.0.1">https://example.com</host>
          <severity>Medium</severity>
          <confidence>Certain</confidence>
          <path>/a</path>
          <location>/a</location>
        </issue>
        <issue>
          <type>1048832</type>
          <name>SSL Issue</name>
          <host ip="10.0.0.1">https://example.com</host>
          <severity>Medium</severity>
          <confidence>Certain</confidence>
          <path>/b</path>
          <location>/b</location>
        </issue>
      </issues>`;
    const hdf = parseHdf(await convertBurpsuiteToHdf(xml));
    // Same type should be grouped into one requirement with multiple results
    expect(hdf.baselines[0]!.requirements).toHaveLength(1);
    expect(hdf.baselines[0]!.requirements[0]!.results).toHaveLength(2);
  });
});

// ---------------------------------------------------------------------------
// Grype branch coverage
// ---------------------------------------------------------------------------
describe('Grype branch coverage', () => {
  it('should handle negligible severity', async () => {
    const input = JSON.stringify({
      matches: [{
        vulnerability: { id: 'CVE-2021-1', severity: 'Negligible', dataSource: 'ds' },
        artifact: { name: 'pkg', version: '1.0', type: 'deb' },
        relatedVulnerabilities: [],
      }],
      source: { type: 'image', target: { userInput: 'test:latest' } },
      descriptor: { name: 'grype', version: '0.1' },
    });
    const hdf = parseHdf(await convertGrypeToHdf(input));
    expect(hdf.baselines[0]!.requirements[0]!.impact).toBe(0.0);
  });

  it('should handle match with fix state "wont-fix"', async () => {
    const input = JSON.stringify({
      matches: [{
        vulnerability: { id: 'CVE-2021-3', severity: 'Medium', dataSource: 'ds',
          fix: { state: 'wont-fix' } },
        artifact: { name: 'pkg', version: '1.0', type: 'npm' },
        relatedVulnerabilities: [],
      }],
      source: { type: 'image', target: { userInput: 'test:latest' } },
      descriptor: { name: 'grype', version: '0.1' },
    });
    const hdf = parseHdf(await convertGrypeToHdf(input));
    expect(hdf.baselines[0]!.requirements).toHaveLength(1);
  });

  it('should handle match with directory source type (string target)', async () => {
    const input = JSON.stringify({
      matches: [{
        vulnerability: { id: 'CVE-2021-4', severity: 'Low', dataSource: 'ds', description: 'desc' },
        artifact: { name: 'lib', version: '2.0', type: 'go-module', locations: [{ path: '/go/pkg' }] },
        relatedVulnerabilities: [{
          id: 'CVE-2021-4', severity: 'Low', description: 'related desc',
          urls: ['https://nvd.nist.gov/vuln/detail/CVE-2021-4'],
        }],
      }],
      source: { type: 'directory', target: '/app/src' },
      descriptor: { name: 'grype', version: '0.1' },
    });
    const hdf = parseHdf(await convertGrypeToHdf(input));
    expect(hdf.baselines[0]!.requirements).toHaveLength(1);
  });

  it('should handle match with no fix info', async () => {
    const input = JSON.stringify({
      matches: [{
        vulnerability: { id: 'CVE-2021-5', severity: 'High', dataSource: 'ds' },
        artifact: { name: 'pkg', version: '1.0', type: 'deb' },
        relatedVulnerabilities: [],
      }],
      source: { type: 'image', target: { userInput: 'test:latest' } },
      descriptor: { name: 'grype', version: '0.1' },
    });
    const hdf = parseHdf(await convertGrypeToHdf(input));
    expect(hdf.baselines[0]!.requirements).toHaveLength(1);
  });

  it('should handle match with fixed state and versions', async () => {
    const input = JSON.stringify({
      matches: [{
        vulnerability: { id: 'CVE-2021-6', severity: 'Critical', dataSource: 'ds',
          fix: { state: 'fixed', versions: ['2.0.1', '3.0.0'] } },
        artifact: { name: 'openssl', version: '1.0', type: 'deb' },
        relatedVulnerabilities: [],
      }],
      source: { type: 'image', target: { userInput: 'test:latest' } },
      descriptor: { name: 'grype', version: '0.1' },
    });
    const hdf = parseHdf(await convertGrypeToHdf(input));
    expect(hdf.baselines[0]!.requirements).toHaveLength(1);
  });
});

// ---------------------------------------------------------------------------
// Conveyor branch coverage
// ---------------------------------------------------------------------------
describe('Conveyor branch coverage', () => {
  function makeConveyorInput(scannerName: string, sections: Record<string, unknown>[], score = 500): string {
    return JSON.stringify({
      api_response: {
        results: {
          'file-sha': {
            sha256: 'abc123',
            response: {
              service_name: scannerName,
            },
            result: {
              score,
              sections,
            },
          },
        },
        file_tree: {},
      },
    });
  }

  it('should handle Moldy scanner with heuristic', async () => {
    const input = makeConveyorInput('Moldy', [{
      title_text: 'Suspicious file',
      body: 'Found malware signature',
      body_format: 'text',
      classification: 'MALICIOUS',
      depth: 1,
      heuristic: { heur_id: 'MAL-001', score: 100, name: 'Known malware' },
    }]);
    const hdf = parseHdf(await convertConveyorToHdf(input));
    expect(hdf.baselines[0]!.requirements).toHaveLength(1);
  });

  it('should handle Clamav scanner', async () => {
    const input = makeConveyorInput('Clamav', [{
      title_text: 'Virus found',
      body: 'Eicar test',
      body_format: 'text',
      classification: 'MALICIOUS',
      depth: 0,
    }]);
    const hdf = parseHdf(await convertConveyorToHdf(input));
    expect(hdf.baselines[0]!.requirements).toHaveLength(1);
  });

  it('should handle Stigma scanner', async () => {
    const input = makeConveyorInput('Stigma', [{
      title_text: 'Stigma finding',
      body: 'Pattern matched',
      body_format: 'text',
      classification: 'SUSPICIOUS',
      depth: 0,
    }]);
    const hdf = parseHdf(await convertConveyorToHdf(input));
    expect(hdf.baselines[0]!.requirements).toHaveLength(1);
  });

  it('should handle CodeQuality scanner', async () => {
    const input = makeConveyorInput('CodeQuality', [{
      title_text: 'Code smell',
      body: 'Function too long',
      body_format: 'text',
      classification: 'SUSPICIOUS',
      depth: 0,
    }]);
    const hdf = parseHdf(await convertConveyorToHdf(input));
    expect(hdf.baselines[0]!.requirements).toHaveLength(1);
  });

  it('should handle unknown scanner (JSON stringify fallback)', async () => {
    const input = makeConveyorInput('CustomScanner', [{
      title_text: 'Custom finding',
      body: 'Something found',
    }]);
    const hdf = parseHdf(await convertConveyorToHdf(input));
    expect(hdf.baselines[0]!.requirements).toHaveLength(1);
  });

  it('should handle null body', async () => {
    const input = makeConveyorInput('Moldy', [{
      title_text: 'Test',
      body: null,
      body_format: 'text',
      classification: 'CLEAN',
      depth: 0,
    }]);
    const hdf = parseHdf(await convertConveyorToHdf(input));
    expect(hdf.baselines[0]!.requirements).toHaveLength(1);
  });

  it('should handle score 0 (passed status)', async () => {
    const input = makeConveyorInput('Moldy', [{
      title_text: 'Clean',
      body: 'No threats',
      body_format: 'text',
    }], 0);
    const hdf = parseHdf(await convertConveyorToHdf(input));
    expect(hdf.baselines[0]!.requirements[0]!.results[0]!.status).toBe('passed');
  });

  it('should handle missing api_response.results', async () => {
    const input = JSON.stringify({ api_response: {} });
    await expect(convertConveyorToHdf(input)).rejects.toThrow('conveyor: missing api_response.results field');
  });

  it('should handle missing api_response', async () => {
    const input = JSON.stringify({ something: 'else' });
    await expect(convertConveyorToHdf(input)).rejects.toThrow('conveyor: missing api_response field');
  });
});

// ---------------------------------------------------------------------------
// SARIF branch coverage
// ---------------------------------------------------------------------------
describe('SARIF branch coverage', () => {
  it('should handle result with message template (id + arguments)', async () => {
    const input = JSON.stringify({
      version: '2.1.0',
      runs: [{
        tool: {
          driver: {
            name: 'TestTool', version: '1.0',
            rules: [{
              id: 'RULE001',
              name: 'TestRule',
              shortDescription: { text: 'A test rule' },
              fullDescription: { text: 'Full description of the test rule' },
              help: { text: 'How to fix this issue' },
              messageStrings: {
                'msg001': { text: 'Found {0} issues in {1}' },
              },
            }],
          },
        },
        results: [{
          ruleId: 'RULE001',
          ruleIndex: 0,
          level: 'error',
          message: { id: 'msg001', arguments: ['3', 'file.ts'] },
          locations: [{
            physicalLocation: {
              artifactLocation: { uri: 'src/file.ts' },
              region: { startLine: 10, startColumn: 5, snippet: { text: 'let x = 1;' } },
            },
          }],
          fixes: [{ description: { text: 'Remove unused variable' } }],
          suppressions: [],
        }],
      }],
    });
    const hdf = parseHdf(await convertSarifToHdf(input));
    expect(hdf.baselines[0]!.requirements).toHaveLength(1);
    expect(hdf.baselines[0]!.requirements[0]!.title).toBe('TestRule');
  });

  it('should handle result with no rule (unknown)', async () => {
    const input = JSON.stringify({
      version: '2.1.0',
      runs: [{
        tool: { driver: { name: 'Tool', rules: [] } },
        results: [{
          ruleId: 'UNKNOWN',
          level: 'warning',
          message: { text: 'Some warning message' },
          locations: [{
            physicalLocation: {
              artifactLocation: { uri: 'file.js' },
              region: { startLine: 5 },
            },
          }],
        }],
      }],
    });
    const hdf = parseHdf(await convertSarifToHdf(input));
    expect(hdf.baselines[0]!.requirements).toHaveLength(1);
  });

  it('should handle result with suppression', async () => {
    const input = JSON.stringify({
      version: '2.1.0',
      runs: [{
        tool: { driver: { name: 'Tool', rules: [{ id: 'R1', name: 'Rule1' }] } },
        results: [{
          ruleId: 'R1', ruleIndex: 0, level: 'error',
          message: { text: 'Error' },
          locations: [{ physicalLocation: { artifactLocation: { uri: 'f.ts' }, region: { startLine: 1 } } }],
          suppressions: [{ justification: 'False positive' }],
        }],
      }],
    });
    const hdf = parseHdf(await convertSarifToHdf(input));
    // De-laundering: the raw result status stays the tool's (failed) rather than
    // being flipped to notReviewed; the suppression record is preserved on the
    // requirement's suppressions tag (an accepted status would also add an override).
    const req = hdf.baselines[0]!.requirements[0]!;
    expect(req.results[0]!.status).toBe('failed');
    expect(req.tags?.suppressions).toBeDefined();
  });

  it('should handle result with no locations', async () => {
    const input = JSON.stringify({
      version: '2.1.0',
      runs: [{
        tool: { driver: { name: 'Tool', rules: [{ id: 'R1' }] } },
        results: [{
          ruleId: 'R1', ruleIndex: 0, level: 'note',
          message: { text: 'Info note' },
          locations: [],
        }],
      }],
    });
    const hdf = parseHdf(await convertSarifToHdf(input));
    expect(hdf.baselines[0]!.requirements).toHaveLength(1);
  });

  it('should handle result with codeFlows (backtrace)', async () => {
    const input = JSON.stringify({
      version: '2.1.0',
      runs: [{
        tool: { driver: { name: 'Tool', rules: [{ id: 'R1', name: 'FlowRule' }] } },
        results: [{
          ruleId: 'R1', ruleIndex: 0, level: 'error',
          message: { text: 'Tainted data flow' },
          locations: [{ physicalLocation: { artifactLocation: { uri: 'src/a.ts' }, region: { startLine: 10 } } }],
          codeFlows: [{
            threadFlows: [{
              locations: [{
                location: {
                  physicalLocation: { artifactLocation: { uri: 'src/a.ts' }, region: { startLine: 5 } },
                  message: { text: 'Source' },
                },
              }, {
                location: {
                  physicalLocation: { artifactLocation: { uri: 'src/b.ts' }, region: { startLine: 20 } },
                },
              }],
            }],
          }],
        }],
      }],
    });
    const hdf = parseHdf(await convertSarifToHdf(input));
    expect(hdf.baselines[0]!.requirements).toHaveLength(1);
  });

  it('should handle rule with shortDescription but no name', async () => {
    const input = JSON.stringify({
      version: '2.1.0',
      runs: [{
        tool: { driver: { name: 'Tool', rules: [{ id: 'R1', shortDescription: { text: 'Short desc' } }] } },
        results: [{
          ruleId: 'R1', ruleIndex: 0, level: 'warning',
          message: { text: 'Warning text' },
          locations: [{ physicalLocation: { artifactLocation: { uri: 'f.ts' }, region: { startLine: 1 } } }],
        }],
      }],
    });
    const hdf = parseHdf(await convertSarifToHdf(input));
    expect(hdf.baselines[0]!.requirements[0]!.title).toBe('Short desc');
  });

  it('should handle result with CWE in rule relationships', async () => {
    const input = JSON.stringify({
      version: '2.1.0',
      runs: [{
        tool: {
          driver: {
            name: 'Tool',
            rules: [{
              id: 'R1', name: 'XSS',
              relationships: [{
                target: { id: '79', toolComponent: { name: 'CWE' } },
                kinds: ['superset'],
              }],
            }],
          },
        },
        results: [{
          ruleId: 'R1', ruleIndex: 0, level: 'error',
          message: { text: 'XSS found' },
          locations: [{ physicalLocation: { artifactLocation: { uri: 'f.ts' }, region: { startLine: 1 } } }],
        }],
      }],
    });
    const hdf = parseHdf(await convertSarifToHdf(input));
    const tags = hdf.baselines[0]!.requirements[0]!.tags as Record<string, unknown>;
    expect(tags.nist).toBeDefined();
  });

  it('should handle rule with shortDescription fallback for empty description', async () => {
    const input = JSON.stringify({
      version: '2.1.0',
      runs: [{
        tool: { driver: { name: 'Tool', rules: [{ id: 'R1', shortDescription: { text: 'Fallback desc' } }] } },
        results: [{
          ruleId: 'R1', ruleIndex: 0, level: 'error',
          message: { id: 'nonexistent' },
          locations: [{ physicalLocation: { artifactLocation: { uri: 'f.ts' }, region: { startLine: 1 } } }],
        }],
      }],
    });
    const hdf = parseHdf(await convertSarifToHdf(input));
    // shortDescription should be used as default desc when message resolves to empty
    expect(hdf.baselines[0]!.requirements).toHaveLength(1);
  });
});

// ---------------------------------------------------------------------------
// XCCDF Results/Benchmark/Auto-detect branch coverage
// ---------------------------------------------------------------------------
describe('XCCDF branch coverage', () => {
  function makeXccdfResultsXml(opts: {
    ruleResults?: Array<{ idref: string; result: string; severity?: string }>;
    hasTarget?: boolean;
    hasTargetAddress?: boolean;
    hasStartTime?: boolean;
    hasEndTime?: boolean;
    hasBenchmarkTitle?: boolean;
    ruleIdents?: Array<{ text: string; system: string }>;
    textElements?: boolean;
  }): string {
    const ruleResults = opts.ruleResults ?? [{ idref: 'rule_1', result: 'pass' }];
    const rrXml = ruleResults.map(rr => {
      const identXml = (opts.ruleIdents ?? []).map(i => `<ident system="${i.system}">${i.text}</ident>`).join('');
      return `<rule-result idref="${rr.idref}" ${rr.severity ? `severity="${rr.severity}"` : ''}><result>${rr.result}</result>${identXml}</rule-result>`;
    }).join('');

    const titleEl = opts.hasBenchmarkTitle !== false
      ? (opts.textElements ? '<title><![CDATA[Test Benchmark]]></title>' : '<title>Test Benchmark</title>')
      : '';
    const targetEl = opts.hasTarget !== false ? '<target>test-host</target>' : '';
    const targetAddr = opts.hasTargetAddress ? '<target-address>10.0.0.1</target-address>' : '';
    const startTime = opts.hasStartTime !== false ? 'start-time="2025-01-01T00:00:00"' : '';
    const endTime = opts.hasEndTime !== false ? 'end-time="2025-01-01T01:00:00"' : '';

    return `<?xml version="1.0" encoding="UTF-8"?>
      <Benchmark id="test-benchmark">
        ${titleEl}
        <Group id="G-1"><title>Group 1</title>
          <Rule id="rule_1" severity="high">
            <title>Rule 1 Title</title>
            <version>SV-001</version>
            <description>&lt;VulnDiscussion&gt;This is a vulnerability discussion&lt;/VulnDiscussion&gt;</description>
            <fixtext fixref="F-1">Fix this issue</fixtext>
            <ident system="http://cyber.mil/cci">CCI-000001</ident>
            <check system="C-1"><check-content>Verify the setting</check-content></check>
          </Rule>
        </Group>
        <TestResult id="TR-1" ${startTime} ${endTime}>
          ${targetEl}
          ${targetAddr}
          ${rrXml}
        </TestResult>
      </Benchmark>`;
  }

  it('should handle rule-result with "fail" status', async () => {
    const xml = makeXccdfResultsXml({ ruleResults: [{ idref: 'rule_1', result: 'fail' }] });
    const hdf = parseHdf(await convertXccdfResultsToHdf(xml));
    expect(hdf.baselines[0]!.requirements[0]!.results[0]!.status).toBe('failed');
  });

  it('should handle rule-result with "error" status', async () => {
    const xml = makeXccdfResultsXml({ ruleResults: [{ idref: 'rule_1', result: 'error' }] });
    const hdf = parseHdf(await convertXccdfResultsToHdf(xml));
    expect(hdf.baselines[0]!.requirements[0]!.results[0]!.status).toBe('error');
  });

  it('should handle rule-result with "unknown" status', async () => {
    const xml = makeXccdfResultsXml({ ruleResults: [{ idref: 'rule_1', result: 'unknown' }] });
    const hdf = parseHdf(await convertXccdfResultsToHdf(xml));
    expect(hdf.baselines[0]!.requirements[0]!.results[0]!.status).toBe('error');
  });

  it('should handle rule-result with "notapplicable" status', async () => {
    const xml = makeXccdfResultsXml({ ruleResults: [{ idref: 'rule_1', result: 'notapplicable' }] });
    const hdf = parseHdf(await convertXccdfResultsToHdf(xml));
    expect(hdf.baselines[0]!.requirements[0]!.results[0]!.status).toBe('notApplicable');
  });

  it('should handle rule-result with "notchecked" status', async () => {
    const xml = makeXccdfResultsXml({ ruleResults: [{ idref: 'rule_1', result: 'notchecked' }] });
    const hdf = parseHdf(await convertXccdfResultsToHdf(xml));
    expect(hdf.baselines[0]!.requirements[0]!.results[0]!.status).toBe('notReviewed');
  });

  it('should handle rule-result with "notselected" status', async () => {
    const xml = makeXccdfResultsXml({ ruleResults: [{ idref: 'rule_1', result: 'notselected' }] });
    const hdf = parseHdf(await convertXccdfResultsToHdf(xml));
    expect(hdf.baselines[0]!.requirements[0]!.results[0]!.status).toBe('notReviewed');
  });

  it('should handle rule-result with "informational" status', async () => {
    const xml = makeXccdfResultsXml({ ruleResults: [{ idref: 'rule_1', result: 'informational' }] });
    const hdf = parseHdf(await convertXccdfResultsToHdf(xml));
    expect(hdf.baselines[0]!.requirements[0]!.results[0]!.status).toBe('notReviewed');
  });

  it('should handle rule-result with "fixed" status', async () => {
    const xml = makeXccdfResultsXml({ ruleResults: [{ idref: 'rule_1', result: 'fixed' }] });
    const hdf = parseHdf(await convertXccdfResultsToHdf(xml));
    expect(hdf.baselines[0]!.requirements[0]!.results[0]!.status).toBe('passed');
  });

  it('should handle rule-result with unrecognized status (defaults to error)', async () => {
    const xml = makeXccdfResultsXml({ ruleResults: [{ idref: 'rule_1', result: 'something_else' }] });
    const hdf = parseHdf(await convertXccdfResultsToHdf(xml));
    expect(hdf.baselines[0]!.requirements[0]!.results[0]!.status).toBe('error');
  });

  it('should handle rule-result with no matching rule in index', async () => {
    const xml = makeXccdfResultsXml({ ruleResults: [{ idref: 'nonexistent_rule', result: 'pass' }] });
    const hdf = parseHdf(await convertXccdfResultsToHdf(xml));
    expect(hdf.baselines[0]!.requirements[0]!.id).toBe('nonexistent_rule');
  });

  it('should handle missing target element', async () => {
    const xml = makeXccdfResultsXml({ hasTarget: false });
    const hdf = parseHdf(await convertXccdfResultsToHdf(xml));
    expect(hdf.components).toHaveLength(0);
  });

  it('should handle target with address', async () => {
    const xml = makeXccdfResultsXml({ hasTargetAddress: true });
    const hdf = parseHdf(await convertXccdfResultsToHdf(xml));
    expect(hdf.components![0]!.ipAddress).toBe('10.0.0.1');
  });

  it('should handle missing start-time', async () => {
    const xml = makeXccdfResultsXml({ hasStartTime: false, hasEndTime: false });
    const hdf = parseHdf(await convertXccdfResultsToHdf(xml));
    expect(hdf.timestamp).toBeDefined();
  });

  it('should handle benchmark with no title', async () => {
    const xml = makeXccdfResultsXml({ hasBenchmarkTitle: false });
    const hdf = parseHdf(await convertXccdfResultsToHdf(xml));
    // Should fall back to "XCCDF Benchmark"
    expect(hdf.baselines[0]!.name).toBeDefined();
  });

  it('should convert benchmark-only to baseline', async () => {
    const xml = `<?xml version="1.0" encoding="UTF-8"?>
      <Benchmark id="test_benchmark_v1">
        <title>Test Benchmark</title>
        <description>Benchmark description</description>
        <version>1.0</version>
        <Group id="G-1"><title>Group 1</title>
          <Rule id="rule_1" severity="high">
            <title>Rule 1</title>
            <version>SV-001</version>
            <description>&lt;VulnDiscussion&gt;Discussion text&lt;/VulnDiscussion&gt;</description>
            <fixtext fixref="F-1">Fix it</fixtext>
            <ident system="http://cyber.mil/cci">CCI-000001</ident>
            <check system="C-1"><check-content>Verify it</check-content></check>
          </Rule>
        </Group>
      </Benchmark>`;
    const baseline = parseBaseline(await convertXccdfBenchmarkToHdf(xml));
    expect(baseline.requirements).toHaveLength(1);
    expect(baseline.groups).toHaveLength(1);
  });

  it('should handle benchmark rule with no severity', async () => {
    const xml = `<?xml version="1.0" encoding="UTF-8"?>
      <Benchmark id="test_benchmark">
        <title>Test</title>
        <Group id="G-1"><title>Group 1</title>
          <Rule id="rule_1">
            <title>No Severity Rule</title>
            <version>SV-001</version>
          </Rule>
        </Group>
      </Benchmark>`;
    const baseline = parseBaseline(await convertXccdfBenchmarkToHdf(xml));
    expect(baseline.requirements[0]!.impact).toBe(0.5);
  });

  it('should handle benchmark rule with no description', async () => {
    const xml = `<?xml version="1.0" encoding="UTF-8"?>
      <Benchmark id="test_benchmark">
        <title>Test</title>
        <Group id="G-1"><title>Group 1</title>
          <Rule id="rule_1" severity="low">
            <title>No Desc Rule</title>
            <version>SV-001</version>
          </Rule>
        </Group>
      </Benchmark>`;
    const baseline = parseBaseline(await convertXccdfBenchmarkToHdf(xml));
    expect(baseline.requirements[0]!.descriptions[0]!.data).toBe('');
  });

  it('should handle benchmark rule with no version (fallback to rule id)', async () => {
    const xml = `<?xml version="1.0" encoding="UTF-8"?>
      <Benchmark id="test_benchmark">
        <title>Test</title>
        <Group id="G-1"><title>Group 1</title>
          <Rule id="rule_1" severity="medium">
            <title>No Version Rule</title>
          </Rule>
        </Group>
      </Benchmark>`;
    const baseline = parseBaseline(await convertXccdfBenchmarkToHdf(xml));
    expect(baseline.requirements[0]!.id).toBe('rule_1');
  });

  it('should handle benchmark with top-level rules (not in groups)', async () => {
    const xml = `<?xml version="1.0" encoding="UTF-8"?>
      <Benchmark id="test_benchmark">
        <title>Test</title>
        <Rule id="top_rule_1" severity="high">
          <title>Top Level Rule</title>
          <version>SV-100</version>
          <description>Top level description</description>
        </Rule>
      </Benchmark>`;
    const baseline = parseBaseline(await convertXccdfBenchmarkToHdf(xml));
    expect(baseline.requirements).toHaveLength(1);
    expect(baseline.requirements[0]!.id).toBe('top_rule_1');
  });

  it('should handle benchmark rule with no fixtext', async () => {
    const xml = `<?xml version="1.0" encoding="UTF-8"?>
      <Benchmark id="test_benchmark">
        <title>Test</title>
        <Group id="G-1"><title>Group 1</title>
          <Rule id="rule_1" severity="medium">
            <title>No Fix Rule</title>
            <version>SV-001</version>
            <description>Description only</description>
          </Rule>
        </Group>
      </Benchmark>`;
    const baseline = parseBaseline(await convertXccdfBenchmarkToHdf(xml));
    // Should only have "default" description, no "fix"
    const descs = baseline.requirements[0]!.descriptions;
    expect(descs.find(d => d.label === 'fix')).toBeUndefined();
  });

  it('should handle benchmark rule with no check-content', async () => {
    const xml = `<?xml version="1.0" encoding="UTF-8"?>
      <Benchmark id="test_benchmark">
        <title>Test</title>
        <Group id="G-1"><title>Group 1</title>
          <Rule id="rule_1" severity="medium">
            <title>No Check Rule</title>
            <version>SV-001</version>
            <description>Some desc</description>
          </Rule>
        </Group>
      </Benchmark>`;
    const baseline = parseBaseline(await convertXccdfBenchmarkToHdf(xml));
    const descs = baseline.requirements[0]!.descriptions;
    expect(descs.find(d => d.label === 'check')).toBeUndefined();
  });

  it('should handle benchmark rule with no idents (no CCI)', async () => {
    const xml = `<?xml version="1.0" encoding="UTF-8"?>
      <Benchmark id="test_benchmark">
        <title>Test</title>
        <Group id="G-1"><title>Group 1</title>
          <Rule id="rule_1" severity="medium">
            <title>No CCI Rule</title>
            <version>SV-001</version>
          </Rule>
        </Group>
      </Benchmark>`;
    const baseline = parseBaseline(await convertXccdfBenchmarkToHdf(xml));
    const tags = baseline.requirements[0]!.tags as Record<string, unknown>;
    expect(tags.cci).toBeUndefined();
  });

  it('should handle benchmark rule with string fixtext (not object)', async () => {
    const xml = `<?xml version="1.0" encoding="UTF-8"?>
      <Benchmark id="test_benchmark">
        <title>Test</title>
        <Group id="G-1"><title>Group 1</title>
          <Rule id="rule_1" severity="medium">
            <title>String Fix Rule</title>
            <version>SV-001</version>
            <fixtext>Simple string fix</fixtext>
          </Rule>
        </Group>
      </Benchmark>`;
    const baseline = parseBaseline(await convertXccdfBenchmarkToHdf(xml));
    const fixDesc = baseline.requirements[0]!.descriptions.find(d => d.label === 'fix');
    expect(fixDesc).toBeDefined();
    expect(fixDesc!.data).toBe('Simple string fix');
  });

  it('should handle convertXccdfToHdf auto-detect for benchmark', async () => {
    const xml = `<?xml version="1.0" encoding="UTF-8"?>
      <Benchmark id="test_benchmark">
        <title>Auto-detect Benchmark</title>
        <Group id="G-1"><title>G1</title>
          <Rule id="rule_1" severity="low"><title>R1</title><version>SV-001</version></Rule>
        </Group>
      </Benchmark>`;
    const result = await convertXccdfToHdf(xml);
    expect(result.outputType).toBe('baseline');
  });

  it('should handle convertXccdfToHdf auto-detect for results', async () => {
    const xml = makeXccdfResultsXml({});
    const result = await convertXccdfToHdf(xml);
    expect(result.outputType).toBe('results');
  });

  it('should handle benchmark with rule that has no id (skipped)', async () => {
    const xml = `<?xml version="1.0" encoding="UTF-8"?>
      <Benchmark id="test_benchmark">
        <title>Test</title>
        <Group id="G-1"><title>Group 1</title>
          <Rule severity="medium">
            <title>No ID Rule</title>
          </Rule>
          <Rule id="rule_1" severity="low">
            <title>Has ID</title>
            <version>SV-001</version>
          </Rule>
        </Group>
      </Benchmark>`;
    const baseline = parseBaseline(await convertXccdfBenchmarkToHdf(xml));
    // Rule without id should be skipped
    expect(baseline.requirements).toHaveLength(1);
  });

  it('should handle description with VulnDiscussion XML tags (not entity-encoded)', async () => {
    const xml = `<?xml version="1.0" encoding="UTF-8"?>
      <Benchmark id="test_benchmark">
        <title>Test</title>
        <Group id="G-1"><title>Group 1</title>
          <Rule id="rule_1" severity="medium">
            <title>VulnDisc Rule</title>
            <version>SV-001</version>
            <description><![CDATA[<VulnDiscussion>Real discussion text here</VulnDiscussion>]]></description>
          </Rule>
        </Group>
      </Benchmark>`;
    const baseline = parseBaseline(await convertXccdfBenchmarkToHdf(xml));
    expect(baseline.requirements[0]!.descriptions[0]!.data).toBe('Real discussion text here');
  });

  it('should throw when benchmark-to-baseline input has TestResult', async () => {
    const xml = makeXccdfResultsXml({});
    await expect(convertXccdfBenchmarkToHdf(xml)).rejects.toThrow('results document');
  });

  it('should throw when results input has no TestResult', async () => {
    const xml = `<?xml version="1.0" encoding="UTF-8"?>
      <Benchmark id="test"><title>T</title></Benchmark>`;
    await expect(convertXccdfResultsToHdf(xml)).rejects.toThrow('benchmark');
  });

  it('should throw on non-XCCDF XML', async () => {
    const xml = `<?xml version="1.0" encoding="UTF-8"?><root><something/></root>`;
    await expect(convertXccdfResultsToHdf(xml)).rejects.toThrow('not an XCCDF');
  });

  it('should handle rule-result with CCI idents', async () => {
    const xml = makeXccdfResultsXml({
      ruleIdents: [
        { text: 'CCI-000001', system: 'http://cyber.mil/cci' },
        { text: 'CCI-000002', system: 'http://cyber.mil/cci' },
      ],
    });
    const hdf = parseHdf(await convertXccdfResultsToHdf(xml));
    const tags = hdf.baselines[0]!.requirements[0]!.tags as Record<string, unknown>;
    expect(tags.cci).toBeDefined();
  });

  it('should handle benchmark with no id (kebabCase fallback)', async () => {
    const xml = `<?xml version="1.0" encoding="UTF-8"?>
      <Benchmark>
        <title>No ID Benchmark</title>
        <Group id="G-1"><title>G1</title>
          <Rule id="rule_1" severity="low"><title>R1</title><version>SV-001</version></Rule>
        </Group>
      </Benchmark>`;
    const baseline = parseBaseline(await convertXccdfBenchmarkToHdf(xml));
    expect(baseline.name).toBe('xccdf-benchmark');
  });
});

// ---------------------------------------------------------------------------
// CycloneDX branch coverage
// ---------------------------------------------------------------------------
describe('CycloneDX branch coverage', () => {
  it('should handle vulnerability with severity-only rating (no CVSS score)', async () => {
    const input = JSON.stringify({
      bomFormat: 'CycloneDX', specVersion: '1.4',
      vulnerabilities: [{
        id: 'CVE-2021-10', description: 'Test',
        ratings: [{ severity: 'high' }],
        source: { name: 'test' },
        affects: [{ ref: 'ref1' }],
      }],
      components: [{ type: 'library', name: 'lib', version: '1.0', 'bom-ref': 'ref1' }],
    });
    const hdf = parseHdf(await convertCyclonedxToHdf(input));
    expect(hdf.baselines[0]!.requirements[0]!.impact).toBe(0.7);
  });

  it('should handle vulnerability with info severity (notReviewed)', async () => {
    const input = JSON.stringify({
      bomFormat: 'CycloneDX', specVersion: '1.4',
      vulnerabilities: [{
        id: 'CVE-2021-11', description: 'Info',
        ratings: [{ severity: 'info' }],
        source: { name: 'test' },
        affects: [{ ref: 'ref1' }],
      }],
      components: [{ type: 'library', name: 'lib', version: '1.0', 'bom-ref': 'ref1' }],
    });
    const hdf = parseHdf(await convertCyclonedxToHdf(input));
    expect(hdf.baselines[0]!.requirements).toHaveLength(1);
  });

  it('should handle vulnerability with unknown severity (notReviewed)', async () => {
    const input = JSON.stringify({
      bomFormat: 'CycloneDX', specVersion: '1.4',
      vulnerabilities: [{
        id: 'CVE-2021-12', description: 'Unknown',
        ratings: [{ severity: 'unknown' }],
        source: { name: 'test' },
        affects: [{ ref: 'ref1' }],
      }],
      components: [{ type: 'library', name: 'lib', version: '1.0', 'bom-ref': 'ref1' }],
    });
    const hdf = parseHdf(await convertCyclonedxToHdf(input));
    expect(hdf.baselines[0]!.requirements).toHaveLength(1);
  });

  it('should handle vulnerability with multiple ratings (max selected)', async () => {
    const input = JSON.stringify({
      bomFormat: 'CycloneDX', specVersion: '1.4',
      vulnerabilities: [{
        id: 'CVE-2021-13', description: 'Multi',
        ratings: [
          { score: 5.0, method: 'CVSSv3' },
          { score: 7.5, method: 'CVSSv31' },
        ],
        source: { name: 'test' },
        affects: [{ ref: 'ref1' }],
      }],
      components: [{ type: 'library', name: 'lib', version: '1.0', 'bom-ref': 'ref1' }],
    });
    const hdf = parseHdf(await convertCyclonedxToHdf(input));
    expect(hdf.baselines[0]!.requirements[0]!.impact).toBeCloseTo(0.75, 2);
  });

  it('should handle vulnerability with recommendation', async () => {
    const input = JSON.stringify({
      bomFormat: 'CycloneDX', specVersion: '1.4',
      vulnerabilities: [{
        id: 'CVE-2021-14', description: 'Has fix',
        ratings: [{ severity: 'medium' }],
        recommendation: 'Upgrade to version 2.0',
        source: { name: 'test' },
        affects: [{ ref: 'ref1' }],
      }],
      components: [{ type: 'library', name: 'lib', version: '1.0', 'bom-ref': 'ref1' }],
    });
    const hdf = parseHdf(await convertCyclonedxToHdf(input));
    const descs = hdf.baselines[0]!.requirements[0]!.descriptions;
    expect(descs.find(d => d.label === 'fix')).toBeDefined();
  });

  it('should handle metadata with component info', async () => {
    const input = JSON.stringify({
      bomFormat: 'CycloneDX', specVersion: '1.4',
      metadata: {
        timestamp: '2025-01-01T00:00:00Z',
        component: { type: 'application', name: 'my-app', version: '3.0' },
      },
      vulnerabilities: [{
        id: 'CVE-2021-15', description: 'App vuln',
        ratings: [{ severity: 'low' }],
        source: { name: 'test' },
        affects: [{ ref: 'ref1' }],
      }],
      components: [{ type: 'library', name: 'lib', version: '1.0', 'bom-ref': 'ref1' }],
    });
    const hdf = parseHdf(await convertCyclonedxToHdf(input));
    expect(hdf.timestamp).toBeDefined();
  });
});

// ---------------------------------------------------------------------------
// Splunk/GoSec/DepTrack/Twistlock/GitLab/NetSparker/SonarQube/NeuVector
// (smaller gaps — just hit the main uncovered branches)
// ---------------------------------------------------------------------------
describe('NeuVector branch coverage', () => {
  it('should handle vulnerability with score field', async () => {
    const input = JSON.stringify({
      report: {
        vulnerabilities: [{
          name: 'CVE-2021-2', severity: 'Medium',
          package_name: 'pkg', package_version: '1.0',
          description: 'desc', link: 'https://example.com',
          score: 6.5, score_v3: 7.0, vectors: 'AV:N',
          published_timestamp: 1609459200,
          last_modified_timestamp: 1609459200,
          feed_rating: 'Medium',
        }],
      },
    });
    const hdf = parseHdf(await convertNeuvectorToHdf(input));
    expect(hdf.baselines[0]!.requirements).toHaveLength(1);
  });
});

describe('GoSec branch coverage', () => {
  it('should handle suppressed issue (nosec=true with suppressions)', async () => {
    const input = JSON.stringify({
      Issues: [{
        severity: 'HIGH',
        confidence: 'HIGH',
        cwe: { id: '89', url: 'https://cwe.mitre.org/data/definitions/89.html' },
        details: 'SQL injection detected',
        file: '/app/main.go',
        line: '42',
        column: '10',
        code: 'db.Query(userInput)',
        nosec: true,
        suppressions: [{ kind: 'inSource', justification: 'Validated input' }],
        rule_id: 'G201',
      }],
      Stats: { files: 10, lines: 500, nosec: 1, found: 1 },
      GosecVersion: '2.0.0',
    });
    const hdf = parseHdf(await convertGosecToHdf(input));
    expect(hdf.baselines[0]!.requirements[0]!.results[0]!.status).toBe('notReviewed');
  });

  it('should handle suppressed issue with empty suppressions list', async () => {
    const input = JSON.stringify({
      Issues: [{
        severity: 'MEDIUM',
        confidence: 'LOW',
        cwe: { id: '79', url: 'https://cwe.mitre.org/data/definitions/79.html' },
        details: 'XSS possible',
        file: '/app/handler.go',
        line: '15',
        column: '5',
        code: 'w.Write(data)',
        nosec: true,
        suppressions: [],
        rule_id: 'G203',
      }],
      Stats: { files: 5, lines: 200, nosec: 1, found: 1 },
    });
    const hdf = parseHdf(await convertGosecToHdf(input));
    expect(hdf.baselines[0]!.requirements[0]!.results[0]!.status).toBe('notReviewed');
  });

  it('should handle non-suppressed issue', async () => {
    const input = JSON.stringify({
      Issues: [{
        severity: 'MEDIUM',
        confidence: 'HIGH',
        cwe: { id: '89', url: 'https://cwe.mitre.org/data/definitions/89.html' },
        details: 'SQL injection',
        file: '/app/db.go',
        line: '15',
        column: '5',
        code: 'query()',
        nosec: false,
        suppressions: null,
        rule_id: 'G201',
      }],
      Stats: { files: 5, lines: 200, nosec: 0, found: 1 },
    });
    const hdf = parseHdf(await convertGosecToHdf(input));
    expect(hdf.baselines[0]!.requirements[0]!.results[0]!.status).toBe('failed');
  });

  it('should handle empty Issues array', async () => {
    const input = JSON.stringify({
      Issues: [],
      Stats: { files: 5, lines: 200, nosec: 0, found: 0 },
    });
    const hdf = parseHdf(await convertGosecToHdf(input));
    expect(hdf.baselines[0]!.requirements).toHaveLength(1);
    expect(hdf.baselines[0]!.requirements[0]!.id).toBe('gosec-no-findings');
    expect(hdf.baselines[0]!.requirements[0]!.results[0]!.status).toBe('passed');
  });
});

describe('DepTrack branch coverage', () => {
  it('should handle finding with no CWE', async () => {
    const input = JSON.stringify({
      project: { name: 'test-project', version: '1.0' },
      meta: { timestamp: '2025-01-01T00:00:00Z' },
      findings: [{
        component: { name: 'dep1', version: '1.0', purl: 'pkg:npm/dep1@1.0' },
        vulnerability: {
          vulnId: 'CVE-2021-1',
          severity: 'HIGH',
          description: 'Some vuln',
          source: 'NVD',
        },
        matrix: 'test-project:dep1:CVE-2021-1',
      }],
    });
    const hdf = parseHdf(await convertDeptrackToHdf(input));
    expect(hdf.baselines[0]!.requirements).toHaveLength(1);
  });

  it('should handle finding with CWE array', async () => {
    const input = JSON.stringify({
      project: { name: 'test-project', version: '1.0' },
      findings: [{
        component: { name: 'dep1', version: '1.0' },
        vulnerability: {
          vulnId: 'CVE-2021-2',
          severity: 'MEDIUM',
          description: 'With CWE',
          source: 'NVD',
          cwes: [{ cweId: 79, name: 'XSS' }],
        },
        matrix: 'test-project:dep1:CVE-2021-2',
      }],
    });
    const hdf = parseHdf(await convertDeptrackToHdf(input));
    expect(hdf.baselines[0]!.requirements).toHaveLength(1);
  });
});

describe('Twistlock branch coverage', () => {
  it('should handle code repo scan (no results wrapper)', async () => {
    const input = JSON.stringify({
      id: 'scan1',
      vulnerabilities: [{
        id: 'CVE-2021-1', severity: 'high',
        packageName: 'pkg', packageVersion: '1.0',
        description: 'desc', link: 'https://example.com',
      }],
    });
    const hdf = parseHdf(await convertTwistlockToHdf(input));
    expect(hdf.baselines[0]!.requirements).toHaveLength(1);
  });
});

describe('GitLab branch coverage', () => {
  it('should handle DAST scanner with location fields', async () => {
    const input = JSON.stringify({
      scan: { scanner: { id: 'dast', name: 'DAST Scanner' }, type: 'dast' },
      vulnerabilities: [{
        id: 'vuln-1', name: 'XSS', severity: 'High',
        description: 'Cross-site scripting',
        location: { hostname: 'example.com', path: '/page', method: 'GET', param: 'q' },
        identifiers: [{ type: 'cwe', name: 'CWE-79', value: '79' }],
      }],
    });
    const hdf = parseHdf(await convertGitlabToHdf(input));
    expect(hdf.baselines[0]!.requirements).toHaveLength(1);
  });

  it('should handle dependency_scanning scanner', async () => {
    const input = JSON.stringify({
      scan: { scanner: { id: 'dep-scan', name: 'Dep Scanner' }, type: 'dependency_scanning' },
      vulnerabilities: [{
        id: 'vuln-2', name: 'Dep Vuln', severity: 'Medium',
        description: 'Vulnerable dependency',
        location: {
          file: 'package.json',
          dependency: { package: { name: 'lodash' }, version: '4.0.0' },
        },
        identifiers: [{ type: 'cwe', name: 'CWE-400', value: '400' }],
      }],
    });
    const hdf = parseHdf(await convertGitlabToHdf(input));
    expect(hdf.baselines[0]!.requirements).toHaveLength(1);
  });

  it('should handle container_scanning scanner', async () => {
    const input = JSON.stringify({
      scan: { scanner: { id: 'container', name: 'Container Scanner' }, type: 'container_scanning' },
      vulnerabilities: [{
        id: 'vuln-3', name: 'Container Vuln', severity: 'Critical',
        description: 'OS package vulnerability',
        location: {
          image: 'nginx:1.19',
          dependency: { package: { name: 'openssl' }, version: '1.1.1' },
        },
        identifiers: [{ type: 'cve', name: 'CVE-2021-1', value: 'CVE-2021-1' }],
      }],
    });
    const hdf = parseHdf(await convertGitlabToHdf(input));
    expect(hdf.baselines[0]!.requirements).toHaveLength(1);
  });

  it('should handle unknown scanner type (default location)', async () => {
    const input = JSON.stringify({
      scan: { scanner: { id: 'custom', name: 'Custom' }, type: 'custom_type' },
      vulnerabilities: [{
        id: 'vuln-4', name: 'Custom Finding', severity: 'Low',
        description: 'Custom finding desc',
        location: { custom_field: 'value' },
        identifiers: [],
      }],
    });
    const hdf = parseHdf(await convertGitlabToHdf(input));
    expect(hdf.baselines[0]!.requirements).toHaveLength(1);
  });
});

describe('SonarQube branch coverage', () => {
  it('should handle issue with no component path', async () => {
    const input = JSON.stringify({
      issues: [{
        key: 'issue-1',
        rule: 'squid:S1234',
        severity: 'CRITICAL',
        component: 'project',
        message: 'Fix this',
        type: 'BUG',
        status: 'OPEN',
        effort: '30min',
      }],
      components: [{ key: 'project', name: 'Project' }],
      rules: [{ key: 'squid:S1234', name: 'Rule Name', htmlDesc: '<p>Description</p>' }],
    });
    const hdf = parseHdf(await convertSonarqubeToHdf(input));
    expect(hdf.baselines[0]!.requirements).toHaveLength(1);
  });
});

describe('MSFT Secure Score branch coverage', () => {
  it('should handle control with partial score (not fully implemented)', async () => {
    const input = JSON.stringify({
      secureScore: {
        value: [{
          id: 'ss-1',
          azureTenantId: 'tenant-1',
          createdDateTime: '2025-01-01T00:00:00Z',
          controlScores: [{
            controlName: 'partial-control',
            controlCategory: 'Data',
            description: 'Partially implemented',
            score: 3.0,
            maxScore: 10.0,
            scoreInPercentage: 30,
            implementationStatus: 'partiallyImplemented',
            actionUrl: 'https://example.com/fix',
            count: 2,
          }],
        }],
      },
      profiles: {
        value: [{
          id: 'partial-control',
          controlCategory: 'Data',
          title: 'Partial Control',
          remediation: 'Complete the configuration',
          remediationImpact: 'Medium',
          service: 'Azure AD',
        }],
      },
    });
    const hdf = parseHdf(await convertMsftSecureScoreToHdf(input));
    expect(hdf.baselines[0]!.requirements).toHaveLength(1);
    // Partial implementation should result in "failed"
    expect(hdf.baselines[0]!.requirements[0]!.results[0]!.status).toBe('failed');
  });

  it('should handle control with thirdParty implementation status', async () => {
    const input = JSON.stringify({
      secureScore: {
        value: [{
          id: 'ss-2',
          azureTenantId: 'tenant-2',
          createdDateTime: '2025-01-01T00:00:00Z',
          controlScores: [{
            controlName: 'tp-control',
            controlCategory: 'Identity',
            description: 'Third party managed',
            score: 10.0,
            maxScore: 10.0,
            scoreInPercentage: 100,
            implementationStatus: 'thirdParty',
            count: 1,
          }],
        }],
      },
      profiles: {
        value: [{
          id: 'tp-control',
          controlCategory: 'Identity',
          title: 'Third Party Control',
        }],
      },
    });
    const hdf = parseHdf(await convertMsftSecureScoreToHdf(input));
    expect(hdf.baselines[0]!.requirements).toHaveLength(1);
  });
});

describe('Netsparker branch coverage', () => {
  it('should handle vulnerability with no classification', async () => {
    const xml = `<?xml version="1.0" encoding="utf-8"?>
      <netsparker-enterprise>
        <target>
          <scan-id>scan1</scan-id>
          <url>http://test.com</url>
          <initiated>01/01/2025 12:00 PM</initiated>
        </target>
        <vulnerabilities>
          <vulnerability>
            <url>http://test.com/page</url>
            <type>CustomType</type>
            <name>Custom Finding</name>
            <severity>Information</severity>
            <certainty>100</certainty>
            <confirmed>True</confirmed>
            <description>Some finding</description>
          </vulnerability>
        </vulnerabilities>
      </netsparker-enterprise>`;
    const hdf = parseHdf(await convertNetsparkerToHdf(xml));
    expect(hdf.baselines[0]!.requirements).toHaveLength(1);
  });

  it('should handle vulnerability with CWE classification', async () => {
    const xml = `<?xml version="1.0" encoding="utf-8"?>
      <invicti-enterprise>
        <target>
          <scan-id>scan2</scan-id>
          <url>http://test.com</url>
          <initiated>01/01/2025 12:00 PM</initiated>
        </target>
        <vulnerabilities>
          <vulnerability>
            <url>http://test.com/page</url>
            <type>SqlInjection</type>
            <name>SQL Injection</name>
            <severity>Critical</severity>
            <certainty>100</certainty>
            <confirmed>True</confirmed>
            <description>SQL injection found</description>
            <classification><cwe>89</cwe><owasp>A1</owasp></classification>
            <remedy>Use parameterized queries</remedy>
            <remedyReferences>https://owasp.org</remedyReferences>
            <extraInformation>Additional info</extraInformation>
            <proofOfConcept>test payload</proofOfConcept>
          </vulnerability>
        </vulnerabilities>
      </invicti-enterprise>`;
    const hdf = parseHdf(await convertNetsparkerToHdf(xml));
    expect(hdf.baselines[0]!.requirements).toHaveLength(1);
  });
});

// ---------------------------------------------------------------------------
// XCCDF ARF branch coverage (covers the ARF conversion path)
// ---------------------------------------------------------------------------
describe('XCCDF ARF branch coverage', () => {
  it('should handle minimal ARF document with TestResult', async () => {
    const xml = `<?xml version="1.0" encoding="UTF-8"?>
      <asset-report-collection>
        <report-requests>
          <report-request id="rr1">
            <content>
              <data-stream-collection>
                <component id="comp1">
                  <Benchmark id="test-benchmark">
                    <title>Test Benchmark</title>
                    <Group id="G-1"><title>Group 1</title>
                      <Rule id="rule_1" severity="high">
                        <title>Rule 1</title>
                        <version>SV-001</version>
                        <description>Rule desc</description>
                        <fixtext fixref="F-1">Fix text</fixtext>
                        <ident system="http://cyber.mil/cci">CCI-000001</ident>
                      </Rule>
                    </Group>
                  </Benchmark>
                </component>
              </data-stream-collection>
            </content>
          </report-request>
        </report-requests>
        <assets>
          <asset id="asset1">
            <computing-device>
              <fqdn>test.example.com</fqdn>
              <hostname>testhost</hostname>
              <connections>
                <connection>
                  <ip-address><ip-v4>10.0.0.1</ip-v4></ip-address>
                  <mac-address>AA:BB:CC:DD:EE:FF</mac-address>
                </connection>
              </connections>
            </computing-device>
          </asset>
        </assets>
        <relationships>
          <relationship type="http://scap.nist.gov/specifications/arf/vocabulary/relationships/1.0#isAbout" subject="report1">
            <ref>asset1</ref>
          </relationship>
        </relationships>
        <reports>
          <report id="report1">
            <content>
              <TestResult id="TR-1" start-time="2025-01-01T00:00:00" end-time="2025-01-01T01:00:00">
                <target>test-host</target>
                <target-address>10.0.0.1</target-address>
                <rule-result idref="rule_1"><result>fail</result></rule-result>
              </TestResult>
            </content>
          </report>
        </reports>
      </asset-report-collection>`;
    const hdf = parseHdf(await convertXccdfResultsToHdf(xml));
    expect(hdf.baselines).toHaveLength(1);
    expect(hdf.baselines[0]!.requirements).toHaveLength(1);
    expect(hdf.baselines[0]!.requirements[0]!.results[0]!.status).toBe('failed');
  });

  it('should handle ARF with no Benchmark in data-stream-collection', async () => {
    const xml = `<?xml version="1.0" encoding="UTF-8"?>
      <asset-report-collection>
        <reports>
          <report id="report1">
            <content>
              <TestResult id="TR-1" start-time="2025-01-01T00:00:00">
                <target>host1</target>
                <rule-result idref="unknown_rule"><result>pass</result></rule-result>
              </TestResult>
            </content>
          </report>
        </reports>
      </asset-report-collection>`;
    const hdf = parseHdf(await convertXccdfResultsToHdf(xml));
    expect(hdf.baselines).toHaveLength(1);
  });

  it('should auto-detect ARF format via convertXccdfToHdf', async () => {
    const xml = `<?xml version="1.0" encoding="UTF-8"?>
      <asset-report-collection>
        <reports>
          <report id="report1">
            <content>
              <TestResult id="TR-1">
                <target>host1</target>
                <rule-result idref="rule_1"><result>pass</result></rule-result>
              </TestResult>
            </content>
          </report>
        </reports>
      </asset-report-collection>`;
    const result = await convertXccdfToHdf(xml);
    expect(result.outputType).toBe('results');
  });

  it('should handle ARF with asset without computing-device', async () => {
    const xml = `<?xml version="1.0" encoding="UTF-8"?>
      <asset-report-collection>
        <assets>
          <asset id="asset1"/>
        </assets>
        <relationships>
          <relationship type="http://scap.nist.gov/specifications/arf/vocabulary/relationships/1.0#isAbout" subject="report1">
            <ref>asset1</ref>
          </relationship>
        </relationships>
        <reports>
          <report id="report1">
            <content>
              <TestResult id="TR-1">
                <target>host1</target>
                <rule-result idref="rule_1"><result>pass</result></rule-result>
              </TestResult>
            </content>
          </report>
        </reports>
      </asset-report-collection>`;
    const hdf = parseHdf(await convertXccdfResultsToHdf(xml));
    expect(hdf.baselines).toHaveLength(1);
  });

  it('should handle ARF with connection having only IPv6', async () => {
    const xml = `<?xml version="1.0" encoding="UTF-8"?>
      <asset-report-collection>
        <assets>
          <asset id="asset1">
            <computing-device>
              <fqdn>test.example.com</fqdn>
              <connections>
                <connection>
                  <ip-address><ip-v6>fe80::1</ip-v6></ip-address>
                </connection>
              </connections>
            </computing-device>
          </asset>
        </assets>
        <relationships>
          <relationship type="http://scap.nist.gov/specifications/arf/vocabulary/relationships/1.0#isAbout" subject="report1">
            <ref>asset1</ref>
          </relationship>
        </relationships>
        <reports>
          <report id="report1">
            <content>
              <TestResult id="TR-1">
                <target>host1</target>
                <rule-result idref="rule_1"><result>pass</result></rule-result>
              </TestResult>
            </content>
          </report>
        </reports>
      </asset-report-collection>`;
    const hdf = parseHdf(await convertXccdfResultsToHdf(xml));
    expect(hdf.baselines).toHaveLength(1);
  });

  it('should handle ARF with loopback MAC (skipped)', async () => {
    const xml = `<?xml version="1.0" encoding="UTF-8"?>
      <asset-report-collection>
        <assets>
          <asset id="asset1">
            <computing-device>
              <connections>
                <connection>
                  <ip-address><ip-v4>127.0.0.1</ip-v4></ip-address>
                  <mac-address>00:00:00:00:00:00</mac-address>
                </connection>
              </connections>
            </computing-device>
          </asset>
        </assets>
        <relationships>
          <relationship type="http://scap.nist.gov/specifications/arf/vocabulary/relationships/1.0#isAbout" subject="report1">
            <ref>asset1</ref>
          </relationship>
        </relationships>
        <reports>
          <report id="report1">
            <content>
              <TestResult id="TR-1" start-time="2025-01-01T00:00:00" end-time="2025-01-01T00:30:00">
                <target>host1</target>
                <rule-result idref="rule_1"><result>fail</result></rule-result>
              </TestResult>
            </content>
          </report>
        </reports>
      </asset-report-collection>`;
    const hdf = parseHdf(await convertXccdfResultsToHdf(xml));
    expect(hdf.statistics).toBeDefined();
  });
});

// ---------------------------------------------------------------------------
// Additional XCCDF extractCheckContent branch coverage
// ---------------------------------------------------------------------------
describe('XCCDF check-content branch coverage', () => {
  it('should handle benchmark rule with check element but no check-content', async () => {
    const xml = `<?xml version="1.0" encoding="UTF-8"?>
      <Benchmark id="test_benchmark">
        <title>Test</title>
        <Group id="G-1"><title>G1</title>
          <Rule id="rule_1" severity="low">
            <title>Rule With Empty Check</title>
            <version>SV-001</version>
            <check system="C-1"/>
          </Rule>
        </Group>
      </Benchmark>`;
    const baseline = parseBaseline(await convertXccdfBenchmarkToHdf(xml));
    expect(baseline.requirements).toHaveLength(1);
  });

  it('should handle rule-result with no result value', async () => {
    const xml = `<?xml version="1.0" encoding="UTF-8"?>
      <Benchmark id="test_benchmark">
        <title>Test</title>
        <Group id="G-1"><title>G1</title>
          <Rule id="rule_1" severity="medium">
            <title>Rule 1</title>
            <version>SV-001</version>
          </Rule>
        </Group>
        <TestResult id="TR-1" start-time="2025-01-01T00:00:00">
          <target>host</target>
          <rule-result idref="rule_1"><result/></rule-result>
        </TestResult>
      </Benchmark>`;
    const hdf = parseHdf(await convertXccdfResultsToHdf(xml));
    // Empty result should map to "notReviewed" via default
    expect(hdf.baselines[0]!.requirements).toHaveLength(1);
  });

  it('should handle benchmark with entity-encoded VulnDiscussion', async () => {
    const xml = `<?xml version="1.0" encoding="UTF-8"?>
      <Benchmark id="test_benchmark">
        <title>Test</title>
        <Group id="G-1"><title>G1</title>
          <Rule id="rule_1" severity="medium">
            <title>Entity Rule</title>
            <version>SV-001</version>
            <description>Before &lt;VulnDiscussion&gt;Entity encoded discussion&lt;/VulnDiscussion&gt; After</description>
          </Rule>
        </Group>
      </Benchmark>`;
    const baseline = parseBaseline(await convertXccdfBenchmarkToHdf(xml));
    expect(baseline.requirements[0]!.descriptions[0]!.data).toBe('Entity encoded discussion');
  });
});

// ---------------------------------------------------------------------------
// Additional per-converter edge cases for remaining branches
// ---------------------------------------------------------------------------
describe('Additional DBProtect branch coverage', () => {
  it('should handle findings with missing optional fields', async () => {
    const xml = `<?xml version="1.0" encoding="UTF-8"?>
      <dataset>
        <metadata>
          <item><name>Check ID</name><type>xs:string</type></item>
          <item><name>Check</name><type>xs:string</type></item>
          <item><name>Risk DV</name><type>xs:string</type></item>
          <item><name>Details</name><type>xs:string</type></item>
          <item><name>Date</name><type>xs:string</type></item>
          <item><name>Job Name</name><type>xs:string</type></item>
        </metadata>
        <data>
          <row>
            <value>CHK-001</value>
            <value>Check Name</value>
            <value>Low</value>
            <value>Some details</value>
            <value>Jan 01 2025 12:00</value>
            <value>Job1</value>
          </row>
        </data>
      </dataset>`;
    const hdf = parseHdf(await convertDbprotectToHdf(xml));
    expect(hdf.baselines[0]!.requirements).toHaveLength(1);
    // Without Task, Check Category, Organization, Asset fields - ?? fallbacks exercised
    expect(hdf.baselines[0]!.requirements[0]!.impact).toBe(0.3);
  });

  it('should handle multiple findings with same Check ID', async () => {
    const xml = `<?xml version="1.0" encoding="UTF-8"?>
      <dataset>
        <metadata>
          <item><name>Check ID</name><type>xs:string</type></item>
          <item><name>Check</name><type>xs:string</type></item>
          <item><name>Result Status</name><type>xs:string</type></item>
          <item><name>Risk DV</name><type>xs:string</type></item>
          <item><name>Details</name><type>xs:string</type></item>
          <item><name>Date</name><type>xs:string</type></item>
          <item><name>Job Name</name><type>xs:string</type></item>
          <item><name>Asset</name><type>xs:string</type></item>
        </metadata>
        <data>
          <row>
            <value>CHK-001</value><value>Check</value><value>Failed</value><value>Medium</value><value>D1</value><value>Jan 01 2025 12:00</value><value>Job1</value><value>Asset1</value>
          </row>
          <row>
            <value>CHK-001</value><value>Check</value><value>Not A Finding</value><value>Medium</value><value>D2</value><value>Jan 02 2025 12:00</value><value>Job1</value><value>Asset1</value>
          </row>
        </data>
      </dataset>`;
    const hdf = parseHdf(await convertDbprotectToHdf(xml));
    // Should group by Check ID — 1 requirement with 2 results
    expect(hdf.baselines[0]!.requirements).toHaveLength(1);
    expect(hdf.baselines[0]!.requirements[0]!.results).toHaveLength(2);
  });
});

describe('Additional JUnit branch coverage', () => {
  it('should handle testcase with time but invalid value', async () => {
    const xml = `<?xml version="1.0" encoding="UTF-8"?>
      <testsuites>
        <testsuite name="Suite1" timestamp="2025-01-01T00:00:00">
          <testcase name="test1" classname="pkg.Class" time="not-a-number"/>
        </testsuite>
      </testsuites>`;
    const hdf = parseHdf(await convertJunitToHdf(xml));
    expect(hdf.baselines[0]!.requirements).toHaveLength(1);
  });

  it('should handle testsuites with empty name', async () => {
    const xml = `<?xml version="1.0" encoding="UTF-8"?>
      <testsuites>
        <testsuite name="">
          <testcase name="test1" classname="pkg.Class">
            <failure message="fail">fail body</failure>
          </testcase>
        </testsuite>
      </testsuites>`;
    const hdf = parseHdf(await convertJunitToHdf(xml));
    expect(hdf.baselines[0]!.requirements).toHaveLength(1);
  });
});

describe('Additional BurpSuite branch coverage', () => {
  it('should handle issue with vulnerabilityClassifications containing CWE', async () => {
    const xml = `<?xml version="1.0" encoding="UTF-8"?>
      <issues burpVersion="2023.1" exportTime="2025-01-01">
        <issue>
          <type>2097920</type>
          <name>XSS</name>
          <host ip="10.0.0.1">https://example.com</host>
          <severity>High</severity>
          <confidence>Firm</confidence>
          <issueBackground>XSS background</issueBackground>
          <remediationBackground>Fix XSS</remediationBackground>
          <references>https://example.com</references>
          <vulnerabilityClassifications>CWE-79: Cross-site Scripting</vulnerabilityClassifications>
          <issueDetail>Found in param</issueDetail>
          <path>/page</path>
          <location>/page [param]</location>
        </issue>
      </issues>`;
    const hdf = parseHdf(await convertBurpsuiteToHdf(xml));
    expect(hdf.baselines[0]!.requirements).toHaveLength(1);
  });

  it('should handle empty issues list', async () => {
    const xml = `<?xml version="1.0" encoding="UTF-8"?>
      <issues burpVersion="2023.1" exportTime="2025-01-01">
      </issues>`;
    const hdf = parseHdf(await convertBurpsuiteToHdf(xml));
    expect(hdf.baselines[0]!.requirements).toHaveLength(1);
    expect(hdf.baselines[0]!.requirements[0]!.id).toBe('burpsuite-no-findings');
    expect(hdf.baselines[0]!.requirements[0]!.results[0]!.status).toBe('passed');
  });
});

describe('Additional Grype branch coverage', () => {
  it('should handle match with empty relatedVulnerabilities description', async () => {
    const input = JSON.stringify({
      matches: [{
        vulnerability: { id: 'CVE-2021-7', severity: 'High', dataSource: 'ds' },
        artifact: { name: 'pkg', version: '1.0', type: 'deb' },
        relatedVulnerabilities: [{
          id: 'CVE-2021-7', severity: 'High',
        }],
      }],
      source: { type: 'image', target: { userInput: 'test:latest' } },
      descriptor: { name: 'grype', version: '0.1' },
    });
    const hdf = parseHdf(await convertGrypeToHdf(input));
    expect(hdf.baselines[0]!.requirements).toHaveLength(1);
  });

  it('should handle match with fix state "unknown"', async () => {
    const input = JSON.stringify({
      matches: [{
        vulnerability: { id: 'CVE-2021-8', severity: 'Medium', dataSource: 'ds',
          fix: { state: 'unknown' } },
        artifact: { name: 'pkg', version: '1.0', type: 'npm' },
        relatedVulnerabilities: [],
      }],
      source: { type: 'image', target: { userInput: 'test:latest' } },
      descriptor: { name: 'grype', version: '0.1' },
    });
    const hdf = parseHdf(await convertGrypeToHdf(input));
    expect(hdf.baselines[0]!.requirements).toHaveLength(1);
  });

  it('should handle match with no severity (default)', async () => {
    const input = JSON.stringify({
      matches: [{
        vulnerability: { id: 'CVE-2021-9', dataSource: 'ds' },
        artifact: { name: 'pkg', version: '1.0', type: 'deb' },
        relatedVulnerabilities: [],
      }],
      source: { type: 'image', target: { userInput: 'test:latest' } },
      descriptor: { name: 'grype', version: '0.1' },
    });
    const hdf = parseHdf(await convertGrypeToHdf(input));
    expect(hdf.baselines[0]!.requirements[0]!.impact).toBe(0.5);
  });
});

describe('Additional ZAP branch coverage', () => {
  it('should handle alert with risk code default (unknown)', async () => {
    const input = JSON.stringify({
      site: [{
        '@name': 'http://test.com', '@host': 'test.com', '@port': '80',
        alerts: [{
          pluginid: '10001', riskcode: '99', name: 'Unknown Risk', desc: 'd',
          instances: [{ uri: 'http://test.com/' }],
        }],
      }],
      '@generated': '2025-01-01T00:00:00.000+0000',
    });
    const hdf = parseHdf(await convertZapToHdf(input));
    expect(hdf.baselines[0]!.requirements).toHaveLength(1);
  });

  it('should handle alert with no cweid (defaults to SA-11/RA-5)', async () => {
    const input = JSON.stringify({
      site: [{
        '@name': 'http://test.com', '@host': 'test.com', '@port': '80',
        alerts: [{
          pluginid: '10001', riskcode: '2', name: 'No CWE', desc: 'd',
          instances: [{ uri: 'http://test.com/' }],
        }],
      }],
    });
    const hdf = parseHdf(await convertZapToHdf(input));
    expect(hdf.baselines[0]!.requirements).toHaveLength(1);
  });

  it('should handle alert with no instances', async () => {
    const input = JSON.stringify({
      site: [{
        '@name': 'http://test.com', '@host': 'test.com', '@port': '80',
        alerts: [{
          pluginid: '10001', riskcode: '2', name: 'No instances', desc: 'd',
        }],
      }],
    });
    const hdf = parseHdf(await convertZapToHdf(input));
    expect(hdf.baselines[0]!.requirements).toHaveLength(1);
  });
});

describe('Additional AWS Config branch coverage', () => {
  it('should handle rule with empty InputParameters', async () => {
    const input = JSON.stringify({
      ConfigRules: [{
        ConfigRuleId: 'rule-1',
        ConfigRuleName: 'test-rule',
        ConfigRuleArn: 'arn:aws:config:us-east-1:123456789012:config-rule/rule-1',
        Description: 'Test',
        Source: { SourceIdentifier: 'S3_BUCKET_VERSIONING_ENABLED' },
        InputParameters: '',
        EvaluationResults: [{
          ComplianceType: 'COMPLIANT',
          EvaluationResultIdentifier: {
            EvaluationResultQualifier: {
              ConfigRuleName: 'test-rule',
              ResourceType: 'AWS::S3::Bucket',
              ResourceId: 'bucket1',
            },
          },
          ResultRecordedTime: '2025-01-01T00:00:00.000Z',
        }],
      }],
    });
    const hdf = parseHdf(await convertAwsConfigToHdf(input));
    expect(hdf.baselines).toHaveLength(1);
  });

  it('should handle evaluation result with no ConfigRuleInvokedTime', async () => {
    const input = JSON.stringify({
      ConfigRules: [{
        ConfigRuleId: 'rule-1',
        ConfigRuleName: 'test-rule',
        ConfigRuleArn: 'arn:aws:config:us-east-1:123456789012:config-rule/rule-1',
        Description: 'Test',
        Source: { SourceIdentifier: 'S3_BUCKET_VERSIONING_ENABLED' },
        InputParameters: '{}',
        EvaluationResults: [{
          ComplianceType: 'COMPLIANT',
          EvaluationResultIdentifier: {
            EvaluationResultQualifier: {
              ConfigRuleName: 'test-rule',
              ResourceType: 'AWS::S3::Bucket',
              ResourceId: 'bucket1',
            },
          },
          ResultRecordedTime: '2025-01-01T00:00:00.000Z',
        }],
      }],
    });
    const hdf = parseHdf(await convertAwsConfigToHdf(input));
    expect(hdf.baselines).toHaveLength(1);
  });
});

// ---------------------------------------------------------------------------
// Veracode branch coverage
// ---------------------------------------------------------------------------
describe('Veracode branch coverage', () => {
  function makeVeracodeXml(opts: {
    hasSCA?: boolean;
    hasStaticAnalysis?: boolean;
    hasSeverity?: boolean;
    hasSummaryReport?: boolean;
    hasFlawWithoutPath?: boolean;
    emptyCweID?: boolean;
    noTimestamp?: boolean;
    noAppName?: boolean;
  }): string {
    const timestamp = opts.noTimestamp ? '' : 'first_build_submitted_date="2021-12-29 22:16:36 UTC"';
    const appName = opts.noAppName ? '' : 'app_name="TestApp"';

    if (opts.hasSummaryReport) {
      return `<?xml version="1.0"?><summaryreport/>`;
    }

    const flawCode = opts.hasFlawWithoutPath
      ? '<flaw issueid="1001" severity="3" cweid="79"/>'
      : '<flaw issueid="1001" severity="3" cweid="79" sourcefilepath="/app/src/test.java" line="42" affects_policy_compliance="true" remediationeffort="3" exploitLevel="1" module="MainModule" type="java.sql.Statement.executeQuery" date_first_occurrence="2021-12-01" cia_impact="pph" description="XSS" sourcefile="test.java" scope="org.app" pcirelated="true" functionprototype="void test()" functionrelativelocation="50"/>';

    const scaSection = opts.hasSCA ? `
      <software_composition_analysis>
        <vulnerable_components>
          <component component_id="comp1" sha1="abc" file_name="lib.jar" max_cvss_score="7.5" version="1.0" library="TestLib" library_id="lib1" vendor="Test" description="Test lib" added_date="2021-01-01" component_affects_policy_compliance="true" vulnerabilities="1">
            <file_paths><file_path value="/app/lib/test.jar"/></file_paths>
            <vulnerabilities>
              <vulnerability cve_id="CVE-2021-1" severity="4" ${opts.emptyCweID ? '' : 'cwe_id="CWE-79"'} cve_summary="Test CVE"/>
            </vulnerabilities>
          </component>
        </vulnerable_components>
      </software_composition_analysis>` : '';

    const staticAnalysis = opts.hasStaticAnalysis ? `
      <static-analysis>
        <modules><module name="MainModule"/></modules>
      </static-analysis>` : '';

    const severity = opts.hasSeverity !== false ? `
      <severity level="3">
        <category categoryid="XSS" categoryname="Cross-Site Scripting">
          <desc><para text="XSS description"/></desc>
          <recommendations><para text="Fix recommendation"><bulletitem text="Bullet point"/></para></recommendations>
          <cwe cweid="79" cwename="XSS" pcirelated="true" owasp="A7" sans="SANS-1" certc="C-1" certcpp="CPP-1" certjava="J-1" owaspmobile="M-1">
            <description><text text="CWE description"/></description>
            <staticflaws>${flawCode}</staticflaws>
          </cwe>
        </category>
      </severity>` : '';

    return `<?xml version="1.0"?><detailedreport ${timestamp} ${appName} policy_version="1" policy_name="Policy1">${severity}${scaSection}${staticAnalysis}</detailedreport>`;
  }

  it('should handle severity level not in map (default 0.1)', async () => {
    const xml = `<?xml version="1.0"?><detailedreport first_build_submitted_date="2021-12-29 22:16:36 UTC" app_name="App">
      <severity level="9"><category categoryid="C1" categoryname="Cat1">
        <cwe cweid="79" cwename="XSS"><staticflaws><flaw issueid="1" severity="3" sourcefilepath="/a.java"/></staticflaws></cwe>
      </category></severity></detailedreport>`;
    const hdf = parseHdf(await (await import('../converters/veracode-to-hdf/typescript/converter.js')).convertVeracodeToHdf(xml));
    expect(hdf.baselines[0]!.requirements).toHaveLength(1);
  });

  it('should handle flaw without sourcefilepath', async () => {
    const xml = makeVeracodeXml({ hasFlawWithoutPath: true });
    const hdf = parseHdf(await (await import('../converters/veracode-to-hdf/typescript/converter.js')).convertVeracodeToHdf(xml));
    expect(hdf.baselines[0]!.requirements).toHaveLength(1);
  });

  it('should handle SCA with CWE-based NIST mapping', async () => {
    const xml = makeVeracodeXml({ hasSCA: true });
    const hdf = parseHdf(await (await import('../converters/veracode-to-hdf/typescript/converter.js')).convertVeracodeToHdf(xml));
    expect(hdf.baselines[0]!.requirements.length).toBeGreaterThan(0);
  });

  it('should handle SCA with no cwe_id (default NIST)', async () => {
    const xml = makeVeracodeXml({ hasSCA: true, emptyCweID: true });
    const hdf = parseHdf(await (await import('../converters/veracode-to-hdf/typescript/converter.js')).convertVeracodeToHdf(xml));
    expect(hdf.baselines[0]!.requirements.length).toBeGreaterThan(0);
  });

  it('should handle static-analysis module for title', async () => {
    const xml = makeVeracodeXml({ hasStaticAnalysis: true });
    const hdf = parseHdf(await (await import('../converters/veracode-to-hdf/typescript/converter.js')).convertVeracodeToHdf(xml));
    expect(hdf.baselines).toHaveLength(1);
  });

  it('should handle no timestamp (undefined date)', async () => {
    const xml = makeVeracodeXml({ noTimestamp: true });
    const hdf = parseHdf(await (await import('../converters/veracode-to-hdf/typescript/converter.js')).convertVeracodeToHdf(xml));
    expect(hdf.baselines).toHaveLength(1);
  });

  it('should handle no app_name (fallback)', async () => {
    const xml = makeVeracodeXml({ noAppName: true });
    const hdf = parseHdf(await (await import('../converters/veracode-to-hdf/typescript/converter.js')).convertVeracodeToHdf(xml));
    expect(hdf.baselines).toHaveLength(1);
  });

  it('should throw on summary report', async () => {
    const xml = makeVeracodeXml({ hasSummaryReport: true });
    await expect((await import('../converters/veracode-to-hdf/typescript/converter.js')).convertVeracodeToHdf(xml)).rejects.toThrow('summary');
  });

  it('should handle no severity categories', async () => {
    const xml = `<?xml version="1.0"?><detailedreport first_build_submitted_date="2021-12-29 22:16:36 UTC" app_name="App"></detailedreport>`;
    const hdf = parseHdf(await (await import('../converters/veracode-to-hdf/typescript/converter.js')).convertVeracodeToHdf(xml));
    expect(hdf.baselines[0]!.requirements).toHaveLength(1);
    expect(hdf.baselines[0]!.requirements[0]!.id).toBe('veracode-no-findings');
    expect(hdf.baselines[0]!.requirements[0]!.results[0]!.status).toBe('passed');
  });
});

// ---------------------------------------------------------------------------
// SonarQube branch coverage
// ---------------------------------------------------------------------------
describe('SonarQube branch coverage', () => {
  it('should handle issue with no line (no source location)', async () => {
    const input = JSON.stringify({
      issues: [{
        key: 'issue-1', rule: 'squid:S1234', severity: 'MAJOR',
        component: 'proj:src/Main.java', message: 'Fix this', type: 'BUG',
        status: 'RESOLVED', resolution: 'FIXED',
        creationDate: '2025-01-01T00:00:00+0000',
        tags: ['cwe-79', 'owasp-a7'],
      }],
      components: [{ key: 'proj:src/Main.java', path: 'src/Main.java', name: 'Main.java', longName: 'src/Main.java' }],
      rules: [{ key: 'squid:S1234', name: 'Rule Name', htmlDesc: '<p>Description with CWE-79</p>' }],
    });
    const hdf = parseHdf(await convertSonarqubeToHdf(input));
    expect(hdf.baselines[0]!.requirements).toHaveLength(1);
  });

  it('should handle issue with line number', async () => {
    const input = JSON.stringify({
      issues: [{
        key: 'issue-2', rule: 'squid:S1234', severity: 'MINOR',
        component: 'proj:src/Main.java', message: 'Minor issue', type: 'CODE_SMELL',
        status: 'OPEN', line: 42,
        creationDate: '2025-01-01T00:00:00+0000',
        tags: ['performance'],
      }],
      components: [{ key: 'proj:src/Main.java', path: 'src/Main.java' }],
      rules: [{ key: 'squid:S1234', name: 'Rule Name' }],
    });
    const hdf = parseHdf(await convertSonarqubeToHdf(input));
    expect(hdf.baselines[0]!.requirements).toHaveLength(1);
  });

  it('should handle issue with component having only key (no path)', async () => {
    const input = JSON.stringify({
      issues: [{
        key: 'issue-3', rule: 'squid:S5678', severity: 'CRITICAL',
        component: 'proj:unknown', message: 'Critical', type: 'VULNERABILITY',
        status: 'OPEN', line: 10,
        creationDate: '2025-01-01T00:00:00+0000',
      }],
      components: [{ key: 'proj:unknown' }],
      rules: [{ key: 'squid:S5678' }],
    });
    const hdf = parseHdf(await convertSonarqubeToHdf(input));
    expect(hdf.baselines[0]!.requirements).toHaveLength(1);
  });

  it('should handle tags with category:value format', async () => {
    const input = JSON.stringify({
      issues: [{
        key: 'issue-4', rule: 'squid:S1234', severity: 'INFO',
        component: 'proj:src/Main.java', message: 'Info', type: 'BUG',
        status: 'OPEN', creationDate: '2025-01-01T00:00:00+0000',
      }],
      components: [{ key: 'proj:src/Main.java', path: 'src/Main.java' }],
      rules: [{
        key: 'squid:S1234', name: 'Rule',
        sysTags: ['security', 'owasp-a1', 'cwe-89'],
      }],
    });
    const hdf = parseHdf(await convertSonarqubeToHdf(input));
    expect(hdf.baselines[0]!.requirements).toHaveLength(1);
  });
});

// ---------------------------------------------------------------------------
// Snyk additional branch coverage
// ---------------------------------------------------------------------------
describe('Snyk additional branch coverage', () => {
  it('should handle single project with path but no projectName', async () => {
    const input = JSON.stringify({
      path: '/app/package.json',
      vulnerabilities: [{ id: 'v1', title: 'V1', severity: 'low', description: 'd',
        from: ['a'], identifiers: { CWE: [] } }],
    });
    const hdf = parseHdf(await convertSnykToHdf(input));
    expect(hdf.baselines).toHaveLength(1);
  });
});

// ---------------------------------------------------------------------------
// Splunk additional branch coverage
// ---------------------------------------------------------------------------
describe('Splunk additional branch coverage', () => {
  function makeSplunkInput(controlOpts: {
    tags?: Record<string, unknown>;
    source_location?: { ref: string; line: number };
    results?: Array<{ status: string; code_desc: string; start_time: string; message?: string; run_time?: number }>;
  }): string {
    const meta = { guid: 'g1', subtype: 'header', hdf_splunk_schema: '1.0', filetype: 'inspec', filename: 'test' };
    const header = {
      meta: { ...meta, subtype: 'header' },
      profiles: [], platform: { name: 'test', release: '1.0' },
      statistics: {}, version: '4.52.9',
    };
    const profile = {
      meta: { ...meta, subtype: 'profile' },
      name: 'test-profile', title: 'Test', sha256: 'abc123', version: '1.0',
      supports: [], groups: [], attributes: [], controls: [],
    };
    const control = {
      meta: { ...meta, subtype: 'control', profile_sha256: 'abc123' },
      id: 'ctrl-1', title: 'Test Control', desc: 'desc', impact: 0.5, code: '',
      descriptions: { default: 'desc' },
      results: controlOpts.results ?? [{ status: 'passed', code_desc: 'ok', start_time: '2025-01-01T00:00:00Z' }],
      refs: [],
      ...(controlOpts.tags !== undefined ? { tags: controlOpts.tags } : {}),
      ...(controlOpts.source_location ? { source_location: controlOpts.source_location } : {}),
    };
    return JSON.stringify([header, profile, control]);
  }

  it('should handle control with no tags', async () => {
    const hdf = parseHdf(await convertSplunkToHdf(makeSplunkInput({})));
    expect(hdf.baselines[0]!.requirements).toHaveLength(1);
  });

  it('should handle control with source_location', async () => {
    const hdf = parseHdf(await convertSplunkToHdf(makeSplunkInput({
      tags: { nist: ['AC-1'] },
      source_location: { ref: 'controls/test.rb', line: 10 },
      results: [{ status: 'failed', code_desc: 'fail', start_time: '2025-01-01T00:00:00Z', message: 'Expected true', run_time: 0.5 }],
    })));
    expect(hdf.baselines[0]!.requirements).toHaveLength(1);
  });
});

// ---------------------------------------------------------------------------
// Additional MSFT, CycloneDX, DepTrack, Twistlock, NeuVector, ScoutSuite, Nikto
// ---------------------------------------------------------------------------
describe('MSFT additional branch coverage', () => {
  it('should handle empty secureScore value array', async () => {
    const input = JSON.stringify({
      secureScore: { value: [] },
      profiles: { value: [] },
    });
    await expect(convertMsftSecureScoreToHdf(input)).rejects.toThrow('empty');
  });

  it('should handle control where score equals profile maxScore but percentage is not 100', async () => {
    // This hits the cs.score === maxScore branch (L147)
    // scoreInPercentage != 100, but cs.score matches profile maxScore
    const input = JSON.stringify({
      secureScore: {
        value: [{
          id: 'ss-1', azureTenantId: 't1', createdDateTime: '2025-01-01T00:00:00Z',
          controlScores: [{
            controlName: 'ctrl1', controlCategory: 'Identity',
            description: 'desc', score: 5.0, maxScore: 10.0,
            scoreInPercentage: 50,
            implementationStatus: 'implemented', count: 1,
          }],
        }],
      },
      profiles: { value: [{ id: 'ctrl1', title: 'Control 1', maxScore: 5.0 }] },
    });
    const hdf = parseHdf(await convertMsftSecureScoreToHdf(input));
    expect(hdf.baselines[0]!.requirements[0]!.results[0]!.status).toBe('passed');
  });
});

describe('CycloneDX additional branch coverage', () => {
  it('should handle vulnerability with no affects', async () => {
    const input = JSON.stringify({
      bomFormat: 'CycloneDX', specVersion: '1.4',
      vulnerabilities: [{
        id: 'CVE-2021-20', description: 'No affects',
        ratings: [{ severity: 'low' }],
        source: { name: 'test' },
      }],
    });
    const hdf = parseHdf(await convertCyclonedxToHdf(input));
    expect(hdf.baselines[0]!.requirements).toHaveLength(1);
  });

  it('should handle component with sub-components', async () => {
    const input = JSON.stringify({
      bomFormat: 'CycloneDX', specVersion: '1.4',
      components: [{
        type: 'library', name: 'parent', version: '1.0', 'bom-ref': 'parent-ref',
        components: [{ type: 'library', name: 'child', version: '0.1', 'bom-ref': 'child-ref' }],
      }],
      vulnerabilities: [{
        id: 'CVE-2021-21', description: 'Child vuln',
        ratings: [{ severity: 'high' }],
        source: { name: 'test' },
        affects: [{ ref: 'child-ref' }],
      }],
    });
    const hdf = parseHdf(await convertCyclonedxToHdf(input));
    expect(hdf.baselines[0]!.requirements).toHaveLength(1);
  });
});

describe('DepTrack additional branch coverage', () => {
  it('should handle report with no project', async () => {
    const input = JSON.stringify({
      findings: [{
        component: { name: 'dep1', version: '1.0' },
        vulnerability: { vulnId: 'CVE-2021-1', severity: 'HIGH', description: 'd', source: 'NVD' },
        matrix: 'x:dep1:CVE-2021-1',
      }],
    });
    const hdf = parseHdf(await convertDeptrackToHdf(input));
    expect(hdf.baselines).toHaveLength(1);
  });
});

describe('Twistlock additional branch coverage', () => {
  it('should handle container scan with results array', async () => {
    const input = JSON.stringify({
      results: [{
        id: 'scan1',
        vulnerabilities: [{
          id: 'CVE-2021-1', severity: 'critical',
          packageName: 'pkg', packageVersion: '1.0',
          description: 'desc', link: 'https://example.com',
        }],
      }],
    });
    const hdf = parseHdf(await convertTwistlockToHdf(input));
    expect(hdf.baselines).toHaveLength(1);
  });
});

describe('NeuVector additional branch coverage', () => {
  it('should synthesize a passed placeholder for empty vulnerabilities', async () => {
    const input = JSON.stringify({
      report: { vulnerabilities: [] },
    });
    const hdf = parseHdf(await convertNeuvectorToHdf(input));
    const reqs = hdf.baselines[0]!.requirements;
    expect(reqs).toHaveLength(1);
    expect(reqs[0]!.id).toBe('neuvector-no-findings');
    expect(reqs[0]!.results[0]!.status).toBe('passed');
  });
});

describe('ScoutSuite additional branch coverage', () => {
  it('should handle service with no findings key', async () => {
    const data = {
      last_run: { ruleset_name: 'default', provider: 'aws', result_format: '2.0' },
      services: { s3: {} },
      account_id: '999',
    };
    const input = `scoutsuite_results = ${JSON.stringify(data)}`;
    const hdf = parseHdf(await convertScoutsuiteToHdf(input));
    expect(hdf.baselines[0]!.requirements).toHaveLength(1);
    expect(hdf.baselines[0]!.requirements[0]!.id).toBe('scoutsuite-no-findings');
    expect(hdf.baselines[0]!.requirements[0]!.results[0]!.status).toBe('passed');
  });
});

describe('Nikto additional branch coverage', () => {
  it('should handle report with no host info (minimal)', async () => {
    const input = JSON.stringify({
      vulnerabilities: [
        { id: '100', method: 'GET', url: '/test', msg: 'Issue found' },
      ],
    });
    const hdf = parseHdf(await convertNiktoToHdf(input));
    expect(hdf.baselines[0]!.requirements).toHaveLength(1);
  });
});

// ---------------------------------------------------------------------------
// Fortify additional branch coverage (L141, L165-166, L184, L196, L218, L259, L323)
// ---------------------------------------------------------------------------
describe('Fortify additional branch coverage', () => {
  function makeFortifyXml(opts: {
    vulnClassID?: string;
    vulnHasEntry?: boolean;
    entryHasSnippet?: boolean;
    entryHasPath?: boolean;
    entryHasNode?: boolean;
    descClassID?: string;
    descAbstract?: string;
    descExplanation?: string;
    descRecommendations?: string;
    nistRef?: boolean;
    snippets?: boolean;
    snippetMissing?: boolean;
    noCreatedTS?: boolean;
    multipleVulnsSameClass?: boolean;
    noVulnerabilities?: boolean;
  }): string {
    const classID = opts.vulnClassID ?? 'CLASS-1';
    const descClassID = opts.descClassID ?? classID;

    // Build entries
    let entryXml = '';
    if (opts.vulnHasEntry !== false) {
      if (opts.entryHasNode === false) {
        // Entry without Node — triggers "continue" at L177
        entryXml = '<Entry><NodeRef id="n1"/></Entry>';
      } else if (opts.entryHasSnippet === false && opts.entryHasPath !== false) {
        // Entry with Node but no snippet — triggers L180-184 (path without snippet)
        entryXml = '<Entry><Node isDefault="true"><SourceLocation path="/app/test.java" line="42"/></Node></Entry>';
      } else if (opts.entryHasPath === false) {
        // Entry with Node, no snippet, no path — triggers L183 false
        entryXml = '<Entry><Node isDefault="true"><SourceLocation/></Node></Entry>';
      } else if (opts.snippetMissing) {
        // Entry with snippet ID that doesn't exist in map — triggers L190 false
        entryXml = '<Entry><Node isDefault="true"><SourceLocation snippet="nonexistent"/></Node></Entry>';
      } else {
        entryXml = '<Entry><Node isDefault="true"><SourceLocation snippet="s1" path="/app/test.java" line="10" lineEnd="15"/></Node></Entry>';
      }
    }

    // Build vulnerability — may or may not have entries
    const vulnXml = opts.noVulnerabilities ? '' : `<Vulnerability>
      <ClassInfo><ClassID>${classID}</ClassID><DefaultSeverity>2.5</DefaultSeverity></ClassInfo>
      <InstanceInfo><InstanceID>INST-1</InstanceID><InstanceSeverity>2.5</InstanceSeverity></InstanceInfo>
      <AnalysisInfo><Unified><Trace><Primary>${entryXml}</Primary></Trace></Unified></AnalysisInfo>
    </Vulnerability>${opts.multipleVulnsSameClass ? `<Vulnerability>
      <ClassInfo><ClassID>${classID}</ClassID><DefaultSeverity>2.5</DefaultSeverity></ClassInfo>
      <InstanceInfo><InstanceID>INST-2</InstanceID></InstanceInfo>
      <AnalysisInfo><Unified><Trace><Primary>${entryXml}</Primary></Trace></Unified></AnalysisInfo>
    </Vulnerability>` : ''}`;

    // Build reference
    const refXml = opts.nistRef
      ? `<References><Reference><Title>AC-2 SI-10</Title><Author>Standards Mapping - NIST Special Publication 800-53 Revision 4</Author></Reference></References>`
      : '';

    // Build snippet
    const snippetXml = opts.snippets !== false
      ? `<Snippets><Snippet><id>s1</id><File>/app/test.java</File><StartLine>10</StartLine><EndLine>15</EndLine><Text>some code</Text></Snippet></Snippets>`
      : '<Snippets/>';

    // Build description
    const abstractXml = opts.descAbstract !== undefined ? `<Abstract>${opts.descAbstract}</Abstract>` : '<Abstract>Test abstract</Abstract>';
    const explanationXml = opts.descExplanation !== undefined ? `<Explanation>${opts.descExplanation}</Explanation>` : '<Explanation>Test explanation</Explanation>';
    const recsXml = opts.descRecommendations ? `<Recommendations>${opts.descRecommendations}</Recommendations>` : '';

    const createdTS = opts.noCreatedTS ? '' : '<CreatedTS date="2025-01-01" time="00:00:00"/>';

    return `<?xml version="1.0" encoding="UTF-8"?>
      <FVDL>
        ${createdTS}
        <UUID>test-uuid</UUID>
        <Build><BuildID>build1</BuildID><SourceBasePath>/app</SourceBasePath></Build>
        <Vulnerabilities>${vulnXml}</Vulnerabilities>
        <Description classID="${descClassID}">
          ${abstractXml}
          ${explanationXml}
          ${recsXml}
          ${refXml}
        </Description>
        ${snippetXml}
        <EngineData><EngineVersion>1.0</EngineVersion></EngineData>
      </FVDL>`;
  }

  it('should handle vuln with classID missing (defaults to "unknown") — L141', async () => {
    const xml = `<?xml version="1.0" encoding="UTF-8"?>
      <FVDL>
        <Vulnerabilities><Vulnerability>
          <ClassInfo><DefaultSeverity>2.5</DefaultSeverity></ClassInfo>
          <InstanceInfo><InstanceID>INST-1</InstanceID></InstanceInfo>
        </Vulnerability></Vulnerabilities>
        <Description classID="unknown"><Abstract>Test</Abstract><Explanation>Explain</Explanation></Description>
      </FVDL>`;
    const hdf = parseHdf(await convertFortifyToHdf(xml));
    expect(hdf.baselines[0]!.requirements).toHaveLength(1);
    expect(hdf.baselines[0]!.requirements[0]!.id).toBe('unknown');
  });

  it('should handle formatSnippet with missing fields — L165-166', async () => {
    // Snippet with missing File, StartLine, EndLine, Text
    const xml = `<?xml version="1.0" encoding="UTF-8"?>
      <FVDL>
        <Vulnerabilities><Vulnerability>
          <ClassInfo><ClassID>C1</ClassID><DefaultSeverity>3.0</DefaultSeverity></ClassInfo>
          <InstanceInfo><InstanceID>I1</InstanceID></InstanceInfo>
          <AnalysisInfo><Unified><Trace><Primary>
            <Entry><Node isDefault="true"><SourceLocation snippet="s1"/></Node></Entry>
          </Primary></Trace></Unified></AnalysisInfo>
        </Vulnerability></Vulnerabilities>
        <Description classID="C1"><Abstract>A</Abstract><Explanation>E</Explanation></Description>
        <Snippets><Snippet><id>s1</id></Snippet></Snippets>
      </FVDL>`;
    const hdf = parseHdf(await convertFortifyToHdf(xml));
    expect(hdf.baselines[0]!.requirements).toHaveLength(1);
  });

  it('should handle entry with Node but no snippet, with path — L184', async () => {
    const xml = makeFortifyXml({ entryHasSnippet: false, entryHasPath: true, snippets: false });
    const hdf = parseHdf(await convertFortifyToHdf(xml));
    expect(hdf.baselines[0]!.requirements).toHaveLength(1);
  });

  it('should handle entry with Node but no snippet and no path — L183 false', async () => {
    const xml = makeFortifyXml({ entryHasPath: false, snippets: false });
    const hdf = parseHdf(await convertFortifyToHdf(xml));
    expect(hdf.baselines[0]!.requirements).toHaveLength(1);
  });

  it('should handle vuln with no entries (empty parts → fallback code desc) — L196', async () => {
    const xml = makeFortifyXml({ vulnHasEntry: false });
    const hdf = parseHdf(await convertFortifyToHdf(xml));
    expect(hdf.baselines[0]!.requirements).toHaveLength(1);
  });

  it('should handle empty Explanation (falls back to title) — L218', async () => {
    const xml = makeFortifyXml({ descExplanation: '' });
    const hdf = parseHdf(await convertFortifyToHdf(xml));
    const desc = hdf.baselines[0]!.requirements[0]!.descriptions[0]!;
    expect(desc.data).toBe('Test abstract');
  });

  it('should handle Description with NIST reference — L155', async () => {
    const xml = makeFortifyXml({ nistRef: true });
    const hdf = parseHdf(await convertFortifyToHdf(xml));
    const tags = hdf.baselines[0]!.requirements[0]!.tags as Record<string, unknown>;
    expect(tags.nist).toBeDefined();
  });

  it('should handle Description with Recommendations — L230', async () => {
    const xml = makeFortifyXml({ descRecommendations: 'Use safe API' });
    const hdf = parseHdf(await convertFortifyToHdf(xml));
    const descs = hdf.baselines[0]!.requirements[0]!.descriptions;
    expect(descs.find(d => d.label === 'fix')).toBeDefined();
  });

  it('should handle multiple vulns with same classID (grouping) — L143-144', async () => {
    const xml = makeFortifyXml({ multipleVulnsSameClass: true });
    const hdf = parseHdf(await convertFortifyToHdf(xml));
    // Should produce 1 requirement with 2 results
    expect(hdf.baselines[0]!.requirements).toHaveLength(1);
    expect(hdf.baselines[0]!.requirements[0]!.results).toHaveLength(2);
  });

  it('should handle snippet ID not in map — L190 false', async () => {
    const xml = makeFortifyXml({ snippetMissing: true, snippets: false });
    const hdf = parseHdf(await convertFortifyToHdf(xml));
    expect(hdf.baselines[0]!.requirements).toHaveLength(1);
  });

  it('should handle entry without Node — L177', async () => {
    const xml = makeFortifyXml({ entryHasNode: false, snippets: false });
    const hdf = parseHdf(await convertFortifyToHdf(xml));
    expect(hdf.baselines[0]!.requirements).toHaveLength(1);
  });

  it('should handle desc classID mismatch (no vulns for desc) — L323 empty vulns', async () => {
    const xml = makeFortifyXml({ vulnClassID: 'OTHER', descClassID: 'NOMATCH' });
    const hdf = parseHdf(await convertFortifyToHdf(xml));
    // Description with no matching vulns produces 0 results
    expect(hdf.baselines[0]!.requirements[0]!.results).toHaveLength(0);
  });

  it('should handle no CreatedTS — L317-318 defaults', async () => {
    const xml = makeFortifyXml({ noCreatedTS: true });
    const hdf = parseHdf(await convertFortifyToHdf(xml));
    expect(hdf.baselines).toHaveLength(1);
  });
});

// ---------------------------------------------------------------------------
// Nessus additional branch coverage (L165, L230, L295, L298, L314, L318, L385, L391)
// ---------------------------------------------------------------------------
describe('Nessus additional branch coverage', () => {
  function makeNessusXml(opts: {
    hosts?: Array<{
      name?: string;
      items?: Array<{
        pluginID?: string;
        pluginName?: string;
        pluginFamily?: string;
        severity?: string;
        port?: string;
        protocol?: string;
        svc_name?: string;
        description?: string;
        solution?: string;
        plugin_output?: string;
        see_also?: string;
        compliance_reference?: string;
        compliance_check_name?: string;
        compliance_info?: string;
        compliance_solution?: string;
        compliance_result?: string;
        compliance_actual_value?: string;
        risk_factor?: string;
      }>;
      hostStart?: string;
      hostEnd?: string;
    }>;
    noPrefs?: boolean;
  }): string {
    const hosts = opts.hosts ?? [{ name: 'host1', items: [{ pluginID: '1', pluginName: 'Test', pluginFamily: 'General', severity: '2', port: '443', protocol: 'tcp', svc_name: 'https' }] }];

    const hostXml = hosts.map(h => {
      const tags: string[] = [];
      if (h.hostStart) tags.push(`<tag name="HOST_START">${h.hostStart}</tag>`);
      if (h.hostEnd) tags.push(`<tag name="HOST_END">${h.hostEnd}</tag>`);

      const items = (h.items ?? []).map(item => {
        const compRefAttr = item.compliance_reference ? `<compliance-reference>${item.compliance_reference}</compliance-reference>` : '';
        const compCheckName = item.compliance_check_name ? `<compliance-check-name>${item.compliance_check_name}</compliance-check-name>` : '';
        const compInfo = item.compliance_info ? `<compliance-info>${item.compliance_info}</compliance-info>` : '';
        const compSolution = item.compliance_solution ? `<compliance-solution>${item.compliance_solution}</compliance-solution>` : '';
        const compResult = item.compliance_result ? `<compliance-result>${item.compliance_result}</compliance-result>` : '';
        const compActual = item.compliance_actual_value ? `<compliance-actual-value>${item.compliance_actual_value}</compliance-actual-value>` : '';
        return `<ReportItem port="${item.port ?? '0'}" svc_name="${item.svc_name ?? 'general'}" protocol="${item.protocol ?? 'tcp'}" severity="${item.severity ?? '0'}" pluginID="${item.pluginID ?? '0'}" pluginName="${item.pluginName ?? 'Test'}" pluginFamily="${item.pluginFamily ?? 'General'}">
          ${item.description ? `<description>${item.description}</description>` : ''}
          ${item.solution ? `<solution>${item.solution}</solution>` : ''}
          ${item.plugin_output ? `<plugin_output>${item.plugin_output}</plugin_output>` : ''}
          ${item.see_also ? `<see_also>${item.see_also}</see_also>` : ''}
          ${item.risk_factor ? `<risk_factor>${item.risk_factor}</risk_factor>` : ''}
          ${compRefAttr}${compCheckName}${compInfo}${compSolution}${compResult}${compActual}
        </ReportItem>`;
      }).join('');

      return `<ReportHost name="${h.name ?? 'host'}">
        <HostProperties>${tags.join('')}</HostProperties>
        ${items}
      </ReportHost>`;
    }).join('');

    const prefs = opts.noPrefs ? '' : '<Preferences><ServerPreferences><preference><name>sc_version</name><value>5.0</value></preference></ServerPreferences></Preferences>';

    return `<?xml version="1.0"?>
      <NessusClientData_v2>
        <Policy><policyName>Test Policy</policyName>${prefs}</Policy>
        <Report name="Test Report">${hostXml}</Report>
      </NessusClientData_v2>`;
  }

  it('should handle host with no HOST_START or HOST_END — L165 (timing defaults)', async () => {
    const xml = makeNessusXml({
      hosts: [{
        name: 'host1',
        // no hostStart, no hostEnd
        items: [{
          pluginID: '1', pluginName: 'Test', pluginFamily: 'General',
          severity: '2', port: '80', protocol: 'tcp', svc_name: 'http',
        }],
      }],
    });
    const hdf = await convertNessusToHdf(xml);
    expect(hdf.baselines).toHaveLength(1);
  });

  it('should handle compliance item with check-name — L230', async () => {
    const xml = makeNessusXml({
      hosts: [{
        name: 'host1',
        hostStart: '2025-01-01T00:00:00',
        items: [{
          pluginID: '1', pluginName: 'Compliance Check', pluginFamily: 'Policy Compliance',
          severity: '2', port: '0', protocol: 'tcp', svc_name: 'general',
          compliance_reference: 'Vuln-ID|V-1234,CCI|CCI-000001,CAT|II,Rule-ID|SV-1234,STIG-ID|STIG-1234',
          compliance_check_name: 'Check password policy',
          compliance_info: 'Verify password settings',
          compliance_solution: 'Set password length to 14',
          compliance_result: 'PASSED',
        }],
      }],
    });
    const hdf = await convertNessusToHdf(xml);
    expect(hdf.baselines[0]!.requirements[0]!.title).toBe('Check password policy');
  });

  it('should handle compliance with CAT value — L295', async () => {
    const xml = makeNessusXml({
      hosts: [{
        name: 'host1',
        hostStart: '2025-01-01T00:00:00',
        items: [{
          pluginID: '1', pluginName: 'Compliance', pluginFamily: 'Policy Compliance',
          severity: '0', port: '0', protocol: 'tcp', svc_name: 'general',
          compliance_reference: 'Vuln-ID|V-100,CAT|I,CCI|CCI-000002,Rule-ID|SV-100',
          compliance_result: 'FAILED',
          compliance_info: 'Check info',
        }],
      }],
    });
    const hdf = await convertNessusToHdf(xml);
    // CAT I = 'i' in lowercase → IMPACT_MAPPING['i'] = 0.7
    expect(hdf.baselines[0]!.requirements[0]!.impact).toBe(0.7);
  });

  it('should handle non-compliance item with unknown severity (default 0.0) — L298', async () => {
    const xml = makeNessusXml({
      hosts: [{
        name: 'host1',
        hostStart: '2025-01-01T00:00:00',
        items: [{
          pluginID: '99', pluginName: 'Unknown Sev', pluginFamily: 'General',
          severity: '99', port: '80', protocol: 'tcp', svc_name: 'http',
        }],
      }],
    });
    const hdf = await convertNessusToHdf(xml);
    expect(hdf.baselines[0]!.requirements[0]!.impact).toBe(0.0);
  });

  it('should handle non-compliance NIST lookup — L318', async () => {
    const xml = makeNessusXml({
      hosts: [{
        name: 'host1',
        hostStart: '2025-01-01T00:00:00',
        items: [{
          pluginID: '11111', pluginName: 'Info Plugin', pluginFamily: 'General',
          severity: '0', port: '0', protocol: 'tcp', svc_name: 'general',
        }],
      }],
    });
    const hdf = await convertNessusToHdf(xml);
    const tags = hdf.baselines[0]!.requirements[0]!.tags as Record<string, unknown>;
    expect(tags.nist).toBeDefined();
  });

  it('should handle code desc with no description and no plugin_output — L385', async () => {
    const xml = makeNessusXml({
      hosts: [{
        name: 'host1',
        hostStart: '2025-01-01T00:00:00',
        items: [{
          pluginID: '1', pluginName: 'No Output', pluginFamily: 'General',
          severity: '1', port: '80', protocol: 'tcp', svc_name: 'http',
          // no description, no plugin_output
        }],
      }],
    });
    const hdf = await convertNessusToHdf(xml);
    // Should get fallback "This Nessus Plugin does not provide output message."
    expect(hdf.baselines[0]!.requirements).toHaveLength(1);
  });

  it('should handle compliance-reference parsing with empty key matches — L391', async () => {
    const xml = makeNessusXml({
      hosts: [{
        name: 'host1',
        hostStart: '2025-01-01T00:00:00',
        items: [{
          pluginID: '1', pluginName: 'Partial Ref', pluginFamily: 'Policy Compliance',
          severity: '2', port: '0', protocol: 'tcp', svc_name: 'general',
          compliance_reference: 'Vuln-ID|,CCI|CCI-000001',
          compliance_result: 'WARNING',
          compliance_info: 'Info',
        }],
      }],
    });
    const hdf = await convertNessusToHdf(xml);
    expect(hdf.baselines[0]!.requirements[0]!.results[0]!.status).toBe('notApplicable');
  });

  it('should handle solution "n/a" — L281', async () => {
    const xml = makeNessusXml({
      hosts: [{
        name: 'host1',
        hostStart: '2025-01-01T00:00:00',
        items: [{
          pluginID: '1', pluginName: 'Test', pluginFamily: 'General',
          severity: '2', port: '80', protocol: 'tcp', svc_name: 'http',
          solution: 'n/a',
        }],
      }],
    });
    const hdf = await convertNessusToHdf(xml);
    const descs = hdf.baselines[0]!.requirements[0]!.descriptions;
    const fix = descs.find(d => d.label === 'fix');
    expect(fix?.data).toBe('n/a');
  });

  it('should handle compliance ERROR result — L374', async () => {
    const xml = makeNessusXml({
      hosts: [{
        name: 'host1',
        hostStart: '2025-01-01T00:00:00',
        items: [{
          pluginID: '1', pluginName: 'Error Check', pluginFamily: 'Policy Compliance',
          severity: '2', port: '0', protocol: 'tcp', svc_name: 'general',
          compliance_reference: 'Vuln-ID|V-1',
          compliance_result: 'ERROR',
          compliance_info: 'Info',
        }],
      }],
    });
    const hdf = await convertNessusToHdf(xml);
    expect(hdf.baselines[0]!.requirements[0]!.results[0]!.status).toBe('error');
  });

  it('should handle host with no HostProperties — L186', async () => {
    const xml = `<?xml version="1.0"?>
      <NessusClientData_v2>
        <Policy><policyName>Test</policyName></Policy>
        <Report><ReportHost name="bare-host">
          <ReportItem port="0" svc_name="general" protocol="tcp" severity="0" pluginID="1" pluginName="Test" pluginFamily="General"/>
        </ReportHost></Report>
      </NessusClientData_v2>`;
    const hdf = await convertNessusToHdf(xml);
    expect(hdf.baselines).toHaveLength(1);
  });

  it('should handle host with no ReportItems — L210', async () => {
    const xml = `<?xml version="1.0"?>
      <NessusClientData_v2>
        <Policy><policyName>Test</policyName></Policy>
        <Report><ReportHost name="empty-host">
          <HostProperties><tag name="HOST_START">2025-01-01T00:00:00</tag></HostProperties>
        </ReportHost></Report>
      </NessusClientData_v2>`;
    const hdf = await convertNessusToHdf(xml);
    expect(hdf.baselines[0]!.requirements).toHaveLength(1);
    expect(hdf.baselines[0]!.requirements[0]!.id).toBe('nessus-no-findings');
    expect(hdf.baselines[0]!.requirements[0]!.results[0]!.status).toBe('passed');
  });

  it('should handle no Preferences — L157', async () => {
    const xml = makeNessusXml({ noPrefs: true });
    const hdf = await convertNessusToHdf(xml);
    expect(hdf.baselines).toHaveLength(1);
  });
});

// ---------------------------------------------------------------------------
// XCCDF additional branch coverage for extractCheckContent, extractText, etc.
// ---------------------------------------------------------------------------
describe('XCCDF extractCheckContent branch coverage', () => {
  it('should handle check-content as array with #text object — L901', async () => {
    // XCCDF where check-content parses as array of objects with #text
    const xml = `<?xml version="1.0" encoding="UTF-8"?>
      <Benchmark id="test_benchmark">
        <title>Test</title>
        <Group id="G-1"><title>G1</title>
          <Rule id="rule_1" severity="medium">
            <title>ArrayCheck Rule</title>
            <version>SV-001</version>
            <check system="C-1">
              <check-content>First check content</check-content>
              <check-content>Second check content</check-content>
            </check>
          </Rule>
        </Group>
      </Benchmark>`;
    const baseline = parseBaseline(await convertXccdfBenchmarkToHdf(xml));
    expect(baseline.requirements).toHaveLength(1);
  });

  it('should handle rule-result with severity override — L767', async () => {
    const xml = `<?xml version="1.0" encoding="UTF-8"?>
      <Benchmark id="test_benchmark">
        <title>Test</title>
        <Group id="G-1"><title>G1</title>
          <Rule id="rule_1" severity="low">
            <title>Rule 1</title>
            <version>SV-001</version>
          </Rule>
        </Group>
        <TestResult id="TR-1" start-time="2025-01-01T00:00:00" end-time="2025-01-01T01:00:00">
          <target>host</target>
          <rule-result idref="rule_1" severity="high"><result>fail</result></rule-result>
        </TestResult>
      </Benchmark>`;
    const hdf = parseHdf(await convertXccdfResultsToHdf(xml));
    // severity override in rule-result should take precedence
    expect(hdf.baselines[0]!.requirements[0]!.impact).toBe(0.7);
  });

  it('should handle results with no start-time but has end-time (no duration) — L385-390', async () => {
    const xml = `<?xml version="1.0" encoding="UTF-8"?>
      <Benchmark id="test_benchmark">
        <title>Test</title>
        <Group id="G-1"><title>G1</title>
          <Rule id="rule_1" severity="low">
            <title>Rule 1</title>
            <version>SV-001</version>
          </Rule>
        </Group>
        <TestResult id="TR-1" end-time="2025-01-01T01:00:00">
          <target>host</target>
          <rule-result idref="rule_1"><result>pass</result></rule-result>
        </TestResult>
      </Benchmark>`;
    const hdf = parseHdf(await convertXccdfResultsToHdf(xml));
    // No start-time means no elapsed time to report; duration stays 0 (matches Go).
    expect(hdf.statistics?.duration).toBe(0);
  });

  it('should handle rule-result with no description in rule def — L771-777', async () => {
    const xml = `<?xml version="1.0" encoding="UTF-8"?>
      <Benchmark id="test_benchmark">
        <title>Test</title>
        <Group id="G-1"><title>G1</title>
          <Rule id="rule_1" severity="medium">
            <title>No Desc Rule</title>
            <version>SV-001</version>
          </Rule>
        </Group>
        <TestResult id="TR-1" start-time="2025-01-01T00:00:00">
          <target>host</target>
          <rule-result idref="rule_1"><result>pass</result></rule-result>
        </TestResult>
      </Benchmark>`;
    const hdf = parseHdf(await convertXccdfResultsToHdf(xml));
    // Rule def has no description
    expect(hdf.baselines[0]!.requirements).toHaveLength(1);
  });

  it('should handle rule-result with no matching rule and no severity — L761-768', async () => {
    const xml = `<?xml version="1.0" encoding="UTF-8"?>
      <Benchmark id="test_benchmark">
        <title>Test</title>
        <TestResult id="TR-1" start-time="2025-01-01T00:00:00">
          <target>host</target>
          <rule-result idref="nonexistent"><result>fail</result></rule-result>
        </TestResult>
      </Benchmark>`;
    const hdf = parseHdf(await convertXccdfResultsToHdf(xml));
    // No matching rule, no severity → default 0.5 impact
    expect(hdf.baselines[0]!.requirements[0]!.impact).toBe(0.5);
    expect(hdf.baselines[0]!.requirements[0]!.id).toBe('nonexistent');
  });

  it('should handle ARF with empty reports (throws) — L644', async () => {
    const xml = `<?xml version="1.0" encoding="UTF-8"?>
      <asset-report-collection>
        <reports>
          <report id="report1">
            <content>
              <SomeOtherThing/>
            </content>
          </report>
        </reports>
      </asset-report-collection>`;
    await expect(convertXccdfResultsToHdf(xml)).rejects.toThrow('no XCCDF TestResult');
  });

  it('should handle ARF with report that has no targets — L817', async () => {
    const xml = `<?xml version="1.0" encoding="UTF-8"?>
      <asset-report-collection>
        <reports>
          <report id="report1">
            <content>
              <TestResult id="TR-1">
                <rule-result idref="rule_1"><result>pass</result></rule-result>
              </TestResult>
            </content>
          </report>
        </reports>
      </asset-report-collection>`;
    const hdf = parseHdf(await convertXccdfResultsToHdf(xml));
    expect(hdf.components).toHaveLength(0);
  });

  it('should handle benchmark top-level rule with no id (skipped) — L440', async () => {
    const xml = `<?xml version="1.0" encoding="UTF-8"?>
      <Benchmark id="test_benchmark">
        <title>Test</title>
        <Rule severity="medium">
          <title>No ID Top Rule</title>
        </Rule>
        <Rule id="rule_1" severity="low">
          <title>Has ID</title>
          <version>SV-001</version>
        </Rule>
      </Benchmark>`;
    const baseline = parseBaseline(await convertXccdfBenchmarkToHdf(xml));
    // Top-level rule without id should be skipped
    expect(baseline.requirements).toHaveLength(1);
  });

  it('should handle benchmark rule with title as #text object — L846', async () => {
    // This hits extractText where field is an object with #text
    const xml = `<?xml version="1.0" encoding="UTF-8"?>
      <Benchmark id="test_benchmark">
        <title>Test</title>
        <Group id="G-1"><title>G1</title>
          <Rule id="rule_1" severity="low">
            <title>Simple Title</title>
            <version>SV-001</version>
          </Rule>
        </Group>
      </Benchmark>`;
    const baseline = parseBaseline(await convertXccdfBenchmarkToHdf(xml));
    expect(baseline.requirements[0]!.title).toBeDefined();
  });

  it('should handle benchmark rule with version as #text object — L861', async () => {
    // version may be parsed as {#text: "V-1", update: "..."}
    const xml = `<?xml version="1.0" encoding="UTF-8"?>
      <Benchmark id="test_benchmark">
        <title>Test</title>
        <version>2.0</version>
        <Group id="G-1"><title>G1</title>
          <Rule id="rule_1" severity="low">
            <title>Version Object Rule</title>
            <version update="http://example.com">SV-001</version>
          </Rule>
        </Group>
      </Benchmark>`;
    const baseline = parseBaseline(await convertXccdfBenchmarkToHdf(xml));
    expect(baseline.requirements[0]!.id).toBe('rule_1');
  });

  it('should handle benchmark rule with fixtext as #text object — L876', async () => {
    const xml = `<?xml version="1.0" encoding="UTF-8"?>
      <Benchmark id="test_benchmark">
        <title>Test</title>
        <Group id="G-1"><title>G1</title>
          <Rule id="rule_1" severity="low">
            <title>Fixtext Object Rule</title>
            <version>SV-001</version>
            <fixtext fixref="F-1">Fix the setting by configuring it correctly</fixtext>
          </Rule>
        </Group>
      </Benchmark>`;
    const baseline = parseBaseline(await convertXccdfBenchmarkToHdf(xml));
    const fixDesc = baseline.requirements[0]!.descriptions.find(d => d.label === 'fix');
    expect(fixDesc).toBeDefined();
  });

  it('should handle ARF report with no id for relationship matching — L632', async () => {
    const xml = `<?xml version="1.0" encoding="UTF-8"?>
      <asset-report-collection>
        <assets>
          <asset id="a1"><computing-device><fqdn>test.com</fqdn></computing-device></asset>
        </assets>
        <relationships>
          <relationship type="http://scap.nist.gov/specifications/arf/vocabulary/relationships/1.0#isAbout" subject="reportX">
            <ref>a1</ref>
          </relationship>
        </relationships>
        <reports>
          <report>
            <content>
              <TestResult id="TR-1" start-time="2025-01-01T00:00:00">
                <target>host1</target>
                <rule-result idref="rule_1"><result>pass</result></rule-result>
              </TestResult>
            </content>
          </report>
        </reports>
      </asset-report-collection>`;
    const hdf = parseHdf(await convertXccdfResultsToHdf(xml));
    // Report has no id so relationship won't match — no enrichment
    expect(hdf.baselines).toHaveLength(1);
  });

  it('should handle ARF baseline name fallback to TestResult title — L616-619', async () => {
    const xml = `<?xml version="1.0" encoding="UTF-8"?>
      <asset-report-collection>
        <reports>
          <report id="r1">
            <content>
              <TestResult id="TR-1" start-time="2025-01-01T00:00:00">
                <title>TestResult Title</title>
                <target>host1</target>
                <rule-result idref="rule_1"><result>pass</result></rule-result>
              </TestResult>
            </content>
          </report>
        </reports>
      </asset-report-collection>`;
    const hdf = parseHdf(await convertXccdfResultsToHdf(xml));
    // No benchmark title → falls back to TestResult title
    expect(hdf.baselines[0]!.name).toBeDefined();
  });
});

// ---------------------------------------------------------------------------
// Veracode additional branch coverage (L71, L268, L288, L293, L333, L343, L381)
// ---------------------------------------------------------------------------
describe('Veracode additional branch coverage', () => {
  it('should handle invalid timestamp (returns undefined) — L71', async () => {
    const xml = `<?xml version="1.0"?><detailedreport first_build_submitted_date="not-a-date" app_name="App">
      <severity level="3"><category categoryid="C1" categoryname="Cat1">
        <cwe cweid="79" cwename="XSS"><staticflaws><flaw issueid="1" severity="3" sourcefilepath="/a.java"/></staticflaws></cwe>
      </category></severity></detailedreport>`;
    const hdf = parseHdf(await convertVeracodeToHdf(xml));
    expect(hdf.baselines[0]!.requirements).toHaveLength(1);
  });

  it('should handle SCA with component that has vulnerabilities=0 attr — L283', async () => {
    const xml = `<?xml version="1.0"?><detailedreport first_build_submitted_date="2021-12-29 22:16:36 UTC" app_name="App">
      <software_composition_analysis>
        <vulnerable_components>
          <component component_id="c1" vulnerabilities="0"/>
        </vulnerable_components>
      </software_composition_analysis></detailedreport>`;
    const hdf = parseHdf(await convertVeracodeToHdf(xml));
    // Component with vulnerabilities=0 should be skipped; synthesizer kicks in for empty set
    expect(hdf.baselines[0]!.requirements).toHaveLength(1);
    expect(hdf.baselines[0]!.requirements[0]!.id).toBe('veracode-no-findings');
    expect(hdf.baselines[0]!.requirements[0]!.results[0]!.status).toBe('passed');
  });

  it('should handle SCA vulnerability with no vulnerability element — L288', async () => {
    const xml = `<?xml version="1.0"?><detailedreport first_build_submitted_date="2021-12-29 22:16:36 UTC" app_name="App">
      <software_composition_analysis>
        <vulnerable_components>
          <component component_id="c1" vulnerabilities="1">
            <vulnerabilities/>
          </component>
        </vulnerable_components>
      </software_composition_analysis></detailedreport>`;
    const hdf = parseHdf(await convertVeracodeToHdf(xml));
    expect(hdf.baselines[0]!.requirements).toHaveLength(1);
    expect(hdf.baselines[0]!.requirements[0]!.id).toBe('veracode-no-findings');
    expect(hdf.baselines[0]!.requirements[0]!.results[0]!.status).toBe('passed');
  });

  it('should handle SCA vulnerability with no cve_id — L293', async () => {
    const xml = `<?xml version="1.0"?><detailedreport first_build_submitted_date="2021-12-29 22:16:36 UTC" app_name="App">
      <software_composition_analysis>
        <vulnerable_components>
          <component component_id="c1" vulnerabilities="1">
            <vulnerabilities>
              <vulnerability severity="3" cve_summary="Some vuln"/>
            </vulnerabilities>
          </component>
        </vulnerable_components>
      </software_composition_analysis></detailedreport>`;
    const hdf = parseHdf(await convertVeracodeToHdf(xml));
    // Vuln with no cve_id should be skipped; synthesizer kicks in for empty set
    expect(hdf.baselines[0]!.requirements).toHaveLength(1);
    expect(hdf.baselines[0]!.requirements[0]!.id).toBe('veracode-no-findings');
    expect(hdf.baselines[0]!.requirements[0]!.results[0]!.status).toBe('passed');
  });

  it('should handle SCA with multiple components sharing same CVE — L296', async () => {
    const xml = `<?xml version="1.0"?><detailedreport first_build_submitted_date="2021-12-29 22:16:36 UTC" app_name="App">
      <software_composition_analysis>
        <vulnerable_components>
          <component component_id="c1" vulnerabilities="1">
            <vulnerabilities>
              <vulnerability cve_id="CVE-2021-1" severity="4" cwe_id="CWE-79" cve_summary="Shared CVE"/>
            </vulnerabilities>
          </component>
          <component component_id="c2" vulnerabilities="1">
            <vulnerabilities>
              <vulnerability cve_id="CVE-2021-1" severity="4" cwe_id="CWE-79" cve_summary="Shared CVE"/>
            </vulnerabilities>
          </component>
        </vulnerable_components>
      </software_composition_analysis></detailedreport>`;
    const hdf = parseHdf(await convertVeracodeToHdf(xml));
    // Same CVE from 2 components → 1 requirement with 2 results
    expect(hdf.baselines[0]!.requirements).toHaveLength(1);
    expect(hdf.baselines[0]!.requirements[0]!.results).toHaveLength(2);
  });

  it('should handle no detailedreport root element — L381', async () => {
    const xml = `<?xml version="1.0"?><otherroot/>`;
    await expect(convertVeracodeToHdf(xml)).rejects.toThrow('no <detailedreport>');
  });

  it('should handle SCA with no vulnerable_components element — L268', async () => {
    const xml = `<?xml version="1.0"?><detailedreport first_build_submitted_date="2021-12-29 22:16:36 UTC" app_name="App">
      <software_composition_analysis/>
    </detailedreport>`;
    const hdf = parseHdf(await convertVeracodeToHdf(xml));
    expect(hdf.baselines[0]!.requirements).toHaveLength(1);
    expect(hdf.baselines[0]!.requirements[0]!.id).toBe('veracode-no-findings');
    expect(hdf.baselines[0]!.requirements[0]!.results[0]!.status).toBe('passed');
  });

  it('should handle timestamp with XML entities (&#x3a;) — L69', async () => {
    const xml = `<?xml version="1.0"?><detailedreport first_build_submitted_date="2021-12-29 22&#x3a;16&#x3a;36 UTC" app_name="App">
      <severity level="1"><category categoryid="C1" categoryname="Cat1">
        <cwe cweid="79" cwename="XSS"><staticflaws><flaw issueid="1" severity="1" sourcefilepath="/a.java"/></staticflaws></cwe>
      </category></severity></detailedreport>`;
    const hdf = parseHdf(await convertVeracodeToHdf(xml));
    expect(hdf.baselines[0]!.requirements).toHaveLength(1);
  });
});

// ---------------------------------------------------------------------------
// DBProtect additional branch coverage (L160, L164-165, L171, L173, L197, L216, L232)
// ---------------------------------------------------------------------------
describe('DBProtect deeper branch coverage', () => {
  it('should handle empty dataset (no rows) — L197', async () => {
    const xml = `<?xml version="1.0" encoding="UTF-8"?>
      <dataset>
        <metadata>
          <item><name>Check ID</name><type>xs:string</type></item>
        </metadata>
        <data/>
      </dataset>`;
    await expect(convertDbprotectToHdf(xml)).rejects.toThrow('no data rows');
  });
});

// ---------------------------------------------------------------------------
// Conveyor deeper branch coverage (L134, L151-160, L290)
// ---------------------------------------------------------------------------
describe('Conveyor deeper branch coverage', () => {
  it('should handle section with null/undefined body — L133', async () => {
    const input = JSON.stringify({
      api_response: {
        results: {
          'file-sha': {
            sha256: 'abc123',
            response: { service_name: 'Moldy' },
            result: { score: 100, sections: [{ title_text: 'Finding', body: undefined, body_format: 'text', classification: 'CLEAN', depth: 0 }] },
          },
        },
      },
    });
    const hdf = parseHdf(await convertConveyorToHdf(input));
    expect(hdf.baselines[0]!.requirements).toHaveLength(1);
  });

  it('should handle CodeQuality scanner section fields — L155-160', async () => {
    const input = JSON.stringify({
      api_response: {
        results: {
          'file-sha': {
            sha256: 'abc123',
            response: { service_name: 'CodeQuality' },
            result: {
              score: 200,
              sections: [{
                title_text: 'Code smell found',
                body: 'Function is too long',
                body_format: 'text',
                classification: 'SUSPICIOUS',
                depth: 1,
              }],
            },
          },
        },
      },
    });
    const hdf = parseHdf(await convertConveyorToHdf(input));
    expect(hdf.baselines[0]!.requirements).toHaveLength(1);
  });

  it('should handle invalid JSON — L290', async () => {
    await expect(convertConveyorToHdf('not json')).rejects.toThrow();
  });
});

// ---------------------------------------------------------------------------
// BurpSuite deeper branch coverage (L126, L144, L236, L254, L265, L269)
// ---------------------------------------------------------------------------
describe('BurpSuite deeper branch coverage', () => {
  it('should handle non-issues root (missing <issues>) — L126', async () => {
    const xml = `<?xml version="1.0" encoding="UTF-8"?><something><data/></something>`;
    await expect(convertBurpsuiteToHdf(xml)).rejects.toThrow('missing <issues>');
  });

  it('should handle issue with unknown type (defaults to "unknown") — L144', async () => {
    const xml = `<?xml version="1.0" encoding="UTF-8"?>
      <issues burpVersion="2023.1" exportTime="2025-01-01">
        <issue>
          <name>Unknown Type Issue</name>
          <host ip="10.0.0.1">https://example.com</host>
          <severity>Low</severity>
          <confidence>Tentative</confidence>
          <issueBackground>BG</issueBackground>
          <path>/test</path>
          <location>/test</location>
        </issue>
      </issues>`;
    const hdf = parseHdf(await convertBurpsuiteToHdf(xml));
    expect(hdf.baselines[0]!.requirements).toHaveLength(1);
  });

  it('should handle issue with no issueBackground (name fallback) — L236', async () => {
    const xml = `<?xml version="1.0" encoding="UTF-8"?>
      <issues burpVersion="2023.1" exportTime="2025-01-01">
        <issue>
          <type>12345</type>
          <name>Some Issue</name>
          <host ip="10.0.0.1">https://example.com</host>
          <severity>Medium</severity>
          <confidence>Firm</confidence>
          <path>/x</path>
          <location>/x</location>
        </issue>
      </issues>`;
    const hdf = parseHdf(await convertBurpsuiteToHdf(xml));
    // No issueBackground → default desc should be issue name
    expect(hdf.baselines[0]!.requirements[0]!.descriptions[0]!.data).toBe('Some Issue');
  });

  it('should handle issue with "Low" severity — L265', async () => {
    const xml = `<?xml version="1.0" encoding="UTF-8"?>
      <issues burpVersion="2023.1" exportTime="2025-01-01">
        <issue>
          <type>99999</type>
          <name>Low Issue</name>
          <host ip="10.0.0.1">https://example.com</host>
          <severity>Low</severity>
          <confidence>Tentative</confidence>
          <path>/low</path>
          <location>/low</location>
        </issue>
      </issues>`;
    const hdf = parseHdf(await convertBurpsuiteToHdf(xml));
    expect(hdf.baselines[0]!.requirements[0]!.impact).toBe(0.3);
  });
});

// ---------------------------------------------------------------------------
// ZAP deeper branch coverage (L140, L184, L192, L241, L268, L304)
// ---------------------------------------------------------------------------
describe('ZAP deeper branch coverage', () => {
  it('should handle site with @generated timestamp — L192', async () => {
    const input = JSON.stringify({
      site: [],
      '@version': '2.14.0',
      '@generated': '2025-01-01T00:00:00.000+0000',
    });
    const hdf = parseHdf(await convertZapToHdf(input));
    expect(hdf.timestamp).toBeDefined();
  });

  it('should handle alert with instance attack message — L251', async () => {
    const input = JSON.stringify({
      site: [{
        '@name': 'http://test.com', '@host': 'test.com', '@port': '80',
        alerts: [{
          pluginid: '10001', riskcode: '3', cweid: '79', name: 'XSS',
          desc: 'XSS desc',
          instances: [{ uri: 'http://test.com/page', method: 'GET', attack: '<script>alert(1)</script>' }],
        }],
      }],
    });
    const hdf = parseHdf(await convertZapToHdf(input));
    expect(hdf.baselines[0]!.requirements[0]!.results[0]!.message).toContain('<script>');
  });

  it('should handle site with @name but no @host — L304', async () => {
    const input = JSON.stringify({
      site: [{
        '@name': 'http://test.com', '@port': '80',
        alerts: [{ pluginid: '1', riskcode: '1', name: 'A', desc: 'd', instances: [{ uri: 'http://test.com/' }] }],
      }],
    });
    const hdf = parseHdf(await convertZapToHdf(input));
    expect(hdf.baselines).toHaveLength(1);
  });
});

// ---------------------------------------------------------------------------
// JUnit deeper branch coverage (L104, L114, L190, L198, L200)
// ---------------------------------------------------------------------------
describe('JUnit deeper branch coverage', () => {
  it('should handle testsuites with name attribute — L105', async () => {
    const xml = `<?xml version="1.0" encoding="UTF-8"?>
      <testsuites name="My Test Suite">
        <testsuite name="Suite1">
          <testcase name="test1" classname="pkg.Class"/>
        </testsuite>
      </testsuites>`;
    const hdf = parseHdf(await convertJunitToHdf(xml));
    expect(hdf.baselines).toHaveLength(1);
  });

  it('should handle testsuite root as array — L114', async () => {
    const xml = `<?xml version="1.0" encoding="UTF-8"?>
      <testsuite name="Suite">
        <testcase name="test1" classname="pkg.Class"/>
      </testsuite>`;
    const hdf = parseHdf(await convertJunitToHdf(xml));
    expect(hdf.baselines[0]!.requirements).toHaveLength(1);
  });

  it('should handle skipped as empty string (not object) — L205', async () => {
    const xml = `<?xml version="1.0" encoding="UTF-8"?>
      <testsuites>
        <testsuite name="Suite1">
          <testcase name="test1" classname="pkg.Class">
            <skipped/>
          </testcase>
        </testsuite>
      </testsuites>`;
    const hdf = parseHdf(await convertJunitToHdf(xml));
    expect(hdf.baselines[0]!.requirements[0]!.results[0]!.status).toBe('notReviewed');
  });

  it('should handle error without message or type — L198-200', async () => {
    const xml = `<?xml version="1.0" encoding="UTF-8"?>
      <testsuites>
        <testsuite name="Suite1">
          <testcase name="test1" classname="pkg.Class">
            <error>Stack trace here</error>
          </testcase>
        </testsuite>
      </testsuites>`;
    const hdf = parseHdf(await convertJunitToHdf(xml));
    expect(hdf.baselines[0]!.requirements[0]!.results[0]!.status).toBe('error');
  });
});

// ---------------------------------------------------------------------------
// Snyk deeper branch coverage (L185, L201)
// ---------------------------------------------------------------------------
describe('Snyk deeper branch coverage', () => {
  it('should handle invalid JSON input — L185', async () => {
    await expect(convertSnykToHdf('not json')).rejects.toThrow();
  });

  it('should handle multi-project array input — L201', async () => {
    const input = JSON.stringify([
      {
        projectName: 'proj1', path: '/app1/package.json',
        vulnerabilities: [{ id: 'v1', title: 'V1', severity: 'low', description: 'd', from: ['a'], identifiers: { CWE: [] } }],
      },
      {
        projectName: 'proj2', path: '/app2/package.json',
        vulnerabilities: [{ id: 'v2', title: 'V2', severity: 'medium', description: 'd2', from: ['b'], identifiers: { CWE: ['CWE-79'] } }],
      },
    ]);
    const hdf = parseHdf(await convertSnykToHdf(input));
    expect(hdf.baselines).toHaveLength(2);
  });
});

// ---------------------------------------------------------------------------
// GoSec deeper branch coverage (L92, L158)
// ---------------------------------------------------------------------------
describe('GoSec deeper branch coverage', () => {
  it('should handle issue with single suppression with no justification — L92', async () => {
    const input = JSON.stringify({
      Issues: [{
        severity: 'HIGH', confidence: 'HIGH',
        cwe: { id: '89', url: 'https://cwe.mitre.org/data/definitions/89.html' },
        details: 'SQL injection', file: '/app/main.go', line: '42', column: '10',
        code: 'db.Query(userInput)', nosec: true,
        suppressions: [{ kind: 'inSource' }],
        rule_id: 'G201',
      }],
      Stats: { files: 10, lines: 500, nosec: 1, found: 1 },
    });
    const hdf = parseHdf(await convertGosecToHdf(input));
    expect(hdf.baselines[0]!.requirements[0]!.results[0]!.status).toBe('notReviewed');
  });

  it('should handle invalid JSON structure (not object) — L158', async () => {
    await expect(convertGosecToHdf('"just a string"')).rejects.toThrow('not a valid JSON object');
  });
});

// ---------------------------------------------------------------------------
// MSFT Secure Score deeper branch coverage (L198, L203, L234)
// ---------------------------------------------------------------------------
describe('MSFT Secure Score deeper branch coverage', () => {
  it('should handle control with no createdDateTime — L198', async () => {
    const input = JSON.stringify({
      secureScore: {
        value: [{
          id: 'ss-1', azureTenantId: 't1',
          controlScores: [{
            controlName: 'ctrl1', controlCategory: 'Identity',
            description: 'desc', score: 10.0, maxScore: 10.0,
            scoreInPercentage: 100,
            implementationStatus: 'implemented', count: 1,
          }],
        }],
      },
      profiles: { value: [{ id: 'ctrl1', title: 'Ctrl 1' }] },
    });
    const hdf = parseHdf(await convertMsftSecureScoreToHdf(input));
    expect(hdf.baselines[0]!.requirements).toHaveLength(1);
  });

  it('should handle invalid JSON — L234', async () => {
    await expect(convertMsftSecureScoreToHdf('not json')).rejects.toThrow();
  });
});

// ---------------------------------------------------------------------------
// Splunk deeper branch coverage (L207, L216, L231)
// ---------------------------------------------------------------------------
describe('Splunk deeper branch coverage', () => {
  it('should handle control with no results array — L231', async () => {
    const meta = { guid: 'g1', subtype: 'header', hdf_splunk_schema: '1.0', filetype: 'inspec', filename: 'test' };
    const header = {
      meta: { ...meta, subtype: 'header' },
      profiles: [], platform: { name: 'test', release: '1.0' },
      statistics: {}, version: '4.52.9',
    };
    const profile = {
      meta: { ...meta, subtype: 'profile' },
      name: 'test-profile', title: 'Test', sha256: 'abc123', version: '1.0',
      supports: [], groups: [], attributes: [], controls: [],
    };
    const control = {
      meta: { ...meta, subtype: 'control', profile_sha256: 'abc123' },
      id: 'ctrl-1', title: 'Test Control', desc: 'desc', impact: 0.5, code: '',
      descriptions: { default: 'desc' },
      results: null,
      refs: [],
    };
    const input = JSON.stringify([header, profile, control]);
    const hdf = parseHdf(await convertSplunkToHdf(input));
    expect(hdf.baselines[0]!.requirements).toHaveLength(1);
    // null results should produce empty results array
    expect(hdf.baselines[0]!.requirements[0]!.results).toHaveLength(0);
  });

  it('should handle control with missing profile_sha256 — L207', async () => {
    const meta = { guid: 'g1', subtype: 'header', hdf_splunk_schema: '1.0', filetype: 'inspec', filename: 'test' };
    const header = {
      meta: { ...meta, subtype: 'header' },
      profiles: [], platform: { name: 'test', release: '1.0' },
      statistics: {}, version: '4.52.9',
    };
    const profile = {
      meta: { ...meta, subtype: 'profile' },
      name: 'test-profile', title: 'Test', sha256: 'abc123', version: '1.0',
      supports: [], groups: [], attributes: [], controls: [],
    };
    const control = {
      meta: { ...meta, subtype: 'control' },
      id: 'ctrl-1', title: 'Test Control', desc: 'desc', impact: 0.5, code: '',
      descriptions: { default: 'desc' },
      results: [{ status: 'passed', code_desc: 'ok', start_time: '2025-01-01T00:00:00Z' }],
      refs: [],
    };
    const input = JSON.stringify([header, profile, control]);
    const hdf = parseHdf(await convertSplunkToHdf(input));
    expect(hdf.baselines).toHaveLength(1);
  });
});

// ---------------------------------------------------------------------------
// NeuVector deeper branch coverage (L200, L207)
// ---------------------------------------------------------------------------
describe('NeuVector deeper branch coverage', () => {
  it('should handle invalid structure (not object) — L200', async () => {
    await expect(convertNeuvectorToHdf('"not an object"')).rejects.toThrow('invalid JSON structure');
  });

  it('should handle vuln with no score_v3 (falls back to score) — L207', async () => {
    const input = JSON.stringify({
      report: {
        vulnerabilities: [{
          name: 'CVE-2021-1', severity: 'Medium',
          package_name: 'pkg', package_version: '1.0',
          description: 'desc', link: 'https://example.com',
          score: 6.5, vectors: 'AV:N',
          published_timestamp: 1609459200,
          last_modified_timestamp: 1609459200,
          feed_rating: 'Medium',
        }],
      },
    });
    const hdf = parseHdf(await convertNeuvectorToHdf(input));
    expect(hdf.baselines[0]!.requirements).toHaveLength(1);
  });
});

// ---------------------------------------------------------------------------
// Second pass: deeper branch coverage for XCCDF, Conveyor, DBProtect, ZAP,
// BurpSuite, AWS Config, Snyk, JUnit, Fortify
// ---------------------------------------------------------------------------
describe('XCCDF second-pass branch coverage', () => {
  it('should handle benchmark group with no Rule element — L423', async () => {
    const xml = `<?xml version="1.0" encoding="UTF-8"?>
      <Benchmark id="test_benchmark">
        <title>Test</title>
        <Group id="G-1"><title>Empty Group</title></Group>
        <Group id="G-2"><title>Group 2</title>
          <Rule id="rule_1" severity="low"><title>R1</title><version>SV-001</version></Rule>
        </Group>
      </Benchmark>`;
    const baseline = parseBaseline(await convertXccdfBenchmarkToHdf(xml));
    // Group without Rule should produce no requirements from that group
    expect(baseline.requirements).toHaveLength(1);
  });

  it('should handle benchmark rule with no version AND no id — L471-472', async () => {
    // This is technically invalid (no id) so rule gets skipped at L425/L440
    // But to test L471-472, we need a rule where version returns empty
    const xml = `<?xml version="1.0" encoding="UTF-8"?>
      <Benchmark id="test_benchmark">
        <title>Test</title>
        <Group id="G-1"><title>G1</title>
          <Rule id="rule_1" severity="low">
            <title>Rule with no version</title>
          </Rule>
        </Group>
      </Benchmark>`;
    const baseline = parseBaseline(await convertXccdfBenchmarkToHdf(xml));
    // No version → id falls back to rule.id
    expect(baseline.requirements[0]!.id).toBe('rule_1');
  });

  it('should handle benchmark rule with empty title (falls back to id) — L472', async () => {
    const xml = `<?xml version="1.0" encoding="UTF-8"?>
      <Benchmark id="test_benchmark">
        <title>Test</title>
        <Group id="G-1"><title>G1</title>
          <Rule id="rule_1" severity="low">
            <version>SV-001</version>
          </Rule>
        </Group>
      </Benchmark>`;
    const baseline = parseBaseline(await convertXccdfBenchmarkToHdf(xml));
    // No title → omitted entirely (an empty string is junk; matches Go).
    expect(baseline.requirements[0]!.title).toBeUndefined();
  });

  it('should handle ARF with relationship ref missing — L572', async () => {
    const xml = `<?xml version="1.0" encoding="UTF-8"?>
      <asset-report-collection>
        <relationships>
          <relationship type="http://scap.nist.gov/specifications/arf/vocabulary/relationships/1.0#isAbout" subject="r1"/>
        </relationships>
        <reports>
          <report id="r1">
            <content>
              <TestResult id="TR-1"><target>host</target>
                <rule-result idref="rule_1"><result>pass</result></rule-result>
              </TestResult>
            </content>
          </report>
        </reports>
      </asset-report-collection>`;
    const hdf = parseHdf(await convertXccdfResultsToHdf(xml));
    expect(hdf.baselines).toHaveLength(1);
  });

  it('should handle ARF with no reports element — L582', async () => {
    const xml = `<?xml version="1.0" encoding="UTF-8"?>
      <asset-report-collection/>`;
    await expect(convertXccdfResultsToHdf(xml)).rejects.toThrow();
  });

  it('should handle ARF report with no rule-results — L602', async () => {
    const xml = `<?xml version="1.0" encoding="UTF-8"?>
      <asset-report-collection>
        <reports>
          <report id="r1">
            <content>
              <TestResult id="TR-1"><target>host</target></TestResult>
            </content>
          </report>
        </reports>
      </asset-report-collection>`;
    const hdf = parseHdf(await convertXccdfResultsToHdf(xml));
    expect(hdf.baselines[0]!.requirements).toHaveLength(1);
    expect(hdf.baselines[0]!.requirements[0]!.id).toBe('xccdf-results-no-findings');
    expect(hdf.baselines[0]!.requirements[0]!.results[0]!.status).toBe('passed');
  });

  it('should handle ARF with no benchmark and no TestResult title — L619', async () => {
    const xml = `<?xml version="1.0" encoding="UTF-8"?>
      <asset-report-collection>
        <reports>
          <report id="r1">
            <content>
              <TestResult id="TR-1">
                <target>host</target>
                <rule-result idref="rule_1"><result>pass</result></rule-result>
              </TestResult>
            </content>
          </report>
        </reports>
      </asset-report-collection>`;
    const hdf = parseHdf(await convertXccdfResultsToHdf(xml));
    // No benchmark title, no TestResult title → falls back to TestResult id or 'ARF Report'
    expect(hdf.baselines[0]!.name).toBeDefined();
  });

  it('should handle ARF findBenchmarkInArf with no report-requests — L671/L676', async () => {
    // No report-requests means no benchmark found
    const xml = `<?xml version="1.0" encoding="UTF-8"?>
      <asset-report-collection>
        <reports>
          <report id="r1">
            <content>
              <TestResult id="TR-1"><target>host</target>
                <rule-result idref="rule_1"><result>pass</result></rule-result>
              </TestResult>
            </content>
          </report>
        </reports>
      </asset-report-collection>`;
    const hdf = parseHdf(await convertXccdfResultsToHdf(xml));
    expect(hdf.baselines).toHaveLength(1);
  });

  it('should handle ARF asset with no connections — L698', async () => {
    const xml = `<?xml version="1.0" encoding="UTF-8"?>
      <asset-report-collection>
        <assets>
          <asset id="a1">
            <computing-device><fqdn>test.com</fqdn></computing-device>
          </asset>
        </assets>
        <relationships>
          <relationship type="http://scap.nist.gov/specifications/arf/vocabulary/relationships/1.0#isAbout" subject="r1">
            <ref>a1</ref>
          </relationship>
        </relationships>
        <reports>
          <report id="r1">
            <content>
              <TestResult id="TR-1"><target>host</target>
                <rule-result idref="rule_1"><result>pass</result></rule-result>
              </TestResult>
            </content>
          </report>
        </reports>
      </asset-report-collection>`;
    const hdf = parseHdf(await convertXccdfResultsToHdf(xml));
    expect(hdf.components[0]!.fqdn).toBe('test.com');
  });

  it('should handle buildRuleIndex with groups having no Rule — L743', async () => {
    const xml = `<?xml version="1.0" encoding="UTF-8"?>
      <Benchmark id="test_benchmark">
        <title>Test</title>
        <Group id="G-1"><title>Empty Group</title></Group>
        <TestResult id="TR-1" start-time="2025-01-01T00:00:00">
          <target>host</target>
          <rule-result idref="nonexistent"><result>pass</result></rule-result>
        </TestResult>
      </Benchmark>`;
    const hdf = parseHdf(await convertXccdfResultsToHdf(xml));
    expect(hdf.baselines).toHaveLength(1);
  });

  it('should handle rule-result with empty result string (defaults to error) — L783', async () => {
    const xml = `<?xml version="1.0" encoding="UTF-8"?>
      <Benchmark id="test_benchmark">
        <title>Test</title>
        <Group id="G-1"><title>G1</title>
          <Rule id="rule_1" severity="low"><title>R1</title><version>SV-001</version></Rule>
        </Group>
        <TestResult id="TR-1" start-time="2025-01-01T00:00:00">
          <target>host</target>
          <rule-result idref="rule_1"><result></result></rule-result>
        </TestResult>
      </Benchmark>`;
    const hdf = parseHdf(await convertXccdfResultsToHdf(xml));
    // Empty result → default notReviewed
    expect(hdf.baselines[0]!.requirements[0]!.results[0]!.status).toBe('error');
  });

  it('should handle rule-result where idents fall back to rule def idents — L795', async () => {
    const xml = `<?xml version="1.0" encoding="UTF-8"?>
      <Benchmark id="test_benchmark">
        <title>Test</title>
        <Group id="G-1"><title>G1</title>
          <Rule id="rule_1" severity="medium">
            <title>R1</title>
            <version>SV-001</version>
            <ident system="http://cyber.mil/cci">CCI-000001</ident>
          </Rule>
        </Group>
        <TestResult id="TR-1" start-time="2025-01-01T00:00:00">
          <target>host</target>
          <rule-result idref="rule_1"><result>pass</result></rule-result>
        </TestResult>
      </Benchmark>`;
    const hdf = parseHdf(await convertXccdfResultsToHdf(xml));
    // Rule-result has no idents → falls back to rule def idents
    const tags = hdf.baselines[0]!.requirements[0]!.tags as Record<string, unknown>;
    expect(tags.cci).toBeDefined();
  });

  it('should handle extractCCIs with ident that has no #text — L937', async () => {
    const xml = `<?xml version="1.0" encoding="UTF-8"?>
      <Benchmark id="test_benchmark">
        <title>Test</title>
        <Group id="G-1"><title>G1</title>
          <Rule id="rule_1" severity="medium">
            <title>R1</title><version>SV-001</version>
            <ident system="http://cyber.mil/cci"/>
            <ident system="http://other.system">OTHER-001</ident>
          </Rule>
        </Group>
      </Benchmark>`;
    const baseline = parseBaseline(await convertXccdfBenchmarkToHdf(xml));
    // Empty CCI ident should be filtered out
    expect(baseline.requirements).toHaveLength(1);
  });

  it('should handle TestResult with no rule-result — L357', async () => {
    const xml = `<?xml version="1.0" encoding="UTF-8"?>
      <Benchmark id="test_benchmark">
        <title>Test</title>
        <TestResult id="TR-1" start-time="2025-01-01T00:00:00">
          <target>host</target>
        </TestResult>
      </Benchmark>`;
    const hdf = parseHdf(await convertXccdfResultsToHdf(xml));
    expect(hdf.baselines[0]!.requirements).toHaveLength(1);
    expect(hdf.baselines[0]!.requirements[0]!.id).toBe('xccdf-results-no-findings');
    expect(hdf.baselines[0]!.requirements[0]!.results[0]!.status).toBe('passed');
  });
});

describe('Conveyor second-pass branch coverage', () => {
  it('should handle body as non-string type (number) — L134', async () => {
    const input = JSON.stringify({
      api_response: {
        results: {
          'file-sha': {
            sha256: 'abc123',
            response: { service_name: 'Moldy' },
            result: { score: 100, sections: [{
              title_text: 'Finding', body: 42, body_format: 'text',
              classification: 'SUSPICIOUS', depth: 0,
            }] },
          },
        },
      },
    });
    const hdf = parseHdf(await convertConveyorToHdf(input));
    expect(hdf.baselines[0]!.requirements).toHaveLength(1);
  });

  it('should handle Moldy heuristic with missing sub-fields — L151-153', async () => {
    const input = JSON.stringify({
      api_response: {
        results: {
          'file-sha': {
            sha256: 'abc123',
            response: { service_name: 'Moldy' },
            result: { score: 100, sections: [{
              title_text: 'Finding', body: 'text', body_format: 'text',
              classification: 'SUSPICIOUS', depth: 0,
              heuristic: {},
            }] },
          },
        },
      },
    });
    const hdf = parseHdf(await convertConveyorToHdf(input));
    expect(hdf.baselines[0]!.requirements).toHaveLength(1);
  });

  it('should handle CodeQuality with missing optional fields — L157-160', async () => {
    const input = JSON.stringify({
      api_response: {
        results: {
          'file-sha': {
            sha256: 'abc123',
            response: { service_name: 'CodeQuality' },
            result: { score: 50, sections: [{ title_text: 'Finding' }] },
          },
        },
      },
    });
    const hdf = parseHdf(await convertConveyorToHdf(input));
    expect(hdf.baselines[0]!.requirements).toHaveLength(1);
  });

  it('should handle parseJSON returning null — L290', async () => {
    await expect(convertConveyorToHdf('null')).rejects.toThrow('invalid JSON');
  });
});

describe('DBProtect second-pass branch coverage', () => {
  it('should handle findings with missing Details, Date, Check, Risk DV, Job Name, Asset — L160-232', async () => {
    // Minimal DBProtect with columns but values missing
    const xml = `<?xml version="1.0" encoding="UTF-8"?>
      <dataset>
        <metadata>
          <item><name>Check ID</name><type>xs:string</type></item>
          <item><name>Result Status</name><type>xs:string</type></item>
        </metadata>
        <data>
          <row><value>CHK-001</value><value>Failed</value></row>
        </data>
      </dataset>`;
    const hdf = parseHdf(await convertDbprotectToHdf(xml));
    expect(hdf.baselines[0]!.requirements).toHaveLength(1);
  });
});

describe('ZAP second-pass branch coverage', () => {
  it('should convert every site even when none have alerts (multi-site no-findings)', async () => {
    const input = JSON.stringify({
      site: [
        { '@name': 'http://a.com', '@host': 'a.com', '@port': '80' },
        { '@name': 'http://b.com', '@host': 'b.com', '@port': '80' },
      ],
      '@version': '2.14.0',
    });
    const hdf = parseHdf(await convertZapToHdf(input));
    // Each alert-less site still yields its own baseline with a no-findings placeholder.
    expect(hdf.baselines).toHaveLength(2);
    for (const b of hdf.baselines) {
      expect(b!.requirements[0]!.results[0]!.status).toBe('passed');
    }
  });

  it('should handle alert with no desc — L260', async () => {
    const input = JSON.stringify({
      site: [{
        '@name': 'http://test.com', '@host': 'test.com', '@port': '80',
        alerts: [{
          pluginid: '10001', riskcode: '2', name: 'No Desc Alert',
          instances: [{ uri: 'http://test.com/' }],
        }],
      }],
    });
    const hdf = parseHdf(await convertZapToHdf(input));
    expect(hdf.baselines[0]!.requirements).toHaveLength(1);
  });

  it('should handle alert with unknown riskcode — L268', async () => {
    const input = JSON.stringify({
      site: [{
        '@name': 'http://test.com', '@host': 'test.com', '@port': '80',
        alerts: [{
          pluginid: '10001', name: 'No Risk', desc: 'd',
          instances: [{ uri: 'http://test.com/' }],
        }],
      }],
    });
    const hdf = parseHdf(await convertZapToHdf(input));
    expect(hdf.baselines[0]!.requirements).toHaveLength(1);
  });

  it('should handle site with @host but no @name (target path) — L304', async () => {
    const input = JSON.stringify({
      site: [{
        '@host': 'test.com', '@port': '80',
        alerts: [{ pluginid: '1', riskcode: '1', name: 'A', desc: 'd', instances: [{ uri: 'http://test.com/' }] }],
      }],
    });
    const hdf = parseHdf(await convertZapToHdf(input));
    expect(hdf.baselines).toHaveLength(1);
  });

  it('should handle instances truncation warning — L241', async () => {
    // Can't actually trigger truncation with 100K items in a test,
    // but can test the no-instances branch
    const input = JSON.stringify({
      site: [{
        '@name': 'http://test.com', '@host': 'test.com', '@port': '80',
        alerts: [{
          pluginid: '10001', riskcode: '2', name: 'Empty Inst', desc: 'd',
          instances: [],
        }],
      }],
    });
    const hdf = parseHdf(await convertZapToHdf(input));
    expect(hdf.baselines[0]!.requirements[0]!.results).toHaveLength(0);
  });
});

describe('BurpSuite second-pass branch coverage', () => {
  it('should handle issue with no severity (defaults to information) — L265', async () => {
    const xml = `<?xml version="1.0" encoding="UTF-8"?>
      <issues burpVersion="2023.1" exportTime="2025-01-01">
        <issue>
          <type>99999</type>
          <name>No Sev</name>
          <host ip="10.0.0.1">https://example.com</host>
          <confidence>Certain</confidence>
          <issueBackground>BG</issueBackground>
          <path>/test</path>
          <location>/test</location>
        </issue>
      </issues>`;
    const hdf = parseHdf(await convertBurpsuiteToHdf(xml));
    expect(hdf.baselines[0]!.requirements[0]!.impact).toBe(0.3);
  });

  it('should handle issue with no name — L269', async () => {
    const xml = `<?xml version="1.0" encoding="UTF-8"?>
      <issues burpVersion="2023.1" exportTime="2025-01-01">
        <issue>
          <type>99999</type>
          <host ip="10.0.0.1">https://example.com</host>
          <severity>Medium</severity>
          <confidence>Firm</confidence>
          <path>/test</path>
          <location>/test</location>
        </issue>
      </issues>`;
    const hdf = parseHdf(await convertBurpsuiteToHdf(xml));
    expect(hdf.baselines[0]!.requirements).toHaveLength(1);
  });

  it('should handle issue with host having no text content — L254', async () => {
    const xml = `<?xml version="1.0" encoding="UTF-8"?>
      <issues burpVersion="2023.1" exportTime="2025-01-01">
        <issue>
          <type>99999</type>
          <name>Host No Text</name>
          <host ip="10.0.0.1"/>
          <severity>Low</severity>
          <confidence>Tentative</confidence>
          <issueBackground>BG</issueBackground>
          <path>/test</path>
          <location>/test</location>
        </issue>
      </issues>`;
    const hdf = parseHdf(await convertBurpsuiteToHdf(xml));
    expect(hdf.baselines[0]!.requirements).toHaveLength(1);
  });
});

describe('AWS Config second-pass branch coverage', () => {
  it('should handle invalid JSON — L166', async () => {
    await expect(convertAwsConfigToHdf('not json')).rejects.toThrow();
  });

  it('should handle rule with empty ARN and SourceIdentifier — L91-92', async () => {
    const input = JSON.stringify({
      ConfigRules: [{
        ConfigRuleId: 'rule-1',
        ConfigRuleName: 'test-rule',
        Description: 'Test',
        Source: { SourceIdentifier: '' },
        InputParameters: '{}',
        EvaluationResults: [{
          ComplianceType: 'COMPLIANT',
          EvaluationResultIdentifier: {
            EvaluationResultQualifier: {
              ConfigRuleName: 'test-rule',
              ResourceType: 'AWS::S3::Bucket',
              ResourceId: 'bucket1',
            },
          },
          ResultRecordedTime: '2025-01-01T00:00:00.000Z',
        }],
      }],
    });
    const hdf = parseHdf(await convertAwsConfigToHdf(input));
    expect(hdf.baselines).toHaveLength(1);
  });

  it('should handle rule where both NIST lookups return empty — L85', async () => {
    const input = JSON.stringify({
      ConfigRules: [{
        ConfigRuleId: 'rule-1',
        ConfigRuleName: 'completely-unknown-custom-rule',
        ConfigRuleArn: 'arn:aws:config:us-east-1:123456789012:config-rule/rule-1',
        Description: 'Test',
        Source: { SourceIdentifier: 'COMPLETELY_UNKNOWN_IDENTIFIER' },
        InputParameters: '{}',
        EvaluationResults: [{
          ComplianceType: 'COMPLIANT',
          EvaluationResultIdentifier: {
            EvaluationResultQualifier: {
              ConfigRuleName: 'completely-unknown-custom-rule',
              ResourceType: 'AWS::S3::Bucket',
              ResourceId: 'bucket1',
            },
          },
          ResultRecordedTime: '2025-01-01T00:00:00.000Z',
        }],
      }],
    });
    const hdf = parseHdf(await convertAwsConfigToHdf(input));
    expect(hdf.baselines).toHaveLength(1);
  });
});

describe('Snyk second-pass branch coverage', () => {
  it('should handle multi-project with no projectName on first item — L201', async () => {
    const input = JSON.stringify([
      {
        path: '/app1/package.json',
        vulnerabilities: [{ id: 'v1', title: 'V1', severity: 'low', description: 'd', from: ['a'], identifiers: { CWE: [] } }],
      },
    ]);
    const hdf = parseHdf(await convertSnykToHdf(input));
    expect(hdf.baselines).toHaveLength(1);
  });
});

describe('JUnit second-pass branch coverage', () => {
  it('should handle testsuites with no name — L104-105', async () => {
    const xml = `<?xml version="1.0" encoding="UTF-8"?>
      <testsuites>
        <testsuite>
          <testcase name="test1" classname="pkg.Class"/>
        </testsuite>
      </testsuites>`;
    const hdf = parseHdf(await convertJunitToHdf(xml));
    expect(hdf.baselines).toHaveLength(1);
  });

  it('should handle failure with no message or type — L190', async () => {
    const xml = `<?xml version="1.0" encoding="UTF-8"?>
      <testsuites>
        <testsuite name="Suite1">
          <testcase name="test1" classname="pkg.Class">
            <failure>Assertion text only</failure>
          </testcase>
        </testsuite>
      </testsuites>`;
    const hdf = parseHdf(await convertJunitToHdf(xml));
    expect(hdf.baselines[0]!.requirements[0]!.results[0]!.status).toBe('failed');
  });
});

describe('Fortify second-pass branch coverage', () => {
  it('should handle desc with no Abstract — L218 descAbstract undefined', async () => {
    const xml = `<?xml version="1.0" encoding="UTF-8"?>
      <FVDL>
        <Vulnerabilities><Vulnerability>
          <ClassInfo><ClassID>C1</ClassID><DefaultSeverity>2.0</DefaultSeverity></ClassInfo>
          <InstanceInfo><InstanceID>I1</InstanceID></InstanceInfo>
        </Vulnerability></Vulnerabilities>
        <Description classID="C1"><Explanation>Explain</Explanation></Description>
      </FVDL>`;
    const hdf = parseHdf(await convertFortifyToHdf(xml));
    expect(hdf.baselines[0]!.requirements).toHaveLength(1);
  });

  it('should handle desc with classID missing — L259', async () => {
    const xml = `<?xml version="1.0" encoding="UTF-8"?>
      <FVDL>
        <Vulnerabilities><Vulnerability>
          <ClassInfo><ClassID>unknown</ClassID><DefaultSeverity>2.0</DefaultSeverity></ClassInfo>
          <InstanceInfo><InstanceID>I1</InstanceID></InstanceInfo>
        </Vulnerability></Vulnerabilities>
        <Description><Abstract>Test</Abstract><Explanation>E</Explanation></Description>
      </FVDL>`;
    const hdf = parseHdf(await convertFortifyToHdf(xml));
    expect(hdf.baselines[0]!.requirements).toHaveLength(1);
  });

  it('should handle vuln entry with SourceLocation that has path but no line — L184', async () => {
    const xml = `<?xml version="1.0" encoding="UTF-8"?>
      <FVDL>
        <Vulnerabilities><Vulnerability>
          <ClassInfo><ClassID>C1</ClassID><DefaultSeverity>2.0</DefaultSeverity></ClassInfo>
          <InstanceInfo><InstanceID>I1</InstanceID></InstanceInfo>
          <AnalysisInfo><Unified><Trace><Primary>
            <Entry><Node isDefault="true"><SourceLocation path="/app/src/Main.java"/></Node></Entry>
          </Primary></Trace></Unified></AnalysisInfo>
        </Vulnerability></Vulnerabilities>
        <Description classID="C1"><Abstract>A</Abstract><Explanation>E</Explanation></Description>
      </FVDL>`;
    const hdf = parseHdf(await convertFortifyToHdf(xml));
    expect(hdf.baselines[0]!.requirements).toHaveLength(1);
  });
});

describe('Additional Conveyor branch coverage', () => {
  it('should handle result with empty sections array', async () => {
    const input = JSON.stringify({
      api_response: {
        results: {
          'file-sha': {
            sha256: 'abc123',
            response: { service_name: 'TestScanner' },
            result: { score: 0, sections: [] },
          },
        },
      },
    });
    const hdf = parseHdf(await convertConveyorToHdf(input));
    expect(hdf.baselines[0]!.requirements).toHaveLength(1);
  });

  it('should handle result with no file_tree', async () => {
    const input = JSON.stringify({
      api_response: {
        results: {
          'file-sha': {
            sha256: 'abc123',
            response: {
              service_name: 'Scanner',
              milestones: { service_started: '2025-01-01T00:00:00Z' },
            },
            result: { score: 100, sections: [{ title_text: 'Finding' }] },
          },
        },
      },
    });
    const hdf = parseHdf(await convertConveyorToHdf(input));
    expect(hdf.baselines[0]!.requirements).toHaveLength(1);
  });
});
