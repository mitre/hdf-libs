import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { describe, it, expect } from 'vitest';
import { ResultStatus, TargetType, VerificationMethodEnum, type HDFResults } from '@mitre/hdf-schema';
import { convertAsffToHdf } from './converter.js';
import {
  defaultHandler,
  securityHubHandler,
  dispatch,
  dispatchAll,
  whichSpecialCase,
} from './cases.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const FIXTURES_DIR = join(__dirname, '..', 'fixtures', 'input');

function loadFixture(name: string): string {
  return readFileSync(join(FIXTURES_DIR, name), 'utf-8');
}

async function convert(name: string): Promise<HDFResults> {
  const out = await convertAsffToHdf(loadFixture(name));
  return JSON.parse(out) as HDFResults;
}

describe('asff-to-hdf converter', () => {
  it('converts a minimal Security Hub finding', async () => {
    const hdf = await convert('minimal.json');
    expect(hdf.generator?.name).toBe('asff-to-hdf');
    expect(hdf.tool?.name).toBe('AWS Security Finding Format');
    expect(hdf.baselines).toHaveLength(1);
    const bl = hdf.baselines[0];
    expect(bl.requirements).toHaveLength(1);

    const req = bl.requirements[0];
    expect(req.id).toBeTruthy();
    expect(req.title).toContain('root');
    expect(req.descriptions[0].label).toBe('default');
    expect(req.results).toHaveLength(1);
    expect(req.results[0].status).toBe(ResultStatus.Failed);
    expect(req.results[0].codeDesc).toContain('Resources:');
  });

  it('accepts bare-array input', async () => {
    const hdf = await convert('bare-array.json');
    expect(hdf.baselines[0].requirements).toHaveLength(1);
  });

  it('accepts a single-finding object', async () => {
    const hdf = await convert('single.json');
    expect(hdf.baselines[0].requirements).toHaveLength(1);
  });

  it('synthesizes a no-findings placeholder for empty input', async () => {
    const hdf = await convert('empty.json');
    expect(hdf.baselines[0].requirements).toHaveLength(1);
    const req = hdf.baselines[0].requirements[0];
    expect(req.id).toBe('asff-no-findings');
    expect(req.results[0].status).toBe(ResultStatus.Passed);
    expect(req.results[0].codeDesc).toContain('ASFF');
    expect(req.results[0].codeDesc).toContain('zero findings');
  });

  it('consolidates multiple findings sharing one control id', async () => {
    const hdf = await convert('multi-resource.json');
    expect(hdf.baselines[0].requirements).toHaveLength(1);
    expect(hdf.baselines[0].requirements[0].results).toHaveLength(3);
  });

  it('forces impact 0 when Workflow.Status=SUPPRESSED', async () => {
    const hdf = await convert('suppressed.json');
    expect(hdf.baselines[0].requirements[0].impact).toBe(0);
  });

  it('derives CloudAccount component from AwsAccountId', async () => {
    const hdf = await convert('minimal.json');
    expect(hdf.components).toHaveLength(1);
    expect(hdf.components![0].type).toBe(TargetType.CloudAccount);
    expect(hdf.components![0].name).toContain('123456789123');
  });

  it('dispatches Security Hub findings to the SecurityHub case', async () => {
    const hdf = await convert('securityhub.json');
    expect(hdf.baselines[0].title).toContain('v1.2.0');
  });

  it('SecurityHub case derives finding id from ProductFields.RuleId', async () => {
    const hdf = await convert('minimal.json');
    expect(hdf.baselines[0].requirements[0].id).toBe('1.1');
  });

  it('SecurityHub case bumps INFORMATIONAL impact to MEDIUM', async () => {
    const input = JSON.stringify({
      Findings: [
        {
          SchemaVersion: '2018-10-08',
          Id: 'info-test',
          ProductArn: 'arn:aws:securityhub:us-east-1::product/aws/securityhub',
          GeneratorId: 'test/gen',
          AwsAccountId: '123456789123',
          Title: 'Informational finding',
          Description: 'Should be bumped to medium',
          Severity: { Label: 'INFORMATIONAL', Normalized: 0 },
          Resources: [{ Type: 'AwsAccount', Id: 'AWS::::Account:123456789123' }],
          ProductFields: { RuleId: 'test-rule' },
          Compliance: { Status: 'FAILED' },
          UpdatedAt: '2026-01-01T00:00:00Z',
          Types: ['Test'],
        },
      ],
    });
    const hdf: HDFResults = JSON.parse(await convertAsffToHdf(input));
    expect(hdf.baselines[0].requirements[0].impact).toBeCloseTo(0.5);
  });

  it('SecurityHub resolves NIST tags via AWS Config rule lookup', async () => {
    const hdf = await convert('config-rule.json');
    const tags = hdf.baselines[0].requirements[0].tags;
    expect(Array.isArray(tags.nist)).toBe(true);
    const nist = tags.nist as string[];
    expect(nist).toContain('AC-3');
    expect(nist).toContain('SC-7');
  });

  it('sets verificationMethod to automated', async () => {
    const hdf = await convert('config-rule.json');
    const req = hdf.baselines[0].requirements[0];
    expect(req.verificationMethod).toBe(VerificationMethodEnum.Automated);
  });

  it('derives controlType when NIST tags are present', async () => {
    const hdf = await convert('config-rule.json');
    expect(hdf.baselines[0].requirements[0].controlType).toBeTruthy();
  });

  describe('compliance status mapping', () => {
    const cases: Array<[string, ResultStatus]> = [
      ['PASSED', ResultStatus.Passed],
      ['FAILED', ResultStatus.Failed],
      ['WARNING', ResultStatus.NotReviewed],
      ['NOT_AVAILABLE', ResultStatus.NotReviewed],
    ];
    for (const [asff, hdfStatus] of cases) {
      it(`maps ${asff}`, async () => {
        const doc = JSON.parse(loadFixture('minimal.json'));
        doc.Findings[0].Compliance = { Status: asff };
        const hdf: HDFResults = JSON.parse(await convertAsffToHdf(JSON.stringify(doc)));
        expect(hdf.baselines[0].requirements[0].results[0].status).toBe(hdfStatus);
      });
    }

    it('missing Compliance defaults to Failed', async () => {
      const doc = JSON.parse(loadFixture('minimal.json'));
      delete doc.Findings[0].Compliance;
      const hdf: HDFResults = JSON.parse(await convertAsffToHdf(JSON.stringify(doc)));
      expect(hdf.baselines[0].requirements[0].results[0].status).toBe(ResultStatus.Failed);
    });
  });

  describe('error paths', () => {
    it('rejects invalid JSON', async () => {
      await expect(convertAsffToHdf('not valid json')).rejects.toThrow();
    });
    it('rejects empty input', async () => {
      await expect(convertAsffToHdf('')).rejects.toThrow();
    });
    it('rejects a non-array Findings value', async () => {
      await expect(convertAsffToHdf('{"Findings": "nope"}')).rejects.toThrow();
    });
    it('rejects garbage scalar at top level', async () => {
      await expect(convertAsffToHdf('42')).rejects.toThrow();
    });
  });

  describe('default-case full path', () => {
    it('non-SecurityHub ARN goes through the default case', async () => {
      const input = JSON.stringify({
        Findings: [
          {
            SchemaVersion: '2018-10-08',
            Id: 'default-test',
            ProductArn: 'arn:aws:securityhub:us-east-1::product/companyx/scannery',
            GeneratorId: 'scannery/rule/123',
            AwsAccountId: '999999999999',
            Title: 'Default-case finding',
            Description: 'Default dispatch path',
            Severity: { Label: 'LOW' },
            Resources: [{ Type: 'AwsEc2Instance', Id: 'i-abc' }],
            Compliance: { Status: 'PASSED', StatusReasons: [{ ReasonCode: 'OK', Description: 'All checks passed' }] },
            UpdatedAt: '2026-01-01T00:00:00Z',
            SourceUrl: 'https://example.com/finding',
            Remediation: { Recommendation: { Text: 'Do the thing', Url: 'https://example.com/fix' } },
            Types: ['Test'],
          },
        ],
      });
      const hdf: HDFResults = JSON.parse(await convertAsffToHdf(input));
      const bl = hdf.baselines[0];
      const req = bl.requirements[0];
      expect(req.id).toBe('scannery/rule/123');
      expect(req.title).toBe('Default-case finding');
      expect(req.impact).toBeCloseTo(0.3);
      expect(req.results[0].status).toBe(ResultStatus.Passed);
      expect(req.results[0].message).toContain('All checks passed');
      expect(bl.title).toBe('companyx - scannery');
      expect(req.refs?.[0]?.url).toBe('https://example.com/finding');
      const fix = req.descriptions.find((d) => d.label === 'fix');
      expect(fix?.data).toContain('Do the thing');
      expect(fix?.data).toContain('https://example.com/fix');
    });

    it('omits Components when AwsAccountId is missing', async () => {
      const input = JSON.stringify({
        Findings: [
          {
            ProductArn: 'arn:aws:securityhub:us-east-1::product/aws/securityhub',
            GeneratorId: 'g',
            Title: 't',
            Description: 'd',
            Severity: { Label: 'LOW' },
            Resources: [],
            Compliance: { Status: 'PASSED' },
            UpdatedAt: '2026-01-01T00:00:00Z',
          },
        ],
      });
      const hdf: HDFResults = JSON.parse(await convertAsffToHdf(input));
      expect(hdf.components ?? []).toHaveLength(0);
    });
  });
});

describe('consolidation across heterogeneous findings', () => {
  it('unions NIST tag arrays from two findings sharing one control id', async () => {
    // Build two findings that consolidate by id but bring different NIST tags
    // via different AWS Config rule references — exercises mergeTags/unionStringArrays.
    const input = JSON.stringify({
      Findings: [
        {
          ProductArn: 'arn:aws:securityhub:us-east-1::product/aws/securityhub',
          GeneratorId: 'g',
          AwsAccountId: '1',
          Title: 'a',
          Description: 'd',
          Severity: { Label: 'LOW' },
          Resources: [],
          Compliance: { Status: 'PASSED' },
          UpdatedAt: '2026-01-01T00:00:00Z',
          ProductFields: {
            RuleId: 'same-id',
            'RelatedAWSResources:0/type': 'AWS::Config::ConfigRule',
            'RelatedAWSResources:0/name': 's3-bucket-public-read-prohibited',
          },
        },
        {
          ProductArn: 'arn:aws:securityhub:us-east-1::product/aws/securityhub',
          GeneratorId: 'g',
          AwsAccountId: '1',
          Title: 'a',
          Description: 'd',
          Severity: { Label: 'LOW' },
          Resources: [],
          Compliance: { Status: 'PASSED' },
          UpdatedAt: '2026-01-01T00:00:00Z',
          ProductFields: {
            RuleId: 'same-id',
            'RelatedAWSResources:0/type': 'AWS::Config::ConfigRule',
            'RelatedAWSResources:0/name': 'iam-password-policy',
          },
        },
      ],
    });
    const hdf: HDFResults = JSON.parse(await convertAsffToHdf(input));
    expect(hdf.baselines[0].requirements).toHaveLength(1);
    const tags = hdf.baselines[0].requirements[0].tags;
    const nist = tags.nist as string[];
    // S3 rule contributes AC-3/4/6/21(b)/SC-7/SC-7(3); IAM password policy contributes IA-5(1) family.
    // The merged NIST array should contain entries from both — verifies unionStringArrays path.
    expect(nist).toContain('SC-7');
    expect(nist.length).toBeGreaterThan(6);
  });
});

describe('parseFindings edge cases (branch coverage)', () => {
  it('rejects bare array whose elements are not objects', async () => {
    await expect(convertAsffToHdf('["string-not-object"]')).rejects.toThrow();
  });
  it('rejects array with null element', async () => {
    await expect(convertAsffToHdf('[null]')).rejects.toThrow();
  });
  it('rejects nested arrays in Findings', async () => {
    await expect(convertAsffToHdf('{"Findings": [["nested"]]}')).rejects.toThrow();
  });
});

describe('status reason branches', () => {
  async function withCompliance(compliance: unknown): Promise<HDFResults> {
    const doc = JSON.parse(loadFixture('minimal.json'));
    doc.Findings[0].Compliance = compliance;
    return JSON.parse(await convertAsffToHdf(JSON.stringify(doc))) as HDFResults;
  }

  it('formats desc-only reasons', async () => {
    const hdf = await withCompliance({ Status: 'FAILED', StatusReasons: [{ Description: 'just desc' }] });
    expect(hdf.baselines[0].requirements[0].results[0].message).toBe('just desc');
  });
  it('formats code-only reasons', async () => {
    const hdf = await withCompliance({ Status: 'FAILED', StatusReasons: [{ ReasonCode: 'ONLY_CODE' }] });
    expect(hdf.baselines[0].requirements[0].results[0].message).toBe('ONLY_CODE');
  });
  it('joins multiple reason entries with semicolons', async () => {
    const hdf = await withCompliance({
      Status: 'FAILED',
      StatusReasons: [
        { Description: 'first' },
        { ReasonCode: 'CODE_TWO', Description: 'second' },
      ],
    });
    expect(hdf.baselines[0].requirements[0].results[0].message).toBe('first; CODE_TWO: second');
  });
  it('handles empty StatusReasons array', async () => {
    const hdf = await withCompliance({ Status: 'PASSED', StatusReasons: [] });
    // No message attached when no reasons present.
    expect(hdf.baselines[0].requirements[0].results[0].message).toBeUndefined();
  });
  it('Error status does not emit message even when reason text present', async () => {
    const hdf = await withCompliance({ Status: 'BOGUS', StatusReasons: [{ Description: 'x' }] });
    expect(hdf.baselines[0].requirements[0].results[0].status).toBe(ResultStatus.Error);
    expect(hdf.baselines[0].requirements[0].results[0].message).toBeUndefined();
  });
});

describe('UpdatedAt parsing', () => {
  it('falls back to now() when UpdatedAt is missing', async () => {
    const doc = JSON.parse(loadFixture('minimal.json'));
    delete doc.Findings[0].UpdatedAt;
    const hdf: HDFResults = JSON.parse(await convertAsffToHdf(JSON.stringify(doc)));
    expect(hdf.baselines[0].requirements[0].results[0].startTime).toBeTruthy();
  });
  it('falls back to now() when UpdatedAt is unparseable', async () => {
    const doc = JSON.parse(loadFixture('minimal.json'));
    doc.Findings[0].UpdatedAt = 'not-a-date';
    const hdf: HDFResults = JSON.parse(await convertAsffToHdf(JSON.stringify(doc)));
    expect(hdf.baselines[0].requirements[0].results[0].startTime).toBeTruthy();
  });
});

describe('consolidation dedupes shared SourceUrl', () => {
  it('refs from two consolidated findings dedup by URL', async () => {
    const input = JSON.stringify({
      Findings: [
        {
          ProductArn: 'arn:aws:securityhub:us-east-1::product/companyx/scannery',
          GeneratorId: 'shared-id',
          AwsAccountId: '1',
          Title: 'a',
          Description: 'd',
          Severity: { Label: 'LOW' },
          Resources: [],
          Compliance: { Status: 'PASSED' },
          UpdatedAt: '2026-01-01T00:00:00Z',
          SourceUrl: 'https://example.com/same',
        },
        {
          ProductArn: 'arn:aws:securityhub:us-east-1::product/companyx/scannery',
          GeneratorId: 'shared-id',
          AwsAccountId: '1',
          Title: 'a',
          Description: 'd',
          Severity: { Label: 'LOW' },
          Resources: [],
          Compliance: { Status: 'PASSED' },
          UpdatedAt: '2026-01-01T00:00:00Z',
          SourceUrl: 'https://example.com/same',
        },
      ],
    });
    const hdf: HDFResults = JSON.parse(await convertAsffToHdf(input));
    expect(hdf.baselines[0].requirements).toHaveLength(1);
    expect(hdf.baselines[0].requirements[0].refs).toHaveLength(1);
  });
});

describe('asff cases module', () => {
  it('whichSpecialCase identifies SecurityHub', () => {
    expect(whichSpecialCase({ ProductArn: 'arn:aws:securityhub:us-east-1::product/aws/securityhub' })).toBe('SecurityHub');
  });
  it('whichSpecialCase falls through to Default for unknown', () => {
    expect(whichSpecialCase({ ProductArn: 'arn:aws:securityhub:us-east-1::product/companyx/scannery' })).toBe('Default');
  });
  it('whichSpecialCase handles missing ProductArn', () => {
    expect(whichSpecialCase({})).toBe('Default');
  });
  it('dispatch returns SecurityHub handler', () => {
    expect(dispatch({ ProductArn: 'arn:aws:securityhub:us-east-1::product/aws/securityhub' })).toBe(securityHubHandler);
  });
  it('dispatch returns default handler for unknown', () => {
    expect(dispatch({ ProductArn: 'whatever' })).toBe(defaultHandler);
  });
  it('dispatchAll handles empty array', () => {
    expect(dispatchAll([])).toBe(defaultHandler);
  });

  describe('defaultHandler', () => {
    it('findingImpact: critical', () => {
      expect(defaultHandler.findingImpact({ Severity: { Label: 'CRITICAL' } })).toBeCloseTo(0.9);
    });
    it('findingImpact: normalized fallback', () => {
      expect(defaultHandler.findingImpact({ Severity: { Normalized: 45 } })).toBeCloseTo(0.45);
    });
    it('findingImpact: missing severity', () => {
      expect(defaultHandler.findingImpact({})).toBe(0);
    });
    it('findingImpact: suppressed overrides', () => {
      expect(defaultHandler.findingImpact({ Severity: { Label: 'CRITICAL' }, Workflow: { Status: 'SUPPRESSED' } })).toBe(0);
    });
    it('findingImpact: unknown label', () => {
      expect(defaultHandler.findingImpact({ Severity: { Label: 'BOGUS' } })).toBe(0);
    });
    it('findingStatus: missing Compliance is Failed', () => {
      expect(defaultHandler.findingStatus({})).toBe(ResultStatus.Failed);
    });
    it('findingStatus: unknown status is Error', () => {
      expect(defaultHandler.findingStatus({ Compliance: { Status: 'BOGUS' } })).toBe(ResultStatus.Error);
    });
    it('productName: empty list', () => {
      expect(defaultHandler.productName([])).toBe('ASFF Findings');
    });
    it('productName: malformed arn', () => {
      expect(defaultHandler.productName([{ ProductArn: 'garbage' }])).toBe('ASFF Findings');
    });
  });

  describe('securityHubHandler', () => {
    it('findingId prefers ControlId', () => {
      expect(
        securityHubHandler.findingId({
          ProductFields: { ControlId: 'CTRL-100', RuleId: '1.1' },
          GeneratorId: 'unused',
        }),
      ).toBe('CTRL-100');
    });
    it('findingId falls back to GeneratorId tail', () => {
      expect(securityHubHandler.findingId({ GeneratorId: 'arn:foo/9.9' })).toBe('9.9');
    });
    it('findingId plain GeneratorId no slash', () => {
      expect(securityHubHandler.findingId({ GeneratorId: 'plain' })).toBe('plain');
    });
    it('findingImpact: HIGH not bumped', () => {
      expect(
        securityHubHandler.findingImpact({
          ProductArn: 'arn:aws:securityhub:us-east-1::product/aws/securityhub',
          Severity: { Label: 'HIGH' },
        }),
      ).toBeCloseTo(0.7);
    });
    it('findingImpact: suppressed overrides', () => {
      expect(
        securityHubHandler.findingImpact({
          Severity: { Label: 'CRITICAL' },
          Workflow: { Status: 'SUPPRESSED' },
        }),
      ).toBe(0);
    });
    it('findingImpact: missing severity', () => {
      expect(securityHubHandler.findingImpact({})).toBe(0);
    });
    it('findingImpact: normalized fallback', () => {
      expect(securityHubHandler.findingImpact({ Severity: { Normalized: 80 } })).toBeCloseTo(0.8);
    });
    it('findingNistTags: non-config-rule returns empty', () => {
      expect(securityHubHandler.findingNistTags({ ProductFields: {} })).toEqual([]);
    });
    it('findingNistTags: unknown rule returns empty', () => {
      expect(
        securityHubHandler.findingNistTags({
          ProductFields: {
            'RelatedAWSResources:0/type': 'AWS::Config::ConfigRule',
            'RelatedAWSResources:0/name': 'this-rule-does-not-exist-in-the-mapping',
          },
        }),
      ).toEqual([]);
    });
    it('productName: empty list', () => {
      expect(securityHubHandler.productName([])).toBe('AWS Security Hub');
    });
    it('productName: missing StandardsControlArn falls back to default tail', () => {
      expect(
        securityHubHandler.productName([{ ProductArn: 'arn:aws:securityhub:us-east-1::product/aws/securityhub' }]),
      ).toBe('aws - securityhub');
    });
  });
});
