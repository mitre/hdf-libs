import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { describe, it, expect } from 'vitest';
import { expectValidResults } from '../../../test/helpers/expectValidHdf.js';
import {
  convertAsffToHdf,
  mapComplianceStatus,
  severityLabelToImpact,
  findingImpact,
  trivyLocation,
} from './converter.js';
import type { HDFResults, EvaluatedBaseline } from '@mitre/hdf-schema';
import { ResultStatus } from '@mitre/hdf-schema';

const __dirname = dirname(fileURLToPath(import.meta.url));
const FIXTURES_DIR = join(__dirname, '..', 'fixtures');

function loadFixture(name: string): string {
  return readFileSync(join(FIXTURES_DIR, 'input', name), 'utf-8');
}

function baselineByName(hdf: HDFResults, name: string): EvaluatedBaseline {
  const b = hdf.baselines.find((x) => x.name === name);
  if (!b) {
    throw new Error(`baseline ${name} not found; have ${hdf.baselines.map((x) => x.name).join(', ')}`);
  }
  return b;
}

describe('asff-to-hdf converter', () => {
  it('throws on empty input', async () => {
    await expect(convertAsffToHdf('')).rejects.toThrow();
  });

  it('throws on invalid JSON', async () => {
    await expect(convertAsffToHdf('not valid json')).rejects.toThrow();
  });

  it('throws on valid-but-scalar JSON rather than accepting it as a finding', async () => {
    // `42` / `null` / `"x"` parse cleanly but are not findings — must error like Go.
    await expect(convertAsffToHdf('42')).rejects.toThrow(/invalid ASFF JSON/);
    await expect(convertAsffToHdf('null')).rejects.toThrow(/invalid ASFF JSON/);
  });

  it('splits one baseline per Security Hub standard', async () => {
    const hdf = JSON.parse(await convertAsffToHdf(loadFixture('minimal.json'), '0.1.0')) as HDFResults;

    expect(hdf.generator?.name).toBe('asff-to-hdf');
    expect(hdf.baselines).toHaveLength(2);

    const cis = baselineByName(hdf, 'CIS AWS Foundations Benchmark v1.2.0');
    expect(cis.requirements.map((r) => r.id).sort()).toEqual(['1.1', '2.5']);

    const afsbp = baselineByName(hdf, 'AWS Foundational Security Best Practices v1.0.0');
    expect(afsbp.requirements.map((r) => r.id).sort()).toEqual(['Config.1', 'S3.2']);
  });

  it('maps status and impact, up-grading Security Hub INFORMATIONAL to MEDIUM', async () => {
    const hdf = JSON.parse(await convertAsffToHdf(loadFixture('minimal.json'), '0.1.0')) as HDFResults;
    const afsbp = baselineByName(hdf, 'AWS Foundational Security Best Practices v1.0.0');

    const s32 = afsbp.requirements.find((r) => r.id === 'S3.2')!;
    expect(s32.results[0]!.status).toBe(ResultStatus.Passed);
    expect(s32.impact).toBeCloseTo(0.5, 5);

    const config1 = afsbp.requirements.find((r) => r.id === 'Config.1')!;
    expect(config1.results[0]!.status).toBe(ResultStatus.Failed);
    expect(config1.impact).toBeCloseTo(0.5, 5);

    for (const req of afsbp.requirements) {
      for (const res of req.results) {
        expect(res.codeDesc).toBeTruthy();
        expect(res.startTime).toBeTruthy();
      }
    }
  });

  it('floors an unmapped Security Hub config-rule finding to CM-6, not SA-11/RA-5', async () => {
    // Synthetic rule name so it stays unmapped; a Config-rule-backed finding we can't
    // map is still a configuration-settings check → CM-6, matching aws-config-to-hdf.
    const input = JSON.stringify({
      Findings: [
        {
          SchemaVersion: '2018-10-08',
          Id: 'arn:aws:securityhub:us-east-1:123456789123:subscription/aws-foundational-security-best-practices/v/1.0.0/EXAMPLE.1/finding/abc',
          ProductArn: 'arn:aws:securityhub:us-east-1::product/aws/securityhub',
          GeneratorId: 'aws-foundational-security-best-practices/v/1.0.0/EXAMPLE.1',
          AwsAccountId: '123456789123',
          Types: ['Software and Configuration Checks'],
          Severity: { Label: 'HIGH', Normalized: 70 },
          Title: 'EXAMPLE.1 An unmapped config rule',
          Description: 'A Security Hub control backed by a Config rule we do not map.',
          Resources: [{ Type: 'AwsS3Bucket', Id: 'arn:aws:s3:::some-bucket', Region: 'us-east-1' }],
          ProductFields: {
            'RelatedAWSResources:0/name': 'zzz-nonexistent-config-rule',
            'RelatedAWSResources:0/type': 'AWS::Config::ConfigRule',
            StandardsArn: 'arn:aws:securityhub:::standards/aws-foundational-security-best-practices/v/1.0.0',
          },
          Compliance: { Status: 'FAILED' },
          RecordState: 'ACTIVE',
        },
      ],
    });
    const hdf = JSON.parse(await convertAsffToHdf(input)) as HDFResults;
    expect(hdf.baselines[0]!.requirements[0]!.tags?.nist).toEqual(['CM-6']);
  });

  it('emits one CloudAccount component per AWS account', async () => {
    const hdf = JSON.parse(await convertAsffToHdf(loadFixture('minimal.json'), '0.1.0')) as HDFResults;
    expect(hdf.components).toHaveLength(1);
    expect(hdf.components![0]!.name).toBe('123456789123');
    expect(hdf.components![0]!.type).toBe('cloudAccount');
  });

  it('produces schema-valid HDF from the real Security Hub sample', async () => {
    const hdf = JSON.parse(await convertAsffToHdf(loadFixture('securityhub_sample.json'), '0.1.0')) as HDFResults;
    expect(hdf.baselines).toHaveLength(2);
    expectValidResults(hdf);
  });

  it('accepts a bare array of findings (non-Security-Hub product)', async () => {
    const input = '[{"Id":"a","ProductArn":"arn:aws:securityhub:us-east-1::product/aws/guardduty","GeneratorId":"foo/bar/GD.1","Compliance":{"Status":"FAILED"}}]';
    const hdf = JSON.parse(await convertAsffToHdf(input, '0.1.0')) as HDFResults;
    expect(hdf.baselines).toHaveLength(1);
    expect(hdf.baselines[0]!.name).toBe('aws - guardduty');
    expect(hdf.baselines[0]!.requirements[0]!.id).toBe('GD.1');
  });

  it('accepts a single finding object', async () => {
    const input = '{"Id":"b","ProductArn":"arn:aws:securityhub:us-east-1::product/aws/guardduty","GeneratorId":"x/y/z"}';
    const hdf = JSON.parse(await convertAsffToHdf(input, '0.1.0')) as HDFResults;
    expect(hdf.baselines).toHaveLength(1);
    // No compliance status -> per-instance finding keyed by its unique Id.
    expect(hdf.baselines[0]!.requirements[0]!.id).toBe('b');
  });

  it('synthesizes a passed placeholder for empty findings', async () => {
    const hdf = JSON.parse(await convertAsffToHdf(loadFixture('empty.json'), '0.1.0')) as HDFResults;
    expect(hdf.baselines).toHaveLength(1);
    expect(hdf.baselines[0]!.requirements).toHaveLength(1);
    const req = hdf.baselines[0]!.requirements[0]!;
    expect(req.id).toBe('asff-no-findings');
    expect(req.results[0]!.status).toBe(ResultStatus.Passed);
    expectValidResults(hdf);
  });
});

describe('asff mapping helpers', () => {
  it('maps Compliance.Status to HDF status (no "skipped")', () => {
    expect(mapComplianceStatus('PASSED')).toBe(ResultStatus.Passed);
    expect(mapComplianceStatus('FAILED')).toBe(ResultStatus.Failed);
    expect(mapComplianceStatus('WARNING')).toBe(ResultStatus.NotReviewed);
    expect(mapComplianceStatus('NOT_AVAILABLE')).toBe(ResultStatus.NotReviewed);
    expect(mapComplianceStatus(undefined)).toBe(ResultStatus.Failed);
    expect(mapComplianceStatus('BOGUS')).toBe(ResultStatus.Error);
  });

  it('maps severity labels to impact', () => {
    expect(severityLabelToImpact('CRITICAL')).toBeCloseTo(0.9, 5);
    expect(severityLabelToImpact('HIGH')).toBeCloseTo(0.7, 5);
    expect(severityLabelToImpact('MEDIUM')).toBeCloseTo(0.5, 5);
    expect(severityLabelToImpact('LOW')).toBeCloseTo(0.3, 5);
    expect(severityLabelToImpact('INFORMATIONAL')).toBeCloseTo(0.0, 5);
  });

  it('renders Trivy misconfiguration file locations, omitting line 0', () => {
    expect(trivyLocation({ Filename: 'Dockerfile', StartLine: '0', EndLine: '0' })).toBe('Dockerfile');
    expect(trivyLocation({ Filename: 'main.tf', StartLine: '12', EndLine: '12' })).toBe('main.tf:12');
    expect(trivyLocation({ Filename: 'main.tf', StartLine: '12', EndLine: '18' })).toBe('main.tf:12-18');
    // A line number with no filename is meaningless — return empty, not ':12'.
    expect(trivyLocation({ StartLine: '12' })).toBe('');
  });

  it('forces suppressed findings to zero impact', () => {
    expect(
      findingImpact({ Severity: { Label: 'CRITICAL' }, Workflow: { Status: 'SUPPRESSED' } })
    ).toBeCloseTo(0.0, 5);
  });
});

describe('asff product special-cases', () => {
  it('converts Prowler (baseline by ProviderName, blank control desc, failed results)', async () => {
    const hdf = JSON.parse(await convertAsffToHdf(loadFixture('prowler_sample.json'), '0.1.0')) as HDFResults;
    expect(hdf.baselines).toHaveLength(1);
    expect(hdf.baselines[0]!.name).toBe('Prowler');
    expect(hdf.baselines[0]!.requirements.map((r) => r.id).sort()).toEqual(['check11', 'check12']);
    for (const req of hdf.baselines[0]!.requirements) {
      expect(req.descriptions[0]!.data).toBe(' ');
      for (const res of req.results) {
        expect(res.status).toBe(ResultStatus.Failed);
        expect(res.codeDesc).toBeTruthy();
      }
    }
    expectValidResults(hdf);
  });

  it('parses Prowler NDJSON identically to its JSON form', async () => {
    const j = JSON.parse(await convertAsffToHdf(loadFixture('prowler_sample.json'), '0.1.0')) as HDFResults;
    const n = JSON.parse(await convertAsffToHdf(loadFixture('prowler_sample.ndjson'), '0.1.0')) as HDFResults;
    expect(n.baselines[0]!.name).toBe('Prowler');
    expect(n.baselines[0]!.requirements.map((r) => r.id).sort()).toEqual(
      j.baselines[0]!.requirements.map((r) => r.id).sort()
    );
  });

  it('converts Trivy (CVE control id, failed, package message, remediation NIST)', async () => {
    const hdf = JSON.parse(await convertAsffToHdf(loadFixture('trivy_sample.json'), '0.1.0')) as HDFResults;
    expect(hdf.baselines).toHaveLength(1);
    expect(hdf.baselines[0]!.name).toBe('Aqua Security - Trivy');
    const cve = hdf.baselines[0]!.requirements.find((r) => r.id === 'Trivy/CVE-2021-36159')!;
    expect(cve).toBeDefined();
    expect(cve.results[0]!.status).toBe(ResultStatus.Failed);
    expect(cve.results[0]!.message).toContain('For package apk-tools');
    expect(cve.tags.nist).toEqual(['SI-2', 'RA-5']);
    expectValidResults(hdf);
  });


  // ASFF findings vary wildly by producer: Trivy, Prowler and Security Hub each
  // populate a different subset, and third-party integrations populate less
  // still. These assert how a finding stripped of its optional fields degrades —
  // real fixtures never reach these paths because real producers fill them in.
  describe('degrades gracefully on sparse findings', () => {
    const sparse = (extra: Record<string, unknown> = {}) =>
      JSON.stringify([{ Id: 'finding-1', ...extra }]);

    it('falls back to the ASFF product name when the ProductArn carries none', async () => {
      const hdf = JSON.parse(await convertAsffToHdf(sparse())) as HDFResults;
      expect(hdf.baselines[0]!.name).toBe('AWS Security Finding Format');
    });

    it('keys the requirement off Id when there is no GeneratorId', async () => {
      const hdf = JSON.parse(await convertAsffToHdf(sparse())) as HDFResults;
      expect(hdf.baselines[0]!.requirements[0]!.id).toBe('finding-1');
    });

    it('keys a per-instance finding by its Id, and a compliance finding by its control ref', async () => {
      // No compliance status -> keyed by the unique finding Id (never collapses).
      const inst = JSON.parse(
        await convertAsffToHdf(sparse({ GeneratorId: 'some/path/rule-42' })),
      ) as HDFResults;
      expect(inst.baselines[0]!.requirements[0]!.id).toBe('finding-1');
      // With a compliance status it is a control finding -> groups by generator ref.
      const ctrl = JSON.parse(
        await convertAsffToHdf(sparse({ GeneratorId: 'some/path/rule-42', Compliance: { Status: 'FAILED' } })),
      ) as HDFResults;
      expect(ctrl.baselines[0]!.requirements[0]!.id).toBe('rule-42');
    });

    it('names the baseline from the ProductArn company and product', async () => {
      const hdf = JSON.parse(
        await convertAsffToHdf(
          sparse({ ProductArn: 'arn:aws:securityhub:us-east-1::product/acme/scanner' }),
        ),
      ) as HDFResults;
      expect(hdf.baselines[0]!.name).toBe('acme - scanner');
    });

    it('falls back to the default NIST controls when nothing maps', async () => {
      const hdf = JSON.parse(await convertAsffToHdf(sparse())) as HDFResults;
      const tags = hdf.baselines[0]!.requirements[0]!.tags ?? {};
      // A finding with no AWS Config rule and no compliance mapping still needs
      // controls; SA-11/RA-5 is the documented default, not an invented mapping.
      expect(tags['nist']).toEqual(['SA-11', 'RA-5']);
    });

    it('omits message when the finding carries no remediation text', async () => {
      const hdf = JSON.parse(await convertAsffToHdf(sparse())) as HDFResults;
      // message is optional in HDF and the Go converter omits it; an empty
      // string here would diverge from Go (hdf-libs-ppis).
      expect(hdf.baselines[0]!.requirements[0]!.results[0]!.message).toBeUndefined();
    });

    it('accepts a lone unwrapped finding object, not just Findings/array payloads', async () => {
      // Some ASFF producers emit a single finding with no Findings wrapper. The
      // Go parseFindings ladder accepts the same three shapes.
      const hdf = JSON.parse(
        await convertAsffToHdf(JSON.stringify({ Id: 'lone-1', GeneratorId: 'x/rule-9' })),
      ) as HDFResults;
      expect(hdf.baselines[0]!.requirements[0]!.id).toBe('lone-1');
    });
  });


  // Each ASFF producer populates a different subset of the optional fields.
  describe('producer-specific optional fields', () => {
    const one = (extra: Record<string, unknown>) => JSON.stringify([{ Id: 'f1', ...extra }]);

    it('derives impact from Severity.Normalized when no Label is present', async () => {
      const hdf = JSON.parse(await convertAsffToHdf(one({ Severity: { Normalized: 70 } }))) as HDFResults;
      expect(hdf.baselines[0]!.requirements[0]!.impact).toBeGreaterThan(0);
    });

    it('uses the Prowler ProviderName as the baseline name', async () => {
      const hdf = JSON.parse(
        await convertAsffToHdf(
          one({
            ProductArn: 'arn:aws:securityhub:us-east-1::product/prowler/prowler',
            ProductFields: { ProviderName: 'AWS' },
          }),
        ),
      ) as HDFResults;
      expect(hdf.baselines[0]!.name).toBe('AWS');
    });

    it('falls back to ProductFields.RuleId when Security Hub omits ControlId', async () => {
      const hdf = JSON.parse(
        await convertAsffToHdf(
          one({
            ProductArn: 'arn:aws:securityhub:us-east-1::product/aws/securityhub',
            ProductFields: { RuleId: '1.5', StandardsControlArn: 'arn:x:y:z/cis-aws/v/1.2.0/1.5' },
          }),
        ),
      ) as HDFResults;
      expect(hdf.baselines[0]!.requirements[0]!.id).toBe('1.5');
    });

    it('carries the finding SourceUrl into the requirement refs', async () => {
      const hdf = JSON.parse(
        await convertAsffToHdf(one({ SourceUrl: 'https://example.test/finding/1' })),
      ) as HDFResults;
      const refs = hdf.baselines[0]!.requirements[0]!.refs ?? [];
      expect(JSON.stringify(refs)).toContain('https://example.test/finding/1');
    });

    it('carries the compliance StatusReason into the result message', async () => {
      const hdf = JSON.parse(
        await convertAsffToHdf(
          one({ Resources: [{ Type: 'AwsAccount', Id: 'acct-1' }], Compliance: { Status: 'FAILED', StatusReasons: [{ ReasonCode: 'CONFIG_EVALUATES_NONCOMPLIANT' }] } }),
        ),
      ) as HDFResults;
      const res = hdf.baselines[0]!.requirements[0]!.results[0]!;
      // StatusReasons feed the message; codeDesc carries the resources.
      expect(res.message).toContain('CONFIG_EVALUATES_NONCOMPLIANT');
      expect(res.codeDesc).toContain('acct-1');
    });
  });


  // A producer we have no special case for — a detection engine that does not yet
  // exist — must still convert correctly from standard ASFF fields alone: distinct
  // per-instance findings never collapse (even sharing a GeneratorId), their
  // Vulnerabilities[] data survives, and compliance findings still group by control.
  describe('unknown producer — generic path conformance', () => {
    it('never collapses distinct findings, preserves vuln data, groups compliance by control', async () => {
      const hdf = JSON.parse(await convertAsffToHdf(loadFixture('unknown-producer.json'), '1.0.0')) as HDFResults;
      const reqs = hdf.baselines[0]!.requirements;
      expect(reqs).toHaveLength(3); // 2 distinct CVEs + 1 control; the CVEs must not collapse
      const byId = new Map(reqs.map((r) => [r.id, r]));

      const v1 = byId.get('acme/future-scanner/finding/0001')!;
      expect(v1).toBeDefined(); // keyed by finding Id, not the shared GeneratorId
      const msg = v1.results[0]!.message ?? '';
      expect(msg).toContain('CVE-2099-0001');
      expect(msg).toContain('CVSS 3.1 8.1');
      expect(msg).toContain('libexample@1.2.3 (fixed in 1.2.4)');
      expect(v1.refs).toEqual([{ url: 'https://example.test/CVE-2099-0001' }]);

      expect(byId.has('acme/future-scanner/finding/0002')).toBe(true); // second CVE, own requirement
      expect(byId.has('ACME.1')).toBe(true); // compliance finding groups by control ref
    });
  });


  // The vulnerability summary degrades on sparse Vulnerabilities[] entries and
  // dedupes reference URLs — a producer may populate very little.
  it('summarizes a sparse vulnerability and dedupes reference URLs', async () => {
    const input = JSON.stringify([{
      Id: 'sparse-1',
      ProductArn: 'arn:aws:securityhub:us-east-1::product/acme/future-scanner',
      Vulnerabilities: [
        {},
        { Id: 'CVE-2099-9999', ReferenceUrls: ['https://example.test/dup', 'https://example.test/dup'] },
      ],
    }]);
    const hdf = JSON.parse(await convertAsffToHdf(input, '1.0.0')) as HDFResults;
    const req = hdf.baselines[0]!.requirements[0]!;
    expect(req.results[0]!.message).toContain('CVE-2099-9999');
    // the duplicate URL appears once
    expect(req.refs).toEqual([{ url: 'https://example.test/dup' }]);
  });

});
