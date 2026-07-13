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
    expect(hdf.baselines[0]!.requirements[0]!.id).toBe('z');
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

});
