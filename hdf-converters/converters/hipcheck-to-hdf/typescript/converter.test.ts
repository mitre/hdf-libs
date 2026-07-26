import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { describe, it, expect } from 'vitest';
import { convertHipcheckToHdf } from './converter.js';
import { runConverterContractTests } from '../../../shared/typescript/converter-contract.js';
import { expectValidResults } from '../../../test/helpers/expectValidHdf.js';
import type { HDFResults, EvaluatedRequirement } from '@mitre/hdf-schema';

const __dirname = dirname(fileURLToPath(import.meta.url));
const FIXTURES_DIR = join(__dirname, '..', 'fixtures');

function loadFixture(name: string): string {
  return readFileSync(join(FIXTURES_DIR, 'input', name), 'utf-8');
}

async function convert(name: string): Promise<HDFResults> {
  return JSON.parse(await convertHipcheckToHdf(loadFixture(name))) as HDFResults;
}

function findReq(hdf: HDFResults, id: string): EvaluatedRequirement | undefined {
  return hdf.baselines[0]!.requirements.find((r) => r.id === id);
}

runConverterContractTests({
  converterName: 'hipcheck-to-hdf',
  convertFn: convertHipcheckToHdf,
  minimalFixture: 'minimal.json',
});

describe('hipcheck to HDF converter', () => {
  it('rejects input that is not a Hipcheck report', async () => {
    await expect(convertHipcheckToHdf('{"foo":1}')).rejects.toThrow('does not look like a Hipcheck report');
  });

  describe('real fixture (juice-shop, Investigate)', () => {
    it('produces a schema-valid, correctly-shaped document', async () => {
      const hdf = await convert('real.json');
      expectValidResults(hdf);

      const bl = hdf.baselines[0]!;
      expect(bl.name).toBe('Hipcheck Scan');
      expect(bl.title).toBe('Hipcheck analysis of juice-shop/juice-shop @ v20.1.1');
      expect(bl.requirements).toHaveLength(8); // 3 passing + 3 failing + 2 errored
      expect(hdf.tool?.version).toBe('3.15.0');
      expect(hdf.components).toHaveLength(1);
      expect(hdf.components![0]!.name).toBe('juice-shop/juice-shop');
      expect(hdf.components![0]!.type).toBe('repository');
    });

    it('summarizes the Investigate/FailedAnalyses recommendation on the baseline', async () => {
      const hdf = await convert('real.json');
      expect(hdf.baselines[0]!.summary).toBe(
        "Hipcheck recommendation: Investigate (risk score 0.42, policy '(gt 0.5 $)'). Investigation forced by failed analyses: mitre/binary.",
      );
    });

    it('maps passing/failing/errored to passed/failed/error', async () => {
      const hdf = await convert('real.json');
      expect(findReq(hdf, 'mitre/activity')!.results[0]!.status).toBe('passed');
      expect(findReq(hdf, 'mitre/activity')!.impact).toBe(0.5);

      const binary = findReq(hdf, 'mitre/binary')!;
      expect(binary.results[0]!.status).toBe('failed');
      expect(binary.results[0]!.message).toContain('invalidTypeForClient.exe');

      const review = findReq(hdf, 'mitre/review')!;
      expect(review.results[0]!.status).toBe('error');
      expect(review.results[0]!.message).toBe('unknown error');
    });

    it('attaches RMF-reviewed NIST tags and automated verificationMethod', async () => {
      const hdf = await convert('real.json');
      expect((findReq(hdf, 'mitre/binary')!.tags as { nist: string[] }).nist).toEqual(['SI-7', 'SR-4']);
      expect((findReq(hdf, 'mitre/activity')!.tags as { nist: string[] }).nist).toEqual(['SR-3', 'SR-4']);
      expect((findReq(hdf, 'mitre/fuzz')!.tags as { nist: string[] }).nist).toEqual(['SA-11']);
      expect(findReq(hdf, 'mitre/fuzz')!.verificationMethod).toBe('automated');
    });
  });

  describe('pass fixture (Pass / reason null)', () => {
    it('summarizes a Pass recommendation with no suffix', async () => {
      const hdf = await convert('pass.json');
      expect(hdf.baselines[0]!.summary).toBe(
        "Hipcheck recommendation: Pass (risk score 0.33, policy '(gt 0.5 $)').",
      );
      expect(hdf.baselines[0]!.title).toBe('Hipcheck analysis of asff-to-hdf @ feat/aws-config-hdf-enrichment');
      expect(findReq(hdf, 'mitre/binary')!.results[0]!.status).toBe('passed');
      expect(hdf.components![0]!.name).toBe('asff-to-hdf'); // owner null -> bare name
    });
  });

  it('never emits a trailing-slash repo identifier when repo_name is empty', async () => {
    const input = JSON.stringify({
      repo_name: '',
      repo_owner: 'acme',
      repo_head: 'v1',
      hipcheck_version: '3.15.0',
      analyzed_at: '2026-07-25T22:38:44.586772-04:00',
      passing: [],
      failing: [],
      errored: [],
      recommendation: { kind: 'Pass', reason: null, risk_score: 0, risk_policy: '(gt 0.5 $)' },
    });
    const hdf = JSON.parse(await convertHipcheckToHdf(input)) as HDFResults;
    expect(hdf.baselines[0]!.title).toBe('Hipcheck analysis of acme @ v1');
    expect(hdf.components![0]!.name).toBe('acme'); // not "acme/"
  });

  // Branch coverage for paths the real fixtures don't hit (mirrors the Go unit
  // tests, which can call the unexported helpers directly; TS drives them
  // through the public converter with crafted reports).
  describe('recommendation reason + unmapped-analysis branches', () => {
    const baseReport = (overrides: Record<string, unknown>) =>
      JSON.stringify({
        repo_name: 'x',
        repo_owner: null,
        repo_head: 'h',
        hipcheck_version: '3.15.0',
        analyzed_at: '2026-07-25T22:38:44.586772-04:00',
        passing: [],
        failing: [],
        errored: [],
        recommendation: { kind: 'Pass', reason: null, risk_score: 0, risk_policy: '(gt 0.5 $)' },
        ...overrides,
      });

    it('renders the "Policy" reason variant', async () => {
      const hdf = JSON.parse(await convertHipcheckToHdf(baseReport({
        recommendation: { kind: 'Investigate', reason: 'Policy', risk_score: 0.7, risk_policy: '(gt 0.5 $)' },
      }))) as HDFResults;
      expect(hdf.baselines[0]!.summary).toContain('exceeded the policy threshold');
    });

    it('renders an unrecognized string reason verbatim', async () => {
      const hdf = JSON.parse(await convertHipcheckToHdf(baseReport({
        recommendation: { kind: 'Investigate', reason: 'ManualHold', risk_score: 0.7, risk_policy: '(gt 0.5 $)' },
      }))) as HDFResults;
      expect(hdf.baselines[0]!.summary).toContain('Investigation reason: ManualHold.');
    });

    it('omits the suffix for Investigate with an empty FailedAnalyses list', async () => {
      const hdf = JSON.parse(await convertHipcheckToHdf(baseReport({
        recommendation: { kind: 'Investigate', reason: { FailedAnalyses: [] }, risk_score: 0.42, risk_policy: '(gt 0.5 $)' },
      }))) as HDFResults;
      expect(hdf.baselines[0]!.summary).toBe(
        "Hipcheck recommendation: Investigate (risk score 0.42, policy '(gt 0.5 $)').",
      );
    });

    it('emits no NIST tags for an analysis with no mapping', async () => {
      const hdf = JSON.parse(await convertHipcheckToHdf(baseReport({
        passing: [{ analysis: 'Analysis', name: 'mitre/unknownxyz', passed: true, policy_expr: '(x)', final_value: '0', message: 'm' }],
      }))) as HDFResults;
      const req = findReq(hdf, 'mitre/unknownxyz')!;
      expect((req.tags as { nist: string[] }).nist).toEqual([]); // no controls, matches Go
      expect(req.controlType).toBeUndefined();
    });
  });

  describe('robustness to sparse / partial reports', () => {
    it('converts a minimal report missing most optional fields', async () => {
      // Only the two identity fields — exercises the ?? fallbacks for
      // repo_owner/repo_head/analyzed_at, the missing passing/failing/errored
      // arrays, and an absent recommendation object.
      const hdf = JSON.parse(await convertHipcheckToHdf(
        JSON.stringify({ repo_name: 'x', hipcheck_version: '3.15.0' }),
      )) as HDFResults;
      expect(hdf.baselines[0]!.requirements).toHaveLength(1);
      expect(hdf.baselines[0]!.requirements[0]!.id).toBe('hipcheck-no-findings');
      expect(hdf.baselines[0]!.title).toBe('Hipcheck analysis of x @ ');
      expect(hdf.baselines[0]!.summary).toBe(
        "Hipcheck recommendation:  (risk score 0, policy '').",
      );
    });

    it('handles an analysis with no message or policy_expr', async () => {
      const hdf = JSON.parse(await convertHipcheckToHdf(JSON.stringify({
        repo_name: 'x',
        hipcheck_version: '3.15.0',
        passing: [{ name: 'mitre/fuzz', passed: true }],
        failing: [],
        errored: [],
        recommendation: { kind: 'Pass', reason: null, risk_score: 0, risk_policy: '(gt 0.5 $)' },
      }))) as HDFResults;
      const req = findReq(hdf, 'mitre/fuzz')!;
      expect(req.results[0]!.codeDesc).toBe('');
      expect(req.descriptions).toHaveLength(1); // no "check" description without policy_expr
    });

    it('flattens a missing error and a nested error chain', async () => {
      const hdf = JSON.parse(await convertHipcheckToHdf(JSON.stringify({
        repo_name: 'x',
        hipcheck_version: '3.15.0',
        passing: [],
        failing: [],
        errored: [
          { analysis: 'mitre/review', name: 'mitre/review' },
          { analysis: 'mitre/fuzz', name: 'mitre/fuzz', error: { msg: 'outer', source: { msg: 'inner' } } },
        ],
        recommendation: { kind: 'Pass', reason: null, risk_score: 0, risk_policy: '(gt 0.5 $)' },
      }))) as HDFResults;
      expect(findReq(hdf, 'mitre/review')!.results[0]!.message).toBe('unknown error');
      expect(findReq(hdf, 'mitre/fuzz')!.results[0]!.message).toBe('outer: inner');
    });
  });

  describe('empty fixture (no analyses)', () => {
    it('synthesizes a passed no-findings placeholder', async () => {
      const hdf = await convert('empty.json');
      expect(hdf.baselines[0]!.requirements).toHaveLength(1);
      const req = hdf.baselines[0]!.requirements[0]!;
      expect(req.id).toBe('hipcheck-no-findings');
      expect(req.results[0]!.status).toBe('passed');
      expect(req.results[0]!.codeDesc).toContain('Hipcheck');
      expect(hdf.baselines[0]!.summary).toBe(
        "Hipcheck recommendation: Pass (risk score 0, policy '(gt 0.5 $)').",
      );
    });
  });
});
