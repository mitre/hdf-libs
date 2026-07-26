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
