import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { describe, it, expect } from 'vitest';
import { convertCheckovToHdf } from './converter.js';
import { runConverterContractTests } from '../../../shared/typescript/converter-contract.js';
import type { HdfResults } from '@mitre/hdf-schema';

const __dirname = dirname(fileURLToPath(import.meta.url));
const FIXTURES_DIR = join(__dirname, '..', 'fixtures');

function loadFixture(name: string): string {
  return readFileSync(join(FIXTURES_DIR, 'input', name), 'utf-8');
}

runConverterContractTests({
  converterName: 'checkov-to-hdf',
  convertFn: convertCheckovToHdf,
  minimalFixture: 'minimal.json',
});

describe('checkov to HDF converter', async () => {
  describe('convertCheckovToHdf', async () => {
    it('should throw when results field is missing', async () => {
      await expect(convertCheckovToHdf(JSON.stringify({ check_type: 'terraform' }))).rejects.toThrow(
        'missing or invalid results field'
      );
    });

    it('should produce valid HDF structure from minimal fixture', async () => {
      const output = await convertCheckovToHdf(loadFixture('minimal.json'));
      const hdf = JSON.parse(output) as HdfResults;

      expect(hdf.timestamp).toBeTruthy();
      expect(hdf.generator?.name).toBe('checkov-to-hdf');
      expect(hdf.generator?.version).toBe('1.0.0');
      expect(hdf.tool?.name).toBe('Checkov');
      expect(hdf.tool?.version).toBe('3.2.524');
      expect(hdf.tool?.format).toBe('terraform');
      expect(hdf.baselines).toHaveLength(1);
    });

    it('should use "Checkov Scan" as the baseline name', async () => {
      const hdf = JSON.parse(await convertCheckovToHdf(loadFixture('minimal.json'))) as HdfResults;
      expect(hdf.baselines[0]!.name).toBe('Checkov Scan');
    });

    it('should include a sha256 checksum', async () => {
      const hdf = JSON.parse(await convertCheckovToHdf(loadFixture('minimal.json'))) as HdfResults;
      const checksum = hdf.baselines[0]!.resultsChecksum;
      expect(checksum?.algorithm).toBe('sha256');
      expect(checksum?.value).toMatch(/^[a-f0-9]{64}$/);
    });

    it('should group checks by check_id', async () => {
      // minimal.json has CKV_TF_2 (2 passed), CKV_TF_1 (3 failed),
      // CKV2_AWS_6 (1 skipped), CKV_AWS_18 (1 skipped) → 4 requirements
      const hdf = JSON.parse(await convertCheckovToHdf(loadFixture('minimal.json'))) as HdfResults;
      const reqs = hdf.baselines[0]!.requirements;

      expect(reqs).toHaveLength(4);
      const ids = reqs.map(r => r.id).sort();
      expect(ids).toEqual(['CKV2_AWS_6', 'CKV_AWS_18', 'CKV_TF_1', 'CKV_TF_2']);
    });

    it('should create multiple results for repeated check_id', async () => {
      const hdf = JSON.parse(await convertCheckovToHdf(loadFixture('minimal.json'))) as HdfResults;
      const ckvTF1 = hdf.baselines[0]!.requirements.find(r => r.id === 'CKV_TF_1');
      expect(ckvTF1?.results).toHaveLength(3);
    });

    it('should map PASSED to passed status', async () => {
      const hdf = JSON.parse(await convertCheckovToHdf(loadFixture('minimal.json'))) as HdfResults;
      const ckvTF2 = hdf.baselines[0]!.requirements.find(r => r.id === 'CKV_TF_2');
      for (const result of ckvTF2!.results) {
        expect(result.status).toBe('passed');
      }
    });

    it('should map FAILED to failed status', async () => {
      const hdf = JSON.parse(await convertCheckovToHdf(loadFixture('minimal.json'))) as HdfResults;
      const ckvTF1 = hdf.baselines[0]!.requirements.find(r => r.id === 'CKV_TF_1');
      for (const result of ckvTF1!.results) {
        expect(result.status).toBe('failed');
      }
    });

    it('should map SKIPPED to notReviewed status', async () => {
      const hdf = JSON.parse(await convertCheckovToHdf(loadFixture('minimal.json'))) as HdfResults;
      const ckv2AWS6 = hdf.baselines[0]!.requirements.find(r => r.id === 'CKV2_AWS_6');
      for (const result of ckv2AWS6!.results) {
        expect(result.status).toBe('notReviewed');
      }
    });

    it('should include suppress_comment in skip message', async () => {
      const hdf = JSON.parse(await convertCheckovToHdf(loadFixture('minimal.json'))) as HdfResults;
      const ckv2AWS6 = hdf.baselines[0]!.requirements.find(r => r.id === 'CKV2_AWS_6');
      expect(ckv2AWS6?.results[0]?.message).toContain('Skipping public access block for demo');
    });

    it('should include resource in code_desc', async () => {
      const hdf = JSON.parse(await convertCheckovToHdf(loadFixture('minimal.json'))) as HdfResults;
      const ckvTF1 = hdf.baselines[0]!.requirements.find(r => r.id === 'CKV_TF_1');
      expect(ckvTF1?.results[0]?.codeDesc).toContain('vpc');
    });

    it('should use default 0.5 impact when severity is null', async () => {
      const hdf = JSON.parse(await convertCheckovToHdf(loadFixture('minimal.json'))) as HdfResults;
      const ckvTF1 = hdf.baselines[0]!.requirements.find(r => r.id === 'CKV_TF_1');
      expect(ckvTF1?.impact).toBe(0.5);
    });

    it('should map severity strings to impact', async () => {
      const input = JSON.stringify({
        check_type: 'terraform',
        results: {
          passed_checks: [],
          failed_checks: [{
            check_id: 'CKV_TEST_1',
            check_name: 'Critical check',
            check_result: { result: 'FAILED' },
            severity: 'CRITICAL',
            file_path: '/main.tf',
            file_line_range: [1, 5],
            resource: 'test',
            guideline: null,
            code_block: null,
            check_class: 'test',
          }, {
            check_id: 'CKV_TEST_2',
            check_name: 'Low check',
            check_result: { result: 'FAILED' },
            severity: 'LOW',
            file_path: '/main.tf',
            file_line_range: [6, 10],
            resource: 'test2',
            guideline: null,
            code_block: null,
            check_class: 'test',
          }],
          skipped_checks: [],
          parsing_errors: [],
        },
        summary: { passed: 0, failed: 2, skipped: 0, parsing_errors: 0, resource_count: 2, checkov_version: '3.2.524' },
      });
      const hdf = JSON.parse(await convertCheckovToHdf(input)) as HdfResults;
      const crit = hdf.baselines[0]!.requirements.find(r => r.id === 'CKV_TEST_1');
      const low = hdf.baselines[0]!.requirements.find(r => r.id === 'CKV_TEST_2');
      expect(crit?.impact).toBe(0.9);
      expect(low?.impact).toBe(0.3);
    });

    it('should include default description with check name', async () => {
      const hdf = JSON.parse(await convertCheckovToHdf(loadFixture('minimal.json'))) as HdfResults;
      const ckvTF1 = hdf.baselines[0]!.requirements.find(r => r.id === 'CKV_TF_1');
      const defaultDesc = ckvTF1?.descriptions?.find(d => d.label === 'default');
      expect(defaultDesc?.data).toContain('Ensure Terraform module sources use a commit hash');
    });

    it('should include check description with guideline URL', async () => {
      const hdf = JSON.parse(await convertCheckovToHdf(loadFixture('minimal.json'))) as HdfResults;
      const ckvTF1 = hdf.baselines[0]!.requirements.find(r => r.id === 'CKV_TF_1');
      const checkDesc = ckvTF1?.descriptions?.find(d => d.label === 'check');
      expect(checkDesc?.data).toContain('prismacloud.io');
    });

    it('should use default static analysis NIST tags', async () => {
      const hdf = JSON.parse(await convertCheckovToHdf(loadFixture('minimal.json'))) as HdfResults;
      const ckvTF1 = hdf.baselines[0]!.requirements.find(r => r.id === 'CKV_TF_1');
      expect(ckvTF1?.tags?.['nist']).toEqual(['SA-11', 'RA-5']);
    });

    it('should handle empty checks', async () => {
      const input = JSON.stringify({
        check_type: 'terraform',
        results: {
          passed_checks: [],
          failed_checks: [],
          skipped_checks: [],
          parsing_errors: [],
        },
        summary: { passed: 0, failed: 0, skipped: 0, parsing_errors: 0, resource_count: 0, checkov_version: '3.2.524' },
      });
      const hdf = JSON.parse(await convertCheckovToHdf(input)) as HdfResults;
      expect(hdf.baselines[0]!.requirements).toHaveLength(0);
    });
  });

  describe('multi-framework', async () => {
    it('should merge all frameworks into one baseline', async () => {
      const hdf = JSON.parse(await convertCheckovToHdf(loadFixture('multi-framework.json'))) as HdfResults;
      expect(hdf.baselines).toHaveLength(1);
      expect(hdf.baselines[0]!.name).toBe('Checkov Scan');
    });

    it('should include checks from both terraform and dockerfile', async () => {
      const hdf = JSON.parse(await convertCheckovToHdf(loadFixture('multi-framework.json'))) as HdfResults;
      const ids = hdf.baselines[0]!.requirements.map(r => r.id);
      // From terraform
      expect(ids).toContain('CKV_TF_1');
      // From dockerfile
      expect(ids).toContain('CKV_DOCKER_7');
    });

    it('should include all framework types in tool format', async () => {
      const hdf = JSON.parse(await convertCheckovToHdf(loadFixture('multi-framework.json'))) as HdfResults;
      expect(hdf.tool?.format).toContain('terraform');
      expect(hdf.tool?.format).toContain('dockerfile');
    });
  });

  describe('SARIF routing', async () => {
    function loadSarifFixture(name: string): string {
      return readFileSync(join(__dirname, '..', '..', 'sarif-to-hdf', 'fixtures', 'input', name), 'utf-8');
    }

    it('should detect SARIF input and delegate to SARIF converter', async () => {
      const input = loadSarifFixture('gosec.sarif');
      const hdf = JSON.parse(await convertCheckovToHdf(input)) as HdfResults;

      expect(hdf.baselines).toHaveLength(1);
      expect(hdf.baselines[0]!.requirements.length).toBeGreaterThan(0);
    });

    it('should not route native checkov JSON to SARIF converter', async () => {
      const hdf = JSON.parse(await convertCheckovToHdf(loadFixture('minimal.json'))) as HdfResults;
      expect(hdf.baselines[0]!.name).toBe('Checkov Scan');
    });
  });
});
