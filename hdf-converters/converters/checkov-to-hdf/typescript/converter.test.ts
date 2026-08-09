import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { describe, it, expect } from 'vitest';
import { convertCheckovToHdf } from './converter.js';
import { runConverterContractTests } from '../../../shared/typescript/converter-contract.js';
import { expectValidResults } from '../../../test/helpers/expectValidHdf.js';
import { assertRequirementCount } from '../../../shared/typescript/anchor.js';
import type { HDFResults } from '@mitre/hdf-schema';

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

// Parses raw checkov JSON generically — deliberately NOT the converter's parser
// — and returns the number of distinct check_id values across every framework's
// passed/failed/skipped checks. The converter groups checks by check_id (one
// requirement per group), so the distinct count is the ground truth.
function countDistinctCheckIds(input: string): number {
  type Check = { check_id?: string };
  type Report = {
    results?: { passed_checks?: Check[]; failed_checks?: Check[]; skipped_checks?: Check[] };
  };
  const parsed = JSON.parse(input) as Report | Report[];
  const reports = Array.isArray(parsed) ? parsed : [parsed];
  const distinct = new Set<string>();
  for (const r of reports) {
    for (const key of ['passed_checks', 'failed_checks', 'skipped_checks'] as const) {
      for (const c of r.results?.[key] ?? []) distinct.add(c.check_id ?? '');
    }
  }
  return distinct.size;
}

// Ground-truth anchor (input-derived count; see shared/typescript/anchor.ts):
// one requirement per distinct check_id.
describe('checkov-to-hdf ground-truth anchor', () => {
  it('emits one requirement per distinct check_id (multi-framework)', async () => {
    const input = loadFixture('multi-framework.json');
    assertRequirementCount(
      await convertCheckovToHdf(input),
      countDistinctCheckIds(input),
      'multi-framework.json: one requirement per distinct check_id',
    );
  });
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
      const hdf = JSON.parse(output) as HDFResults;

      expect(hdf.timestamp).toBeTruthy();
      expect(hdf.generator?.name).toBe('checkov-to-hdf');
      expect(hdf.generator?.version).toBe('1.0.0');
      expect(hdf.tool?.name).toBe('Checkov');
      expect(hdf.tool?.version).toBe('3.2.524');
      // Scan scope is not a format; check_type lives in requirement tags (kpvj).
      expect(hdf.tool?.format).toBeUndefined();
      expect(hdf.baselines).toHaveLength(1);
    });

    it('should produce schema-valid HDF results', async () => {
      const hdf = JSON.parse(await convertCheckovToHdf(loadFixture('minimal.json')));
      expectValidResults(hdf);
    });

    it('should use "Checkov Scan" as the baseline name', async () => {
      const hdf = JSON.parse(await convertCheckovToHdf(loadFixture('minimal.json'))) as HDFResults;
      expect(hdf.baselines[0]!.name).toBe('Checkov Scan');
    });

    it('should include a sha256 checksum', async () => {
      const hdf = JSON.parse(await convertCheckovToHdf(loadFixture('minimal.json'))) as HDFResults;
      const checksum = hdf.baselines[0]!.resultsChecksum;
      expect(checksum?.algorithm).toBe('sha256');
      expect(checksum?.value).toMatch(/^[a-f0-9]{64}$/);
    });

    it('should group checks by check_id', async () => {
      // minimal.json has CKV_TF_2 (2 passed), CKV_TF_1 (3 failed),
      // CKV2_AWS_6 (1 skipped), CKV_AWS_18 (1 skipped) → 4 requirements
      const hdf = JSON.parse(await convertCheckovToHdf(loadFixture('minimal.json'))) as HDFResults;
      const reqs = hdf.baselines[0]!.requirements;

      expect(reqs).toHaveLength(4);
      const ids = reqs.map(r => r.id).sort();
      expect(ids).toEqual(['CKV2_AWS_6', 'CKV_AWS_18', 'CKV_TF_1', 'CKV_TF_2']);
    });

    it('should create multiple results for repeated check_id', async () => {
      const hdf = JSON.parse(await convertCheckovToHdf(loadFixture('minimal.json'))) as HDFResults;
      const ckvTF1 = hdf.baselines[0]!.requirements.find(r => r.id === 'CKV_TF_1');
      expect(ckvTF1?.results).toHaveLength(3);
    });

    it('should set requirement.code to the rendered code_block source snippet', async () => {
      const hdf = JSON.parse(await convertCheckovToHdf(loadFixture('minimal.json'))) as HDFResults;
      const ckvTF1 = hdf.baselines[0]!.requirements.find(r => r.id === 'CKV_TF_1');
      expect(ckvTF1?.code).toBe(
        [
          '26 module "vpc" {',
          '27   source  = "terraform-aws-modules/vpc/aws"',
          '28   version = "5.8.1"',
          '29 ',
          '30   name = "education-vpc"',
        ].join('\n'),
      );
    });

    it('should omit requirement.code when code_block is null', async () => {
      const input = JSON.stringify({
        check_type: 'terraform',
        results: {
          passed_checks: [],
          failed_checks: [{
            check_id: 'CKV_TEST_1',
            check_name: 'Test check',
            check_result: { result: 'FAILED' },
            severity: null,
            file_path: '/main.tf',
            file_line_range: [1, 5],
            resource: 'aws_s3_bucket.test',
            guideline: null,
            code_block: null,
            check_class: 'checkov.terraform.checks.resource.Test',
          }],
          skipped_checks: [],
          parsing_errors: [],
        },
        summary: { passed: 0, failed: 1, skipped: 0, parsing_errors: 0, resource_count: 1, checkov_version: '3.2.524' },
      });
      const hdf = JSON.parse(await convertCheckovToHdf(input)) as HDFResults;
      expect(hdf.baselines[0]!.requirements[0]!.code).toBeUndefined();
    });

    it('should map PASSED to passed status', async () => {
      const hdf = JSON.parse(await convertCheckovToHdf(loadFixture('minimal.json'))) as HDFResults;
      const ckvTF2 = hdf.baselines[0]!.requirements.find(r => r.id === 'CKV_TF_2');
      for (const result of ckvTF2!.results) {
        expect(result.status).toBe('passed');
      }
    });

    it('should map FAILED to failed status', async () => {
      const hdf = JSON.parse(await convertCheckovToHdf(loadFixture('minimal.json'))) as HDFResults;
      const ckvTF1 = hdf.baselines[0]!.requirements.find(r => r.id === 'CKV_TF_1');
      for (const result of ckvTF1!.results) {
        expect(result.status).toBe('failed');
      }
    });

    it('should map SKIPPED to notReviewed status', async () => {
      const hdf = JSON.parse(await convertCheckovToHdf(loadFixture('minimal.json'))) as HDFResults;
      const ckv2AWS6 = hdf.baselines[0]!.requirements.find(r => r.id === 'CKV2_AWS_6');
      for (const result of ckv2AWS6!.results) {
        expect(result.status).toBe('notReviewed');
      }
    });

    it('should include suppress_comment in skip message', async () => {
      const hdf = JSON.parse(await convertCheckovToHdf(loadFixture('minimal.json'))) as HDFResults;
      const ckv2AWS6 = hdf.baselines[0]!.requirements.find(r => r.id === 'CKV2_AWS_6');
      expect(ckv2AWS6?.results[0]?.message).toContain('Skipping public access block for demo');
    });

    it('should include resource in code_desc', async () => {
      const hdf = JSON.parse(await convertCheckovToHdf(loadFixture('minimal.json'))) as HDFResults;
      const ckvTF1 = hdf.baselines[0]!.requirements.find(r => r.id === 'CKV_TF_1');
      expect(ckvTF1?.results[0]?.codeDesc).toContain('vpc');
    });

    it('should use default 0.5 impact when severity is null', async () => {
      const hdf = JSON.parse(await convertCheckovToHdf(loadFixture('minimal.json'))) as HDFResults;
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
      const hdf = JSON.parse(await convertCheckovToHdf(input)) as HDFResults;
      const crit = hdf.baselines[0]!.requirements.find(r => r.id === 'CKV_TEST_1');
      const low = hdf.baselines[0]!.requirements.find(r => r.id === 'CKV_TEST_2');
      expect(crit?.impact).toBe(0.9);
      expect(low?.impact).toBe(0.3);
    });

    it('renders code_block defensively — skips malformed entries; empty array yields no code', async () => {
      const input = JSON.stringify({
        check_type: 'terraform',
        results: {
          passed_checks: [],
          failed_checks: [{
            check_id: 'CKV_EDGE_1',
            check_name: 'Mixed code_block',
            check_result: { result: 'FAILED' },
            severity: 'LOW',
            file_path: '/main.tf',
            file_line_range: [26, 30],
            resource: 'edge',
            guideline: null,
            code_block: [[26, 'valid line\n'], 'not-an-array', [27], [28, 123], [29, 'no-eol']],
            check_class: 'test',
          }, {
            check_id: 'CKV_EDGE_2',
            check_name: 'Empty code_block',
            check_result: { result: 'FAILED' },
            severity: 'LOW',
            file_path: '/main.tf',
            file_line_range: [1, 1],
            resource: 'edge2',
            guideline: null,
            code_block: [],
            check_class: 'test',
          }],
          skipped_checks: [],
          parsing_errors: [],
        },
        summary: { passed: 0, failed: 2, skipped: 0, parsing_errors: 0, resource_count: 2, checkov_version: '3.2.524' },
      });
      const hdf = JSON.parse(await convertCheckovToHdf(input)) as HDFResults;
      const mixed = hdf.baselines[0]!.requirements.find(r => r.id === 'CKV_EDGE_1');
      const empty = hdf.baselines[0]!.requirements.find(r => r.id === 'CKV_EDGE_2');
      // valid entry kept; non-array/short entries skipped; non-string source -> "28 "; no-newline kept verbatim
      expect(mixed?.code).toBe('26 valid line\n28 \n29 no-eol');
      // Array.isArray true but no valid entries -> code omitted
      expect(empty?.code).toBeUndefined();
    });

    it('should include default description with check name', async () => {
      const hdf = JSON.parse(await convertCheckovToHdf(loadFixture('minimal.json'))) as HDFResults;
      const ckvTF1 = hdf.baselines[0]!.requirements.find(r => r.id === 'CKV_TF_1');
      const defaultDesc = ckvTF1?.descriptions?.find(d => d.label === 'default');
      expect(defaultDesc?.data).toContain('Ensure Terraform module sources use a commit hash');
    });

    it('should include check description with guideline URL', async () => {
      const hdf = JSON.parse(await convertCheckovToHdf(loadFixture('minimal.json'))) as HDFResults;
      const ckvTF1 = hdf.baselines[0]!.requirements.find(r => r.id === 'CKV_TF_1');
      const checkDesc = ckvTF1?.descriptions?.find(d => d.label === 'check');
      expect(checkDesc?.data).toContain('prismacloud.io');
    });

    it('should use default static analysis NIST tags', async () => {
      const hdf = JSON.parse(await convertCheckovToHdf(loadFixture('minimal.json'))) as HDFResults;
      const ckvTF1 = hdf.baselines[0]!.requirements.find(r => r.id === 'CKV_TF_1');
      expect(ckvTF1?.tags?.['nist']).toEqual(['SA-11', 'RA-5']);
    });

    it('tags each requirement with its Bridgecrew bc_check_id', async () => {
      const hdf = JSON.parse(await convertCheckovToHdf(loadFixture('minimal.json'))) as HDFResults;
      const byId = new Map(hdf.baselines[0]!.requirements.map((r) => [r.id, r] as const));
      expect(byId.get('CKV_TF_1')?.tags?.['bc_check_id']).toBe('BC_CROSS_1');
      expect(byId.get('CKV_AWS_18')?.tags?.['bc_check_id']).toBe('BC_AWS_S3_13');
    });

    it('omits the bc_check_id tag when the source field is absent', async () => {
      const doc = {
        check_type: 'terraform',
        results: {
          passed_checks: [],
          failed_checks: [
            { check_id: 'CKV_NOBC_1', check_name: 'no bc', check_result: { result: 'FAILED' }, resource: 'r', file_path: 'f', file_line_range: [1, 2], severity: null },
          ],
          skipped_checks: [],
        },
        summary: { passed: 0, failed: 1, skipped: 0, parsing_errors: 0, resource_count: 1, checkov_version: '3.2.0' },
      };
      const hdf = JSON.parse(await convertCheckovToHdf(JSON.stringify(doc))) as HDFResults;
      const req = hdf.baselines?.[0]?.requirements?.[0];
      expect(req?.id).toBe('CKV_NOBC_1');
      expect(req?.tags?.['bc_check_id']).toBeUndefined();
    });

    it('omits the bc_check_id tag when the source field is null', async () => {
      const doc = {
        check_type: 'terraform',
        results: {
          passed_checks: [],
          failed_checks: [
            { check_id: 'CKV_NULLBC_1', bc_check_id: null, check_name: 'null bc', check_result: { result: 'FAILED' }, resource: 'r', file_path: 'f', file_line_range: [1, 2], severity: null },
          ],
          skipped_checks: [],
        },
        summary: { passed: 0, failed: 1, skipped: 0, parsing_errors: 0, resource_count: 1, checkov_version: '3.2.0' },
      };
      const hdf = JSON.parse(await convertCheckovToHdf(JSON.stringify(doc))) as HDFResults;
      const req = hdf.baselines?.[0]?.requirements?.[0];
      expect(req?.id).toBe('CKV_NULLBC_1');
      expect(req?.tags?.['bc_check_id']).toBeUndefined();
    });

    it('should synthesize a passed placeholder for empty checks', async () => {
      const hdf = JSON.parse(await convertCheckovToHdf(loadFixture('empty.json'))) as HDFResults;
      expect(hdf.baselines).toHaveLength(1);
      expect(hdf.baselines[0]!.requirements).toHaveLength(1);

      const req = hdf.baselines[0]!.requirements[0]!;
      expect(req.id).toBe('checkov-no-findings');
      expect(req.results).toHaveLength(1);
      expect(req.results[0]!.status).toBe('passed');
      expect(req.results[0]!.codeDesc).toContain('Checkov');
      expect(req.results[0]!.codeDesc).toContain('terraform');
      expect(req.results[0]!.codeDesc).toContain('zero findings');
    });
  });

  describe('multi-framework', async () => {
    it('should merge all frameworks into one baseline', async () => {
      const hdf = JSON.parse(await convertCheckovToHdf(loadFixture('multi-framework.json'))) as HDFResults;
      expect(hdf.baselines).toHaveLength(1);
      expect(hdf.baselines[0]!.name).toBe('Checkov Scan');
    });

    it('should include checks from both terraform and dockerfile', async () => {
      const hdf = JSON.parse(await convertCheckovToHdf(loadFixture('multi-framework.json'))) as HDFResults;
      const ids = hdf.baselines[0]!.requirements.map(r => r.id);
      // From terraform
      expect(ids).toContain('CKV_TF_1');
      // From dockerfile
      expect(ids).toContain('CKV_DOCKER_7');
    });

    it('omits the check_type tag when a report carries an empty check_type', async () => {
      const doc = {
        check_type: '',
        results: {
          passed_checks: [
            { check_id: 'CKV_X_1', check_name: 'edge', check_result: { result: 'PASSED' }, resource: 'r', file_path: 'f', file_line_range: [1, 2], severity: null },
          ],
          failed_checks: [],
          skipped_checks: [],
        },
        summary: { passed: 1, failed: 0, skipped: 0, parsing_errors: 0, resource_count: 1, checkov_version: '3.2.0' },
      };
      const hdf = JSON.parse(await convertCheckovToHdf(JSON.stringify(doc))) as HDFResults;
      const req = hdf.baselines?.[0]?.requirements?.[0];
      expect(req?.id).toBe('CKV_X_1');
      // An empty check_type is not a scan scope: no tag, rather than [""].
      expect(req?.tags?.['check_type']).toBeUndefined();
    });

    it('rejects a non-object payload with a structure error', async () => {
      await expect(convertCheckovToHdf('"just a string"')).rejects.toThrow('Invalid checkov structure');
    });

    it('tags each requirement with its report check_type and drops tool.format', async () => {
      const hdf = JSON.parse(await convertCheckovToHdf(loadFixture('multi-framework.json'))) as HDFResults;
      expect(hdf.tool?.format).toBeUndefined();
      const byId = new Map(
        (hdf.baselines ?? []).flatMap((b) => (b.requirements ?? []).map((r) => [r.id, r] as const)),
      );
      expect(byId.get('CKV_TF_1')?.tags?.['check_type']).toEqual(['terraform']);
      expect(byId.get('CKV_DOCKER_7')?.tags?.['check_type']).toEqual(['dockerfile']);
    });

  });

  describe('SARIF routing', async () => {
    function loadSarifFixture(name: string): string {
      return readFileSync(join(__dirname, '..', '..', 'sarif-to-hdf', 'fixtures', 'input', name), 'utf-8');
    }

    it('should detect SARIF input and delegate to SARIF converter', async () => {
      const input = loadSarifFixture('gosec.sarif');
      const hdf = JSON.parse(await convertCheckovToHdf(input)) as HDFResults;

      expect(hdf.baselines).toHaveLength(1);
      expect(hdf.baselines[0]!.requirements.length).toBeGreaterThan(0);
    });

    it('should not route native checkov JSON to SARIF converter', async () => {
      const hdf = JSON.parse(await convertCheckovToHdf(loadFixture('minimal.json'))) as HDFResults;
      expect(hdf.baselines[0]!.name).toBe('Checkov Scan');
    });
  });
});
