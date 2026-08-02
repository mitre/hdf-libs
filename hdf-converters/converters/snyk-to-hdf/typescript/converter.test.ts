import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { describe, it, expect } from 'vitest';
import { convertSnykToHdf, buildSnykCvss } from './converter.js';
import { runConverterContractTests } from '../../../shared/typescript/converter-contract.js';
import { DEFAULT_MAX_INPUT_SIZE } from '../../../shared/typescript/converterutil.js';
import { expectValidResults } from '../../../test/helpers/expectValidHdf.js';
import { assertRequirementCount } from '../../../shared/typescript/anchor.js';
import type { HDFResults } from '@mitre/hdf-schema';

const __dirname = dirname(fileURLToPath(import.meta.url));
const FIXTURES_DIR = join(__dirname, '..', 'fixtures');

function loadFixture(name: string): string {
  return readFileSync(join(FIXTURES_DIR, 'input', name), 'utf-8');
}

// countDistinctSnykVulnIDs walks the raw Snyk document — deliberately NOT the
// converter's parser — and returns the number of distinct vulnerabilities[].id
// values. Snyk groups every entry sharing an id into one requirement, so a plain
// vulnerabilities count overshoots; the emission unit is the distinct vuln id.
// Handles both single-project (object) and multi-project (array) input.
function countDistinctSnykVulnIDs(input: string): number {
  const parsed = JSON.parse(input) as unknown;
  const projects = Array.isArray(parsed) ? parsed : [parsed];
  const distinct = new Set<string>();
  for (const p of projects as Array<{ vulnerabilities?: Array<{ id: string }> }>) {
    for (const v of p.vulnerabilities ?? []) distinct.add(v.id);
  }
  return distinct.size;
}

runConverterContractTests({
  converterName: 'snyk-to-hdf',
  convertFn: convertSnykToHdf,
  minimalFixture: 'minimal.json',
});

// Ground-truth anchor (input-derived count; see shared/typescript/anchor.ts):
// one requirement per DISTINCT vulnerabilities[].id, counted independently of
// the converter so a silent under-extraction fails even when Go/TS parity
// agrees. nodejs-goof-local's 379 vulns collapse to 94 distinct ids.
describe('snyk-to-hdf ground-truth anchor', () => {
  it('emits one requirement per distinct vulnerabilities[].id', async () => {
    const input = loadFixture('nodejs-goof-local.json');
    assertRequirementCount(
      await convertSnykToHdf(input),
      countDistinctSnykVulnIDs(input),
      'nodejs-goof-local.json: one requirement per distinct vulnerabilities[].id',
    );
  });
});

describe('snyk to HDF converter', async () => {
  describe('input validation', async () => {
    it('should throw on oversized input', async () => {
      const big = '{' + 'x'.repeat(DEFAULT_MAX_INPUT_SIZE + 1) + '}';
      await expect(convertSnykToHdf(big)).rejects.toThrow('exceeds maximum');
    });
  });

  describe('conversion basics', async () => {
    it('should produce valid HDF from minimal fixture', async () => {
      const output = await convertSnykToHdf(loadFixture('minimal.json'));
      const hdf = JSON.parse(output) as HDFResults;

      expectValidResults(hdf);
      expect(hdf.timestamp).toBeTruthy();
      expect(hdf.generator?.name).toBe('snyk-to-hdf');
      expect(hdf.generator?.version).toBe('1.0.0');
      expect(hdf.baselines).toHaveLength(1);
      // minimal.json has 8 unique vulnerability IDs (9 total entries)
      expect(hdf.baselines[0]!.requirements).toHaveLength(8);
    });

    it('should use "Snyk Scan" as the baseline name', async () => {
      const hdf = JSON.parse(await convertSnykToHdf(loadFixture('minimal.json'))) as HDFResults;
      expect(hdf.baselines[0]!.name).toBe('Snyk Scan');
    });

    it('should include baseline title with project name', async () => {
      const hdf = JSON.parse(await convertSnykToHdf(loadFixture('minimal.json'))) as HDFResults;
      expect(hdf.baselines[0]!.title).toContain('goof');
    });

    it('should include baseline summary', async () => {
      const hdf = JSON.parse(await convertSnykToHdf(loadFixture('minimal.json'))) as HDFResults;
      expect(hdf.baselines[0]!.summary).toContain('vulnerable dependency paths');
    });

    it('should include a sha256 checksum', async () => {
      const hdf = JSON.parse(await convertSnykToHdf(loadFixture('minimal.json'))) as HDFResults;
      const checksum = hdf.baselines[0]!.resultsChecksum;
      expect(checksum?.algorithm).toBe('sha256');
      expect(checksum?.value).toMatch(/^[a-f0-9]{64}$/);
    });
  });

  describe('generator and dataSource', async () => {
    it('should set generator name and version', async () => {
      const hdf = JSON.parse(await convertSnykToHdf(loadFixture('minimal.json'))) as HDFResults;
      expect(hdf.generator?.name).toBe('snyk-to-hdf');
      expect(hdf.generator?.version).toBe('1.0.0');
    });

    it('should set tool name to "Snyk" with no format', async () => {
      const hdf = JSON.parse(await convertSnykToHdf(loadFixture('minimal.json'))) as HDFResults;
      expect(hdf.tool?.name).toBe('Snyk');
      expect(hdf.tool?.format).toBeUndefined() // serialization structures are not formats (kpvj);
    });
  });

  describe('severity to impact mapping', async () => {
    it('should map critical severity to 0.9', async () => {
      const hdf = JSON.parse(await convertSnykToHdf(loadFixture('minimal.json'))) as HDFResults;
      const critical = hdf.baselines[0]!.requirements.find(r => r.id === 'npm:adm-zip:20180415');
      expect(critical?.impact).toBe(0.9);
    });

    it('should map high severity to 0.7', async () => {
      const hdf = JSON.parse(await convertSnykToHdf(loadFixture('minimal.json'))) as HDFResults;
      const high = hdf.baselines[0]!.requirements.find(r => r.id === 'SNYK-JS-ADMZIP-1065796');
      expect(high?.impact).toBe(0.7);
    });

    it('should map medium severity to 0.5', async () => {
      const hdf = JSON.parse(await convertSnykToHdf(loadFixture('minimal.json'))) as HDFResults;
      const medium = hdf.baselines[0]!.requirements.find(r => r.id === 'SNYK-JS-HIGHLIGHTJS-1045326');
      expect(medium?.impact).toBe(0.5);
    });

    it('should map low severity to 0.3', async () => {
      const hdf = JSON.parse(await convertSnykToHdf(loadFixture('minimal.json'))) as HDFResults;
      const low = hdf.baselines[0]!.requirements.find(r => r.id === 'SNYK-JS-HBS-1566555');
      expect(low?.impact).toBe(0.3);
    });
  });

  describe('CWE to NIST mapping', async () => {
    it('should map CWE to NIST controls', async () => {
      const hdf = JSON.parse(await convertSnykToHdf(loadFixture('minimal.json'))) as HDFResults;
      const req = hdf.baselines[0]!.requirements.find(r => r.id === 'SNYK-JS-ADMZIP-1065796');
      // CWE-22 → has NIST mapping
      const nist = req?.tags?.['nist'] as string[];
      expect(nist).toBeDefined();
      expect(nist.length).toBeGreaterThan(0);
    });
  });

  describe('deduplication', async () => {
    it('should deduplicate vulnerabilities by ID', async () => {
      const hdf = JSON.parse(await convertSnykToHdf(loadFixture('minimal.json'))) as HDFResults;
      // SNYK-JS-HANDLEBARS-534988 appears twice → single requirement, 2 results
      const req = hdf.baselines[0]!.requirements.find(r => r.id === 'SNYK-JS-HANDLEBARS-534988');
      expect(req).toBeDefined();
      expect(req!.results).toHaveLength(2);
    });
  });

  describe('dependency path', async () => {
    it('should include dependency path in result code_desc', async () => {
      const hdf = JSON.parse(await convertSnykToHdf(loadFixture('minimal.json'))) as HDFResults;
      const req = hdf.baselines[0]!.requirements.find(r => r.id === 'SNYK-JS-ADMZIP-1065796');
      expect(req).toBeDefined();
      const codeDesc = req!.results[0]?.codeDesc ?? '';
      expect(codeDesc).toContain('goof@1.0.1');
      expect(codeDesc).toContain('adm-zip@0.4.7');
    });
  });

  describe('tags', async () => {
    it('should populate tags (cve, ghsaid, nist, cci) and drop cweid/cveid', async () => {
      const hdf = JSON.parse(await convertSnykToHdf(loadFixture('minimal.json'))) as HDFResults;
      // npm:adm-zip:20180415 has CVE, CWE, and GHSA identifiers
      const req = hdf.baselines[0]!.requirements.find(r => r.id === 'npm:adm-zip:20180415');
      expect(req).toBeDefined();

      const tags = req!.tags;
      // CWE moved to first-class cwe[]; cveid renamed to cve
      expect(tags?.['cweid']).toBeUndefined();
      expect(tags?.['cveid']).toBeUndefined();
      expect(tags?.['cve']).toContain('CVE-2018-1002204');
      expect(tags?.['ghsaid']).toContain('GHSA-3v6h-hqm4-2rg6');
      expect((tags?.['nist'] as string[]).length).toBeGreaterThan(0);
      expect((tags?.['cci'] as string[]).length).toBeGreaterThan(0);
    });
  });

  describe('structured cvss', async () => {
    it('should map cvssScore + CVSSv3 vector into requirement.cvss[]', async () => {
      const hdf = JSON.parse(await convertSnykToHdf(loadFixture('minimal.json'))) as HDFResults;
      const req = hdf.baselines[0]!.requirements.find(r => r.id === 'SNYK-JS-ADMZIP-1065796');
      expect(req).toBeDefined();

      expect(req!.cvss).toHaveLength(1);
      const cv = req!.cvss![0]!;
      expect(cv.version).toBe('3.1');
      expect(cv.baseScore).toBeCloseTo(7.4, 3);
      expect(cv.baseVector).toBe('CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N');
      expect(cv.baseSeverity).toBe('high');
      // old CVSS tags gone
      expect(req!.tags?.['cvss_base_score']).toBeUndefined();
      expect(req!.tags?.['cvss31']).toBeUndefined();
    });

    it('omits cvss[] when the vulnerability carries no score or vector', () => {
      expect(buildSnykCvss({id: 'x', title: 't', description: 'd', severity: 'low', identifiers: {}, from: []})).toEqual([]);
    });

    it('sets baseScore without vector when only cvssScore is present', () => {
      const out = buildSnykCvss({id: 'x', title: 't', description: 'd', severity: 'low', cvssScore: 5.5, identifiers: {}, from: []});
      expect(out).toHaveLength(1);
      expect(out[0]!.version).toBe('3.1');
      expect(out[0]!.baseScore).toBeCloseTo(5.5, 3);
      expect(out[0]!.baseVector).toBeUndefined();
    });

    it('sets vector and version without baseScore when only CVSSv3 is present', () => {
      const out = buildSnykCvss({id: 'x', title: 't', description: 'd', severity: 'low', CVSSv3: 'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', identifiers: {}, from: []});
      expect(out).toHaveLength(1);
      expect(out[0]!.version).toBe('3.0');
      expect(out[0]!.baseScore).toBeUndefined();
      expect(out[0]!.baseVector).toBe('CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H');
    });
  });

  describe('structured cwe', async () => {
    it('maps identifiers.CWE into requirement.cwe[] while keeping nist tag', async () => {
      const hdf = JSON.parse(await convertSnykToHdf(loadFixture('minimal.json'))) as HDFResults;
      const req = hdf.baselines[0]!.requirements.find(r => r.id === 'SNYK-JS-ADMZIP-1065796');
      expect(req).toBeDefined();
      expect(req!.cwe).toEqual(['CWE-22']);
      expect((req!.tags?.['nist'] as string[]).length).toBeGreaterThan(0);
    });
  });

  describe('status', async () => {
    it('should mark all vulnerabilities as failed', async () => {
      const hdf = JSON.parse(await convertSnykToHdf(loadFixture('minimal.json'))) as HDFResults;
      for (const req of hdf.baselines[0]!.requirements) {
        for (const result of req.results) {
          expect(result.status).toBe('failed');
        }
      }
    });
  });

  describe('description', async () => {
    it('should include default description with vulnerability details', async () => {
      const hdf = JSON.parse(await convertSnykToHdf(loadFixture('minimal.json'))) as HDFResults;
      const req = hdf.baselines[0]!.requirements.find(r => r.id === 'SNYK-JS-ADMZIP-1065796');
      const defaultDesc = req?.descriptions?.find(d => d.label === 'default');
      expect(defaultDesc).toBeDefined();
      expect(defaultDesc!.data).toContain('adm-zip');
    });
  });

  describe('target', async () => {
    it('should include project name as target', async () => {
      const hdf = JSON.parse(await convertSnykToHdf(loadFixture('minimal.json'))) as HDFResults;
      expect(hdf.components).toBeDefined();
      expect(hdf.components![0]!.name).toBe('goof');
    });
  });

  describe('SARIF format routing', async () => {
    function loadSarifFixture(name: string): string {
      return readFileSync(join(__dirname, '..', '..', 'sarif-to-hdf', 'fixtures', 'input', name), 'utf-8');
    }

    it('should route SARIF input to SARIF converter', async () => {
      const input = loadSarifFixture('gosec.sarif');
      const hdf = JSON.parse(await convertSnykToHdf(input)) as HDFResults;

      // SARIF converter uses tool driver name as baseline name (not "Snyk Scan")
      expect(hdf.baselines).toHaveLength(1);
      expect(hdf.baselines[0]!.name).not.toBe('Snyk Scan');
    });

    it('should not route native input to SARIF converter', async () => {
      const hdf = JSON.parse(await convertSnykToHdf(loadFixture('minimal.json'))) as HDFResults;
      expect(hdf.baselines[0]!.name).toBe('Snyk Scan');
    });
  });

  describe('full fixture smoke tests', async () => {
    it('should handle full nodejs-goof-local.json (94 unique vulns, 379 total)', async () => {
      const hdf = JSON.parse(await convertSnykToHdf(loadFixture('nodejs-goof-local.json'))) as HDFResults;
      expect(hdf.baselines[0]!.requirements).toHaveLength(94);

      // Verify deduplication: 379 total entries → 94 requirements, total results = 379
      const totalResults = hdf.baselines[0]!.requirements.reduce((sum, r) => sum + r.results.length, 0);
      expect(totalResults).toBe(379);
    });

    it('should handle full nodejs-goof-remote.json', async () => {
      const hdf = JSON.parse(await convertSnykToHdf(loadFixture('nodejs-goof-remote.json'))) as HDFResults;
      const reqs = hdf.baselines[0]!.requirements;
      expect(reqs.length).toBeGreaterThan(0);
      for (const req of reqs) {
        expect(req.id).toBeTruthy();
        expect(req.results.length).toBeGreaterThan(0);
      }
    });
  });

  describe('empty vulnerabilities', async () => {
    it('should synthesize a passed placeholder requirement from empty.json fixture', async () => {
      const hdf = JSON.parse(await convertSnykToHdf(loadFixture('empty.json'))) as HDFResults;

      expect(hdf.baselines).toHaveLength(1);
      expect(hdf.baselines[0]!.requirements).toHaveLength(1);

      const req = hdf.baselines[0]!.requirements[0]!;
      expect(req.id).toBe('snyk-no-findings');
      expect(req.results).toHaveLength(1);
      expect(req.results[0]!.status).toBe('passed');
      expect(req.results[0]!.codeDesc).toContain('Snyk');
      expect(req.results[0]!.codeDesc).toContain('scanned');
      expect(req.results[0]!.codeDesc).toContain('vulnerable components');
      expect(req.results[0]!.codeDesc).toContain('clean-project');

      expect(hdf.components?.[0]?.name).toBe('clean-project');
    });
  });

  describe('affectedPackages ecosystem mapping', () => {
    async function convertWithPm(packageManager: string | undefined) {
      const input = JSON.stringify({
        ok: false,
        packageManager,
        projectName: 'test',
        vulnerabilities: [
          {
            id: 'SNYK-1',
            title: 'test',
            description: 'd',
            severity: 'high',
            identifiers: { CVE: ['CVE-2026-1'] },
            packageName: 'foo',
            version: '1.0.0',
            from: ['root', 'foo@1.0.0'],
            fixedIn: ['1.0.1'],
          },
        ],
      });
      const out = JSON.parse(await convertSnykToHdf(input)) as HDFResults;
      return out.baselines[0]!.requirements[0]!;
    }

    it.each([
      ['npm', 'npm', 'pkg:npm/foo@1.0.0'],
      ['yarn', 'npm', 'pkg:npm/foo@1.0.0'],
      ['pip', 'pypi', 'pkg:pypi/foo@1.0.0'],
      ['pip3', 'pypi', 'pkg:pypi/foo@1.0.0'],
      ['rubygems', 'gem', 'pkg:gem/foo@1.0.0'],
      ['bundler', 'gem', 'pkg:gem/foo@1.0.0'],
      ['maven', 'maven', 'pkg:maven/foo@1.0.0'],
    ])('packageManager %s → ecosystem %s + synthesized purl', async (pm, ecosystem, purl) => {
      const req = await convertWithPm(pm);
      expect(req.affectedPackages?.[0]).toMatchObject({
        name: 'foo',
        version: '1.0.0',
        ecosystem,
        purl,
        fixedInVersion: '1.0.1',
      });
    });

    it('omits synthesized purl when ecosystem falls back to generic', async () => {
      const req = await convertWithPm('unrecognized-mgr');
      expect(req.affectedPackages?.[0]).toMatchObject({
        name: 'foo',
        version: '1.0.0',
        ecosystem: 'generic',
      });
      expect(req.affectedPackages?.[0]?.purl).toBeUndefined();
    });

    it('skips affectedPackages when name or version is missing', async () => {
      const input = JSON.stringify({
        ok: false,
        packageManager: 'npm',
        projectName: 'test',
        vulnerabilities: [
          {
            id: 'SNYK-2',
            title: 't',
            description: 'd',
            severity: 'low',
            identifiers: {},
            // packageName missing
            version: '1.0.0',
            from: [],
          },
        ],
      });
      const out = JSON.parse(await convertSnykToHdf(input)) as HDFResults;
      expect(out.baselines[0]!.requirements[0]!.affectedPackages).toBeUndefined();
    });
  });
});
