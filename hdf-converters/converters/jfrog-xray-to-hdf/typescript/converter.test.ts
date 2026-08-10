import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { describe, it, expect } from 'vitest';
import { convertJfrogXrayToHdf } from './converter.js';
import { runConverterContractTests } from '../../../shared/typescript/converter-contract.js';
import { expectValidResults } from '../../../test/helpers/expectValidHdf.js';
import { assertRequirementCount } from '../../../shared/typescript/anchor.js';
import type { HDFResults } from '@mitre/hdf-schema';

const __dirname = dirname(fileURLToPath(import.meta.url));
const FIXTURES_DIR = join(__dirname, '..', 'fixtures');

function loadFixture(name: string): string {
  return readFileSync(join(FIXTURES_DIR, 'input', name), 'utf-8');
}

// Derive the ground-truth requirement count directly from the raw JSON,
// independent of the converter: JFrog Xray groups data[] entries by their
// effective ID (the entry's id, or its summary when id is empty) and emits one
// requirement per group. A plain data[] count would over-count merged
// duplicates, so the grouping is re-derived here.
function countDistinctEntryIds(input: string): number {
  const doc = JSON.parse(input) as {
    data?: Array<{ id?: string; summary?: string }>;
  };
  const seen = new Set<string>();
  for (const e of doc.data ?? []) {
    seen.add(e.id && e.id !== '' ? e.id : `summary:${e.summary ?? ''}`);
  }
  return seen.size;
}

runConverterContractTests({
  converterName: 'jfrog-xray-to-hdf',
  convertFn: convertJfrogXrayToHdf,
  minimalFixture: 'jfrog_xray_sample.json',
});

// Ground-truth anchor: one requirement per distinct effective entry ID.
describe('jfrog-xray-to-hdf ground-truth anchor', () => {
  it('emits one requirement per distinct data[] entry ID', async () => {
    const input = loadFixture('jfrog_xray_sample.json');
    assertRequirementCount(
      await convertJfrogXrayToHdf(input),
      countDistinctEntryIds(input),
      'jfrog_xray_sample.json: one requirement per distinct data[] entry ID',
    );
  });
});

describe('jfrog-xray to HDF converter', async () => {
  describe('conversion basics', async () => {
    it('should produce valid HDF from fixture', async () => {
      const output = await convertJfrogXrayToHdf(loadFixture('jfrog_xray_sample.json'));
      const hdf = JSON.parse(output) as HDFResults;

      expectValidResults(hdf);
      expect(hdf.timestamp).toBeTruthy();
      expect(hdf.generator?.name).toBe('jfrog-xray-to-hdf');
      expect(hdf.generator?.version).toBe('1.0.0');
      expect(hdf.baselines).toHaveLength(1);
    });

    it('should use "JFrog Xray Scan" as the baseline name', async () => {
      const hdf = JSON.parse(await convertJfrogXrayToHdf(loadFixture('jfrog_xray_sample.json'))) as HDFResults;
      expect(hdf.baselines[0]!.name).toBe('JFrog Xray Scan');
    });

    it('should produce 17 unique requirements from 30 entries', async () => {
      const hdf = JSON.parse(await convertJfrogXrayToHdf(loadFixture('jfrog_xray_sample.json'))) as HDFResults;
      expect(hdf.baselines[0]!.requirements).toHaveLength(17);
    });

    it('should include a sha256 checksum', async () => {
      const hdf = JSON.parse(await convertJfrogXrayToHdf(loadFixture('jfrog_xray_sample.json'))) as HDFResults;
      const checksum = hdf.baselines[0]!.resultsChecksum;
      expect(checksum?.algorithm).toBe('sha256');
      expect(checksum?.value).toMatch(/^[a-f0-9]{64}$/);
    });
  });

  describe('CODE tab: requirement.code', async () => {
    it('populates requirement.code with the serialized entry JSON', async () => {
      const hdf = JSON.parse(await convertJfrogXrayToHdf(loadFixture('jfrog_xray_sample.json'))) as HDFResults;
      const acorn = hdf.baselines[0]!.requirements.find((r) => r.title?.includes('Acorn regexp.js'));
      expect(acorn).toBeDefined();
      expect(acorn!.code).toBeDefined();

      // Indented (2-space) serialization of the source entry object.
      expect(acorn!.code!.startsWith('{\n  "')).toBe(true);

      const decoded = JSON.parse(acorn!.code!) as {
        source_comp_id: string;
        severity: string;
        component_versions: {
          fixed_versions: string[];
          more_details: { cves: Array<{ cvss_v3?: string }> };
        };
      };
      expect(decoded.source_comp_id).toBe('npm://acorn:5.7.3');
      expect(decoded.severity).toBe('High');
      expect(decoded.component_versions.fixed_versions).toEqual(['5.7.4', '6.4.1', '7.1.1']);
      expect(decoded.component_versions.more_details.cves[0]!.cvss_v3).toBe(
        '7.5/CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H',
      );
    });
  });

  describe('generator and dataSource', async () => {
    it('should set generator name and version', async () => {
      const hdf = JSON.parse(await convertJfrogXrayToHdf(loadFixture('jfrog_xray_sample.json'))) as HDFResults;
      expect(hdf.generator?.name).toBe('jfrog-xray-to-hdf');
      expect(hdf.generator?.version).toBe('1.0.0');
    });

    it('should set tool name to "JFrog Xray" with no format', async () => {
      const hdf = JSON.parse(await convertJfrogXrayToHdf(loadFixture('jfrog_xray_sample.json'))) as HDFResults;
      expect(hdf.tool?.name).toBe('JFrog Xray');
      expect(hdf.tool?.format).toBeUndefined() // serialization structures are not formats (kpvj);
    });
  });

  describe('target', async () => {
    it('should include target with Application type', async () => {
      const hdf = JSON.parse(await convertJfrogXrayToHdf(loadFixture('jfrog_xray_sample.json'))) as HDFResults;
      expect(hdf.components).toBeDefined();
      expect(hdf.components![0]!.name).toBe('JFrog Xray Scan');
      expect(hdf.components![0]!.type).toBe('application');
    });
  });

  describe('severity to impact mapping', async () => {
    it('should map high severity to 0.7', async () => {
      const hdf = JSON.parse(await convertJfrogXrayToHdf(loadFixture('jfrog_xray_sample.json'))) as HDFResults;
      const reqs = hdf.baselines[0]!.requirements;
      const hasHigh = reqs.some(r => r.impact === 0.7);
      expect(hasHigh).toBe(true);
    });

    it('should map medium severity to 0.5', async () => {
      const hdf = JSON.parse(await convertJfrogXrayToHdf(loadFixture('jfrog_xray_sample.json'))) as HDFResults;
      const reqs = hdf.baselines[0]!.requirements;
      const hasMedium = reqs.some(r => r.impact === 0.5);
      expect(hasMedium).toBe(true);
    });

    it('should map low severity to 0.3', async () => {
      const hdf = JSON.parse(await convertJfrogXrayToHdf(loadFixture('jfrog_xray_sample.json'))) as HDFResults;
      const reqs = hdf.baselines[0]!.requirements;
      const hasLow = reqs.some(r => r.impact === 0.3);
      expect(hasLow).toBe(true);
    });
  });

  describe('ID generation', async () => {
    it('should generate non-empty IDs for all requirements', async () => {
      const hdf = JSON.parse(await convertJfrogXrayToHdf(loadFixture('jfrog_xray_sample.json'))) as HDFResults;
      for (const req of hdf.baselines[0]!.requirements) {
        expect(req.id).toBeTruthy();
      }
    });
  });

  describe('deduplication', async () => {
    it('should produce 27 total results across 17 requirements', async () => {
      const hdf = JSON.parse(await convertJfrogXrayToHdf(loadFixture('jfrog_xray_sample.json'))) as HDFResults;
      const totalResults = hdf.baselines[0]!.requirements.reduce((sum, r) => sum + r.results.length, 0);
      expect(totalResults).toBe(27);
    });

    it('should group duplicate entries into multiple results', async () => {
      const hdf = JSON.parse(await convertJfrogXrayToHdf(loadFixture('jfrog_xray_sample.json'))) as HDFResults;
      const hasMultipleResults = hdf.baselines[0]!.requirements.some(r => r.results.length > 1);
      expect(hasMultipleResults).toBe(true);
    });
  });

  describe('status', async () => {
    it('should mark all results as failed', async () => {
      const hdf = JSON.parse(await convertJfrogXrayToHdf(loadFixture('jfrog_xray_sample.json'))) as HDFResults;
      for (const req of hdf.baselines[0]!.requirements) {
        for (const result of req.results) {
          expect(result.status).toBe('failed');
        }
      }
    });
  });

  describe('description', async () => {
    it('should include default description for each requirement', async () => {
      const hdf = JSON.parse(await convertJfrogXrayToHdf(loadFixture('jfrog_xray_sample.json'))) as HDFResults;
      for (const req of hdf.baselines[0]!.requirements) {
        const defaultDesc = req.descriptions?.find(d => d.label === 'default');
        expect(defaultDesc).toBeDefined();
        expect(defaultDesc!.data.length).toBeGreaterThan(0);
      }
    });
  });

  describe('code description', async () => {
    it('should include non-empty codeDesc for each result', async () => {
      const hdf = JSON.parse(await convertJfrogXrayToHdf(loadFixture('jfrog_xray_sample.json'))) as HDFResults;
      for (const req of hdf.baselines[0]!.requirements) {
        for (const result of req.results) {
          expect(result.codeDesc).toBeTruthy();
        }
      }
    });
  });

  describe('CWE to NIST mapping', async () => {
    it('should include nist tags on all requirements', async () => {
      const hdf = JSON.parse(await convertJfrogXrayToHdf(loadFixture('jfrog_xray_sample.json'))) as HDFResults;
      for (const req of hdf.baselines[0]!.requirements) {
        const nist = req.tags?.['nist'] as string[];
        expect(nist).toBeDefined();
        expect(nist.length).toBeGreaterThan(0);
      }
    });

    it('should populate first-class cwe[] and drop the cweid tag', async () => {
      const hdf = JSON.parse(await convertJfrogXrayToHdf(loadFixture('jfrog_xray_sample.json'))) as HDFResults;
      const reqs = hdf.baselines[0]!.requirements;
      for (const r of reqs) {
        expect(r.tags?.['cweid']).toBeUndefined();
      }
      const hasCWE = reqs.some(r => (r.cwe?.length ?? 0) > 0);
      expect(hasCWE).toBe(true);
    });
  });

  describe('structured CVSS / CWE / CVE scoring', async () => {
    function findByTitle(reqs: HDFResults['baselines'][0]['requirements'], substr: string) {
      return reqs.find(r => (r.title ?? '').includes(substr));
    }

    it('maps cvss_v3 then cvss_v2 into requirement.cvss[] with source, severity, and vector', async () => {
      const hdf = JSON.parse(await convertJfrogXrayToHdf(loadFixture('jfrog_xray_sample.json'))) as HDFResults;
      const req = findByTitle(hdf.baselines[0]!.requirements, 'prior to 4.3.0 are vulnerable to Prototype Pollution');
      expect(req).toBeDefined();
      expect(req!.cvss).toHaveLength(2);

      const [v3, v2] = req!.cvss!;
      expect(v3!.version).toBe('3.1');
      expect(v3!.baseScore).toBeCloseTo(9.8, 5);
      expect(v3!.baseVector).toBe('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H');
      expect(v3!.baseSeverity).toBe('critical');
      expect(v3!.source).toBe('CVE-2019-19919');

      expect(v2!.version).toBe('2.0');
      expect(v2!.baseScore).toBeCloseTo(7.5, 5);
      expect(v2!.baseVector).toBe('CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P');
      expect(v2!.baseSeverity).toBe('high');

      expect(req!.cwe).toEqual(['CWE-74']);
      expect(req!.tags?.['cve']).toEqual(['CVE-2019-19919']);
      expect((req!.tags?.['nist'] as string[]).length).toBeGreaterThan(0);
    });

    it('derives the v2 version from the field, not the (prefix-less) vector', async () => {
      const hdf = JSON.parse(await convertJfrogXrayToHdf(loadFixture('jfrog_xray_sample.json'))) as HDFResults;
      const acorn = findByTitle(hdf.baselines[0]!.requirements, 'Acorn regexp.js');
      expect(acorn).toBeDefined();
      expect(acorn!.cvss).toHaveLength(2);
      expect(acorn!.cvss![0]!.version).toBe('3.0');
      expect(acorn!.cvss![0]!.baseVector).toBe('CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H');
      expect(acorn!.cvss![1]!.version).toBe('2.0');
      expect(acorn!.cvss![1]!.baseVector).toBe('AV:N/AC:M/Au:N/C:N/I:N/A:C');
      // No CVE → no source and no tags.cve; no CWE → no cwe[].
      expect(acorn!.cvss![0]!.source).toBeUndefined();
      expect(acorn!.cwe).toBeUndefined();
      expect(acorn!.tags?.['cve']).toBeUndefined();
    });

    it('emits only the v2 metric when cvss_v3 is absent', async () => {
      const hdf = JSON.parse(await convertJfrogXrayToHdf(loadFixture('jfrog_xray_sample.json'))) as HDFResults;
      const req = findByTitle(hdf.baselines[0]!.requirements, 'node-handlebars Template Handling');
      expect(req).toBeDefined();
      expect(req!.cvss).toHaveLength(1);
      expect(req!.cvss![0]!.version).toBe('2.0');
      expect(req!.cvss![0]!.baseScore).toBeCloseTo(10.0, 5);
      expect(req!.cvss![0]!.baseSeverity).toBe('critical');
    });

    it('omits cvss[]/cwe[]/tags.cve when the finding has no cves', async () => {
      const hdf = JSON.parse(await convertJfrogXrayToHdf(loadFixture('jfrog_xray_sample.json'))) as HDFResults;
      const req = findByTitle(hdf.baselines[0]!.requirements, 'baseZipObject');
      expect(req).toBeDefined();
      expect(req!.cvss).toBeUndefined();
      expect(req!.cwe).toBeUndefined();
      expect(req!.tags?.['cve']).toBeUndefined();
    });

    it('keeps a vector-only v3 metric and skips an absent v2 (synthetic input)', async () => {
      const synthetic = JSON.stringify({
        data: [{
          id: 'x', severity: 'High', summary: 'synthetic vector-only',
          component_versions: { more_details: { cves: [{
            cve: 'CVE-9999-0001',
            cvss_v3: 'bad/CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
          }] } },
        }],
      });
      const hdf = JSON.parse(await convertJfrogXrayToHdf(synthetic)) as HDFResults;
      const req = hdf.baselines[0]!.requirements[0]!;
      expect(req.cvss).toHaveLength(1);
      expect(req.cvss![0]!.version).toBe('3.1');
      expect(req.cvss![0]!.baseScore).toBeUndefined();
      expect(req.cvss![0]!.baseVector).toBe('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H');
      expect(req.tags?.['cve']).toEqual(['CVE-9999-0001']);
    });
  });

  describe('title', async () => {
    it('should include summary as title for each requirement', async () => {
      const hdf = JSON.parse(await convertJfrogXrayToHdf(loadFixture('jfrog_xray_sample.json'))) as HDFResults;
      for (const req of hdf.baselines[0]!.requirements) {
        expect(req.title).toBeTruthy();
      }
    });
  });

  describe('empty data', async () => {
    it('should synthesize a passed placeholder when no findings are reported', async () => {
      const hdf = JSON.parse(await convertJfrogXrayToHdf(loadFixture('empty.json'))) as HDFResults;
      expect(hdf.baselines).toHaveLength(1);

      const reqs = hdf.baselines[0]!.requirements;
      expect(reqs).toHaveLength(1);

      const req = reqs[0]!;
      expect(req.id).toBe('jfrog-xray-no-findings');
      expect(req.results).toHaveLength(1);
      expect(req.results[0]!.status).toBe('passed');
      expect(req.results[0]!.codeDesc).toContain('JFrog Xray');
      expect(req.results[0]!.codeDesc).toContain('zero vulnerable components');
    });
  });
});
