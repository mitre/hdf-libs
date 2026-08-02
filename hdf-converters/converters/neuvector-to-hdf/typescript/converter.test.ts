import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { describe, it, expect } from 'vitest';
import { convertNeuvectorToHdf } from './converter.js';
import { runConverterContractTests } from '../../../shared/typescript/converter-contract.js';
import { assertRequirementCount } from '../../../shared/typescript/anchor.js';
import { expectValidResults } from '../../../test/helpers/expectValidHdf.js';
import type { HDFResults } from '@mitre/hdf-schema';

// countDistinctNeuVectorVulns parses raw NeuVector JSON — deliberately NOT the
// converter's parser — and returns the number of vulnerabilities distinct by the
// composite ID name/package_name/package_version. The converter dedups on that
// key, so a plain array count over-counts; this mirrors the dedup independently.
function countDistinctNeuVectorVulns(input: string): number {
  const doc = JSON.parse(input) as {
    report?: {
      vulnerabilities?: Array<{ name?: string; package_name?: string; package_version?: string }>;
    };
  };
  const distinct = new Set<string>();
  for (const v of doc.report?.vulnerabilities ?? []) {
    distinct.add(`${v.name}/${v.package_name}/${v.package_version}`);
  }
  return distinct.size;
}

const __dirname = dirname(fileURLToPath(import.meta.url));
const FIXTURES_DIR = join(__dirname, '..', 'fixtures');

function loadFixture(name: string): string {
  return readFileSync(join(FIXTURES_DIR, 'input', name), 'utf-8');
}

runConverterContractTests({
  converterName: 'neuvector-to-hdf',
  convertFn: convertNeuvectorToHdf,
  minimalFixture: 'minimal.json',
});

describe('neuvector to HDF converter', async () => {
  // Ground-truth anchor (input-derived count; see shared/typescript/anchor.ts).
  // Golden parity proves Go and TS agree, not that either is correct. NeuVector
  // emits one requirement per vulnerability distinct by
  // name/package_name/package_version (it dedups on that composite ID); assert
  // that distinct count derived INDEPENDENTLY from the source, catching a silent
  // under-extraction even when both languages agree.
  it('emits one requirement per distinct vulnerability (neuvector-mitre-heimdall.json)', async () => {
    const input = loadFixture('neuvector-mitre-heimdall.json');
    const result = await convertNeuvectorToHdf(input);
    assertRequirementCount(
      result,
      countDistinctNeuVectorVulns(input),
      'neuvector-mitre-heimdall.json: one requirement per distinct name/package_name/package_version vulnerability',
    );
  });

  describe('conversion basics', async () => {
    it('should produce valid HDF from minimal fixture', async () => {
      const output = await convertNeuvectorToHdf(loadFixture('minimal.json'));
      const hdf = JSON.parse(output) as HDFResults;

      expect(hdf.timestamp).toBeTruthy();
      expect(hdf.generator?.name).toBe('neuvector-to-hdf');
      expect(hdf.generator?.version).toBe('1.0.0');
      expect(hdf.baselines).toHaveLength(1);
      // minimal.json has 8 unique vulnerability IDs (name/package_name/package_version)
      expect(hdf.baselines[0]!.requirements).toHaveLength(8);
      expectValidResults(hdf);
    });

    it('should use "NeuVector Scan" as the baseline name', async () => {
      const hdf = JSON.parse(await convertNeuvectorToHdf(loadFixture('minimal.json'))) as HDFResults;
      expect(hdf.baselines[0]!.name).toBe('NeuVector Scan');
    });

    it('should include baseline title with image info', async () => {
      const hdf = JSON.parse(await convertNeuvectorToHdf(loadFixture('minimal.json'))) as HDFResults;
      expect(hdf.baselines[0]!.title).toContain('mitre/heimdall');
      expect(hdf.baselines[0]!.title).toContain('latest');
    });

    it('should include a sha256 checksum', async () => {
      const hdf = JSON.parse(await convertNeuvectorToHdf(loadFixture('minimal.json'))) as HDFResults;
      const checksum = hdf.baselines[0]!.resultsChecksum;
      expect(checksum?.algorithm).toBe('sha256');
      expect(checksum?.value).toMatch(/^[a-f0-9]{64}$/);
    });
  });

  describe('generator and dataSource', async () => {
    it('should set generator name and version', async () => {
      const hdf = JSON.parse(await convertNeuvectorToHdf(loadFixture('minimal.json'))) as HDFResults;
      expect(hdf.generator?.name).toBe('neuvector-to-hdf');
      expect(hdf.generator?.version).toBe('1.0.0');
    });

    it('should set tool name to "NeuVector" with no format', async () => {
      const hdf = JSON.parse(await convertNeuvectorToHdf(loadFixture('minimal.json'))) as HDFResults;
      expect(hdf.tool?.name).toBe('NeuVector');
      expect(hdf.tool?.format).toBeUndefined() // serialization structures are not formats (kpvj);
    });
  });

  describe('impact from CVSS v3 score', async () => {
    it('should compute impact as score_v3 / 10', async () => {
      const hdf = JSON.parse(await convertNeuvectorToHdf(loadFixture('minimal.json'))) as HDFResults;
      // CVE-2021-36159/apk-tools/2.10.5-r1 has score_v3=9.1 -> impact=0.91
      const req = hdf.baselines[0]!.requirements.find(
        r => r.id === 'CVE-2021-36159/apk-tools/2.10.5-r1'
      );
      expect(req?.impact).toBeCloseTo(0.91, 2);
    });

    it('should handle medium-score CVSS v3', async () => {
      const hdf = JSON.parse(await convertNeuvectorToHdf(loadFixture('minimal.json'))) as HDFResults;
      // CVE-2021-36217/avahi/0.8-r0 has score_v3=6.2 -> impact=0.62
      const req = hdf.baselines[0]!.requirements.find(
        r => r.id === 'CVE-2021-36217/avahi/0.8-r0'
      );
      expect(req?.impact).toBeCloseTo(0.62, 2);
    });

    it('should fall back to CVSS v2 when v3 is 0', async () => {
      const input = JSON.stringify({
        error_message: '',
        report: {
          image_id: 'abc123',
          registry: 'https://registry.example.com',
          repository: 'test/image',
          tag: 'latest',
          digest: 'sha256:abc',
          size: 100,
          author: '',
          base_os: 'alpine:3.12',
          created_at: '2024-01-01T00:00:00Z',
          cvedb_version: '1.0',
          cvedb_create_time: '2024-01-01T00:00:00Z',
          layers: [],
          vulnerabilities: [{
            name: 'CVE-2020-0001',
            score: 7.5,
            severity: 'High',
            vectors: 'AV:N/AC:L/Au:N/C:P/I:P/A:P',
            description: 'Test vuln with only v2 score',
            file_name: '',
            package_name: 'test-pkg',
            package_version: '1.0.0',
            fixed_version: '1.0.1',
            link: 'https://example.com',
            score_v3: 0,
            vectors_v3: '',
            published_timestamp: 1700000000,
            last_modified_timestamp: 1700000000,
            feed_rating: 'High',
          }],
        },
      });
      const hdf = JSON.parse(await convertNeuvectorToHdf(input)) as HDFResults;
      const reqs = hdf.baselines[0]!.requirements;
      expect(reqs).toHaveLength(1);
      // score=7.5 / 10 = 0.75
      expect(reqs[0]!.impact).toBeCloseTo(0.75, 2);
    });
  });

  describe('CWE extraction from description', async () => {
    it('should extract CWE from description and map to NIST', async () => {
      const hdf = JSON.parse(await convertNeuvectorToHdf(loadFixture('minimal.json'))) as HDFResults;
      // CVE-2020-25613/ruby:webrick/1.4.2 has CWE-444 in description
      const req = hdf.baselines[0]!.requirements.find(
        r => r.id === 'CVE-2020-25613/ruby:webrick/1.4.2'
      );
      expect(req).toBeDefined();

      const nist = req!.tags?.['nist'] as string[];
      expect(nist).toBeDefined();
      expect(nist.length).toBeGreaterThan(0);
    });

    it('should include CWE tags when found', async () => {
      const hdf = JSON.parse(await convertNeuvectorToHdf(loadFixture('minimal.json'))) as HDFResults;
      // CVE-2018-25032/ruby:nokogiri/1.10.9 has CWE-787 in description
      const req = hdf.baselines[0]!.requirements.find(
        r => r.id === 'CVE-2018-25032/ruby:nokogiri/1.10.9'
      );
      expect(req).toBeDefined();
      expect(req!.tags?.['cwe']).toContain('CWE-787');
    });

    it('should use default remediation NIST when no CWE found', async () => {
      const hdf = JSON.parse(await convertNeuvectorToHdf(loadFixture('minimal.json'))) as HDFResults;
      // CVE-2021-36159/apk-tools/2.10.5-r1 has no CWE in description
      const req = hdf.baselines[0]!.requirements.find(
        r => r.id === 'CVE-2021-36159/apk-tools/2.10.5-r1'
      );
      expect(req).toBeDefined();

      const nist = req!.tags?.['nist'] as string[];
      expect(nist).toBeDefined();
      expect(nist).toContain('SI-2');
      expect(nist).toContain('RA-5');
    });
  });

  describe('requirement structure', async () => {
    it('should use name/package_name/package_version as ID', async () => {
      const hdf = JSON.parse(await convertNeuvectorToHdf(loadFixture('minimal.json'))) as HDFResults;
      const req = hdf.baselines[0]!.requirements.find(
        r => r.id === 'CVE-2021-36159/apk-tools/2.10.5-r1'
      );
      expect(req).toBeDefined();
      expect(req!.id).toBe('CVE-2021-36159/apk-tools/2.10.5-r1');
    });

    it('should set title with vulnerability details', async () => {
      const hdf = JSON.parse(await convertNeuvectorToHdf(loadFixture('minimal.json'))) as HDFResults;
      const req = hdf.baselines[0]!.requirements.find(
        r => r.id === 'CVE-2021-36159/apk-tools/2.10.5-r1'
      );
      expect(req).toBeDefined();
      expect(req!.title).toContain('CVE-2021-36159');
      expect(req!.title).toContain('apk-tools');
      expect(req!.title).toContain('2.10.5-r1');
    });

    it('should include default description', async () => {
      const hdf = JSON.parse(await convertNeuvectorToHdf(loadFixture('minimal.json'))) as HDFResults;
      const req = hdf.baselines[0]!.requirements.find(
        r => r.id === 'CVE-2021-36159/apk-tools/2.10.5-r1'
      );
      expect(req).toBeDefined();
      const defaultDesc = req!.descriptions?.find(d => d.label === 'default');
      expect(defaultDesc).toBeDefined();
      expect(defaultDesc!.data).toContain('libfetch');
    });
  });

  describe('status', async () => {
    it('should mark all vulnerabilities as failed', async () => {
      const hdf = JSON.parse(await convertNeuvectorToHdf(loadFixture('minimal.json'))) as HDFResults;
      for (const req of hdf.baselines[0]!.requirements) {
        for (const result of req.results) {
          expect(result.status).toBe('failed');
        }
      }
    });
  });

  describe('result message', async () => {
    it('should include upgrade info when fixed_version exists', async () => {
      const hdf = JSON.parse(await convertNeuvectorToHdf(loadFixture('minimal.json'))) as HDFResults;
      const req = hdf.baselines[0]!.requirements.find(
        r => r.id === 'CVE-2021-36159/apk-tools/2.10.5-r1'
      );
      expect(req).toBeDefined();
      const msg = req!.results[0]?.message ?? '';
      expect(msg).toContain('apk-tools');
      expect(msg).toContain('2.10.5-r1');
      expect(msg).toContain('2.10.7-r0');
    });

    it('should indicate no fixed version when unavailable', async () => {
      const hdf = JSON.parse(await convertNeuvectorToHdf(loadFixture('minimal.json'))) as HDFResults;
      const req = hdf.baselines[0]!.requirements.find(
        r => r.id === 'CVE-2023-37920/ca-certificates/2023.2.60_v7.0.306-80.0.el8_8'
      );
      expect(req).toBeDefined();
      const msg = req!.results[0]?.message ?? '';
      expect(msg).toContain('No fixed version');
    });
  });

  describe('target', async () => {
    it('should include image reference as target', async () => {
      const hdf = JSON.parse(await convertNeuvectorToHdf(loadFixture('minimal.json'))) as HDFResults;
      expect(hdf.components).toBeDefined();
      expect(hdf.components![0]!.name).toContain('mitre/heimdall');
      expect(hdf.components![0]!.type).toBe('containerImage');
    });
  });

  describe('tags', async () => {
    it('should populate nist and cci tags', async () => {
      const hdf = JSON.parse(await convertNeuvectorToHdf(loadFixture('minimal.json'))) as HDFResults;
      const req = hdf.baselines[0]!.requirements.find(
        r => r.id === 'CVE-2021-36159/apk-tools/2.10.5-r1'
      );
      expect(req).toBeDefined();

      const tags = req!.tags;
      expect((tags?.['nist'] as string[]).length).toBeGreaterThan(0);
      expect((tags?.['cci'] as string[]).length).toBeGreaterThan(0);
    });
  });

  describe('empty vulnerabilities', async () => {
    it('synthesizes a passed placeholder for empty vulnerabilities array', async () => {
      const input = JSON.stringify({
        error_message: '',
        report: {
          image_id: 'abc123',
          registry: 'https://registry.example.com',
          repository: 'test/image',
          tag: 'latest',
          digest: 'sha256:abc',
          size: 100,
          author: '',
          base_os: 'alpine:3.12',
          created_at: '2024-01-01T00:00:00Z',
          cvedb_version: '1.0',
          cvedb_create_time: '2024-01-01T00:00:00Z',
          layers: [],
          vulnerabilities: [],
        },
      });
      const hdf = JSON.parse(await convertNeuvectorToHdf(input)) as HDFResults;
      expect(hdf.baselines).toHaveLength(1);
      const reqs = hdf.baselines[0]!.requirements;
      expect(reqs).toHaveLength(1);
      expect(reqs[0]!.id).toBe('neuvector-no-findings');
      expect(reqs[0]!.results[0]!.status).toBe('passed');
      expect(reqs[0]!.results[0]!.codeDesc).toContain('NeuVector');
      expect(reqs[0]!.results[0]!.codeDesc).toContain('test/image');
    });

    it('synthesizes a passed placeholder for empty fixture', async () => {
      const hdf = JSON.parse(await convertNeuvectorToHdf(loadFixture('empty.json'))) as HDFResults;
      expect(hdf.baselines).toHaveLength(1);
      const reqs = hdf.baselines[0]!.requirements;
      expect(reqs).toHaveLength(1);
      expect(reqs[0]!.id).toBe('neuvector-no-findings');
      expect(reqs[0]!.results[0]!.status).toBe('passed');
      expect(reqs[0]!.results[0]!.codeDesc).toContain('NeuVector');
      expect(reqs[0]!.results[0]!.codeDesc).toContain('mitre/heimdall');
    });
  });

  describe('full fixture smoke tests', async () => {
    it('should handle neuvector-mitre-heimdall.json', async () => {
      const hdf = JSON.parse(await convertNeuvectorToHdf(loadFixture('neuvector-mitre-heimdall.json'))) as HDFResults;
      const reqs = hdf.baselines[0]!.requirements;
      expect(reqs.length).toBeGreaterThan(0);
      for (const req of reqs) {
        expect(req.id).toBeTruthy();
        expect(req.results.length).toBeGreaterThan(0);
      }
    });

    it('should handle neuvector-mitre-heimdall2.json', async () => {
      const hdf = JSON.parse(await convertNeuvectorToHdf(loadFixture('neuvector-mitre-heimdall2.json'))) as HDFResults;
      const reqs = hdf.baselines[0]!.requirements;
      expect(reqs.length).toBeGreaterThan(0);
      for (const req of reqs) {
        expect(req.id).toBeTruthy();
        expect(req.results.length).toBeGreaterThan(0);
      }
    });
  });
});
