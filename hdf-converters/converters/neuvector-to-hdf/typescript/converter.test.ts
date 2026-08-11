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

  describe('CODE tab / code_desc fidelity', async () => {
    it('populates requirement.code with the source vuln as indented JSON that round-trips', async () => {
      const input = loadFixture('minimal.json');
      const sourceVuln = (JSON.parse(input) as {
        report: { vulnerabilities: unknown[] };
      }).report.vulnerabilities[0];

      const hdf = JSON.parse(await convertNeuvectorToHdf(input)) as HDFResults;
      const req = hdf.baselines[0]!.requirements[0]!;
      expect(req.code).toBeTruthy();
      expect(JSON.parse(req.code!)).toEqual(sourceVuln);
    });

    it('builds a pipe-joined composite code_desc (no longer empty)', async () => {
      const hdf = JSON.parse(await convertNeuvectorToHdf(loadFixture('minimal.json'))) as HDFResults;
      const cd = hdf.baselines[0]!.requirements[0]!.results[0]!.codeDesc;
      expect(cd).toBeTruthy();
      expect(cd).toBe(
        'apk-tools@2.10.5-r1 | CVE-2021-36159 | CVSS 9.1 | libfetch before 2021-07-26, as used in apk-tools, xbps, and other products, mishandles numeric strin…',
      );
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
      expect(req?.impact).toBe(0.91);
    });

    it('should handle medium-score CVSS v3', async () => {
      const hdf = JSON.parse(await convertNeuvectorToHdf(loadFixture('minimal.json'))) as HDFResults;
      // CVE-2021-36217/avahi/0.8-r0 has score_v3=6.2 -> impact=0.62
      const req = hdf.baselines[0]!.requirements.find(
        r => r.id === 'CVE-2021-36217/avahi/0.8-r0'
      );
      expect(req?.impact).toBe(0.62);
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
      expect(reqs[0]!.impact).toBe(0.75);
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

    it('should emit CWE as a first-class field, not a tag', async () => {
      const hdf = JSON.parse(await convertNeuvectorToHdf(loadFixture('minimal.json'))) as HDFResults;
      // CVE-2018-25032/ruby:nokogiri/1.10.9 has CWE-787 in description
      const req = hdf.baselines[0]!.requirements.find(
        r => r.id === 'CVE-2018-25032/ruby:nokogiri/1.10.9'
      );
      expect(req).toBeDefined();
      expect(req!.cwe).toContain('CWE-787');
      expect(req!.tags?.['cwe']).toBeUndefined();
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

  describe('structured CVSS', async () => {
    it('emits a v3 cvss entry from vectors_v3 + score_v3', async () => {
      const hdf = JSON.parse(await convertNeuvectorToHdf(loadFixture('minimal.json'))) as HDFResults;
      const req = hdf.baselines[0]!.requirements.find(
        r => r.id === 'CVE-2021-36159/apk-tools/2.10.5-r1'
      );
      expect(req?.cvss).toHaveLength(1);
      const cv = req!.cvss![0]!;
      expect(cv.version).toBe('3.1');
      expect(cv.baseScore).toBeCloseTo(9.1, 2);
      expect(cv.baseVector).toBe('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H');
      expect(cv.baseSeverity).toBe('critical');
      expect(cv.source).toBe('NeuVector');
    });

    it('falls back to the prefix-less v2 vector forced to version 2.0', async () => {
      const hdf = JSON.parse(await convertNeuvectorToHdf(loadFixture('minimal.json'))) as HDFResults;
      // CVE-2018-25032/ruby:nokogiri has no v3 vector.
      const req = hdf.baselines[0]!.requirements.find(
        r => r.id === 'CVE-2018-25032/ruby:nokogiri/1.10.9'
      );
      expect(req?.cvss).toHaveLength(1);
      const cv = req!.cvss![0]!;
      expect(cv.version).toBe('2.0');
      expect(cv.baseScore).toBeCloseTo(5, 2);
      expect(cv.baseVector).toBe('AV:N/AC:L/Au:N/C:N/I:N/A:P');
    });

    it('omits baseScore when a vector is present but the score is zero', async () => {
      const mk = (v: Record<string, unknown>) => JSON.stringify({
        error_message: '',
        report: {
          image_id: 'a', registry: 'r', repository: 'x/y', tag: 't', digest: 'd',
          size: 1, author: '', base_os: 'alpine', created_at: '2024-01-01T00:00:00Z',
          cvedb_version: '1', cvedb_create_time: '2024-01-01T00:00:00Z', layers: [],
          vulnerabilities: [{
            name: 'CVE-2020-0002', score: 0, severity: 'High', vectors: '', description: 'x',
            file_name: '', package_name: 'p', package_version: '1.0', fixed_version: '',
            link: '', score_v3: 0, vectors_v3: '', published_timestamp: 1, last_modified_timestamp: 1,
            feed_rating: 'High', ...v,
          }],
        },
      });
      const v3 = JSON.parse(await convertNeuvectorToHdf(mk({ vectors_v3: 'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' }))) as HDFResults;
      const cv3 = v3.baselines[0]!.requirements[0]!.cvss![0]!;
      expect(cv3.version).toBe('3.0');
      expect(cv3.baseScore).toBeUndefined();
      expect(cv3.baseVector).toBeTruthy();

      const v2 = JSON.parse(await convertNeuvectorToHdf(mk({ vectors: 'AV:N/AC:L/Au:N/C:P/I:P/A:P' }))) as HDFResults;
      const cv2 = v2.baselines[0]!.requirements[0]!.cvss![0]!;
      expect(cv2.version).toBe('2.0');
      expect(cv2.baseScore).toBeUndefined();
    });

    it('omits cvss[] when the vulnerability carries no vector', async () => {
      // A vector-less vuln (score only) is present in the large heimdall fixture.
      const hdf = JSON.parse(await convertNeuvectorToHdf(loadFixture('neuvector-mitre-heimdall.json'))) as HDFResults;
      const noVector = hdf.baselines[0]!.requirements.filter(r => r.cvss === undefined);
      expect(noVector.length).toBeGreaterThan(0);
    });
  });

  describe('external references (refs[])', async () => {
    it('maps vulnerability.link to refs[0].url', async () => {
      const hdf = JSON.parse(await convertNeuvectorToHdf(loadFixture('minimal.json'))) as HDFResults;
      const req = hdf.baselines[0]!.requirements.find(
        r => r.id === 'CVE-2021-36159/apk-tools/2.10.5-r1'
      );
      expect(req?.refs).toHaveLength(1);
      expect(req!.refs![0]!.url).toBe('https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-36159');
      expect(req!.refs![0]!.ref).toBeUndefined();
      expect(req!.refs![0]!.uri).toBeUndefined();
    });

    it('omits refs[] when the vulnerability carries no link', async () => {
      const input = JSON.stringify({
        error_message: '',
        report: {
          image_id: 'a', registry: 'r', repository: 'x/y', tag: 't', digest: 'd',
          size: 1, author: '', base_os: 'alpine', created_at: '2024-01-01T00:00:00Z',
          cvedb_version: '1', cvedb_create_time: '2024-01-01T00:00:00Z', layers: [],
          vulnerabilities: [{
            name: 'CVE-2020-0002', score: 0, severity: 'High', vectors: '', description: 'x',
            file_name: '', package_name: 'p', package_version: '1.0', fixed_version: '',
            link: '', score_v3: 0, vectors_v3: '', published_timestamp: 1, last_modified_timestamp: 1,
            feed_rating: 'High',
          }],
        },
      });
      const hdf = JSON.parse(await convertNeuvectorToHdf(input)) as HDFResults;
      expect(hdf.baselines[0]!.requirements[0]!.refs).toBeUndefined();
    });
  });

  describe('CVE tag (interim)', async () => {
    it('emits cves[] as tags.cve, distinct from the composite requirement id', async () => {
      const hdf = JSON.parse(await convertNeuvectorToHdf(loadFixture('minimal.json'))) as HDFResults;
      const req = hdf.baselines[0]!.requirements.find(
        r => r.id === 'CVE-2021-36159/apk-tools/2.10.5-r1'
      );
      expect(req).toBeDefined();
      expect(req!.id).not.toBe('CVE-2021-36159');
      expect(req!.tags?.['cve']).toEqual(['CVE-2021-36159']);
    });

    it('dedupes and drops empty entries in cves[]', async () => {
      const input = JSON.stringify({
        error_message: '',
        report: {
          image_id: 'a', registry: 'r', repository: 'x/y', tag: 't', digest: 'd',
          size: 1, author: '', base_os: 'alpine', created_at: '2024-01-01T00:00:00Z',
          cvedb_version: '1', cvedb_create_time: '2024-01-01T00:00:00Z', layers: [],
          vulnerabilities: [{
            name: 'CVE-2020-0003', score: 5, severity: 'High', vectors: '', description: 'x',
            file_name: '', package_name: 'p', package_version: '1.0', fixed_version: '',
            link: '', score_v3: 0, vectors_v3: '', published_timestamp: 1, last_modified_timestamp: 1,
            feed_rating: 'High', cves: ['CVE-2020-0003', '', 'CVE-2020-0003', 'CVE-2020-9999'],
          }],
        },
      });
      const hdf = JSON.parse(await convertNeuvectorToHdf(input)) as HDFResults;
      expect(hdf.baselines[0]!.requirements[0]!.tags?.['cve']).toEqual(['CVE-2020-0003', 'CVE-2020-9999']);
    });

    it('omits tags.cve when the vulnerability has no cves', async () => {
      const input = JSON.stringify({
        error_message: '',
        report: {
          image_id: 'a', registry: 'r', repository: 'x/y', tag: 't', digest: 'd',
          size: 1, author: '', base_os: 'alpine', created_at: '2024-01-01T00:00:00Z',
          cvedb_version: '1', cvedb_create_time: '2024-01-01T00:00:00Z', layers: [],
          vulnerabilities: [{
            name: 'GHSA-xxxx', score: 5, severity: 'High', vectors: '', description: 'x',
            file_name: '', package_name: 'p', package_version: '1.0', fixed_version: '',
            link: '', score_v3: 0, vectors_v3: '', published_timestamp: 1, last_modified_timestamp: 1,
            feed_rating: 'High',
          }],
        },
      });
      const hdf = JSON.parse(await convertNeuvectorToHdf(input)) as HDFResults;
      expect(hdf.baselines[0]!.requirements[0]!.tags?.['cve']).toBeUndefined();
    });
  });

  describe('feed_rating tag', async () => {
    it('maps vulnerability.feed_rating to tags.feed_rating as a string', async () => {
      const hdf = JSON.parse(await convertNeuvectorToHdf(loadFixture('minimal.json'))) as HDFResults;
      const req = hdf.baselines[0]!.requirements.find(
        r => r.id === 'CVE-2021-36159/apk-tools/2.10.5-r1'
      );
      expect(req!.tags?.['feed_rating']).toBe('Critical');

      const medium = hdf.baselines[0]!.requirements.find(
        r => r.id === 'CVE-2021-36217/avahi/0.8-r0'
      );
      expect(medium!.tags?.['feed_rating']).toBe('Medium');
    });

    it('omits tags.feed_rating when the vulnerability carries no feed_rating', async () => {
      const input = JSON.stringify({
        error_message: '',
        report: {
          image_id: 'a', registry: 'r', repository: 'x/y', tag: 't', digest: 'd',
          size: 1, author: '', base_os: 'alpine', created_at: '2024-01-01T00:00:00Z',
          cvedb_version: '1', cvedb_create_time: '2024-01-01T00:00:00Z', layers: [],
          vulnerabilities: [{
            name: 'CVE-2020-0001', score: 5, severity: 'High', vectors: '', description: 'x',
            file_name: '', package_name: 'pkg', package_version: '1.0', fixed_version: '',
            link: '', score_v3: 0, vectors_v3: '', published_timestamp: 1, last_modified_timestamp: 1,
          }],
        },
      });
      const hdf = JSON.parse(await convertNeuvectorToHdf(input)) as HDFResults;
      expect(hdf.baselines[0]!.requirements[0]!.tags?.['feed_rating']).toBeUndefined();
    });
  });

  describe('severity / status / source / timestamp tags (h2 parity)', async () => {
    it('maps severity and the epoch published/last_modified timestamps to tags', async () => {
      const hdf = JSON.parse(await convertNeuvectorToHdf(loadFixture('minimal.json'))) as HDFResults;
      const req = hdf.baselines[0]!.requirements.find(
        r => r.id === 'CVE-2021-36159/apk-tools/2.10.5-r1'
      );
      expect(req!.tags?.['severity']).toBe('Critical');
      expect(req!.tags?.['published_timestamp']).toBe(1699328203);
      expect(req!.tags?.['last_modified_timestamp']).toBe(1699328203);
      // minimal.json has no report.modules or report.cmds.
      expect(req!.tags?.['status']).toBeUndefined();
      expect(req!.tags?.['source']).toBeUndefined();
    });

    it('recovers status and source by cross-referencing report.modules', async () => {
      const hdf = JSON.parse(await convertNeuvectorToHdf(loadFixture('neuvector-mitre-heimdall2.json'))) as HDFResults;
      const req = hdf.baselines[0]!.requirements.find(
        r => r.id === 'CVE-2019-12904/libgcrypt/1.8.5-7.el8_6'
      );
      expect(req).toBeDefined();
      expect(req!.tags?.['status']).toBe('unpatched');
      expect(req!.tags?.['source']).toBe('rhel:8.10');
      expect(req!.tags?.['severity']).toBe('Medium');
    });

    it('omits the new tags when the source carries none of them', async () => {
      const input = JSON.stringify({
        report: {
          registry: 'reg', repository: 'repo', tag: 'latest',
          vulnerabilities: [
            { name: 'CVE-2020-0001', description: 'x', package_name: 'pkg', package_version: '1.0' },
          ],
        },
      });
      const hdf = JSON.parse(await convertNeuvectorToHdf(input)) as HDFResults;
      const tags = hdf.baselines[0]!.requirements[0]!.tags ?? {};
      for (const k of ['severity', 'status', 'source', 'published_timestamp', 'last_modified_timestamp']) {
        expect(tags[k]).toBeUndefined();
      }
    });
  });

  describe('report.cmds → baseline.extensions.neuvector (scan-scope metadata)', async () => {
    it('emits report.cmds once on baseline.extensions and never on requirement tags', async () => {
      const hdf = JSON.parse(await convertNeuvectorToHdf(loadFixture('neuvector-mitre-heimdall2.json'))) as HDFResults;
      const baseline = hdf.baselines[0]!;
      const ext = baseline.extensions?.['neuvector'] as { cmds?: string[] } | undefined;
      expect(ext).toBeDefined();
      expect(ext!.cmds).toHaveLength(66);
      expect(ext!.cmds![0]).toBe('CMD ["/usr/local/bin/cmd.sh"]');
      // cmds must NOT be duplicated onto any requirement's tags.
      for (const req of baseline.requirements) {
        expect(req.tags?.['cmds']).toBeUndefined();
      }
    });

    it('omits baseline.extensions entirely when report.cmds is absent', async () => {
      const hdf = JSON.parse(await convertNeuvectorToHdf(loadFixture('minimal.json'))) as HDFResults;
      const baseline = hdf.baselines[0]!;
      expect(baseline.extensions).toBeUndefined();
      for (const req of baseline.requirements) {
        expect(req.tags?.['cmds']).toBeUndefined();
      }
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

  describe('scan-target component identity', async () => {
    it('enriches the containerImage component from image identity', async () => {
      const hdf = JSON.parse(await convertNeuvectorToHdf(loadFixture('neuvector-mitre-heimdall.json'))) as HDFResults;
      expect(hdf.components).toHaveLength(1);
      const comp = hdf.components![0]!;
      expect(comp.type).toBe('containerImage');
      expect(comp.name).toBe('https://registry.hub.docker.com/mitre/heimdall:latest');
      // base_os "alpine:3.12.1" → osName/osVersion
      expect(comp.osName).toBe('alpine');
      expect(comp.osVersion).toBe('3.12.1');
      expect(comp.imageId).toBe('65785cbf46647c77caf8d7c40485900b013fca1290d1a7ab06c9039c3b29761c');
      expect(comp.registry).toBe('https://registry.hub.docker.com');
      expect(comp.repository).toBe('mitre/heimdall');
      expect(comp.tag).toBe('latest');
      // digest "sha256:54cb..." → integrity{sha256, hex without prefix}
      expect(comp.integrity).toEqual([
        { algorithm: 'sha256', value: '54cbfb34a9a8fe00c9a60d722aa1c12f25bec825c505139cfffaeabc91fb10e6' },
      ]);
    });

    it('splits a different base_os (rhel:8.10)', async () => {
      const hdf = JSON.parse(await convertNeuvectorToHdf(loadFixture('neuvector-mitre-heimdall2.json'))) as HDFResults;
      const comp = hdf.components![0]!;
      expect(comp.osName).toBe('rhel');
      expect(comp.osVersion).toBe('8.10');
    });

    it('omits osName/osVersion/imageId/integrity when the report carries none', async () => {
      const input = JSON.stringify({
        report: {
          registry: 'reg',
          repository: 'repo',
          tag: 'latest',
          vulnerabilities: [
            { name: 'CVE-2020-0001', package_name: 'pkg', package_version: '1.0', description: '' },
          ],
        },
      });
      const hdf = JSON.parse(await convertNeuvectorToHdf(input)) as HDFResults;
      expect(hdf.components).toHaveLength(1);
      const comp = hdf.components![0]!;
      expect(comp.type).toBe('containerImage');
      expect(comp.osName).toBeUndefined();
      expect(comp.osVersion).toBeUndefined();
      expect(comp.imageId).toBeUndefined();
      expect(comp.integrity).toBeUndefined();
      expect(comp.registry).toBe('reg');
    });

    it('folds a non-sha256 digest prefix into the algorithm', async () => {
      const input = JSON.stringify({
        report: {
          registry: 'reg',
          repository: 'repo',
          tag: 'latest',
          base_os: 'scratch',
          digest: 'sha512:deadbeef',
          vulnerabilities: [],
        },
      });
      const hdf = JSON.parse(await convertNeuvectorToHdf(input)) as HDFResults;
      const comp = hdf.components![0]!;
      // base_os with no ":" → osName only, no osVersion
      expect(comp.osName).toBe('scratch');
      expect(comp.osVersion).toBeUndefined();
      expect(comp.integrity).toEqual([{ algorithm: 'sha512', value: 'deadbeef' }]);
    });
  });
});
