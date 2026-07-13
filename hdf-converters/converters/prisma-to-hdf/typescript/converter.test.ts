import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { describe, it, expect } from 'vitest';
import { convertPrismaToHdf } from './converter.js';
import { expectValidResults } from '../../../test/helpers/expectValidHdf.js';
import type { HDFResults, EvaluatedBaseline, EvaluatedRequirement } from '@mitre/hdf-schema';

const __dirname = dirname(fileURLToPath(import.meta.url));
const FIXTURES_DIR = join(__dirname, '..', 'fixtures');

function loadFixture(name: string): string {
  return readFileSync(join(FIXTURES_DIR, 'input', name), 'utf-8');
}

function findBaseline(baselines: EvaluatedBaseline[], titleSubstring: string): EvaluatedBaseline | undefined {
  return baselines.find(b => b.title?.includes(titleSubstring));
}

function findRequirement(reqs: EvaluatedRequirement[], id: string): EvaluatedRequirement | undefined {
  return reqs.find(r => r.id === id);
}

describe('prisma to HDF converter', () => {
  describe('input validation', () => {
    it('should throw on empty input', async () => {
      await expect(convertPrismaToHdf('')).rejects.toThrow();
    });

    it('should throw on invalid CSV (missing required columns)', async () => {
      await expect(convertPrismaToHdf('a,b,c\n1,2,3')).rejects.toThrow();
    });
  });

  describe('schema validity', () => {
    it('should produce schema-valid HDF results', async () => {
      const hdf = JSON.parse(await convertPrismaToHdf(loadFixture('minimal.csv'))) as HDFResults;
      expectValidResults(hdf);
    });
  });

  describe('multi-host grouping', () => {
    it('should produce one baseline per hostname', async () => {
      const output = await convertPrismaToHdf(loadFixture('minimal.csv'));
      const hdf = JSON.parse(output) as HDFResults;
      // minimal.csv has 2 hosts
      expect(hdf.baselines).toHaveLength(2);
    });

    it('should use "Prisma Cloud Scan" as the baseline name', async () => {
      const hdf = JSON.parse(await convertPrismaToHdf(loadFixture('minimal.csv'))) as HDFResults;
      for (const baseline of hdf.baselines) {
        expect(baseline.name).toBe('Prisma Cloud Scan');
      }
    });

    it('should include hostname in baseline title', async () => {
      const hdf = JSON.parse(await convertPrismaToHdf(loadFixture('minimal.csv'))) as HDFResults;
      const titles = hdf.baselines.map(b => b.title).sort();
      expect(titles[0]).toBe('Prisma Cloud Scan (host-1.example.com)');
      expect(titles[1]).toBe('Prisma Cloud Scan (host-2.example.com)');
    });
  });

  describe('checksum', () => {
    it('should include sha256 checksum on each baseline', async () => {
      const hdf = JSON.parse(await convertPrismaToHdf(loadFixture('minimal.csv'))) as HDFResults;
      for (const baseline of hdf.baselines) {
        expect(baseline.resultsChecksum?.algorithm).toBe('sha256');
        expect(baseline.resultsChecksum?.value).toMatch(/^[a-f0-9]{64}$/);
      }
    });
  });

  describe('generator and dataSource', () => {
    it('should set generator name and version', async () => {
      const hdf = JSON.parse(await convertPrismaToHdf(loadFixture('minimal.csv'))) as HDFResults;
      expect(hdf.generator?.name).toBe('prisma-to-hdf');
      expect(hdf.generator?.version).toBe('1.0.0');
    });

    it('should set tool to Prisma Cloud / CSV', async () => {
      const hdf = JSON.parse(await convertPrismaToHdf(loadFixture('minimal.csv'))) as HDFResults;
      expect(hdf.tool?.name).toBe('Prisma Cloud');
      expect(hdf.tool?.format).toBe('CSV');
    });
  });

  describe('targets', () => {
    it('should produce one target per hostname with Host type', async () => {
      const hdf = JSON.parse(await convertPrismaToHdf(loadFixture('minimal.csv'))) as HDFResults;
      expect(hdf.components).toHaveLength(2);
      const names = hdf.components!.map(t => t.name).sort();
      expect(names[0]).toBe('host-1.example.com');
      expect(names[1]).toBe('host-2.example.com');
      for (const target of hdf.components!) {
        expect(target.type).toBe('host');
      }
    });
  });

  describe('requirement IDs', () => {
    it('should format CVE requirement IDs as ComplianceID-CVEID', async () => {
      const hdf = JSON.parse(await convertPrismaToHdf(loadFixture('minimal.csv'))) as HDFResults;
      const host1 = findBaseline(hdf.baselines, 'host-1.example.com');
      expect(host1).toBeDefined();
      const req = findRequirement(host1!.requirements, '46-CVE-2021-44142');
      expect(req).toBeDefined();
    });

    it('should format non-CVE requirement IDs as ComplianceID-Distro-Severity', async () => {
      const hdf = JSON.parse(await convertPrismaToHdf(loadFixture('minimal.csv'))) as HDFResults;
      const host1 = findBaseline(hdf.baselines, 'host-1.example.com');
      expect(host1).toBeDefined();
      const req = findRequirement(host1!.requirements, '60522-redhat-RHEL7-high');
      expect(req).toBeDefined();
    });

    it('should produce correct number of requirements per host', async () => {
      const hdf = JSON.parse(await convertPrismaToHdf(loadFixture('minimal.csv'))) as HDFResults;
      const host1 = findBaseline(hdf.baselines, 'host-1.example.com');
      expect(host1).toBeDefined();
      // host-1: 3 records → 3 requirements
      expect(host1!.requirements).toHaveLength(3);
    });
  });

  describe('severity to impact mapping', () => {
    it('should map critical severity to 0.9', async () => {
      const hdf = JSON.parse(await convertPrismaToHdf(loadFixture('minimal.csv'))) as HDFResults;
      const host1 = findBaseline(hdf.baselines, 'host-1.example.com');
      const req = findRequirement(host1!.requirements, '46-CVE-2021-44142');
      expect(req?.impact).toBe(0.9);
    });

    it('should map low severity to 0.3', async () => {
      const hdf = JSON.parse(await convertPrismaToHdf(loadFixture('minimal.csv'))) as HDFResults;
      const host1 = findBaseline(hdf.baselines, 'host-1.example.com');
      const req = findRequirement(host1!.requirements, '46-CVE-2016-2226');
      expect(req?.impact).toBe(0.3);
    });

    it('should map high severity to 0.7', async () => {
      const hdf = JSON.parse(await convertPrismaToHdf(loadFixture('minimal.csv'))) as HDFResults;
      const host1 = findBaseline(hdf.baselines, 'host-1.example.com');
      const req = findRequirement(host1!.requirements, '60522-redhat-RHEL7-high');
      expect(req?.impact).toBe(0.7);
    });
  });

  describe('NIST tags', () => {
    it('should assign remediation NIST tags for CVE findings', async () => {
      const hdf = JSON.parse(await convertPrismaToHdf(loadFixture('minimal.csv'))) as HDFResults;
      const host1 = findBaseline(hdf.baselines, 'host-1.example.com');
      const req = findRequirement(host1!.requirements, '46-CVE-2021-44142');
      const nist = req?.tags?.['nist'] as string[];
      expect(nist).toBeDefined();
      expect(nist).toContain('SI-2');
      expect(nist).toContain('RA-5');
    });

    it('should assign static analysis NIST tags for non-CVE findings', async () => {
      const hdf = JSON.parse(await convertPrismaToHdf(loadFixture('minimal.csv'))) as HDFResults;
      const host1 = findBaseline(hdf.baselines, 'host-1.example.com');
      const req = findRequirement(host1!.requirements, '60522-redhat-RHEL7-high');
      const nist = req?.tags?.['nist'] as string[];
      expect(nist).toBeDefined();
      expect(nist).toContain('SA-11');
      expect(nist).toContain('RA-5');
    });
  });

  describe('status', () => {
    it('should mark all findings as failed', async () => {
      const hdf = JSON.parse(await convertPrismaToHdf(loadFixture('minimal.csv'))) as HDFResults;
      for (const baseline of hdf.baselines) {
        for (const req of baseline.requirements) {
          for (const result of req.results) {
            expect(result.status).toBe('failed');
          }
        }
      }
    });
  });

  describe('code description', () => {
    it('should include package name for image type findings', async () => {
      const hdf = JSON.parse(await convertPrismaToHdf(loadFixture('minimal.csv'))) as HDFResults;
      const host1 = findBaseline(hdf.baselines, 'host-1.example.com');
      const req = findRequirement(host1!.requirements, '46-CVE-2021-44142');
      expect(req!.results[0]?.codeDesc).toContain('samba-common');
    });

    it('should include configuration check info for linux type findings', async () => {
      const hdf = JSON.parse(await convertPrismaToHdf(loadFixture('minimal.csv'))) as HDFResults;
      const host1 = findBaseline(hdf.baselines, 'host-1.example.com');
      const req = findRequirement(host1!.requirements, '60522-redhat-RHEL7-high');
      expect(req!.results[0]?.codeDesc).toContain('Configuration check');
    });
  });

  describe('descriptions', () => {
    it('should include default description with finding details', async () => {
      const hdf = JSON.parse(await convertPrismaToHdf(loadFixture('minimal.csv'))) as HDFResults;
      const host1 = findBaseline(hdf.baselines, 'host-1.example.com');
      const req = findRequirement(host1!.requirements, '46-CVE-2021-44142');
      const desc = req?.descriptions?.find(d => d.label === 'default');
      expect(desc).toBeDefined();
      expect(desc!.data).toContain('Samba');
    });
  });

  describe('CVE tags', () => {
    it('should include CVE ID in tags for CVE findings', async () => {
      const hdf = JSON.parse(await convertPrismaToHdf(loadFixture('minimal.csv'))) as HDFResults;
      const host1 = findBaseline(hdf.baselines, 'host-1.example.com');
      const req = findRequirement(host1!.requirements, '46-CVE-2021-44142');
      expect(req?.tags?.['cve']).toContain('CVE-2021-44142');
    });
  });

  describe('message field', () => {
    it('should include Cause in message for compliance findings', async () => {
      const hdf = JSON.parse(await convertPrismaToHdf(loadFixture('minimal.csv'))) as HDFResults;
      const host1 = findBaseline(hdf.baselines, 'host-1.example.com');
      const req = findRequirement(host1!.requirements, '60522-redhat-RHEL7-high');
      expect(req!.results[0]?.message).toContain('File ownership is wrong');
    });
  });

  describe('no findings', () => {
    it('should synthesize a passed placeholder for headers-only CSV', async () => {
      const hdf = JSON.parse(await convertPrismaToHdf(loadFixture('empty.csv'))) as HDFResults;
      expect(hdf.baselines).toHaveLength(1);
      expect(hdf.baselines[0]!.requirements).toHaveLength(1);
      const req = hdf.baselines[0]!.requirements[0]!;
      expect(req.id).toBe('prisma-no-findings');
      expect(req.results[0]!.status).toBe('passed');
      expect(req.results[0]!.codeDesc).toContain('Prisma');
      expect(req.results[0]!.codeDesc).toContain('scanned');
      expect(req.results[0]!.codeDesc).toContain('vulnerable components');
    });
  });

  describe('full fixture smoke test', () => {
    it('should handle the full prismacloud_sample.csv', async () => {
      const hdf = JSON.parse(await convertPrismaToHdf(loadFixture('prismacloud_sample.csv'))) as HDFResults;
      // 16 unique hostnames in the full fixture
      expect(hdf.baselines).toHaveLength(16);
      for (const baseline of hdf.baselines) {
        expect(baseline.requirements.length).toBeGreaterThan(0);
      }
    });
  });

  describe('affectedPackages from CSV columns', () => {
    function fixtureCsv(rows: Record<string, string>[]): string {
      const header = [
        'Hostname', 'Distro', 'CVE ID', 'Compliance ID', 'Type', 'Severity',
        'Packages', 'Source Package', 'Package Version', 'Package License',
        'CVSS', 'Fix Status', 'Vulnerability Tags', 'Description', 'Cause',
        'Published', 'Services', 'Cluster', 'Vulnerability Link',
      ];
      const lines = [header.join(',')];
      for (const r of rows) {
        lines.push(header.map((h) => r[h] ?? '').join(','));
      }
      return lines.join('\n');
    }

    it.each([
      ['redhat-RHEL7', 'rpm'],
      ['centos-7', 'rpm'],
      ['rocky-9', 'rpm'],
      ['alma-9', 'rpm'],
      ['amazon-2', 'rpm'],
      ['suse-15', 'rpm'],
      ['debian-buster', 'deb'],
      ['ubuntu-20.04', 'deb'],
      ['alpine-3.14', 'generic'],
      ['', 'generic'],
    ])('Distro %s → ecosystem %s', async (distro, ecosystem) => {
      const csv = fixtureCsv([{
        Hostname: 'h', Distro: distro, 'CVE ID': 'CVE-2026-1',
        'Compliance ID': '1', Type: 'image', Severity: 'high',
        'Source Package': 'foo', 'Package Version': '1.0',
        'Fix Status': 'fixed in 1.0.1',
        Description: 'd',
      }]);
      const hdf = JSON.parse(await convertPrismaToHdf(csv)) as HDFResults;
      const pkg = hdf.baselines[0]!.requirements[0]!.affectedPackages?.[0];
      expect(pkg).toMatchObject({ name: 'foo', version: '1.0', ecosystem, fixedInVersion: '1.0.1' });
    });

    it('parses fixedInVersion only when "fixed in <version>" pattern matches', async () => {
      const csv = fixtureCsv([{
        Hostname: 'h', Distro: 'debian-buster', 'CVE ID': 'CVE-2026-2',
        'Compliance ID': '2', Type: 'image', Severity: 'medium',
        'Source Package': 'bar', 'Package Version': '2.0',
        'Fix Status': 'not yet available',
        Description: 'd',
      }]);
      const hdf = JSON.parse(await convertPrismaToHdf(csv)) as HDFResults;
      expect(hdf.baselines[0]!.requirements[0]!.affectedPackages?.[0]?.fixedInVersion).toBeUndefined();
    });

    it('skips affectedPackages for non-CVE compliance findings', async () => {
      const csv = fixtureCsv([{
        Hostname: 'h', Distro: 'redhat-RHEL7',
        'Compliance ID': '60522', Type: 'linux', Severity: 'high',
        Description: 'CIS check',
      }]);
      const hdf = JSON.parse(await convertPrismaToHdf(csv)) as HDFResults;
      expect(hdf.baselines[0]!.requirements[0]!.affectedPackages).toBeUndefined();
    });
  });
});
