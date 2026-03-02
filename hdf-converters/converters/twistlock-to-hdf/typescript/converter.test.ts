import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { describe, it, expect } from 'vitest';
import { convertTwistlockToHdf } from './converter.js';
import type { HdfResults } from '@mitre/hdf-schema';

const __dirname = dirname(fileURLToPath(import.meta.url));
const FIXTURES_DIR = join(__dirname, '..', 'fixtures');

function loadFixture(name: string): string {
  return readFileSync(join(FIXTURES_DIR, 'input', name), 'utf-8');
}

describe('twistlock to HDF converter', async () => {
  describe('input validation', async () => {
    it('should throw on invalid JSON', async () => {
      await expect(convertTwistlockToHdf('not json')).rejects.toThrow();
    });

    it('should throw on empty input', async () => {
      await expect(convertTwistlockToHdf('')).rejects.toThrow();
    });
  });

  describe('container scan (results wrapper)', async () => {
    it('should produce 1 baseline from sample-1', async () => {
      const output = await convertTwistlockToHdf(loadFixture('twistlock-twistcli-sample-1.json'));
      const hdf = JSON.parse(output) as HdfResults;

      expect(hdf.baselines).toHaveLength(1);
    });

    it('should use "Twistlock Scan" as baseline name', async () => {
      const hdf = JSON.parse(
        await convertTwistlockToHdf(loadFixture('twistlock-twistcli-sample-1.json'))
      ) as HdfResults;
      expect(hdf.baselines[0]!.name).toBe('Twistlock Scan');
    });

    it('should include baseline title with project info', async () => {
      const hdf = JSON.parse(
        await convertTwistlockToHdf(loadFixture('twistlock-twistcli-sample-1.json'))
      ) as HdfResults;
      expect(hdf.baselines[0]!.title).toContain('Twistlock Project:');
    });

    it('should include summary with vulnerability distribution', async () => {
      const hdf = JSON.parse(
        await convertTwistlockToHdf(loadFixture('twistlock-twistcli-sample-1.json'))
      ) as HdfResults;
      expect(hdf.baselines[0]!.summary).toContain('Package Vulnerability Summary:');
    });

    it('should produce 97 requirements from sample-1 (97 unique CVEs)', async () => {
      const hdf = JSON.parse(
        await convertTwistlockToHdf(loadFixture('twistlock-twistcli-sample-1.json'))
      ) as HdfResults;
      expect(hdf.baselines[0]!.requirements).toHaveLength(97);
    });

    it('should include sha256 checksum', async () => {
      const hdf = JSON.parse(
        await convertTwistlockToHdf(loadFixture('twistlock-twistcli-sample-1.json'))
      ) as HdfResults;
      const checksum = hdf.baselines[0]!.resultsChecksum;
      expect(checksum?.algorithm).toBe('sha256');
      expect(checksum?.value).toMatch(/^[a-f0-9]{64}$/);
    });
  });

  describe('code repo scan (no results wrapper)', async () => {
    it('should produce 1 baseline from coderepo scan', async () => {
      const hdf = JSON.parse(
        await convertTwistlockToHdf(loadFixture('twistlock-twistcli-coderepo-scan-sample.json'))
      ) as HdfResults;
      expect(hdf.baselines).toHaveLength(1);
    });

    it('should include repository name in title', async () => {
      const hdf = JSON.parse(
        await convertTwistlockToHdf(loadFixture('twistlock-twistcli-coderepo-scan-sample.json'))
      ) as HdfResults;
      expect(hdf.baselines[0]!.title).toContain('My-Repo');
    });

    it('should produce 4 requirements (4 unique CVEs)', async () => {
      const hdf = JSON.parse(
        await convertTwistlockToHdf(loadFixture('twistlock-twistcli-coderepo-scan-sample.json'))
      ) as HdfResults;
      expect(hdf.baselines[0]!.requirements).toHaveLength(4);
    });
  });

  describe('generator and dataSource', async () => {
    it('should set generator name and version', async () => {
      const hdf = JSON.parse(
        await convertTwistlockToHdf(loadFixture('twistlock-twistcli-coderepo-scan-sample.json'))
      ) as HdfResults;
      expect(hdf.generator?.name).toBe('twistlock-to-hdf');
      expect(hdf.generator?.version).toBe('1.0.0');
    });

    it('should set dataSource to Twistlock/JSON', async () => {
      const hdf = JSON.parse(
        await convertTwistlockToHdf(loadFixture('twistlock-twistcli-coderepo-scan-sample.json'))
      ) as HdfResults;
      expect(hdf.dataSource?.name).toBe('Twistlock');
      expect(hdf.dataSource?.format).toBe('JSON');
    });
  });

  describe('severity to impact mapping', async () => {
    it('should map critical to 0.9', async () => {
      const hdf = JSON.parse(
        await convertTwistlockToHdf(loadFixture('twistlock-twistcli-coderepo-scan-sample.json'))
      ) as HdfResults;
      const req = hdf.baselines[0]!.requirements.find(r => r.id === 'CVE-2021-44228');
      expect(req?.impact).toBe(0.9);
    });

    it('should map high to 0.7', async () => {
      const hdf = JSON.parse(
        await convertTwistlockToHdf(loadFixture('twistlock-twistcli-coderepo-scan-sample.json'))
      ) as HdfResults;
      const req = hdf.baselines[0]!.requirements.find(r => r.id === 'CVE-2021-45105');
      expect(req?.impact).toBe(0.7);
    });

    it('should map medium to 0.5', async () => {
      const hdf = JSON.parse(
        await convertTwistlockToHdf(loadFixture('twistlock-twistcli-coderepo-scan-sample.json'))
      ) as HdfResults;
      const req = hdf.baselines[0]!.requirements.find(r => r.id === 'CVE-2021-44832');
      expect(req?.impact).toBe(0.5);
    });
  });

  describe('tags', async () => {
    it('should use default remediation NIST tags (SI-2, RA-5)', async () => {
      const hdf = JSON.parse(
        await convertTwistlockToHdf(loadFixture('twistlock-twistcli-coderepo-scan-sample.json'))
      ) as HdfResults;
      const req = hdf.baselines[0]!.requirements.find(r => r.id === 'CVE-2021-44228');
      const nist = req?.tags?.['nist'] as string[];
      expect(nist).toBeDefined();
      expect(nist).toContain('SI-2');
      expect(nist).toContain('RA-5');
    });

    it('should include CVE ID in cveid tag', async () => {
      const hdf = JSON.parse(
        await convertTwistlockToHdf(loadFixture('twistlock-twistcli-coderepo-scan-sample.json'))
      ) as HdfResults;
      const req = hdf.baselines[0]!.requirements.find(r => r.id === 'CVE-2021-44228');
      const cveid = req?.tags?.['cveid'] as string[];
      expect(cveid).toBeDefined();
      expect(cveid).toContain('CVE-2021-44228');
    });
  });

  describe('status', async () => {
    it('should mark all results as failed', async () => {
      const hdf = JSON.parse(
        await convertTwistlockToHdf(loadFixture('twistlock-twistcli-coderepo-scan-sample.json'))
      ) as HdfResults;
      for (const req of hdf.baselines[0]!.requirements) {
        for (const result of req.results) {
          expect(result.status).toBe('failed');
        }
      }
    });
  });

  describe('code description', async () => {
    it('should include package name in code_desc', async () => {
      const hdf = JSON.parse(
        await convertTwistlockToHdf(loadFixture('twistlock-twistcli-coderepo-scan-sample.json'))
      ) as HdfResults;
      const req = hdf.baselines[0]!.requirements.find(r => r.id === 'CVE-2021-44228');
      expect(req).toBeDefined();
      expect(req!.results[0]?.codeDesc).toContain('org.apache.logging.log4j_log4j-core');
    });
  });

  describe('description', async () => {
    it('should include default description with vulnerability info', async () => {
      const hdf = JSON.parse(
        await convertTwistlockToHdf(loadFixture('twistlock-twistcli-coderepo-scan-sample.json'))
      ) as HdfResults;
      const req = hdf.baselines[0]!.requirements.find(r => r.id === 'CVE-2021-44228');
      const desc = req?.descriptions?.find(d => d.label === 'default');
      expect(desc).toBeDefined();
      expect(desc!.data).toContain('Log4j');
    });
  });

  describe('requirement title and ID', async () => {
    it('should use CVE ID as both title and ID', async () => {
      const hdf = JSON.parse(
        await convertTwistlockToHdf(loadFixture('twistlock-twistcli-coderepo-scan-sample.json'))
      ) as HdfResults;
      const req = hdf.baselines[0]!.requirements.find(r => r.id === 'CVE-2021-44228');
      expect(req).toBeDefined();
      expect(req!.id).toBe('CVE-2021-44228');
      expect(req!.title).toBe('CVE-2021-44228');
    });
  });

  describe('target', async () => {
    it('should include image name as target for container scans', async () => {
      const hdf = JSON.parse(
        await convertTwistlockToHdf(loadFixture('twistlock-twistcli-sample-1.json'))
      ) as HdfResults;
      expect(hdf.targets).toBeDefined();
      expect(hdf.targets![0]!.name).toContain('registry.io/test');
      expect(hdf.targets![0]!.type).toBe('containerImage');
    });
  });

  describe('empty vulnerabilities', async () => {
    it('should handle null vulnerabilities', async () => {
      const input = JSON.stringify({
        results: [{
          name: 'clean-image',
          collections: ['All'],
          vulnerabilities: null,
          vulnerabilityDistribution: { critical: 0, high: 0, medium: 0, low: 0, total: 0 },
          complianceDistribution: { critical: 0, high: 0, medium: 0, low: 0, total: 0 },
        }],
      });
      const hdf = JSON.parse(await convertTwistlockToHdf(input)) as HdfResults;
      expect(hdf.baselines[0]!.requirements).toHaveLength(0);
    });
  });

  describe('start time', async () => {
    it('should use discoveredDate as start_time', async () => {
      const hdf = JSON.parse(
        await convertTwistlockToHdf(loadFixture('twistlock-twistcli-coderepo-scan-sample.json'))
      ) as HdfResults;
      const req = hdf.baselines[0]!.requirements.find(r => r.id === 'CVE-2021-44228');
      expect(req).toBeDefined();
      expect(req!.results[0]?.startTime).toBe('2021-12-10T10:15:00.000Z');
    });
  });
});
