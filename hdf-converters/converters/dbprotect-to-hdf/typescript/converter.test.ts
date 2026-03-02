import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { describe, it, expect } from 'vitest';
import { convertDbprotectToHdf } from './converter.js';
import type { HdfResults } from '@mitre/hdf-schema';

const __dirname = dirname(fileURLToPath(import.meta.url));
const FIXTURES_DIR = join(__dirname, '..', 'fixtures');

function loadFixture(name: string): string {
  return readFileSync(join(FIXTURES_DIR, 'input', name), 'utf-8');
}

describe('dbprotect to HDF converter', () => {
  describe('input validation', () => {
    it('should throw on invalid XML', async () => {
      await expect(convertDbprotectToHdf('not valid xml')).rejects.toThrow();
    });

    it('should throw on empty input', async () => {
      await expect(convertDbprotectToHdf('')).rejects.toThrow();
    });
  });

  describe('check results details', () => {
    it('should produce valid HDF from check results fixture', async () => {
      const output = await convertDbprotectToHdf(loadFixture('sample-check-results.xml'));
      const hdf = JSON.parse(output) as HdfResults;

      expect(hdf.timestamp).toBeTruthy();
      expect(hdf.generator?.name).toBe('dbprotect-to-hdf');
      expect(hdf.generator?.version).toBe('1.0.0');
      expect(hdf.baselines).toHaveLength(1);
    });

    it('should use "DBProtect Scan" as the baseline name', async () => {
      const hdf = JSON.parse(await convertDbprotectToHdf(loadFixture('sample-check-results.xml'))) as HdfResults;
      expect(hdf.baselines[0]!.name).toBe('DBProtect Scan');
    });

    it('should include baseline title with job name', async () => {
      const hdf = JSON.parse(await convertDbprotectToHdf(loadFixture('sample-check-results.xml'))) as HdfResults;
      expect(hdf.baselines[0]!.title).toContain('Heimdal Test scan report generation');
    });

    it('should include baseline summary with asset info', async () => {
      const hdf = JSON.parse(await convertDbprotectToHdf(loadFixture('sample-check-results.xml'))) as HdfResults;
      expect(hdf.baselines[0]!.summary).toContain('Organization');
      expect(hdf.baselines[0]!.summary).toContain('CONDS181');
    });

    it('should include a sha256 checksum', async () => {
      const hdf = JSON.parse(await convertDbprotectToHdf(loadFixture('sample-check-results.xml'))) as HdfResults;
      const checksum = hdf.baselines[0]!.resultsChecksum;
      expect(checksum?.algorithm).toBe('sha256');
      expect(checksum?.value).toMatch(/^[a-f0-9]{64}$/);
    });

    it('should set dataSource name to "DBProtect" and format to "XML"', async () => {
      const hdf = JSON.parse(await convertDbprotectToHdf(loadFixture('sample-check-results.xml'))) as HdfResults;
      expect(hdf.dataSource?.name).toBe('DBProtect');
      expect(hdf.dataSource?.format).toBe('XML');
    });

    it('should have 6 unique requirements from 8 rows', async () => {
      const hdf = JSON.parse(await convertDbprotectToHdf(loadFixture('sample-check-results.xml'))) as HdfResults;
      // 8 rows with 6 unique Check IDs: 2986 (2), 2903, 2841, 2801 (2), 2942, 2976
      expect(hdf.baselines[0]!.requirements).toHaveLength(6);
    });

    it('should group results by Check ID', async () => {
      const hdf = JSON.parse(await convertDbprotectToHdf(loadFixture('sample-check-results.xml'))) as HdfResults;
      const req2986 = hdf.baselines[0]!.requirements.find(r => r.id === '2986');
      expect(req2986).toBeDefined();
      expect(req2986!.results).toHaveLength(2);

      const req2801 = hdf.baselines[0]!.requirements.find(r => r.id === '2801');
      expect(req2801).toBeDefined();
      expect(req2801!.results).toHaveLength(2);
    });

    it('should set requirement title from Check column', async () => {
      const hdf = JSON.parse(await convertDbprotectToHdf(loadFixture('sample-check-results.xml'))) as HdfResults;
      const req = hdf.baselines[0]!.requirements.find(r => r.id === '2986');
      expect(req?.title).toBe('Schema ownership');
    });

    it('should set description with task and category', async () => {
      const hdf = JSON.parse(await convertDbprotectToHdf(loadFixture('sample-check-results.xml'))) as HdfResults;
      const req = hdf.baselines[0]!.requirements.find(r => r.id === '2986');
      expect(req?.descriptions).toBeDefined();
      expect(req!.descriptions!.length).toBeGreaterThan(0);
      const defaultDesc = req!.descriptions!.find(d => d.label === 'default');
      expect(defaultDesc).toBeDefined();
      expect(defaultDesc!.data).toContain('Task');
      expect(defaultDesc!.data).toContain('Check Category');
    });
  });

  describe('impact mapping', () => {
    it('should map High risk to 0.7', async () => {
      const hdf = JSON.parse(await convertDbprotectToHdf(loadFixture('sample-check-results.xml'))) as HdfResults;
      const req = hdf.baselines[0]!.requirements.find(r => r.id === '2903');
      expect(req?.impact).toBe(0.7);
    });

    it('should map Medium risk to 0.5', async () => {
      const hdf = JSON.parse(await convertDbprotectToHdf(loadFixture('sample-check-results.xml'))) as HdfResults;
      const req = hdf.baselines[0]!.requirements.find(r => r.id === '2986');
      expect(req?.impact).toBe(0.5);
    });

    it('should map Low risk to 0.3', async () => {
      const hdf = JSON.parse(await convertDbprotectToHdf(loadFixture('sample-check-results.xml'))) as HdfResults;
      const req = hdf.baselines[0]!.requirements.find(r => r.id === '2841');
      expect(req?.impact).toBe(0.3);
    });

    it('should map Informational risk to 0.0', async () => {
      const hdf = JSON.parse(await convertDbprotectToHdf(loadFixture('sample-check-results.xml'))) as HdfResults;
      const req = hdf.baselines[0]!.requirements.find(r => r.id === '2801');
      expect(req?.impact).toBe(0.0);
    });
  });

  describe('status mapping', () => {
    it('should map Fact to notReviewed', async () => {
      const hdf = JSON.parse(await convertDbprotectToHdf(loadFixture('sample-check-results.xml'))) as HdfResults;
      const req = hdf.baselines[0]!.requirements.find(r => r.id === '2986');
      expect(req!.results[0]!.status).toBe('notReviewed');
    });

    it('should map Failed to failed', async () => {
      const hdf = JSON.parse(await convertDbprotectToHdf(loadFixture('sample-check-results.xml'))) as HdfResults;
      const req = hdf.baselines[0]!.requirements.find(r => r.id === '2841');
      expect(req!.results[0]!.status).toBe('failed');
    });

    it('should map Finding to failed', async () => {
      const hdf = JSON.parse(await convertDbprotectToHdf(loadFixture('sample-check-results.xml'))) as HdfResults;
      const req = hdf.baselines[0]!.requirements.find(r => r.id === '2801');
      expect(req!.results[0]!.status).toBe('failed');
    });

    it('should map Not A Finding to passed', async () => {
      const hdf = JSON.parse(await convertDbprotectToHdf(loadFixture('sample-check-results.xml'))) as HdfResults;
      const req = hdf.baselines[0]!.requirements.find(r => r.id === '2942');
      expect(req!.results[0]!.status).toBe('passed');
    });

    it('should map Skipped to notReviewed', async () => {
      const hdf = JSON.parse(await convertDbprotectToHdf(loadFixture('sample-check-results.xml'))) as HdfResults;
      const req = hdf.baselines[0]!.requirements.find(r => r.id === '2976');
      expect(req!.results[0]!.status).toBe('notReviewed');
    });
  });

  describe('code description and start time', () => {
    it('should set codeDesc from Details column', async () => {
      const hdf = JSON.parse(await convertDbprotectToHdf(loadFixture('sample-check-results.xml'))) as HdfResults;
      const req = hdf.baselines[0]!.requirements.find(r => r.id === '2986');
      expect(req!.results[0]!.codeDesc).toContain('Schema name=DatabaseMailUserRole');
    });

    it('should set startTime from Date column', async () => {
      const hdf = JSON.parse(await convertDbprotectToHdf(loadFixture('sample-check-results.xml'))) as HdfResults;
      const req = hdf.baselines[0]!.requirements.find(r => r.id === '2986');
      expect(req!.results[0]!.startTime).toBeTruthy();
    });
  });

  describe('NIST tags', () => {
    it('should include default static analysis NIST tags', async () => {
      const hdf = JSON.parse(await convertDbprotectToHdf(loadFixture('sample-check-results.xml'))) as HdfResults;
      const req = hdf.baselines[0]!.requirements.find(r => r.id === '2986');
      expect(req?.tags).toBeDefined();
      const nist = req!.tags!['nist'] as string[];
      expect(nist).toBeDefined();
      expect(nist.length).toBeGreaterThan(0);
    });
  });

  describe('target', () => {
    it('should set target name from Asset column', async () => {
      const hdf = JSON.parse(await convertDbprotectToHdf(loadFixture('sample-check-results.xml'))) as HdfResults;
      expect(hdf.targets).toBeDefined();
      expect(hdf.targets!.length).toBeGreaterThan(0);
      expect(hdf.targets![0]!.name).toBe('CONDS181');
    });

    it('should set target type to Host', async () => {
      const hdf = JSON.parse(await convertDbprotectToHdf(loadFixture('sample-check-results.xml'))) as HdfResults;
      expect(hdf.targets![0]!.type).toBe('host');
    });
  });

  describe('findings detail', () => {
    it('should produce valid HDF from findings detail fixture', async () => {
      const hdf = JSON.parse(await convertDbprotectToHdf(loadFixture('sample-findings-detail.xml'))) as HdfResults;
      expect(hdf.baselines).toHaveLength(1);
      expect(hdf.baselines[0]!.name).toBe('DBProtect Scan');
    });

    it('should have 3 unique requirements from 4 rows', async () => {
      const hdf = JSON.parse(await convertDbprotectToHdf(loadFixture('sample-findings-detail.xml'))) as HdfResults;
      // 4 rows with 3 unique Check IDs: 2801 (2), 2830, 2903
      expect(hdf.baselines[0]!.requirements).toHaveLength(3);
    });

    it('should treat all findings as failed (no Result Status column)', async () => {
      const hdf = JSON.parse(await convertDbprotectToHdf(loadFixture('sample-findings-detail.xml'))) as HdfResults;
      for (const req of hdf.baselines[0]!.requirements) {
        for (const result of req.results) {
          expect(result.status).toBe('failed');
        }
      }
    });
  });
});
