import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { describe, it, expect } from 'vitest';
import { convertConveyorToHdf } from './converter.js';
import type { HdfResults } from '@mitre/hdf-schema';

const __dirname = dirname(fileURLToPath(import.meta.url));
const FIXTURES_DIR = join(__dirname, '..', 'fixtures');

function loadFixture(name: string): string {
  return readFileSync(join(FIXTURES_DIR, 'input', name), 'utf-8');
}

describe('conveyor to HDF converter', async () => {
  describe('input validation', async () => {
    it('should throw on empty input', async () => {
      await expect(convertConveyorToHdf('')).rejects.toThrow();
    });

    it('should throw on invalid JSON', async () => {
      await expect(convertConveyorToHdf('not json')).rejects.toThrow();
    });

    it('should throw when api_response is missing', async () => {
      await expect(convertConveyorToHdf('{"api_error_message": ""}')).rejects.toThrow();
    });
  });

  describe('multi-baseline output (grouped by scanner)', async () => {
    it('should produce multiple baselines (one per scanner type)', async () => {
      const hdf = JSON.parse(await convertConveyorToHdf(loadFixture('sample-results.json'))) as HdfResults;
      // Fixture has 4 scanner types: Clamav, CodeQuality, Stigma, Moldy
      expect(hdf.baselines.length).toBeGreaterThanOrEqual(4);
    });

    it('should use "Conveyor Scan" as baseline name for all baselines', async () => {
      const hdf = JSON.parse(await convertConveyorToHdf(loadFixture('sample-results.json'))) as HdfResults;
      for (const baseline of hdf.baselines) {
        expect(baseline.name).toBe('Conveyor Scan');
      }
    });

    it('should include scanner name in baseline title', async () => {
      const hdf = JSON.parse(await convertConveyorToHdf(loadFixture('sample-results.json'))) as HdfResults;
      const titles = hdf.baselines.map(b => b.title ?? '');
      const hasClamav = titles.some(t => t.includes('Clamav'));
      const hasMoldy = titles.some(t => t.includes('Moldy'));
      expect(hasClamav).toBe(true);
      expect(hasMoldy).toBe(true);
    });
  });

  describe('checksum', async () => {
    it('should include sha256 checksum on each baseline', async () => {
      const hdf = JSON.parse(await convertConveyorToHdf(loadFixture('sample-results.json'))) as HdfResults;
      for (const baseline of hdf.baselines) {
        expect(baseline.resultsChecksum?.algorithm).toBe('sha256');
        expect(baseline.resultsChecksum?.value).toMatch(/^[a-f0-9]{64}$/);
      }
    });
  });

  describe('generator and dataSource', async () => {
    it('should set generator name and version', async () => {
      const hdf = JSON.parse(await convertConveyorToHdf(loadFixture('sample-results.json'))) as HdfResults;
      expect(hdf.generator?.name).toBe('conveyor-to-hdf');
      expect(hdf.generator?.version).toBe('1.0.0');
    });

    it('should set dataSource name to "Conveyor" and format to "JSON"', async () => {
      const hdf = JSON.parse(await convertConveyorToHdf(loadFixture('sample-results.json'))) as HdfResults;
      expect(hdf.dataSource?.name).toBe('Conveyor');
      expect(hdf.dataSource?.format).toBe('JSON');
    });
  });

  describe('target', async () => {
    it('should set target type to Application', async () => {
      const hdf = JSON.parse(await convertConveyorToHdf(loadFixture('sample-results.json'))) as HdfResults;
      expect(hdf.targets).toBeDefined();
      expect(hdf.targets![0]!.type).toBe('application');
    });
  });

  describe('score to impact mapping', async () => {
    it('should map score=1000 to impact=1.0', async () => {
      const hdf = JSON.parse(await convertConveyorToHdf(loadFixture('sample-results.json'))) as HdfResults;
      // Moldy baseline has score=1000
      const moldy = hdf.baselines.find(b => b.title?.includes('Moldy'));
      expect(moldy).toBeDefined();
      const hasMax = moldy!.requirements.some(r => r.impact === 1.0);
      expect(hasMax).toBe(true);
    });

    it('should map score=0 to impact=0.0', async () => {
      const hdf = JSON.parse(await convertConveyorToHdf(loadFixture('sample-results.json'))) as HdfResults;
      const moldy = hdf.baselines.find(b => b.title?.includes('Moldy'));
      expect(moldy).toBeDefined();
      const hasZero = moldy!.requirements.some(r => r.impact === 0.0);
      expect(hasZero).toBe(true);
    });
  });

  describe('status mapping', async () => {
    it('should mark score=0 results as passed', async () => {
      const hdf = JSON.parse(await convertConveyorToHdf(loadFixture('sample-results.json'))) as HdfResults;
      const moldy = hdf.baselines.find(b => b.title?.includes('Moldy'));
      expect(moldy).toBeDefined();
      const hasPassed = moldy!.requirements.some(
        r => r.results.some(res => res.status === 'passed')
      );
      expect(hasPassed).toBe(true);
    });

    it('should mark score>0 results as failed', async () => {
      const hdf = JSON.parse(await convertConveyorToHdf(loadFixture('sample-results.json'))) as HdfResults;
      const moldy = hdf.baselines.find(b => b.title?.includes('Moldy'));
      expect(moldy).toBeDefined();
      const hasFailed = moldy!.requirements.some(
        r => r.results.some(res => res.status === 'failed')
      );
      expect(hasFailed).toBe(true);
    });
  });

  describe('requirement structure', async () => {
    it('should use sha256 hash as requirement ID', async () => {
      const hdf = JSON.parse(await convertConveyorToHdf(loadFixture('sample-results.json'))) as HdfResults;
      for (const baseline of hdf.baselines) {
        for (const req of baseline.requirements) {
          expect(req.id).toMatch(/^[a-f0-9]{64}$/);
        }
      }
    });

    it('should map file tree names to requirement titles', async () => {
      const hdf = JSON.parse(await convertConveyorToHdf(loadFixture('sample-results.json'))) as HdfResults;
      const hasTitle = hdf.baselines.some(b =>
        b.requirements.some(r => r.title && r.title.length > 0)
      );
      expect(hasTitle).toBe(true);
    });

    it('should include default description on every requirement', async () => {
      const hdf = JSON.parse(await convertConveyorToHdf(loadFixture('sample-results.json'))) as HdfResults;
      for (const baseline of hdf.baselines) {
        for (const req of baseline.requirements) {
          const hasDefault = req.descriptions?.some(d => d.label === 'default');
          expect(hasDefault).toBe(true);
        }
      }
    });

    it('should include NIST tags on every requirement', async () => {
      const hdf = JSON.parse(await convertConveyorToHdf(loadFixture('sample-results.json'))) as HdfResults;
      for (const baseline of hdf.baselines) {
        for (const req of baseline.requirements) {
          const nist = req.tags?.['nist'] as string[];
          expect(nist).toBeDefined();
          expect(nist.length).toBeGreaterThan(0);
        }
      }
    });
  });

  describe('result structure', async () => {
    it('should include code_desc on every result', async () => {
      const hdf = JSON.parse(await convertConveyorToHdf(loadFixture('sample-results.json'))) as HdfResults;
      for (const baseline of hdf.baselines) {
        for (const req of baseline.requirements) {
          for (const res of req.results) {
            expect(res.codeDesc).toBeTruthy();
          }
        }
      }
    });

    it('should include start_time on every result', async () => {
      const hdf = JSON.parse(await convertConveyorToHdf(loadFixture('sample-results.json'))) as HdfResults;
      for (const baseline of hdf.baselines) {
        for (const req of baseline.requirements) {
          for (const res of req.results) {
            expect(res.startTime).toBeTruthy();
          }
        }
      }
    });
  });

  describe('timestamp', async () => {
    it('should include a timestamp', async () => {
      const hdf = JSON.parse(await convertConveyorToHdf(loadFixture('sample-results.json'))) as HdfResults;
      expect(hdf.timestamp).toBeTruthy();
    });
  });
});
