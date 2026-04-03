import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { describe, it, expect } from 'vitest';
import { convertJfrogXrayToHdf } from './converter.js';
import { runConverterContractTests } from '../../../shared/typescript/converter-contract.js';
import type { HdfResults } from '@mitre/hdf-schema';

const __dirname = dirname(fileURLToPath(import.meta.url));
const FIXTURES_DIR = join(__dirname, '..', 'fixtures');

function loadFixture(name: string): string {
  return readFileSync(join(FIXTURES_DIR, 'input', name), 'utf-8');
}

runConverterContractTests({
  converterName: 'jfrog-xray-to-hdf',
  convertFn: convertJfrogXrayToHdf,
  minimalFixture: 'jfrog_xray_sample.json',
});

describe('jfrog-xray to HDF converter', async () => {
  describe('conversion basics', async () => {
    it('should produce valid HDF from fixture', async () => {
      const output = await convertJfrogXrayToHdf(loadFixture('jfrog_xray_sample.json'));
      const hdf = JSON.parse(output) as HdfResults;

      expect(hdf.timestamp).toBeTruthy();
      expect(hdf.generator?.name).toBe('jfrog-xray-to-hdf');
      expect(hdf.generator?.version).toBe('1.0.0');
      expect(hdf.baselines).toHaveLength(1);
    });

    it('should use "JFrog Xray Scan" as the baseline name', async () => {
      const hdf = JSON.parse(await convertJfrogXrayToHdf(loadFixture('jfrog_xray_sample.json'))) as HdfResults;
      expect(hdf.baselines[0]!.name).toBe('JFrog Xray Scan');
    });

    it('should produce 17 unique requirements from 30 entries', async () => {
      const hdf = JSON.parse(await convertJfrogXrayToHdf(loadFixture('jfrog_xray_sample.json'))) as HdfResults;
      expect(hdf.baselines[0]!.requirements).toHaveLength(17);
    });

    it('should include a sha256 checksum', async () => {
      const hdf = JSON.parse(await convertJfrogXrayToHdf(loadFixture('jfrog_xray_sample.json'))) as HdfResults;
      const checksum = hdf.baselines[0]!.resultsChecksum;
      expect(checksum?.algorithm).toBe('sha256');
      expect(checksum?.value).toMatch(/^[a-f0-9]{64}$/);
    });
  });

  describe('generator and dataSource', async () => {
    it('should set generator name and version', async () => {
      const hdf = JSON.parse(await convertJfrogXrayToHdf(loadFixture('jfrog_xray_sample.json'))) as HdfResults;
      expect(hdf.generator?.name).toBe('jfrog-xray-to-hdf');
      expect(hdf.generator?.version).toBe('1.0.0');
    });

    it('should set tool name to "JFrog Xray" and format to "JSON"', async () => {
      const hdf = JSON.parse(await convertJfrogXrayToHdf(loadFixture('jfrog_xray_sample.json'))) as HdfResults;
      expect(hdf.tool?.name).toBe('JFrog Xray');
      expect(hdf.tool?.format).toBe('JSON');
    });
  });

  describe('target', async () => {
    it('should include target with Application type', async () => {
      const hdf = JSON.parse(await convertJfrogXrayToHdf(loadFixture('jfrog_xray_sample.json'))) as HdfResults;
      expect(hdf.components).toBeDefined();
      expect(hdf.components![0]!.name).toBe('JFrog Xray Scan');
      expect(hdf.components![0]!.type).toBe('application');
    });
  });

  describe('severity to impact mapping', async () => {
    it('should map high severity to 0.7', async () => {
      const hdf = JSON.parse(await convertJfrogXrayToHdf(loadFixture('jfrog_xray_sample.json'))) as HdfResults;
      const reqs = hdf.baselines[0]!.requirements;
      const hasHigh = reqs.some(r => r.impact === 0.7);
      expect(hasHigh).toBe(true);
    });

    it('should map medium severity to 0.5', async () => {
      const hdf = JSON.parse(await convertJfrogXrayToHdf(loadFixture('jfrog_xray_sample.json'))) as HdfResults;
      const reqs = hdf.baselines[0]!.requirements;
      const hasMedium = reqs.some(r => r.impact === 0.5);
      expect(hasMedium).toBe(true);
    });

    it('should map low severity to 0.3', async () => {
      const hdf = JSON.parse(await convertJfrogXrayToHdf(loadFixture('jfrog_xray_sample.json'))) as HdfResults;
      const reqs = hdf.baselines[0]!.requirements;
      const hasLow = reqs.some(r => r.impact === 0.3);
      expect(hasLow).toBe(true);
    });
  });

  describe('ID generation', async () => {
    it('should generate non-empty IDs for all requirements', async () => {
      const hdf = JSON.parse(await convertJfrogXrayToHdf(loadFixture('jfrog_xray_sample.json'))) as HdfResults;
      for (const req of hdf.baselines[0]!.requirements) {
        expect(req.id).toBeTruthy();
      }
    });
  });

  describe('deduplication', async () => {
    it('should produce 27 total results across 17 requirements', async () => {
      const hdf = JSON.parse(await convertJfrogXrayToHdf(loadFixture('jfrog_xray_sample.json'))) as HdfResults;
      const totalResults = hdf.baselines[0]!.requirements.reduce((sum, r) => sum + r.results.length, 0);
      expect(totalResults).toBe(27);
    });

    it('should group duplicate entries into multiple results', async () => {
      const hdf = JSON.parse(await convertJfrogXrayToHdf(loadFixture('jfrog_xray_sample.json'))) as HdfResults;
      const hasMultipleResults = hdf.baselines[0]!.requirements.some(r => r.results.length > 1);
      expect(hasMultipleResults).toBe(true);
    });
  });

  describe('status', async () => {
    it('should mark all results as failed', async () => {
      const hdf = JSON.parse(await convertJfrogXrayToHdf(loadFixture('jfrog_xray_sample.json'))) as HdfResults;
      for (const req of hdf.baselines[0]!.requirements) {
        for (const result of req.results) {
          expect(result.status).toBe('failed');
        }
      }
    });
  });

  describe('description', async () => {
    it('should include default description for each requirement', async () => {
      const hdf = JSON.parse(await convertJfrogXrayToHdf(loadFixture('jfrog_xray_sample.json'))) as HdfResults;
      for (const req of hdf.baselines[0]!.requirements) {
        const defaultDesc = req.descriptions?.find(d => d.label === 'default');
        expect(defaultDesc).toBeDefined();
        expect(defaultDesc!.data.length).toBeGreaterThan(0);
      }
    });
  });

  describe('code description', async () => {
    it('should include non-empty codeDesc for each result', async () => {
      const hdf = JSON.parse(await convertJfrogXrayToHdf(loadFixture('jfrog_xray_sample.json'))) as HdfResults;
      for (const req of hdf.baselines[0]!.requirements) {
        for (const result of req.results) {
          expect(result.codeDesc).toBeTruthy();
        }
      }
    });
  });

  describe('CWE to NIST mapping', async () => {
    it('should include nist tags on all requirements', async () => {
      const hdf = JSON.parse(await convertJfrogXrayToHdf(loadFixture('jfrog_xray_sample.json'))) as HdfResults;
      for (const req of hdf.baselines[0]!.requirements) {
        const nist = req.tags?.['nist'] as string[];
        expect(nist).toBeDefined();
        expect(nist.length).toBeGreaterThan(0);
      }
    });

    it('should populate cweid tag when CWE is present', async () => {
      const hdf = JSON.parse(await convertJfrogXrayToHdf(loadFixture('jfrog_xray_sample.json'))) as HdfResults;
      const hasCWE = hdf.baselines[0]!.requirements.some(r => {
        const cweid = r.tags?.['cweid'] as string[] | undefined;
        return cweid && cweid.length > 0;
      });
      expect(hasCWE).toBe(true);
    });
  });

  describe('title', async () => {
    it('should include summary as title for each requirement', async () => {
      const hdf = JSON.parse(await convertJfrogXrayToHdf(loadFixture('jfrog_xray_sample.json'))) as HdfResults;
      for (const req of hdf.baselines[0]!.requirements) {
        expect(req.title).toBeTruthy();
      }
    });
  });

  describe('empty data', async () => {
    it('should handle empty data array', async () => {
      const input = JSON.stringify({
        total_count: 0,
        data: [],
      });
      const hdf = JSON.parse(await convertJfrogXrayToHdf(input)) as HdfResults;
      expect(hdf.baselines[0]!.requirements).toHaveLength(0);
    });
  });
});
