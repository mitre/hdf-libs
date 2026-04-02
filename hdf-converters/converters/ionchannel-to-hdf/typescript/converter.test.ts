import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { describe, it, expect } from 'vitest';
import { convertIonchannelToHdf } from './converter.js';
import { runConverterContractTests } from '../../../shared/typescript/converter-contract.js';
import { DEFAULT_MAX_INPUT_SIZE } from '../../../shared/typescript/converterutil.js';
import type { HdfResults } from '@mitre/hdf-schema';

const __dirname = dirname(fileURLToPath(import.meta.url));
const FIXTURES_DIR = join(__dirname, '..', 'fixtures');

function loadFixture(name: string): string {
  return readFileSync(join(FIXTURES_DIR, 'input', name), 'utf-8');
}

runConverterContractTests({
  converterName: 'ionchannel-to-hdf',
  convertFn: convertIonchannelToHdf,
  minimalFixture: 'minimal.json',
});

describe('ionchannel to HDF converter', async () => {
  describe('input validation', async () => {
    it('should throw on oversized input', async () => {
      const big = '{' + 'x'.repeat(DEFAULT_MAX_INPUT_SIZE + 1) + '}';
      await expect(convertIonchannelToHdf(big)).rejects.toThrow('exceeds maximum');
    });
  });

  describe('minimal fixture', async () => {
    it('should produce valid HDF from minimal fixture', async () => {
      const output = await convertIonchannelToHdf(loadFixture('minimal.json'));
      const hdf = JSON.parse(output) as HdfResults;

      expect(hdf.timestamp).toBeTruthy();
      expect(hdf.generator?.name).toBe('ionchannel-to-hdf');
      expect(hdf.generator?.version).toBe('1.0.0');
      expect(hdf.baselines).toHaveLength(1);
    });

    it('should use "Ion Channel SBOM Analysis" as the baseline name', async () => {
      const hdf = JSON.parse(await convertIonchannelToHdf(loadFixture('minimal.json'))) as HdfResults;
      expect(hdf.baselines[0]!.name).toBe('Ion Channel SBOM Analysis');
    });

    it('should include baseline title with source', async () => {
      const hdf = JSON.parse(await convertIonchannelToHdf(loadFixture('minimal.json'))) as HdfResults;
      expect(hdf.baselines[0]!.title).toBe(
        'Ion Channel Analysis of https://github.com/example-org/example-project.git',
      );
    });

    it('should include data source info', async () => {
      const hdf = JSON.parse(await convertIonchannelToHdf(loadFixture('minimal.json'))) as HdfResults;
      expect(hdf.tool?.name).toBe('Ion Channel');
      expect(hdf.tool?.format).toBe('JSON');
    });

    it('should flatten 2 top-level + 1 sub-dependency into 3 requirements', async () => {
      const hdf = JSON.parse(await convertIonchannelToHdf(loadFixture('minimal.json'))) as HdfResults;
      expect(hdf.baselines[0]!.requirements).toHaveLength(3);
    });

    it('should produce correct requirement IDs', async () => {
      const hdf = JSON.parse(await convertIonchannelToHdf(loadFixture('minimal.json'))) as HdfResults;
      const ids = hdf.baselines[0]!.requirements.map((r) => r.id);
      expect(ids).toContain('dependency-expressjs/express');
      expect(ids).toContain('dependency-jshttp/accepts');
      expect(ids).toContain('dependency-lodash/lodash');
    });

    it('should build correct title for standard dependency', async () => {
      const hdf = JSON.parse(await convertIonchannelToHdf(loadFixture('minimal.json'))) as HdfResults;
      const req = hdf.baselines[0]!.requirements.find(
        (r) => r.id === 'dependency-expressjs/express',
      );
      expect(req?.title).toBe('Dependency express from expressjs @ 4.18.2 (Required ^4.18.0)');
    });

    it('should set impact to 0.0 for all dependencies', async () => {
      const hdf = JSON.parse(await convertIonchannelToHdf(loadFixture('minimal.json'))) as HdfResults;
      for (const req of hdf.baselines[0]!.requirements) {
        expect(req.impact).toBe(0.0);
      }
    });

    it('should include NIST CM-8 tags', async () => {
      const hdf = JSON.parse(await convertIonchannelToHdf(loadFixture('minimal.json'))) as HdfResults;
      const req = hdf.baselines[0]!.requirements.find(
        (r) => r.id === 'dependency-expressjs/express',
      );
      expect(req?.tags?.nist).toContain('CM-8');
    });

    it('should include tags with metadata', async () => {
      // CM-8 has no CCI mappings, so just verify tags exist with metadata
      const hdf = JSON.parse(await convertIonchannelToHdf(loadFixture('minimal.json'))) as HdfResults;
      const req = hdf.baselines[0]!.requirements.find(
        (r) => r.id === 'dependency-expressjs/express',
      );
      expect(req?.tags).toBeDefined();
      expect(req?.tags?.org).toBe('expressjs');
    });

    it('should track sub-dependencies in tags', async () => {
      const hdf = JSON.parse(await convertIonchannelToHdf(loadFixture('minimal.json'))) as HdfResults;
      const express = hdf.baselines[0]!.requirements.find(
        (r) => r.id === 'dependency-expressjs/express',
      );
      expect(express?.tags?.dependencies).toContain('accepts');
    });

    it('should track parent dependencies in tags', async () => {
      const hdf = JSON.parse(await convertIonchannelToHdf(loadFixture('minimal.json'))) as HdfResults;
      const accepts = hdf.baselines[0]!.requirements.find(
        (r) => r.id === 'dependency-jshttp/accepts',
      );
      expect(accepts?.tags?.parentDependencies).toContain('expressjs/express');
    });

    it('should include dependency JSON in code field', async () => {
      const hdf = JSON.parse(await convertIonchannelToHdf(loadFixture('minimal.json'))) as HdfResults;
      const lodash = hdf.baselines[0]!.requirements.find(
        (r) => r.id === 'dependency-lodash/lodash',
      );
      expect(lodash?.code).toContain('"name": "lodash"');
      expect(lodash?.code).toContain('"version": "4.17.21"');
    });

    it('should have notReviewed results for all dependencies', async () => {
      const hdf = JSON.parse(await convertIonchannelToHdf(loadFixture('minimal.json'))) as HdfResults;
      for (const req of hdf.baselines[0]!.requirements) {
        expect(req.results).toHaveLength(1);
        expect(req.results[0]!.status).toBe('notReviewed');
      }
    });

    it('should include sha256 integrity', async () => {
      const hdf = JSON.parse(await convertIonchannelToHdf(loadFixture('minimal.json'))) as HdfResults;
      expect(hdf.baselines[0]!.integrity?.algorithm).toBe('sha256');
      expect(hdf.baselines[0]!.integrity?.checksum).toBeTruthy();
    });
  });

  describe('edge cases fixture', async () => {
    it('should handle Python editable install', async () => {
      const hdf = JSON.parse(await convertIonchannelToHdf(loadFixture('edge-cases.json'))) as HdfResults;
      const req = hdf.baselines[0]!.requirements.find(
        (r) => r.id === 'dependency-n/a/-e',
      );
      expect(req?.title).toBe('Python requirements file requirements.txt');
    });

    it('should omit n/a fields from title', async () => {
      const hdf = JSON.parse(await convertIonchannelToHdf(loadFixture('edge-cases.json'))) as HdfResults;
      const req = hdf.baselines[0]!.requirements.find(
        (r) => r.id === 'dependency-n/a/requests',
      );
      expect(req?.title).toBe('Dependency requests @ 2.31.0');
    });

    it('should omit n/a version from title', async () => {
      const hdf = JSON.parse(await convertIonchannelToHdf(loadFixture('edge-cases.json'))) as HdfResults;
      const req = hdf.baselines[0]!.requirements.find(
        (r) => r.id === 'dependency-example-corp/internal-lib',
      );
      expect(req?.title).toBe('Dependency internal-lib from example-corp (Required >=0.5.0)');
    });

    it('should ignore non-dependency scan summaries', async () => {
      const hdf = JSON.parse(await convertIonchannelToHdf(loadFixture('edge-cases.json'))) as HdfResults;
      // Only 3 deps from the dependency scan, community scan is ignored
      expect(hdf.baselines[0]!.requirements).toHaveLength(3);
    });
  });
});
