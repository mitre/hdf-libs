import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { describe, it, expect } from 'vitest';
import { convertMsftDefenderCloudToHdf } from './converter.js';
import { runConverterContractTests } from '../../../shared/typescript/converter-contract.js';
import type { HdfResults } from '@mitre/hdf-schema';

const __dirname = dirname(fileURLToPath(import.meta.url));
const FIXTURES_DIR = join(__dirname, '..', 'fixtures');

function loadFixture(name: string): string {
  return readFileSync(join(FIXTURES_DIR, 'input', name), 'utf-8');
}

runConverterContractTests({
  converterName: 'msft-defender-cloud-to-hdf',
  convertFn: convertMsftDefenderCloudToHdf,
  minimalFixture: 'minimal.json',
});

describe('Microsoft Defender for Cloud to HDF converter', async () => {
  describe('error handling', async () => {
    it('should throw when value array is missing', async () => {
      await expect(convertMsftDefenderCloudToHdf(JSON.stringify({}))).rejects.toThrow(
        'missing or invalid value array',
      );
    });

    it('should throw when value is not an array', async () => {
      await expect(convertMsftDefenderCloudToHdf(JSON.stringify({ value: 'notarray' }))).rejects.toThrow(
        'missing or invalid value array',
      );
    });
  });

  describe('minimal fixture conversion', async () => {
    it('should produce valid HDF structure', async () => {
      const output = await convertMsftDefenderCloudToHdf(loadFixture('minimal.json'));
      const hdf = JSON.parse(output) as HdfResults;

      expect(hdf.timestamp).toBeTruthy();
      expect(hdf.generator?.name).toBe('msft-defender-cloud-to-hdf');
      expect(hdf.generator?.version).toBe('1.0.0');
      expect(hdf.tool?.name).toBe('Microsoft Defender for Cloud');
      expect(hdf.tool?.format).toBe('JSON');
      expect(hdf.baselines).toHaveLength(1);
    });

    it('should create 2 requirements from 2 assessments', async () => {
      const hdf = JSON.parse(await convertMsftDefenderCloudToHdf(loadFixture('minimal.json'))) as HdfResults;
      expect(hdf.baselines[0]!.requirements).toHaveLength(2);
    });

    it('should use correct baseline name', async () => {
      const hdf = JSON.parse(await convertMsftDefenderCloudToHdf(loadFixture('minimal.json'))) as HdfResults;
      expect(hdf.baselines[0]!.name).toBe('Microsoft Defender for Cloud Assessments');
    });

    it('should include a sha256 checksum', async () => {
      const hdf = JSON.parse(await convertMsftDefenderCloudToHdf(loadFixture('minimal.json'))) as HdfResults;
      const checksum = hdf.baselines[0]!.resultsChecksum;
      expect(checksum?.algorithm).toBe('sha256');
      expect(checksum?.value).toMatch(/^[a-f0-9]{64}$/);
    });
  });

  describe('sample fixture conversion', async () => {
    it('should produce 6 requirements from 6 assessments', async () => {
      const hdf = JSON.parse(await convertMsftDefenderCloudToHdf(loadFixture('sample.json'))) as HdfResults;
      expect(hdf.baselines[0]!.requirements).toHaveLength(6);
    });
  });

  describe('status mapping', async () => {
    it('should map Healthy to passed', async () => {
      const hdf = JSON.parse(await convertMsftDefenderCloudToHdf(loadFixture('minimal.json'))) as HdfResults;
      const req0 = hdf.baselines[0]!.requirements[0]!;
      expect(req0.results[0]!.status).toBe('passed');
    });

    it('should map Unhealthy to failed', async () => {
      const hdf = JSON.parse(await convertMsftDefenderCloudToHdf(loadFixture('minimal.json'))) as HdfResults;
      const req1 = hdf.baselines[0]!.requirements[1]!;
      expect(req1.results[0]!.status).toBe('failed');
    });

    it('should map NotApplicable to notApplicable', async () => {
      const hdf = JSON.parse(await convertMsftDefenderCloudToHdf(loadFixture('sample.json'))) as HdfResults;
      const req4 = hdf.baselines[0]!.requirements[4]!;
      expect(req4.results[0]!.status).toBe('notApplicable');
    });
  });

  describe('severity mapping', async () => {
    it('should map High severity to 0.7', async () => {
      const hdf = JSON.parse(await convertMsftDefenderCloudToHdf(loadFixture('minimal.json'))) as HdfResults;
      const req1 = hdf.baselines[0]!.requirements[1]!;
      expect(req1.impact).toBe(0.7);
    });

    it('should map Medium severity to 0.5', async () => {
      const hdf = JSON.parse(await convertMsftDefenderCloudToHdf(loadFixture('minimal.json'))) as HdfResults;
      const req0 = hdf.baselines[0]!.requirements[0]!;
      expect(req0.impact).toBe(0.5);
    });

    it('should map Low severity to 0.3', async () => {
      const hdf = JSON.parse(await convertMsftDefenderCloudToHdf(loadFixture('sample.json'))) as HdfResults;
      const req4 = hdf.baselines[0]!.requirements[4]!;
      expect(req4.impact).toBe(0.3);
    });
  });

  describe('target', async () => {
    it('should set target as CloudAccount type', async () => {
      const hdf = JSON.parse(await convertMsftDefenderCloudToHdf(loadFixture('minimal.json'))) as HdfResults;
      expect(hdf.components).toHaveLength(1);
      expect(hdf.components![0]!.type).toBe('cloudAccount');
    });

    it('should include subscription ID in target', async () => {
      const hdf = JSON.parse(await convertMsftDefenderCloudToHdf(loadFixture('minimal.json'))) as HdfResults;
      const target = hdf.components![0]!;
      expect(target.accountId).toBe('a1b2c3d4-e5f6-7890-abcd-ef1234567890');
      expect(target.name).toContain('a1b2c3d4-e5f6-7890-abcd-ef1234567890');
    });

    it('should set Azure as provider', async () => {
      const hdf = JSON.parse(await convertMsftDefenderCloudToHdf(loadFixture('minimal.json'))) as HdfResults;
      expect(hdf.components![0]!.provider).toBe('azure');
    });
  });

  describe('MITRE ATT&CK tags', async () => {
    it('should include tactics from metadata', async () => {
      const hdf = JSON.parse(await convertMsftDefenderCloudToHdf(loadFixture('minimal.json'))) as HdfResults;
      const req0 = hdf.baselines[0]!.requirements[0]!;
      expect(req0.tags?.['tactics']).toContain('Discovery');
      expect(req0.tags?.['tactics']).toContain('Exfiltration');
    });

    it('should include techniques from metadata', async () => {
      const hdf = JSON.parse(await convertMsftDefenderCloudToHdf(loadFixture('minimal.json'))) as HdfResults;
      const req0 = hdf.baselines[0]!.requirements[0]!;
      expect(req0.tags?.['techniques']).toContain('T1046');
      expect(req0.tags?.['techniques']).toContain('T1530');
    });
  });

  describe('categories', async () => {
    it('should include categories in tags', async () => {
      const hdf = JSON.parse(await convertMsftDefenderCloudToHdf(loadFixture('minimal.json'))) as HdfResults;
      const req0 = hdf.baselines[0]!.requirements[0]!;
      expect(req0.tags?.['categories']).toContain('Networking');
    });
  });

  describe('descriptions', async () => {
    it('should include default description from metadata.description', async () => {
      const hdf = JSON.parse(await convertMsftDefenderCloudToHdf(loadFixture('minimal.json'))) as HdfResults;
      const req0 = hdf.baselines[0]!.requirements[0]!;
      const defaultDesc = req0.descriptions?.find((d: { label: string }) => d.label === 'default');
      expect(defaultDesc?.data).toContain('Private links enforce secure communication');
    });

    it('should include fix description from remediationDescription', async () => {
      const hdf = JSON.parse(await convertMsftDefenderCloudToHdf(loadFixture('minimal.json'))) as HdfResults;
      const req0 = hdf.baselines[0]!.requirements[0]!;
      const fixDesc = req0.descriptions?.find((d: { label: string }) => d.label === 'fix');
      expect(fixDesc?.data).toContain('private endpoint');
    });
  });

  describe('requirement details', async () => {
    it('should use assessment GUID as requirement ID', async () => {
      const hdf = JSON.parse(await convertMsftDefenderCloudToHdf(loadFixture('minimal.json'))) as HdfResults;
      const req0 = hdf.baselines[0]!.requirements[0]!;
      expect(req0.id).toBe('11111111-1111-1111-1111-111111111111');
    });

    it('should use displayName as title', async () => {
      const hdf = JSON.parse(await convertMsftDefenderCloudToHdf(loadFixture('minimal.json'))) as HdfResults;
      const req0 = hdf.baselines[0]!.requirements[0]!;
      expect(req0.title).toBe('Storage account should use a private link connection');
    });

    it('should include resource ID in code_desc', async () => {
      const hdf = JSON.parse(await convertMsftDefenderCloudToHdf(loadFixture('minimal.json'))) as HdfResults;
      const req0 = hdf.baselines[0]!.requirements[0]!;
      expect(req0.results[0]!.codeDesc).toContain('storageAccounts/mystorageacct');
    });

    it('should include status description as message for unhealthy', async () => {
      const hdf = JSON.parse(await convertMsftDefenderCloudToHdf(loadFixture('minimal.json'))) as HdfResults;
      const req1 = hdf.baselines[0]!.requirements[1]!;
      expect(req1.results[0]!.message).toContain('Azure Disk Encryption is not enabled');
    });
  });

  describe('empty value array', async () => {
    it('should handle empty value array', async () => {
      const hdf = JSON.parse(await convertMsftDefenderCloudToHdf(JSON.stringify({ value: [] }))) as HdfResults;
      expect(hdf.baselines[0]!.requirements).toHaveLength(0);
    });
  });
});
