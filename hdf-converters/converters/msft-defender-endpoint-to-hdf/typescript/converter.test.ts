import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { describe, it, expect } from 'vitest';
import { convertMsftDefenderEndpointToHdf } from './converter.js';
import { runConverterContractTests } from '../../../shared/typescript/converter-contract.js';
import type { HdfResults } from '@mitre/hdf-schema';

const __dirname = dirname(fileURLToPath(import.meta.url));
const FIXTURES_DIR = join(__dirname, '..', 'fixtures');

function loadFixture(name: string): string {
  return readFileSync(join(FIXTURES_DIR, 'input', name), 'utf-8');
}

runConverterContractTests({
  converterName: 'msft-defender-endpoint-to-hdf',
  convertFn: convertMsftDefenderEndpointToHdf,
  minimalFixture: 'minimal.json',
});

describe('msft-defender-endpoint to HDF converter', async () => {
  describe('error handling', async () => {
    it('should throw when value array is missing', async () => {
      await expect(convertMsftDefenderEndpointToHdf(JSON.stringify({ foo: 'bar' }))).rejects.toThrow(
        'missing or invalid value array',
      );
    });
  });

  describe('minimal fixture conversion', async () => {
    it('should produce valid HDF structure from minimal fixture', async () => {
      const output = await convertMsftDefenderEndpointToHdf(loadFixture('minimal.json'));
      const hdf = JSON.parse(output) as HdfResults;

      expect(hdf.timestamp).toBeTruthy();
      expect(hdf.generator?.name).toBe('msft-defender-endpoint-to-hdf');
      expect(hdf.generator?.version).toBe('1.0.0');
      expect(hdf.tool?.name).toBe('Microsoft Defender for Endpoint');
      expect(hdf.baselines).toHaveLength(1);
    });

    it('should convert 1 alert to 1 requirement', async () => {
      const hdf = JSON.parse(await convertMsftDefenderEndpointToHdf(loadFixture('minimal.json'))) as HdfResults;
      expect(hdf.baselines[0]!.requirements).toHaveLength(1);
    });

    it('should use alert ID as requirement ID', async () => {
      const hdf = JSON.parse(await convertMsftDefenderEndpointToHdf(loadFixture('minimal.json'))) as HdfResults;
      expect(hdf.baselines[0]!.requirements[0]!.id).toBe('da637472900382838869_1364969609');
    });
  });

  describe('sample fixture conversion', async () => {
    it('should convert 4 alerts to 4 requirements', async () => {
      const hdf = JSON.parse(await convertMsftDefenderEndpointToHdf(loadFixture('sample.json'))) as HdfResults;
      expect(hdf.baselines[0]!.requirements).toHaveLength(4);
    });
  });

  describe('status mapping', async () => {
    it('should map "new" status to failed', async () => {
      const hdf = JSON.parse(await convertMsftDefenderEndpointToHdf(loadFixture('minimal.json'))) as HdfResults;
      expect(hdf.baselines[0]!.requirements[0]!.results[0]!.status).toBe('failed');
    });

    it('should map "inProgress" status to failed', async () => {
      const hdf = JSON.parse(await convertMsftDefenderEndpointToHdf(loadFixture('sample.json'))) as HdfResults;
      expect(hdf.baselines[0]!.requirements[1]!.results[0]!.status).toBe('failed');
    });

    it('should map "resolved" with falsePositive classification to passed', async () => {
      const hdf = JSON.parse(await convertMsftDefenderEndpointToHdf(loadFixture('sample.json'))) as HdfResults;
      expect(hdf.baselines[0]!.requirements[2]!.results[0]!.status).toBe('passed');
    });

    it('should map "resolved" with truePositive classification to failed', async () => {
      const hdf = JSON.parse(await convertMsftDefenderEndpointToHdf(loadFixture('sample.json'))) as HdfResults;
      expect(hdf.baselines[0]!.requirements[3]!.results[0]!.status).toBe('failed');
    });
  });

  describe('severity mapping', async () => {
    it('should map "high" severity to 0.7', async () => {
      const hdf = JSON.parse(await convertMsftDefenderEndpointToHdf(loadFixture('sample.json'))) as HdfResults;
      expect(hdf.baselines[0]!.requirements[0]!.impact).toBe(0.7);
    });

    it('should map "medium" severity to 0.5', async () => {
      const hdf = JSON.parse(await convertMsftDefenderEndpointToHdf(loadFixture('sample.json'))) as HdfResults;
      expect(hdf.baselines[0]!.requirements[1]!.impact).toBe(0.5);
    });

    it('should map "low" severity to 0.3', async () => {
      const hdf = JSON.parse(await convertMsftDefenderEndpointToHdf(loadFixture('minimal.json'))) as HdfResults;
      expect(hdf.baselines[0]!.requirements[0]!.impact).toBe(0.3);
    });

    it('should map "informational" severity to 0.0', async () => {
      const hdf = JSON.parse(await convertMsftDefenderEndpointToHdf(loadFixture('sample.json'))) as HdfResults;
      expect(hdf.baselines[0]!.requirements[2]!.impact).toBe(0.0);
    });
  });

  describe('targets', async () => {
    it('should create Host target from device evidence', async () => {
      const hdf = JSON.parse(await convertMsftDefenderEndpointToHdf(loadFixture('minimal.json'))) as HdfResults;
      expect(hdf.components).toBeDefined();
      expect(hdf.components!.length).toBeGreaterThan(0);
      expect(hdf.components![0]!.type).toBe('host');
      expect(hdf.components![0]!.name).toBe('temp123.middleeast.corp.microsoft.com');
      expect(hdf.components![0]!.fqdn).toBe('temp123.middleeast.corp.microsoft.com');
      expect(hdf.components![0]!.osName).toBe('Windows10');
    });

    it('should deduplicate targets by name', async () => {
      const hdf = JSON.parse(await convertMsftDefenderEndpointToHdf(loadFixture('sample.json'))) as HdfResults;
      // 4 alerts with 4 different devices → 4 targets
      expect(hdf.components).toHaveLength(4);
    });
  });

  describe('MITRE ATT&CK techniques', async () => {
    it('should include MITRE techniques in tags', async () => {
      const hdf = JSON.parse(await convertMsftDefenderEndpointToHdf(loadFixture('minimal.json'))) as HdfResults;
      const tags = hdf.baselines[0]!.requirements[0]!.tags!;
      const mitre = tags['mitre'] as string[];
      expect(mitre).toContain('T1064');
      expect(mitre).toContain('T1085');
      expect(mitre).toContain('T1220');
    });

    it('should omit mitre tag when no techniques present', async () => {
      const hdf = JSON.parse(await convertMsftDefenderEndpointToHdf(loadFixture('sample.json'))) as HdfResults;
      const tags = hdf.baselines[0]!.requirements[2]!.tags!;
      expect(tags['mitre']).toBeUndefined();
    });
  });

  describe('category tag', async () => {
    it('should include category in tags', async () => {
      const hdf = JSON.parse(await convertMsftDefenderEndpointToHdf(loadFixture('minimal.json'))) as HdfResults;
      const tags = hdf.baselines[0]!.requirements[0]!.tags!;
      expect(tags['category']).toBe('Execution');
    });
  });

  describe('descriptions', async () => {
    it('should include default description from alert description', async () => {
      const hdf = JSON.parse(await convertMsftDefenderEndpointToHdf(loadFixture('minimal.json'))) as HdfResults;
      const descs = hdf.baselines[0]!.requirements[0]!.descriptions!;
      const defaultDesc = descs.find(d => d.label === 'default');
      expect(defaultDesc?.data).toContain('Binaries signed by Microsoft');
    });

    it('should include fix description from recommendedActions', async () => {
      const hdf = JSON.parse(await convertMsftDefenderEndpointToHdf(loadFixture('minimal.json'))) as HdfResults;
      const descs = hdf.baselines[0]!.requirements[0]!.descriptions!;
      const fixDesc = descs.find(d => d.label === 'fix');
      expect(fixDesc?.data).toContain('Collect artifacts');
    });
  });

  describe('evidence in code_desc', async () => {
    it('should include device and process evidence in code_desc', async () => {
      const hdf = JSON.parse(await convertMsftDefenderEndpointToHdf(loadFixture('minimal.json'))) as HdfResults;
      const codeDesc = hdf.baselines[0]!.requirements[0]!.results[0]!.codeDesc ?? '';
      expect(codeDesc).toContain('Device: temp123.middleeast.corp.microsoft.com');
      expect(codeDesc).toContain('rundll32.exe');
    });
  });

  describe('classification and determination', async () => {
    it('should include classification and determination in tags when present', async () => {
      const hdf = JSON.parse(await convertMsftDefenderEndpointToHdf(loadFixture('sample.json'))) as HdfResults;
      const tags = hdf.baselines[0]!.requirements[3]!.tags!;
      expect(tags['classification']).toBe('truePositive');
      expect(tags['determination']).toBe('malware');
    });

    it('should omit classification and determination when null', async () => {
      const hdf = JSON.parse(await convertMsftDefenderEndpointToHdf(loadFixture('minimal.json'))) as HdfResults;
      const tags = hdf.baselines[0]!.requirements[0]!.tags!;
      expect(tags['classification']).toBeUndefined();
      expect(tags['determination']).toBeUndefined();
    });
  });

  describe('checksum', async () => {
    it('should include sha256 checksum', async () => {
      const hdf = JSON.parse(await convertMsftDefenderEndpointToHdf(loadFixture('minimal.json'))) as HdfResults;
      const checksum = hdf.baselines[0]!.resultsChecksum;
      expect(checksum?.algorithm).toBe('sha256');
      expect(checksum?.value).toMatch(/^[a-f0-9]{64}$/);
    });
  });

  describe('empty value array', async () => {
    it('should handle empty value array', async () => {
      const hdf = JSON.parse(await convertMsftDefenderEndpointToHdf(JSON.stringify({ value: [] }))) as HdfResults;
      expect(hdf.baselines[0]!.requirements).toHaveLength(0);
    });
  });

  describe('baseline name', async () => {
    it('should use "Microsoft Defender for Endpoint Scan" as baseline name', async () => {
      const hdf = JSON.parse(await convertMsftDefenderEndpointToHdf(loadFixture('minimal.json'))) as HdfResults;
      expect(hdf.baselines[0]!.name).toBe('Microsoft Defender for Endpoint Scan');
    });
  });
});
