import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, it, expect } from 'vitest';
import { convertMsftDefenderDevopsToHdf } from './converter.js';
import { runConverterContractTests } from '../../../shared/typescript/converter-contract.js';
import type { HdfResults } from '@mitre/hdf-schema';

function loadFixture(name: string): string {
  return readFileSync(join(__dirname, '..', 'fixtures', name), 'utf-8');
}

runConverterContractTests({
  converterName: 'msft-defender-devops-to-hdf',
  convertFn: convertMsftDefenderDevopsToHdf,
  minimalFixture: 'minimal.sarif',
});

describe('msft-defender-devops-to-hdf', () => {
  // ---- Error handling ----

  describe('error handling', () => {
    it('should reject JSON without runs', async () => {
      await expect(convertMsftDefenderDevopsToHdf('{"version": "2.1.0"}')).rejects.toThrow();
    });
  });

  // ---- Minimal fixture ----

  describe('minimal fixture', () => {
    it('should produce 2 baselines from 2 runs', async () => {
      const input = loadFixture('input/minimal.sarif');
      const result = JSON.parse(await convertMsftDefenderDevopsToHdf(input)) as HdfResults;

      expect(result.baselines).toHaveLength(2);
      expect(result.baselines![0]!.requirements!.length).toBeGreaterThan(0);
      expect(result.baselines![1]!.requirements!.length).toBeGreaterThan(0);
    });
  });

  // ---- Full SDA fixture ----

  describe('full SDA fixture', () => {
    it('should produce 7 baselines with correct tool names', async () => {
      const input = loadFixture('input/sda.sarif');
      const result = JSON.parse(await convertMsftDefenderDevopsToHdf(input)) as HdfResults;

      expect(result.baselines).toHaveLength(7);

      const expectedNames = [
        'antimalware', 'bandit', 'credscan', 'eslint',
        'iacfilescanner', 'templateanalyzer', 'checkov',
      ];
      for (let i = 0; i < expectedNames.length; i++) {
        expect(result.baselines![i]!.name).toBe(expectedNames[i]);
      }
    });
  });

  // ---- Repository target ----

  describe('repository target', () => {
    it('should extract target from versionControlProvenance', async () => {
      const input = loadFixture('input/minimal.sarif');
      const result = JSON.parse(await convertMsftDefenderDevopsToHdf(input)) as HdfResults;

      expect(result.components).toBeDefined();
      expect(result.components!.length).toBeGreaterThan(0);

      const target = result.components![0]!;
      expect(target.type).toBe('repository');
      expect(target.name).toBe('security-devops-action');
      expect(target.url).toContain('github.com');
      expect(target.branch).toBe('main');
      expect(target.commit).toBeDefined();
      expect(target.commit!.length).toBeGreaterThan(0);
    });

    it('should deduplicate targets across runs', async () => {
      const input = loadFixture('input/sda.sarif');
      const result = JSON.parse(await convertMsftDefenderDevopsToHdf(input)) as HdfResults;

      // All 7 runs reference the same repo
      expect(result.components).toHaveLength(1);
    });
  });

  // ---- Tool metadata tags ----

  describe('tool metadata', () => {
    it('should include organization, product, fullName for credscan', async () => {
      const input = loadFixture('input/minimal.sarif');
      const result = JSON.parse(await convertMsftDefenderDevopsToHdf(input)) as HdfResults;

      const req = result.baselines![0]!.requirements![0]!;
      const tags = req.tags as Record<string, unknown>;

      expect(tags.msdo_organization).toBe('Microsoft Corporation');
      expect(tags.msdo_product).toBe('Microsoft Security Credential Scanner Client');
      expect(tags.msdo_fullName).toBe('CredentialScanner 2.5.1.13');
      expect(tags.msdo_rawName).toBe('credscan');
    });

    it('should include only RawName for checkov', async () => {
      const input = loadFixture('input/minimal.sarif');
      const result = JSON.parse(await convertMsftDefenderDevopsToHdf(input)) as HdfResults;

      const req = result.baselines![1]!.requirements![0]!;
      const tags = req.tags as Record<string, unknown>;

      expect(tags.msdo_rawName).toBe('checkov');
      expect(tags.msdo_organization).toBeUndefined();
    });
  });

  // ---- Policy tag ----

  describe('policy tag', () => {
    it('should store policy in requirement tags', async () => {
      const input = loadFixture('input/minimal.sarif');
      const result = JSON.parse(await convertMsftDefenderDevopsToHdf(input)) as HdfResults;

      const req = result.baselines![0]!.requirements![0]!;
      const tags = req.tags as Record<string, unknown>;

      expect(tags.msdo_policy).toBe('Microsoft 2.0.3');
    });
  });

  // ---- Result properties ----

  describe('result properties', () => {
    it('should include CredScan result-level properties', async () => {
      const input = loadFixture('input/minimal.sarif');
      const result = JSON.parse(await convertMsftDefenderDevopsToHdf(input)) as HdfResults;

      const req = result.baselines![0]!.requirements![0]!;
      const tags = req.tags as Record<string, unknown>;
      const props = tags.msdo_properties as Record<string, unknown>;

      expect(props).toBeDefined();
      expect(props.DefectCode).toBe('SecretInFile');
      expect(props.MatchingScore).toBeDefined();
      expect(props.Risk).toBeDefined();
      expect(props.Validation).toBe('NoValidationRequested');
    });
  });

  // ---- Generator name ----

  describe('generator', () => {
    it('should use msft-defender-devops-to-hdf generator name', async () => {
      const input = loadFixture('input/minimal.sarif');
      const result = JSON.parse(await convertMsftDefenderDevopsToHdf(input)) as HdfResults;

      expect(result.generator?.name).toBe('msft-defender-devops-to-hdf');
    });
  });

  // ---- Data source ----

  describe('data source', () => {
    it('should use Microsoft Defender for DevOps as data source name', async () => {
      const input = loadFixture('input/minimal.sarif');
      const result = JSON.parse(await convertMsftDefenderDevopsToHdf(input)) as HdfResults;

      expect(result.tool?.name).toBe('Microsoft Defender for DevOps');
    });
  });

  // ---- Delegates base SARIF ----

  describe('base SARIF delegation', () => {
    it('should preserve standard SARIF tags (nist, severity)', async () => {
      const input = loadFixture('input/minimal.sarif');
      const result = JSON.parse(await convertMsftDefenderDevopsToHdf(input)) as HdfResults;

      const req = result.baselines![1]!.requirements![0]!;
      const tags = req.tags as Record<string, unknown>;

      expect(tags.nist).toBeDefined();
      expect(tags.severity).toBeDefined();
    });
  });
});
