import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { describe, it, expect } from 'vitest';
import { convertCyclonedxToHdf } from './converter.js';
import { runConverterContractTests } from '../../../shared/typescript/converter-contract.js';
import type { HDFResults } from '@mitre/hdf-schema';

const __dirname = dirname(fileURLToPath(import.meta.url));
const FIXTURES_DIR = join(__dirname, '..', 'fixtures');

function loadFixture(name: string): string {
  return readFileSync(join(FIXTURES_DIR, 'input', name), 'utf-8');
}

runConverterContractTests({
  converterName: 'cyclonedx-to-hdf',
  convertFn: convertCyclonedxToHdf,
  minimalFixture: 'minimal-vulns.json',
});

describe('cyclonedx to HDF converter', async () => {
  describe('input validation', async () => {
    it('should throw on missing bomFormat', async () => {
      await expect(
        convertCyclonedxToHdf(JSON.stringify({ specVersion: '1.5' }))
      ).rejects.toThrow('bomFormat');
    });

    it('should throw on missing both components and vulnerabilities', async () => {
      await expect(
        convertCyclonedxToHdf(
          JSON.stringify({ bomFormat: 'CycloneDX', specVersion: '1.5' })
        )
      ).rejects.toThrow();
    });
  });

  describe('conversion basics', async () => {
    it('should produce valid HDF from minimal fixture', async () => {
      const output = await convertCyclonedxToHdf(
        loadFixture('minimal-vulns.json')
      );
      const hdf = JSON.parse(output) as HDFResults;

      expect(hdf.timestamp).toBeTruthy();
      expect(hdf.baselines).toHaveLength(1);
      // minimal-vulns.json has 3 vulnerabilities
      expect(hdf.baselines[0]!.requirements).toHaveLength(3);
    });

    it('should use "CycloneDX Scan" as the baseline name', async () => {
      const hdf = JSON.parse(
        await convertCyclonedxToHdf(loadFixture('minimal-vulns.json'))
      ) as HDFResults;
      expect(hdf.baselines[0]!.name).toBe('CycloneDX Scan');
    });

    it('should include a sha256 checksum', async () => {
      const hdf = JSON.parse(
        await convertCyclonedxToHdf(loadFixture('minimal-vulns.json'))
      ) as HDFResults;
      const checksum = hdf.baselines[0]!.resultsChecksum;
      expect(checksum?.algorithm).toBe('sha256');
      expect(checksum?.value).toMatch(/^[a-f0-9]{64}$/);
    });
  });

  describe('generator and dataSource', async () => {
    it('should set generator name and version', async () => {
      const hdf = JSON.parse(
        await convertCyclonedxToHdf(loadFixture('minimal-vulns.json'))
      ) as HDFResults;
      expect(hdf.generator?.name).toBe('cyclonedx-to-hdf');
      expect(hdf.generator?.version).toBe('1.0.0');
    });

    it('should set dataSource name to "CycloneDX" and format to "JSON"', async () => {
      const hdf = JSON.parse(
        await convertCyclonedxToHdf(loadFixture('minimal-vulns.json'))
      ) as HDFResults;
      expect(hdf.tool?.name).toBe('CycloneDX');
      expect(hdf.tool?.format).toBe('JSON');
    });
  });

  describe('impact from CVSS score', async () => {
    it('should compute impact from CVSS score (max of ratings)', async () => {
      // vex.json has ratings with scores: 7.5, 8.2, 0.0
      // max CVSS score = 8.2, impact = 8.2 / 10 = 0.82
      const hdf = JSON.parse(
        await convertCyclonedxToHdf(loadFixture('vex.json'))
      ) as HDFResults;
      const req = hdf.baselines[0]!.requirements[0]!;
      expect(req.impact).toBeCloseTo(0.82, 2);
    });
  });

  describe('impact from severity string', async () => {
    it('should map low severity to 0.3', async () => {
      const hdf = JSON.parse(
        await convertCyclonedxToHdf(loadFixture('minimal-vulns.json'))
      ) as HDFResults;
      const low = hdf.baselines[0]!.requirements.find(
        (r) => r.id === 'GHSA-5mg8-w23w-74h3'
      );
      expect(low?.impact).toBe(0.3);
    });

    it('should map medium severity to 0.5', async () => {
      const hdf = JSON.parse(
        await convertCyclonedxToHdf(loadFixture('minimal-vulns.json'))
      ) as HDFResults;
      const medium = hdf.baselines[0]!.requirements.find(
        (r) => r.id === 'GHSA-7g45-4rm6-3mm3'
      );
      expect(medium?.impact).toBe(0.5);
    });

    it('should map critical severity to 0.9', async () => {
      const hdf = JSON.parse(
        await convertCyclonedxToHdf(loadFixture('minimal-vulns.json'))
      ) as HDFResults;
      const critical = hdf.baselines[0]!.requirements.find(
        (r) => r.id === 'GHSA-5p34-5m6p-p58g'
      );
      expect(critical?.impact).toBe(0.9);
    });
  });

  describe('CWE to NIST mapping', async () => {
    it('should map CWE to NIST controls', async () => {
      // vex.json has cwes: [611]
      const hdf = JSON.parse(
        await convertCyclonedxToHdf(loadFixture('vex.json'))
      ) as HDFResults;
      const req = hdf.baselines[0]!.requirements[0]!;
      const nist = req.tags?.['nist'] as string[];
      expect(nist).toBeDefined();
      expect(nist.length).toBeGreaterThan(0);
    });

    it('should fall back to default NIST tags when no CWE mapping exists', async () => {
      // Construct input with a CWE that has no mapping (99999)
      const input = JSON.stringify({
        bomFormat: 'CycloneDX',
        specVersion: '1.5',
        vulnerabilities: [
          {
            id: 'TEST-NO-MAPPING',
            ratings: [{ severity: 'high' }],
            cwes: [99999],
            affects: [{ ref: 'comp-1' }],
          },
        ],
        components: [{ type: 'library', name: 'test-lib', 'bom-ref': 'comp-1' }],
      });
      const hdf = JSON.parse(
        await convertCyclonedxToHdf(input)
      ) as HDFResults;
      const nist = hdf.baselines[0]!.requirements[0]!.tags?.['nist'] as string[];
      expect(nist).toContain('SA-11');
      expect(nist).toContain('RA-5');
    });
  });

  describe('tags', async () => {
    it('should populate nist, cci, cweid, and ratings tags', async () => {
      const hdf = JSON.parse(
        await convertCyclonedxToHdf(loadFixture('vex.json'))
      ) as HDFResults;
      const req = hdf.baselines[0]!.requirements[0]!;
      const tags = req.tags;

      expect(tags?.['nist']).toBeDefined();
      expect((tags?.['nist'] as string[]).length).toBeGreaterThan(0);
      expect(tags?.['cci']).toBeDefined();
      expect((tags?.['cci'] as string[]).length).toBeGreaterThan(0);
      expect(tags?.['cweid']).toContain('CWE-611');
      expect(tags?.['ratings']).toContain('NVD - high');
    });
  });

  describe('result code_desc', async () => {
    it('should format code_desc with group/name@version', async () => {
      const hdf = JSON.parse(
        await convertCyclonedxToHdf(loadFixture('minimal-vulns.json'))
      ) as HDFResults;
      // GHSA-5mg8-w23w-74h3 affects guava (com.google.guava/guava@24.1.1-jre)
      const req = hdf.baselines[0]!.requirements.find(
        (r) => r.id === 'GHSA-5mg8-w23w-74h3'
      );
      expect(req).toBeDefined();
      expect(req!.results[0]?.codeDesc).toContain('com.google.guava/guava@24.1.1-jre');
      expect(req!.results[0]?.codeDesc).toContain('is vulnerable');
    });

    it('should handle components without group or version', async () => {
      const input = JSON.stringify({
        bomFormat: 'CycloneDX',
        specVersion: '1.5',
        vulnerabilities: [
          {
            id: 'TEST-NO-GROUP',
            ratings: [{ severity: 'high' }],
            affects: [{ ref: 'comp-1' }],
          },
        ],
        components: [
          { type: 'library', name: 'bare-lib', 'bom-ref': 'comp-1' },
        ],
      });
      const hdf = JSON.parse(
        await convertCyclonedxToHdf(input)
      ) as HDFResults;
      const codeDesc = hdf.baselines[0]!.requirements[0]!.results[0]?.codeDesc ?? '';
      expect(codeDesc).toBe('Component bare-lib is vulnerable');
    });
  });

  describe('result status', async () => {
    it('should mark all results as failed by default', async () => {
      const hdf = JSON.parse(
        await convertCyclonedxToHdf(loadFixture('minimal-vulns.json'))
      ) as HDFResults;
      for (const req of hdf.baselines[0]!.requirements) {
        for (const result of req.results) {
          expect(result.status).toBe('failed');
        }
      }
    });
  });

  describe('info/unknown severity — still Failed', async () => {
    it('should mark info/unknown severity vulns as Failed', async () => {
      const input = JSON.stringify({
        bomFormat: 'CycloneDX',
        specVersion: '1.5',
        vulnerabilities: [
          {
            id: 'TEST-INFO-ONLY',
            ratings: [{ severity: 'info' }],
            affects: [{ ref: 'comp-1' }],
          },
          {
            id: 'TEST-UNKNOWN-ONLY',
            ratings: [{ severity: 'unknown' }],
            affects: [{ ref: 'comp-1' }],
          },
        ],
        components: [
          { type: 'library', name: 'test-lib', 'bom-ref': 'comp-1' },
        ],
      });
      const hdf = JSON.parse(
        await convertCyclonedxToHdf(input)
      ) as HDFResults;
      // Info/unknown severity vulns are still Failed — a vuln is a finding
      // regardless of severity confidence. Impact reflects the severity.
      for (const req of hdf.baselines[0]!.requirements) {
        for (const result of req.results) {
          expect(result.status).toBe('failed');
        }
      }
    });

    it('should also mark mixed severity vulns as Failed', async () => {
      const input = JSON.stringify({
        bomFormat: 'CycloneDX',
        specVersion: '1.5',
        vulnerabilities: [
          {
            id: 'TEST-MIXED',
            ratings: [
              { severity: 'info' },
              { severity: 'high' },
            ],
            affects: [{ ref: 'comp-1' }],
          },
        ],
        components: [
          { type: 'library', name: 'test-lib', 'bom-ref': 'comp-1' },
        ],
      });
      const hdf = JSON.parse(
        await convertCyclonedxToHdf(input)
      ) as HDFResults;
      expect(hdf.baselines[0]!.requirements[0]!.results[0]?.status).toBe('failed');
    });
  });

  describe('no-vuln SBOM', async () => {
    it('should reject SBOM-only input with helpful message', async () => {
      await expect(
        convertCyclonedxToHdf(loadFixture('spdx-to-cyclonedx.json'))
      ).rejects.toThrow('SBOM inventory with no vulnerabilities');
    });
  });

  describe('VEX format', async () => {
    it('should handle pure VEX input (no components)', async () => {
      const hdf = JSON.parse(
        await convertCyclonedxToHdf(loadFixture('vex.json'))
      ) as HDFResults;
      expect(hdf.baselines[0]!.requirements).toHaveLength(1);
      expect(hdf.baselines[0]!.requirements[0]!.id).toBe('CVE-2020-25649');
    });

    it('should use bom-ref as component name in VEX code_desc', async () => {
      const hdf = JSON.parse(
        await convertCyclonedxToHdf(loadFixture('vex.json'))
      ) as HDFResults;
      const codeDesc =
        hdf.baselines[0]!.requirements[0]!.results[0]?.codeDesc ?? '';
      // VEX has no components, so falls back to the ref string from affects
      expect(codeDesc).toContain('is vulnerable');
    });
  });

  describe('descriptions', async () => {
    it('should include fix label from recommendation', async () => {
      const hdf = JSON.parse(
        await convertCyclonedxToHdf(loadFixture('vex.json'))
      ) as HDFResults;
      const req = hdf.baselines[0]!.requirements[0]!;
      const fixDesc = req.descriptions?.find((d) => d.label === 'fix');
      expect(fixDesc).toBeDefined();
      expect(fixDesc!.data).toContain('Upgrade');
    });

    it('should include default label from description and detail', async () => {
      const hdf = JSON.parse(
        await convertCyclonedxToHdf(loadFixture('vex.json'))
      ) as HDFResults;
      const req = hdf.baselines[0]!.requirements[0]!;
      const defaultDesc = req.descriptions?.find((d) => d.label === 'default');
      expect(defaultDesc).toBeDefined();
      expect(defaultDesc!.data).toContain('jackson-databind');
      expect(defaultDesc!.data).toContain('XXE Injection');
    });
  });

  describe('full fixture smoke test', async () => {
    it('should convert dropwizard-vulns.json with 87 requirements', async () => {
      const hdf = JSON.parse(
        await convertCyclonedxToHdf(loadFixture('dropwizard-vulns.json'))
      ) as HDFResults;
      expect(hdf.baselines[0]!.requirements).toHaveLength(87);
      // Every requirement should have at least one result
      for (const req of hdf.baselines[0]!.requirements) {
        expect(req.results.length).toBeGreaterThan(0);
      }
    });
  });
});
