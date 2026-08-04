import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { describe, it, expect } from 'vitest';
import { convertCyclonedxToHdf } from './converter.js';
import { runConverterContractTests } from '../../../shared/typescript/converter-contract.js';
import { expectValidResults } from '../../../test/helpers/expectValidHdf.js';
import {
  assertRequirementCount,
  countJsonItemsUnderKey,
} from '../../../shared/typescript/anchor.js';
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

// Ground-truth anchor (input-derived count; see shared/typescript/anchor.ts):
// one requirement per BOM vulnerabilities[] entry (no grouping/dedup), counted
// independently of the converter's parser so a silent under-extraction fails even
// when Go/TS agree. dropwizard-vulns.json carries 87 vulnerabilities.
describe('cyclonedx-to-hdf ground-truth anchor', () => {
  it('emits one requirement per vulnerabilities[] entry', async () => {
    const input = loadFixture('dropwizard-vulns.json');
    assertRequirementCount(
      await convertCyclonedxToHdf(input),
      countJsonItemsUnderKey(input, 'vulnerabilities'),
      'dropwizard-vulns.json: one requirement per vulnerabilities[]',
    );
  });
});

describe('timestamp parse fallback', () => {
  it('uses conversion time when the BOM metadata timestamp is unparseable', async () => {
    const input = loadFixture('minimal-vulns.json').replace(/2024-07-08T17:30:28Z/g, 'not-a-date');
    const hdf = JSON.parse(await convertCyclonedxToHdf(input)) as HDFResults;
    expectValidResults(hdf);
  });
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

      expectValidResults(hdf);
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

    it('should set dataSource name to "CycloneDX" with no format', async () => {
      const hdf = JSON.parse(
        await convertCyclonedxToHdf(loadFixture('minimal-vulns.json'))
      ) as HDFResults;
      expect(hdf.tool?.name).toBe('CycloneDX');
      expect(hdf.tool?.format).toBeUndefined() // serialization structures are not formats (kpvj);
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
    it('should populate nist and cci tags and drop the old scoring tags', async () => {
      const hdf = JSON.parse(
        await convertCyclonedxToHdf(loadFixture('vex.json'))
      ) as HDFResults;
      const req = hdf.baselines[0]!.requirements[0]!;
      const tags = req.tags;

      expect(tags?.['nist']).toBeDefined();
      expect((tags?.['nist'] as string[]).length).toBeGreaterThan(0);
      expect(tags?.['cci']).toBeDefined();
      expect((tags?.['cci'] as string[]).length).toBeGreaterThan(0);
      // Moved to structured requirement.cwe[] / requirement.cvss[].
      expect(tags?.['cweid']).toBeUndefined();
      expect(tags?.['ratings']).toBeUndefined();
    });
  });

  describe('structured CVSS', async () => {
    it('should map CVSS ratings to requirement.cvss[]', async () => {
      const hdf = JSON.parse(
        await convertCyclonedxToHdf(loadFixture('vex.json'))
      ) as HDFResults;
      const req = hdf.baselines[0]!.requirements[0]!;
      const cvss = req.cvss;
      expect(cvss).toHaveLength(3);

      expect(cvss![0]!.baseScore).toBeCloseTo(7.5, 2);
      expect(cvss![0]!.baseSeverity).toBe('high');
      expect(cvss![0]!.version).toBe('3.1');
      expect(cvss![0]!.baseVector).toBe('AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N');
      expect(cvss![0]!.source).toBe('NVD');

      expect(cvss![1]!.baseScore).toBeCloseTo(8.2, 2);
      expect(cvss![1]!.source).toBe('SNYK');

      expect(cvss![2]!.baseScore).toBeCloseTo(0.0, 2);
      expect(cvss![2]!.baseSeverity).toBe('none');
    });

    it('should omit cvss[] when ratings carry no CVSS metrics', async () => {
      const hdf = JSON.parse(
        await convertCyclonedxToHdf(loadFixture('minimal-vulns.json'))
      ) as HDFResults;
      for (const req of hdf.baselines[0]!.requirements) {
        expect(req.cvss).toBeUndefined();
      }
    });

    it('should emit a vector-only entry with defaulted version and no source', async () => {
      const input = JSON.stringify({
        bomFormat: 'CycloneDX',
        specVersion: '1.5',
        vulnerabilities: [
          {
            id: 'TEST-VECTOR-ONLY',
            ratings: [
              { method: 'CVSSv3', vector: 'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' },
            ],
            affects: [{ ref: 'comp-1' }],
          },
        ],
        components: [{ type: 'library', name: 'test-lib', 'bom-ref': 'comp-1' }],
      });
      const hdf = JSON.parse(await convertCyclonedxToHdf(input)) as HDFResults;
      const cvss = hdf.baselines[0]!.requirements[0]!.cvss;
      expect(cvss).toHaveLength(1);
      expect(cvss![0]!.baseScore).toBeUndefined();
      expect(cvss![0]!.source).toBeUndefined();
      expect(cvss![0]!.version).toBe('3.1');
      expect(cvss![0]!.baseVector).toBe('AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H');
    });
  });

  describe('structured CWE', async () => {
    it('should map cwes to requirement.cwe[] and keep the NIST mapping', async () => {
      const hdf = JSON.parse(
        await convertCyclonedxToHdf(loadFixture('vex.json'))
      ) as HDFResults;
      const req = hdf.baselines[0]!.requirements[0]!;
      expect(req.cwe).toEqual(['CWE-611']);
      expect((req.tags?.['nist'] as string[]).length).toBeGreaterThan(0);
    });

    it('should carry all CWE ids for multi-CWE findings', async () => {
      const hdf = JSON.parse(
        await convertCyclonedxToHdf(loadFixture('minimal-vulns.json'))
      ) as HDFResults;
      const req = hdf.baselines[0]!.requirements.find(
        (r) => r.id === 'GHSA-5mg8-w23w-74h3'
      );
      expect(req!.cwe).toEqual(['CWE-173', 'CWE-200', 'CWE-378', 'CWE-732']);
    });

    it('should omit cwe[] when the vulnerability has no cwes', async () => {
      const input = JSON.stringify({
        bomFormat: 'CycloneDX',
        specVersion: '1.5',
        vulnerabilities: [
          {
            id: 'TEST-NO-CWE',
            ratings: [{ severity: 'high' }],
            affects: [{ ref: 'comp-1' }],
          },
        ],
        components: [{ type: 'library', name: 'test-lib', 'bom-ref': 'comp-1' }],
      });
      const hdf = JSON.parse(await convertCyclonedxToHdf(input)) as HDFResults;
      expect(hdf.baselines[0]!.requirements[0]!.cwe).toBeUndefined();
    });
  });

  describe('external references (refs[])', async () => {
    it('should collect source.url, references[].source.url, and advisories[].url de-duplicated in order', async () => {
      const hdf = JSON.parse(
        await convertCyclonedxToHdf(loadFixture('vex.json'))
      ) as HDFResults;
      const req = hdf.baselines[0]!.requirements[0]!;
      expect(req.refs?.map((r) => r.url)).toEqual([
        'https://nvd.nist.gov/vuln/detail/CVE-2020-25649',
        'https://security.snyk.io/vuln/SNYK-JAVA-COMFASTERXMLJACKSONCORE-1048302',
        'https://github.com/FasterXML/jackson-databind/commit/612f971b78c60202e9cd75a299050c8f2d724a59',
        'https://github.com/FasterXML/jackson-databind/issues/2589',
        'https://bugzilla.redhat.com/show_bug.cgi?id=1887664',
      ]);
    });

    it('should emit a single ref when only source.url is present', async () => {
      const hdf = JSON.parse(
        await convertCyclonedxToHdf(loadFixture('minimal-vulns.json'))
      ) as HDFResults;
      const req = hdf.baselines[0]!.requirements.find(
        (r) => r.id === 'GHSA-5mg8-w23w-74h3'
      );
      expect(req!.refs?.map((r) => r.url)).toEqual(['https://github.com/advisories']);
    });

    it('should omit refs[] when the vulnerability carries no links', async () => {
      const input = JSON.stringify({
        bomFormat: 'CycloneDX',
        specVersion: '1.5',
        vulnerabilities: [
          {
            id: 'TEST-NO-REFS',
            ratings: [{ severity: 'high' }],
            affects: [{ ref: 'comp-1' }],
          },
        ],
        components: [{ type: 'library', name: 'test-lib', 'bom-ref': 'comp-1' }],
      });
      const hdf = JSON.parse(await convertCyclonedxToHdf(input)) as HDFResults;
      expect(hdf.baselines[0]!.requirements[0]!.refs).toBeUndefined();
    });

    it('should de-dup across sources, skip empty urls, and tolerate references without a source', async () => {
      const input = JSON.stringify({
        bomFormat: 'CycloneDX',
        specVersion: '1.5',
        vulnerabilities: [
          {
            id: 'TEST-DEDUP',
            source: { name: 'NVD', url: 'https://example.com/a' },
            references: [
              { id: 'REF-NO-SOURCE' },
              { id: 'REF-1', source: { name: 'SNYK', url: 'https://example.com/b' } },
            ],
            advisories: [
              { title: 'dup', url: 'https://example.com/a' },
              { title: 'empty', url: '' },
              { title: 'new', url: 'https://example.com/c' },
            ],
            affects: [{ ref: 'comp-1' }],
          },
        ],
        components: [{ type: 'library', name: 'test-lib', 'bom-ref': 'comp-1' }],
      });
      const hdf = JSON.parse(await convertCyclonedxToHdf(input)) as HDFResults;
      expect(hdf.baselines[0]!.requirements[0]!.refs?.map((r) => r.url)).toEqual([
        'https://example.com/a',
        'https://example.com/b',
        'https://example.com/c',
      ]);
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

    it('should reject SBOM-only input with the positional system-create syntax', async () => {
      await expect(
        convertCyclonedxToHdf(loadFixture('spdx-to-cyclonedx.json'))
      ).rejects.toThrow('hdf system create <sbom-file> --component-name <name>');
    });

    it('should reject a no-vuln AI-BOM with an AI-BOM-specific message', async () => {
      const input = JSON.stringify({
        bomFormat: 'CycloneDX',
        specVersion: '1.6',
        components: [
          {
            type: 'machine-learning-model',
            name: 'stable-diffusion',
            'bom-ref': 'model-a',
          },
        ],
      });
      await expect(convertCyclonedxToHdf(input)).rejects.toThrow(
        'hdf system create <file> --from cyclonedx-mlbom'
      );
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

  describe('boms[].document byte parity', async () => {
    const pickDocument = (r: HDFResults): Record<string, unknown> | undefined =>
      (r.components?.[0]?.boms?.[0] as { document?: Record<string, unknown> })
        ?.document;

    // The Go converter serializes the passthrough via json.Marshal, which sorts
    // map keys in code-point order; without canonicalize the TS side keeps source
    // insertion order. Re-stringifying both documents isolates key order (it
    // normalizes away pretty-print whitespace and Go's HTML-escaping, which are
    // separate axes), so this pins the canonicalize call that keeps the two
    // languages' key ordering identical against a genuine Go-produced golden.
    it('emits boms[].document keys in Go json.Marshal order (matches the Go golden)', async () => {
      const tsDoc = pickDocument(
        JSON.parse(
          await convertCyclonedxToHdf(loadFixture('minimal-vulns.json'))
        ) as HDFResults
      );
      const goDoc = pickDocument(
        JSON.parse(
          readFileSync(
            join(FIXTURES_DIR, 'expected', 'minimal-vulns.json.hdf.json'),
            'utf-8'
          )
        ) as HDFResults
      );

      expect(tsDoc).toBeDefined();
      expect(goDoc).toBeDefined();
      expect(JSON.stringify(tsDoc)).toBe(JSON.stringify(goDoc));
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

  describe('component boms[] attachment', async () => {
    it('should attach an sbom boms[] entry with normalized packages and document passthrough', async () => {
      // minimal-vulns.json has 2 components
      const hdf = JSON.parse(
        await convertCyclonedxToHdf(loadFixture('minimal-vulns.json'))
      ) as HDFResults;
      const boms = hdf.components?.[0]?.boms;
      expect(boms).toHaveLength(1);
      expect(boms![0]!.bomType).toBe('sbom');
      expect(boms![0]!.format).toBe('cyclonedx');
      expect(boms![0]!.packages?.length).toBeGreaterThan(0);
      expect(boms![0]!.document).toBeDefined();
    });

    it('should carry document only (no packages) for vuln-only input', async () => {
      // vex.json has no components
      const hdf = JSON.parse(
        await convertCyclonedxToHdf(loadFixture('vex.json'))
      ) as HDFResults;
      const boms = hdf.components?.[0]?.boms;
      expect(boms).toHaveLength(1);
      expect(boms![0]!.bomType).toBe('sbom');
      expect(boms![0]!.format).toBe('cyclonedx');
      expect(boms![0]!.packages ?? []).toHaveLength(0);
      expect(boms![0]!.document).toBeDefined();
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

  describe('cvss version from rating method', () => {
    it('derives the version from rating.method when the vector lacks a CVSS prefix', async () => {
      const input = JSON.stringify({
        bomFormat: 'CycloneDX',
        specVersion: '1.5',
        vulnerabilities: [
          {
            id: 'CVE-2021-0001',
            ratings: [
              {
                method: 'CVSSv2',
                vector: 'AV:N/AC:L/Au:N/C:P/I:P/A:P',
                score: 6.8,
              },
            ],
          },
          {
            id: 'CVE-2021-0002',
            ratings: [
              {
                method: 'CVSSv4',
                vector:
                  'AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N',
                score: 9.3,
              },
            ],
          },
        ],
      });
      const hdf = JSON.parse(await convertCyclonedxToHdf(input)) as HDFResults;
      const versions = hdf.baselines
        .flatMap((b) => b.requirements)
        .flatMap((r) => r.cvss ?? [])
        .map((c) => c.version);
      expect(versions).toContain('2.0');
      expect(versions).toContain('4.0');
    });
  });
});
