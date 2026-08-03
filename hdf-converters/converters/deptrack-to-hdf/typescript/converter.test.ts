import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { describe, it, expect } from 'vitest';
import { convertDeptrackToHdf } from './converter.js';
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
  converterName: 'deptrack-to-hdf',
  convertFn: convertDeptrackToHdf,
  minimalFixture: 'fpf-default.json',
});

// Ground-truth anchor (input-derived count; see shared/typescript/anchor.ts):
// one requirement per top-level findings[] entry, counted independently of the
// converter's parser so a silent under-extraction fails even when Go/TS agree.
describe('deptrack-to-hdf ground-truth anchor', () => {
  it('emits one requirement per findings[]', async () => {
    const input = loadFixture('fpf-default.json');
    assertRequirementCount(
      await convertDeptrackToHdf(input),
      countJsonItemsUnderKey(input, 'findings'),
      'fpf-default.json: one requirement per findings[]',
    );
  });
});

describe('timestamp parse fallback', () => {
  it('falls back to a valid startTime when the report timestamp is unparseable', async () => {
    const input = loadFixture('fpf-default.json').replace(/2022-02-18T23:31:42Z/g, 'not-a-date');
    const hdf = JSON.parse(await convertDeptrackToHdf(input)) as HDFResults;
    expectValidResults(hdf);
  });

  it('falls back to a valid startTime when the report timestamp is absent', async () => {
    const input = loadFixture('fpf-default.json').replace(/"timestamp"/g, '"timestampAbsent"');
    const hdf = JSON.parse(await convertDeptrackToHdf(input)) as HDFResults;
    expectValidResults(hdf);
  });
});

describe('Dependency-Track to HDF converter', async () => {
  describe('conversion basics', async () => {
    it('should produce valid HDF from default fixture', async () => {
      const output = await convertDeptrackToHdf(loadFixture('fpf-default.json'));
      const hdf = JSON.parse(output) as HDFResults;
      expectValidResults(hdf);

      expect(hdf.timestamp).toBeTruthy();
      expect(hdf.generator?.name).toBe('deptrack-to-hdf');
      expect(hdf.generator?.version).toBe('1.0.0');
      expect(hdf.baselines).toHaveLength(1);
      // fpf-default.json has 2 findings with unique matrix IDs
      expect(hdf.baselines[0]!.requirements).toHaveLength(2);
    });

    it('should use "Dependency-Track Scan" as the baseline name', async () => {
      const hdf = JSON.parse(await convertDeptrackToHdf(loadFixture('fpf-default.json'))) as HDFResults;
      expect(hdf.baselines[0]!.name).toBe('Dependency-Track Scan');
    });

    it('should include baseline title with project name', async () => {
      const hdf = JSON.parse(await convertDeptrackToHdf(loadFixture('fpf-default.json'))) as HDFResults;
      expect(hdf.baselines[0]!.title).toContain('Acme Example');
    });

    it('should include a sha256 checksum', async () => {
      const hdf = JSON.parse(await convertDeptrackToHdf(loadFixture('fpf-default.json'))) as HDFResults;
      const checksum = hdf.baselines[0]!.resultsChecksum;
      expect(checksum?.algorithm).toBe('sha256');
      expect(checksum?.value).toMatch(/^[a-f0-9]{64}$/);
    });
  });

  describe('generator and dataSource', async () => {
    it('should set generator name and version', async () => {
      const hdf = JSON.parse(await convertDeptrackToHdf(loadFixture('fpf-default.json'))) as HDFResults;
      expect(hdf.generator?.name).toBe('deptrack-to-hdf');
      expect(hdf.generator?.version).toBe('1.0.0');
    });

    it('should set tool name to "Dependency-Track" and format to "FPF"', async () => {
      const hdf = JSON.parse(await convertDeptrackToHdf(loadFixture('fpf-default.json'))) as HDFResults;
      expect(hdf.tool?.name).toBe('Dependency-Track');
      expect(hdf.tool?.format).toBe('FPF');
    });
  });

  describe('target', async () => {
    it('should include project name as target', async () => {
      const hdf = JSON.parse(await convertDeptrackToHdf(loadFixture('fpf-default.json'))) as HDFResults;
      expect(hdf.components).toBeDefined();
      expect(hdf.components![0]!.name).toBe('Acme Example');
      expect(hdf.components![0]!.type).toBe('application');
    });
  });

  describe('severity to impact mapping', async () => {
    it('should map LOW severity to 0.3', async () => {
      const hdf = JSON.parse(await convertDeptrackToHdf(loadFixture('fpf-default.json'))) as HDFResults;
      // Both findings in fpf-default.json are LOW severity
      for (const req of hdf.baselines[0]!.requirements) {
        expect(req.impact).toBe(0.3);
      }
    });

    it('should map INFO severity to 0.0', async () => {
      const hdf = JSON.parse(await convertDeptrackToHdf(loadFixture('fpf-info-vulnerability.json'))) as HDFResults;
      expect(hdf.baselines[0]!.requirements).toHaveLength(1);
      expect(hdf.baselines[0]!.requirements[0]!.impact).toBe(0.0);
    });
  });

  describe('CWE to NIST mapping', async () => {
    it('should map CWE to NIST controls', async () => {
      const hdf = JSON.parse(await convertDeptrackToHdf(loadFixture('fpf-default.json'))) as HDFResults;
      const req = hdf.baselines[0]!.requirements[0]!;
      // CWE-400 should have a NIST mapping
      const nist = req.tags?.['nist'] as string[];
      expect(nist).toBeDefined();
      expect(nist.length).toBeGreaterThan(0);
    });
  });

  describe('requirement ID', async () => {
    it('should use the matrix field as requirement ID', async () => {
      const hdf = JSON.parse(await convertDeptrackToHdf(loadFixture('fpf-default.json'))) as HDFResults;
      const req = hdf.baselines[0]!.requirements.find(
        r => r.id === 'ca4f2da9-0fad-4a13-92d7-f627f3168a56:b815b581-fec1-4374-a871-68862a8f8d52:115b80bb-46c4-41d1-9f10-8a175d4abb46'
      );
      expect(req).toBeDefined();
    });
  });

  describe('requirement title', async () => {
    it('should include purl and vulnerability title', async () => {
      const hdf = JSON.parse(await convertDeptrackToHdf(loadFixture('fpf-default.json'))) as HDFResults;
      const req = hdf.baselines[0]!.requirements.find(
        r => r.id === 'ca4f2da9-0fad-4a13-92d7-f627f3168a56:b815b581-fec1-4374-a871-68862a8f8d52:115b80bb-46c4-41d1-9f10-8a175d4abb46'
      );
      expect(req).toBeDefined();
      expect(req!.title).toContain('pkg:npm/timespan@2.3.0');
      expect(req!.title).toContain('Regular Expression Denial of Service');
    });
  });

  describe('descriptions', async () => {
    it('should include check and fix descriptions', async () => {
      const hdf = JSON.parse(await convertDeptrackToHdf(loadFixture('fpf-default.json'))) as HDFResults;
      const req = hdf.baselines[0]!.requirements.find(
        r => r.id === 'ca4f2da9-0fad-4a13-92d7-f627f3168a56:b815b581-fec1-4374-a871-68862a8f8d52:115b80bb-46c4-41d1-9f10-8a175d4abb46'
      );
      expect(req).toBeDefined();

      const checkDesc = req!.descriptions?.find(d => d.label === 'check');
      expect(checkDesc).toBeDefined();
      expect(checkDesc!.data).toContain('timespan');

      const fixDesc = req!.descriptions?.find(d => d.label === 'fix');
      expect(fixDesc).toBeDefined();
      expect(fixDesc!.data).toContain('No direct patch');

      const defaultDesc = req!.descriptions?.find(d => d.label === 'default');
      expect(defaultDesc).toBeDefined();
    });
  });

  describe('status', async () => {
    it('should mark all findings as failed', async () => {
      const hdf = JSON.parse(await convertDeptrackToHdf(loadFixture('fpf-default.json'))) as HDFResults;
      for (const req of hdf.baselines[0]!.requirements) {
        for (const result of req.results) {
          expect(result.status).toBe('failed');
        }
      }
    });
  });

  describe('tags', async () => {
    it('should retain nist/cci and retire the cweIds tag', async () => {
      const hdf = JSON.parse(await convertDeptrackToHdf(loadFixture('fpf-default.json'))) as HDFResults;
      const req = hdf.baselines[0]!.requirements[0]!;

      expect(req.tags?.['nist']).toBeDefined();
      expect((req.tags?.['nist'] as string[]).length).toBeGreaterThan(0);
      expect(req.tags?.['cci']).toBeDefined();
      expect((req.tags?.['cci'] as string[]).length).toBeGreaterThan(0);
      // cweIds tag is retired — CWE now lives in the first-class cwe[] field.
      expect(req.tags?.['cweIds']).toBeUndefined();
    });
  });

  describe('CWE first-class field', async () => {
    it('populates requirement.cwe[] from vulnerability.cwes', async () => {
      const hdf = JSON.parse(await convertDeptrackToHdf(loadFixture('fpf-default.json'))) as HDFResults;
      // Both findings carry cwes:[{cweId:400}].
      for (const req of hdf.baselines[0]!.requirements) {
        expect(req.cwe).toEqual(['CWE-400']);
      }
    });

    it('omits cwe[] and tags.cve when the source carries neither', async () => {
      const input = JSON.stringify({
        meta: {},
        project: { uuid: 'p1', name: 'test' },
        findings: [{
          component: { name: 'comp' },
          vulnerability: { severity: 'LOW' },
          matrix: 'm1',
        }],
      });
      const hdf = JSON.parse(await convertDeptrackToHdf(input)) as HDFResults;
      const req = hdf.baselines[0]!.requirements[0]!;
      expect(req.cwe).toBeUndefined();
      expect(req.tags?.['cve']).toBeUndefined();
    });
  });

  describe('CVE tag', async () => {
    it('maps aliases[].cveId to tags.cve, only where a CVE alias exists', async () => {
      const hdf = JSON.parse(await convertDeptrackToHdf(loadFixture('fpf-default.json'))) as HDFResults;

      // Finding 1 (timespan) has no aliases → no tags.cve.
      const first = hdf.baselines[0]!.requirements.find(
        r => r.id === 'ca4f2da9-0fad-4a13-92d7-f627f3168a56:b815b581-fec1-4374-a871-68862a8f8d52:115b80bb-46c4-41d1-9f10-8a175d4abb46'
      )!;
      expect(first.tags?.['cve']).toBeUndefined();

      // Finding 2 (uglify-js) has aliases[0].cveId = CVE-2022-2053.
      const second = hdf.baselines[0]!.requirements.find(
        r => r.id === 'ca4f2da9-0fad-4a13-92d7-f627f3168a56:979f87f5-eaf5-4095-9d38-cde17bf9228e:701a3953-666b-4b7a-96ca-e1e6a3e1def3'
      )!;
      expect(second.tags?.['cve']).toEqual(['CVE-2022-2053']);
      // CVE must not leak into cwe[].
      expect(second.cwe).not.toContain('CVE-2022-2053');
    });

    it('dedupes repeated cveIds and skips empty ones', async () => {
      const input = JSON.stringify({
        meta: {},
        project: { uuid: 'p1', name: 'test' },
        findings: [{
          component: { name: 'comp' },
          vulnerability: {
            severity: 'LOW',
            aliases: [{ cveId: 'CVE-2021-44228' }, { cveId: 'CVE-2021-44228' }, { ghsaId: 'GHSA-x' }],
          },
          matrix: 'm1',
        }],
      });
      const hdf = JSON.parse(await convertDeptrackToHdf(input)) as HDFResults;
      expect(hdf.baselines[0]!.requirements[0]!.tags?.['cve']).toEqual(['CVE-2021-44228']);
    });
  });

  describe('no vulnerabilities', async () => {
    it('should synthesize a passed placeholder for empty findings array', async () => {
      const hdf = JSON.parse(await convertDeptrackToHdf(loadFixture('fpf-no-vulnerabilities.json'))) as HDFResults;
      expect(hdf.baselines[0]!.requirements).toHaveLength(1);
      const req = hdf.baselines[0]!.requirements[0]!;
      expect(req.id).toBe('deptrack-no-findings');
      expect(req.results[0]!.status).toBe('passed');
      expect(req.results[0]!.codeDesc).toContain('zero vulnerable components');
      expect(hdf.components![0]!.name).toBe('laravel');
    });
  });

  describe('result codeDesc', async () => {
    it('should include recommendation in codeDesc', async () => {
      const hdf = JSON.parse(await convertDeptrackToHdf(loadFixture('fpf-default.json'))) as HDFResults;
      const req = hdf.baselines[0]!.requirements.find(
        r => r.id === 'ca4f2da9-0fad-4a13-92d7-f627f3168a56:979f87f5-eaf5-4095-9d38-cde17bf9228e:701a3953-666b-4b7a-96ca-e1e6a3e1def3'
      );
      expect(req).toBeDefined();
      expect(req!.results[0]?.codeDesc).toContain('Update to version 2.6.0 or later.');
    });
  });

  describe('requirement code (Heimdall CODE tab)', async () => {
    it('sets code to the raw finding object, round-tripping including dropped fields', async () => {
      for (const name of ['fpf-default.json', 'fpf-info-vulnerability.json']) {
        const input = loadFixture(name);
        const hdf = JSON.parse(await convertDeptrackToHdf(input)) as HDFResults;
        const source = JSON.parse(input) as { findings: unknown[] };
        const reqs = hdf.baselines[0]!.requirements;
        expect(reqs).toHaveLength(source.findings.length);
        reqs.forEach((req, i) => {
          expect(req.code).toBeDefined();
          expect(JSON.parse(req.code!)).toEqual(source.findings[i]);
        });
      }
    });

    it('preserves untyped fields (aliases, source, vulnId) in code', async () => {
      const hdf = JSON.parse(await convertDeptrackToHdf(loadFixture('fpf-default.json'))) as HDFResults;
      const req = hdf.baselines[0]!.requirements.find(
        r => r.id === 'ca4f2da9-0fad-4a13-92d7-f627f3168a56:979f87f5-eaf5-4095-9d38-cde17bf9228e:701a3953-666b-4b7a-96ca-e1e6a3e1def3'
      );
      expect(req!.code).toContain('CVE-2022-2053');
      expect(req!.code).toContain('GHSA-95rf-557x-44g5');
      expect(req!.code).toContain('"vulnId": "48"');
    });
  });

  describe('edge cases: missing optional fields', async () => {
    it('should handle all severity levels', async () => {
      for (const [sev, expected] of [['CRITICAL', 0.9], ['HIGH', 0.7], ['MEDIUM', 0.5], ['LOW', 0.3], ['INFO', 0.0], ['UNKNOWN', 0.5]] as const) {
        const input = JSON.stringify({
          meta: { timestamp: '2024-01-01T00:00:00Z' },
          project: { uuid: 'p1', name: 'test' },
          findings: [{
            component: { name: 'comp' },
            vulnerability: { severity: sev },
            matrix: `m-${sev}`,
          }],
        });
        const hdf = JSON.parse(await convertDeptrackToHdf(input)) as HDFResults;
        expect(hdf.baselines[0]!.requirements[0]!.impact).toBe(expected);
      }
    });

    it('should handle missing vulnerability title (purl-only title)', async () => {
      const input = JSON.stringify({
        meta: {},
        project: { uuid: 'p1', name: 'test' },
        findings: [{
          component: { name: 'comp', purl: 'pkg:npm/test@1.0' },
          vulnerability: { severity: 'LOW' },
          matrix: 'm1',
        }],
      });
      const hdf = JSON.parse(await convertDeptrackToHdf(input)) as HDFResults;
      // No title → just purl
      expect(hdf.baselines[0]!.requirements[0]!.title).toBe('pkg:npm/test@1.0');
    });

    it('should use component name when purl is missing', async () => {
      const input = JSON.stringify({
        meta: {},
        project: { uuid: 'p1', name: 'test' },
        findings: [{
          component: { name: 'my-component' },
          vulnerability: { severity: 'HIGH', title: 'Some Vuln' },
          matrix: 'm1',
        }],
      });
      const hdf = JSON.parse(await convertDeptrackToHdf(input)) as HDFResults;
      expect(hdf.baselines[0]!.requirements[0]!.title).toContain('my-component');
    });

    it('should handle empty cwes array', async () => {
      const input = JSON.stringify({
        meta: {},
        project: { uuid: 'p1', name: 'test' },
        findings: [{
          component: { name: 'comp' },
          vulnerability: { severity: 'LOW', cwes: [] },
          matrix: 'm1',
        }],
      });
      const hdf = JSON.parse(await convertDeptrackToHdf(input)) as HDFResults;
      const req = hdf.baselines[0]!.requirements[0]!;
      // No CWE IDs → no cwe[] field (and the retired cweIds tag stays absent)
      expect(req.cwe).toBeUndefined();
      expect(req.tags?.['cweIds']).toBeUndefined();
    });

    it('should handle missing description and recommendation', async () => {
      const input = JSON.stringify({
        meta: {},
        project: { uuid: 'p1', name: 'test' },
        findings: [{
          component: { name: 'comp' },
          vulnerability: { severity: 'LOW' },
          matrix: 'm1',
        }],
      });
      const hdf = JSON.parse(await convertDeptrackToHdf(input)) as HDFResults;
      const req = hdf.baselines[0]!.requirements[0]!;
      // Default description with empty data
      const defaultDesc = req.descriptions?.find(d => d.label === 'default');
      expect(defaultDesc).toBeDefined();
      expect(defaultDesc!.data).toBe('');
      // No check or fix descriptions
      const check = req.descriptions?.find(d => d.label === 'check');
      expect(check).toBeUndefined();
      const fix = req.descriptions?.find(d => d.label === 'fix');
      expect(fix).toBeUndefined();
      // codeDesc fallback
      expect(req.results[0]?.codeDesc).toBe('No recommendation available');
    });

    it('should handle missing project fields', async () => {
      const input = JSON.stringify({
        meta: {},
        project: { uuid: 'u1', name: '' },
        findings: [],
      });
      const hdf = JSON.parse(await convertDeptrackToHdf(input)) as HDFResults;
      expect(hdf.baselines[0]!.requirements).toHaveLength(1);
      expect(hdf.baselines[0]!.requirements[0]!.id).toBe('deptrack-no-findings');
    });

    it('should use project uuid as target when name is missing', async () => {
      const input = JSON.stringify({
        meta: {},
        project: { uuid: 'uuid-123' },
        findings: [],
      });
      const hdf = JSON.parse(await convertDeptrackToHdf(input)) as HDFResults;
      expect(hdf.components![0]!.name).toBe('uuid-123');
    });

    it('should handle missing findings/project/meta gracefully', async () => {
      const input = JSON.stringify({ other: 'field' });
      await expect(convertDeptrackToHdf(input)).rejects.toThrow(
        'does not appear to be a Dependency-Track report'
      );
    });

    it('should handle missing meta timestamp (no startTime)', async () => {
      const input = JSON.stringify({
        meta: {},
        project: { uuid: 'p1', name: 'test' },
        findings: [{
          component: { name: 'comp' },
          vulnerability: { severity: 'LOW' },
          matrix: 'm1',
        }],
      });
      const hdf = JSON.parse(await convertDeptrackToHdf(input)) as HDFResults;
      // startTime should be undefined when no timestamp
      expect(hdf.baselines[0]!.requirements[0]!.results[0]).toBeDefined();
    });
  });
});
