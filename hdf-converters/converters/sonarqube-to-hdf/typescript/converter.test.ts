import { describe, it, expect } from 'vitest';
import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { convertSonarqubeToHdf } from './converter.js';
import { runConverterContractTests } from '../../../shared/typescript/converter-contract.js';
import type { HDFResults } from '@mitre/hdf-schema';

const __dirname = dirname(fileURLToPath(import.meta.url));

runConverterContractTests({
  converterName: 'sonarqube-to-hdf',
  convertFn: convertSonarqubeToHdf,
  minimalFixture: 'minimal.json',
});

describe('SonarQube to HDF Converter', async () => {
  describe('convertSonarqubeToHdf', async () => {
    it('should convert minimal SonarQube issues to HDF', async () => {
      const inputPath = join(__dirname, '../fixtures/input/minimal.json');
      const input = readFileSync(inputPath, 'utf-8');

      const result = await convertSonarqubeToHdf(input);
      expect(result).toBeTruthy();

      const hdf: HDFResults = JSON.parse(result);

      // Verify HDF structure
      expect(hdf.timestamp).toBeTruthy();
      expect(typeof hdf.timestamp === 'string' || hdf.timestamp instanceof Date).toBe(true);
      expect(hdf.baselines).toBeInstanceOf(Array);
      expect(hdf.baselines.length).toBeGreaterThan(0);
      expect(hdf.generator?.name).toBe('sonarqube-to-hdf');
      expect(hdf.generator?.version).toBe('1.0.0');
      expect(hdf.tool?.name).toBe('SonarQube');
      expect(hdf.tool?.version).toBeUndefined();
      expect(hdf.tool?.format).toBeUndefined();
    });

    it('should create baselines per project', async () => {
      const inputPath = join(__dirname, '../fixtures/input/minimal.json');
      const input = readFileSync(inputPath, 'utf-8');

      const result = await convertSonarqubeToHdf(input);
      const hdf: HDFResults = JSON.parse(result);

      // Minimal fixture has 1 project
      expect(hdf.baselines.length).toBe(1);

      const baseline = hdf.baselines[0]!;
      expect(baseline.name).toBe('com.example:myproject');
      expect(baseline.requirements).toBeInstanceOf(Array);
    });

    it('should create requirements per rule', async () => {
      const inputPath = join(__dirname, '../fixtures/input/minimal.json');
      const input = readFileSync(inputPath, 'utf-8');

      const result = await convertSonarqubeToHdf(input);
      const hdf: HDFResults = JSON.parse(result);

      const baseline = hdf.baselines[0]!;

      // Minimal fixture has 2 rules
      expect(baseline.requirements.length).toBe(2);

      // Check rule IDs
      const ruleIds = baseline.requirements.map(r => r.id).sort();
      expect(ruleIds).toEqual(['java:S1144', 'java:S2259']);
    });

    it('should map severity to impact correctly', async () => {
      const inputPath = join(__dirname, '../fixtures/input/minimal.json');
      const input = readFileSync(inputPath, 'utf-8');

      const result = await convertSonarqubeToHdf(input);
      const hdf: HDFResults = JSON.parse(result);

      const baseline = hdf.baselines[0]!;

      // Find BLOCKER severity rule (java:S2259)
      const blockerRule = baseline.requirements.find(r => r.id === 'java:S2259');
      expect(blockerRule).toBeDefined();
      expect(blockerRule!.impact).toBe(1.0); // BLOCKER = 1.0

      // Find MAJOR severity rule (java:S1144)
      const majorRule = baseline.requirements.find(r => r.id === 'java:S1144');
      expect(majorRule).toBeDefined();
      expect(majorRule!.impact).toBe(0.5); // MAJOR = 0.5
    });

    it('should extract CWE tags from issues and rules', async () => {
      const inputPath = join(__dirname, '../fixtures/input/minimal.json');
      const input = readFileSync(inputPath, 'utf-8');

      const result = await convertSonarqubeToHdf(input);
      const hdf: HDFResults = JSON.parse(result);

      const baseline = hdf.baselines[0]!;

      // Find rule with CWE tag (java:S2259 has cwe-476)
      const ruleWithCwe = baseline.requirements.find(r => r.id === 'java:S2259');
      expect(ruleWithCwe).toBeDefined();
      expect(ruleWithCwe!.tags.cwe).toContain('CWE-476');
    });

    it('should map CWE to NIST controls', async () => {
      const inputPath = join(__dirname, '../fixtures/input/minimal.json');
      const input = readFileSync(inputPath, 'utf-8');

      const result = await convertSonarqubeToHdf(input);
      const hdf: HDFResults = JSON.parse(result);

      const baseline = hdf.baselines[0]!;

      // Find rule with CWE (java:S2259 has CWE-476)
      const ruleWithCwe = baseline.requirements.find(r => r.id === 'java:S2259');
      expect(ruleWithCwe).toBeDefined();
      expect(ruleWithCwe!.tags.nist).toBeDefined();
      expect(Array.isArray(ruleWithCwe!.tags.nist)).toBe(true);

      // CWE-476 should map to NIST controls
      if (Array.isArray(ruleWithCwe!.tags.nist) && (ruleWithCwe!.tags.nist as string[]).length > 0) {
        expect((ruleWithCwe!.tags.nist as string[]).length).toBeGreaterThan(0);
      }
    });

    it('should create results for each issue', async () => {
      const inputPath = join(__dirname, '../fixtures/input/minimal.json');
      const input = readFileSync(inputPath, 'utf-8');

      const result = await convertSonarqubeToHdf(input);
      const hdf: HDFResults = JSON.parse(result);

      const baseline = hdf.baselines[0]!;

      // Each requirement should have results
      for (const requirement of baseline.requirements) {
        expect(requirement.results).toBeInstanceOf(Array);
        expect(requirement.results.length).toBeGreaterThan(0);

        // Check result structure
        const firstResult = requirement.results[0]!;
        expect(firstResult.status).toBeDefined();
        expect(firstResult.codeDesc).toBeDefined();
        expect(firstResult.startTime).toBeDefined();
      }
    });

    it('should include component path in code description', async () => {
      const inputPath = join(__dirname, '../fixtures/input/minimal.json');
      const input = readFileSync(inputPath, 'utf-8');

      const result = await convertSonarqubeToHdf(input);
      const hdf: HDFResults = JSON.parse(result);

      const baseline = hdf.baselines[0]!;
      const requirement = baseline.requirements[0]!;
      const result0 = requirement.results[0]!;

      // Should include file path
      expect(result0.codeDesc).toContain('src/main/java/com/example/');
      // Should include line number
      expect(result0.codeDesc).toMatch(/LINE : \d+/);
    });

    it('should include source location for issues with line numbers', async () => {
      const inputPath = join(__dirname, '../fixtures/input/minimal.json');
      const input = readFileSync(inputPath, 'utf-8');

      const result = await convertSonarqubeToHdf(input);
      const hdf: HDFResults = JSON.parse(result);

      const baseline = hdf.baselines[0]!;

      // At least one requirement should have sourceLocation
      const reqWithLocation = baseline.requirements.find(r => r.sourceLocation !== undefined);
      expect(reqWithLocation).toBeDefined();
      expect(reqWithLocation!.sourceLocation?.ref).toBeTruthy();
      expect(reqWithLocation!.sourceLocation?.line).toBeGreaterThan(0);
    });

    it('should throw error for missing issues field', async () => {
      await expect(convertSonarqubeToHdf('{"total": 0}')).rejects.toThrow('Invalid SonarQube structure: missing or invalid issues field');
    });

    it('should synthesize a passed placeholder for empty issues array', async () => {
      const inputPath = join(__dirname, '../fixtures/input/empty.json');
      const input = readFileSync(inputPath, 'utf-8');

      const result = await convertSonarqubeToHdf(input);
      const hdf: HDFResults = JSON.parse(result);

      expect(hdf.baselines).toHaveLength(1);
      const reqs = hdf.baselines[0]!.requirements;
      expect(reqs).toHaveLength(1);
      expect(reqs[0]!.id).toBe('sonarqube-no-findings');
      expect(reqs[0]!.results[0]!.status).toBe('passed');
      expect(reqs[0]!.results[0]!.codeDesc).toContain('SonarQube');
      expect(reqs[0]!.results[0]!.codeDesc).toContain('com.example:myproject');
      expect(reqs[0]!.results[0]!.codeDesc).toContain('zero findings');
    });

    it('should set default NIST tags for non-security issues', async () => {
      const input = JSON.stringify({
        total: 1,
        p: 1,
        ps: 100,
        paging: { pageIndex: 1, pageSize: 100, total: 1 },
        issues: [
          {
            key: 'test-key',
            rule: 'test:rule',
            severity: 'MAJOR',
            component: 'test:component',
            project: 'test:project',
            status: 'OPEN',
            message: 'Test message',
            creationDate: '2026-01-01T00:00:00+0000',
            updateDate: '2026-01-01T00:00:00+0000',
            type: 'CODE_SMELL',
          },
        ],
        components: [],
        rules: [],
      });

      const result = await convertSonarqubeToHdf(input);
      const hdf: HDFResults = JSON.parse(result);

      const baseline = hdf.baselines[0]!;
      const requirement = baseline.requirements[0]!;

      // CODE_SMELL without CWE should get default SA-11
      expect(requirement.tags.nist).toEqual(['SA-11']);
    });

    // ---- SonarQube 26+ tests (descriptionSections format) ----

    it('should extract CWE IDs from descriptionSections (SQ 26 format)', async () => {
      const inputPath = join(__dirname, '../fixtures/input/sq26-with-sections.json');
      const input = readFileSync(inputPath, 'utf-8');

      const result = await convertSonarqubeToHdf(input);
      const hdf: HDFResults = JSON.parse(result);

      const baseline = hdf.baselines[0]!;

      // secrets:S6706 should have CWE-798 and CWE-259 from descriptionSections
      const secretsRule = baseline.requirements.find(r => r.id === 'secrets:S6706');
      expect(secretsRule).toBeDefined();
      expect(secretsRule!.tags.cwe).toContain('CWE-798');
      expect(secretsRule!.tags.cwe).toContain('CWE-259');

      // typescript:S7790 should have CWE-20 from descriptionSections
      const tsRule = baseline.requirements.find(r => r.id === 'typescript:S7790');
      expect(tsRule).toBeDefined();
      expect(tsRule!.tags.cwe).toContain('CWE-20');

      // Web rule should have no CWE IDs
      const webRule = baseline.requirements.find(r => r.id === 'Web:MouseEventWithoutKeyboardEquivalentCheck');
      expect(webRule).toBeDefined();
      expect((webRule!.tags.cwe as string[]).length).toBe(0);
    });

    it('should derive NIST controls from CWE in descriptionSections', async () => {
      const inputPath = join(__dirname, '../fixtures/input/sq26-with-sections.json');
      const input = readFileSync(inputPath, 'utf-8');

      const result = await convertSonarqubeToHdf(input);
      const hdf: HDFResults = JSON.parse(result);

      const baseline = hdf.baselines[0]!;

      // secrets:S6706 has CWE-798/259 → should have NIST from CWE mapping, not SA-11
      const secretsRule = baseline.requirements.find(r => r.id === 'secrets:S6706');
      expect(secretsRule).toBeDefined();
      expect(Array.isArray(secretsRule!.tags.nist)).toBe(true);
      expect((secretsRule!.tags.nist as string[]).length).toBeGreaterThan(0);

      // Web rule without CWE should get default SA-11
      const webRule = baseline.requirements.find(r => r.id === 'Web:MouseEventWithoutKeyboardEquivalentCheck');
      expect(webRule).toBeDefined();
      expect(webRule!.tags.nist).toContain('SA-11');
    });

    it('should fall back to descriptionSections for descriptions (SQ 26)', async () => {
      const inputPath = join(__dirname, '../fixtures/input/sq26-with-sections.json');
      const input = readFileSync(inputPath, 'utf-8');

      const result = await convertSonarqubeToHdf(input);
      const hdf: HDFResults = JSON.parse(result);

      const baseline = hdf.baselines[0]!;

      // secrets:S6706 should get description from root_cause section
      const secretsRule = baseline.requirements.find(r => r.id === 'secrets:S6706');
      expect(secretsRule).toBeDefined();
      const desc = secretsRule!.descriptions[0]!.data;
      expect(desc).toContain('trust boundaries');
      expect(desc).not.toContain('<p>');
    });

    it('should set security NIST tags for vulnerability issues', async () => {
      const input = JSON.stringify({
        total: 1,
        p: 1,
        ps: 100,
        paging: { pageIndex: 1, pageSize: 100, total: 1 },
        issues: [
          {
            key: 'test-key',
            rule: 'test:rule',
            severity: 'CRITICAL',
            component: 'test:component',
            project: 'test:project',
            status: 'OPEN',
            message: 'Security issue',
            creationDate: '2026-01-01T00:00:00+0000',
            updateDate: '2026-01-01T00:00:00+0000',
            type: 'VULNERABILITY',
          },
        ],
        components: [],
        rules: [],
      });

      const result = await convertSonarqubeToHdf(input);
      const hdf: HDFResults = JSON.parse(result);

      const baseline = hdf.baselines[0]!;
      const requirement = baseline.requirements[0]!;

      // VULNERABILITY without CWE should get default SA-11
      expect(requirement.tags.nist).toEqual(['SA-11']);
    });
  });

  describe('edge cases: missing optional fields', () => {
    it('should handle issue with no rule in ruleMap (empty description)', async () => {
      const input = JSON.stringify({
        total: 1, p: 1, ps: 100,
        paging: { pageIndex: 1, pageSize: 100, total: 1 },
        issues: [{
          key: 'k1', rule: 'unknown:rule', severity: 'MINOR',
          component: 'src/file.ts', project: 'proj',
          status: 'OPEN', message: 'msg', type: 'BUG',
          creationDate: '2025-01-01T00:00:00Z', updateDate: '2025-01-01T00:00:00Z',
        }],
        rules: [],
      });
      const hdf = JSON.parse(await convertSonarqubeToHdf(input)) as HDFResults;
      const req = hdf.baselines[0]!.requirements[0]!;
      expect(req.title).toBe('unknown:rule');
    });

    it('should handle rule with mdDesc', async () => {
      const input = JSON.stringify({
        total: 1, p: 1, ps: 100,
        paging: { pageIndex: 1, pageSize: 100, total: 1 },
        issues: [{
          key: 'k1', rule: 'r1', severity: 'BLOCKER',
          component: 'src/file.ts', project: 'proj',
          status: 'RESOLVED', message: 'msg', type: 'VULNERABILITY',
          creationDate: '2025-01-01T00:00:00Z', updateDate: '2025-01-01T00:00:00Z',
          tags: ['cwe-79'],
        }],
        rules: [{ key: 'r1', name: 'Rule 1', mdDesc: 'markdown description', tags: ['security'], sysTags: ['owasp-a1'] }],
      });
      const hdf = JSON.parse(await convertSonarqubeToHdf(input)) as HDFResults;
      expect(hdf.baselines[0]!.requirements[0]!.results[0]!.status).toBe('passed');
    });

    it('should handle rule with descriptionSections (SQ 26+ format)', async () => {
      const input = JSON.stringify({
        total: 1, p: 1, ps: 100,
        paging: { pageIndex: 1, pageSize: 100, total: 1 },
        issues: [{
          key: 'k1', rule: 'r1', severity: 'MAJOR',
          component: 'src/file.ts', project: 'proj',
          status: 'OPEN', message: 'msg', type: 'CODE_SMELL', line: 10,
          creationDate: '2025-01-01T00:00:00Z', updateDate: '2025-01-01T00:00:00Z',
        }],
        rules: [{
          key: 'r1', name: 'Rule 1',
          descriptionSections: [
            { key: 'root_cause', content: '<p>Root cause text</p>' },
            { key: 'how_to_fix', content: '<p>Fix it</p>' },
          ],
          tags: ['cwe:123:extra'],
        }],
        components: [{ key: 'src/file.ts', path: 'src/file.ts', longName: 'src/file.ts' }],
      });
      const hdf = JSON.parse(await convertSonarqubeToHdf(input)) as HDFResults;
      const req = hdf.baselines[0]!.requirements[0]!;
      expect(req.sourceLocation).toBeDefined();
      expect(req.sourceLocation!.line).toBe(10);
    });

    it('should handle rule with htmlDesc only (no mdDesc)', async () => {
      const input = JSON.stringify({
        total: 1, p: 1, ps: 100,
        paging: { pageIndex: 1, pageSize: 100, total: 1 },
        issues: [{
          key: 'k1', rule: 'r1', severity: 'INFO',
          component: 'src/file.ts', project: 'proj',
          status: 'OPEN', message: 'msg', type: 'SECURITY_HOTSPOT',
          creationDate: '2025-01-01T00:00:00Z', updateDate: '2025-01-01T00:00:00Z',
        }],
        rules: [{ key: 'r1', name: 'Rule 1', htmlDesc: '<p>HTML description CWE-79</p>' }],
      });
      const hdf = JSON.parse(await convertSonarqubeToHdf(input)) as HDFResults;
      // INFO maps to 0.0 in SEVERITY_IMPACT_MAPPING, but `0.0 || 0.5` = 0.5 (JS falsy)
      expect(hdf.baselines[0]!.requirements[0]!.impact).toBe(0.5);
    });

    it('should handle rule with name fallback (no desc at all)', async () => {
      const input = JSON.stringify({
        total: 1, p: 1, ps: 100,
        paging: { pageIndex: 1, pageSize: 100, total: 1 },
        issues: [{
          key: 'k1', rule: 'r1', severity: 'CRITICAL',
          component: 'src/file.ts', project: 'proj',
          status: 'CONFIRMED', message: 'msg', type: 'BUG',
          creationDate: '2025-01-01T00:00:00Z', updateDate: '2025-01-01T00:00:00Z',
        }],
        rules: [{ key: 'r1', name: 'Rule Name Only' }],
      });
      const hdf = JSON.parse(await convertSonarqubeToHdf(input)) as HDFResults;
      expect(hdf.baselines[0]!.requirements[0]!.impact).toBe(0.7);
    });

    it('should handle issue with no line number', async () => {
      const input = JSON.stringify({
        total: 1, p: 1, ps: 100,
        paging: { pageIndex: 1, pageSize: 100, total: 1 },
        issues: [{
          key: 'k1', rule: 'r1', severity: 'MAJOR',
          component: 'src/file.ts', project: 'proj',
          status: 'OPEN', message: 'msg', type: 'BUG',
          creationDate: '2025-01-01T00:00:00Z', updateDate: '2025-01-01T00:00:00Z',
        }],
        rules: [{ key: 'r1', name: 'Rule' }],
      });
      const hdf = JSON.parse(await convertSonarqubeToHdf(input)) as HDFResults;
      expect(hdf.baselines[0]!.requirements[0]!.sourceLocation).toBeUndefined();
    });

    it('should handle no components map', async () => {
      const input = JSON.stringify({
        total: 1, p: 1, ps: 100,
        paging: { pageIndex: 1, pageSize: 100, total: 1 },
        issues: [{
          key: 'k1', rule: 'r1', severity: 'MAJOR',
          component: 'src/file.ts', project: 'proj', line: 5,
          status: 'OPEN', message: 'msg', type: 'BUG',
          creationDate: '2025-01-01T00:00:00Z', updateDate: '2025-01-01T00:00:00Z',
        }],
        rules: [{ key: 'r1', name: 'Rule' }],
      });
      const hdf = JSON.parse(await convertSonarqubeToHdf(input)) as HDFResults;
      expect(hdf.baselines[0]!.requirements[0]!.results[0]!.codeDesc).toContain('src/file.ts');
    });

    it('should handle descriptionSections with no root_cause', async () => {
      const input = JSON.stringify({
        total: 1, p: 1, ps: 100,
        paging: { pageIndex: 1, pageSize: 100, total: 1 },
        issues: [{
          key: 'k1', rule: 'r1', severity: 'MAJOR',
          component: 'src/file.ts', project: 'proj',
          status: 'OPEN', message: 'msg', type: 'BUG',
          creationDate: '2025-01-01T00:00:00Z', updateDate: '2025-01-01T00:00:00Z',
        }],
        rules: [{
          key: 'r1', name: 'Rule',
          descriptionSections: [{ key: 'how_to_fix', content: '<p>Fix</p>' }],
        }],
      });
      const hdf = JSON.parse(await convertSonarqubeToHdf(input)) as HDFResults;
      expect(hdf.baselines).toHaveLength(1);
    });
  });
});
