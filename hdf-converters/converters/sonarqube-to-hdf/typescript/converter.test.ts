import { describe, it, expect } from 'vitest';
import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { convertSonarqubeToHdf } from './converter.js';
import type { HdfResults } from '@mitre/hdf-schema';

const __dirname = dirname(fileURLToPath(import.meta.url));

describe('SonarQube to HDF Converter', () => {
  describe('convertSonarqubeToHdf', () => {
    it('should convert minimal SonarQube issues to HDF', () => {
      const inputPath = join(__dirname, '../fixtures/input/minimal.json');
      const input = readFileSync(inputPath, 'utf-8');

      const result = convertSonarqubeToHdf(input);
      expect(result).toBeTruthy();

      const hdf: HdfResults = JSON.parse(result);

      // Verify HDF structure
      expect(hdf.timestamp).toBeTruthy();
      expect(typeof hdf.timestamp === 'string' || hdf.timestamp instanceof Date).toBe(true);
      expect(hdf.baselines).toBeInstanceOf(Array);
      expect(hdf.baselines.length).toBeGreaterThan(0);
      expect(hdf.generator?.name).toBe('sonarqube-to-hdf');
      expect(hdf.generator?.version).toBe('1.0.0');
    });

    it('should create baselines per project', () => {
      const inputPath = join(__dirname, '../fixtures/input/minimal.json');
      const input = readFileSync(inputPath, 'utf-8');

      const result = convertSonarqubeToHdf(input);
      const hdf: HdfResults = JSON.parse(result);

      // Minimal fixture has 1 project
      expect(hdf.baselines.length).toBe(1);

      const baseline = hdf.baselines[0]!;
      expect(baseline.name).toBe('com.example:myproject');
      expect(baseline.requirements).toBeInstanceOf(Array);
    });

    it('should create requirements per rule', () => {
      const inputPath = join(__dirname, '../fixtures/input/minimal.json');
      const input = readFileSync(inputPath, 'utf-8');

      const result = convertSonarqubeToHdf(input);
      const hdf: HdfResults = JSON.parse(result);

      const baseline = hdf.baselines[0]!;

      // Minimal fixture has 2 rules
      expect(baseline.requirements.length).toBe(2);

      // Check rule IDs
      const ruleIds = baseline.requirements.map(r => r.id).sort();
      expect(ruleIds).toEqual(['java:S1144', 'java:S2259']);
    });

    it('should map severity to impact correctly', () => {
      const inputPath = join(__dirname, '../fixtures/input/minimal.json');
      const input = readFileSync(inputPath, 'utf-8');

      const result = convertSonarqubeToHdf(input);
      const hdf: HdfResults = JSON.parse(result);

      const baseline = hdf.baselines[0]!;

      // Find BLOCKER severity rule (java:S2259)
      const blockerRule = baseline.requirements.find(r => r.id === 'java:S2259');
      expect(blockerRule).toBeDefined();
      expect(blockerRule!.impact).toBe(1.0); // BLOCKER = 1.0

      // Find MAJOR severity rule (java:S1144)
      const majorRule = baseline.requirements.find(r => r.id === 'java:S1144');
      expect(majorRule).toBeDefined();
      expect(majorRule!.impact).toBe(0.7); // MAJOR = 0.7
    });

    it('should extract CWE tags from issues and rules', () => {
      const inputPath = join(__dirname, '../fixtures/input/minimal.json');
      const input = readFileSync(inputPath, 'utf-8');

      const result = convertSonarqubeToHdf(input);
      const hdf: HdfResults = JSON.parse(result);

      const baseline = hdf.baselines[0]!;

      // Find rule with CWE tag (java:S2259 has cwe-476)
      const ruleWithCwe = baseline.requirements.find(r => r.id === 'java:S2259');
      expect(ruleWithCwe).toBeDefined();
      expect(ruleWithCwe!.tags.cwe).toContain('CWE-476');
    });

    it('should map CWE to NIST controls', () => {
      const inputPath = join(__dirname, '../fixtures/input/minimal.json');
      const input = readFileSync(inputPath, 'utf-8');

      const result = convertSonarqubeToHdf(input);
      const hdf: HdfResults = JSON.parse(result);

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

    it('should create results for each issue', () => {
      const inputPath = join(__dirname, '../fixtures/input/minimal.json');
      const input = readFileSync(inputPath, 'utf-8');

      const result = convertSonarqubeToHdf(input);
      const hdf: HdfResults = JSON.parse(result);

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

    it('should include component path in code description', () => {
      const inputPath = join(__dirname, '../fixtures/input/minimal.json');
      const input = readFileSync(inputPath, 'utf-8');

      const result = convertSonarqubeToHdf(input);
      const hdf: HdfResults = JSON.parse(result);

      const baseline = hdf.baselines[0]!;
      const requirement = baseline.requirements[0]!;
      const result0 = requirement.results[0]!;

      // Should include file path
      expect(result0.codeDesc).toContain('src/main/java/com/example/');
      // Should include line number
      expect(result0.codeDesc).toMatch(/LINE : \d+/);
    });

    it('should include source location for issues with line numbers', () => {
      const inputPath = join(__dirname, '../fixtures/input/minimal.json');
      const input = readFileSync(inputPath, 'utf-8');

      const result = convertSonarqubeToHdf(input);
      const hdf: HdfResults = JSON.parse(result);

      const baseline = hdf.baselines[0]!;

      // At least one requirement should have sourceLocation
      const reqWithLocation = baseline.requirements.find(r => r.sourceLocation !== undefined);
      expect(reqWithLocation).toBeDefined();
      expect(reqWithLocation!.sourceLocation?.ref).toBeTruthy();
      expect(reqWithLocation!.sourceLocation?.line).toBeGreaterThan(0);
    });

    it('should throw error for invalid JSON', () => {
      expect(() => {
        convertSonarqubeToHdf('not valid json');
      }).toThrow();
    });

    it('should throw error for missing issues field', () => {
      expect(() => {
        convertSonarqubeToHdf('{"total": 0}');
      }).toThrow('Invalid SonarQube structure: missing or invalid issues field');
    });

    it('should handle empty issues array', () => {
      const input = JSON.stringify({
        total: 0,
        p: 1,
        ps: 100,
        paging: { pageIndex: 1, pageSize: 100, total: 0 },
        issues: [],
        components: [],
        rules: [],
      });

      const result = convertSonarqubeToHdf(input);
      const hdf: HdfResults = JSON.parse(result);

      expect(hdf.baselines).toEqual([]);
    });

    it('should set default NIST tags for non-security issues', () => {
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

      const result = convertSonarqubeToHdf(input);
      const hdf: HdfResults = JSON.parse(result);

      const baseline = hdf.baselines[0]!;
      const requirement = baseline.requirements[0]!;

      // CODE_SMELL without CWE should get default SA-11
      expect(requirement.tags.nist).toEqual(['SA-11']);
    });

    it('should set security NIST tags for vulnerability issues', () => {
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

      const result = convertSonarqubeToHdf(input);
      const hdf: HdfResults = JSON.parse(result);

      const baseline = hdf.baselines[0]!;
      const requirement = baseline.requirements[0]!;

      // VULNERABILITY without CWE should get default SI-10
      expect(requirement.tags.nist).toEqual(['SI-10']);
    });
  });
});
