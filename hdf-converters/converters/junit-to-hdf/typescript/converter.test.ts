import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { describe, it, expect } from 'vitest';
import { convertJunitToHdf } from './converter.js';
import type { HdfResults } from '@mitre/hdf-schema';
import { ResultStatus } from '@mitre/hdf-schema';

const __dirname = dirname(fileURLToPath(import.meta.url));
const FIXTURES_DIR = join(__dirname, '..', 'fixtures');

function loadFixture(name: string): string {
  return readFileSync(join(FIXTURES_DIR, 'input', name), 'utf-8');
}

function parseHdf(fixture: string): HdfResults {
  return JSON.parse(convertJunitToHdf(loadFixture(fixture))) as HdfResults;
}

// Fixtures sourced from apache/maven-surefire test resources:
// https://github.com/apache/maven-surefire/tree/master/surefire-report-parser/src/test/resources/fixture/testsuitexmlparser

describe('junit to HDF converter', () => {
  // --- Input validation ---

  describe('input validation', () => {
    it('should throw on empty input', () => {
      expect(() => convertJunitToHdf('')).toThrow();
    });

    it('should throw on invalid XML', () => {
      expect(() => convertJunitToHdf('not xml')).toThrow();
    });

    it('should throw on unclosed XML', () => {
      expect(() => convertJunitToHdf('<unclosed')).toThrow();
    });

    it('should throw on non-JUnit XML', () => {
      expect(() =>
        convertJunitToHdf('<?xml version="1.0"?><root><item/></root>')
      ).toThrow(/not a JUnit XML/i);
    });
  });

  // --- Conversion basics ---

  describe('conversion basics (surefire-failing)', () => {
    it('should produce valid HDF structure', () => {
      const hdf = parseHdf('surefire-failing.xml');

      expect(hdf.timestamp).toBeTruthy();
      expect(hdf.generator?.name).toBe('hdf-converters');
      expect(hdf.generator?.version).toBeTruthy();
      expect(hdf.baselines).toHaveLength(1);
    });

    it('should set dataSource', () => {
      const hdf = parseHdf('surefire-failing.xml');
      expect(hdf.dataSource?.name).toBe('JUnit XML');
      expect(hdf.dataSource?.format).toBe('XML');
    });
  });

  // --- Baseline structure ---

  describe('baseline structure', () => {
    it('should use testsuite name as baseline name (surefire-failing)', () => {
      const hdf = parseHdf('surefire-failing.xml');
      expect(hdf.baselines[0]!.name).toBe(
        'org.apache.maven.surefire.test.FailingTest'
      );
    });

    it('should use testsuite name as baseline name (surefire-error)', () => {
      const hdf = parseHdf('surefire-error.xml');
      expect(hdf.baselines[0]!.name).toBe('surefire.MyTest');
    });

    it('should include sha256 checksum', () => {
      const hdf = parseHdf('surefire-failing.xml');
      const checksum = hdf.baselines[0]!.resultsChecksum;
      expect(checksum?.algorithm).toBe('sha256');
      expect(checksum?.value).toMatch(/^[a-f0-9]{64}$/);
    });
  });

  // --- Requirements from test cases ---

  describe('requirement fields', () => {
    it('should create one requirement per testcase (surefire-failing has 2)', () => {
      const hdf = parseHdf('surefire-failing.xml');
      expect(hdf.baselines[0]!.requirements).toHaveLength(2);
    });

    it('should use classname.name as requirement ID', () => {
      const hdf = parseHdf('surefire-failing.xml');
      const ids = hdf.baselines[0]!.requirements.map((r) => r.id);
      expect(ids).toContain(
        'org.apache.maven.surefire.test.FailingTest.defaultTestValueIs_Value'
      );
      expect(ids).toContain(
        'org.apache.maven.surefire.test.FailingTest.setTestAndRetrieveValue'
      );
    });

    it('should use test name as requirement title', () => {
      const hdf = parseHdf('surefire-failing.xml');
      const req = hdf.baselines[0]!.requirements.find(
        (r) =>
          r.id ===
          'org.apache.maven.surefire.test.FailingTest.defaultTestValueIs_Value'
      );
      expect(req?.title).toBe('defaultTestValueIs_Value');
    });

    it('should set impact to 0.5 for all testcases', () => {
      const hdf = parseHdf('surefire-failing.xml');
      for (const req of hdf.baselines[0]!.requirements) {
        expect(req.impact).toBe(0.5);
      }
    });

    it('should include default description', () => {
      const hdf = parseHdf('surefire-error.xml');
      const req = hdf.baselines[0]!.requirements.find(
        (r) => r.id === 'surefire.MyTest.test'
      );
      const desc = req?.descriptions?.find((d) => d.label === 'default');
      expect(desc?.data).toContain('test');
      expect(desc?.data).toContain('surefire.MyTest');
    });
  });

  // --- Status mapping ---

  describe('status mapping', () => {
    it('should map failure to failed', () => {
      const hdf = parseHdf('surefire-failing.xml');
      for (const req of hdf.baselines[0]!.requirements) {
        expect(req.results[0]?.status).toBe(ResultStatus.Failed);
      }
    });

    it('should map error to error', () => {
      const hdf = parseHdf('surefire-error.xml');
      const req = hdf.baselines[0]!.requirements.find(
        (r) => r.id === 'surefire.MyTest.test'
      );
      expect(req?.results[0]?.status).toBe(ResultStatus.Error);
    });

    it('should map passing tests to passed (surefire-flaky)', () => {
      const hdf = parseHdf('surefire-flaky.xml');
      for (const req of hdf.baselines[0]!.requirements) {
        expect(req.results[0]?.status).toBe(ResultStatus.Passed);
      }
    });
  });

  // --- Result details ---

  describe('result details', () => {
    it('should include failure message with type and text', () => {
      const hdf = parseHdf('surefire-failing.xml');
      const req = hdf.baselines[0]!.requirements.find(
        (r) =>
          r.id ===
          'org.apache.maven.surefire.test.FailingTest.defaultTestValueIs_Value'
      );
      expect(req?.results[0]?.message).toContain('wrong');
      expect(req?.results[0]?.message).toContain('value');
    });

    it('should include error message with type', () => {
      const hdf = parseHdf('surefire-error.xml');
      const req = hdf.baselines[0]!.requirements.find(
        (r) => r.id === 'surefire.MyTest.test'
      );
      expect(req?.results[0]?.message).toContain('RuntimeException');
      expect(req?.results[0]?.message).toContain('this is different message');
    });

    it('should include error stack trace', () => {
      const hdf = parseHdf('surefire-error.xml');
      const req = hdf.baselines[0]!.requirements.find(
        (r) => r.id === 'surefire.MyTest.test'
      );
      expect(req?.results[0]?.message).toContain('IndexOutOfBoundsException');
      expect(req?.results[0]?.message).toContain('MyTest.rethrownDelegate');
    });

    it('should include codeDesc with classname and test name', () => {
      const hdf = parseHdf('surefire-failing.xml');
      const req = hdf.baselines[0]!.requirements.find(
        (r) =>
          r.id ===
          'org.apache.maven.surefire.test.FailingTest.defaultTestValueIs_Value'
      );
      expect(req?.results[0]?.codeDesc).toContain(
        'org.apache.maven.surefire.test.FailingTest'
      );
      expect(req?.results[0]?.codeDesc).toContain('defaultTestValueIs_Value');
    });

    it('should include runTime as a number', () => {
      const hdf = parseHdf('surefire-failing.xml');
      const req = hdf.baselines[0]!.requirements.find(
        (r) =>
          r.id ===
          'org.apache.maven.surefire.test.FailingTest.defaultTestValueIs_Value'
      );
      expect(req?.results[0]?.runTime).toBeCloseTo(0.013, 3);
    });
  });

  // --- NIST tags ---

  describe('NIST tags', () => {
    it('should include SA-11 NIST tag on all requirements', () => {
      const hdf = parseHdf('surefire-failing.xml');
      for (const req of hdf.baselines[0]!.requirements) {
        expect(req.tags?.['nist']).toContain('SA-11');
      }
    });
  });

  // --- Flaky test handling ---

  describe('flaky test handling', () => {
    it('should treat flakyFailure/flakyError as passed', () => {
      const hdf = parseHdf('surefire-flaky.xml');
      expect(hdf.baselines[0]!.requirements).toHaveLength(2);

      const req = hdf.baselines[0]!.requirements.find(
        (r) => r.id === 'org.acme.FlakyTest.testFlaky'
      );
      expect(req).toBeDefined();
      expect(req?.results[0]?.status).toBe(ResultStatus.Passed);
    });
  });

  // --- JSON round-trip ---

  describe('JSON round-trip', () => {
    it('should produce valid JSON that re-parses', () => {
      const output = convertJunitToHdf(loadFixture('surefire-failing.xml'));
      const hdf = JSON.parse(output) as HdfResults;
      expect(hdf.generator?.name).toBe('hdf-converters');
      expect(hdf.baselines).toHaveLength(1);
      expect(hdf.baselines[0]!.requirements).toHaveLength(2);
    });
  });
});
