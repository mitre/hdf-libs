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

async function parseHdf(fixture: string): Promise<HdfResults> {
  return JSON.parse(await convertJunitToHdf(loadFixture(fixture))) as HdfResults;
}

// Fixtures sourced from apache/maven-surefire test resources:
// https://github.com/apache/maven-surefire/tree/master/surefire-report-parser/src/test/resources/fixture/testsuitexmlparser

describe('junit to HDF converter', async () => {
  // --- Input validation ---

  describe('input validation', async () => {
    it('should throw on empty input', async () => {
      await expect(convertJunitToHdf('')).rejects.toThrow();
    });

    it('should throw on invalid XML', async () => {
      await expect(convertJunitToHdf('not xml')).rejects.toThrow();
    });

    it('should throw on unclosed XML', async () => {
      await expect(convertJunitToHdf('<unclosed')).rejects.toThrow();
    });

    it('should throw on non-JUnit XML', async () => {
      await expect(
        convertJunitToHdf('<?xml version="1.0"?><root><item/></root>')
      ).rejects.toThrow(/not a JUnit XML/i);
    });
  });

  // --- Conversion basics ---

  describe('conversion basics (surefire-failing)', async () => {
    it('should produce valid HDF structure', async () => {
      const hdf = await parseHdf('surefire-failing.xml');

      expect(hdf.timestamp).toBeTruthy();
      expect(hdf.generator?.name).toBe('hdf-converters');
      expect(hdf.generator?.version).toBeTruthy();
      expect(hdf.baselines).toHaveLength(1);
    });

    it('should set dataSource', async () => {
      const hdf = await parseHdf('surefire-failing.xml');
      expect(hdf.dataSource?.name).toBe('JUnit XML');
      expect(hdf.dataSource?.format).toBe('XML');
    });
  });

  // --- Baseline structure ---

  describe('baseline structure', async () => {
    it('should use testsuite name as baseline name (surefire-failing)', async () => {
      const hdf = await parseHdf('surefire-failing.xml');
      expect(hdf.baselines[0]!.name).toBe(
        'org.apache.maven.surefire.test.FailingTest'
      );
    });

    it('should use testsuite name as baseline name (surefire-error)', async () => {
      const hdf = await parseHdf('surefire-error.xml');
      expect(hdf.baselines[0]!.name).toBe('surefire.MyTest');
    });

    it('should include sha256 checksum', async () => {
      const hdf = await parseHdf('surefire-failing.xml');
      const checksum = hdf.baselines[0]!.resultsChecksum;
      expect(checksum?.algorithm).toBe('sha256');
      expect(checksum?.value).toMatch(/^[a-f0-9]{64}$/);
    });
  });

  // --- Requirements from test cases ---

  describe('requirement fields', async () => {
    it('should create one requirement per testcase (surefire-failing has 2)', async () => {
      const hdf = await parseHdf('surefire-failing.xml');
      expect(hdf.baselines[0]!.requirements).toHaveLength(2);
    });

    it('should use classname.name as requirement ID', async () => {
      const hdf = await parseHdf('surefire-failing.xml');
      const ids = hdf.baselines[0]!.requirements.map((r) => r.id);
      expect(ids).toContain(
        'org.apache.maven.surefire.test.FailingTest.defaultTestValueIs_Value'
      );
      expect(ids).toContain(
        'org.apache.maven.surefire.test.FailingTest.setTestAndRetrieveValue'
      );
    });

    it('should use test name as requirement title', async () => {
      const hdf = await parseHdf('surefire-failing.xml');
      const req = hdf.baselines[0]!.requirements.find(
        (r) =>
          r.id ===
          'org.apache.maven.surefire.test.FailingTest.defaultTestValueIs_Value'
      );
      expect(req?.title).toBe('defaultTestValueIs_Value');
    });

    it('should set impact to 0.5 for all testcases', async () => {
      const hdf = await parseHdf('surefire-failing.xml');
      for (const req of hdf.baselines[0]!.requirements) {
        expect(req.impact).toBe(0.5);
      }
    });

    it('should include default description', async () => {
      const hdf = await parseHdf('surefire-error.xml');
      const req = hdf.baselines[0]!.requirements.find(
        (r) => r.id === 'surefire.MyTest.test'
      );
      const desc = req?.descriptions?.find((d) => d.label === 'default');
      expect(desc?.data).toContain('test');
      expect(desc?.data).toContain('surefire.MyTest');
    });
  });

  // --- Status mapping ---

  describe('status mapping', async () => {
    it('should map failure to failed', async () => {
      const hdf = await parseHdf('surefire-failing.xml');
      for (const req of hdf.baselines[0]!.requirements) {
        expect(req.results[0]?.status).toBe(ResultStatus.Failed);
      }
    });

    it('should map error to error', async () => {
      const hdf = await parseHdf('surefire-error.xml');
      const req = hdf.baselines[0]!.requirements.find(
        (r) => r.id === 'surefire.MyTest.test'
      );
      expect(req?.results[0]?.status).toBe(ResultStatus.Error);
    });

    it('should map passing tests to passed (surefire-flaky)', async () => {
      const hdf = await parseHdf('surefire-flaky.xml');
      for (const req of hdf.baselines[0]!.requirements) {
        expect(req.results[0]?.status).toBe(ResultStatus.Passed);
      }
    });
  });

  // --- Result details ---

  describe('result details', async () => {
    it('should include failure message with type and text', async () => {
      const hdf = await parseHdf('surefire-failing.xml');
      const req = hdf.baselines[0]!.requirements.find(
        (r) =>
          r.id ===
          'org.apache.maven.surefire.test.FailingTest.defaultTestValueIs_Value'
      );
      expect(req?.results[0]?.message).toContain('wrong');
      expect(req?.results[0]?.message).toContain('value');
    });

    it('should include error message with type', async () => {
      const hdf = await parseHdf('surefire-error.xml');
      const req = hdf.baselines[0]!.requirements.find(
        (r) => r.id === 'surefire.MyTest.test'
      );
      expect(req?.results[0]?.message).toContain('RuntimeException');
      expect(req?.results[0]?.message).toContain('this is different message');
    });

    it('should include error stack trace', async () => {
      const hdf = await parseHdf('surefire-error.xml');
      const req = hdf.baselines[0]!.requirements.find(
        (r) => r.id === 'surefire.MyTest.test'
      );
      expect(req?.results[0]?.message).toContain('IndexOutOfBoundsException');
      expect(req?.results[0]?.message).toContain('MyTest.rethrownDelegate');
    });

    it('should include codeDesc with classname and test name', async () => {
      const hdf = await parseHdf('surefire-failing.xml');
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

    it('should include runTime as a number', async () => {
      const hdf = await parseHdf('surefire-failing.xml');
      const req = hdf.baselines[0]!.requirements.find(
        (r) =>
          r.id ===
          'org.apache.maven.surefire.test.FailingTest.defaultTestValueIs_Value'
      );
      expect(req?.results[0]?.runTime).toBeCloseTo(0.013, 3);
    });
  });

  // --- NIST tags ---

  describe('NIST tags', async () => {
    it('should include SA-11 NIST tag on all requirements', async () => {
      const hdf = await parseHdf('surefire-failing.xml');
      for (const req of hdf.baselines[0]!.requirements) {
        expect(req.tags?.['nist']).toContain('SA-11');
      }
    });
  });

  // --- Flaky test handling ---

  describe('flaky test handling', async () => {
    it('should treat flakyFailure/flakyError as passed', async () => {
      const hdf = await parseHdf('surefire-flaky.xml');
      expect(hdf.baselines[0]!.requirements).toHaveLength(2);

      const req = hdf.baselines[0]!.requirements.find(
        (r) => r.id === 'org.acme.FlakyTest.testFlaky'
      );
      expect(req).toBeDefined();
      expect(req?.results[0]?.status).toBe(ResultStatus.Passed);
    });
  });

  // --- Testsuites root with mixed statuses (schema-validated against Windyroad XSD) ---

  describe('testsuites-mixed fixture', async () => {
    it('should handle <testsuites> root element', async () => {
      const hdf = await parseHdf('testsuites-mixed.xml');
      // testsuites has no name attr — should default
      expect(hdf.baselines[0]!.name).toBe('JUnit Test Results');
    });

    it('should produce 5 requirements from 2 suites', async () => {
      const hdf = await parseHdf('testsuites-mixed.xml');
      expect(hdf.baselines[0]!.requirements).toHaveLength(5);
    });

    it('should map skipped test to notReviewed with message', async () => {
      const hdf = await parseHdf('testsuites-mixed.xml');
      const req = hdf.baselines[0]!.requirements.find(
        (r) => r.id === 'com.example.math.MathTest.testSquareRoot'
      );
      expect(req).toBeDefined();
      expect(req?.results[0]?.status).toBe(ResultStatus.NotReviewed);
      expect(req?.results[0]?.message).toContain(
        'Requires math library upgrade'
      );
    });

    it('should map passing test to passed', async () => {
      const hdf = await parseHdf('testsuites-mixed.xml');
      const req = hdf.baselines[0]!.requirements.find(
        (r) => r.id === 'com.example.math.MathTest.testAddition'
      );
      expect(req?.results[0]?.status).toBe(ResultStatus.Passed);
    });

    it('should map failed test with failure message', async () => {
      const hdf = await parseHdf('testsuites-mixed.xml');
      const req = hdf.baselines[0]!.requirements.find(
        (r) => r.id === 'com.example.math.MathTest.testDivisionByZero'
      );
      expect(req?.results[0]?.status).toBe(ResultStatus.Failed);
      expect(req?.results[0]?.message).toContain(
        'Expected exception was not thrown'
      );
    });

    it('should map error test with error message', async () => {
      const hdf = await parseHdf('testsuites-mixed.xml');
      const req = hdf.baselines[0]!.requirements.find(
        (r) => r.id === 'com.example.string.StringTest.testParseInt'
      );
      expect(req?.results[0]?.status).toBe(ResultStatus.Error);
      expect(req?.results[0]?.message).toContain('NullPointerException');
    });

    it('should parse timestamp from suite', async () => {
      const hdf = await parseHdf('testsuites-mixed.xml');
      const req = hdf.baselines[0]!.requirements.find(
        (r) => r.id === 'com.example.math.MathTest.testAddition'
      );
      // Suite has timestamp="2024-11-15T10:30:00" — should appear as startTime
      expect(req?.results[0]?.startTime).toBeTruthy();
    });
  });

  // --- JSON round-trip ---

  describe('JSON round-trip', async () => {
    it('should produce valid JSON that re-parses', async () => {
      const output = await convertJunitToHdf(loadFixture('surefire-failing.xml'));
      const hdf = JSON.parse(output) as HdfResults;
      expect(hdf.generator?.name).toBe('hdf-converters');
      expect(hdf.baselines).toHaveLength(1);
      expect(hdf.baselines[0]!.requirements).toHaveLength(2);
    });
  });
});
