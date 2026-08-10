import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { describe, it, expect } from 'vitest';
import { convertJunitToHdf } from './converter.js';
import { runConverterContractTests } from '../../../shared/typescript/converter-contract.js';
import { expectValidResults } from '../../../test/helpers/expectValidHdf.js';
import {
  assertRequirementCount,
  countXmlElements,
} from '../../../shared/typescript/anchor.js';
import type { HDFResults } from '@mitre/hdf-schema';
import { ResultStatus, TargetType } from '@mitre/hdf-schema';

const __dirname = dirname(fileURLToPath(import.meta.url));
const FIXTURES_DIR = join(__dirname, '..', 'fixtures');

function loadFixture(name: string): string {
  return readFileSync(join(FIXTURES_DIR, 'input', name), 'utf-8');
}

async function parseHdf(fixture: string): Promise<HDFResults> {
  return JSON.parse(await convertJunitToHdf(loadFixture(fixture))) as HDFResults;
}

// Fixtures sourced from apache/maven-surefire test resources:
// https://github.com/apache/maven-surefire/tree/master/surefire-report-parser/src/test/resources/fixture/testsuitexmlparser

runConverterContractTests({
  converterName: 'junit-to-hdf',
  convertFn: convertJunitToHdf,
  minimalFixture: 'surefire-error.xml',
});

// Ground-truth anchor (input-derived count; see shared/typescript/anchor.ts).
// JUnit emits one requirement per <testcase> element across every <testsuite>.
describe('junit-to-hdf ground-truth anchor', () => {
  it('emits one requirement per <testcase>', async () => {
    const input = loadFixture('testsuites-mixed.xml');
    assertRequirementCount(
      await convertJunitToHdf(input),
      countXmlElements(input, 'testcase'),
      'testsuites-mixed.xml: one requirement per <testcase>',
    );
  });
});

describe('junit to HDF converter', async () => {
  // --- Input validation ---

  describe('input validation', async () => {
    it('should throw on unclosed XML', async () => {
      await expect(convertJunitToHdf('<unclosed')).rejects.toThrow();
    });

    it('should throw on non-JUnit XML', async () => {
      await expect(
        convertJunitToHdf('<?xml version="1.0"?><root><item/></root>')
      ).rejects.toThrow(/not a JUnit XML/i);
    });
  });

  // --- startTime fallback ---

  describe('startTime fallback', async () => {
    it('uses conversion time when no testsuite carries a timestamp', async () => {
      const xml = `<?xml version="1.0"?>
<testsuites>
  <testsuite name="s" tests="1" failures="1">
    <testcase name="t" classname="c"><failure message="m">trace</failure></testcase>
  </testsuite>
</testsuites>`;
      const before = Date.now();
      const hdf = JSON.parse(await convertJunitToHdf(xml)) as HDFResults;
      expectValidResults(hdf);
      const startTime = hdf.baselines[0]!.requirements[0]!.results[0]!.startTime;
      expect(startTime).toBeDefined();
      expect(new Date(startTime as string | Date).getTime()).toBeGreaterThanOrEqual(before);
    });
  });

  // --- Conversion basics ---

  describe('conversion basics (surefire-failing)', async () => {
    it('should produce valid HDF structure', async () => {
      const hdf = await parseHdf('surefire-failing.xml');

      expect(hdf.timestamp).toBeTruthy();
      expect(hdf.generator?.name).toBe('junit-to-hdf');
      expect(hdf.generator?.version).toBeTruthy();
      expect(hdf.baselines).toHaveLength(1);
    });

    it('should produce schema-valid HDF results', async () => {
      const hdf = await parseHdf('surefire-failing.xml');
      expectValidResults(hdf);
    });

    it('should set tool', async () => {
      const hdf = await parseHdf('surefire-failing.xml');
      expect(hdf.tool?.name).toBe('JUnit XML');
      expect(hdf.tool?.format).toBeUndefined() // serialization structures are not formats (kpvj);
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

    it('should surface flaky retry system-out/system-err as descriptions', async () => {
      const hdf = await parseHdf('surefire-flaky.xml');
      const req = hdf.baselines[0]!.requirements.find(
        (r) => r.id === 'org.acme.FlakyTest.testFlaky'
      );
      expect(req).toBeDefined();

      const out = req?.descriptions?.find((d) => d.label === 'system-out');
      expect(out).toBeDefined();
      expect(out?.data).toContain('code-with-quarkus 1.0.0-SNAPSHOT on JVM');
      expect(out?.data).toContain('Installed features: [cdi, resteasy-reactive');

      const err = req?.descriptions?.find((d) => d.label === 'system-err');
      expect(err).toBeDefined();
      expect(err?.data).toBe('Test system.err');
    });

    it('should not emit system-out/system-err descriptions when absent', async () => {
      const hdf = await parseHdf('surefire-flaky.xml');
      const req = hdf.baselines[0]!.requirements.find(
        (r) => r.id === 'org.acme.FlakyTest.testStable'
      );
      expect(req).toBeDefined();
      expect(req?.descriptions?.find((d) => d.label === 'system-out')).toBeUndefined();
      expect(req?.descriptions?.find((d) => d.label === 'system-err')).toBeUndefined();
    });

    it('should map direct testcase-level system-out/system-err children', async () => {
      const xml =
        '<?xml version="1.0"?>' +
        '<testsuite name="S"><testcase classname="C" name="t">' +
        '<system-out>  captured stdout\n</system-out>' +
        '<system-err>captured stderr</system-err>' +
        '</testcase></testsuite>';
      const hdf = JSON.parse(await convertJunitToHdf(xml)) as HDFResults;
      const req = hdf.baselines[0]!.requirements.find((r) => r.id === 'C.t');
      expect(req?.descriptions?.find((d) => d.label === 'system-out')?.data).toBe('captured stdout');
      expect(req?.descriptions?.find((d) => d.label === 'system-err')?.data).toBe('captured stderr');
    });

    it('should omit whitespace-only system-out/system-err', async () => {
      const xml =
        '<?xml version="1.0"?>' +
        '<testsuite name="S"><testcase classname="C" name="t">' +
        '<system-out>   \n  </system-out>' +
        '</testcase></testsuite>';
      const hdf = JSON.parse(await convertJunitToHdf(xml)) as HDFResults;
      const req = hdf.baselines[0]!.requirements.find((r) => r.id === 'C.t');
      expect(req?.descriptions?.find((d) => d.label === 'system-out')).toBeUndefined();
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
      const hdf = JSON.parse(output) as HDFResults;
      expect(hdf.generator?.name).toBe('junit-to-hdf');
      expect(hdf.baselines).toHaveLength(1);
      expect(hdf.baselines[0]!.requirements).toHaveLength(2);
    });
  });

  describe('edge cases: missing optional fields', async () => {
    it('should handle testcase with no classname', async () => {
      const xml = `<?xml version="1.0"?>
<testsuites name="Tests">
  <testsuite name="Suite1">
    <testcase name="mytest"/>
  </testsuite>
</testsuites>`;
      const hdf = JSON.parse(await convertJunitToHdf(xml)) as HDFResults;
      const req = hdf.baselines[0]!.requirements[0]!;
      // ID should be just name when no classname
      expect(req.id).toBe('mytest');
      // codeDesc should be just name
      expect(req.results[0]!.codeDesc).toBe('mytest');
    });

    it('should handle testsuites with no name', async () => {
      const xml = `<?xml version="1.0"?>
<testsuites>
  <testsuite name="S1">
    <testcase name="t1" classname="c1"/>
  </testsuite>
</testsuites>`;
      const hdf = JSON.parse(await convertJunitToHdf(xml)) as HDFResults;
      expect(hdf.baselines[0]!.name).toBe('JUnit Test Results');
    });

    it('should handle single testsuite root element with no name', async () => {
      const xml = `<?xml version="1.0"?>
<testsuite>
  <testcase name="t1"/>
</testsuite>`;
      const hdf = JSON.parse(await convertJunitToHdf(xml)) as HDFResults;
      expect(hdf.baselines[0]!.name).toBe('JUnit Test Results');
    });

    it('should handle failure with no type and body', async () => {
      const xml = `<?xml version="1.0"?>
<testsuites name="Tests">
  <testsuite name="Suite1">
    <testcase name="t1" classname="c1">
      <failure message="fail msg"/>
    </testcase>
  </testsuite>
</testsuites>`;
      const hdf = JSON.parse(await convertJunitToHdf(xml)) as HDFResults;
      const req = hdf.baselines[0]!.requirements[0]!;
      expect(req.results[0]!.status).toBe('failed');
      expect(req.results[0]!.message).toContain('fail msg');
    });

    it('should handle error with type and body text', async () => {
      const xml = `<?xml version="1.0"?>
<testsuites name="Tests">
  <testsuite name="Suite1">
    <testcase name="t1" classname="c1">
      <error message="error msg" type="NullPointerException">stack trace here</error>
    </testcase>
  </testsuite>
</testsuites>`;
      const hdf = JSON.parse(await convertJunitToHdf(xml)) as HDFResults;
      const req = hdf.baselines[0]!.requirements[0]!;
      expect(req.results[0]!.status).toBe('error');
      expect(req.results[0]!.message).toContain('NullPointerException');
      expect(req.results[0]!.message).toContain('stack trace here');
    });

    it('should handle skipped with message', async () => {
      const xml = `<?xml version="1.0"?>
<testsuites name="Tests">
  <testsuite name="Suite1">
    <testcase name="t1" classname="c1">
      <skipped message="Not ready"/>
    </testcase>
  </testsuite>
</testsuites>`;
      const hdf = JSON.parse(await convertJunitToHdf(xml)) as HDFResults;
      const req = hdf.baselines[0]!.requirements[0]!;
      expect(req.results[0]!.status).toBe('notReviewed');
      expect(req.results[0]!.message).toContain('Not ready');
    });

    it('should handle skipped with empty element', async () => {
      const xml = `<?xml version="1.0"?>
<testsuites name="Tests">
  <testsuite name="Suite1">
    <testcase name="t1" classname="c1">
      <skipped/>
    </testcase>
  </testsuite>
</testsuites>`;
      const hdf = JSON.parse(await convertJunitToHdf(xml)) as HDFResults;
      expect(hdf.baselines[0]!.requirements[0]!.results[0]!.status).toBe('notReviewed');
      expect(hdf.baselines[0]!.requirements[0]!.results[0]!.message).toBe('Skipped');
    });

    it('should handle testcase with invalid time', async () => {
      const xml = `<?xml version="1.0"?>
<testsuites name="Tests">
  <testsuite name="Suite1">
    <testcase name="t1" classname="c1" time="abc"/>
  </testsuite>
</testsuites>`;
      const hdf = JSON.parse(await convertJunitToHdf(xml)) as HDFResults;
      expect(hdf.baselines[0]!.requirements[0]!.results[0]!.status).toBe('passed');
    });

    it('should synthesize a passed placeholder when testsuite has no testcases', async () => {
      const xml = `<?xml version="1.0"?>
<testsuites name="EmptySuites">
  <testsuite name="EmptySuite"/>
</testsuites>`;
      const hdf = JSON.parse(await convertJunitToHdf(xml)) as HDFResults;
      expect(hdf.baselines[0]!.requirements).toHaveLength(1);
      expect(hdf.baselines[0]!.requirements[0]!.id).toBe('junit-no-findings');
      expect(hdf.baselines[0]!.requirements[0]!.results[0]!.status).toBe(ResultStatus.Passed);
    });

    it('should reject non-JUnit XML', async () => {
      const xml = `<?xml version="1.0"?><other><data/></other>`;
      await expect(convertJunitToHdf(xml)).rejects.toThrow('not a JUnit XML');
    });

    it('should handle testcase with valid run time and suite timestamp', async () => {
      const xml = `<?xml version="1.0"?>
<testsuites name="Tests">
  <testsuite name="Suite1" timestamp="2025-01-01T00:00:00">
    <testcase name="t1" classname="c1" time="0.123"/>
  </testsuite>
</testsuites>`;
      const hdf = JSON.parse(await convertJunitToHdf(xml)) as HDFResults;
      expect(hdf.baselines[0]!.requirements[0]!.results[0]!.status).toBe('passed');
    });
  });

  // --- Empty findings ---

  describe('empty findings', async () => {
    it('should synthesize a passed placeholder when no test cases exist', async () => {
      const hdf = await parseHdf('empty.xml');
      expect(hdf.baselines).toHaveLength(1);
      const reqs = hdf.baselines[0]!.requirements;
      expect(reqs).toHaveLength(1);
      expect(reqs[0]!.id).toBe('junit-no-findings');
      expect(reqs[0]!.results[0]!.status).toBe(ResultStatus.Passed);
      expect(reqs[0]!.results[0]!.codeDesc).toContain('JUnit');
      expect(reqs[0]!.results[0]!.codeDesc).toContain('EmptySuite');
      expect(reqs[0]!.results[0]!.codeDesc).toContain('zero findings');
    });
  });

  // --- Scan-target components ---

  describe('components', async () => {
    it('emits a deduped host component from testsuite @hostname', async () => {
      const hdf = await parseHdf('testsuites-mixed.xml');
      const hosts = hdf.components!.filter((c) => c.type === TargetType.Host);
      expect(hosts).toHaveLength(1);
      expect(hosts[0]!.name).toBe('ci-runner-01');
      expect(hosts[0]!.hostname).toBe('ci-runner-01');
      // Application component is still present.
      expect(hdf.components!.some((c) => c.type === TargetType.Application)).toBe(true);
    });

    it('emits no host component when no testsuite carries a hostname', async () => {
      const hdf = await parseHdf('surefire-failing.xml');
      expect(hdf.components!.some((c) => c.type === TargetType.Host)).toBe(false);
    });

    it('emits distinct host components for distinct hostnames', async () => {
      const xml = `<?xml version="1.0"?>
<testsuites>
  <testsuite name="A" hostname="alpha"><testcase name="t1" classname="c"/></testsuite>
  <testsuite name="B"><testcase name="t2" classname="c"/></testsuite>
  <testsuite name="C" hostname="beta"><testcase name="t3" classname="c"/></testsuite>
  <testsuite name="D" hostname="alpha"><testcase name="t4" classname="c"/></testsuite>
</testsuites>`;
      const hdf = JSON.parse(await convertJunitToHdf(xml)) as HDFResults;
      const hosts = hdf.components!.filter((c) => c.type === TargetType.Host);
      expect(hosts.map((h) => h.name)).toEqual(['alpha', 'beta']);
    });
  });
});
