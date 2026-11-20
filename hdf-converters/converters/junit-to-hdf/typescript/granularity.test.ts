import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { describe, it, expect } from 'vitest';
import { convertJunitToHdf } from './converter.js';
import type { HDFResults } from '@mitre/hdf-schema';
import { ResultStatus } from '@mitre/hdf-schema';

const __dirname = dirname(fileURLToPath(import.meta.url));
const FIXTURES_DIR = join(__dirname, '..', 'fixtures', 'input');

async function parseHdf(name: string): Promise<HDFResults> {
  const input = readFileSync(join(FIXTURES_DIR, name), 'utf-8');
  return JSON.parse(await convertJunitToHdf(input)) as HDFResults;
}

// Twin of go/fidelity_test.go TestGranularity_*. The granularity model: a
// <testcase> is the requirement and a <testsuite> is a grouping, never the unit
// that decides pass or fail. A suite-shaped requirement holding its cases as
// results would roll a mostly-passing suite up to failed under the worst-wins
// ladder and erase every pass from the compliance score.
describe('junit-to-hdf granularity model', () => {
  it('a <testcase> is the requirement; a <testsuite> is a grouping, not a verdict', async () => {
    const hdf = await parseHdf('testsuites-mixed.xml');
    expect(hdf.baselines).toHaveLength(1);
    const reqs = hdf.baselines[0]!.requirements;
    expect(reqs, 'five testcases across two suites').toHaveLength(5);

    for (const r of reqs) {
      expect(r.results, `${r.id}: one testcase, one verdict`).toHaveLength(1);
      expect(['MathTest', 'StringTest'], 'a suite is not a requirement').not.toContain(r.id);
      expect(['MathTest', 'StringTest'], 'a suite is not a requirement').not.toContain(r.title);
    }
    expect(
      Object.fromEntries(reqs.map((r) => [r.id, r.results[0]!.status])),
      'each case keeps its own verdict; nothing is rolled up by suite',
    ).toEqual({
      'com.example.math.MathTest.testAddition': ResultStatus.Passed,
      'com.example.math.MathTest.testDivisionByZero': ResultStatus.Failed,
      'com.example.math.MathTest.testSquareRoot': ResultStatus.NotReviewed,
      'com.example.string.StringTest.testConcat': ResultStatus.Passed,
      'com.example.string.StringTest.testParseInt': ResultStatus.Error,
    });
  });

  // A Surefire flaky case — failed attempts, then a pass — is one passed result.
  // The case's verdict is the one Surefire recorded; the retries are not
  // separate results for the worst-wins ladder to turn into a failure.
  it('a Surefire flaky case converts to one passed result', async () => {
    const hdf = await parseHdf('surefire-flaky.xml');
    const flaky = hdf.baselines[0]!.requirements.find((r) => r.id === 'org.acme.FlakyTest.testFlaky');
    expect(flaky).toBeDefined();
    expect(flaky!.results).toHaveLength(1);
    expect(flaky!.results[0]!.status).toBe(ResultStatus.Passed);
  });
});
