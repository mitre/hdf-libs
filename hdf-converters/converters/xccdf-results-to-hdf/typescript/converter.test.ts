import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { describe, it, expect } from 'vitest';
import { convertXccdfResultsToHdf, convertXccdfBenchmarkToHdf, convertXccdfToHdf, buildCheckCode, extractCheckContentRef, parseReleaseInfo } from './converter.js';
import type { CheckElement } from './converter.js';
import { runConverterContractTests } from '../../../shared/typescript/converter-contract.js';
import { assertRequirementCount, countXmlElements } from '../../../shared/typescript/anchor.js';
import { expectValidResults, expectValidBaseline } from '../../../test/helpers/expectValidHdf.js';
import type { HDFResults, HDFBaseline, BaselineRequirement, EvaluatedRequirement } from '@mitre/hdf-schema';
import { ResultStatus } from '@mitre/hdf-schema';

const __dirname = dirname(fileURLToPath(import.meta.url));
const FIXTURES_DIR = join(__dirname, '..', 'fixtures');

function loadFixture(name: string): string {
  return readFileSync(join(FIXTURES_DIR, 'input', name), 'utf-8');
}

async function parseHdf(fixture: string): Promise<HDFResults> {
  return JSON.parse(await convertXccdfResultsToHdf(loadFixture(fixture))) as HDFResults;
}

async function parseBaseline(fixture: string): Promise<HDFBaseline> {
  return JSON.parse(await convertXccdfBenchmarkToHdf(loadFixture(fixture))) as HDFBaseline;
}

function findReq(
  hdf: HDFResults,
  id: string
): EvaluatedRequirement | undefined {
  return hdf.baselines[0]!.requirements.find((r) => r.id === id);
}

function findBaselineReq(
  baseline: HDFBaseline,
  id: string
): BaselineRequirement | undefined {
  return baseline.requirements.find((r) => r.id === id);
}

// ---------------------------------------------------------------------------
// Fixtures sourced from real OpenSCAP / DISA STIG scan output
// ---------------------------------------------------------------------------

runConverterContractTests({
  converterName: 'xccdf-results-to-hdf',
  convertFn: convertXccdfResultsToHdf,
  minimalFixture: 'minimal.xml',
});

// Ground-truth anchors (input-derived counts; see shared/typescript/anchor.ts).
// These assert the converter reproduces a count derived INDEPENDENTLY from the
// source, catching a silent under-extraction even when Go and TS agree — the gap
// parity cannot see (bead nhia).
describe('xccdf-results-to-hdf ground-truth anchors', () => {
  // Benchmark-only mode: <Rule>s nested inside nested <Group>s must all be
  // flattened (the nhia regression). One requirement per source <Rule>.
  it('emits one requirement per <Rule> across nested groups (SSG)', async () => {
    const input = loadFixture('benchmark-ssg-nested-groups.xml');
    const result = await convertXccdfBenchmarkToHdf(input);
    assertRequirementCount(
      result,
      countXmlElements(input, 'Rule'),
      'benchmark-ssg-nested-groups.xml: one requirement per <Rule> across all nested groups',
    );
  });

  it('emits one requirement per <rule-result> (stig-rhel7)', async () => {
    const input = loadFixture('stig-rhel7.xml');
    const result = await convertXccdfResultsToHdf(input);
    assertRequirementCount(
      result,
      countXmlElements(input, 'rule-result'),
      'stig-rhel7.xml: one requirement per <rule-result>',
    );
  });
});

describe('xccdf-results-to-hdf converter', async () => {
  // --- Input validation ---

  describe('input validation', () => {
    it('should throw on whitespace-only input', async () => {
      await expect(convertXccdfResultsToHdf('   ')).rejects.toThrow('Empty input');
    });

    it('should throw on non-XCCDF XML', async () => {
      await expect(
        convertXccdfResultsToHdf('<?xml version="1.0"?><root><item/></root>')
      ).rejects.toThrow(/not an XCCDF/i);
    });

    it('should throw on XCCDF without TestResult', async () => {
      const xml = `<?xml version="1.0"?>
        <Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2" id="test">
          <status>incomplete</status>
          <version>1.0</version>
        </Benchmark>`;
      await expect(convertXccdfResultsToHdf(xml)).rejects.toThrow(/no TestResult/);
    });
  });

  // --- Minimal fixture ---

  describe('minimal fixture', () => {
    it('should produce valid HDF structure', async () => {
      const hdf = await parseHdf('minimal.xml');
      expectValidResults(hdf);

      expect(hdf.baselines).toHaveLength(1);
      expect(hdf.generator).toBeDefined();
      expect(hdf.tool).toBeDefined();
      expect(hdf.timestamp).toBeTruthy();
    });

    it('should produce 2 requirements from 2 rule-results', async () => {
      const hdf = await parseHdf('minimal.xml');
      expect(hdf.baselines[0]!.requirements).toHaveLength(2);
    });

    it('should map fail result to Failed status', async () => {
      const hdf = await parseHdf('minimal.xml');
      const req = findReq(hdf, 'xccdf_moc.elpmaxe.www_rule_1');
      expect(req).toBeDefined();
      expect(req!.results[0]!.status).toBe(ResultStatus.Failed);
    });

    it('should map pass result to Passed status', async () => {
      const hdf = await parseHdf('minimal.xml');
      const req = findReq(hdf, 'xccdf_moc.elpmaxe.www_rule_2');
      expect(req).toBeDefined();
      expect(req!.results[0]!.status).toBe(ResultStatus.Passed);
    });

    it('should use idref as requirement ID when no version element exists', async () => {
      const hdf = await parseHdf('minimal.xml');
      const ids = hdf.baselines[0]!.requirements.map((r) => r.id);
      expect(ids).toContain('xccdf_moc.elpmaxe.www_rule_1');
      expect(ids).toContain('xccdf_moc.elpmaxe.www_rule_2');
    });

    it('should default impact to 0.5 when no severity is specified', async () => {
      const hdf = await parseHdf('minimal.xml');
      for (const req of hdf.baselines[0]!.requirements) {
        expect(req.impact).toBe(0.5);
      }
    });

    it('should set target name from TestResult target', async () => {
      const hdf = await parseHdf('minimal.xml');
      expect(hdf.components).toBeDefined();
      expect(hdf.components).toHaveLength(1);
      expect(hdf.components![0]!.name).toBe('Test Target');
    });

    it('should set timestamp from TestResult start-time', async () => {
      const hdf = await parseHdf('minimal.xml');
      const ts = new Date(hdf.timestamp as unknown as string);
      expect(ts.getFullYear()).toBe(2012);
    });
  });

  // --- Per-rule startTime (parity with the Go converter) ---

  describe('per-rule-result startTime', () => {
    it('uses each rule-result @time (UTC-normalized), not a single scan-level time', async () => {
      const hdf = await parseHdf('xccdf-results-scc-rhel8.xml');
      expectValidResults(hdf);
      const startTimes = hdf.baselines[0]!.requirements.map(
        (r) => r.results[0]!.startTime as unknown as string,
      );
      // The fixture's rule-results carry distinct @time values; a correct
      // converter reflects them rather than stamping one TestResult start-time.
      expect(new Set(startTimes).size).toBeGreaterThan(1);
      // Zone-less @time values must be emitted as UTC ('Z').
      expect(startTimes.every((t) => t.endsWith('Z'))).toBe(true);
      // A per-rule time that differs from the TestResult start-time (10:24:33).
      expect(startTimes).toContain('2021-12-17T10:24:35Z');
    });
  });

  // --- Required-field fallbacks ---

  describe('schema-required field fallbacks', () => {
    // A rule with neither description nor fixtext, and a TestResult with no
    // start-time, exercises the descriptions-minItems and startTime fallbacks.
    const bareXml = `<?xml version="1.0" encoding="UTF-8"?>
<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2" id="xccdf_test_benchmark_bare">
  <Rule id="xccdf_test_rule_bare" selected="true">
    <check system="http://oval.mitre.org/XMLSchema/oval-definitions-5">
      <check-content-ref name="oval:x:def:1" href="oval.xml"/>
    </check>
  </Rule>
  <TestResult id="xccdf_test_testresult_bare">
    <target>bare-target</target>
    <rule-result idref="xccdf_test_rule_bare">
      <result>pass</result>
    </rule-result>
  </TestResult>
</Benchmark>`;

    it('produces schema-valid HDF with a default description and a startTime', async () => {
      const before = Date.now();
      const hdf = JSON.parse(await convertXccdfResultsToHdf(bareXml)) as HDFResults;
      expectValidResults(hdf);

      const req = hdf.baselines[0]!.requirements[0]!;
      expect(req.descriptions.length).toBeGreaterThanOrEqual(1);
      const startTime = req.results[0]!.startTime;
      expect(startTime).toBeDefined();
      expect(new Date(startTime as string | Date).getTime()).toBeGreaterThanOrEqual(before);
    });

    it('treats a present-but-invalid start-time as missing (does not throw)', async () => {
      const xml = `<?xml version="1.0" encoding="UTF-8"?>
<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2" id="xccdf_test_benchmark_badtime">
  <Rule id="xccdf_test_rule_x" selected="true"><check system="x"><check-content-ref name="o" href="o.xml"/></check></Rule>
  <TestResult id="xccdf_test_testresult_badtime" start-time="not-a-real-date">
    <target>t</target>
    <rule-result idref="xccdf_test_rule_x"><result>pass</result></rule-result>
  </TestResult>
</Benchmark>`;
      const before = Date.now();
      const hdf = JSON.parse(await convertXccdfResultsToHdf(xml)) as HDFResults;
      expectValidResults(hdf);
      const startTime = hdf.baselines[0]!.requirements[0]!.results[0]!.startTime;
      expect(new Date(startTime as string | Date).getTime()).toBeGreaterThanOrEqual(before);
    });
  });

  // --- STIG RHEL7 fixture ---

  describe('STIG RHEL7 fixture', () => {
    it('should set baseline name from Benchmark title', async () => {
      const hdf = await parseHdf('stig-rhel7.xml');
      expect(hdf.baselines[0]!.name).toBe(
        'Red Hat Enterprise Linux 7 Security Technical Implementation Guide'
      );
    });

    it('should produce 5 requirements from 5 rule-results', async () => {
      const hdf = await parseHdf('stig-rhel7.xml');
      expect(hdf.baselines[0]!.requirements).toHaveLength(5);
    });

    it('should use the Rule id vulnerability number as requirement ID', async () => {
      const hdf = await parseHdf('stig-rhel7.xml');
      const ids = hdf.baselines[0]!.requirements.map((r) => r.id);
      expect(ids).toContain('SV-204393');
      expect(ids).toContain('SV-204396');
      expect(ids).toContain('SV-204405');
      expect(ids).toContain('SV-204424');
      expect(ids).toContain('SV-204452');
    });

    it('should set target name to localhost.localdomain', async () => {
      const hdf = await parseHdf('stig-rhel7.xml');
      expect(hdf.components![0]!.name).toBe('localhost.localdomain');
    });

    it('should set target ipAddress to first target-address', async () => {
      const hdf = await parseHdf('stig-rhel7.xml');
      expect(hdf.components![0]!.ipAddress).toBe('127.0.0.1');
    });

    it('should include sha256 results checksum', async () => {
      const hdf = await parseHdf('stig-rhel7.xml');
      const checksum = hdf.baselines[0]!.resultsChecksum;
      expect(checksum?.algorithm).toBe('sha256');
      expect(checksum?.value).toMatch(/^[a-f0-9]{64}$/);
    });

    it('should set generator fields', async () => {
      const hdf = await parseHdf('stig-rhel7.xml');
      expect(hdf.generator?.name).toBe('xccdf-results-to-hdf');
      expect(hdf.generator?.version).toBe('1.0.0');
    });

    it('should set tool fields', async () => {
      const hdf = await parseHdf('stig-rhel7.xml');
      expect(hdf.tool?.name).toBe('XCCDF');
      expect(hdf.tool?.format).toBe('XCCDF');
    });

    it('should set tool.version from TestResult @test-system CPE', async () => {
      const hdf = await parseHdf('stig-rhel7.xml');
      // cpe:/a:redhat:openscap:1.2.17
      expect(hdf.tool?.version).toBe('1.2.17');
      expect(hdf.tool?.name).toBe('XCCDF');
    });

    it('should set tool.version from an SCC scanner CPE', async () => {
      const hdf = await parseHdf('xccdf-results-scc-rhel8.xml');
      // cpe:/a:spawar:scc:5.4.2
      expect(hdf.tool?.version).toBe('5.4.2');
    });

    it('should leave tool.version unset when @test-system is absent', async () => {
      const hdf = await parseHdf('minimal.xml');
      expect(hdf.tool?.version).toBeUndefined();
      expect(hdf.tool?.name).toBe('XCCDF');
    });

    it('should set timestamp from TestResult start-time', async () => {
      const hdf = await parseHdf('stig-rhel7.xml');
      const ts = new Date(hdf.timestamp as unknown as string);
      expect(ts.toISOString()).toContain('2021-12-17');
    });

    it('should compute duration from start-time and end-time', async () => {
      const hdf = await parseHdf('stig-rhel7.xml');
      // 10:39:29 to 10:40:58 = 89 seconds
      expect(hdf.statistics?.duration).toBe(89);
    });

    it('should derive controlType from NIST tags (v3.2 classification field)', async () => {
      const hdf = await parseHdf('stig-rhel7.xml');
      // RHEL-07-010030 maps to AC-* via CCI; expect technical.
      const technicalReq = findReq(hdf, 'SV-204393');
      expect(technicalReq!.controlType).toBe('technical');
    });

    it('should omit controlType when no NIST tag resolves to a known family', async () => {
      const hdf = await parseHdf('stig-rhel7.xml');
      // Find any requirement; if NIST is empty, controlType must be absent.
      for (const req of hdf.baselines[0]!.requirements) {
        const nist = (req.tags as Record<string, unknown>)['nist'] as string[] | undefined;
        if (!nist || nist.length === 0) {
          expect(req.controlType).toBeUndefined();
          return;
        }
      }
      // If we never hit a no-NIST requirement, that's fine; the test is best-effort.
    });
  });

  // --- Rule/group identifier tags (stig_id, cce, legacy_id, gid, gtitle) ---

  describe('rule/group identifier tags', () => {
    it('carries stig_id, cce, legacy_id, gid, gtitle on grouped rules', async () => {
      const hdf = await parseHdf('stig-rhel7.xml');
      const tags = findReq(hdf, 'SV-204393')!.tags as Record<string, unknown>;
      expect(tags['stig_id']).toBe('RHEL-07-010030');
      expect(tags['cce']).toBe('CCE-26970-4');
      expect(tags['legacy_id']).toEqual(['V-71859', 'SV-86483']);
      expect(tags['gid']).toBe('xccdf_mil.disa.stig_group_V-204393');
      expect(tags['gtitle']).toBe('SRG-OS-000023-GPOS-00006');
    });

    it('emits stig_id + gid/gtitle but omits cce/legacy_id when absent (rhel8)', async () => {
      const hdf = await parseHdf('xccdf-results-openscap-rhel8.xml');
      const tags = findReq(hdf, 'SV-230221')!.tags as Record<string, unknown>;
      expect(tags['stig_id']).toBe('RHEL-08-010000');
      expect(tags['gid']).toBe('xccdf_mil.disa.stig_group_V-230221');
      expect(tags['gtitle']).toBe('SRG-OS-000480-GPOS-00227');
      expect('cce' in tags).toBe(false);
      expect('legacy_id' in tags).toBe(false);
    });

    it('omits every identifier tag for un-grouped, version-less rules (minimal)', async () => {
      const hdf = await parseHdf('minimal.xml');
      for (const req of hdf.baselines[0]!.requirements) {
        const tags = req.tags as Record<string, unknown>;
        for (const key of ['stig_id', 'cce', 'legacy_id', 'gid', 'gtitle']) {
          expect(key in tags).toBe(false);
        }
      }
    });
  });

  // --- Severity → impact mapping ---

  describe('severity to impact mapping', () => {
    it('should map high severity to 0.7 impact', async () => {
      const hdf = await parseHdf('stig-rhel7.xml');
      const req = findReq(hdf, 'SV-204424');
      expect(req!.impact).toBe(0.7);
    });

    it('should map medium severity to 0.5 impact', async () => {
      const hdf = await parseHdf('stig-rhel7.xml');
      const req = findReq(hdf, 'SV-204393');
      expect(req!.impact).toBe(0.5);
    });

    it('should map low severity to 0.3 impact', async () => {
      const hdf = await parseHdf('stig-rhel7.xml');
      const req = findReq(hdf, 'SV-204452');
      expect(req!.impact).toBe(0.3);
    });
  });

  // --- Severity enum (results path) ---
  // The results path derives impact from severity but historically never set the
  // requirement.severity enum, unlike the baseline path. Pin the parity.

  describe('severity enum on results-path requirements', () => {
    it('sets high severity from stig-rhel7', async () => {
      const hdf = await parseHdf('stig-rhel7.xml');
      expect(findReq(hdf, 'SV-204424')!.severity).toBe('high');
    });

    it('sets medium severity from stig-rhel7', async () => {
      const hdf = await parseHdf('stig-rhel7.xml');
      expect(findReq(hdf, 'SV-204393')!.severity).toBe('medium');
    });

    it('sets low severity from stig-rhel7', async () => {
      const hdf = await parseHdf('stig-rhel7.xml');
      expect(findReq(hdf, 'SV-204452')!.severity).toBe('low');
    });

    it('derives severity from the rule-result attribute when no Rule defs ship (SCC)', async () => {
      const hdf = await parseHdf('xccdf-results-scc-rhel7.xml');
      expect(findReq(hdf, 'SV-204393')!.severity).toBe('medium');
    });

    it('omits severity="unknown" rather than fabricating one (arf-minimal)', async () => {
      const hdf = await parseHdf('arf-minimal.xml');
      expect(hdf.baselines[0]!.requirements[0]!.severity).toBeUndefined();
    });

    it('falls back to the Rule severity when the rule-result omits it, and omits it when absent everywhere', async () => {
      const input = `<?xml version="1.0" encoding="UTF-8"?>
<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2" id="xccdf_test_benchmark_sev">
  <version>1.0</version>
  <Rule id="xccdf_test_rule_1" selected="true" severity="high">
    <title>Rule with severity</title>
    <description>desc</description>
  </Rule>
  <TestResult id="xccdf_test_testresult_1" start-time="2021-01-01T00:00:00">
    <target>host</target>
    <rule-result idref="xccdf_test_rule_1" time="2021-01-01T00:00:00">
      <result>fail</result>
    </rule-result>
    <rule-result idref="xccdf_unmatched_rule" time="2021-01-01T00:00:00">
      <result>pass</result>
    </rule-result>
  </TestResult>
</Benchmark>`;
      const hdf = JSON.parse(await convertXccdfResultsToHdf(input)) as HDFResults;
      const reqs = hdf.baselines[0]!.requirements;
      expect(reqs[0]!.severity).toBe('high');
      expect(reqs[1]!.severity).toBeUndefined();
    });
  });

  // --- Status mapping ---

  describe('status mapping', () => {
    it('should map fail to Failed (RHEL-07-010030)', async () => {
      const hdf = await parseHdf('stig-rhel7.xml');
      const req = findReq(hdf, 'SV-204393');
      expect(req!.results[0]!.status).toBe(ResultStatus.Failed);
    });

    it('should map pass to Passed (RHEL-07-010118)', async () => {
      const hdf = await parseHdf('stig-rhel7.xml');
      const req = findReq(hdf, 'SV-204405');
      expect(req!.results[0]!.status).toBe(ResultStatus.Passed);
    });

    it('should map error to Error via synthetic input', async () => {
      const xml = `<?xml version="1.0"?>
        <Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2" id="test">
          <status>incomplete</status>
          <version>1.0</version>
          <TestResult id="tr1" start-time="2024-01-01T00:00:00" end-time="2024-01-01T00:00:01">
            <target>host</target>
            <rule-result idref="rule1"><result>error</result></rule-result>
          </TestResult>
        </Benchmark>`;
      const hdf = JSON.parse(await convertXccdfResultsToHdf(xml)) as HDFResults;
      expect(hdf.baselines[0]!.requirements[0]!.results[0]!.status).toBe(
        ResultStatus.Error
      );
    });

    it('should map unknown to Error via synthetic input', async () => {
      const xml = `<?xml version="1.0"?>
        <Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2" id="test">
          <status>incomplete</status>
          <version>1.0</version>
          <TestResult id="tr1" start-time="2024-01-01T00:00:00" end-time="2024-01-01T00:00:01">
            <target>host</target>
            <rule-result idref="rule1"><result>unknown</result></rule-result>
          </TestResult>
        </Benchmark>`;
      const hdf = JSON.parse(await convertXccdfResultsToHdf(xml)) as HDFResults;
      expect(hdf.baselines[0]!.requirements[0]!.results[0]!.status).toBe(
        ResultStatus.Error
      );
    });

    it('should map notapplicable to NotApplicable via synthetic input', async () => {
      const xml = `<?xml version="1.0"?>
        <Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2" id="test">
          <status>incomplete</status>
          <version>1.0</version>
          <TestResult id="tr1" start-time="2024-01-01T00:00:00" end-time="2024-01-01T00:00:01">
            <target>host</target>
            <rule-result idref="rule1"><result>notapplicable</result></rule-result>
          </TestResult>
        </Benchmark>`;
      const hdf = JSON.parse(await convertXccdfResultsToHdf(xml)) as HDFResults;
      expect(hdf.baselines[0]!.requirements[0]!.results[0]!.status).toBe(
        ResultStatus.NotApplicable
      );
    });

    it('should map notchecked to NotReviewed via synthetic input', async () => {
      const xml = `<?xml version="1.0"?>
        <Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2" id="test">
          <status>incomplete</status>
          <version>1.0</version>
          <TestResult id="tr1" start-time="2024-01-01T00:00:00" end-time="2024-01-01T00:00:01">
            <target>host</target>
            <rule-result idref="rule1"><result>notchecked</result></rule-result>
          </TestResult>
        </Benchmark>`;
      const hdf = JSON.parse(await convertXccdfResultsToHdf(xml)) as HDFResults;
      expect(hdf.baselines[0]!.requirements[0]!.results[0]!.status).toBe(
        ResultStatus.NotReviewed
      );
    });

    it('should map notselected to NotReviewed via synthetic input', async () => {
      const xml = `<?xml version="1.0"?>
        <Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2" id="test">
          <status>incomplete</status>
          <version>1.0</version>
          <TestResult id="tr1" start-time="2024-01-01T00:00:00" end-time="2024-01-01T00:00:01">
            <target>host</target>
            <rule-result idref="rule1"><result>notselected</result></rule-result>
          </TestResult>
        </Benchmark>`;
      const hdf = JSON.parse(await convertXccdfResultsToHdf(xml)) as HDFResults;
      expect(hdf.baselines[0]!.requirements[0]!.results[0]!.status).toBe(
        ResultStatus.NotReviewed
      );
    });

    it('should map informational to NotReviewed via synthetic input', async () => {
      const xml = `<?xml version="1.0"?>
        <Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2" id="test">
          <status>incomplete</status>
          <version>1.0</version>
          <TestResult id="tr1" start-time="2024-01-01T00:00:00" end-time="2024-01-01T00:00:01">
            <target>host</target>
            <rule-result idref="rule1"><result>informational</result></rule-result>
          </TestResult>
        </Benchmark>`;
      const hdf = JSON.parse(await convertXccdfResultsToHdf(xml)) as HDFResults;
      expect(hdf.baselines[0]!.requirements[0]!.results[0]!.status).toBe(
        ResultStatus.NotReviewed
      );
    });

    it('should map fixed to Passed via synthetic input', async () => {
      const xml = `<?xml version="1.0"?>
        <Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2" id="test">
          <status>incomplete</status>
          <version>1.0</version>
          <TestResult id="tr1" start-time="2024-01-01T00:00:00" end-time="2024-01-01T00:00:01">
            <target>host</target>
            <rule-result idref="rule1"><result>fixed</result></rule-result>
          </TestResult>
        </Benchmark>`;
      const hdf = JSON.parse(await convertXccdfResultsToHdf(xml)) as HDFResults;
      expect(hdf.baselines[0]!.requirements[0]!.results[0]!.status).toBe(
        ResultStatus.Passed
      );
    });
  });

  // --- CCI and NIST tag extraction ---

  describe('CCI and NIST tag extraction', () => {
    it('should extract CCI tags from rule-result idents', async () => {
      const hdf = await parseHdf('stig-rhel7.xml');
      const req = findReq(hdf, 'SV-204393');
      expect(req!.tags?.['cci']).toContain('CCI-000048');
    });

    it('should map CCI-000048 to NIST AC-8 tags', async () => {
      const hdf = await parseHdf('stig-rhel7.xml');
      const req = findReq(hdf, 'SV-204393');
      const nist = req!.tags?.['nist'] as string[];
      expect(nist).toBeDefined();
      expect(nist.some((n: string) => n.startsWith('AC-8'))).toBe(true);
    });

    it('should map CCI-000366 to NIST CM-6 tags', async () => {
      const hdf = await parseHdf('stig-rhel7.xml');
      const req = findReq(hdf, 'SV-204424');
      const nist = req!.tags?.['nist'] as string[];
      expect(nist).toBeDefined();
      expect(nist.some((n: string) => n.startsWith('CM-6'))).toBe(true);
    });

    it('should map CCI-002617 to NIST SI-2 tags', async () => {
      const hdf = await parseHdf('stig-rhel7.xml');
      const req = findReq(hdf, 'SV-204452');
      const nist = req!.tags?.['nist'] as string[];
      expect(nist).toBeDefined();
      expect(nist.some((n: string) => n.startsWith('SI-2'))).toBe(true);
    });

    it('should not include non-CCI idents in cci tags', async () => {
      const hdf = await parseHdf('stig-rhel7.xml');
      const req = findReq(hdf, 'SV-204393');
      const ccis = req!.tags?.['cci'] as string[];
      // Should not include CCE or legacy idents
      for (const cci of ccis) {
        expect(cci).toMatch(/^CCI-/);
      }
    });

    it('should emit an empty nist tag and no cci tag when no CCI idents exist', async () => {
      const hdf = await parseHdf('minimal.xml');
      const req = findReq(hdf, 'xccdf_moc.elpmaxe.www_rule_1');
      expect(req!.tags?.['cci']).toBeUndefined();
      expect(req!.tags?.['nist']).toEqual([]);
    });
  });

  // --- Descriptions ---

  describe('descriptions', () => {
    it('should extract VulnDiscussion as default description', async () => {
      const hdf = await parseHdf('stig-rhel7.xml');
      const req = findReq(hdf, 'SV-204424');
      const defaultDesc = req!.descriptions.find(
        (d) => d.label === 'default'
      );
      expect(defaultDesc).toBeDefined();
      expect(defaultDesc!.data).toContain('empty password');
    });

    it('should not include raw VulnDiscussion XML tags in description', async () => {
      const hdf = await parseHdf('stig-rhel7.xml');
      const req = findReq(hdf, 'SV-204424');
      const defaultDesc = req!.descriptions.find(
        (d) => d.label === 'default'
      );
      expect(defaultDesc!.data).not.toContain('<VulnDiscussion>');
      expect(defaultDesc!.data).not.toContain('</VulnDiscussion>');
      expect(defaultDesc!.data).not.toContain('<FalsePositives>');
    });

    it('should include fix description from fixtext element', async () => {
      const hdf = await parseHdf('stig-rhel7.xml');
      const req = findReq(hdf, 'SV-204393');
      const fixDesc = req!.descriptions.find((d) => d.label === 'fix');
      expect(fixDesc).toBeDefined();
      expect(fixDesc!.data).toContain('dconf');
    });

    it('should include fix description for RHEL-07-010290', async () => {
      const hdf = await parseHdf('stig-rhel7.xml');
      const req = findReq(hdf, 'SV-204424');
      const fixDesc = req!.descriptions.find((d) => d.label === 'fix');
      expect(fixDesc).toBeDefined();
      expect(fixDesc!.data).toContain('nullok');
    });

    // The results path historically dropped the check description that the
    // baseline path already produces. Pin the restored parity.
    it('emits a check description in the results path (parity with baseline path)', async () => {
      const xml = `<?xml version="1.0" encoding="UTF-8"?>
<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2" id="xccdf_test_benchmark_1">
  <version>1.0</version>
  <Rule id="xccdf_test_rule_1" selected="true" severity="medium">
    <title>Test rule</title>
    <description>&lt;VulnDiscussion&gt;Some discussion&lt;/VulnDiscussion&gt;</description>
    <check system="http://oval.mitre.org/XMLSchema/oval-definitions-5">
      <check-content>OVAL definition logic goes here</check-content>
      <check-content-ref name="oval:x:def:1" href="oval.xml"/>
    </check>
  </Rule>
  <TestResult id="xccdf_test_testresult_1" start-time="2021-01-01T00:00:00">
    <target>host</target>
    <rule-result idref="xccdf_test_rule_1" time="2021-01-01T00:00:00">
      <result>fail</result>
    </rule-result>
  </TestResult>
</Benchmark>`;
      const hdf = JSON.parse(await convertXccdfResultsToHdf(xml)) as HDFResults;
      const req = hdf.baselines[0]!.requirements[0]!;
      const checkDesc = req.descriptions.find((d) => d.label === 'check');
      expect(checkDesc).toBeDefined();
      expect(checkDesc!.data).toContain('OVAL definition logic goes here');
    });

    // heimdall2 sources the check description from the OVAL/SCE definition name
    // (check-content-ref/@name) that SCAP content carries instead of inline
    // logic. Ours previously read only the (empty) inline content.
    it('sources the check description from the OVAL definition name when inline content is absent', async () => {
      const hdf = await parseHdf('stig-rhel7.xml');
      const req = findReq(hdf, 'SV-204393');
      const checkDesc = req!.descriptions.find((d) => d.label === 'check');
      expect(checkDesc).toBeDefined();
      expect(checkDesc!.data).toBe('oval:mil.disa.stig.rhel7:def:922');
    });

    // Baseline path: rationale and warning descriptions must be emitted when the
    // source Rule carries them. Pinned against benchmark-ssg-nested-groups.
    it('emits rationale and warning descriptions in the baseline path', async () => {
      const baseline = await parseBaseline('benchmark-ssg-nested-groups.xml');
      const dnsmasq = findBaselineReq(
        baseline,
        'xccdf_org.ssgproject.content_rule_package_dnsmasq_removed'
      );
      const rationale = dnsmasq!.descriptions.find(
        (d) => d.label === 'rationale'
      );
      expect(rationale).toBeDefined();
      expect(rationale!.data).toContain('specifically designated to act as a DNS');

      const withWarning = baseline.requirements.find((r) =>
        r.descriptions.some((d) => d.label === 'warning')
      );
      expect(withWarning).toBeDefined();
      const warning = withWarning!.descriptions.find(
        (d) => d.label === 'warning'
      );
      expect(warning!.data.length).toBeGreaterThan(0);
    });
  });

  // --- requirement.refs (external references) ---

  describe('requirement.refs', () => {
    // STIG Dublin Core reference (publisher/identifier/type) → ref object array.
    it('emits a Dublin Core reference as a ref object array in the results path', async () => {
      const hdf = await parseHdf('stig-rhel7.xml');
      const req = findReq(hdf, 'SV-204393');
      expect(req!.refs).toBeDefined();
      expect(req!.refs!).toHaveLength(1);
      const ref = req!.refs![0]!.ref as Record<string, string>[];
      expect(Array.isArray(ref)).toBe(true);
      expect(ref[0]).toEqual({
        identifier: '2899',
        publisher: 'DISA',
        type: 'DPMS Target',
      });
      expect(req!.refs![0]!.url).toBeUndefined();
    });

    // SSG/CIS text-body reference with an href → ref string + url.
    it('emits a text-body reference as a string with its href as url in the baseline path', async () => {
      const baseline = await parseBaseline('benchmark-ssg-nested-groups.xml');
      const req = findBaselineReq(
        baseline,
        'xccdf_org.ssgproject.content_rule_service_dnsmasq_disabled'
      );
      expect(req!.refs).toBeDefined();
      expect(req!.refs![0]!.ref).toBe('2.1.6');
      expect(req!.refs![0]!.url).toBe(
        'https://www.cisecurity.org/benchmark/red_hat_linux/'
      );
    });
  });

  // --- impact zeroing for skipped statuses ---

  describe('impact zeroing', () => {
    // heimdall2 zeros impact for not-applicable/not-selected/informational
    // rule-results regardless of severity; status still records the disposition.
    it('zeros impact for notapplicable/notselected/informational, keeping real failures weighted', async () => {
      const xml = `<?xml version="1.0" encoding="UTF-8"?>
<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2" id="xccdf_test_benchmark_impact">
  <version>1.0</version>
  <Rule id="rule_na" selected="true" severity="high"><title>NA</title></Rule>
  <Rule id="rule_ns" selected="true" severity="high"><title>NS</title></Rule>
  <Rule id="rule_info" selected="true" severity="high"><title>INFO</title></Rule>
  <Rule id="rule_fail" selected="true" severity="high"><title>FAIL</title></Rule>
  <TestResult id="xccdf_test_tr" start-time="2021-01-01T00:00:00">
    <target>host</target>
    <rule-result idref="rule_na" time="2021-01-01T00:00:00"><result>notapplicable</result></rule-result>
    <rule-result idref="rule_ns" time="2021-01-01T00:00:00"><result>notselected</result></rule-result>
    <rule-result idref="rule_info" time="2021-01-01T00:00:00"><result>informational</result></rule-result>
    <rule-result idref="rule_fail" time="2021-01-01T00:00:00"><result>fail</result></rule-result>
  </TestResult>
</Benchmark>`;
      const hdf = JSON.parse(await convertXccdfResultsToHdf(xml)) as HDFResults;
      const reqs = hdf.baselines[0]!.requirements;
      const byTitle = (t: string) => reqs.find((r) => r.title === t)!;
      expect(byTitle('NA').impact).toBe(0);
      expect(byTitle('NS').impact).toBe(0);
      expect(byTitle('INFO').impact).toBe(0);
      expect(byTitle('FAIL').impact).toBe(0.7);
    });
  });

  // Branch pins for the ref/description edge cases the real fixtures never hit
  // (empty references, inline check-content with attributes, revision-less SV
  // ids). Synthetic XML inputs, not committed fixtures — no fabricated data.
  describe('branch coverage (synthetic inputs)', () => {
    it('skips an empty <reference>, keeps an href-only ref, and carries reference text', async () => {
      const xml = `<?xml version="1.0" encoding="UTF-8"?>
<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2" xmlns:dc="http://purl.org/dc/elements/1.1/" id="xccdf_test_refedge">
  <version>1.0</version>
  <Rule id="rule_refs" selected="true" severity="low">
    <title>Ref edge cases</title>
    <reference></reference>
    <reference href="https://example.test/a"/>
    <reference>freetext<dc:publisher>ACME</dc:publisher></reference>
  </Rule>
  <TestResult id="xccdf_test_tr" start-time="2021-01-01T00:00:00">
    <target>host</target>
    <rule-result idref="rule_refs" time="2021-01-01T00:00:00"><result>pass</result></rule-result>
  </TestResult>
</Benchmark>`;
      const hdf = JSON.parse(await convertXccdfResultsToHdf(xml)) as HDFResults;
      const refs = hdf.baselines[0]!.requirements[0]!.refs;
      // The empty reference is dropped; the href-only and text refs remain.
      expect(refs).toEqual([
        { url: 'https://example.test/a' },
        { ref: [{ publisher: 'ACME', text: 'freetext' }] },
      ]);
    });

    it('reads inline check-content that carries an attribute (array-of-object form)', async () => {
      const xml = `<?xml version="1.0" encoding="UTF-8"?>
<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2" id="xccdf_test_ccattr">
  <version>1.0</version>
  <Rule id="rule_cc" selected="true" severity="low">
    <title>CC attr</title>
    <check system="s"><check-content lang="en">inline logic</check-content></check>
  </Rule>
  <TestResult id="xccdf_test_tr" start-time="2021-01-01T00:00:00">
    <target>host</target>
    <rule-result idref="rule_cc" time="2021-01-01T00:00:00"><result>pass</result></rule-result>
  </TestResult>
</Benchmark>`;
      const hdf = JSON.parse(await convertXccdfResultsToHdf(xml)) as HDFResults;
      const checkDesc = hdf.baselines[0]!.requirements[0]!.descriptions.find(
        (d) => d.label === 'check'
      );
      expect(checkDesc!.data).toBe('inline logic');
    });

    it('falls back to the OVAL name when check-content is an empty attributed element', async () => {
      const xml = `<?xml version="1.0" encoding="UTF-8"?>
<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2" id="xccdf_test_ccempty">
  <version>1.0</version>
  <Rule id="rule_cc" selected="true" severity="low">
    <title>CC empty</title>
    <check system="s">
      <check-content lang="en"></check-content>
      <check-content-ref name="oval:x:def:9" href="o.xml"/>
    </check>
  </Rule>
  <TestResult id="xccdf_test_tr" start-time="2021-01-01T00:00:00">
    <target>host</target>
    <rule-result idref="rule_cc" time="2021-01-01T00:00:00"><result>pass</result></rule-result>
  </TestResult>
</Benchmark>`;
      const hdf = JSON.parse(await convertXccdfResultsToHdf(xml)) as HDFResults;
      const checkDesc = hdf.baselines[0]!.requirements[0]!.descriptions.find(
        (d) => d.label === 'check'
      );
      expect(checkDesc!.data).toBe('oval:x:def:9');
    });

    it('keeps a revision-less SV id unchanged', async () => {
      const xml = `<?xml version="1.0" encoding="UTF-8"?>
<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2" id="xccdf_test_svid">
  <version>1.0</version>
  <Rule id="SV-99999" selected="true" severity="low"><title>No revision</title></Rule>
  <TestResult id="xccdf_test_tr" start-time="2021-01-01T00:00:00">
    <target>host</target>
    <rule-result idref="SV-99999" time="2021-01-01T00:00:00"><result>pass</result></rule-result>
  </TestResult>
</Benchmark>`;
      const hdf = JSON.parse(await convertXccdfResultsToHdf(xml)) as HDFResults;
      expect(hdf.baselines[0]!.requirements[0]!.id).toBe('SV-99999');
    });
  });

  // --- requirement.code (CODE tab) ---

  describe('requirement.code', () => {
    it('carries the OVAL check-content-ref name/href as the code fill', async () => {
      const hdf = await parseHdf('stig-rhel7.xml');
      const req = findReq(hdf, 'SV-204393');
      expect(req!.code).toBeDefined();
      const parsed = JSON.parse(req!.code!) as {
        system: string;
        checkContentRef: { name: string; href: string };
      };
      expect(parsed.system).toBe(
        'http://oval.mitre.org/XMLSchema/oval-definitions-5'
      );
      expect(parsed.checkContentRef.name).toBe(
        'oval:mil.disa.stig.rhel7:def:922'
      );
      expect(parsed.checkContentRef.href).toContain('oval.xml');
    });

    // Fixtures only carry check-content-ref with empty inline check-content;
    // these crafted inputs exercise the remaining buildCheckCode branches.
    it('includes inline check-content and omits checkContentRef when only content is present', async () => {
      const xml = `<?xml version="1.0" encoding="UTF-8"?>
<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2" id="xccdf_test_benchmark_c">
  <version>1.0</version>
  <Rule id="xccdf_test_rule_1" selected="true" severity="medium">
    <title>Inline content rule</title>
    <description>desc</description>
    <check system="http://oval.mitre.org/XMLSchema/oval-definitions-5">
      <check-content>  OVAL definition logic  </check-content>
    </check>
  </Rule>
  <TestResult id="xccdf_test_testresult_1" start-time="2021-01-01T00:00:00">
    <target>host</target>
    <rule-result idref="xccdf_test_rule_1" time="2021-01-01T00:00:00">
      <result>fail</result>
    </rule-result>
  </TestResult>
</Benchmark>`;
      const hdf = JSON.parse(await convertXccdfResultsToHdf(xml)) as HDFResults;
      const req = hdf.baselines[0]!.requirements[0]!;
      expect(req.code).toBeDefined();
      const parsed = JSON.parse(req.code!) as Record<string, unknown>;
      expect(parsed.checkContent).toBe('OVAL definition logic');
      expect(parsed.checkContentRef).toBeUndefined();
    });

    it('leaves code unset when the check element is empty', async () => {
      const xml = `<?xml version="1.0" encoding="UTF-8"?>
<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2" id="xccdf_test_benchmark_e">
  <version>1.0</version>
  <Rule id="xccdf_test_rule_1" selected="true" severity="low">
    <title>Empty check rule</title>
    <description>desc</description>
    <check></check>
  </Rule>
  <TestResult id="xccdf_test_testresult_1" start-time="2021-01-01T00:00:00">
    <target>host</target>
    <rule-result idref="xccdf_test_rule_1" time="2021-01-01T00:00:00">
      <result>pass</result>
    </rule-result>
  </TestResult>
</Benchmark>`;
      const hdf = JSON.parse(await convertXccdfResultsToHdf(xml)) as HDFResults;
      const req = hdf.baselines[0]!.requirements[0]!;
      expect(req.code).toBeUndefined();
    });

    it('leaves code unset when the rule has no check element', async () => {
      const xml = `<?xml version="1.0" encoding="UTF-8"?>
<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2" id="xccdf_test_benchmark_2">
  <version>1.0</version>
  <Rule id="xccdf_test_rule_1" selected="true" severity="low">
    <title>No check rule</title>
    <description>desc</description>
  </Rule>
  <TestResult id="xccdf_test_testresult_1" start-time="2021-01-01T00:00:00">
    <target>host</target>
    <rule-result idref="xccdf_test_rule_1" time="2021-01-01T00:00:00">
      <result>pass</result>
    </rule-result>
  </TestResult>
</Benchmark>`;
      const hdf = JSON.parse(await convertXccdfResultsToHdf(xml)) as HDFResults;
      const req = hdf.baselines[0]!.requirements[0]!;
      expect(req.code).toBeUndefined();
    });
  });

  // --- Rule title ---

  describe('rule title', () => {
    it('should set requirement title from Rule title element', async () => {
      const hdf = await parseHdf('stig-rhel7.xml');
      const req = findReq(hdf, 'SV-204424');
      expect(req!.title).toContain('blank or null passwords');
    });

    it('should fall back to ID for title when Rule has no title', async () => {
      const hdf = await parseHdf('minimal.xml');
      const req = findReq(hdf, 'xccdf_moc.elpmaxe.www_rule_1');
      // Rule in minimal.xml has no <title>, so title falls back to the ID
      expect(req!.title).toBe('xccdf_moc.elpmaxe.www_rule_1');
    });
  });

  // --- JSON round-trip ---

  describe('JSON round-trip', () => {
    it('should produce valid JSON that re-parses', async () => {
      const output = await convertXccdfResultsToHdf(
        loadFixture('stig-rhel7.xml')
      );
      const hdf = JSON.parse(output) as HDFResults;
      expect(hdf.generator?.name).toBe('xccdf-results-to-hdf');
      expect(hdf.baselines).toHaveLength(1);
      expect(hdf.baselines[0]!.requirements).toHaveLength(5);
    });
  });

  // --- ARF (Asset Reporting Format) support ---

  describe('ARF input', () => {
    it('should detect ARF input and produce valid HDF', async () => {
      const hdf = await parseHdf('arf-minimal.xml');

      expect(hdf.baselines).toHaveLength(1);
      expect(hdf.generator).toBeDefined();
      expect(hdf.tool).toBeDefined();
      expect(hdf.components).toBeDefined();
      expect(hdf.components).toHaveLength(1);
    });

    it('should produce 1 requirement from 1 ARF rule-result', async () => {
      const hdf = await parseHdf('arf-minimal.xml');
      expect(hdf.baselines[0]!.requirements).toHaveLength(1);
    });

    it('should map fail result to Failed status', async () => {
      const hdf = await parseHdf('arf-minimal.xml');
      const req = hdf.baselines[0]!.requirements[0]!;
      expect(req.results[0]!.status).toBe(ResultStatus.Failed);
    });

    it('should set baseline name from embedded Benchmark title', async () => {
      const hdf = await parseHdf('arf-minimal.xml');
      expect(hdf.baselines[0]!.name).toBe('Test Benchmark');
    });

    it('should set target name from TestResult target element', async () => {
      const hdf = await parseHdf('arf-minimal.xml');
      expect(hdf.components![0]!.name).toBe('rh-hony');
    });

    it('should set target IP from TestResult target-address', async () => {
      const hdf = await parseHdf('arf-minimal.xml');
      expect(hdf.components![0]!.ipAddress).toBe('127.0.0.1');
    });

    it('should enrich target with ARF asset FQDN', async () => {
      const hdf = await parseHdf('arf-minimal.xml');
      expect(hdf.components![0]!.fqdn).toBe('rh-hony');
    });

    it('should enrich target with ARF asset MAC address', async () => {
      const hdf = await parseHdf('arf-minimal.xml');
      expect(hdf.components![0]!.macAddress).toBeDefined();
      expect(hdf.components![0]!.macAddress).not.toBe('');
    });

    it('should set tool name to ARF', async () => {
      const hdf = await parseHdf('arf-minimal.xml');
      expect(hdf.tool?.name).toBe('ARF');
      expect(hdf.tool?.format).toBe('ARF');
    });

    it('should set tool.version from the ARF TestResult @test-system CPE', async () => {
      const hdf = await parseHdf('arf-minimal.xml');
      // cpe:/a:redhat:openscap:1.3.5
      expect(hdf.tool?.version).toBe('1.3.5');
      expect(hdf.tool?.name).toBe('ARF');
    });

    it('should skip OVAL reports and only produce baselines from XCCDF', async () => {
      // arf-minimal.xml has 2 reports: xccdf1 and oval0
      const hdf = await parseHdf('arf-minimal.xml');
      expect(hdf.baselines).toHaveLength(1);
    });

    it('should include sha256 results checksum', async () => {
      const hdf = await parseHdf('arf-minimal.xml');
      const checksum = hdf.baselines[0]!.resultsChecksum;
      expect(checksum?.algorithm).toBe('sha256');
      expect(checksum?.value).toMatch(/^[a-f0-9]{64}$/);
    });

    it('should set timestamp from TestResult start-time', async () => {
      const hdf = await parseHdf('arf-minimal.xml');
      const ts = new Date(hdf.timestamp as unknown as string);
      expect(ts.getFullYear()).toBe(2021);
    });

    it('should still handle raw XCCDF input after ARF support added', async () => {
      // Regression test: raw XCCDF must still work
      const hdf = await parseHdf('stig-rhel7.xml');
      expect(hdf.baselines).toHaveLength(1);
      expect(hdf.baselines[0]!.requirements).toHaveLength(5);
    });
  });

  // --- XCCDF 1.1 benchmark-only input (should error for results API) ---

  describe('XCCDF 1.1 benchmark without TestResult', () => {
    it('should error when calling convertXccdfResultsToHdf', async () => {
      await expect(
        convertXccdfResultsToHdf(loadFixture('benchmark-minimal-1.1.xml'))
      ).rejects.toThrow(/no TestResult/);
    });
  });

  describe('empty rule-results', () => {
    it('should synthesize a passed placeholder for XCCDF TestResult with no rule-results', async () => {
      const result = await parseHdf('empty.xml');
      expect(result.baselines).toHaveLength(1);
      const reqs = result.baselines[0]!.requirements;
      expect(reqs).toHaveLength(1);
      expect(reqs[0]!.id).toBe('xccdf-results-no-findings');
      expect(reqs[0]!.results[0]!.status).toBe('passed');
      expect(reqs[0]!.results[0]!.codeDesc).toContain('XCCDF');
      expect(reqs[0]!.results[0]!.codeDesc).toContain('empty-host.example.com');
      expect(reqs[0]!.results[0]!.codeDesc).toContain('zero findings');
    });

    it('should synthesize a passed placeholder for ARF report with no rule-results', async () => {
      const xml = `<?xml version="1.0" encoding="UTF-8"?>
        <asset-report-collection>
          <reports>
            <report id="r1">
              <content>
                <TestResult id="TR-1"><target>arf-empty-host</target></TestResult>
              </content>
            </report>
          </reports>
        </asset-report-collection>`;
      const hdf = JSON.parse(await convertXccdfResultsToHdf(xml)) as HDFResults;
      expect(hdf.baselines).toHaveLength(1);
      const reqs = hdf.baselines[0]!.requirements;
      expect(reqs).toHaveLength(1);
      expect(reqs[0]!.id).toBe('xccdf-results-no-findings');
      expect(reqs[0]!.results[0]!.status).toBe('passed');
      expect(reqs[0]!.results[0]!.codeDesc).toContain('XCCDF');
      expect(reqs[0]!.results[0]!.codeDesc).toContain('arf-empty-host');
      expect(reqs[0]!.results[0]!.codeDesc).toContain('zero findings');
    });
  });
});

// ---------------------------------------------------------------------------
// Benchmark-to-Baseline conversion
// ---------------------------------------------------------------------------

describe('xccdf-benchmark-to-hdf converter', async () => {
  describe('multi-check rules prefer the automated OVAL check', () => {
    it('sets check_id to the OVAL system, not whichever check comes last', async () => {
      const baseline = await parseBaseline('benchmark-ssg-nested-groups.xml');
      const ovalSystem = 'http://oval.mitre.org/XMLSchema/oval-definitions-5';
      for (const rid of [
        'xccdf_org.ssgproject.content_rule_package_dnsmasq_removed',
        'xccdf_org.ssgproject.content_rule_package_bind_removed',
        'xccdf_org.ssgproject.content_rule_service_named_disabled',
      ]) {
        const req = findBaselineReq(baseline, rid);
        expect(req?.tags?.['check_id']).toBe(ovalSystem);
      }
    });
  });

  describe('input validation', () => {
    it('should throw on empty input', async () => {
      await expect(convertXccdfBenchmarkToHdf('')).rejects.toThrow('Empty input');
    });

    it('should throw on non-XCCDF XML', async () => {
      await expect(
        convertXccdfBenchmarkToHdf('<?xml version="1.0"?><root/>')
      ).rejects.toThrow(/not an XCCDF/i);
    });

    it('should throw on results document', async () => {
      await expect(
        convertXccdfBenchmarkToHdf(loadFixture('stig-rhel7.xml'))
      ).rejects.toThrow(/TestResult/);
    });
  });

  describe('XCCDF 1.1 minimal benchmark', () => {
    it('should produce valid baseline structure', async () => {
      const baseline = await parseBaseline('benchmark-minimal-1.1.xml');

      expect(baseline.name).toBe('ms-windows-server-2022-stig');
      expect(baseline.title).toBe('Microsoft Windows Server 2022 Security Technical Implementation Guide');
      expect(baseline.version).toBe('2');
      expect(baseline.status).toBe('loaded');
      expect(baseline.summary).toContain('Security Technical Implementation Guide');
      expect(baseline.requirements).toHaveLength(3);
      expect(baseline.groups).toHaveLength(3);
    });

    it('should use Rule version as requirement ID', async () => {
      const baseline = await parseBaseline('benchmark-minimal-1.1.xml');
      const ids = baseline.requirements.map((r) => r.id);
      expect(ids).toContain('SV-254238');
      expect(ids).toContain('SV-254239');
      expect(ids).toContain('SV-254240');
    });

    it('should map severity to impact', async () => {
      const baseline = await parseBaseline('benchmark-minimal-1.1.xml');
      const req10 = findBaselineReq(baseline, 'SV-254238');
      expect(req10!.impact).toBe(0.5); // medium
      const req30 = findBaselineReq(baseline, 'SV-254240');
      expect(req30!.impact).toBe(0.7); // high
    });

    it('carries the DISA description sub-elements as tags', async () => {
      const xml = `<?xml version="1.0" encoding="UTF-8"?>
<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.1" id="B">
  <title>B</title>
  <version>1</version>
  <Group id="V-1">
    <title>G</title>
    <Rule id="SV-1r1_rule" severity="medium">
      <version>STIG-1</version>
      <title>Rule One</title>
      <description>&lt;VulnDiscussion&gt;Why&lt;/VulnDiscussion&gt;&lt;FalsePositives&gt;&lt;/FalsePositives&gt;&lt;FalseNegatives&gt;&lt;/FalseNegatives&gt;&lt;Documentable&gt;true&lt;/Documentable&gt;&lt;Mitigations&gt;Use &lt;b&gt;TLS&lt;/b&gt;&lt;/Mitigations&gt;&lt;SeverityOverrideGuidance&gt;Elevate to CAT I if world-writable.&lt;/SeverityOverrideGuidance&gt;&lt;Responsibility&gt;System Administrator&lt;/Responsibility&gt;&lt;Responsibility&gt;Information Assurance Officer&lt;/Responsibility&gt;&lt;IAControls&gt;ECAR-1, ECAR-2&lt;/IAControls&gt;</description>
      <fixtext>Fix it</fixtext>
    </Rule>
  </Group>
</Benchmark>`;
      const baseline = JSON.parse(await convertXccdfBenchmarkToHdf(xml)) as HDFBaseline;
      const tags = (baseline.requirements as BaselineRequirement[])[0]!.tags!;
      expect(tags['documentable']).toBe(true);
      expect(tags['responsibility']).toEqual(['System Administrator', 'Information Assurance Officer']);
      expect(tags['ia_controls']).toBe('ECAR-1, ECAR-2');
      expect(tags['mitigations']).toBe('Use TLS');
      expect(tags['severity_override_guidance']).toBe('Elevate to CAT I if world-writable.');
      for (const absent of ['false_positives', 'false_negatives', 'potential_impacts', 'third_party_tools', 'mitigation_control', 'vuln_discussion']) {
        expect(tags).not.toHaveProperty(absent);
      }
    });

    it('omits documentable when its value is not a boolean', async () => {
      const xml = `<?xml version="1.0" encoding="UTF-8"?>
<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.1" id="B">
  <title>B</title>
  <version>1</version>
  <Group id="V-1">
    <title>G</title>
    <Rule id="SV-1r1_rule" severity="medium">
      <version>STIG-1</version>
      <title>Rule One</title>
      <description>&lt;VulnDiscussion&gt;Why&lt;/VulnDiscussion&gt;&lt;Documentable&gt;maybe&lt;/Documentable&gt;</description>
    </Rule>
  </Group>
</Benchmark>`;
      const baseline = JSON.parse(await convertXccdfBenchmarkToHdf(xml)) as HDFBaseline;
      expect((baseline.requirements as BaselineRequirement[])[0]!.tags).not.toHaveProperty('documentable');
    });

    it('carries the sub-elements the real DISA fixtures fill', async () => {
      const sles = await parseBaseline('U_SLES_V11_for_System_z_STIG_V1R12_Manual-xccdf.xml');
      const byId = new Map((sles.requirements as BaselineRequirement[]).map((r) => [r.id, r]));
      expect(byId.get('SV-44791')!.tags!['documentable']).toBe(true);
      expect(byId.get('SV-44760')!.tags!['documentable']).toBe(false);
      expect(byId.get('SV-45877')!.tags!['responsibility']).toEqual(['System Administrator', 'Information Assurance Officer']);
      expect(byId.get('SV-44760')!.tags!['responsibility']).toEqual(['System Administrator']);
      expect(byId.get('SV-45872')!.tags!['false_positives']).toMatch(/^False positives may occur with the SMTP EXPN check/);
      expect(byId.get('SV-45723')!.tags!['mitigations']).toBe('GEN000000-FW');
      expect(byId.get('SV-45723')!.tags!['mitigation_control']).toMatch(/^The system's firewall default-deny policy/);
      expect(byId.get('SV-45286')!.tags!['ia_controls']).toBe('ECAR-1, ECAR-2, ECAR-3');
      const mfd = await parseBaseline('U_Multifunction_Device_and_Network_Printers_STIG_V2R15_Manual-xccdf.xml');
      const r = (mfd.requirements as BaselineRequirement[]).find((x) => x.id === 'SV-7015');
      expect(r!.tags!['potential_impacts']).toMatch(/^Print clients configured to use the unauthorized port\(s\)/);
    });

    it('should extract VulnDiscussion as default description', async () => {
      const baseline = await parseBaseline('benchmark-minimal-1.1.xml');
      const req = findBaselineReq(baseline, 'SV-254238');
      const defaultDesc = req!.descriptions.find((d) => d.label === 'default');
      expect(defaultDesc).toBeDefined();
      expect(defaultDesc!.data).toContain('privileged account');
      expect(defaultDesc!.data).not.toContain('<VulnDiscussion>');
    });

    it('should extract check-content as check description', async () => {
      const baseline = await parseBaseline('benchmark-minimal-1.1.xml');
      const req = findBaselineReq(baseline, 'SV-254238');
      const checkDesc = req!.descriptions.find((d) => d.label === 'check');
      expect(checkDesc).toBeDefined();
      expect(checkDesc!.data).toContain('administrative privileges');
    });

    it('should extract fixtext as fix description', async () => {
      const baseline = await parseBaseline('benchmark-minimal-1.1.xml');
      const req = findBaselineReq(baseline, 'SV-254238');
      const fixDesc = req!.descriptions.find((d) => d.label === 'fix');
      expect(fixDesc).toBeDefined();
      expect(fixDesc!.data).toContain('separate account');
    });

    it('should extract CCI tags', async () => {
      const baseline = await parseBaseline('benchmark-minimal-1.1.xml');
      const req = findBaselineReq(baseline, 'SV-254238');
      expect(req!.tags['cci']).toContain('CCI-000366');
      expect(req!.tags['nist']).toBeDefined();
    });

    it('should extract multiple CCI idents', async () => {
      const baseline = await parseBaseline('benchmark-minimal-1.1.xml');
      const req = findBaselineReq(baseline, 'SV-254239');
      const ccis = req!.tags['cci'] as string[];
      expect(ccis).toHaveLength(2);
      expect(ccis).toContain('CCI-004066');
      expect(ccis).toContain('CCI-000199');
    });

    it('should include STIG-specific tags', async () => {
      const baseline = await parseBaseline('benchmark-minimal-1.1.xml');
      const req = findBaselineReq(baseline, 'SV-254238');
      expect(req!.tags['rid']).toBe('SV-254238r991589_rule');
      expect(req!.tags['stig_id']).toBe('WN22-00-000010');
      expect(req!.tags['severity']).toBe('medium');
      expect(req!.tags['check_id']).toBe('C-57723r848528_chk');
      expect(req!.tags['fix_id']).toBe('F-57674r848529_fix');
      expect(req!.tags['gid']).toBe('V-254238');
      expect(req!.tags['gtitle']).toBe('SRG-OS-000480-GPOS-00227');
    });

    it('should set groups', async () => {
      const baseline = await parseBaseline('benchmark-minimal-1.1.xml');
      expect(baseline.groups).toHaveLength(3);
      expect(baseline.groups![0]!.id).toBe('V-254238');
      expect(baseline.groups![0]!.title).toBe('SRG-OS-000480-GPOS-00227');
      expect(baseline.groups![0]!.requirements).toEqual(['SV-254238']);
    });

    it('should include generator', async () => {
      const baseline = await parseBaseline('benchmark-minimal-1.1.xml');
      expect(baseline.generator?.name).toBe('xccdf-results-to-hdf');
      expect(baseline.generator?.version).toBe('1.0.0');
    });

    it('should include integrity', async () => {
      const baseline = await parseBaseline('benchmark-minimal-1.1.xml');
      expect(baseline.integrity?.algorithm).toBe('sha256');
      expect(baseline.integrity?.checksum).toMatch(/^[a-f0-9]{64}$/);
    });

    it('should set severity field', async () => {
      const baseline = await parseBaseline('benchmark-minimal-1.1.xml');
      const req = findBaselineReq(baseline, 'SV-254238');
      expect(req!.severity).toBe('medium');
      const highReq = findBaselineReq(baseline, 'SV-254240');
      expect(highReq!.severity).toBe('high');
    });
  });

  describe('XCCDF 1.2 minimal benchmark', () => {
    it('should produce identical structure to 1.1', async () => {
      const baseline = await parseBaseline('benchmark-minimal-1.2.xml');
      expect(baseline.name).toBe('ms-windows-server-2022-stig');
      expect(baseline.requirements).toHaveLength(3);
    });
  });
});

// ---------------------------------------------------------------------------
// Auto-detect (convertXccdfToHdf)
// ---------------------------------------------------------------------------

describe('convertXccdfToHdf auto-detect', async () => {
  it('should detect benchmark and return baseline', async () => {
    const { json, outputType } = await convertXccdfToHdf(loadFixture('benchmark-minimal-1.1.xml'));
    expect(outputType).toBe('baseline');
    const baseline = JSON.parse(json) as HDFBaseline;
    expect(baseline.name).toBe('ms-windows-server-2022-stig');
    expect(baseline.requirements).toHaveLength(3);
  });

  it('should detect results and return results', async () => {
    const { json, outputType } = await convertXccdfToHdf(loadFixture('stig-rhel7.xml'));
    expect(outputType).toBe('results');
    const results = JSON.parse(json) as HDFResults;
    expect(results.baselines[0]!.requirements).toHaveLength(5);
  });

  it('should detect ARF and return results', async () => {
    const { json, outputType } = await convertXccdfToHdf(loadFixture('arf-minimal.xml'));
    expect(outputType).toBe('results');
    expect(json).toBeTruthy();
  });

  it('should throw on empty input', async () => {
    await expect(convertXccdfToHdf('')).rejects.toThrow('Empty input');
  });

  it('should throw on non-XCCDF input', async () => {
    await expect(
      convertXccdfToHdf('<?xml version="1.0"?><root/>')
    ).rejects.toThrow(/not an XCCDF/i);
  });

  it('should handle benchmark-only XCCDF (no TestResult) as baseline', async () => {
    const { outputType } = await convertXccdfToHdf(loadFixture('benchmark-minimal-1.2.xml'));
    expect(outputType).toBe('baseline');
  });

  it('should handle minimal XCCDF results with no severity and sparse fields', async () => {
    const xml = `<?xml version="1.0" encoding="UTF-8"?>
<Benchmark id="test_bench" xmlns="http://checklists.nist.gov/xccdf/1.2">
  <title>Test Benchmark</title>
  <version>1.0</version>
  <TestResult id="TR1">
    <rule-result idref="nonexistent_rule">
      <result>pass</result>
    </rule-result>
    <rule-result idref="another_rule">
      <result>fail</result>
    </rule-result>
    <rule-result idref="unknown_result">
      <result>unknownstatus</result>
    </rule-result>
  </TestResult>
</Benchmark>`;
    const hdf = JSON.parse(await convertXccdfResultsToHdf(xml)) as HDFResults;
    expect(hdf.baselines[0]!.requirements).toHaveLength(3);
    // Pass status
    expect(hdf.baselines[0]!.requirements[0]!.results[0]!.status).toBe('passed');
    // Fail status
    expect(hdf.baselines[0]!.requirements[1]!.results[0]!.status).toBe('failed');
    // Unrecognized status → error
    expect(hdf.baselines[0]!.requirements[2]!.results[0]!.status).toBe('error');
    // No target when no target element
    expect(hdf.components).toHaveLength(0);
  });

  it('should handle XCCDF results with target and timing', async () => {
    const xml = `<?xml version="1.0" encoding="UTF-8"?>
<Benchmark id="timing_bench" xmlns="http://checklists.nist.gov/xccdf/1.2">
  <title>Timing Test</title>
  <version>1.0</version>
  <TestResult id="TR1" start-time="2025-01-01T00:00:00" end-time="2025-01-01T00:01:00">
    <target>myhost</target>
    <target-address>10.0.0.1</target-address>
    <rule-result idref="R1">
      <result>notapplicable</result>
    </rule-result>
  </TestResult>
</Benchmark>`;
    const hdf = JSON.parse(await convertXccdfResultsToHdf(xml)) as HDFResults;
    expect(hdf.components).toHaveLength(1);
    expect(hdf.components![0]!.name).toBe('myhost');
    expect(hdf.components![0]!.ipAddress).toBe('10.0.0.1');
    expect(hdf.statistics?.duration).toBe(60);
    expect(hdf.baselines[0]!.requirements[0]!.results[0]!.status).toBe('notApplicable');
  });

  it('should handle XCCDF with Rule definitions and CCI identifiers', async () => {
    const xml = `<?xml version="1.0" encoding="UTF-8"?>
<Benchmark id="cci_bench" xmlns="http://checklists.nist.gov/xccdf/1.2">
  <title>CCI Test</title>
  <version>1.0</version>
  <Group id="G1">
    <title>Group One</title>
    <Rule id="R1" severity="high">
      <version>SV-001</version>
      <title>Rule One</title>
      <description>&lt;VulnDiscussion&gt;This is the discussion&lt;/VulnDiscussion&gt;</description>
      <fixtext fixref="F1">Fix this issue</fixtext>
      <check system="C5386-0">
        <check-content>Check for the config</check-content>
      </check>
      <ident system="http://cyber.mil/cci">CCI-000001</ident>
    </Rule>
  </Group>
  <TestResult id="TR1">
    <rule-result idref="R1" severity="medium">
      <result>fail</result>
      <ident system="http://cyber.mil/cci">CCI-000001</ident>
    </rule-result>
  </TestResult>
</Benchmark>`;
    const hdf = JSON.parse(await convertXccdfResultsToHdf(xml)) as HDFResults;
    const req = hdf.baselines[0]!.requirements[0]!;
    // A Rule id with no SV- vulnerability number passes through unchanged.
    expect(req.id).toBe('R1');
    expect(req.title).toBe('Rule One');
    expect(req.tags?.['cci']).toContain('CCI-000001');
    expect(req.tags?.['nist']).toBeDefined();
    const descs = req.descriptions!;
    const def = descs.find(d => d.label === 'default');
    expect(def!.data).toContain('discussion');
    const fix = descs.find(d => d.label === 'fix');
    expect(fix!.data).toContain('Fix this issue');
  });

  it('should handle benchmark-to-baseline with no severity on Rule', async () => {
    const xml = `<?xml version="1.0" encoding="UTF-8"?>
<Benchmark id="nosev_bench" xmlns="http://checklists.nist.gov/xccdf/1.2">
  <title>No Sev Test</title>
  <version>1.0</version>
  <Group id="G1">
    <title>Group 1</title>
    <Rule id="R1">
      <version>SV-001</version>
      <title>Rule One</title>
      <description>Some text without VulnDiscussion</description>
      <fixtext>Fix it</fixtext>
    </Rule>
  </Group>
  <Rule id="R2">
    <version>SV-002</version>
    <title>Top Rule</title>
  </Rule>
</Benchmark>`;
    const baseline = JSON.parse(await convertXccdfBenchmarkToHdf(xml)) as HDFBaseline;
    expect(baseline.requirements).toHaveLength(2);
    const r1 = (baseline.requirements as BaselineRequirement[]).find(r => r.id === 'R1');
    expect(r1).toBeDefined();
    expect(r1!.impact).toBe(0.5); // no severity → default 0.5
    const r2 = (baseline.requirements as BaselineRequirement[]).find(r => r.id === 'R2');
    expect(r2).toBeDefined();
    // Top-level rule without Group
    expect(r2!.tags?.['gid']).toBeUndefined();
  });

  it('should handle benchmark-to-baseline with Rule having no id (skip it)', async () => {
    const xml = `<?xml version="1.0" encoding="UTF-8"?>
<Benchmark id="noid_bench" xmlns="http://checklists.nist.gov/xccdf/1.2">
  <title>No ID Test</title>
  <version>1.0</version>
  <Group id="G1">
    <title>Group</title>
    <Rule>
      <version>SV-001</version>
      <title>No ID Rule</title>
    </Rule>
    <Rule id="R2">
      <version>SV-002</version>
      <title>Has ID</title>
    </Rule>
  </Group>
</Benchmark>`;
    const baseline = JSON.parse(await convertXccdfBenchmarkToHdf(xml)) as HDFBaseline;
    // Rule without id should be skipped
    expect(baseline.requirements).toHaveLength(1);
  });

  it('should handle benchmark-to-baseline with no description (empty default)', async () => {
    const xml = `<?xml version="1.0" encoding="UTF-8"?>
<Benchmark id="nodesc_bench" xmlns="http://checklists.nist.gov/xccdf/1.2">
  <title>No Desc</title>
  <version>1.0</version>
  <Group id="G1">
    <title>Group</title>
    <Rule id="R1" severity="low">
      <version>SV-001</version>
      <title>No Desc Rule</title>
      <check system="C1">
        <check-content>Check this</check-content>
      </check>
      <fixtext fixref="F1">Fix text here</fixtext>
    </Rule>
  </Group>
</Benchmark>`;
    const baseline = JSON.parse(await convertXccdfBenchmarkToHdf(xml)) as HDFBaseline;
    const req = (baseline.requirements as BaselineRequirement[])[0]!;
    const def = req.descriptions!.find(d => d.label === 'default');
    expect(def!.data).toBe('');
    const checkD = req.descriptions!.find(d => d.label === 'check');
    expect(checkD!.data).toContain('Check this');
    const fixD = req.descriptions!.find(d => d.label === 'fix');
    expect(fixD!.data).toContain('Fix text here');
    expect(req.tags?.['severity']).toBe('low');
    expect(req.tags?.['check_id']).toBeDefined();
    expect(req.tags?.['fix_id']).toBe('F1');
    expect(req.tags?.['gid']).toBe('G1');
  });

  it('should handle XCCDF results with notchecked and error statuses', async () => {
    const xml = `<?xml version="1.0" encoding="UTF-8"?>
<Benchmark id="status_bench" xmlns="http://checklists.nist.gov/xccdf/1.2">
  <title>Status Test</title>
  <version>1.0</version>
  <TestResult id="TR1">
    <rule-result idref="R1"><result>notchecked</result></rule-result>
    <rule-result idref="R2"><result>error</result></rule-result>
    <rule-result idref="R3"><result>informational</result></rule-result>
    <rule-result idref="R4"><result>fixed</result></rule-result>
  </TestResult>
</Benchmark>`;
    const hdf = JSON.parse(await convertXccdfResultsToHdf(xml)) as HDFResults;
    expect(hdf.baselines[0]!.requirements).toHaveLength(4);
  });

  it('should fall back to the Benchmark id when it has no title', async () => {
    const xml = `<?xml version="1.0" encoding="UTF-8"?>
<Benchmark id="no_title" xmlns="http://checklists.nist.gov/xccdf/1.2">
  <version>1.0</version>
  <TestResult id="TR1">
    <rule-result idref="R1"><result>pass</result></rule-result>
  </TestResult>
</Benchmark>`;
    const hdf = JSON.parse(await convertXccdfResultsToHdf(xml)) as HDFResults;
    expect(hdf.baselines[0]!.name).toBe('no_title');
  });
});

describe('nested and multi-rule Groups', () => {
  // Real SCAP Security Guide content nests Groups and puts many Rules in one
  // Group. Treating a Group as a flat, single-rule container silently discarded
  // ~99% of the rules in an ssg-rhel8 benchmark.
  //
  // Fixture shape (verbatim from ComplianceAsCode v0.1.81, ssg-rhel8):
  //   Benchmark > Group services > Group dns (2 rules)
  //                                  ├── Group disabling_dns_server  (2 rules)
  //                                  └── Group dns_server_protection (3 rules)
  it('keeps every rule at every depth', async () => {
    const baseline = await parseBaseline('benchmark-ssg-nested-groups.xml');
    const ids = baseline.requirements.map(r => r.id);

    expect(ids).toHaveLength(7);

    // Rules directly on a Group that also has nested Groups.
    expect(ids).toContain('xccdf_org.ssgproject.content_rule_package_dnsmasq_removed');
    expect(ids).toContain('xccdf_org.ssgproject.content_rule_service_dnsmasq_disabled');
    // A nested Group with 2 rules — the second proves we keep more than the last.
    expect(ids).toContain('xccdf_org.ssgproject.content_rule_package_bind_removed');
    expect(ids).toContain('xccdf_org.ssgproject.content_rule_service_named_disabled');
    // A sibling nested Group with 3 rules.
    expect(ids).toContain('xccdf_org.ssgproject.content_rule_dns_server_authenticate_zone_transfers');
    expect(ids).toContain('xccdf_org.ssgproject.content_rule_dns_server_disable_dynamic_updates');
    expect(ids).toContain('xccdf_org.ssgproject.content_rule_dns_server_disable_zone_transfers');
  });

  it('emits one group per XCCDF Group, carrying all of its rules', async () => {
    const baseline = await parseBaseline('benchmark-ssg-nested-groups.xml');
    const byId = new Map((baseline.groups ?? []).map(g => [g.id, g.requirements]));

    expect(byId.get('xccdf_org.ssgproject.content_group_dns')).toHaveLength(2);
    expect(byId.get('xccdf_org.ssgproject.content_group_disabling_dns_server')).toHaveLength(2);
    expect(byId.get('xccdf_org.ssgproject.content_group_dns_server_protection')).toHaveLength(3);

    const total = [...byId.values()].reduce((n, reqs) => n + reqs.length, 0);
    expect(total, 'no rule dropped or duplicated across groups').toBe(7);
  });
});

describe('XCCDF severity mapping', () => {
  // XCCDF severity is unknown|info|low|medium|high; HDF severity is
  // critical|high|medium|low|informational. Casting straight across emitted
  // schema-invalid HDF for the two XCCDF values HDF lacks.
  it('omits severity="unknown" rather than downgrading it', async () => {
    const baseline = await parseBaseline('benchmark-ssg-nested-groups.xml');

    const counts: Record<string, number> = {};
    for (const req of baseline.requirements) {
      const key = req.severity ?? '<omitted>';
      counts[key] = (counts[key] ?? 0) + 1;
    }

    // The fixture holds 2 low, 3 medium, and 2 severity="unknown" rules.
    expect(counts['low']).toBe(2);
    expect(counts['medium']).toBe(3);
    expect(counts['<omitted>'], 'severity="unknown" must not be emitted').toBe(2);
    expect(counts['unknown'], 'raw XCCDF severity must never reach HDF').toBeUndefined();
  });
});

// Direct unit tests for the two code-fill helpers. The converter-level tests
// can't drive every field-presence combination (fixtures always carry a
// check-content-ref with empty inline content), so exercise each branch here.
// Mirrors the Go TestBuildCheckCode.
describe('buildCheckCode', () => {
  it('returns empty string for an undefined check', () => {
    expect(buildCheckCode(undefined)).toBe('');
  });

  it('returns empty string for an entirely empty check', () => {
    expect(buildCheckCode({} as CheckElement)).toBe('');
  });

  it('emits only system when no ref or content is present', () => {
    const parsed = JSON.parse(buildCheckCode({ system: 'sys' })) as Record<string, unknown>;
    expect(parsed).toEqual({ system: 'sys' });
  });

  it('emits checkContentRef with only name when href is absent, omitting system', () => {
    const parsed = JSON.parse(
      buildCheckCode({ 'check-content-ref': { name: 'oval:x:def:1' } })
    ) as Record<string, unknown>;
    expect(parsed).toEqual({ checkContentRef: { name: 'oval:x:def:1' } });
    expect(parsed.system).toBeUndefined();
  });

  it('emits checkContentRef with only href when name is absent', () => {
    const parsed = JSON.parse(
      buildCheckCode({ 'check-content-ref': { href: 'oval.xml' } })
    ) as Record<string, unknown>;
    expect(parsed).toEqual({ checkContentRef: { href: 'oval.xml' } });
  });

  it('emits system, checkContentRef, and trimmed checkContent when all present', () => {
    const parsed = JSON.parse(
      buildCheckCode({
        system: 'sce',
        'check-content': '  logic  ',
        'check-content-ref': { name: 'n', href: 'h' },
      })
    ) as Record<string, unknown>;
    expect(parsed).toEqual({
      system: 'sce',
      checkContentRef: { name: 'n', href: 'h' },
      checkContent: 'logic',
    });
  });

  it('produces 2-space indented JSON (byte-parity shape with Go)', () => {
    expect(buildCheckCode({ system: 'sys' })).toBe('{\n  "system": "sys"\n}');
  });
});

describe('extractCheckContentRef', () => {
  it('returns empty name/href for an undefined check', () => {
    expect(extractCheckContentRef(undefined)).toEqual({ name: '', href: '' });
  });

  it('returns empty name/href when the check has no content-ref', () => {
    expect(extractCheckContentRef({} as CheckElement)).toEqual({ name: '', href: '' });
  });

  it('reads a single-object check-content-ref', () => {
    expect(
      extractCheckContentRef({ 'check-content-ref': { name: 'n', href: 'h' } })
    ).toEqual({ name: 'n', href: 'h' });
  });

  it('takes the first entry of an array check-content-ref', () => {
    expect(
      extractCheckContentRef({
        'check-content-ref': [
          { name: 'first', href: 'a.xml' },
          { name: 'second', href: 'b.xml' },
        ],
      })
    ).toEqual({ name: 'first', href: 'a.xml' });
  });

  it('defaults missing name/href to empty strings when the ref object is bare', () => {
    expect(
      extractCheckContentRef({ 'check-content-ref': {} as CheckElement['check-content-ref'] })
    ).toEqual({ name: '', href: '' });
  });
});

// XCCDF prose elements are htmlTextWithSubType: CIS and SCAP Security Guide
// content carries its text inside XHTML children, so a parser that reads only
// an element's own text drops every word. Text on both sides of the span
// proves document order is kept.
describe('prose inside xhtml children', () => {
  it('carries text inside xhtml children', async () => {
    const baseline = await parseBaseline('CIS_Google_Chrome_Benchmark_v2.1.0-xccdf.xml');
    expect(baseline.summary?.startsWith('This document provides prescriptive guidance for establishing a secure configuration posture for Google Chrome Browser.'), baseline.summary).toBe(true);

    const req = findBaselineReq(baseline, 'xccdf_org.cisecurity.benchmarks_rule_1.1.1_L1_Ensure_Cross-origin_HTTP_Authentication_prompts_is_set_to_Disabled');
    expect(req).toBeDefined();
    const descriptions = Object.fromEntries(req!.descriptions.map((d) => [d.label, d.data]));
    expect(descriptions['default']).toBe('This setting controls whether third-party sub-content can open a HTTP Basic Auth dialog and is typically disabled. The recommended state for this setting is: Disabled (0)');
    expect(descriptions['rationale']).toBe('This setting is typically disabled to help combat phishing attempts.');
    expect(descriptions['fix']).toBe('To establish the recommended configuration via GP, set the following UI path to Disabled : Computer Configuration\\Policies\\Administrative Templates\\Google\\Google Chrome\\HTTP authentication\\Cross-origin HTTP Authentication prompts Impact: None - This is the default behavior.');
  });
});

// Edges no committed fixture carries: the five predefined entities and numeric
// references decode (an invalid code point becomes U+FFFD), a CDATA section is
// literal, a comment or PI is dropped even when it contains ">", a nested
// element keeps its place, and every prose field is wired. Synthetic XML
// input, not a committed fixture.
describe('prose pipeline edges', () => {
  it('decodes entities, keeps CDATA literal, drops comments and PIs, keeps nested-element order, wires every prose field', async () => {
    const input = '<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2" xmlns:xhtml="http://www.w3.org/1999/xhtml" id="xccdf_x_benchmark_p">' +
      '<status>draft</status><title>t</title><version>1</version>' +
      '<Group id="g"><title>g</title><Rule id="r" severity="low"><title>r</title>' +
      '<description>a &lt;b&gt; &amp; &#65; &#x42; &quot;q&quot; &apos;p&apos; &#xD800; line1\r\nline2 <xhtml:p>in <xhtml:s>s</xhtml:s> out</xhtml:p> <!-- c > d --> <?pi x > y ?> <![CDATA[c &amp; <d>]]> end</description>' +
      '<warning category="general"><xhtml:p>careful <xhtml:code>x</xhtml:code></xhtml:p></warning>' +
      '<rationale><xhtml:p>why <xhtml:em>it</xhtml:em> matters</xhtml:p></rationale>' +
      '<fixtext fixref="f"><xhtml:div>run <xhtml:code>cmd</xhtml:code></xhtml:div></fixtext>' +
      '</Rule></Group></Benchmark>';
    const baseline = JSON.parse(await convertXccdfBenchmarkToHdf(input)) as HDFBaseline;
    expect(baseline.requirements).toHaveLength(1);
    const descriptions = Object.fromEntries(baseline.requirements[0]!.descriptions.map((d) => [d.label, d.data]));
    expect(descriptions).toEqual({
      default: 'a & A B "q" \'p\' \uFFFD line1 line2 in s out c &amp; end',
      fix: 'run cmd',
      rationale: 'why it matters',
      warning: 'careful x',
    });
  });
});

// --- Benchmark-level facts under extensions.passthrough ---

function passthroughOf(baseline: HDFBaseline): Record<string, unknown> {
  expect(baseline.extensions?.passthrough, 'extensions.passthrough missing').toBeDefined();
  return baseline.extensions!.passthrough as Record<string, unknown>;
}

describe('benchmark facts in extensions.passthrough', () => {
  // DISA's release-info, located by id and split on "Benchmark Date: ".
  it('carries release-info into extensions.passthrough', async () => {
    const ext = passthroughOf(await parseBaseline('U_RHEL_9_STIG_V2R9_Manual-xccdf.xml'));
    expect(ext['releaseInfo']).toBe('Release: 9 Benchmark Date: 01 Jul 2026');
    expect(ext['benchmarkRelease']).toBe('9');
    expect(ext['benchmarkDate']).toBe('01 Jul 2026');
  });

  it('carries status, notices, publisher, platforms, profiles and generator facts', async () => {
    const disaBaseline = await parseBaseline('U_RHEL_9_STIG_V2R9_Manual-xccdf.xml');
    const disa = passthroughOf(disaBaseline);
    expect(disa['benchmarkStatus']).toBe('accepted');
    expect(disa['benchmarkStatusDate']).toBe('2026-05-20');
    expect(disa['publisher']).toBe('DISA');
    expect(disa['source']).toBe('STIG.DOD.MIL');
    expect(disa['generatorVersion']).toBe('3.5.2');
    expect(disa['conventionsVersion']).toBe('1.10.0');
    expect(disa['notices']).toEqual([{ id: 'terms-of-use', text: '' }]);
    expect(disa).not.toHaveProperty('platforms');
    const disaProfiles = disa['profiles'] as Array<Record<string, unknown>>;
    expect(disaProfiles).toHaveLength(9);
    expect(disaProfiles[0]).toEqual({
      id: 'MAC-1_Classified',
      selectedRuleIds: ['SV-257777', 'SV-257778', 'SV-257779', 'SV-257782', 'SV-257784', 'SV-257795', 'SV-257949'],
      title: 'I - Mission Critical Classified',
    });
    expect(Object.keys(disa)).toEqual([...Object.keys(disa)].sort());

    const cisBaseline = await parseBaseline('CIS_Google_Chrome_Benchmark_v2.1.0-xccdf.xml');
    const cis = passthroughOf(cisBaseline);
    expect(cis['benchmarkStatus']).toBe('draft');
    expect(cis['benchmarkStatusDate']).toBe('2021-12-09');
    expect(cis['platforms']).toEqual(['cpe:2.3:a:google:chrome:*:*:*:*:*:*:*']);
    for (const absent of ['releaseInfo', 'benchmarkRelease', 'benchmarkDate', 'publisher', 'source', 'generatorVersion', 'conventionsVersion']) {
      expect(cis).not.toHaveProperty(absent);
    }
    const cisNotices = cis['notices'] as Array<Record<string, string>>;
    expect(cisNotices).toHaveLength(1);
    expect(cisNotices[0]!['id']).toBe('terms-of-use');
    expect(cisNotices[0]!['text']!.startsWith('BACKGROUND. The Center for Internet Security'), cisNotices[0]!['text']).toBe(true);
    const cisProfiles = cis['profiles'] as Array<Record<string, unknown>>;
    expect(cisProfiles).toHaveLength(2);
    expect(cisProfiles[0]!['id']).toBe('xccdf_org.cisecurity.benchmarks_profile_Level_1_L1_-_CorporateEnterprise_Environment_general_use');
    expect(cisProfiles[0]!['title']).toBe('Level 1 (L1) - Corporate/Enterprise Environment (general use)');
    const level1 = cisProfiles[0]!['selectedRuleIds'] as string[];
    expect(level1).toHaveLength(15);
    expect(level1[0]).toBe('xccdf_org.cisecurity.benchmarks_rule_1.1.1_L1_Ensure_Cross-origin_HTTP_Authentication_prompts_is_set_to_Disabled');
    expect(cisProfiles[1]!['selectedRuleIds']).toHaveLength(23);

    expectValidBaseline(disaBaseline);
    expectValidBaseline(cisBaseline);
  });

  it('parses release-info', () => {
    const cases: Array<[string, string, string, boolean]> = [
      ['Release: 9 Benchmark Date: 01 Jul 2026', '9', '01 Jul 2026', true],
      ['Release: 3.5 Benchmark Date: 24 Jan 2020', '3.5', '24 Jan 2020', true],
      ['Release: 12 Benchmark Date: 23 Oct 2020 ', '12', '23 Oct 2020', true],
      ['Version 2 build 7', '', '', false],
      ['Benchmark Date: 01 Jul 2026', '', '', false],
      ['Release: 9 Benchmark Date: ', '', '', false],
      ['', '', '', false],
    ];
    for (const [input, release, date, ok] of cases) {
      expect(parseReleaseInfo(input), input).toEqual({ release, date, ok });
    }
  });

  // release-info is found by its id wherever it sits among the plain-text
  // elements, and unparseable text keeps releaseInfo verbatim with no parsed
  // keys and no error. Synthetic XML input, not a committed fixture.
  it('finds release-info by id and keeps unparseable text verbatim', async () => {
    const head = '<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.1" id="x_benchmark"><status date="2026-01-02">accepted</status><title>t</title><description>d</description>';
    const tail = '<version>1</version><Group id="V-1"><title>g</title><Rule id="SV-1r1_rule" severity="low"><version>X-1</version><title>r</title><description>d</description></Rule></Group></Benchmark>';
    const convert = async (xml: string): Promise<Record<string, unknown>> =>
      passthroughOf(JSON.parse(await convertXccdfBenchmarkToHdf(xml)) as HDFBaseline);

    const byId = await convert(head +
      '<plain-text id="other">Release: 1 Benchmark Date: 01 Jan 2000</plain-text><plain-text id="generator">3.5.2</plain-text><plain-text id="conventionsVersion">1.10.0</plain-text><plain-text id="release-info">Release: 4 Benchmark Date: 02 Feb 2026</plain-text>' + tail);
    expect(byId['releaseInfo']).toBe('Release: 4 Benchmark Date: 02 Feb 2026');
    expect(byId['benchmarkRelease']).toBe('4');
    expect(byId['benchmarkDate']).toBe('02 Feb 2026');
    expect(byId['generatorVersion']).toBe('3.5.2');
    expect(byId['conventionsVersion']).toBe('1.10.0');

    const unparseable = await convert(head + '<plain-text id="release-info">Version 2 build 7</plain-text>' + tail);
    expect(unparseable['releaseInfo']).toBe('Version 2 build 7');
    expect(unparseable).not.toHaveProperty('benchmarkRelease');
    expect(unparseable).not.toHaveProperty('benchmarkDate');

    const none = await convert(head + tail);
    for (const absent of ['releaseInfo', 'benchmarkRelease', 'benchmarkDate', 'generatorVersion', 'conventionsVersion', 'notices', 'platforms', 'profiles', 'publisher', 'source']) {
      expect(none).not.toHaveProperty(absent);
    }
    expect(none['benchmarkStatus']).toBe('accepted');
  });
});

// A Profile select names a Rule or a Group. A selected Group contributes every
// rule it holds at any depth unless that rule or an inner group opts out
// (XCCDF: selecting a Group selects its items), so selectedRuleIds always
// holds requirement ids a consumer can join on. Duplicates collapse; an idref
// naming nothing is kept as given. Synthetic XML input, not a committed fixture.
describe('profile selects', () => {
  it('resolve to requirement ids', async () => {
    const input = '<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.1" id="x_benchmark"><status>accepted</status><title>t</title><description>d</description><version>1</version>' +
      '<Profile id="p"><title>P</title><select idref="g1" selected="true"/><select idref="SV-3r1_rule" selected="true"/><select idref="nothing" selected="true"/><select idref="SV-5r1_rule" selected="false"/></Profile>' +
      '<Group id="g1"><title>g1</title><Rule id="SV-1r1_rule" severity="low"><version>X-1</version><title>r1</title><description>d</description></Rule>' +
      '<Group id="g2"><title>g2</title><Rule id="SV-2r1_rule" severity="low" selected="false"><version>X-2</version><title>r2</title><description>d</description></Rule><Rule id="SV-3r1_rule" severity="low"><version>X-3</version><title>r3</title><description>d</description></Rule></Group>' +
      '<Group id="g3" selected="false"><title>g3</title><Rule id="SV-4r1_rule" severity="low"><version>X-4</version><title>r4</title><description>d</description></Rule></Group></Group>' +
      '<Group id="g4"><title>g4</title><Rule id="SV-5r1_rule" severity="low"><version>X-5</version><title>r5</title><description>d</description></Rule></Group></Benchmark>';
    const baseline = JSON.parse(await convertXccdfBenchmarkToHdf(input)) as HDFBaseline;
    const profiles = passthroughOf(baseline)['profiles'] as Array<Record<string, unknown>>;
    expect(profiles).toHaveLength(1);
    expect(profiles[0]!['selectedRuleIds']).toEqual(['SV-1', 'SV-3', 'nothing']);
  });
});

// Edges no fixture carries, resolved alike in both languages: several status
// elements (latest dated wins; undated, the last), attributed Dublin Core
// children, first non-empty publisher and source, a Profile with several titles
// (the first), selected="0", a dangling revisioned idref, a notice with markup.
// Synthetic XML input, not a committed fixture.
describe('benchmark passthrough edges', () => {
  const rule = '<Group id="g"><title>g</title><Rule id="SV-1r1_rule" severity="low"><version>X-1</version><title>r1</title><description>d</description></Rule><Rule id="SV-2r1_rule" severity="low"><version>X-2</version><title>r2</title><description>d</description></Rule></Group></Benchmark>';

  it('resolve identically to Go', async () => {
    const input = '<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.1" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:xhtml="http://www.w3.org/1999/xhtml" id="x_benchmark">' +
      '<status date="2021-02-02">accepted</status><status date="2020-01-01">draft</status><status>incomplete</status>' +
      '<title>t</title><description>d</description>' +
      '<notice id="n"><xhtml:p>a <xhtml:b>b</xhtml:b></xhtml:p></notice>' +
      '<reference href="https://example.invalid"><dc:publisher></dc:publisher><dc:source>S1</dc:source></reference>' +
      '<reference><dc:publisher xml:lang="en">P2</dc:publisher><dc:publisher>P2b</dc:publisher><dc:source>S2</dc:source></reference>' +
      '<reference><dc:publisher>P3</dc:publisher></reference>' +
      '<version>1</version>' +
      '<Profile id="p"><title xml:lang="en">First</title><title xml:lang="de">Zweite</title><select idref="SV-1r1_rule" selected="true"/><select idref="SV-2r1_rule" selected=" 0 "/><select idref="SV-9r2_rule" selected="true"/></Profile>' + rule;
    const ext = passthroughOf(JSON.parse(await convertXccdfBenchmarkToHdf(input)) as HDFBaseline);
    expect(ext).toEqual({
      benchmarkStatus: 'accepted',
      benchmarkStatusDate: '2021-02-02',
      notices: [{ id: 'n', text: 'a b' }],
      profiles: [{ id: 'p', selectedRuleIds: ['SV-1', 'SV-9'], title: 'First' }],
      publisher: 'P2',
      source: 'S1',
    });
    // Key order matches Go's sorted map serialisation at every level.
    expect(Object.keys(ext)).toEqual(['benchmarkStatus', 'benchmarkStatusDate', 'notices', 'profiles', 'publisher', 'source']);
    expect(Object.keys((ext['notices'] as object[])[0]!)).toEqual(['id', 'text']);
    expect(Object.keys((ext['profiles'] as object[])[0]!)).toEqual(['id', 'selectedRuleIds', 'title']);

    const undated = passthroughOf(JSON.parse(await convertXccdfBenchmarkToHdf(
      '<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.1" id="x_benchmark"><status>draft</status><status>accepted</status><title>t</title><description>d</description><version>1</version>' + rule
    )) as HDFBaseline);
    expect(undated).toEqual({ benchmarkStatus: 'accepted' });
  });
});
