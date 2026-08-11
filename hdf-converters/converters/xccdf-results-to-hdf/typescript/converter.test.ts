import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { describe, it, expect } from 'vitest';
import { convertXccdfResultsToHdf, convertXccdfBenchmarkToHdf, convertXccdfToHdf, buildCheckCode, extractCheckContentRef } from './converter.js';
import type { CheckElement } from './converter.js';
import { runConverterContractTests } from '../../../shared/typescript/converter-contract.js';
import { assertRequirementCount, countXmlElements } from '../../../shared/typescript/anchor.js';
import { expectValidResults } from '../../../test/helpers/expectValidHdf.js';
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
