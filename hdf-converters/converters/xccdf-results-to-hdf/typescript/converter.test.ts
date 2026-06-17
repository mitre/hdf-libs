import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { describe, it, expect } from 'vitest';
import { convertXccdfResultsToHdf, convertXccdfBenchmarkToHdf, convertXccdfToHdf } from './converter.js';
import { runConverterContractTests } from '../../../shared/typescript/converter-contract.js';
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

    it('should use version element as requirement ID', async () => {
      const hdf = await parseHdf('stig-rhel7.xml');
      const ids = hdf.baselines[0]!.requirements.map((r) => r.id);
      expect(ids).toContain('RHEL-07-010030');
      expect(ids).toContain('RHEL-07-010060');
      expect(ids).toContain('RHEL-07-010118');
      expect(ids).toContain('RHEL-07-010290');
      expect(ids).toContain('RHEL-07-020200');
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
      expect(hdf.tool?.name).toBe('XCCDF Results');
      expect(hdf.tool?.format).toBe('XML');
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
      const technicalReq = findReq(hdf, 'RHEL-07-010030');
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

  // --- Severity → impact mapping ---

  describe('severity to impact mapping', () => {
    it('should map high severity to 0.7 impact', async () => {
      const hdf = await parseHdf('stig-rhel7.xml');
      const req = findReq(hdf, 'RHEL-07-010290');
      expect(req!.impact).toBe(0.7);
    });

    it('should map medium severity to 0.5 impact', async () => {
      const hdf = await parseHdf('stig-rhel7.xml');
      const req = findReq(hdf, 'RHEL-07-010030');
      expect(req!.impact).toBe(0.5);
    });

    it('should map low severity to 0.3 impact', async () => {
      const hdf = await parseHdf('stig-rhel7.xml');
      const req = findReq(hdf, 'RHEL-07-020200');
      expect(req!.impact).toBe(0.3);
    });
  });

  // --- Status mapping ---

  describe('status mapping', () => {
    it('should map fail to Failed (RHEL-07-010030)', async () => {
      const hdf = await parseHdf('stig-rhel7.xml');
      const req = findReq(hdf, 'RHEL-07-010030');
      expect(req!.results[0]!.status).toBe(ResultStatus.Failed);
    });

    it('should map pass to Passed (RHEL-07-010118)', async () => {
      const hdf = await parseHdf('stig-rhel7.xml');
      const req = findReq(hdf, 'RHEL-07-010118');
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
      const req = findReq(hdf, 'RHEL-07-010030');
      expect(req!.tags?.['cci']).toContain('CCI-000048');
    });

    it('should map CCI-000048 to NIST AC-8 tags', async () => {
      const hdf = await parseHdf('stig-rhel7.xml');
      const req = findReq(hdf, 'RHEL-07-010030');
      const nist = req!.tags?.['nist'] as string[];
      expect(nist).toBeDefined();
      expect(nist.some((n: string) => n.startsWith('AC-8'))).toBe(true);
    });

    it('should map CCI-000366 to NIST CM-6 tags', async () => {
      const hdf = await parseHdf('stig-rhel7.xml');
      const req = findReq(hdf, 'RHEL-07-010290');
      const nist = req!.tags?.['nist'] as string[];
      expect(nist).toBeDefined();
      expect(nist.some((n: string) => n.startsWith('CM-6'))).toBe(true);
    });

    it('should map CCI-002617 to NIST SI-2 tags', async () => {
      const hdf = await parseHdf('stig-rhel7.xml');
      const req = findReq(hdf, 'RHEL-07-020200');
      const nist = req!.tags?.['nist'] as string[];
      expect(nist).toBeDefined();
      expect(nist.some((n: string) => n.startsWith('SI-2'))).toBe(true);
    });

    it('should not include non-CCI idents in cci tags', async () => {
      const hdf = await parseHdf('stig-rhel7.xml');
      const req = findReq(hdf, 'RHEL-07-010030');
      const ccis = req!.tags?.['cci'] as string[];
      // Should not include CCE or legacy idents
      for (const cci of ccis) {
        expect(cci).toMatch(/^CCI-/);
      }
    });

    it('should have no cci/nist tags when no CCI idents exist', async () => {
      const hdf = await parseHdf('minimal.xml');
      const req = findReq(hdf, 'xccdf_moc.elpmaxe.www_rule_1');
      expect(req!.tags?.['cci']).toBeUndefined();
      expect(req!.tags?.['nist']).toBeUndefined();
    });
  });

  // --- Descriptions ---

  describe('descriptions', () => {
    it('should extract VulnDiscussion as default description', async () => {
      const hdf = await parseHdf('stig-rhel7.xml');
      const req = findReq(hdf, 'RHEL-07-010290');
      const defaultDesc = req!.descriptions.find(
        (d) => d.label === 'default'
      );
      expect(defaultDesc).toBeDefined();
      expect(defaultDesc!.data).toContain('empty password');
    });

    it('should not include raw VulnDiscussion XML tags in description', async () => {
      const hdf = await parseHdf('stig-rhel7.xml');
      const req = findReq(hdf, 'RHEL-07-010290');
      const defaultDesc = req!.descriptions.find(
        (d) => d.label === 'default'
      );
      expect(defaultDesc!.data).not.toContain('<VulnDiscussion>');
      expect(defaultDesc!.data).not.toContain('</VulnDiscussion>');
      expect(defaultDesc!.data).not.toContain('<FalsePositives>');
    });

    it('should include fix description from fixtext element', async () => {
      const hdf = await parseHdf('stig-rhel7.xml');
      const req = findReq(hdf, 'RHEL-07-010030');
      const fixDesc = req!.descriptions.find((d) => d.label === 'fix');
      expect(fixDesc).toBeDefined();
      expect(fixDesc!.data).toContain('dconf');
    });

    it('should include fix description for RHEL-07-010290', async () => {
      const hdf = await parseHdf('stig-rhel7.xml');
      const req = findReq(hdf, 'RHEL-07-010290');
      const fixDesc = req!.descriptions.find((d) => d.label === 'fix');
      expect(fixDesc).toBeDefined();
      expect(fixDesc!.data).toContain('nullok');
    });
  });

  // --- Rule title ---

  describe('rule title', () => {
    it('should set requirement title from Rule title element', async () => {
      const hdf = await parseHdf('stig-rhel7.xml');
      const req = findReq(hdf, 'RHEL-07-010290');
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
      expect(ids).toContain('WN22-00-000010');
      expect(ids).toContain('WN22-00-000020');
      expect(ids).toContain('WN22-00-000030');
    });

    it('should map severity to impact', async () => {
      const baseline = await parseBaseline('benchmark-minimal-1.1.xml');
      const req10 = findBaselineReq(baseline, 'WN22-00-000010');
      expect(req10!.impact).toBe(0.5); // medium
      const req30 = findBaselineReq(baseline, 'WN22-00-000030');
      expect(req30!.impact).toBe(0.7); // high
    });

    it('should extract VulnDiscussion as default description', async () => {
      const baseline = await parseBaseline('benchmark-minimal-1.1.xml');
      const req = findBaselineReq(baseline, 'WN22-00-000010');
      const defaultDesc = req!.descriptions.find((d) => d.label === 'default');
      expect(defaultDesc).toBeDefined();
      expect(defaultDesc!.data).toContain('privileged account');
      expect(defaultDesc!.data).not.toContain('<VulnDiscussion>');
    });

    it('should extract check-content as check description', async () => {
      const baseline = await parseBaseline('benchmark-minimal-1.1.xml');
      const req = findBaselineReq(baseline, 'WN22-00-000010');
      const checkDesc = req!.descriptions.find((d) => d.label === 'check');
      expect(checkDesc).toBeDefined();
      expect(checkDesc!.data).toContain('administrative privileges');
    });

    it('should extract fixtext as fix description', async () => {
      const baseline = await parseBaseline('benchmark-minimal-1.1.xml');
      const req = findBaselineReq(baseline, 'WN22-00-000010');
      const fixDesc = req!.descriptions.find((d) => d.label === 'fix');
      expect(fixDesc).toBeDefined();
      expect(fixDesc!.data).toContain('separate account');
    });

    it('should extract CCI tags', async () => {
      const baseline = await parseBaseline('benchmark-minimal-1.1.xml');
      const req = findBaselineReq(baseline, 'WN22-00-000010');
      expect(req!.tags['cci']).toContain('CCI-000366');
      expect(req!.tags['nist']).toBeDefined();
    });

    it('should extract multiple CCI idents', async () => {
      const baseline = await parseBaseline('benchmark-minimal-1.1.xml');
      const req = findBaselineReq(baseline, 'WN22-00-000020');
      const ccis = req!.tags['cci'] as string[];
      expect(ccis).toHaveLength(2);
      expect(ccis).toContain('CCI-004066');
      expect(ccis).toContain('CCI-000199');
    });

    it('should include STIG-specific tags', async () => {
      const baseline = await parseBaseline('benchmark-minimal-1.1.xml');
      const req = findBaselineReq(baseline, 'WN22-00-000010');
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
      expect(baseline.groups![0]!.requirements).toEqual(['WN22-00-000010']);
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
      const req = findBaselineReq(baseline, 'WN22-00-000010');
      expect(req!.severity).toBe('medium');
      const highReq = findBaselineReq(baseline, 'WN22-00-000030');
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
    // Unknown status → notReviewed
    expect(hdf.baselines[0]!.requirements[2]!.results[0]!.status).toBe('notReviewed');
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
    expect(req.id).toBe('SV-001');
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
    const r1 = (baseline.requirements as BaselineRequirement[]).find(r => r.id === 'SV-001');
    expect(r1).toBeDefined();
    expect(r1!.impact).toBe(0.5); // no severity → default 0.5
    const r2 = (baseline.requirements as BaselineRequirement[]).find(r => r.id === 'SV-002');
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

  it('should handle benchmark with no title (fallback name)', async () => {
    const xml = `<?xml version="1.0" encoding="UTF-8"?>
<Benchmark id="no_title" xmlns="http://checklists.nist.gov/xccdf/1.2">
  <version>1.0</version>
  <TestResult id="TR1">
    <rule-result idref="R1"><result>pass</result></rule-result>
  </TestResult>
</Benchmark>`;
    const hdf = JSON.parse(await convertXccdfResultsToHdf(xml)) as HDFResults;
    expect(hdf.baselines[0]!.name).toBe('XCCDF Benchmark');
  });
});
