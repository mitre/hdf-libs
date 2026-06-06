import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, it, expect } from 'vitest';
import { convertNessusToHdf } from './index.js';

const FIXTURES_DIR = join(__dirname, '..', 'fixtures');

// Helper to find a requirement across all baselines
function findReqAcrossBaselines(result: Awaited<ReturnType<typeof convertNessusToHdf>>, id: string) {
  for (const baseline of result.baselines) {
    const req = baseline.requirements.find(r => r.id === id);
    if (req) return req;
  }
  return undefined;
}

describe('Nessus to HDF Converter', async () => {
  describe('convertNessusToHdf', async () => {
    it('should convert real Nessus scan to HDF format', async () => {
      const nessusXml = readFileSync(
        join(FIXTURES_DIR, 'input', 'sample.nessus'),
        'utf-8'
      );

      const result = await convertNessusToHdf(nessusXml);

      // Should return valid HDF Results
      expect(result).toBeDefined();
      expect(result.baselines).toBeDefined();
      expect(result.statistics).toBeDefined();
      expect(result.components).toBeDefined();
      expect(result.tool?.name).toBe('Nessus');
      expect(result.tool?.version).toBeUndefined();
      expect(result.tool?.format).toBeUndefined();
    });

    it('should create one baseline per report with correct metadata', async () => {
      const nessusXml = readFileSync(
        join(FIXTURES_DIR, 'input', 'sample.nessus'),
        'utf-8'
      );

      const result = await convertNessusToHdf(nessusXml);

      expect(result.baselines).toHaveLength(3); // one per scanned host
      const baseline = result.baselines[0];

      expect(baseline.name).toBe('Nessus Basic Network Scan');
      expect(baseline.title).toBe('Nessus Basic Network Scan');
      expect(baseline.status).toBe('loaded');
    });

    it('should convert ReportItems to requirements', async () => {
      const nessusXml = readFileSync(
        join(FIXTURES_DIR, 'input', 'sample.nessus'),
        'utf-8'
      );

      const result = await convertNessusToHdf(nessusXml);

      // Real scan has many requirements across 3 baselines (one per host)
      const totalReqs = result.baselines.reduce((sum, b) => sum + b.requirements.length, 0);
      expect(totalReqs).toBeGreaterThan(10);
    });

    it('should map Nessus fields to HDF requirement fields correctly', async () => {
      const nessusXml = readFileSync(
        join(FIXTURES_DIR, 'input', 'sample.nessus'),
        'utf-8'
      );

      const result = await convertNessusToHdf(nessusXml);
      // Find SSL Certificate Cannot Be Trusted (plugin 51192, severity 2)
      const req = findReqAcrossBaselines(result, '51192');
      expect(req).toBeDefined();

      // Check title mapping (pluginName)
      expect(req!.title).toBe('SSL Certificate Cannot Be Trusted');

      // Check descriptions array has default description
      expect(req!.descriptions).toBeDefined();
      expect(req!.descriptions.length).toBeGreaterThan(0);
      const defaultDesc = req!.descriptions.find(d => d.label === 'default');
      expect(defaultDesc).toBeDefined();
      expect(defaultDesc?.data).toContain('Plugin Family: General');
      expect(defaultDesc?.data).toContain('Port: 8834');
      expect(defaultDesc?.data).toContain('Protocol: tcp');

      // Check fix description
      const fixDesc = req!.descriptions.find(d => d.label === 'fix');
      expect(fixDesc).toBeDefined();
      expect(fixDesc?.data).toContain('proper SSL certificate');
    });

    it('should map Nessus severity to HDF impact', async () => {
      const nessusXml = readFileSync(
        join(FIXTURES_DIR, 'input', 'sample.nessus'),
        'utf-8'
      );

      const result = await convertNessusToHdf(nessusXml);

      // Severity 2 (Medium) should map to 0.5
      const req2 = findReqAcrossBaselines(result, '51192');
      expect(req2?.impact).toBe(0.5);

      // Severity 3 (High) should map to 0.7
      const req3 = findReqAcrossBaselines(result, '154345');
      expect(req3?.impact).toBe(0.7);
    });

    it('should map Nessus plugin family to NIST tags using hdf-mappings', async () => {
      const nessusXml = readFileSync(
        join(FIXTURES_DIR, 'input', 'sample.nessus'),
        'utf-8'
      );

      const result = await convertNessusToHdf(nessusXml);
      const req = findReqAcrossBaselines(result, '51192');

      // Should have tags object with nist array
      expect(req?.tags).toBeDefined();
      expect(req?.tags.nist).toBeDefined();
      expect(Array.isArray(req?.tags.nist)).toBe(true);
    });

    it('should include additional Nessus tags in requirement tags', async () => {
      const nessusXml = readFileSync(
        join(FIXTURES_DIR, 'input', 'sample.nessus'),
        'utf-8'
      );

      const result = await convertNessusToHdf(nessusXml);
      // Use plugin 51192 (SSL Certificate Cannot Be Trusted)
      const req = findReqAcrossBaselines(result, '51192');

      expect(req?.tags.rid).toBe('51192');
      expect(req?.tags.risk_factor).toBe('Medium');
      expect(req?.tags.plugin_type).toBe('remote');
      expect(req?.tags.plugin_publication_date).toBe('2010/12/15');
      expect(req?.tags.fname).toBe('ssl_signed_certificate.nasl');
      expect(req?.tags.cvss_base_score).toBe('6.4');
    });

    it('should split whitespace-separated see_also URLs into one ref per URL', async () => {
      const nessusXml = readFileSync(
        join(FIXTURES_DIR, 'input', 'sample.nessus'),
        'utf-8'
      );

      const result = await convertNessusToHdf(nessusXml);
      // Plugin 51192's see_also is "https://www.itu.int/rec/T-REC-X.509/en\nhttps://en.wikipedia.org/wiki/X.509"
      const req = findReqAcrossBaselines(result, '51192');

      expect(req?.refs).toBeDefined();
      expect(req?.refs?.length).toBe(2);
      const urls = req?.refs?.map(r => r.url) ?? [];
      expect(urls).toContain('https://www.itu.int/rec/T-REC-X.509/en');
      expect(urls).toContain('https://en.wikipedia.org/wiki/X.509');
      // Every emitted URL must be a single standalone URI (no embedded whitespace).
      urls.forEach(u => expect(u).toMatch(/^\S+$/));
    });

    it('should create requirement results with proper status mapping', async () => {
      const nessusXml = readFileSync(
        join(FIXTURES_DIR, 'input', 'sample.nessus'),
        'utf-8'
      );

      const result = await convertNessusToHdf(nessusXml);
      // Use plugin 51192 (medium severity, non-compliance)
      const req = findReqAcrossBaselines(result, '51192');

      // Should have at least one result
      expect(req?.results).toBeDefined();
      expect(req!.results.length).toBeGreaterThan(0);

      const testResult = req!.results[0];

      // No compliance-result field means failed status
      expect(testResult.status).toBe('failed');

      // Should have code_desc
      expect(testResult.codeDesc).toBeDefined();
      expect(typeof testResult.codeDesc).toBe('string');

      // Should have message from plugin_output
      expect(testResult.message).toBeDefined();
      expect(testResult.message).toContain('certificate');

      // Should have start_time from HostProperties HOST_START tag
      expect(testResult.startTime).toBeDefined();
    });

    it('should include code as JSON stringified ReportItem', async () => {
      const nessusXml = readFileSync(
        join(FIXTURES_DIR, 'input', 'sample.nessus'),
        'utf-8'
      );

      const result = await convertNessusToHdf(nessusXml);
      const req = findReqAcrossBaselines(result, '51192');

      expect(req?.code).toBeDefined();
      expect(typeof req?.code).toBe('string');

      // Should be valid JSON
      const parsedCode = JSON.parse(req!.code!);
      expect(parsedCode.pluginID).toBe('51192');
      expect(parsedCode.pluginName).toBe('SSL Certificate Cannot Be Trusted');
    });

    it('should create targets from ReportHosts', async () => {
      const nessusXml = readFileSync(
        join(FIXTURES_DIR, 'input', 'sample.nessus'),
        'utf-8'
      );

      const result = await convertNessusToHdf(nessusXml);

      expect(result.components).toBeDefined();
      expect(result.components?.length).toBe(3);

      // Find the first host (10.0.0.3)
      const target = result.components!.find(t => t.name === '10.0.0.3');
      expect(target).toBeDefined();
      expect(target?.osName).toContain('Ubuntu');
      expect(target?.ipAddress).toBe('10.0.0.3');
    });

    it('should set generator metadata', async () => {
      const nessusXml = readFileSync(
        join(FIXTURES_DIR, 'input', 'sample.nessus'),
        'utf-8'
      );

      const result = await convertNessusToHdf(nessusXml);

      expect(result.generator).toBeDefined();
      expect(result.generator?.name).toBe('hdf-converters');
      expect(result.generator?.version).toBeDefined();
    });

    it('should calculate statistics', async () => {
      const nessusXml = readFileSync(
        join(FIXTURES_DIR, 'input', 'sample.nessus'),
        'utf-8'
      );

      const result = await convertNessusToHdf(nessusXml);

      expect(result.statistics).toBeDefined();
      expect(result.statistics.duration).toBeGreaterThan(0);
    });

    it('should filter out empty refs', async () => {
      const nessusXml = readFileSync(
        join(FIXTURES_DIR, 'input', 'sample.nessus'),
        'utf-8'
      );

      const result = await convertNessusToHdf(nessusXml);

      // All refs should have url defined across all baselines
      for (const baseline of result.baselines) {
        baseline.requirements.forEach(req => {
          req.refs?.forEach(ref => {
            expect(ref.url).toBeDefined();
            expect(ref.url).not.toBe('');
          });
        });
      }
    });

    it('should synthesize a passed placeholder for a host with zero ReportItems', async () => {
      const nessusXml = readFileSync(
        join(FIXTURES_DIR, 'input', 'empty-host.nessus'),
        'utf-8'
      );

      const result = await convertNessusToHdf(nessusXml);

      expect(result.baselines).toHaveLength(1);
      const baseline = result.baselines[0];
      expect(baseline.requirements).toHaveLength(1);

      const req = baseline.requirements[0];
      expect(req.id).toBe('nessus-no-findings');
      expect(req.results[0].status).toBe('passed');
      expect(req.results[0].codeDesc).toContain('Nessus');
      expect(req.results[0].codeDesc).toContain('scanned');
      expect(req.results[0].codeDesc).toContain('cleanhost.example.com');
      expect(req.results[0].codeDesc).toContain('findings');
    });

    it('should populate epss and cwe from an EPSS-enriched ReportItem', async () => {
      // The static sample.nessus predates Nessus' EPSS output, so buildEpss is
      // never exercised by it. This inline NessusClientData_v2 carries the real
      // <epss_score>/<epss_percentile>/<cwe> element shape Nessus emits.
      const enriched = `<?xml version="1.0" ?>
<NessusClientData_v2>
  <Policy>
    <policyName>Enriched Scan</policyName>
  </Policy>
  <Report name="Enriched Scan">
    <ReportHost name="host-epss">
      <HostProperties>
        <tag name="HOST_START">Tue Mar 22 14:54:47 2022</tag>
        <tag name="host-ip">10.0.0.5</tag>
      </HostProperties>
      <ReportItem port="0" svc_name="general" protocol="tcp" severity="4" pluginID="999001" pluginName="Log4Shell" pluginFamily="Misc.">
        <cve>CVE-2021-44228</cve>
        <cvss_score_source>CVE-2021-44228</cvss_score_source>
        <cvss3_base_score>10.0</cvss3_base_score>
        <cvss3_vector>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H</cvss3_vector>
        <cwe>CWE-502</cwe>
        <cwe>917</cwe>
        <epss_score>0.97431</epss_score>
        <epss_percentile>0.99962</epss_percentile>
        <description>Remote code execution via JNDI lookup.</description>
        <solution>Upgrade to a fixed release.</solution>
      </ReportItem>
    </ReportHost>
  </Report>
</NessusClientData_v2>`;

      const result = await convertNessusToHdf(enriched);
      const req = findReqAcrossBaselines(result, '999001');
      expect(req).toBeDefined();

      // epss — score, percentile, and date derived from HOST_START.
      expect(req?.epss?.score).toBeCloseTo(0.97431, 5);
      expect(req?.epss?.percentile).toBeCloseTo(0.99962, 5);
      expect(req?.epss?.date).toBe('2022-03-22');
      // cwe — CWE-prefixed and bare-numeric forms both normalize to CWE-N.
      expect(req?.cwe).toContain('CWE-502');
      expect(req?.cwe).toContain('CWE-917');
      // cvss
      expect(req?.cvss?.[0].baseScore).toBe(10.0);
    });
  });

  describe('Compliance Scan Conversion', async () => {
    it('should convert compliance scan to HDF format', async () => {
      const nessusXml = readFileSync(
        join(FIXTURES_DIR, 'input', 'compliance.nessus'),
        'utf-8'
      );

      const result = await convertNessusToHdf(nessusXml);

      expect(result).toBeDefined();
      expect(result.baselines).toBeDefined();
      expect(result.baselines).toHaveLength(1);
    });

    it('should extract ID from compliance-reference Vuln-ID field', async () => {
      const nessusXml = readFileSync(
        join(FIXTURES_DIR, 'input', 'compliance.nessus'),
        'utf-8'
      );

      const result = await convertNessusToHdf(nessusXml);
      const req = result.baselines[0].requirements[0];

      // Should extract Vuln-ID from compliance-reference
      expect(req.id).toBe('V-71849');
    });

    it('should use compliance-check-name for title', async () => {
      const nessusXml = readFileSync(
        join(FIXTURES_DIR, 'input', 'compliance.nessus'),
        'utf-8'
      );

      const result = await convertNessusToHdf(nessusXml);
      const req = result.baselines[0].requirements[0];

      expect(req.title).toContain('RHEL-07-010010');
      expect(req.title).toContain('Standard Mandatory DoD Notice');
    });

    it('should use compliance-info for default description', async () => {
      const nessusXml = readFileSync(
        join(FIXTURES_DIR, 'input', 'compliance.nessus'),
        'utf-8'
      );

      const result = await convertNessusToHdf(nessusXml);
      const req = result.baselines[0].requirements[0];

      const defaultDesc = req.descriptions.find(d => d.label === 'default');
      expect(defaultDesc?.data).toContain('standardized and approved use notification');
    });

    it('should use compliance-solution for fix description', async () => {
      const nessusXml = readFileSync(
        join(FIXTURES_DIR, 'input', 'compliance.nessus'),
        'utf-8'
      );

      const result = await convertNessusToHdf(nessusXml);
      const req = result.baselines[0].requirements[0];

      const fixDesc = req.descriptions.find(d => d.label === 'fix');
      expect(fixDesc?.data).toContain('Configure the operating system');
      expect(fixDesc?.data).toContain('dconf');
    });

    it('should map CAT levels to impact scores', async () => {
      const nessusXml = readFileSync(
        join(FIXTURES_DIR, 'input', 'compliance.nessus'),
        'utf-8'
      );

      const result = await convertNessusToHdf(nessusXml);

      // CAT I (High) = 0.7
      const catI = result.baselines[0].requirements.find(r => r.id === 'V-71971');
      expect(catI?.impact).toBe(0.7);

      // CAT II (Medium) = 0.5
      const catII = result.baselines[0].requirements.find(r => r.id === 'V-71849');
      expect(catII?.impact).toBe(0.5);

      // CAT III (Low) = 0.3
      const catIII = result.baselines[0].requirements.find(r => r.id === 'V-72083');
      expect(catIII?.impact).toBe(0.3);
    });

    it('should extract CCI from compliance-reference', async () => {
      const nessusXml = readFileSync(
        join(FIXTURES_DIR, 'input', 'compliance.nessus'),
        'utf-8'
      );

      const result = await convertNessusToHdf(nessusXml);
      const req = result.baselines[0].requirements[0];

      expect(req.tags.cci).toBeDefined();
      expect(req.tags.cci).toContain('CCI-000366');
    });

    it('should map CCI to NIST controls using hdf-mappings', async () => {
      const nessusXml = readFileSync(
        join(FIXTURES_DIR, 'input', 'compliance.nessus'),
        'utf-8'
      );

      const result = await convertNessusToHdf(nessusXml);
      const req = result.baselines[0].requirements[0];

      // CCI-000366 should map to NIST controls
      expect(req.tags.nist).toBeDefined();
      expect(Array.isArray(req.tags.nist)).toBe(true);
      expect(req.tags.nist.length).toBeGreaterThan(0);
      // CCI-000366 maps to CM-6 controls
      expect(req.tags.nist).toContain('CM-6 b');
    });

    it('should deduplicate NIST controls when mapping from CCI', async () => {
      const nessusXml = readFileSync(
        join(FIXTURES_DIR, 'input', 'compliance.nessus'),
        'utf-8'
      );

      const result = await convertNessusToHdf(nessusXml);
      const req = result.baselines[0].requirements[0];

      // Verify no duplicates exist
      const nistTags = req.tags.nist;
      const uniqueNist = [...new Set(nistTags)];
      expect(nistTags.length).toBe(uniqueNist.length);
    });

    it('should extract STIG ID from compliance-reference', async () => {
      const nessusXml = readFileSync(
        join(FIXTURES_DIR, 'input', 'compliance.nessus'),
        'utf-8'
      );

      const result = await convertNessusToHdf(nessusXml);
      const req = result.baselines[0].requirements[0];

      expect(req.tags.stig_id).toBe('RHEL-07-010010');
    });

    it('should extract Rule-ID as rid from compliance-reference', async () => {
      const nessusXml = readFileSync(
        join(FIXTURES_DIR, 'input', 'compliance.nessus'),
        'utf-8'
      );

      const result = await convertNessusToHdf(nessusXml);
      const req = result.baselines[0].requirements[0];

      expect(req.tags.rid).toBe('SV-86473r2_rule');
    });

    it('should map compliance-result to HDF status', async () => {
      const nessusXml = readFileSync(
        join(FIXTURES_DIR, 'input', 'compliance.nessus'),
        'utf-8'
      );

      const result = await convertNessusToHdf(nessusXml);

      // PASSED -> passed
      const passed = result.baselines[0].requirements.find(r => r.id === 'V-72083');
      expect(passed?.results[0].status).toBe('passed');

      // FAILED -> failed
      const failed = result.baselines[0].requirements.find(r => r.id === 'V-71849');
      expect(failed?.results[0].status).toBe('failed');

      // WARNING -> notApplicable
      const warning = result.baselines[0].requirements.find(r => r.id === 'V-72095');
      expect(warning?.results[0].status).toBe('notApplicable');

      // ERROR -> error
      const error = result.baselines[0].requirements.find(r => r.id === 'V-72229');
      expect(error?.results[0].status).toBe('error');
    });

    it('should use compliance-actual-value for result message', async () => {
      const nessusXml = readFileSync(
        join(FIXTURES_DIR, 'input', 'compliance.nessus'),
        'utf-8'
      );

      const result = await convertNessusToHdf(nessusXml);
      const req = result.baselines[0].requirements[0];

      expect(req.results[0].message).toContain('banner-message-enable : not set');
    });
  });

  describe('Edge Cases', async () => {
    it('should handle missing optional fields gracefully', async () => {
      const minimalXml = `<?xml version="1.0"?>
<NessusClientData_v2>
  <Policy><policyName>Test</policyName></Policy>
  <Report name="Test">
    <ReportHost name="10.0.0.1">
      <HostProperties>
        <tag name="HOST_START">Mon Jan 29 10:00:00 2024</tag>
      </HostProperties>
      <ReportItem port="0" svc_name="test" protocol="tcp" severity="0" pluginID="1" pluginName="Test" pluginFamily="Test">
        <description>Test</description>
      </ReportItem>
    </ReportHost>
  </Report>
</NessusClientData_v2>`;

      const result = await convertNessusToHdf(minimalXml);
      expect(result).toBeDefined();
      expect(result.baselines[0].version).toBeUndefined();
    });

    it('should handle ReportHost without HostProperties', async () => {
      const xml = `<?xml version="1.0"?>
<NessusClientData_v2>
  <Policy><policyName>Test</policyName></Policy>
  <Report name="Test">
    <ReportHost name="10.0.0.1">
      <ReportItem port="0" svc_name="test" protocol="tcp" severity="0" pluginID="1" pluginName="Test" pluginFamily="Test">
        <description>Test</description>
      </ReportItem>
    </ReportHost>
  </Report>
</NessusClientData_v2>`;

      const result = await convertNessusToHdf(xml);
      expect(result.components).toBeDefined();
    });

    it('should handle ReportHost without ReportItems', async () => {
      const xml = `<?xml version="1.0"?>
<NessusClientData_v2>
  <Policy><policyName>Test</policyName></Policy>
  <Report name="Test">
    <ReportHost name="10.0.0.1">
      <HostProperties>
        <tag name="HOST_START">Mon Jan 29 10:00:00 2024</tag>
      </HostProperties>
    </ReportHost>
  </Report>
</NessusClientData_v2>`;

      const result = await convertNessusToHdf(xml);
      expect(result.baselines[0].requirements).toHaveLength(1);
      expect(result.baselines[0].requirements[0].id).toBe('nessus-no-findings');
      expect(result.baselines[0].requirements[0].results[0].status).toBe('passed');
    });

    it('should handle ReportItem without see_also', async () => {
      const xml = `<?xml version="1.0"?>
<NessusClientData_v2>
  <Policy><policyName>Test</policyName></Policy>
  <Report name="Test">
    <ReportHost name="10.0.0.1">
      <HostProperties>
        <tag name="HOST_START">Mon Jan 29 10:00:00 2024</tag>
      </HostProperties>
      <ReportItem port="0" svc_name="test" protocol="tcp" severity="0" pluginID="1" pluginName="Test" pluginFamily="Test">
        <description>Test</description>
      </ReportItem>
    </ReportHost>
  </Report>
</NessusClientData_v2>`;

      const result = await convertNessusToHdf(xml);
      const req = result.baselines[0].requirements[0];
      expect(req.refs).toBeUndefined();
    });

    it('should handle compliance item without solution', async () => {
      const xml = `<?xml version="1.0"?>
<NessusClientData_v2>
  <Policy><policyName>Test</policyName></Policy>
  <Report name="Test" xmlns:cm="http://www.nessus.org/cm">
    <ReportHost name="10.0.0.1">
      <HostProperties>
        <tag name="HOST_START">Mon Jan 29 10:00:00 2024</tag>
      </HostProperties>
      <ReportItem port="0" svc_name="test" protocol="tcp" severity="2" pluginID="1" pluginName="Test" pluginFamily="Policy Compliance">
        <cm:compliance-reference>CCI|CCI-000001,CAT|II</cm:compliance-reference>
        <cm:compliance-check-name>Test Check</cm:compliance-check-name>
        <cm:compliance-info>Info</cm:compliance-info>
        <cm:compliance-result>FAILED</cm:compliance-result>
        <description>Test</description>
      </ReportItem>
    </ReportHost>
  </Report>
</NessusClientData_v2>`;

      const result = await convertNessusToHdf(xml);
      const fixDesc = result.baselines[0].requirements[0].descriptions.find(d => d.label === 'fix');
      expect(fixDesc).toBeUndefined();
    });

    it('should handle compliance result without actual value', async () => {
      const xml = `<?xml version="1.0"?>
<NessusClientData_v2>
  <Policy><policyName>Test</policyName></Policy>
  <Report name="Test" xmlns:cm="http://www.nessus.org/cm">
    <ReportHost name="10.0.0.1">
      <HostProperties>
        <tag name="HOST_START">Mon Jan 29 10:00:00 2024</tag>
      </HostProperties>
      <ReportItem port="0" svc_name="test" protocol="tcp" severity="2" pluginID="1" pluginName="Test" pluginFamily="Policy Compliance">
        <cm:compliance-reference>CCI|CCI-000001,CAT|II</cm:compliance-reference>
        <cm:compliance-check-name>Test Check</cm:compliance-check-name>
        <cm:compliance-info>Info</cm:compliance-info>
        <cm:compliance-result>FAILED</cm:compliance-result>
        <description>Test</description>
      </ReportItem>
    </ReportHost>
  </Report>
</NessusClientData_v2>`;

      const result = await convertNessusToHdf(xml);
      expect(result.baselines[0].requirements[0].results[0].message).toBeUndefined();
    });
  });

  describe('CVE-ecosystem structured fields', () => {
    // Plugin 156888 in sample.nessus carries full v3 base + temporal + v2
    // base + temporal vectors and score-source CVE-2022-21291.
    it('populates cvss[] for v3 + temporal vectors and keeps legacy tags', async () => {
      const nessusXml = readFileSync(join(FIXTURES_DIR, 'input', 'sample.nessus'), 'utf-8');
      const result = await convertNessusToHdf(nessusXml);
      const req = findReqAcrossBaselines(result, '156888');
      expect(req).toBeDefined();

      expect(req!.cvss).toBeDefined();
      expect(req!.cvss).toHaveLength(1);
      const c = req!.cvss![0];
      expect(c.version).toBe('3.0');
      expect(c.source).toBe('CVE-2022-21291');
      expect(c.baseVector).toBe('CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N');
      expect(c.baseScore).toBeCloseTo(5.3, 3);
      expect(c.baseSeverity).toBe('medium');
      // CVSS:3.0/ prefix must be stripped from temporal vector.
      expect(c.threatVector).toBe('E:U/RL:O/RC:C');
      expect(c.threatScore).toBeCloseTo(4.6, 3);
      // Temporal score is the post-threat-enrichment computed score.
      expect(c.computedScore).toBeCloseTo(4.6, 3);
      expect(c.computedSeverity).toBe('medium');

      // Legacy back-compat tags preserved for one release.
      expect(req!.tags.cvss3_base_score).toBe('5.3');
      expect(req!.tags.cvss_base_score).toBe('5.0');
    });

    // Plugin 10114 (ICMP Timestamp) has <cwe>200</cwe> + CVE-1999-0524 with
    // a 0.0 base score (CVSS "none" band).
    it('populates cwe[] in CWE-N format and cvss source for CVE findings', async () => {
      const nessusXml = readFileSync(join(FIXTURES_DIR, 'input', 'sample.nessus'), 'utf-8');
      const result = await convertNessusToHdf(nessusXml);
      const req = findReqAcrossBaselines(result, '10114');
      expect(req).toBeDefined();

      expect(req!.cwe).toEqual(['CWE-200']);

      expect(req!.cvss).toHaveLength(1);
      const c = req!.cvss![0];
      expect(c.source).toBe('CVE-1999-0524');
      expect(c.version).toBe('3.0');
      expect(c.baseVector).toBe('CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N');
      expect(c.baseScore).toBeCloseTo(0.0, 3);
      expect(c.baseSeverity).toBe('none');
      // No temporal data on this finding.
      expect(c.threatVector).toBeUndefined();
      expect(c.threatScore).toBeUndefined();
      expect(c.computedScore).toBeUndefined();
    });

    // Plugin 57582 (SSL Self-Signed Certificate) has v2 base score + vector
    // but no <cvss_score_source>, no <cve>. Should NOT emit cvss[] — that
    // field is reserved for CVE findings.
    it('does not emit cvss[] for non-CVE findings, only legacy tag', async () => {
      const nessusXml = readFileSync(join(FIXTURES_DIR, 'input', 'sample.nessus'), 'utf-8');
      const result = await convertNessusToHdf(nessusXml);
      const req = findReqAcrossBaselines(result, '57582');
      expect(req).toBeDefined();

      expect(req!.cvss === undefined || req!.cvss!.length === 0).toBe(true);
      expect(req!.cwe === undefined || req!.cwe!.length === 0).toBe(true);
      // Legacy tag is still present.
      expect(req!.tags.cvss_base_score).toBe('6.4');
    });

    // Synthetic v2-only ReportItem: tests the legacy CVSS v2 branch +
    // CVSS:3.1/ version detection + EPSS + multi-CWE pipe-delimited input.
    // Real Nessus output occasionally lacks v3 fields for older plugins.
    it('handles v2-only CVE finding with EPSS, CVSS:3.1, multi-CWE', async () => {
      const xml = `<?xml version="1.0"?>
<NessusClientData_v2>
  <Policy>
    <policyName>Synthetic</policyName>
    <Preferences><ServerPreferences/></Preferences>
  </Policy>
  <Report name="Synthetic">
    <ReportHost name="10.0.0.1">
      <HostProperties>
        <tag name="HOST_START">Mon Jan 29 10:00:00 2024</tag>
      </HostProperties>
      <ReportItem port="443" svc_name="www" protocol="tcp" severity="3" pluginID="999999" pluginName="Synthetic V2-Only Finding" pluginFamily="Misc.">
        <cvss_base_score>9.8</cvss_base_score>
        <cvss_score_source>CVE-2024-99999</cvss_score_source>
        <cvss_vector>CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C</cvss_vector>
        <cvss_temporal_score>8.5</cvss_temporal_score>
        <cvss_temporal_vector>CVSS2#E:F/RL:OF/RC:C</cvss_temporal_vector>
        <epss_score>0.91234</epss_score>
        <epss_percentile>0.98</epss_percentile>
        <cwe>79|89</cwe>
        <cwe>352</cwe>
        <description>Synthetic v2-only finding for branch coverage.</description>
      </ReportItem>
    </ReportHost>
  </Report>
</NessusClientData_v2>`;
      const result = await convertNessusToHdf(xml);
      const req = findReqAcrossBaselines(result, '999999');
      expect(req).toBeDefined();

      // v2-only branch fires when no cvss3_vector/cvss3_base_score present.
      expect(req!.cvss).toHaveLength(1);
      const c = req!.cvss![0];
      expect(c.version).toBe('2.0');
      expect(c.baseVector).toBe('AV:N/AC:L/Au:N/C:C/I:C/A:C'); // CVSS2# stripped
      expect(c.baseScore).toBeCloseTo(9.8, 3);
      expect(c.baseSeverity).toBe('critical');
      expect(c.threatVector).toBe('E:F/RL:OF/RC:C');
      expect(c.threatScore).toBeCloseTo(8.5, 3);
      expect(c.computedSeverity).toBe('high');

      // EPSS populated with both score + percentile; date derived from
      // host HOST_START.
      expect(req!.epss).toBeDefined();
      expect(req!.epss!.score).toBeCloseTo(0.91234, 4);
      expect(req!.epss!.percentile).toBeCloseTo(0.98, 3);
      expect(req!.epss!.date).toBe('2024-01-29');

      // CWE extraction from pipe-delimited + separate elements; deduped,
      // sorted, formatted as CWE-N.
      expect(req!.cwe).toEqual(['CWE-352', 'CWE-79', 'CWE-89']);
    });

    // CVSS:3.1 vector detection (real-world but absent from this fixture).
    it('detects CVSS:3.1 vector prefix', async () => {
      const xml = `<?xml version="1.0"?>
<NessusClientData_v2>
  <Policy><policyName>P</policyName><Preferences><ServerPreferences/></Preferences></Policy>
  <Report name="R">
    <ReportHost name="h">
      <HostProperties><tag name="HOST_START">Mon Jan 29 10:00:00 2024</tag></HostProperties>
      <ReportItem port="0" svc_name="g" protocol="tcp" severity="3" pluginID="31" pluginName="V3.1" pluginFamily="X">
        <cvss3_base_score>7.5</cvss3_base_score>
        <cvss3_vector>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N</cvss3_vector>
        <cvss_score_source>CVE-2024-0003</cvss_score_source>
      </ReportItem>
    </ReportHost>
  </Report>
</NessusClientData_v2>`;
      const result = await convertNessusToHdf(xml);
      const req = findReqAcrossBaselines(result, '31');
      expect(req!.cvss![0].version).toBe('3.1');
      expect(req!.cvss![0].baseSeverity).toBe('high');
    });

    // Low-band severity (1.0-3.9) + ensures the 'low' switch case in
    // mapCvssSeverity is exercised.
    it('maps low CVSS band to low severity', async () => {
      const xml = `<?xml version="1.0"?>
<NessusClientData_v2>
  <Policy><policyName>P</policyName><Preferences><ServerPreferences/></Preferences></Policy>
  <Report name="R">
    <ReportHost name="h">
      <HostProperties><tag name="HOST_START">Mon Jan 29 10:00:00 2024</tag></HostProperties>
      <ReportItem port="0" svc_name="g" protocol="tcp" severity="1" pluginID="20" pluginName="Low" pluginFamily="X">
        <cvss3_base_score>2.5</cvss3_base_score>
        <cvss3_vector>CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L</cvss3_vector>
        <cvss_score_source>CVE-2024-0020</cvss_score_source>
      </ReportItem>
    </ReportHost>
  </Report>
</NessusClientData_v2>`;
      const result = await convertNessusToHdf(xml);
      const req = findReqAcrossBaselines(result, '20');
      expect(req!.cvss![0].baseSeverity).toBe('low');
    });

    // CVSS:4.0 prefix stripping (edge case in stripVersionPrefix).
    it('strips CVSS:4.0 prefix from temporal vector', async () => {
      const xml = `<?xml version="1.0"?>
<NessusClientData_v2>
  <Policy><policyName>P</policyName><Preferences><ServerPreferences/></Preferences></Policy>
  <Report name="R">
    <ReportHost name="h">
      <HostProperties><tag name="HOST_START">Mon Jan 29 10:00:00 2024</tag></HostProperties>
      <ReportItem port="0" svc_name="g" protocol="tcp" severity="2" pluginID="40" pluginName="V4" pluginFamily="X">
        <cvss3_base_score>5.0</cvss3_base_score>
        <cvss3_vector>CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N</cvss3_vector>
        <cvss3_temporal_vector>CVSS:4.0/E:A</cvss3_temporal_vector>
        <cvss_score_source>CVE-2024-0004</cvss_score_source>
      </ReportItem>
    </ReportHost>
  </Report>
</NessusClientData_v2>`;
      const result = await convertNessusToHdf(xml);
      const req = findReqAcrossBaselines(result, '40');
      expect(req!.cvss![0].threatVector).toBe('E:A');
    });
  });
});
