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
      expect(result.targets).toBeDefined();
      expect(result.dataSource?.name).toBe('Nessus');
      expect(result.dataSource?.version).toBeUndefined();
      expect(result.dataSource?.format).toBeUndefined();
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

    it('should map see_also to refs array', async () => {
      const nessusXml = readFileSync(
        join(FIXTURES_DIR, 'input', 'sample.nessus'),
        'utf-8'
      );

      const result = await convertNessusToHdf(nessusXml);
      // Use plugin 51192 which has see_also URLs
      const req = findReqAcrossBaselines(result, '51192');

      expect(req?.refs).toBeDefined();
      expect(req?.refs?.length).toBeGreaterThan(0);
      // The see_also field contains URLs — verify at least one is present
      const refUrls = req?.refs?.map(r => r.url).join(' ') ?? '';
      expect(refUrls).toContain('X.509');
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

      expect(result.targets).toBeDefined();
      expect(result.targets?.length).toBe(3);

      // Find the first host (10.0.0.3)
      const target = result.targets!.find(t => t.id === '10.0.0.3');
      expect(target).toBeDefined();
      expect(target?.attributes?.['operating-system']).toContain('Ubuntu');
      expect(target?.attributes?.['host-ip']).toBe('10.0.0.3');
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
      expect(result.targets).toBeDefined();
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
      expect(result.baselines[0].requirements).toHaveLength(0);
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
});
