import { describe, it, expect } from 'vitest';
import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { results } from '@mitre/hdf-fixtures';
import { convertHdfToXml } from './converter.js';
import { normalizeXmlForGolden } from '../../../shared/typescript/xml-golden.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const fixturesDir = join(__dirname, '..', 'fixtures');

function loadFixture(type: 'input' | 'expected', filename: string): string {
  return readFileSync(join(fixturesDir, type, filename), 'utf-8');
}

describe('hdf-to-xml Converter', () => {
  // Real InSpec HDF carries zone-less timestamps ("2026-03-25T22:56:27.736808").
  // They must be emitted as canonical trimmed-UTC RFC3339, identical to the Go output.
  it('emits canonical UTC timestamps for zone-less input HDF', () => {
    const result = convertHdfToXml(results.inspecMultilayered.read());

    expect(result).toContain('<startTime>2026-03-25T22:56:27.736Z</startTime>');
    expect(result).not.toContain('2026-03-25T22:56:27.736808');
  });

  describe('Basic conversion', () => {
    it('should convert minimal HDF to XML', () => {
      const input = results.minimal.read();
      const expected = loadFixture('expected', 'minimal.xml');

      const result = convertHdfToXml(input);

      // Same shared normalization the Go test uses — previously each language
      // normalized this golden its own way, so they were not comparing like for like.
      expect(normalizeXmlForGolden(result)).toBe(normalizeXmlForGolden(expected));
    });

    it('should losslessly serialize all Requirement_Core / baseline / component fields', () => {
      const input = loadFixture('input', 'full.json');
      const expected = loadFixture('expected', 'full.xml');

      const result = convertHdfToXml(input);

      // Golden compare under the shared normalization (parity with the Go test).
      expect(normalizeXmlForGolden(result)).toBe(normalizeXmlForGolden(expected));
      // Spot-check the fields that were previously dropped.
      for (const el of ['<code>', '<sourceLocation>', '<controlType>', '<verificationMethod>', '<applicability>', '<refs>', '<summary>', '<resultsChecksum>', '<originalChecksum>', '<componentId>', '<gtitle>', '<generator>']) {
        expect(result).toContain(el);
      }
    });

    it('losslessly serializes the post-v3.2 fields the struct mirror dropped', () => {
      const input = loadFixture('input', 'full.json');
      // Collapse indentation (and decode escaped apostrophes) so the structural
      // multi-element assertions are not defeated by pretty-printing.
      const out = normalizeXmlForGolden(convertHdfToXml(input));

      // Scalar arrays render as repeated unwrapped keys; object arrays keep the
      // wrapper + singular-child form.
      expect(out).toContain('<tags><cci>CCI-000012</cci><gtitle>SRG-OS-000480-GPOS-00227</gtitle><nist>AC-2</nist><nist>AC-3</nist><severity>high</severity></tags>');

      // Requirement-level overrides, dispositions, and effective* fields.
      expect(out).toContain('<statusOverrides><statusOverride><type>riskAdjustment</type>');
      expect(out).toContain('<reason>Compensating control: host isolated on a management VLAN with no inbound internet exposure.</reason>');
      expect(out).toContain('<impact><value>0.3</value></impact>');
      expect(out).toContain('<appliedBy><identifier>jane.doe@example.gov</identifier>');
      expect(out).toContain('<expiresAt>2099-12-31T00:00:00Z</expiresAt>');
      expect(out).toContain('<justification>inline_mitigations_already_exist</justification>');
      expect(out).toContain('<disposition>riskAdjustment</disposition>');
      expect(out).toContain('<effectiveStatus>passed</effectiveStatus>');
      expect(out).toContain('<effectiveImpact>0.3</effectiveImpact>');
      expect(out).toContain('<severity>high</severity>');

      // Vulnerability enrichment. cvss is an object array (wrapped + singular
      // child); cwe is a scalar array (repeated, unwrapped key).
      expect(out).toContain('<cvss><cvss><version>3.1</version>');
      expect(out).toContain('<baseScore>9.8</baseScore>');
      expect(out).toContain('<cwe>CWE-79</cwe><cwe>CWE-89</cwe>');
      expect(out).toContain('<epss><score>0.00432</score><percentile>0.7421</percentile>');
      expect(out).toContain('<kev><inKev>true</inKev>');
      expect(out).toContain('<poams><poam><type>remediation</type>');
      expect(out).toContain('<milestones><milestone><description>Vendor patch validated in staging</description>');
      expect(out).toContain('<affectedPackages><affectedPackage><name>openssl</name>');

      // evidence is an unmapped object array -> wrapper + generic <item> child.
      expect(out).toContain('<evidence><item><type>log</type>');

      // Result-level diagnostics. backtrace is a scalar (string) array ->
      // repeated, unwrapped key.
      expect(out).toContain('<exception>RuntimeError</exception>');
      expect(out).toContain("<backtrace>controls/SV-100001.rb:12:in `block'</backtrace>");
      expect(out).toContain('<resource>sshd_config</resource>');
      expect(out).toContain('<resourceId>/etc/ssh/sshd_config</resourceId>');

      // Baseline- and top-level fields.
      expect(out).toContain('<maintainer>MITRE</maintainer>');
      expect(out).toContain('<tool><name>InSpec</name><version>5.22.3</version><format>inspec-json</format></tool>');
      expect(out).toContain('<signedBy>ci-signer@example.gov</signedBy>');
      expect(out).toContain('<id>b1e7c0de-1a2b-4c3d-8e4f-5a6b7c8d9e0f</id>');
      expect(out).toContain('<runner><name>inspec</name>');
      expect(out).toContain('<macAddress>02:42:ac:11:00:02</macAddress>');
    });

    it('scalar array renders unwrapped; unmapped object array falls back to <item>', () => {
      const input = JSON.stringify({
        baselines: [{ name: 'B', aliases: ['a', 'b', 'c'], widgets: [{ n: 1 }, { n: 2 }], requirements: [] }]
      });
      const out = normalizeXmlForGolden(convertHdfToXml(input));
      // Scalar array -> repeated, unwrapped key.
      expect(out).toContain('<aliases>a</aliases><aliases>b</aliases><aliases>c</aliases>');
      // Unmapped object array -> wrapper + <item> children.
      expect(out).toContain('<widgets><item><n>1</n></item><item><n>2</n></item></widgets>');
    });

    it('should handle empty baselines array', () => {
      const input = JSON.stringify({
        baselines: [],
        components: [],
        statistics: { duration: 0 }
      });

      const result = convertHdfToXml(input);

      expect(result).toContain('<HdfResults>');
      expect(result).toContain('<baselines></baselines>');
      expect(result).toContain('</HdfResults>');
    });

    it('should handle baselines with no requirements', () => {
      const input = JSON.stringify({
        baselines: [{
          name: 'Empty Baseline',
          version: '1.0.0',
          title: 'Test',
          integrity: { algorithm: 'sha256', checksum: 'abc' },
          requirements: []
        }],
        components: [],
        statistics: { duration: 0 }
      });

      const result = convertHdfToXml(input);

      expect(result).toContain('<baseline>');
      expect(result).toContain('<name>Empty Baseline</name>');
      expect(result).toContain('<requirements></requirements>');
    });
  });

  describe('Error handling', () => {
    it('should throw error for invalid JSON', () => {
      expect(() => convertHdfToXml('not json')).toThrow('Invalid JSON');
    });

    it('should throw error for missing baselines field', () => {
      const invalid = JSON.stringify({ foo: 'bar' });
      expect(() => convertHdfToXml(invalid)).toThrow('Invalid HDF structure: missing baselines field');
    });

    it('should throw error for non-array baselines', () => {
      const invalid = JSON.stringify({ baselines: 'not an array' });
      expect(() => convertHdfToXml(invalid)).toThrow('Invalid HDF structure: baselines must be an array');
    });
  });

  describe('Complex structures', () => {
    it('should handle multiple baselines and targets', () => {
      const input = JSON.stringify({
        baselines: [
          {
            name: 'Baseline 1',
            version: '1.0.0',
            integrity: { algorithm: 'sha256', checksum: 'abc' },
            requirements: [{
              id: 'REQ-001',
              title: 'Test Requirement',
              descriptions: [{ label: 'default', data: 'Test description' }],
              impact: 0.5,
              tags: {},
              results: [{ status: 'passed', codeDesc: 'Test', startTime: '2025-01-01T00:00:00Z' }]
            }]
          }
        ],
        components: [{ name: 'Target 1', type: 'host' }],
        statistics: { duration: 10.5 }
      });

      const result = convertHdfToXml(input);

      expect(result).toContain('<name>Baseline 1</name>');
      expect(result).toContain('<id>REQ-001</id>');
      expect(result).toContain('<title>Test Requirement</title>');
      expect(result).toContain('<target>');
      expect(result).toContain('<name>Target 1</name>');
      expect(result).toContain('<type>host</type>');
    });

    it('emits host identity fields (hostname, fqdn, domain) in a stable order', () => {
      const input = JSON.stringify({
        baselines: [{ name: 'B', version: '1.0.0', integrity: { algorithm: 'sha256', checksum: 'abc' }, requirements: [] }],
        components: [{ type: 'host', name: 'web01', hostname: 'web01', fqdn: 'web01.prod.example.com', domain: 'CORP', ipAddress: '10.0.1.5' }],
        statistics: { duration: 0 }
      });

      const result = convertHdfToXml(input);
      expect(result).toContain('<hostname>web01</hostname>');
      expect(result).toContain('<fqdn>web01.prod.example.com</fqdn>');
      expect(result).toContain('<domain>CORP</domain>');
      // hostname before fqdn before domain before ipAddress (parity with Go).
      expect(result.indexOf('<hostname>')).toBeLessThan(result.indexOf('<fqdn>'));
      expect(result.indexOf('<fqdn>')).toBeLessThan(result.indexOf('<domain>'));
      expect(result.indexOf('<domain>')).toBeLessThan(result.indexOf('<ipAddress>'));
    });

    it('should preserve special characters in XML', () => {
      const input = JSON.stringify({
        baselines: [{
          name: 'Test & < > " \'',
          integrity: { algorithm: 'sha256', checksum: 'abc' },
          requirements: [{
            id: 'REQ-001',
            title: 'Description with <tags> & special chars',
            descriptions: [{ label: 'default', data: 'Data' }],
            impact: 0.5,
            tags: {},
            results: [{ status: 'passed', codeDesc: 'Test', startTime: '2025-01-01T00:00:00Z' }]
          }]
        }],
        statistics: {}
      });

      const result = convertHdfToXml(input);

      // XML should escape special characters
      expect(result).toContain('&amp;');
      expect(result).toContain('&lt;');
      expect(result).toContain('&gt;');
    });

    it('should handle baselines with no version or title', () => {
      const input = JSON.stringify({
        baselines: [{
          name: 'MinBaseline',
          integrity: { algorithm: 'sha256', checksum: 'abc' },
          requirements: [{
            id: 'REQ-001',
            descriptions: [{ label: 'default', data: 'Data' }],
            impact: 0.5,
            tags: { nist: ['AC-1'], empty: [] },
            results: [{ status: 'passed', codeDesc: 'Test', startTime: '2025-01-01T00:00:00Z', message: 'ok', runTime: 1.5 }]
          }]
        }],
        components: [{ name: 't1', type: 'host', fqdn: 'test.local', ipAddress: '1.2.3.4', hostname: 'myhost' }],
        timestamp: '2025-01-01T00:00:00Z',
        generator: { name: 'test', version: '1.0' },
        statistics: { duration: 10, requirements: { total: 1 } },
      });
      const result = convertHdfToXml(input);
      expect(result).toContain('MinBaseline');
      expect(result).toContain('fqdn');
      expect(result).toContain('ipAddress');
      expect(result).toContain('<hostname>myhost</hostname>');
      expect(result).toContain('message');
      expect(result).toContain('runTime');
      expect(result).toContain('timestamp');
      expect(result).toContain('generator');
    });

    it('should handle requirement with empty tags', () => {
      const input = JSON.stringify({
        baselines: [{
          name: 'B1',
          integrity: { algorithm: 'sha256', checksum: 'abc' },
          requirements: [{
            id: 'REQ-001',
            descriptions: [],
            impact: 0.0,
            tags: {},
            results: []
          }]
        }],
      });
      const result = convertHdfToXml(input);
      expect(result).toContain('REQ-001');
    });

    it('should handle baselines with no integrity', () => {
      const input = JSON.stringify({
        baselines: [{
          name: 'NoIntegrity',
          requirements: [{
            id: 'REQ-001',
            title: 'Test',
            descriptions: [{ label: 'default', data: 'desc' }],
            impact: 0.5,
            tags: { custom: 'value' },
            results: [{ status: 'passed', codeDesc: 'Test', startTime: '2025-01-01T00:00:00Z' }]
          }]
        }],
      });
      const result = convertHdfToXml(input);
      expect(result).toContain('NoIntegrity');
      expect(result).not.toContain('integrity');
    });

    it('should handle no components', () => {
      const input = JSON.stringify({
        baselines: [{
          name: 'B1',
          requirements: []
        }],
        statistics: {},
      });
      const result = convertHdfToXml(input);
      expect(result).not.toContain('<components>');
    });
  });
});
