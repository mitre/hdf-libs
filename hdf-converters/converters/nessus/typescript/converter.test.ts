import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, it, expect } from 'vitest';
import { convertNessusToHdf } from './converter.js';
import type { HdfResults } from '@mitre/hdf-schema';

const FIXTURES_DIR = join(__dirname, '..', 'fixtures');

describe('Nessus to HDF Converter', () => {
  describe('convertNessusToHdf', () => {
    it('should convert minimal Nessus XML to HDF format', () => {
      const nessusXml = readFileSync(
        join(FIXTURES_DIR, 'input', 'minimal.nessus'),
        'utf-8'
      );

      const result = convertNessusToHdf(nessusXml);

      // Should return valid HDF Results
      expect(result).toBeDefined();
      expect(result.baselines).toBeDefined();
      expect(result.statistics).toBeDefined();
      expect(result.targets).toBeDefined();
    });

    it('should create one baseline per report with correct metadata', () => {
      const nessusXml = readFileSync(
        join(FIXTURES_DIR, 'input', 'minimal.nessus'),
        'utf-8'
      );

      const result = convertNessusToHdf(nessusXml);

      expect(result.baselines).toHaveLength(1);
      const baseline = result.baselines[0];

      expect(baseline.name).toBe('Nessus Basic Network Scan');
      expect(baseline.title).toBe('Nessus Basic Network Scan');
      expect(baseline.version).toBe('5.19.0');
      expect(baseline.status).toBe('loaded');
    });

    it('should convert ReportItems to requirements', () => {
      const nessusXml = readFileSync(
        join(FIXTURES_DIR, 'input', 'minimal.nessus'),
        'utf-8'
      );

      const result = convertNessusToHdf(nessusXml);
      const baseline = result.baselines[0];

      // Should have 2 requirements from the 2 ReportItems
      expect(baseline.requirements).toHaveLength(2);
    });

    it('should map Nessus fields to HDF requirement fields correctly', () => {
      const nessusXml = readFileSync(
        join(FIXTURES_DIR, 'input', 'minimal.nessus'),
        'utf-8'
      );

      const result = convertNessusToHdf(nessusXml);
      const req = result.baselines[0].requirements[0];

      // Check ID mapping (pluginID)
      expect(req.id).toBe('10267');

      // Check title mapping (pluginName)
      expect(req.title).toBe('SSH Server Type and Version Information');

      // Check descriptions array has default description
      expect(req.descriptions).toBeDefined();
      expect(req.descriptions.length).toBeGreaterThan(0);
      const defaultDesc = req.descriptions.find(d => d.label === 'default');
      expect(defaultDesc).toBeDefined();
      expect(defaultDesc?.data).toContain('Plugin Family: Service detection');
      expect(defaultDesc?.data).toContain('Port: 22');
      expect(defaultDesc?.data).toContain('Protocol: tcp');

      // Check fix description
      const fixDesc = req.descriptions.find(d => d.label === 'fix');
      expect(fixDesc).toBeDefined();
      expect(fixDesc?.data).toBe('n/a');
    });

    it('should map Nessus severity to HDF impact', () => {
      const nessusXml = readFileSync(
        join(FIXTURES_DIR, 'input', 'minimal.nessus'),
        'utf-8'
      );

      const result = convertNessusToHdf(nessusXml);

      // Severity 2 (Medium/Low) should map to 0.5
      const req1 = result.baselines[0].requirements.find(r => r.id === '10267');
      expect(req1?.impact).toBe(0.5);

      // Severity 3 (Medium) should map to 0.7
      const req2 = result.baselines[0].requirements.find(r => r.id === '51192');
      expect(req2?.impact).toBe(0.7);
    });

    it('should map Nessus plugin family to NIST tags using hdf-mappings', () => {
      const nessusXml = readFileSync(
        join(FIXTURES_DIR, 'input', 'minimal.nessus'),
        'utf-8'
      );

      const result = convertNessusToHdf(nessusXml);
      const req = result.baselines[0].requirements[0];

      // Should have tags object with nist array
      expect(req.tags).toBeDefined();
      expect(req.tags.nist).toBeDefined();

      // Service detection family should map to specific NIST controls
      // Based on hdf-mappings/src/data/nessus-nist-mappings.json
      expect(Array.isArray(req.tags.nist)).toBe(true);
    });

    it('should include additional Nessus tags in requirement tags', () => {
      const nessusXml = readFileSync(
        join(FIXTURES_DIR, 'input', 'minimal.nessus'),
        'utf-8'
      );

      const result = convertNessusToHdf(nessusXml);
      const req = result.baselines[0].requirements[0];

      expect(req.tags.rid).toBe('10267'); // pluginID as rid
      expect(req.tags.risk_factor).toBe('Low');
      expect(req.tags.plugin_type).toBe('remote');
      expect(req.tags.plugin_publication_date).toBe('1999/10/12');
      expect(req.tags.fname).toBe('ssh_detect.nasl');
      expect(req.tags.cvss_base_score).toBe('0.0');
    });

    it('should map see_also to refs array', () => {
      const nessusXml = readFileSync(
        join(FIXTURES_DIR, 'input', 'minimal.nessus'),
        'utf-8'
      );

      const result = convertNessusToHdf(nessusXml);
      const req = result.baselines[0].requirements[0];

      expect(req.refs).toBeDefined();
      expect(req.refs?.length).toBeGreaterThan(0);
      expect(req.refs?.[0].url).toBe('https://www.ietf.org/rfc/rfc4253.txt');
    });

    it('should create requirement results with proper status mapping', () => {
      const nessusXml = readFileSync(
        join(FIXTURES_DIR, 'input', 'minimal.nessus'),
        'utf-8'
      );

      const result = convertNessusToHdf(nessusXml);
      const req = result.baselines[0].requirements[0];

      // Should have at least one result
      expect(req.results).toBeDefined();
      expect(req.results.length).toBeGreaterThan(0);

      const testResult = req.results[0];

      // No compliance-result field means failed status
      expect(testResult.status).toBe('failed');

      // Should have code_desc from description or plugin_output
      expect(testResult.codeDesc).toBeDefined();
      expect(typeof testResult.codeDesc).toBe('string');

      // Should have message from plugin_output
      expect(testResult.message).toBeDefined();
      expect(testResult.message).toContain('SSH version');

      // Should have start_time from HostProperties HOST_START tag
      expect(testResult.startTime).toBeDefined();
    });

    it('should include code as JSON stringified ReportItem', () => {
      const nessusXml = readFileSync(
        join(FIXTURES_DIR, 'input', 'minimal.nessus'),
        'utf-8'
      );

      const result = convertNessusToHdf(nessusXml);
      const req = result.baselines[0].requirements[0];

      expect(req.code).toBeDefined();
      expect(typeof req.code).toBe('string');

      // Should be valid JSON
      const parsedCode = JSON.parse(req.code!);
      expect(parsedCode.pluginID).toBe('10267');
      expect(parsedCode.pluginName).toBe('SSH Server Type and Version Information');
    });

    it('should create target from ReportHost', () => {
      const nessusXml = readFileSync(
        join(FIXTURES_DIR, 'input', 'minimal.nessus'),
        'utf-8'
      );

      const result = convertNessusToHdf(nessusXml);

      expect(result.targets).toBeDefined();
      expect(result.targets?.length).toBeGreaterThan(0);

      const target = result.targets![0];
      expect(target.id).toBe('192.168.1.100');

      // Should include host properties in attributes
      expect(target.attributes).toBeDefined();
      expect(target.attributes?.['operating-system']).toBe('Linux Kernel 5.4');
      expect(target.attributes?.['host-ip']).toBe('192.168.1.100');
    });

    it('should set generator metadata', () => {
      const nessusXml = readFileSync(
        join(FIXTURES_DIR, 'input', 'minimal.nessus'),
        'utf-8'
      );

      const result = convertNessusToHdf(nessusXml);

      expect(result.generator).toBeDefined();
      expect(result.generator?.name).toBe('hdf-converters');
      expect(result.generator?.version).toBeDefined();
    });

    it('should calculate statistics', () => {
      const nessusXml = readFileSync(
        join(FIXTURES_DIR, 'input', 'minimal.nessus'),
        'utf-8'
      );

      const result = convertNessusToHdf(nessusXml);

      expect(result.statistics).toBeDefined();
      expect(result.statistics.duration).toBeGreaterThan(0);
    });

    it('should filter out empty refs', () => {
      const nessusXml = readFileSync(
        join(FIXTURES_DIR, 'input', 'minimal.nessus'),
        'utf-8'
      );

      const result = convertNessusToHdf(nessusXml);

      // All refs should have url defined
      result.baselines[0].requirements.forEach(req => {
        req.refs?.forEach(ref => {
          expect(ref.url).toBeDefined();
          expect(ref.url).not.toBe('');
        });
      });
    });
  });
});
