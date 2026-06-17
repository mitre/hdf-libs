import {readFileSync} from 'fs';
import {dirname, join} from 'path';
import {fileURLToPath} from 'url';
import {describe, expect, it} from 'vitest';
import {convertZapToHdf} from './converter';
import {runConverterContractTests} from '../../../shared/typescript/converter-contract.js';
import {expectValidResults} from '../../../test/helpers/expectValidHdf.js';
import {parseJSON} from '@mitre/hdf-utilities';
import type {HDFResults} from '@mitre/hdf-schema';

const __dirname = dirname(fileURLToPath(import.meta.url));
const FIXTURES_DIR = join(__dirname, '..', 'fixtures');

function loadFixture(name: string): string {
  return readFileSync(join(FIXTURES_DIR, 'input', name), 'utf-8');
}

runConverterContractTests({
  converterName: 'zap-to-hdf',
  convertFn: convertZapToHdf,
  minimalFixture: 'minimal.json',
});

describe('ZAP Converter', () => {
  describe('validation', () => {
    it('should handle missing site array', async () => {
      const input = JSON.stringify({'@version': '2.7.0'});
      const output = await convertZapToHdf(input);
      const hdf = parseJSON<HDFResults>(output);
      expect(hdf.baselines).toHaveLength(1);
      expect(hdf.baselines[0].requirements).toHaveLength(1);
      const req = hdf.baselines[0].requirements[0];
      expect(req.id).toBe('zap-no-findings');
      expect(req.results[0].status).toBe('passed');
      expect(req.results[0].codeDesc).toContain('OWASP ZAP');
    });

    it('should handle empty site array', async () => {
      const input = JSON.stringify({'@version': '2.7.0', site: []});
      const output = await convertZapToHdf(input);
      const hdf = parseJSON<HDFResults>(output);
      expect(hdf.baselines).toHaveLength(1);
      expect(hdf.baselines[0].requirements).toHaveLength(1);
      const req = hdf.baselines[0].requirements[0];
      expect(req.id).toBe('zap-no-findings');
      expect(req.results[0].status).toBe('passed');
      expect(req.results[0].codeDesc).toContain('OWASP ZAP');
    });

    it('should synthesize no-findings placeholder for empty.json fixture', async () => {
      const input = loadFixture('empty.json');
      const output = await convertZapToHdf(input);
      const hdf = parseJSON<HDFResults>(output);
      expect(hdf.baselines).toHaveLength(1);
      expect(hdf.baselines[0].requirements).toHaveLength(1);
      const req = hdf.baselines[0].requirements[0];
      expect(req.id).toBe('zap-no-findings');
      expect(req.results[0].status).toBe('passed');
      expect(req.results[0].codeDesc).toContain('OWASP ZAP');
      expect(req.results[0].codeDesc).toContain('https://example.com');
    });
  });

  describe('basic structure - minimal fixture', () => {
    it('should create 1 baseline with 2 requirements', async () => {
      const input = loadFixture('minimal.json');
      const output = await convertZapToHdf(input);
      const hdf = parseJSON<HDFResults>(output);
      expectValidResults(hdf);

      expect(hdf.baselines).toHaveLength(1);
      expect(hdf.baselines[0].requirements).toHaveLength(2);
    });

    it('should set baseline name to scan label', async () => {
      const input = loadFixture('minimal.json');
      const output = await convertZapToHdf(input);
      const hdf = parseJSON<HDFResults>(output);

      expect(hdf.baselines[0].name).toBe('OWASP ZAP Scan');
    });

    it('should set baseline title with site name', async () => {
      const input = loadFixture('minimal.json');
      const output = await convertZapToHdf(input);
      const hdf = parseJSON<HDFResults>(output);

      expect(hdf.baselines[0].title).toBe('OWASP ZAP Scan of https://example.com');
    });

    it('should set baseline summary with ZAP version', async () => {
      const input = loadFixture('minimal.json');
      const output = await convertZapToHdf(input);
      const hdf = parseJSON<HDFResults>(output);

      expect(hdf.baselines[0].summary).toBe('ZAP Version 2.7.0');
    });
  });

  describe('targets', () => {
    it('should populate target with host name and application type', async () => {
      const input = loadFixture('minimal.json');
      const output = await convertZapToHdf(input);
      const hdf = parseJSON<HDFResults>(output);

      expect(hdf.components).toHaveLength(1);
      expect(hdf.components![0].name).toBe('example.com');
      expect(hdf.components![0].type).toBe('application');
      expect(hdf.components![0].url).toBe('https://example.com');
    });

    it('should omit targets when host is unknown', async () => {
      const input = JSON.stringify({'@version': '2.7.0', site: [{alerts: []}]});
      const output = await convertZapToHdf(input);
      const hdf = parseJSON<HDFResults>(output);

      expect(hdf.components).toHaveLength(0);
    });
  });

  describe('generator and dataSource', () => {
    it('should set generator name to "zap-to-hdf"', async () => {
      const input = loadFixture('minimal.json');
      const output = await convertZapToHdf(input);
      const hdf = parseJSON<HDFResults>(output);

      expect(hdf.generator.name).toBe('zap-to-hdf');
    });

    it('should set dataSource name to "OWASP ZAP" and format to "JSON"', async () => {
      const input = loadFixture('minimal.json');
      const output = await convertZapToHdf(input);
      const hdf = parseJSON<HDFResults>(output);

      expect(hdf.tool?.name).toBe('OWASP ZAP');
      expect(hdf.tool?.format).toBe('JSON');
    });

    it('should set tool version from @version', async () => {
      const input = loadFixture('minimal.json');
      const output = await convertZapToHdf(input);
      const hdf = parseJSON<HDFResults>(output);

      expect(hdf.tool?.version).toBe('2.7.0');
    });
  });

  describe('timestamp', () => {
    it('should set timestamp from @generated', async () => {
      const input = loadFixture('minimal.json');
      const output = await convertZapToHdf(input);
      const hdf = parseJSON<HDFResults>(output);

      expect(hdf.timestamp).toBeDefined();
    });
  });

  describe('checksum', () => {
    it('should calculate SHA-256 checksum of input', async () => {
      const input = loadFixture('minimal.json');
      const output = await convertZapToHdf(input);
      const hdf = parseJSON<HDFResults>(output);

      expect(hdf.baselines[0].resultsChecksum).toBeDefined();
      expect(hdf.baselines[0].resultsChecksum?.algorithm).toBe('sha256');
      expect(hdf.baselines[0].resultsChecksum?.value).toMatch(/^[a-f0-9]{64}$/);
    });
  });

  describe('impact mapping', () => {
    it('should map riskcode "1" to impact 0.3', async () => {
      const input = loadFixture('minimal.json');
      const output = await convertZapToHdf(input);
      const hdf = parseJSON<HDFResults>(output);

      const req = hdf.baselines[0].requirements.find(r => r.id === '10021');
      expect(req?.impact).toBe(0.3);
    });

    it('should map riskcode "2" to impact 0.5', async () => {
      const input = loadFixture('minimal.json');
      const output = await convertZapToHdf(input);
      const hdf = parseJSON<HDFResults>(output);

      const req = hdf.baselines[0].requirements.find(r => r.id === '90022');
      expect(req?.impact).toBe(0.5);
    });
  });

  describe('requirement IDs', () => {
    it('should use pluginid as requirement ID', async () => {
      const input = loadFixture('minimal.json');
      const output = await convertZapToHdf(input);
      const hdf = parseJSON<HDFResults>(output);

      const ids = hdf.baselines[0].requirements.map(r => r.id);
      expect(ids).toContain('10021');
      expect(ids).toContain('90022');
    });
  });

  describe('requirement titles', () => {
    it('should set title from alert name', async () => {
      const input = loadFixture('minimal.json');
      const output = await convertZapToHdf(input);
      const hdf = parseJSON<HDFResults>(output);

      const req = hdf.baselines[0].requirements.find(r => r.id === '10021');
      expect(req?.title).toBe('X-Content-Type-Options Header Missing');
    });
  });

  describe('descriptions', () => {
    it('should include default description with HTML stripped', async () => {
      const input = loadFixture('minimal.json');
      const output = await convertZapToHdf(input);
      const hdf = parseJSON<HDFResults>(output);

      const req = hdf.baselines[0].requirements.find(r => r.id === '10021');
      const defaultDesc = req?.descriptions?.find(d => d.label === 'default');
      expect(defaultDesc).toBeDefined();
      expect(defaultDesc?.data).not.toContain('<p>');
      expect(defaultDesc?.data).toContain("X-Content-Type-Options was not set to 'nosniff'");
    });

    it('should include check description from solution and otherinfo', async () => {
      const input = loadFixture('minimal.json');
      const output = await convertZapToHdf(input);
      const hdf = parseJSON<HDFResults>(output);

      const req = hdf.baselines[0].requirements.find(r => r.id === '10021');
      const checkDesc = req?.descriptions?.find(d => d.label === 'check');
      expect(checkDesc).toBeDefined();
      expect(checkDesc?.data).toContain('Content-Type header');
      expect(checkDesc?.data).toContain('error type pages');
    });
  });

  describe('NIST mapping', () => {
    it('should map known CWE 16 to NIST control', async () => {
      const input = loadFixture('minimal.json');
      const output = await convertZapToHdf(input);
      const hdf = parseJSON<HDFResults>(output);

      const req = hdf.baselines[0].requirements.find(r => r.id === '10021');
      expect(req?.tags?.nist).toBeDefined();
      expect(Array.isArray(req?.tags?.nist)).toBe(true);
      expect((req?.tags?.nist as string[]).length).toBeGreaterThan(0);
    });

    it('should use DEFAULT_STATIC_ANALYSIS_NIST_TAGS for empty cweid', async () => {
      const input = loadFixture('minimal.json');
      const output = await convertZapToHdf(input);
      const hdf = parseJSON<HDFResults>(output);

      const req = hdf.baselines[0].requirements.find(r => r.id === '90022');
      expect(req?.tags?.nist).toEqual(['SA-11', 'RA-5']);
    });
  });

  describe('CCI tags', () => {
    it('should populate CCI tags from NIST mapping', async () => {
      const input = loadFixture('minimal.json');
      const output = await convertZapToHdf(input);
      const hdf = parseJSON<HDFResults>(output);

      const req = hdf.baselines[0].requirements.find(r => r.id === '10021');
      expect(req?.tags?.cci).toBeDefined();
      expect((req?.tags?.cci as string[]).length).toBeGreaterThan(0);
    });
  });

  describe('extra tags', () => {
    it('should include cweid tag', async () => {
      const input = loadFixture('minimal.json');
      const output = await convertZapToHdf(input);
      const hdf = parseJSON<HDFResults>(output);

      const req = hdf.baselines[0].requirements.find(r => r.id === '10021');
      expect(req?.tags?.cweid).toBe('16');
    });

    it('should include wascid tag', async () => {
      const input = loadFixture('minimal.json');
      const output = await convertZapToHdf(input);
      const hdf = parseJSON<HDFResults>(output);

      const req = hdf.baselines[0].requirements.find(r => r.id === '10021');
      expect(req?.tags?.wascid).toBe('15');
    });

    it('should include riskdesc tag', async () => {
      const input = loadFixture('minimal.json');
      const output = await convertZapToHdf(input);
      const hdf = parseJSON<HDFResults>(output);

      const req = hdf.baselines[0].requirements.find(r => r.id === '10021');
      expect(req?.tags?.riskdesc).toBe('Low (Medium)');
    });

    it('should include confidence tag', async () => {
      const input = loadFixture('minimal.json');
      const output = await convertZapToHdf(input);
      const hdf = parseJSON<HDFResults>(output);

      const req = hdf.baselines[0].requirements.find(r => r.id === '10021');
      expect(req?.tags?.confidence).toBe('2');
    });
  });

  describe('results from instances', () => {
    it('should create one result per instance', async () => {
      const input = loadFixture('minimal.json');
      const output = await convertZapToHdf(input);
      const hdf = parseJSON<HDFResults>(output);

      const req1 = hdf.baselines[0].requirements.find(r => r.id === '10021');
      expect(req1?.results).toHaveLength(1);

      const req2 = hdf.baselines[0].requirements.find(r => r.id === '90022');
      expect(req2?.results).toHaveLength(2);
    });

    it('should set all results to failed', async () => {
      const input = loadFixture('minimal.json');
      const output = await convertZapToHdf(input);
      const hdf = parseJSON<HDFResults>(output);

      for (const req of hdf.baselines[0].requirements) {
        for (const result of req.results) {
          expect(result.status).toBe('failed');
        }
      }
    });

    it('should format codeDesc with URI, method, param, and evidence', async () => {
      const input = loadFixture('minimal.json');
      const output = await convertZapToHdf(input);
      const hdf = parseJSON<HDFResults>(output);

      const req = hdf.baselines[0].requirements.find(r => r.id === '10021');
      expect(req?.results[0].codeDesc).toBe('URI: https://example.com/login | Method: GET | Param: X-Content-Type-Options');
    });

    it('should include attack as result message', async () => {
      const input = loadFixture('minimal.json');
      const output = await convertZapToHdf(input);
      const hdf = parseJSON<HDFResults>(output);

      const req = hdf.baselines[0].requirements.find(r => r.id === '90022');
      // Second instance has an attack field
      expect(req?.results[1].message).toBe("' OR 1=1 --");
    });
  });

  describe('SARIF routing', () => {
    it('should delegate SARIF input to SARIF converter', async () => {
      const sarifInput = JSON.stringify({
        $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
        version: '2.1.0',
        runs: [{
          tool: {driver: {name: 'TestTool', version: '1.0'}},
          results: [],
        }],
      });
      const output = await convertZapToHdf(sarifInput);
      const hdf = parseJSON<HDFResults>(output);
      // SARIF converter produces output with its own generator
      expect(hdf.generator.name).toBe('sarif-to-hdf');
    });
  });

  describe('webgoat fixture', () => {
    it('should select site with most alerts (mymac.com, 25 alerts)', async () => {
      const input = loadFixture('webgoat.json');
      const output = await convertZapToHdf(input);
      const hdf = parseJSON<HDFResults>(output);

      // Baseline.Name is the fixed scan label; the host goes into targets
      expect(hdf.baselines[0].name).toBe('OWASP ZAP Scan');
      expect(hdf.components).toHaveLength(1);
      expect(hdf.components![0].name).toBe('mymac.com');
    });

    it('should produce 15 unique requirements from 25 alerts with deduplication', async () => {
      const input = loadFixture('webgoat.json');
      const output = await convertZapToHdf(input);
      const hdf = parseJSON<HDFResults>(output);

      // 25 alerts, 15 unique pluginids, but duplicates get .1, .2, etc.
      expect(hdf.baselines[0].requirements).toHaveLength(25);
    });

    it('should deduplicate pluginids with .1, .2 suffixes', async () => {
      const input = loadFixture('webgoat.json');
      const output = await convertZapToHdf(input);
      const hdf = parseJSON<HDFResults>(output);

      const ids = hdf.baselines[0].requirements.map(r => r.id);
      expect(ids).toContain('90028');
      expect(ids).toContain('90028.1');
      expect(ids).toContain('90028.2');
    });

    it('should set timestamp from @generated', async () => {
      const input = loadFixture('webgoat.json');
      const output = await convertZapToHdf(input);
      const hdf = parseJSON<HDFResults>(output);

      expect(hdf.timestamp).toBeDefined();
    });

    it('should map riskcode 0 to impact 0.3', async () => {
      const input = loadFixture('webgoat.json');
      const output = await convertZapToHdf(input);
      const hdf = parseJSON<HDFResults>(output);

      // First requirement (90028) has riskcode 0
      const req = hdf.baselines[0].requirements.find(r => r.id === '90028');
      expect(req?.impact).toBe(0.3);
    });

    it('should map riskcode 3 to impact 0.7', async () => {
      const input = loadFixture('webgoat.json');
      const output = await convertZapToHdf(input);
      const hdf = parseJSON<HDFResults>(output);

      // Find a requirement with riskcode 3 (e.g. pluginid 42 or 20012)
      const req = hdf.baselines[0].requirements.find(r => r.id === '42');
      expect(req?.impact).toBe(0.7);
    });

    it('should include dataSource version', async () => {
      const input = loadFixture('webgoat.json');
      const output = await convertZapToHdf(input);
      const hdf = parseJSON<HDFResults>(output);

      expect(hdf.tool?.version).toBe('2.7.0');
    });
  });
});
