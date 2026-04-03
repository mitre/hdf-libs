import {readFileSync} from 'fs';
import {join} from 'path';
import {describe, expect, it} from 'vitest';
import {convertNiktoToHdf} from './converter';
import {runConverterContractTests} from '../../../shared/typescript/converter-contract.js';
import {parseJSON} from '@mitre/hdf-utilities';
import type {HdfResults} from '@mitre/hdf-schema';

const FIXTURES_DIR = join(__dirname, '..', 'fixtures');

function loadFixture(name: string): string {
  return readFileSync(join(FIXTURES_DIR, 'input', name), 'utf-8');
}

runConverterContractTests({
  converterName: 'nikto-to-hdf',
  convertFn: convertNiktoToHdf,
  minimalFixture: 'minimal.json',
});

describe('Nikto Converter', async () => {
  describe('validation', () => {
    it('should handle missing vulnerabilities array', async () => {
      const input = JSON.stringify({host: 'example.com', port: '80'});
      const output = await convertNiktoToHdf(input);
      const hdf = parseJSON<HdfResults>(output);
      expect(hdf.baselines[0].requirements).toHaveLength(0);
    });
  });

  describe('basic structure', () => {
    it('should create 1 baseline with 4 requirements from minimal fixture', async () => {
      const input = loadFixture('minimal.json');
      const output = await convertNiktoToHdf(input);
      const hdf = parseJSON<HdfResults>(output);

      expect(hdf.baselines).toHaveLength(1);
      expect(hdf.baselines[0].requirements).toHaveLength(4);
    });

    it('should set baseline name to "Nikto Website Scanner"', async () => {
      const input = loadFixture('minimal.json');
      const output = await convertNiktoToHdf(input);
      const hdf = parseJSON<HdfResults>(output);

      // Baseline name comes from createMinimalBaseline first arg = target name
      expect(hdf.baselines[0].name).toBe('Host: example.com Port: 80');
    });

    it('should set baseline title with host and port', async () => {
      const input = loadFixture('minimal.json');
      const output = await convertNiktoToHdf(input);
      const hdf = parseJSON<HdfResults>(output);

      expect(hdf.baselines[0].title).toBe('Nikto Target: Host: example.com Port: 80');
    });

    it('should set baseline summary to server banner', async () => {
      const input = loadFixture('minimal.json');
      const output = await convertNiktoToHdf(input);
      const hdf = parseJSON<HdfResults>(output);

      expect(hdf.baselines[0].summary).toBe('Apache/2.4.41');
    });
  });

  describe('generator and dataSource', () => {
    it('should set generator name to "nikto-to-hdf"', async () => {
      const input = loadFixture('minimal.json');
      const output = await convertNiktoToHdf(input);
      const hdf = parseJSON<HdfResults>(output);

      expect(hdf.generator.name).toBe('nikto-to-hdf');
    });

    it('should set dataSource name to "Nikto" and format to "JSON"', async () => {
      const input = loadFixture('minimal.json');
      const output = await convertNiktoToHdf(input);
      const hdf = parseJSON<HdfResults>(output);

      expect(hdf.tool?.name).toBe('Nikto');
      expect(hdf.tool?.format).toBe('JSON');
    });
  });

  describe('checksum', () => {
    it('should calculate SHA-256 checksum of input', async () => {
      const input = loadFixture('minimal.json');
      const output = await convertNiktoToHdf(input);
      const hdf = parseJSON<HdfResults>(output);

      const baseline = hdf.baselines[0];
      expect(baseline.resultsChecksum).toBeDefined();
      expect(baseline.resultsChecksum?.algorithm).toBe('sha256');
      expect(baseline.resultsChecksum?.value).toMatch(/^[a-f0-9]{64}$/);
    });
  });

  describe('impact', () => {
    it('should set all impacts to 0.5', async () => {
      const input = loadFixture('minimal.json');
      const output = await convertNiktoToHdf(input);
      const hdf = parseJSON<HdfResults>(output);

      for (const req of hdf.baselines[0].requirements) {
        expect(req.impact).toBe(0.5);
      }
    });
  });

  describe('status', () => {
    it('should set all statuses to Failed', async () => {
      const input = loadFixture('minimal.json');
      const output = await convertNiktoToHdf(input);
      const hdf = parseJSON<HdfResults>(output);

      for (const req of hdf.baselines[0].requirements) {
        for (const result of req.results) {
          expect(result.status).toBe('failed');
        }
      }
    });
  });

  describe('NIST mapping', () => {
    it('should map known ID 600050 to SI-2', async () => {
      const input = loadFixture('minimal.json');
      const output = await convertNiktoToHdf(input);
      const hdf = parseJSON<HdfResults>(output);

      const req = hdf.baselines[0].requirements.find(r => r.id === '600050');
      expect(req).toBeDefined();
      expect(req?.tags?.nist).toEqual(['SI-2']);
    });

    it('should use DEFAULT_STATIC_ANALYSIS_NIST_TAGS for unmapped ID 999957', async () => {
      const input = loadFixture('minimal.json');
      const output = await convertNiktoToHdf(input);
      const hdf = parseJSON<HdfResults>(output);

      const req = hdf.baselines[0].requirements.find(r => r.id === '999957');
      expect(req).toBeDefined();
      expect(req?.tags?.nist).toEqual(['SA-11', 'RA-5']);
    });
  });

  describe('CCI tags', () => {
    it('should populate CCI tags from NIST mapping', async () => {
      const input = loadFixture('minimal.json');
      const output = await convertNiktoToHdf(input);
      const hdf = parseJSON<HdfResults>(output);

      const req = hdf.baselines[0].requirements.find(r => r.id === '600050');
      expect(req?.tags?.cci).toBeDefined();
      expect((req?.tags?.cci as string[]).length).toBeGreaterThan(0);
    });
  });

  describe('OSVDB tag', () => {
    it('should include OSVDB tag for ID 999971 with value "877"', async () => {
      const input = loadFixture('minimal.json');
      const output = await convertNiktoToHdf(input);
      const hdf = parseJSON<HdfResults>(output);

      const req = hdf.baselines[0].requirements.find(r => r.id === '999971');
      expect(req).toBeDefined();
      expect(req?.tags?.osvdb).toBe('877');
    });

    it('should omit OSVDB tag when value is "0"', async () => {
      const input = loadFixture('minimal.json');
      const output = await convertNiktoToHdf(input);
      const hdf = parseJSON<HdfResults>(output);

      const req = hdf.baselines[0].requirements.find(r => r.id === '600050');
      expect(req?.tags?.osvdb).toBeUndefined();
    });
  });

  describe('codeDesc', () => {
    it('should format codeDesc with URL and method', async () => {
      const input = loadFixture('minimal.json');
      const output = await convertNiktoToHdf(input);
      const hdf = parseJSON<HdfResults>(output);

      const req = hdf.baselines[0].requirements.find(r => r.id === '600050');
      expect(req?.results[0].codeDesc).toBe('URL: / Method: HEAD');
    });
  });

  describe('target name', () => {
    it('should set target name from host and port', async () => {
      const input = loadFixture('zero.webappsecurity.json');
      const output = await convertNiktoToHdf(input);
      const hdf = parseJSON<HdfResults>(output);

      expect(hdf.baselines[0].name).toBe('Host: zero.webappsecurity.com Port: 443');
    });
  });

  describe('descriptions', () => {
    it('should include default description with vulnerability msg', async () => {
      const input = loadFixture('minimal.json');
      const output = await convertNiktoToHdf(input);
      const hdf = parseJSON<HdfResults>(output);

      const req = hdf.baselines[0].requirements.find(r => r.id === '999957');
      const defaultDesc = req?.descriptions?.find(d => d.label === 'default');
      expect(defaultDesc).toBeDefined();
      expect(defaultDesc?.data).toBe('The anti-clickjacking X-Frame-Options header is not present.');
    });
  });

  describe('empty vulnerabilities', () => {
    it('should produce 0 requirements for empty vulnerabilities array', async () => {
      const input = loadFixture('empty-vulns.json');
      const output = await convertNiktoToHdf(input);
      const hdf = parseJSON<HdfResults>(output);

      expect(hdf.baselines).toHaveLength(1);
      expect(hdf.baselines[0].requirements).toHaveLength(0);
    });
  });

  describe('full fixture', () => {
    it('should produce 14 requirements from zero.webappsecurity.json', async () => {
      const input = loadFixture('zero.webappsecurity.json');
      const output = await convertNiktoToHdf(input);
      const hdf = parseJSON<HdfResults>(output);

      expect(hdf.baselines[0].requirements).toHaveLength(14);
    });

    it('should set requirement title from vulnerability msg', async () => {
      const input = loadFixture('zero.webappsecurity.json');
      const output = await convertNiktoToHdf(input);
      const hdf = parseJSON<HdfResults>(output);

      const req = hdf.baselines[0].requirements.find(r => r.id === '999986');
      expect(req?.title).toBe('Retrieved access-control-allow-origin header: *');
    });
  });
});
