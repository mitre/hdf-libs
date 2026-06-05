import {readFileSync} from 'fs';
import {dirname, join} from 'path';
import {fileURLToPath} from 'url';
import {describe, expect, it} from 'vitest';
import {convertGitlabToHdf} from './converter';
import {runConverterContractTests} from '../../../shared/typescript/converter-contract.js';
import {parseJSON} from '@mitre/hdf-utilities';
import type {HDFResults} from '@mitre/hdf-schema';

const __dirname = dirname(fileURLToPath(import.meta.url));
const FIXTURES_DIR = join(__dirname, '..', 'fixtures');

function loadFixture(name: string): string {
  return readFileSync(join(FIXTURES_DIR, 'input', name), 'utf-8');
}

runConverterContractTests({
  converterName: 'gitlab-to-hdf',
  convertFn: convertGitlabToHdf,
  minimalFixture: 'minimal-dast.json',
});

describe('GitLab to HDF converter', () => {
  describe('validation', () => {
    it('should synthesize a passed placeholder when vulnerabilities array is missing', async () => {
      const input = JSON.stringify({version: '15.1.0', scan: {type: 'sast', scanner: {name: 'Semgrep'}}});
      const output = await convertGitlabToHdf(input);
      const hdf = parseJSON<HDFResults>(output);
      expect(hdf.baselines).toHaveLength(1);
      expect(hdf.baselines[0].requirements).toHaveLength(1);
      const req = hdf.baselines[0].requirements[0];
      expect(req.id).toBe('gitlab-no-findings');
      expect(req.results[0].status).toBe('passed');
      expect(req.results[0].codeDesc).toContain('GitLab');
      expect(req.results[0].codeDesc).toContain('Semgrep');
      expect(req.results[0].codeDesc).toContain('zero findings');
    });

    it('should synthesize a passed placeholder when vulnerabilities array is empty', async () => {
      const input = loadFixture('empty.json');
      const output = await convertGitlabToHdf(input);
      const hdf = parseJSON<HDFResults>(output);
      expect(hdf.baselines).toHaveLength(1);
      expect(hdf.baselines[0].requirements).toHaveLength(1);
      const req = hdf.baselines[0].requirements[0];
      expect(req.id).toBe('gitlab-no-findings');
      expect(req.results[0].status).toBe('passed');
      expect(req.results[0].codeDesc).toContain('GitLab');
      expect(req.results[0].codeDesc).toContain('Semgrep');
      expect(req.results[0].codeDesc).toContain('zero findings');
    });
  });

  describe('minimal SAST fixture', () => {
    it('should create 1 baseline with 1 requirement', async () => {
      const input = loadFixture('minimal-sast.json');
      const output = await convertGitlabToHdf(input);
      const hdf = parseJSON<HDFResults>(output);

      expect(hdf.baselines).toHaveLength(1);
      expect(hdf.baselines[0].requirements).toHaveLength(1);
    });

    it('should set baseline name to "GitLab Security Scan"', async () => {
      const input = loadFixture('minimal-sast.json');
      const output = await convertGitlabToHdf(input);
      const hdf = parseJSON<HDFResults>(output);

      expect(hdf.baselines[0].name).toBe('GitLab Security Scan');
    });

    it('should set baseline title with scan type', async () => {
      const input = loadFixture('minimal-sast.json');
      const output = await convertGitlabToHdf(input);
      const hdf = parseJSON<HDFResults>(output);

      expect(hdf.baselines[0].title).toBe('GitLab SAST Security Scan');
    });

    it('should set baseline summary with scanner info', async () => {
      const input = loadFixture('minimal-sast.json');
      const output = await convertGitlabToHdf(input);
      const hdf = parseJSON<HDFResults>(output);

      expect(hdf.baselines[0].summary).toBe('Scanner: Semgrep v1.34.0');
    });

    it('should use vulnerability ID as requirement ID', async () => {
      const input = loadFixture('minimal-sast.json');
      const output = await convertGitlabToHdf(input);
      const hdf = parseJSON<HDFResults>(output);

      expect(hdf.baselines[0].requirements[0].id).toBe('a1b2c3d4-e5f6-7890-abcd-ef1234567890');
    });

    it('should set requirement title from vulnerability name', async () => {
      const input = loadFixture('minimal-sast.json');
      const output = await convertGitlabToHdf(input);
      const hdf = parseJSON<HDFResults>(output);

      expect(hdf.baselines[0].requirements[0].title).toBe('SQL Injection');
    });

    it('should map Critical severity to impact 0.9', async () => {
      const input = loadFixture('minimal-sast.json');
      const output = await convertGitlabToHdf(input);
      const hdf = parseJSON<HDFResults>(output);

      expect(hdf.baselines[0].requirements[0].impact).toBe(0.9);
    });

    it('should set all results to failed', async () => {
      const input = loadFixture('minimal-sast.json');
      const output = await convertGitlabToHdf(input);
      const hdf = parseJSON<HDFResults>(output);

      expect(hdf.baselines[0].requirements[0].results[0].status).toBe('failed');
    });

    it('should format SAST codeDesc with file, line, class, method', async () => {
      const input = loadFixture('minimal-sast.json');
      const output = await convertGitlabToHdf(input);
      const hdf = parseJSON<HDFResults>(output);

      expect(hdf.baselines[0].requirements[0].results[0].codeDesc).toBe(
        'File: src/db/queries.py | Line: 42 | Class: UserRepository | Method: find_by_name',
      );
    });

    it('should set description from vulnerability description', async () => {
      const input = loadFixture('minimal-sast.json');
      const output = await convertGitlabToHdf(input);
      const hdf = parseJSON<HDFResults>(output);

      const defaultDesc = hdf.baselines[0].requirements[0].descriptions?.find(d => d.label === 'default');
      expect(defaultDesc?.data).toContain('SQL query without sanitization');
    });

    it('should set check description from solution', async () => {
      const input = loadFixture('minimal-sast.json');
      const output = await convertGitlabToHdf(input);
      const hdf = parseJSON<HDFResults>(output);

      const checkDesc = hdf.baselines[0].requirements[0].descriptions?.find(d => d.label === 'check');
      expect(checkDesc?.data).toContain('parameterized queries');
    });

    it('should set startTime from scan.start_time', async () => {
      const input = loadFixture('minimal-sast.json');
      const output = await convertGitlabToHdf(input);
      const hdf = parseJSON<HDFResults>(output);

      expect(hdf.baselines[0].requirements[0].results[0].startTime).toBeDefined();
    });
  });

  describe('NIST mapping', () => {
    it('should map CWE-89 to a NIST control', async () => {
      const input = loadFixture('minimal-sast.json');
      const output = await convertGitlabToHdf(input);
      const hdf = parseJSON<HDFResults>(output);

      const tags = hdf.baselines[0].requirements[0].tags;
      expect(tags?.nist).toBeDefined();
      expect(Array.isArray(tags?.nist)).toBe(true);
      expect((tags?.nist as string[]).length).toBeGreaterThan(0);
    });

    it('should include CWE identifier in tags', async () => {
      const input = loadFixture('minimal-sast.json');
      const output = await convertGitlabToHdf(input);
      const hdf = parseJSON<HDFResults>(output);

      const tags = hdf.baselines[0].requirements[0].tags;
      expect(tags?.cwe).toEqual(['89']);
    });

    it('should populate CCI tags from NIST mapping', async () => {
      const input = loadFixture('minimal-sast.json');
      const output = await convertGitlabToHdf(input);
      const hdf = parseJSON<HDFResults>(output);

      const tags = hdf.baselines[0].requirements[0].tags;
      expect(tags?.cci).toBeDefined();
      expect((tags?.cci as string[]).length).toBeGreaterThan(0);
    });
  });

  describe('checksum', () => {
    it('should calculate SHA-256 checksum of input', async () => {
      const input = loadFixture('minimal-sast.json');
      const output = await convertGitlabToHdf(input);
      const hdf = parseJSON<HDFResults>(output);

      expect(hdf.baselines[0].resultsChecksum).toBeDefined();
      expect(hdf.baselines[0].resultsChecksum?.algorithm).toBe('sha256');
      expect(hdf.baselines[0].resultsChecksum?.value).toMatch(/^[a-f0-9]{64}$/);
    });
  });

  describe('generator and dataSource', () => {
    it('should set generator name to "gitlab-to-hdf"', async () => {
      const input = loadFixture('minimal-sast.json');
      const output = await convertGitlabToHdf(input);
      const hdf = parseJSON<HDFResults>(output);

      expect(hdf.generator.name).toBe('gitlab-to-hdf');
    });

    it('should set dataSource name from scanner', async () => {
      const input = loadFixture('minimal-sast.json');
      const output = await convertGitlabToHdf(input);
      const hdf = parseJSON<HDFResults>(output);

      expect(hdf.tool?.name).toBe('Semgrep');
      expect(hdf.tool?.format).toBe('JSON');
      expect(hdf.tool?.version).toBe('1.34.0');
    });
  });

  describe('timestamp', () => {
    it('should set timestamp from scan.end_time', async () => {
      const input = loadFixture('minimal-sast.json');
      const output = await convertGitlabToHdf(input);
      const hdf = parseJSON<HDFResults>(output);

      expect(hdf.timestamp).toBeDefined();
    });
  });

  describe('targets', () => {
    it('should set target type to repository for SAST', async () => {
      const input = loadFixture('minimal-sast.json');
      const output = await convertGitlabToHdf(input);
      const hdf = parseJSON<HDFResults>(output);

      expect(hdf.components).toHaveLength(1);
      expect(hdf.components![0].type).toBe('repository');
    });

    it('should set target type to application for DAST', async () => {
      const input = loadFixture('minimal-dast.json');
      const output = await convertGitlabToHdf(input);
      const hdf = parseJSON<HDFResults>(output);

      expect(hdf.components).toHaveLength(1);
      expect(hdf.components![0].type).toBe('application');
    });
  });

  describe('minimal DAST fixture', () => {
    it('should create 1 requirement from DAST report', async () => {
      const input = loadFixture('minimal-dast.json');
      const output = await convertGitlabToHdf(input);
      const hdf = parseJSON<HDFResults>(output);

      expect(hdf.baselines).toHaveLength(1);
      expect(hdf.baselines[0].requirements).toHaveLength(1);
    });

    it('should set baseline title with DAST type', async () => {
      const input = loadFixture('minimal-dast.json');
      const output = await convertGitlabToHdf(input);
      const hdf = parseJSON<HDFResults>(output);

      expect(hdf.baselines[0].title).toBe('GitLab DAST Security Scan');
    });

    it('should format DAST codeDesc with URL, method, param', async () => {
      const input = loadFixture('minimal-dast.json');
      const output = await convertGitlabToHdf(input);
      const hdf = parseJSON<HDFResults>(output);

      expect(hdf.baselines[0].requirements[0].results[0].codeDesc).toBe(
        'URL: https://app.example.com/search | Method: GET | Param: q',
      );
    });

    it('should map High severity to impact 0.7', async () => {
      const input = loadFixture('minimal-dast.json');
      const output = await convertGitlabToHdf(input);
      const hdf = parseJSON<HDFResults>(output);

      expect(hdf.baselines[0].requirements[0].impact).toBe(0.7);
    });
  });

  describe('multi-vuln fixture', () => {
    it('should create 3 requirements from 3 vulnerabilities', async () => {
      const input = loadFixture('multi-vuln.json');
      const output = await convertGitlabToHdf(input);
      const hdf = parseJSON<HDFResults>(output);

      expect(hdf.baselines[0].requirements).toHaveLength(3);
    });

    it('should map Critical severity to 0.9', async () => {
      const input = loadFixture('multi-vuln.json');
      const output = await convertGitlabToHdf(input);
      const hdf = parseJSON<HDFResults>(output);

      const req = hdf.baselines[0].requirements.find(r => r.id === '11111111-1111-1111-1111-111111111111');
      expect(req?.impact).toBe(0.9);
    });

    it('should map Medium severity to 0.5', async () => {
      const input = loadFixture('multi-vuln.json');
      const output = await convertGitlabToHdf(input);
      const hdf = parseJSON<HDFResults>(output);

      const req = hdf.baselines[0].requirements.find(r => r.id === '22222222-2222-2222-2222-222222222222');
      expect(req?.impact).toBe(0.5);
    });

    it('should map Info severity to 0.0', async () => {
      const input = loadFixture('multi-vuln.json');
      const output = await convertGitlabToHdf(input);
      const hdf = parseJSON<HDFResults>(output);

      const req = hdf.baselines[0].requirements.find(r => r.id === '33333333-3333-3333-3333-333333333333');
      expect(req?.impact).toBe(0.0);
    });

    it('should collect both CWE and CVE identifiers in tags', async () => {
      const input = loadFixture('multi-vuln.json');
      const output = await convertGitlabToHdf(input);
      const hdf = parseJSON<HDFResults>(output);

      const req = hdf.baselines[0].requirements.find(r => r.id === '11111111-1111-1111-1111-111111111111');
      expect(req?.tags?.cwe).toEqual(['78']);
      expect(req?.tags?.cve).toEqual(['CVE-2024-1234']);
    });

    it('should use default NIST tags when no CWE identifiers present', async () => {
      const input = loadFixture('multi-vuln.json');
      const output = await convertGitlabToHdf(input);
      const hdf = parseJSON<HDFResults>(output);

      const req = hdf.baselines[0].requirements.find(r => r.id === '33333333-3333-3333-3333-333333333333');
      expect(req?.tags?.nist).toEqual(['SA-11', 'RA-5']);
    });

    it('should format codeDesc without class/method when absent', async () => {
      const input = loadFixture('multi-vuln.json');
      const output = await convertGitlabToHdf(input);
      const hdf = parseJSON<HDFResults>(output);

      const req = hdf.baselines[0].requirements.find(r => r.id === '11111111-1111-1111-1111-111111111111');
      expect(req?.results[0].codeDesc).toBe('File: src/utils/exec.py | Line: 15-18');
    });

    it('should format codeDesc with class and method when present', async () => {
      const input = loadFixture('multi-vuln.json');
      const output = await convertGitlabToHdf(input);
      const hdf = parseJSON<HDFResults>(output);

      const req = hdf.baselines[0].requirements.find(r => r.id === '22222222-2222-2222-2222-222222222222');
      expect(req?.results[0].codeDesc).toBe(
        'File: src/api/handler.py | Line: 100-105 | Class: RequestHandler | Method: process',
      );
    });
  });

  describe('edge cases: scan types and missing fields', () => {
    it('should handle dast scan type', async () => {
      const input = JSON.stringify({
        scan: { type: 'dast', scanner: { name: 'ZAP' } },
        vulnerabilities: [{
          id: 'v1', severity: 'High',
          location: { hostname: 'https://example.com', path: '/api', method: 'POST', param: 'q' },
        }],
      });
      const hdf = parseJSON<HDFResults>(await convertGitlabToHdf(input));
      expect(hdf.components[0].type).toBe('application');
      expect(hdf.baselines[0].requirements[0].results[0].codeDesc).toContain('URL:');
      expect(hdf.baselines[0].requirements[0].results[0].codeDesc).toContain('Param:');
    });

    it('should handle container_scanning scan type', async () => {
      const input = JSON.stringify({
        scan: { type: 'container_scanning', scanner: { name: 'Trivy', version: '0.1' }, end_time: '2025-01-01T00:00:00Z' },
        vulnerabilities: [{
          id: 'v1', severity: 'Medium',
          location: { image: 'nginx:latest', dependency: { package: { name: 'libssl' }, version: '1.0' } },
        }],
      });
      const hdf = parseJSON<HDFResults>(await convertGitlabToHdf(input));
      expect(hdf.components[0].type).toBe('containerImage');
      expect(hdf.baselines[0].requirements[0].results[0].codeDesc).toContain('Image: nginx');
      expect(hdf.baselines[0].requirements[0].results[0].codeDesc).toContain('libssl@1.0');
      expect(hdf.tool.version).toBe('0.1');
    });

    it('should handle dependency_scanning scan type', async () => {
      const input = JSON.stringify({
        scan: { type: 'dependency_scanning', scanner: { name: 'Dep' } },
        vulnerabilities: [{
          id: 'v1', severity: 'Low',
          location: { file: 'package.json', dependency: { package: { name: 'lodash' } } },
        }],
      });
      const hdf = parseJSON<HDFResults>(await convertGitlabToHdf(input));
      expect(hdf.baselines[0].requirements[0].results[0].codeDesc).toContain('Package: lodash');
    });

    it('should handle secret_detection scan type with same line start/end', async () => {
      const input = JSON.stringify({
        scan: { type: 'secret_detection', scanner: { name: 'GitLeaks' } },
        vulnerabilities: [{
          id: 'v1', severity: 'Critical',
          location: { file: 'config.yaml', start_line: 10, end_line: 10 },
        }],
      });
      const hdf = parseJSON<HDFResults>(await convertGitlabToHdf(input));
      expect(hdf.baselines[0].requirements[0].results[0].codeDesc).toContain('Line: 10');
    });

    it('should handle unknown scan type', async () => {
      const input = JSON.stringify({
        scan: { type: 'api_fuzzing', scanner: { name: 'Fuzzer' } },
        vulnerabilities: [{
          id: 'v1', severity: 'Info',
          location: { file: 'test.txt' },
        }],
      });
      const hdf = parseJSON<HDFResults>(await convertGitlabToHdf(input));
      expect(hdf.baselines[0].title).toContain('API Fuzzing');
    });

    it('should handle vulnerability with no location', async () => {
      const input = JSON.stringify({
        scan: { type: 'sast', scanner: { name: 'Scan' } },
        vulnerabilities: [{
          id: 'v1', severity: 'Medium', description: 'desc', solution: 'fix',
        }],
      });
      const hdf = parseJSON<HDFResults>(await convertGitlabToHdf(input));
      expect(hdf.baselines[0].requirements[0].results[0].codeDesc).toBe('');
    });

    it('should handle vulnerability with no description or solution', async () => {
      const input = JSON.stringify({
        scan: { type: 'sast', scanner: { name: 'Scan' } },
        vulnerabilities: [{ id: 'v1', name: 'Named Vuln' }],
      });
      const hdf = parseJSON<HDFResults>(await convertGitlabToHdf(input));
      const req = hdf.baselines[0].requirements[0];
      expect(req.title).toBe('Named Vuln');
      expect(req.descriptions.length).toBe(0);
    });

    it('should handle no scan field at all', async () => {
      const input = JSON.stringify({
        vulnerabilities: [{ id: 'v1' }],
      });
      const hdf = parseJSON<HDFResults>(await convertGitlabToHdf(input));
      expect(hdf.baselines[0].title).toContain('SAST');
    });

    it('should handle DAST with hostname but no path', async () => {
      const input = JSON.stringify({
        scan: { type: 'dast', scanner: { name: 'ZAP' } },
        vulnerabilities: [{
          id: 'v1',
          location: { hostname: 'https://example.com' },
        }],
      });
      const hdf = parseJSON<HDFResults>(await convertGitlabToHdf(input));
      expect(hdf.baselines[0].requirements[0].results[0].codeDesc).toContain('URL: https://example.com');
    });
  });
});
