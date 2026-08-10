import {readFileSync} from 'fs';
import {dirname, join} from 'path';
import {fileURLToPath} from 'url';
import {describe, expect, it} from 'vitest';
import {convertGitlabToHdf} from './converter';
import {runConverterContractTests} from '../../../shared/typescript/converter-contract.js';
import {expectValidResults} from '../../../test/helpers/expectValidHdf.js';
import {
  assertRequirementCount,
  countJsonItemsUnderKey,
} from '../../../shared/typescript/anchor.js';
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

// Ground-truth anchor (input-derived count; see shared/typescript/anchor.ts):
// one requirement per top-level vulnerabilities[] entry, counted independently
// of the converter's parser so a silent under-extraction fails even when Go/TS
// agree.
describe('gitlab-to-hdf ground-truth anchor', () => {
  it('emits one requirement per vulnerabilities[]', async () => {
    const input = loadFixture('multi-vuln.json');
    assertRequirementCount(
      await convertGitlabToHdf(input),
      countJsonItemsUnderKey(input, 'vulnerabilities'),
      'multi-vuln.json: one requirement per vulnerabilities[]',
    );
  });
});

describe('timestamp parse fallback', () => {
  it('uses conversion time when the scan timestamp is unparseable', async () => {
    const input = loadFixture('empty.json').replace(/2024-01-15T10:00:00/g, 'not-a-date');
    const hdf = JSON.parse(await convertGitlabToHdf(input)) as HDFResults;
    expectValidResults(hdf);
  });
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
      expectValidResults(hdf);

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
      expect(hdf.tool?.format).toBeUndefined() // serialization structures are not formats (kpvj);
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

  // GitLab carries no literal source snippet, so requirement.code holds the whole
  // vulnerability object serialized as indented JSON — byte-identical to the Go
  // twin's json.Indent output. Pin that it is set on every requirement and
  // round-trips to the source vulnerability object across all scan-type fixtures.
  describe('requirement.code (Heimdall CODE tab)', () => {
    for (const name of ['minimal-dast.json', 'minimal-sast.json', 'multi-vuln.json']) {
      it(`round-trips the source vulnerability object for ${name}`, async () => {
        const input = loadFixture(name);
        const source = parseJSON<{vulnerabilities: unknown[]}>(input);
        const hdf = parseJSON<HDFResults>(await convertGitlabToHdf(input));
        const reqs = hdf.baselines[0].requirements;
        expect(reqs.length).toBe(source.vulnerabilities.length);
        reqs.forEach((req, i) => {
          expect(req.code, `requirement ${i}: code unset; CODE tab empty`).toBeDefined();
          expect(req.code).toContain('\n');
          expect(JSON.parse(req.code as string)).toEqual(source.vulnerabilities[i]);
        });
      });
    }
  });
});

describe('gitlab-to-hdf structured sourceLocation', () => {
  function reqById(hdf: HDFResults, id: string) {
    const req = hdf.baselines[0].requirements.find((r) => r.id === id);
    if (!req) throw new Error(`requirement ${id} not found`);
    return req;
  }

  it('promotes location.file + start_line into sourceLocation for a SAST finding', async () => {
    const input = loadFixture('minimal-sast.json');
    const hdf = parseJSON<HDFResults>(await convertGitlabToHdf(input));
    const req = reqById(hdf, 'a1b2c3d4-e5f6-7890-abcd-ef1234567890');
    expect(req.sourceLocation).toEqual({ref: 'src/db/queries.py', line: 42});
  });

  it('omits sourceLocation for a DAST finding with no location.file', async () => {
    const input = loadFixture('minimal-dast.json');
    const hdf = parseJSON<HDFResults>(await convertGitlabToHdf(input));
    const req = hdf.baselines[0].requirements[0];
    expect(req.sourceLocation).toBeUndefined();
  });

  it('falls back to end_line when start_line is absent', async () => {
    const input = JSON.stringify({
      scan: {type: 'sast', scanner: {name: 'Scan'}},
      vulnerabilities: [{id: 'v1', severity: 'High', location: {file: 'b.py', end_line: 12}}],
    });
    const hdf = parseJSON<HDFResults>(await convertGitlabToHdf(input));
    expect(hdf.baselines[0].requirements[0].sourceLocation).toEqual({ref: 'b.py', line: 12});
  });

  it('emits ref only when the location carries a file but no line', async () => {
    const input = JSON.stringify({
      scan: {type: 'sast', scanner: {name: 'Scan'}},
      vulnerabilities: [{id: 'v1', severity: 'High', location: {file: 'c.py'}}],
    });
    const hdf = parseJSON<HDFResults>(await convertGitlabToHdf(input));
    expect(hdf.baselines[0].requirements[0].sourceLocation).toEqual({ref: 'c.py'});
  });
});

describe('gitlab-to-hdf refs and remediation backfill', () => {
  function reqById(hdf: HDFResults, id: string) {
    const req = hdf.baselines[0].requirements.find((r) => r.id === id);
    if (!req) throw new Error(`requirement ${id} not found`);
    return req;
  }

  it('maps links[].url and identifiers[].url into refs[]', async () => {
    const input = loadFixture('minimal-sast.json');
    const hdf = parseJSON<HDFResults>(await convertGitlabToHdf(input));
    const req = reqById(hdf, 'a1b2c3d4-e5f6-7890-abcd-ef1234567890');
    expect(req.refs).toEqual([
      {url: 'https://owasp.org/www-community/attacks/SQL_Injection'},
      {url: 'https://cwe.mitre.org/data/definitions/89.html'},
    ]);
  });

  it('omits refs[] when the vuln carries no links or identifier URLs', async () => {
    const input = loadFixture('multi-vuln.json');
    const hdf = parseJSON<HDFResults>(await convertGitlabToHdf(input));
    const req = reqById(hdf, '33333333-3333-3333-3333-333333333333');
    expect(req.refs).toBeUndefined();
  });

  it('de-duplicates a URL shared by links[] and identifiers[]', async () => {
    const input = JSON.stringify({
      scan: {type: 'sast', scanner: {name: 'Semgrep'}},
      vulnerabilities: [
        {
          id: 'dup-1',
          name: 'Dup',
          severity: 'High',
          links: [{url: 'https://example.com/shared'}],
          identifiers: [
            {type: 'cwe', name: 'CWE-79', value: '79', url: 'https://example.com/shared'},
            {type: 'cve', name: 'CVE-2024-9', value: 'CVE-2024-9', url: 'https://example.com/other'},
          ],
        },
      ],
    });
    const hdf = parseJSON<HDFResults>(await convertGitlabToHdf(input));
    const req = reqById(hdf, 'dup-1');
    expect(req.refs).toEqual([
      {url: 'https://example.com/shared'},
      {url: 'https://example.com/other'},
    ]);
  });

  it('attaches a matching remediation summary as a "remediation" description', async () => {
    const input = loadFixture('multi-vuln.json');
    const hdf = parseJSON<HDFResults>(await convertGitlabToHdf(input));

    const fixed = reqById(hdf, '11111111-1111-1111-1111-111111111111');
    expect(fixed.descriptions).toContainEqual({
      label: 'remediation',
      data: 'Upgrade exec library to version 2.0',
    });

    const unfixed = reqById(hdf, '22222222-2222-2222-2222-222222222222');
    expect(unfixed.descriptions?.some((d) => d.label === 'remediation')).toBe(false);
  });
});
