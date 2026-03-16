/**
 * Edge-case tests for converter branch coverage.
 * Tests missing optional fields, fallback branches, and status mappings.
 */
import { describe, it, expect } from 'vitest';
import type { HdfResults } from '@mitre/hdf-schema';

import { convertSnykToHdf } from '../converters/snyk-to-hdf/typescript/converter.js';
import { convertGrypeToHdf } from '../converters/grype-to-hdf/typescript/converter.js';
import { convertScoutsuiteToHdf } from '../converters/scoutsuite-to-hdf/typescript/converter.js';
import { convertNiktoToHdf } from '../converters/nikto-to-hdf/typescript/converter.js';
import { convertNeuvectorToHdf } from '../converters/neuvector-to-hdf/typescript/converter.js';
import { convertMsftSecureScoreToHdf } from '../converters/msft-secure-score-to-hdf/typescript/converter.js';
import { convertJfrogXrayToHdf } from '../converters/jfrog-xray-to-hdf/typescript/converter.js';
import { convertPrismaToHdf } from '../converters/prisma-to-hdf/typescript/converter.js';
import { convertCyclonedxToHdf } from '../converters/cyclonedx-to-hdf/typescript/converter.js';
import { convertTrufflehogToHdf } from '../converters/trufflehog-to-hdf/typescript/converter.js';

function parseHdf(json: string): HdfResults {
  return JSON.parse(json) as HdfResults;
}

// --- Snyk edge cases ---
describe('Snyk edge cases', () => {
  it('should handle vulnerability with no from path', async () => {
    const input = JSON.stringify({
      projectName: 'test',
      vulnerabilities: [{
        id: 'npm:test:1', title: 'Test', severity: 'high', description: 'desc',
        from: [],
        identifiers: { CWE: [], CVE: ['CVE-2021-1234'], GHSA: ['GHSA-xxxx'] },
      }],
    });
    const hdf = parseHdf(await convertSnykToHdf(input));
    expect(hdf.baselines[0]!.requirements[0]!.results[0]!.codeDesc).toContain('Unknown');
    expect(hdf.baselines[0]!.requirements[0]!.tags?.cveid).toBeDefined();
    expect(hdf.baselines[0]!.requirements[0]!.tags?.ghsaid).toBeDefined();
  });

  it('should handle multi-project array input', async () => {
    const input = JSON.stringify([
      {
        projectName: 'proj1', path: '/path1',
        vulnerabilities: [{ id: 'v1', title: 'V1', severity: 'low', description: 'd', from: ['a'], identifiers: { CWE: ['CWE-79'] } }],
      },
    ]);
    const hdf = parseHdf(await convertSnykToHdf(input));
    expect(hdf.baselines).toHaveLength(1);
  });

  it('should handle vulnerability with no identifiers', async () => {
    const input = JSON.stringify({
      vulnerabilities: [{ id: 'v1', title: 'V1', severity: 'medium', description: 'd', from: ['a'], identifiers: {} }],
    });
    const hdf = parseHdf(await convertSnykToHdf(input));
    expect(hdf.baselines[0]!.requirements[0]!.tags?.cweid).toBeUndefined();
    expect(hdf.baselines[0]!.requirements[0]!.tags?.cveid).toBeUndefined();
  });
});

// --- Grype edge cases ---
describe('Grype edge cases', () => {
  it('should handle match with no vulnerability details', async () => {
    const input = JSON.stringify({
      matches: [{
        vulnerability: { id: 'CVE-2021-1', severity: 'Unknown', dataSource: 'ds' },
        artifact: { name: 'pkg', version: '1.0', type: 'deb' },
        relatedVulnerabilities: [],
      }],
      source: { type: 'image', target: { userInput: 'test:latest' } },
      descriptor: { name: 'grype', version: '0.1' },
    });
    const hdf = parseHdf(await convertGrypeToHdf(input));
    expect(hdf.baselines[0]!.requirements).toHaveLength(1);
  });

  it('should handle match with relatedVulnerabilities having CWEs', async () => {
    const input = JSON.stringify({
      matches: [{
        vulnerability: { id: 'CVE-2021-2', severity: 'Critical', dataSource: 'ds', description: 'desc', fix: { versions: ['2.0'] } },
        artifact: { name: 'pkg', version: '1.0', type: 'npm', locations: [{ path: '/app' }] },
        relatedVulnerabilities: [{
          id: 'CVE-2021-2', severity: 'Critical', urls: ['https://example.com'],
          cvss: [{ metrics: { baseScore: 9.8 }, version: '3.1' }],
        }],
        matchDetails: [{ searchedBy: { namespace: 'nvd' } }],
      }],
      source: { type: 'directory', target: '/path' },
      descriptor: { name: 'grype', version: '0.1' },
    });
    const hdf = parseHdf(await convertGrypeToHdf(input));
    expect(hdf.baselines[0]!.requirements[0]!.impact).toBe(0.9);
  });
});

// --- ScoutSuite edge cases ---
describe('ScoutSuite edge cases', () => {
  it('should handle minimal ScoutSuite input', async () => {
    // ScoutSuite uses JavaScript file format: "scoutsuite_results = {...}"
    const data = {
      last_run: { ruleset_name: 'default', provider: 'aws', result_format: '2.0' },
      services: {
        s3: {
          findings: {
            's3-bucket-no-encryption': {
              flagged_items: 1, items: ['s3.buckets.bucket1'],
              description: 'No encryption', service: 's3',
              rationale: 'Encrypt data', remediation: 'Enable SSE',
              references: ['https://aws.amazon.com'],
              dashboard_name: 'S3 Buckets', path: 's3.buckets',
              level: 'warning', id_suffix: 'no-encryption',
              checked_items: 5, compliance: [],
            },
          },
        },
      },
      account_id: '123456',
    };
    const input = `scoutsuite_results = ${JSON.stringify(data)}`;
    const hdf = parseHdf(await convertScoutsuiteToHdf(input));
    expect(hdf.baselines).toHaveLength(1);
    expect(hdf.baselines[0]!.requirements.length).toBeGreaterThan(0);
  });
});

// --- Nikto edge cases ---
describe('Nikto edge cases', () => {
  it('should handle result with no OSVDB ID', async () => {
    const input = JSON.stringify({
      host: 'localhost', ip: '127.0.0.1', port: '80', banner: 'nginx',
      vulnerabilities: [{
        id: '0', method: 'GET', url: '/',
        msg: 'Server leaks info', references: '',
      }],
    });
    const hdf = parseHdf(await convertNiktoToHdf(input));
    expect(hdf.baselines[0]!.requirements).toHaveLength(1);
  });

  it('should handle empty vulnerabilities array', async () => {
    const input = JSON.stringify({
      host: 'localhost', ip: '127.0.0.1', port: '80', banner: 'nginx',
      vulnerabilities: [],
    });
    const hdf = parseHdf(await convertNiktoToHdf(input));
    expect(hdf.baselines[0]!.requirements).toHaveLength(0);
  });
});

// --- NeuVector edge cases ---
describe('NeuVector edge cases', () => {
  it('should handle vulnerability with no feed_rating and no score', async () => {
    const input = JSON.stringify({
      report: {
        vulnerabilities: [{
          name: 'CVE-2021-1', severity: 'High',
          package_name: 'pkg', package_version: '1.0',
          description: 'desc', link: 'https://example.com',
          published_timestamp: 1609459200,
          last_modified_timestamp: 1609459200,
        }],
      },
    });
    const hdf = parseHdf(await convertNeuvectorToHdf(input));
    expect(hdf.baselines[0]!.requirements).toHaveLength(1);
  });
});

// --- Microsoft Secure Score edge cases ---
describe('MSFT Secure Score edge cases', () => {
  it('should handle control with no remediation or implementationStatus', async () => {
    const input = JSON.stringify({
      secureScore: {
        value: [{
          id: 'ss-1',
          azureTenantId: 'tenant-1',
          createdDateTime: '2025-01-01T00:00:00Z',
          controlScores: [{
            controlName: 'test-control',
            controlCategory: 'Identity',
            description: 'Test description',
            score: 5.0,
            maxScore: 10.0,
            scoreInPercentage: 50,
            implementationStatus: '',
            actionUrl: '',
            count: 1,
          }],
        }],
      },
      profiles: {
        value: [{
          id: 'test-control',
          controlCategory: 'Identity',
          title: 'Test Control',
        }],
      },
    });
    const hdf = parseHdf(await convertMsftSecureScoreToHdf(input));
    expect(hdf.baselines[0]!.requirements).toHaveLength(1);
  });

  it('should handle control with full implementationStatus', async () => {
    const input = JSON.stringify({
      secureScore: {
        value: [{
          id: 'ss-2',
          azureTenantId: 'tenant-2',
          createdDateTime: '2025-01-01T00:00:00Z',
          controlScores: [{
            controlName: 'full-control',
            controlCategory: 'Data',
            description: 'Full desc',
            score: 10.0,
            maxScore: 10.0,
            scoreInPercentage: 100,
            implementationStatus: 'Implemented',
            actionUrl: 'https://example.com',
            count: 5,
            userImpact: 'Low',
            threats: ['MaliciousInsider'],
            deprecationReason: '',
          }],
        }],
      },
      profiles: {
        value: [{
          id: 'full-control',
          controlCategory: 'Data',
          title: 'Full Control',
          remediation: 'Do the thing',
          remediationImpact: 'Low impact',
        }],
      },
    });
    const hdf = parseHdf(await convertMsftSecureScoreToHdf(input));
    expect(hdf.baselines[0]!.requirements[0]!.results[0]!.status).toBe('passed');
  });
});

// --- JFrog Xray edge cases ---
describe('JFrog Xray edge cases', () => {
  it('should handle vulnerability with no fixed_versions', async () => {
    const input = JSON.stringify({
      data: [{
        id: 'XRAY-1',
        severity: 'High',
        summary: 'Test vuln',
        description: 'Desc',
        component_id: 'npm://pkg:1.0',
        cves: [{ cve: 'CVE-2021-1', cvss_v3: '9.0' }],
      }],
    });
    const hdf = parseHdf(await convertJfrogXrayToHdf(input));
    expect(hdf.baselines[0]!.requirements).toHaveLength(1);
  });
});

// --- Prisma edge cases ---
describe('Prisma edge cases', () => {
  it('should handle minimal CSV with required fields only', async () => {
    const csv = `Hostname,Compliance ID,Severity,Type,Description,Status
host-1,P-1,low,Test Policy,Test desc,pass
host-1,P-2,high,Fail Policy,Fail desc,fail
host-2,P-3,medium,Other Policy,Other desc,fail`;
    const hdf = parseHdf(await convertPrismaToHdf(csv));
    expect(hdf.baselines[0]!.requirements.length).toBeGreaterThan(0);
  });
});

// --- CycloneDX edge cases ---
describe('CycloneDX edge cases', () => {
  it('should handle vulnerability with no ratings', async () => {
    const input = JSON.stringify({
      bomFormat: 'CycloneDX',
      specVersion: '1.4',
      vulnerabilities: [{
        id: 'CVE-2021-1',
        description: 'Test vuln',
        source: { name: 'NVD', url: 'https://nvd.nist.gov' },
        affects: [{ ref: 'pkg:npm/test@1.0' }],
      }],
      components: [{ type: 'library', name: 'test', version: '1.0', 'bom-ref': 'pkg:npm/test@1.0' }],
    });
    const hdf = parseHdf(await convertCyclonedxToHdf(input));
    expect(hdf.baselines[0]!.requirements).toHaveLength(1);
  });

  it('should handle vulnerability with CVSS ratings', async () => {
    const input = JSON.stringify({
      bomFormat: 'CycloneDX',
      specVersion: '1.4',
      vulnerabilities: [{
        id: 'CVE-2021-2',
        description: 'Test',
        ratings: [{ score: 9.8, severity: 'critical', method: 'CVSSv31' }],
        cwes: [79],
        advisories: [{ url: 'https://example.com' }],
        recommendation: 'Upgrade to v2',
        source: { name: 'NVD' },
        affects: [{ ref: 'ref1' }],
        analysis: { state: 'exploitable' },
      }],
      components: [{ type: 'library', name: 'lib', version: '1.0', 'bom-ref': 'ref1' }],
    });
    const hdf = parseHdf(await convertCyclonedxToHdf(input));
    expect(hdf.baselines[0]!.requirements[0]!.impact).toBeCloseTo(0.98, 2);
  });

  it('should handle VEX document with analysis state', async () => {
    const input = JSON.stringify({
      bomFormat: 'CycloneDX',
      specVersion: '1.4',
      vulnerabilities: [{
        id: 'CVE-2021-3',
        description: 'Not affected',
        ratings: [{ severity: 'high' }],
        source: { name: 'test' },
        analysis: { state: 'not_affected' },
        affects: [],
      }],
    });
    const hdf = parseHdf(await convertCyclonedxToHdf(input));
    expect(hdf.baselines[0]!.requirements).toHaveLength(1);
  });
});

// --- Trufflehog edge cases ---
describe('Trufflehog edge cases', () => {
  it('should handle finding with no SourceMetadata', async () => {
    const input = JSON.stringify([{
      DetectorType: 1, DetectorName: 'AWS',
      DecoderName: 'BASE64', Verified: false,
      Raw: 'AKIA1234567890EXAMPLE',
    }]);
    const hdf = parseHdf(await convertTrufflehogToHdf(input));
    expect(hdf.baselines[0]!.requirements).toHaveLength(1);
  });

  it('should handle finding with Git SourceMetadata', async () => {
    const input = JSON.stringify([{
      DetectorType: 1, DetectorName: 'GitHub',
      DecoderName: 'PLAIN', Verified: true,
      Raw: 'ghp_abcdef1234567890',
      SourceMetadata: {
        Data: {
          Git: { repository: 'https://github.com/test/repo', commit: 'abc123', file: 'config.yaml', line: 10, email: 'test@test.com', timestamp: '2025-01-01T00:00:00Z' },
        },
      },
    }]);
    const hdf = parseHdf(await convertTrufflehogToHdf(input));
    expect(hdf.baselines[0]!.requirements[0]!.results[0]!.status).toBe('failed');
  });

  it('should handle ndjson format', async () => {
    const line1 = JSON.stringify({ DetectorType: 1, DetectorName: 'AWS', DecoderName: 'PLAIN', Verified: false, Raw: 'test' });
    const line2 = JSON.stringify({ DetectorType: 2, DetectorName: 'Slack', DecoderName: 'PLAIN', Verified: false, Raw: 'xoxb-test' });
    const input = line1 + '\n' + line2;
    const hdf = parseHdf(await convertTrufflehogToHdf(input));
    expect(hdf.baselines[0]!.requirements).toHaveLength(2);
  });
});
