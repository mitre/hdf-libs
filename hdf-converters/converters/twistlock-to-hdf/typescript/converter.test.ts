import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { describe, it, expect } from 'vitest';
import {
  convertTwistlockToHdf,
  buildCvss,
  parseCwes,
  resolveEcosystem,
  extractFixedInVersion,
  buildAffectedPackage,
} from './converter.js';
import { cvssVersionFromVector, cvssSeverityFromScore } from '../../../shared/typescript/cvss.js';
import { runConverterContractTests } from '../../../shared/typescript/converter-contract.js';
import { expectValidResults } from '../../../test/helpers/expectValidHdf.js';
import {
  assertRequirementCount,
  countJsonItemsUnderKey,
} from '../../../shared/typescript/anchor.js';
import { CVSSSeverity, Ecosystem, Version as CvssVersion, type HDFResults } from '@mitre/hdf-schema';

const __dirname = dirname(fileURLToPath(import.meta.url));
const FIXTURES_DIR = join(__dirname, '..', 'fixtures');

function loadFixture(name: string): string {
  return readFileSync(join(FIXTURES_DIR, 'input', name), 'utf-8');
}

runConverterContractTests({
  converterName: 'twistlock-to-hdf',
  convertFn: convertTwistlockToHdf,
  minimalFixture: 'twistlock-twistcli-coderepo-scan-sample.json',
});

// Ground-truth anchor (input-derived count; see shared/typescript/anchor.ts):
// one requirement per results[].vulnerabilities[] entry (no grouping/dedup),
// counted independently of the converter's parser so a silent under-extraction
// fails even when Go/TS agree. twistlock-twistcli-sample-1.json carries 97
// vulnerabilities.
describe('twistlock-to-hdf ground-truth anchor', () => {
  it('emits one requirement per vulnerabilities[] entry', async () => {
    const input = loadFixture('twistlock-twistcli-sample-1.json');
    assertRequirementCount(
      await convertTwistlockToHdf(input),
      countJsonItemsUnderKey(input, 'vulnerabilities'),
      'twistlock-twistcli-sample-1.json: one requirement per results[].vulnerabilities[]',
    );
  });
});

describe('timestamp parse fallback', () => {
  it('falls back to a valid startTime when discoveredDate is unparseable', async () => {
    const input = loadFixture('twistlock-twistcli-sample-1.json').replace(/2021-12-01T00:00:00Z/g, 'not-a-date');
    const hdf = JSON.parse(await convertTwistlockToHdf(input)) as HDFResults;
    expectValidResults(hdf);
  });

  it('falls back to a valid startTime when discoveredDate is absent', async () => {
    const input = loadFixture('twistlock-twistcli-sample-1.json').replace(/"discoveredDate"/g, '"discoveredDateAbsent"');
    const hdf = JSON.parse(await convertTwistlockToHdf(input)) as HDFResults;
    expectValidResults(hdf);
  });
});

describe('twistlock to HDF converter', async () => {
  describe('container scan (results wrapper)', async () => {
    it('should produce 1 baseline from sample-1', async () => {
      const output = await convertTwistlockToHdf(loadFixture('twistlock-twistcli-sample-1.json'));
      const hdf = JSON.parse(output) as HDFResults;
      expectValidResults(hdf);

      expect(hdf.baselines).toHaveLength(1);
    });

    it('should use "Twistlock Scan" as baseline name', async () => {
      const hdf = JSON.parse(
        await convertTwistlockToHdf(loadFixture('twistlock-twistcli-sample-1.json'))
      ) as HDFResults;
      expect(hdf.baselines[0]!.name).toBe('Twistlock Scan');
    });

    it('should include baseline title with project info', async () => {
      const hdf = JSON.parse(
        await convertTwistlockToHdf(loadFixture('twistlock-twistcli-sample-1.json'))
      ) as HDFResults;
      expect(hdf.baselines[0]!.title).toContain('Twistlock Project:');
    });

    it('should include summary with vulnerability distribution', async () => {
      const hdf = JSON.parse(
        await convertTwistlockToHdf(loadFixture('twistlock-twistcli-sample-1.json'))
      ) as HDFResults;
      expect(hdf.baselines[0]!.summary).toContain('Package Vulnerability Summary:');
    });

    it('should produce 97 requirements from sample-1 (97 unique CVEs)', async () => {
      const hdf = JSON.parse(
        await convertTwistlockToHdf(loadFixture('twistlock-twistcli-sample-1.json'))
      ) as HDFResults;
      expect(hdf.baselines[0]!.requirements).toHaveLength(97);
    });

    it('should include sha256 checksum', async () => {
      const hdf = JSON.parse(
        await convertTwistlockToHdf(loadFixture('twistlock-twistcli-sample-1.json'))
      ) as HDFResults;
      const checksum = hdf.baselines[0]!.resultsChecksum;
      expect(checksum?.algorithm).toBe('sha256');
      expect(checksum?.value).toMatch(/^[a-f0-9]{64}$/);
    });
  });

  describe('code repo scan (no results wrapper)', async () => {
    it('should produce 1 baseline from coderepo scan', async () => {
      const hdf = JSON.parse(
        await convertTwistlockToHdf(loadFixture('twistlock-twistcli-coderepo-scan-sample.json'))
      ) as HDFResults;
      expect(hdf.baselines).toHaveLength(1);
    });

    it('should include repository name in title', async () => {
      const hdf = JSON.parse(
        await convertTwistlockToHdf(loadFixture('twistlock-twistcli-coderepo-scan-sample.json'))
      ) as HDFResults;
      expect(hdf.baselines[0]!.title).toContain('My-Repo');
    });

    it('should produce 4 requirements (4 unique CVEs)', async () => {
      const hdf = JSON.parse(
        await convertTwistlockToHdf(loadFixture('twistlock-twistcli-coderepo-scan-sample.json'))
      ) as HDFResults;
      expect(hdf.baselines[0]!.requirements).toHaveLength(4);
    });
  });

  describe('generator and dataSource', async () => {
    it('should set generator name and version', async () => {
      const hdf = JSON.parse(
        await convertTwistlockToHdf(loadFixture('twistlock-twistcli-coderepo-scan-sample.json'))
      ) as HDFResults;
      expect(hdf.generator?.name).toBe('twistlock-to-hdf');
      expect(hdf.generator?.version).toBe('1.0.0');
    });

    it('should set dataSource to Twistlock', async () => {
      const hdf = JSON.parse(
        await convertTwistlockToHdf(loadFixture('twistlock-twistcli-coderepo-scan-sample.json'))
      ) as HDFResults;
      expect(hdf.tool?.name).toBe('Twistlock');
      expect(hdf.tool?.format).toBeUndefined() // serialization structures are not formats (kpvj);
    });
  });

  describe('severity to impact mapping', async () => {
    it('should map critical to 0.9', async () => {
      const hdf = JSON.parse(
        await convertTwistlockToHdf(loadFixture('twistlock-twistcli-coderepo-scan-sample.json'))
      ) as HDFResults;
      const req = hdf.baselines[0]!.requirements.find(r => r.id === 'CVE-2021-44228');
      expect(req?.impact).toBe(0.9);
    });

    it('should map high to 0.7', async () => {
      const hdf = JSON.parse(
        await convertTwistlockToHdf(loadFixture('twistlock-twistcli-coderepo-scan-sample.json'))
      ) as HDFResults;
      const req = hdf.baselines[0]!.requirements.find(r => r.id === 'CVE-2021-45105');
      expect(req?.impact).toBe(0.7);
    });

    it('should map medium to 0.5', async () => {
      const hdf = JSON.parse(
        await convertTwistlockToHdf(loadFixture('twistlock-twistcli-coderepo-scan-sample.json'))
      ) as HDFResults;
      const req = hdf.baselines[0]!.requirements.find(r => r.id === 'CVE-2021-44832');
      expect(req?.impact).toBe(0.5);
    });

    it('should map info to 0.0 like the Go twin (shared standard map)', async () => {
      const input = JSON.stringify({
        results: [{
          vulnerabilities: [{ id: 'CVE-INFO', severity: 'info', description: 'desc' }],
        }],
      });
      const hdf = JSON.parse(await convertTwistlockToHdf(input)) as HDFResults;
      expect(hdf.baselines[0]!.requirements[0]!.impact).toBe(0.0);
    });

    it('defaults an absent severity field to 0.5 without throwing (Go zero-value parity)', async () => {
      const input = JSON.stringify({
        results: [{
          vulnerabilities: [{ id: 'CVE-NOSEV', description: 'desc' }],
        }],
      });
      const hdf = JSON.parse(await convertTwistlockToHdf(input)) as HDFResults;
      expect(hdf.baselines[0]!.requirements[0]!.impact).toBe(0.5);
    });
  });

  describe('tags', async () => {
    it('should use default remediation NIST tags (SI-2, RA-5)', async () => {
      const hdf = JSON.parse(
        await convertTwistlockToHdf(loadFixture('twistlock-twistcli-coderepo-scan-sample.json'))
      ) as HDFResults;
      const req = hdf.baselines[0]!.requirements.find(r => r.id === 'CVE-2021-44228');
      const nist = req?.tags?.['nist'] as string[];
      expect(nist).toBeDefined();
      expect(nist).toContain('SI-2');
      expect(nist).toContain('RA-5');
    });

    it('should include CVE ID in cveid tag', async () => {
      const hdf = JSON.parse(
        await convertTwistlockToHdf(loadFixture('twistlock-twistcli-coderepo-scan-sample.json'))
      ) as HDFResults;
      const req = hdf.baselines[0]!.requirements.find(r => r.id === 'CVE-2021-44228');
      const cveid = req?.tags?.['cveid'] as string[];
      expect(cveid).toBeDefined();
      expect(cveid).toContain('CVE-2021-44228');
    });
  });

  describe('status', async () => {
    it('should mark all results as failed', async () => {
      const hdf = JSON.parse(
        await convertTwistlockToHdf(loadFixture('twistlock-twistcli-coderepo-scan-sample.json'))
      ) as HDFResults;
      for (const req of hdf.baselines[0]!.requirements) {
        for (const result of req.results) {
          expect(result.status).toBe('failed');
        }
      }
    });
  });

  describe('code description', async () => {
    it('should include package name in code_desc', async () => {
      const hdf = JSON.parse(
        await convertTwistlockToHdf(loadFixture('twistlock-twistcli-coderepo-scan-sample.json'))
      ) as HDFResults;
      const req = hdf.baselines[0]!.requirements.find(r => r.id === 'CVE-2021-44228');
      expect(req).toBeDefined();
      expect(req!.results[0]?.codeDesc).toContain('org.apache.logging.log4j_log4j-core');
    });
  });

  describe('description', async () => {
    it('should include default description with vulnerability info', async () => {
      const hdf = JSON.parse(
        await convertTwistlockToHdf(loadFixture('twistlock-twistcli-coderepo-scan-sample.json'))
      ) as HDFResults;
      const req = hdf.baselines[0]!.requirements.find(r => r.id === 'CVE-2021-44228');
      const desc = req?.descriptions?.find(d => d.label === 'default');
      expect(desc).toBeDefined();
      expect(desc!.data).toContain('Log4j');
    });
  });

  describe('requirement title and ID', async () => {
    it('should use CVE ID as both title and ID', async () => {
      const hdf = JSON.parse(
        await convertTwistlockToHdf(loadFixture('twistlock-twistcli-coderepo-scan-sample.json'))
      ) as HDFResults;
      const req = hdf.baselines[0]!.requirements.find(r => r.id === 'CVE-2021-44228');
      expect(req).toBeDefined();
      expect(req!.id).toBe('CVE-2021-44228');
      expect(req!.title).toBe('CVE-2021-44228');
    });
  });

  describe('target', async () => {
    it('should include image name as target for container scans', async () => {
      const hdf = JSON.parse(
        await convertTwistlockToHdf(loadFixture('twistlock-twistcli-sample-1.json'))
      ) as HDFResults;
      expect(hdf.components).toBeDefined();
      expect(hdf.components![0]!.name).toContain('registry.io/test');
      expect(hdf.components![0]!.type).toBe('containerImage');
    });
  });

  describe('empty vulnerabilities', async () => {
    it('should synthesize a passed placeholder when vulnerabilities is null', async () => {
      const input = JSON.stringify({
        results: [{
          name: 'clean-image',
          collections: ['All'],
          vulnerabilities: null,
          vulnerabilityDistribution: { critical: 0, high: 0, medium: 0, low: 0, total: 0 },
          complianceDistribution: { critical: 0, high: 0, medium: 0, low: 0, total: 0 },
        }],
      });
      const hdf = JSON.parse(await convertTwistlockToHdf(input)) as HDFResults;
      expect(hdf.baselines[0]!.requirements).toHaveLength(1);
      const req = hdf.baselines[0]!.requirements[0]!;
      expect(req.id).toBe('twistlock-no-findings');
      expect(req.results).toHaveLength(1);
      expect(req.results[0]!.status).toBe('passed');
      expect(req.results[0]!.codeDesc).toContain('Twistlock');
      expect(req.results[0]!.codeDesc).toContain('vulnerable components');
      expect(req.results[0]!.codeDesc).toContain('clean-image');
    });

    it('should synthesize a passed placeholder from the empty.json fixture', async () => {
      const hdf = JSON.parse(await convertTwistlockToHdf(loadFixture('empty.json'))) as HDFResults;
      expect(hdf.baselines).toHaveLength(1);
      expect(hdf.baselines[0]!.requirements).toHaveLength(1);
      const req = hdf.baselines[0]!.requirements[0]!;
      expect(req.id).toBe('twistlock-no-findings');
      expect(req.impact).toBe(0);
      expect(req.results[0]!.status).toBe('passed');
      expect(req.results[0]!.codeDesc).toContain('registry.io/clean:latest');
    });

    it('should synthesize one placeholder per clean result baseline', async () => {
      const input = JSON.stringify({
        results: [
          { name: 'image-a', vulnerabilities: [] },
          { name: 'image-b', vulnerabilities: [] },
        ],
      });
      const hdf = JSON.parse(await convertTwistlockToHdf(input)) as HDFResults;
      expect(hdf.baselines).toHaveLength(2);
      for (const baseline of hdf.baselines) {
        expect(baseline.requirements).toHaveLength(1);
        expect(baseline.requirements[0]!.id).toBe('twistlock-no-findings');
      }
      expect(hdf.baselines[0]!.requirements[0]!.results[0]!.codeDesc).toContain('image-a');
      expect(hdf.baselines[1]!.requirements[0]!.results[0]!.codeDesc).toContain('image-b');
    });
  });

  describe('start time', async () => {
    it('should use discoveredDate as start_time', async () => {
      const hdf = JSON.parse(
        await convertTwistlockToHdf(loadFixture('twistlock-twistcli-coderepo-scan-sample.json'))
      ) as HDFResults;
      const req = hdf.baselines[0]!.requirements.find(r => r.id === 'CVE-2021-44228');
      expect(req).toBeDefined();
      // Canonical trimmed-UTC RFC3339 (matches the Go converter's RFC3339Nano).
      expect(req!.results[0]?.startTime).toBe('2021-12-10T10:15:00Z');
    });
  });

  describe('structured CVE-ecosystem fields', () => {
    it('populates cvss[] for findings with a vector + score', async () => {
      const hdf = JSON.parse(
        await convertTwistlockToHdf(loadFixture('twistlock-twistcli-coderepo-scan-sample.json'))
      ) as HDFResults;
      const req = hdf.baselines[0]!.requirements.find(r => r.id === 'CVE-2021-44228')!;
      expect(req.cvss).toBeDefined();
      expect(req.cvss).toHaveLength(1);
      const cv = req.cvss![0]!;
      expect(cv.version).toBe('3.1');
      expect(cv.baseVector).toBe('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H');
      expect(cv.baseScore).toBe(10);
      expect(cv.baseSeverity).toBe('critical');
      expect(cv.source).toBe('CVE-2021-44228');
    });

    it('populates affectedPackages[] with maven ecosystem for jar packages', async () => {
      const hdf = JSON.parse(
        await convertTwistlockToHdf(loadFixture('twistlock-twistcli-coderepo-scan-sample.json'))
      ) as HDFResults;
      const req = hdf.baselines[0]!.requirements.find(r => r.id === 'CVE-2021-44228')!;
      expect(req.affectedPackages).toBeDefined();
      expect(req.affectedPackages).toHaveLength(1);
      const pkg = req.affectedPackages![0]!;
      expect(pkg.name).toBe('org.apache.logging.log4j_log4j-core');
      expect(pkg.version).toBe('2.14.1');
      expect(pkg.ecosystem).toBe('maven');
      expect(pkg.fixedInVersion).toBe('2.15.0');
    });

    it('populates affectedPackages[] with rpm ecosystem for RHEL os packages', async () => {
      const hdf = JSON.parse(
        await convertTwistlockToHdf(loadFixture('twistlock-twistcli-sample-1.json'))
      ) as HDFResults;
      const req = hdf.baselines[0]!.requirements.find(r => r.id === 'CVE-2021-43529')!;
      expect(req.affectedPackages).toBeDefined();
      const pkg = req.affectedPackages![0]!;
      expect(pkg.name).toBe('nss-util');
      expect(pkg.ecosystem).toBe('rpm');
    });

    it('retains legacy cvss_base_score tag for one release', async () => {
      const hdf = JSON.parse(
        await convertTwistlockToHdf(loadFixture('twistlock-twistcli-coderepo-scan-sample.json'))
      ) as HDFResults;
      const req = hdf.baselines[0]!.requirements.find(r => r.id === 'CVE-2021-44228')!;
      expect(req.tags?.['cvss_base_score']).toBe(10);
    });

    it('populates cwe[] from synthetic input with cwe field', async () => {
      const input = JSON.stringify({
        results: [{
          name: 'synthetic',
          distro: 'Red Hat Enterprise Linux 8',
          packages: [{ type: 'os', name: 'openssl', version: '1.0' }],
          vulnerabilities: [{
            id: 'CVE-2099-0001',
            severity: 'high',
            description: 'synthetic',
            cvss: 7.5,
            vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H',
            cwe: 'CWE-79',
            packageName: 'openssl',
            packageVersion: '1.0',
            status: 'fixed in 1.1',
          }],
        }],
      });
      const hdf = JSON.parse(await convertTwistlockToHdf(input)) as HDFResults;
      const req = hdf.baselines[0]!.requirements[0]!;
      expect(req.cwe).toEqual(['CWE-79']);
    });
  });

  describe('helper unit tests', () => {
    it('cvssVersionFromVector detects all prefixes', () => {
      expect(cvssVersionFromVector('CVSS:2.0/AV:N')).toBe(CvssVersion.The20);
      expect(cvssVersionFromVector('CVSS:3.0/AV:N')).toBe(CvssVersion.The30);
      expect(cvssVersionFromVector('CVSS:3.1/AV:N')).toBe(CvssVersion.The31);
      expect(cvssVersionFromVector('CVSS:4.0/AV:N')).toBe(CvssVersion.The40);
      expect(cvssVersionFromVector(undefined)).toBe(CvssVersion.The31);
      expect(cvssVersionFromVector('')).toBe(CvssVersion.The31);
      expect(cvssVersionFromVector('AV:N/AC:L')).toBe(CvssVersion.The31);
    });

    it('cvssSeverityFromScore returns FIRST bands', () => {
      expect(cvssSeverityFromScore(0)).toBe(CVSSSeverity.None);
      expect(cvssSeverityFromScore(0.1)).toBe(CVSSSeverity.Low);
      expect(cvssSeverityFromScore(3.9)).toBe(CVSSSeverity.Low);
      expect(cvssSeverityFromScore(4.0)).toBe(CVSSSeverity.Medium);
      expect(cvssSeverityFromScore(7.0)).toBe(CVSSSeverity.High);
      expect(cvssSeverityFromScore(9.0)).toBe(CVSSSeverity.Critical);
      expect(cvssSeverityFromScore(10.0)).toBe(CVSSSeverity.Critical);
    });

    it('buildCvss returns undefined for vulns lacking score+vector', () => {
      expect(buildCvss({ id: 'X', severity: 'low', description: '' })).toBeUndefined();
    });

    it('buildCvss treats 0.0 as a valid score, not "no score"', () => {
      const cv = buildCvss({ id: 'CVE-0', cve: 'CVE-0', severity: 'none', description: '', cvss: 0 });
      expect(cv).toBeDefined();
      expect(cv?.baseScore).toBe(0);
      expect(cv?.baseVector).toBeUndefined();
    });

    it('buildCvss omits baseScore when only a vector is present', () => {
      const cv = buildCvss({ id: 'CVE-1', cve: 'CVE-1', severity: 'high', description: '', vector: 'AV:N/AC:L/Au:N/C:P/I:P/A:P' });
      expect(cv).toBeDefined();
      expect(cv?.baseScore).toBeUndefined();
      expect(cv?.baseVector).toBe('AV:N/AC:L/Au:N/C:P/I:P/A:P');
    });

    it('parseCwes normalizes mixed-case input and dedupes', () => {
      expect(parseCwes(undefined)).toEqual([]);
      expect(parseCwes('')).toEqual([]);
      expect(parseCwes('no cwe here')).toEqual([]);
      expect(parseCwes('CWE-79')).toEqual(['CWE-79']);
      expect(parseCwes('cwe-79')).toEqual(['CWE-79']);
      expect(parseCwes('CWE-79 and CWE-89')).toEqual(['CWE-79', 'CWE-89']);
      expect(parseCwes('CWE-79, CWE-79')).toEqual(['CWE-79']);
    });

    it('resolveEcosystem matrix', () => {
      expect(resolveEcosystem('os', 'Red Hat Enterprise Linux release 8.6')).toBe(Ecosystem.RPM);
      expect(resolveEcosystem('os', 'Ubuntu 22.04')).toBe(Ecosystem.Deb);
      expect(resolveEcosystem('os', 'Alpine Linux')).toBe(Ecosystem.Generic);
      expect(resolveEcosystem('jar', '')).toBe(Ecosystem.Maven);
      expect(resolveEcosystem('python', '')).toBe(Ecosystem.Pypi);
      expect(resolveEcosystem('nodejs', '')).toBe(Ecosystem.Npm);
      expect(resolveEcosystem('gem', '')).toBe(Ecosystem.Gem);
      expect(resolveEcosystem('nuget', '')).toBe(Ecosystem.Nuget);
      expect(resolveEcosystem('go', '')).toBe(Ecosystem.Go);
      expect(resolveEcosystem('unknown-type', '')).toBe(Ecosystem.Generic);
      expect(resolveEcosystem(undefined, undefined)).toBe(Ecosystem.Generic);
    });

    it('extractFixedInVersion prefers fixedBy then status', () => {
      expect(extractFixedInVersion({ id: 'X', severity: '', description: '', fixedBy: '1.2.3', status: 'fixed in 9.9.9' })).toBe('1.2.3');
      expect(extractFixedInVersion({ id: 'X', severity: '', description: '', status: 'fixed in 2.15.0, 2.12.2' })).toBe('2.15.0');
      expect(extractFixedInVersion({ id: 'X', severity: '', description: '', status: 'affected' })).toBe('');
      expect(extractFixedInVersion({ id: 'X', severity: '', description: '' })).toBe('');
    });

    it('buildAffectedPackage returns undefined when name+version missing', () => {
      expect(buildAffectedPackage({ id: 'X', severity: '', description: '' }, new Map(), undefined)).toBeUndefined();
      expect(buildAffectedPackage({ id: 'X', severity: '', description: '', packageName: 'pkg' }, new Map(), undefined)).toBeUndefined();
    });
  });

  describe('edge cases: missing optional fields', async () => {
    it('should handle result with collections but no repository', async () => {
      const input = JSON.stringify({
        results: [{
          collections: ['col1', 'col2'],
          vulnerabilities: [{
            id: 'CVE-1', severity: 'critical', description: 'desc',
          }],
        }],
      });
      const hdf = JSON.parse(await convertTwistlockToHdf(input)) as HDFResults;
      expect(hdf.baselines[0]!.title).toContain('col1 / col2');
      expect(hdf.baselines[0]!.requirements[0]!.impact).toBe(0.9);
    });

    it('should handle result with no repository or collections', async () => {
      const input = JSON.stringify({
        results: [{
          vulnerabilities: [{
            id: 'CVE-2', severity: 'moderate', description: 'desc',
          }],
        }],
      });
      const hdf = JSON.parse(await convertTwistlockToHdf(input)) as HDFResults;
      expect(hdf.baselines[0]!.title).toContain('N/A');
      expect(hdf.baselines[0]!.requirements[0]!.impact).toBe(0.5);
    });

    it('should handle result with no distribution data', async () => {
      const input = JSON.stringify({
        results: [{
          vulnerabilities: [{
            id: 'CVE-3', severity: 'unknown', description: 'desc',
          }],
        }],
      });
      const hdf = JSON.parse(await convertTwistlockToHdf(input)) as HDFResults;
      expect(hdf.baselines[0]!.summary).toContain('N/A');
    });

    it('should handle vulnerability with no discoveredDate', async () => {
      const input = JSON.stringify({
        results: [{
          vulnerabilities: [{
            id: 'CVE-4', severity: 'low', description: 'desc',
            impactedVersions: ['1.0', '2.0'],
          }],
        }],
      });
      const hdf = JSON.parse(await convertTwistlockToHdf(input)) as HDFResults;
      expect(hdf.baselines[0]!.requirements[0]!.impact).toBe(0.3);
    });

    it('should handle vulnerability with empty impactedVersions', async () => {
      const input = JSON.stringify({
        results: [{
          vulnerabilities: [{
            id: 'CVE-5', severity: 'high', description: 'desc',
            impactedVersions: [],
          }],
        }],
      });
      const hdf = JSON.parse(await convertTwistlockToHdf(input)) as HDFResults;
      expect(hdf.baselines[0]!.requirements[0]!.results[0]!.codeDesc).toContain('N/A');
    });

    it('should handle code repo scan (no results wrapper)', async () => {
      const input = JSON.stringify({
        name: 'my-repo',
        vulnerabilities: [{
          id: 'CVE-6', severity: 'medium', description: 'desc',
        }],
      });
      const hdf = JSON.parse(await convertTwistlockToHdf(input)) as HDFResults;
      expect(hdf.components![0]!.name).toBe('my-repo');
    });
  });

  describe('result message (heimdall2 parity)', () => {
    it('sets the expected/detected-version message from packageName/packageVersion', async () => {
      const input = loadFixture('twistlock-twistcli-coderepo-scan-sample.json');
      const hdf = JSON.parse(await convertTwistlockToHdf(input)) as HDFResults;
      const req = hdf.baselines[0]!.requirements.find(r => r.id === 'CVE-2021-44228')!;
      expect(req.results[0]!.message).toBe(
        'Expected latest version of "org.apache.logging.log4j_log4j-core"\nDetected vulnerable version "2.14.1" of "org.apache.logging.log4j_log4j-core"',
      );
    });

    it('renders bare N/A when packageName/packageVersion are absent', async () => {
      const input = JSON.stringify({
        results: [{ vulnerabilities: [{ id: 'CVE-7', severity: 'low', description: 'd' }] }],
      });
      const hdf = JSON.parse(await convertTwistlockToHdf(input)) as HDFResults;
      expect(hdf.baselines[0]!.requirements[0]!.results[0]!.message).toBe(
        'Expected latest version of N/A\nDetected vulnerable version N/A of N/A',
      );
    });
  });

  describe('raw-finding code passthrough (heimdall2 parity)', () => {
    it('preserves otherwise-unmapped fields in requirement.code', async () => {
      const input = loadFixture('twistlock-twistcli-coderepo-scan-sample.json');
      const hdf = JSON.parse(await convertTwistlockToHdf(input)) as HDFResults;
      const req = hdf.baselines[0]!.requirements.find(r => r.id === 'CVE-2021-44228')!;
      expect(req.code).toBeDefined();
      expect(req.code).toContain('"link":');
      expect(req.code).toContain('"riskFactors":');
      expect(req.code).toContain('"publishedDate":');
      expect(req.code).toContain('"layerTime":');
    });

    it('projects fixed field order with empties dropped (Go-parity)', async () => {
      const input = JSON.stringify({
        results: [{
          vulnerabilities: [{
            id: 'CVE-X', status: 'affected', cvss: 7.5, severity: 'high',
            packageName: 'openssl', packageVersion: '1.0', link: 'https://example.test/CVE-X',
          }],
        }],
      });
      const hdf = JSON.parse(await convertTwistlockToHdf(input)) as HDFResults;
      const req = hdf.baselines[0]!.requirements[0]!;
      expect(req.code).toBe(
        '{\n' +
        '  "id": "CVE-X",\n' +
        '  "status": "affected",\n' +
        '  "cvss": 7.5,\n' +
        '  "severity": "high",\n' +
        '  "packageName": "openssl",\n' +
        '  "packageVersion": "1.0",\n' +
        '  "link": "https://example.test/CVE-X"\n' +
        '}',
      );
    });
  });
});

// Impact is deliberately NOT asserted here: the TS severity-to-impact switch
// lacks the info/none cases Go's standard map has (known latent parity gap,
// tracked separately). The marker predicate itself is shared and parity-safe.
describe('unrated severity marker', () => {
  it('tags unrated severities with severity_rating: unrated and leaves rated untagged', async () => {
    const input = JSON.stringify({
      results: [{
        name: 'synthetic-image',
        vulnerabilities: [
          { id: 'CVE-2099-1001', severity: '', description: 'empty severity' },
          { id: 'CVE-2099-1002', severity: 'unknown', description: 'unknown severity' },
          { id: 'CVE-2099-1003', severity: 'moderate', description: 'rated severity' },
          { id: 'CVE-2099-1004', severity: 'info', description: 'zero-impact tier is rated' },
        ],
      }],
    });
    const hdf = JSON.parse(await convertTwistlockToHdf(input)) as HDFResults;
    const reqs = hdf.baselines[0]!.requirements;
    const byId = (id: string) => reqs.find((r) => r.id === id);

    expect(byId('CVE-2099-1001')?.tags?.['severity_rating']).toBe('unrated');
    expect(byId('CVE-2099-1002')?.tags?.['severity_rating']).toBe('unrated');
    // Tag-only assertions: the zero-impact tier is RATED (no marker); impact is
    // deliberately not asserted here (tracked TS info/none impact-map gap).
    expect(byId('CVE-2099-1003')?.tags).not.toHaveProperty('severity_rating');
    expect(byId('CVE-2099-1004')?.tags).not.toHaveProperty('severity_rating');
  });
});
