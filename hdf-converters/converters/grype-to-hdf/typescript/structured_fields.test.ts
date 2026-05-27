import {readFileSync} from 'fs';
import {join} from 'path';
import {describe, expect, it} from 'vitest';
import {convertGrypeToHdf} from './converter';
import {parseJSON} from '@mitre/hdf-utilities';
import {Ecosystem, CVSSSeverity, type HdfResults} from '@mitre/hdf-schema';

const FIXTURES_DIR = join(__dirname, '..', 'fixtures');

function loadFixture(name: string): string {
  return readFileSync(join(FIXTURES_DIR, 'input', name), 'utf-8');
}

describe('Grype structured CVE fields', () => {
  describe('cvss[]', () => {
    it('populates one Cvss entry per vulnerability.cvss array element', async () => {
      const input = loadFixture('amazon.json');
      const output = await convertGrypeToHdf(input);
      const hdf = parseJSON<HdfResults>(output);

      const req = hdf.baselines[0].requirements.find(r => r.id === 'Grype/CVE-2024-7592');
      expect(req).toBeDefined();
      expect(req?.cvss).toBeDefined();
      expect(req?.cvss).toHaveLength(1);
      const entry = req!.cvss![0];
      expect(entry.version).toBe('3.1');
      expect(entry.source).toBe('CVE-2024-7592');
      expect(entry.baseVector).toBe('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H');
      expect(entry.baseScore).toBe(7.5);
      expect(entry.baseSeverity).toBe(CVSSSeverity.High);
    });

    it('emits no entries when vulnerability.cvss is empty (related CVSS not pulled in)', async () => {
      const input = loadFixture('amazon.json');
      const output = await convertGrypeToHdf(input);
      const hdf = parseJSON<HdfResults>(output);

      const req = hdf.baselines[0].requirements.find(r => r.id === 'Grype/ALAS-2024-2607');
      expect(req).toBeDefined();
      expect(req?.cvss ?? []).toHaveLength(0);
    });

    it('derives baseSeverity from baseScore using FIRST band thresholds', async () => {
      const input = loadFixture('amazon.json');
      const output = await convertGrypeToHdf(input);
      const hdf = parseJSON<HdfResults>(output);

      let checked = 0;
      for (const req of hdf.baselines[0].requirements) {
        for (const c of req.cvss ?? []) {
          expect(c.baseSeverity).toBeDefined();
          const score = c.baseScore;
          let expected: CVSSSeverity;
          if (score < 0.1) expected = CVSSSeverity.None;
          else if (score < 4.0) expected = CVSSSeverity.Low;
          else if (score < 7.0) expected = CVSSSeverity.Medium;
          else if (score < 9.0) expected = CVSSSeverity.High;
          else expected = CVSSSeverity.Critical;
          expect(c.baseSeverity).toBe(expected);
          checked++;
        }
      }
      expect(checked).toBeGreaterThan(0);
    });
  });

  describe('affectedPackages[]', () => {
    it('populates from artifact (rpm with cpes, purl, fixed-in)', async () => {
      const input = loadFixture('amazon.json');
      const output = await convertGrypeToHdf(input);
      const hdf = parseJSON<HdfResults>(output);

      const req = hdf.baselines[0].requirements.find(r => r.id === 'Grype/ALAS-2024-2607');
      expect(req).toBeDefined();
      expect(req?.affectedPackages).toHaveLength(1);

      const pkg = req!.affectedPackages![0];
      expect(pkg.name).toBe('ca-certificates');
      expect(pkg.version).toBe('2023.2.64-1.amzn2.0.1');
      expect(pkg.ecosystem).toBe(Ecosystem.RPM);
      expect(pkg.cpe).toMatch(/^cpe:2\.3:a:ca-certificates:ca-certificates:/);
      expect(pkg.purl).toMatch(/^pkg:rpm\/amzn\/ca-certificates@/);
      expect(pkg.fixedInVersion).toBe('2023.2.68-1.amzn2.0.1');
    });

    it('omits fixedInVersion when fix.state != fixed', async () => {
      const input = loadFixture('amazon.json');
      const output = await convertGrypeToHdf(input);
      const hdf = parseJSON<HdfResults>(output);

      const req = hdf.baselines[0].requirements.find(r => r.id === 'Grype/CVE-2024-7592');
      expect(req).toBeDefined();
      expect(req?.affectedPackages).toHaveLength(1);
      const pkg = req!.affectedPackages![0];
      expect(pkg.fixedInVersion).toBeUndefined();
      // python binary → artifact.type "binary" → schema "generic" ecosystem
      expect(pkg.ecosystem).toBe(Ecosystem.Generic);
    });

    it('handles artifact without cpes/purl', async () => {
      const minimalReport = JSON.stringify({
        descriptor: {name: 'grype', version: '0.79.3'},
        source: {target: {userInput: 'test-image'}},
        matches: [{
          vulnerability: {id: 'CVE-2024-3333', severity: 'Medium'},
          matchDetails: [{type: 'exact-direct-match'}],
          artifact: {name: 'thing', version: '2.0', type: 'npm'},
        }],
      });
      const output = await convertGrypeToHdf(minimalReport);
      const hdf = parseJSON<HdfResults>(output);

      const req = hdf.baselines[0].requirements.find(r => r.id === 'Grype/CVE-2024-3333');
      expect(req).toBeDefined();
      expect(req?.affectedPackages).toHaveLength(1);
      const pkg = req!.affectedPackages![0];
      expect(pkg.cpe).toBeUndefined();
      expect(pkg.purl).toBeUndefined();
      expect(pkg.ecosystem).toBe(Ecosystem.Npm);
    });

    it('maps every documented Grype artifact.type to the correct schema Ecosystem', async () => {
      const cases: Array<[string, Ecosystem]> = [
        ['rpm', Ecosystem.RPM],
        ['deb', Ecosystem.Deb],
        ['apk', Ecosystem.Generic],
        ['npm', Ecosystem.Npm],
        ['python', Ecosystem.Pypi],
        ['gem', Ecosystem.Gem],
        ['go-module', Ecosystem.Go],
        ['java-archive', Ecosystem.Maven],
        ['dotnet', Ecosystem.Nuget],
        ['rust-crate', Ecosystem.Cargo],
        ['binary', Ecosystem.Generic],
        ['', Ecosystem.Generic],
        ['some-future-type', Ecosystem.Generic],
      ];

      for (const [grypeType, expected] of cases) {
        const report = JSON.stringify({
          descriptor: {name: 'grype', version: '0.79.3'},
          source: {target: {userInput: 'test-image'}},
          matches: [{
            vulnerability: {id: 'CVE-2024-EE00', severity: 'Low'},
            matchDetails: [{type: 'exact-direct-match'}],
            artifact: {name: 'pkg', version: '1.0', type: grypeType},
          }],
        });
        const output = await convertGrypeToHdf(report);
        const hdf = parseJSON<HdfResults>(output);
        const pkg = hdf.baselines[0].requirements[0].affectedPackages?.[0];
        expect(pkg, `case ${grypeType}`).toBeDefined();
        expect(pkg!.ecosystem, `case ${grypeType}`).toBe(expected);
      }
    });
  });

  describe('cwe[]', () => {
    it('is empty when Grype output has no vulnerability.cwe array', async () => {
      const input = loadFixture('amazon.json');
      const output = await convertGrypeToHdf(input);
      const hdf = parseJSON<HdfResults>(output);

      for (const req of hdf.baselines[0].requirements) {
        expect(req.cwe ?? []).toHaveLength(0);
      }
    });

    it('parses valid CWE-N entries and drops malformed ones', async () => {
      const report = JSON.stringify({
        descriptor: {name: 'grype', version: '0.79.3'},
        source: {target: {userInput: 'test-image'}},
        matches: [{
          vulnerability: {
            id: 'CVE-2024-9999',
            severity: 'High',
            cwe: ['CWE-79', 'CWE-89', 'CWE-bogus', 'CWE-0', 'junk'],
          },
          matchDetails: [{type: 'exact-direct-match'}],
          artifact: {name: 'pkg', version: '1.0', type: 'rpm'},
        }],
      });
      const output = await convertGrypeToHdf(report);
      const hdf = parseJSON<HdfResults>(output);
      const req = hdf.baselines[0].requirements.find(r => r.id === 'Grype/CVE-2024-9999');
      expect(req?.cwe).toEqual(['CWE-79', 'CWE-89']);
    });
  });

  describe('epss', () => {
    it('populates from vulnerability.epss[] (most recent entry by date)', async () => {
      const report = JSON.stringify({
        descriptor: {name: 'grype', version: '0.79.3'},
        source: {target: {userInput: 'test-image'}},
        matches: [{
          vulnerability: {
            id: 'CVE-2024-1111',
            severity: 'High',
            epss: [
              {cve: 'CVE-2024-1111', epss: 0.92, percentile: 0.99, date: '2024-08-29'},
              {cve: 'CVE-2024-1111', epss: 0.45, percentile: 0.85, date: '2024-08-22'},
            ],
          },
          matchDetails: [{type: 'exact-direct-match'}],
          artifact: {name: 'pkg', version: '1.0', type: 'rpm'},
        }],
      });
      const output = await convertGrypeToHdf(report);
      const hdf = parseJSON<HdfResults>(output);
      const req = hdf.baselines[0].requirements.find(r => r.id === 'Grype/CVE-2024-1111');
      expect(req?.epss).toBeDefined();
      expect(req!.epss!.score).toBe(0.92);
      expect(req!.epss!.percentile).toBe(0.99);
      expect(req!.epss!.date).toBe('2024-08-29');
    });
  });

  describe('kev', () => {
    it('populates from vulnerability.kev block', async () => {
      const report = JSON.stringify({
        descriptor: {name: 'grype', version: '0.79.3'},
        source: {target: {userInput: 'test-image'}},
        matches: [{
          vulnerability: {
            id: 'CVE-2024-2222',
            severity: 'Critical',
            kev: {
              inKev: true,
              dateAdded: '2024-01-15',
              dueDate: '2024-02-05',
              notes: 'Actively exploited',
            },
          },
          matchDetails: [{type: 'exact-direct-match'}],
          artifact: {name: 'pkg', version: '1.0', type: 'rpm'},
        }],
      });
      const output = await convertGrypeToHdf(report);
      const hdf = parseJSON<HdfResults>(output);
      const req = hdf.baselines[0].requirements.find(r => r.id === 'Grype/CVE-2024-2222');
      expect(req?.kev).toBeDefined();
      expect(req!.kev!.inKev).toBe(true);
      expect(req!.kev!.dateAdded).toBe('2024-01-15');
      expect(req!.kev!.dueDate).toBe('2024-02-05');
    });

    it('leaves kev undefined when Grype omits the block', async () => {
      const input = loadFixture('amazon.json');
      const output = await convertGrypeToHdf(input);
      const hdf = parseJSON<HdfResults>(output);
      for (const req of hdf.baselines[0].requirements) {
        expect(req.kev).toBeUndefined();
      }
    });
  });
});
