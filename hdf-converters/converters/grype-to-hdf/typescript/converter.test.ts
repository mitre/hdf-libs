import {readFileSync} from 'fs';
import {join} from 'path';
import {describe, expect, it} from 'vitest';
import {convertGrypeToHdf} from './converter';
import {runConverterContractTests} from '../../../shared/typescript/converter-contract.js';
import {expectValidResults} from '../../../test/helpers/expectValidHdf.js';
import {parseJSON} from '@mitre/hdf-utilities';
import {
  assertRequirementCount,
  countJsonItemsUnderKey,
} from '../../../shared/typescript/anchor.js';
import type {HDFResults} from '@mitre/hdf-schema';

const FIXTURES_DIR = join(__dirname, '..', 'fixtures');

function loadFixture(name: string): string {
  return readFileSync(join(FIXTURES_DIR, 'input', name), 'utf-8');
}

runConverterContractTests({
  converterName: 'grype-to-hdf',
  convertFn: convertGrypeToHdf,
  minimalFixture: 'amazon.json',
});

// Ground-truth anchor (input-derived count; see shared/typescript/anchor.ts).
// Grype emits one requirement per matches[] entry (plus ignoredMatches[], which
// anchore_grype.json has none of).
describe('grype-to-hdf ground-truth anchor', () => {
  it('emits one requirement per matches[]', async () => {
    const input = loadFixture('anchore_grype.json');
    assertRequirementCount(
      await convertGrypeToHdf(input),
      countJsonItemsUnderKey(input, 'matches'),
      'anchore_grype.json: one requirement per matches[] (no ignoredMatches)',
    );
  });
});

// Grype carries no literal source snippet, so requirement.code holds the raw
// match object serialized as indented JSON. Pin that it is set and round-trips
// back to the source match (Heimdall CODE-tab fidelity; must byte-match the Go
// twin, enforced by the shared snapshot test).
describe('grype-to-hdf requirement.code (CODE tab)', () => {
  it('sets code to the serialized match that round-trips to source', async () => {
    const input = loadFixture('amazon.json');
    const result = parseJSON<HDFResults>(await convertGrypeToHdf(input));
    const source = parseJSON<{matches: unknown[]}>(input);
    const reqs = result.baselines[0]!.requirements;
    expect(reqs.length).toBe(source.matches.length);
    reqs.forEach((req, i) => {
      expect(req.code, `requirement ${i}: code should be set`).toBeDefined();
      expect(JSON.parse(req.code!)).toEqual(source.matches[i]);
    });
  });
});

describe('timestamp parse fallback', () => {
  it('falls back to conversion time when the descriptor timestamp is unparseable', async () => {
    const doc = JSON.parse(loadFixture('amazon.json'));
    if (doc.descriptor) doc.descriptor.timestamp = 'not-a-date';
    const hdf = JSON.parse(await convertGrypeToHdf(JSON.stringify(doc))) as HDFResults;
    expectValidResults(hdf);
  });
});

describe('Grype Converter', async () => {
  describe('convertGrypeToHdf', async () => {
    it('should convert real Grype report to HDF', async () => {
      const input = loadFixture('amazon.json');
      const output = await convertGrypeToHdf(input);
      const hdf = parseJSON<HDFResults>(output);
      expectValidResults(hdf);

      expect(hdf.baselines).toHaveLength(1);
      expect(hdf.generator.name).toBe('grype-to-hdf');
      expect(hdf.generator.version).toBe('1.0.0');
      expect(hdf.tool?.name).toBe('Grype');
      expect(hdf.tool?.version).toBe('0.79.3');
      expect(hdf.tool?.format).toBeUndefined();
      // Timestamp from real Grype output: "2024-08-29T13:47:41.623667-04:00"
      expect(hdf.timestamp).toBeDefined();
    });

    it('should create baseline with correct name from scan target', async () => {
      const input = loadFixture('amazon.json');
      const output = await convertGrypeToHdf(input);
      const hdf = parseJSON<HDFResults>(output);

      expect(hdf.baselines[0].name).toBe('cloudwatch_to_s3:latest');
    });

    it('should convert matches to requirements', async () => {
      const input = loadFixture('amazon.json');
      const output = await convertGrypeToHdf(input);
      const hdf = parseJSON<HDFResults>(output);

      const requirements = hdf.baselines[0].requirements;
      expect(requirements).toHaveLength(16); // 16 real vulnerability matches

      // Check Low severity match: ALAS-2024-2607 (ca-certificates)
      const alas2607 = requirements.find(r => r.id === 'Grype/ALAS-2024-2607');
      expect(alas2607).toBeDefined();
      expect(alas2607?.impact).toBe(0.3); // Low severity
      expect(alas2607?.results).toHaveLength(1);
      expect(alas2607?.results[0].status).toBe('failed');

      // Check High severity match: CVE-2024-7592 (python binary)
      const cve7592 = requirements.find(r => r.id === 'Grype/CVE-2024-7592');
      expect(cve7592).toBeDefined();
      expect(cve7592?.impact).toBe(0.7); // High severity
    });

    it('should handle ignored matches correctly', async () => {
      // Use inline fixture since the real amazon.json scan has no ignored matches
      const ignoredReport = JSON.stringify({
        descriptor: {name: 'grype', version: '0.79.3'},
        source: {target: {userInput: 'test-image'}},
        matches: [],
        ignoredMatches: [{
          vulnerability: {
            id: 'CVE-2024-0001',
            severity: 'Low',
            urls: ['https://nvd.nist.gov/vuln/detail/CVE-2024-0001'],
            description: 'Test ignored vulnerability',
          },
          matchDetails: [{type: 'exact-direct-match', matcher: 'rpm-matcher'}],
          artifact: {name: 'test-pkg', version: '1.0.0', type: 'rpm'},
        }],
      });

      const output = await convertGrypeToHdf(ignoredReport);
      const hdf = parseJSON<HDFResults>(output);

      const requirements = hdf.baselines[0].requirements;
      const ignored = requirements.find(r => r.id === 'Grype-Ignored-Match/CVE-2024-0001');

      expect(ignored).toBeDefined();
      expect(ignored?.results[0].status).toBe('notReviewed');
      expect(ignored?.results[0].message).toContain('ignored by configured rules');
    });

    it('should include NIST and CCI tags', async () => {
      const input = loadFixture('amazon.json');
      const output = await convertGrypeToHdf(input);
      const hdf = parseJSON<HDFResults>(output);

      const req = hdf.baselines[0].requirements[0];
      expect(req.tags?.nist).toEqual(['SA-11', 'RA-5']);
      // CCI tags from curated NIST→CCI mapping: SA-11→CCI-003173, RA-5→CCI-001643
      expect(req.tags?.cci).toEqual(['CCI-001643', 'CCI-003173']);
    });

    it('should include descriptions for vulnerability, fix, and check', async () => {
      const input = loadFixture('amazon.json');
      const output = await convertGrypeToHdf(input);
      const hdf = parseJSON<HDFResults>(output);

      const req = hdf.baselines[0].requirements[0];
      expect(req.descriptions).toBeDefined();
      expect(req.descriptions?.length).toBeGreaterThanOrEqual(3);

      const defaultDesc = req.descriptions?.find(d => d.label === 'default');
      const fixDesc = req.descriptions?.find(d => d.label === 'fix');
      const checkDesc = req.descriptions?.find(d => d.label === 'check');

      expect(defaultDesc).toBeDefined();
      expect(fixDesc).toBeDefined();
      expect(checkDesc).toBeDefined();
    });

    it('should include references from vulnerability URLs', async () => {
      const input = loadFixture('amazon.json');
      const output = await convertGrypeToHdf(input);
      const hdf = parseJSON<HDFResults>(output);

      // First match (ALAS-2024-2607) has URLs including the ALAS advisory URL
      const req = hdf.baselines[0].requirements[0];
      expect(req.refs).toBeDefined();
      expect(req.refs!.length).toBeGreaterThan(0);
      expect(req.refs![0].url).toBeDefined();
    });

    it('should calculate SHA256 checksum of input', async () => {
      const input = loadFixture('amazon.json');
      const output = await convertGrypeToHdf(input);
      const hdf = parseJSON<HDFResults>(output);

      const baseline = hdf.baselines[0];
      expect(baseline.resultsChecksum).toBeDefined();
      expect(baseline.resultsChecksum?.algorithm).toBe('sha256');
      expect(baseline.resultsChecksum?.value).toMatch(/^[a-f0-9]{64}$/);
    });

    it('should handle fix information correctly', async () => {
      const input = loadFixture('amazon.json');
      const output = await convertGrypeToHdf(input);
      const hdf = parseJSON<HDFResults>(output);

      // ALAS-2024-2607 has fix state "fixed" with version "2023.2.68-1.amzn2.0.1"
      const alas2607 = hdf.baselines[0].requirements.find(r => r.id === 'Grype/ALAS-2024-2607');
      const fixDesc = alas2607?.descriptions?.find(d => d.label === 'fix');

      expect(fixDesc?.data).toContain('vulnerability is fixed');
      expect(fixDesc?.data).toContain('2023.2.68-1.amzn2.0.1');
    });

    it('should include code description with package details', async () => {
      const input = loadFixture('amazon.json');
      const output = await convertGrypeToHdf(input);
      const hdf = parseJSON<HDFResults>(output);

      // First match is ca-certificates rpm package
      const req = hdf.baselines[0].requirements[0];
      expect(req.results[0].codeDesc).toContain('Package:');
      expect(req.results[0].codeDesc).toContain('Type:');
      expect(req.results[0].codeDesc).toContain('Location:');
    });

    it('should handle missing optional fields gracefully', async () => {
      const minimalReport = JSON.stringify({
        descriptor: {
          name: 'grype',
          version: '1.0.0'
        },
        source: {
          target: {
            userInput: 'test-image'
          }
        },
        matches: []
      });

      const output = await convertGrypeToHdf(minimalReport);
      const hdf = parseJSON<HDFResults>(output);

      expect(hdf.baselines).toHaveLength(1);
      const reqs = hdf.baselines[0].requirements;
      expect(reqs).toHaveLength(1);
      expect(reqs[0].id).toBe('grype-no-findings');
      expect(reqs[0].results[0].status).toBe('passed');
      expect(reqs[0].results[0].codeDesc).toContain('Grype');
      expect(reqs[0].results[0].codeDesc).toContain('test-image');
    });

    it('synthesizes a passed placeholder for empty fixture', async () => {
      const input = loadFixture('empty.json');
      const output = await convertGrypeToHdf(input);
      const hdf = parseJSON<HDFResults>(output);

      expect(hdf.baselines).toHaveLength(1);
      const reqs = hdf.baselines[0].requirements;
      expect(reqs).toHaveLength(1);
      expect(reqs[0].id).toBe('grype-no-findings');
      expect(reqs[0].results[0].status).toBe('passed');
      expect(reqs[0].results[0].codeDesc).toContain('Grype');
      expect(reqs[0].results[0].codeDesc).toContain('alpine:3.20');
    });

    it('should populate CVE-ecosystem fields from enriched Grype output', async () => {
      // Inline fixture: the static sample fixtures predate Grype's EPSS/KEV
      // enrichment, so they never exercise buildEpss/buildKev/extractCwe. This
      // input follows the anchore/grype JSON output shape (vulnerability.epss[],
      // vulnerability.kev, vulnerability.cwe[]) for a real CVE (Log4Shell).
      const enriched = JSON.stringify({
        descriptor: {name: 'grype', version: '0.85.0'},
        source: {target: {userInput: 'enriched-image'}},
        matches: [{
          vulnerability: {
            id: 'CVE-2021-44228',
            severity: 'Critical',
            urls: ['https://nvd.nist.gov/vuln/detail/CVE-2021-44228'],
            description: 'Log4Shell remote code execution',
            cvss: [{
              source: 'nvd@nist.gov',
              type: 'Primary',
              version: '3.1',
              vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',
              metrics: {baseScore: 10.0},
            }],
            cwe: ['CWE-502', 'not-a-cwe', 'CWE-917'],
            epss: [{cve: 'CVE-2021-44228', epss: 0.97, percentile: 0.999, date: '2026-05-26'}],
            kev: {inKev: true, dateAdded: '2021-12-10', dueDate: '2021-12-24', notes: 'Apply vendor updates'},
            fix: {state: 'fixed', versions: ['2.17.0']},
          },
          matchDetails: [{type: 'exact-direct-match', matcher: 'java-matcher'}],
          artifact: {
            name: 'log4j-core',
            version: '2.14.1',
            type: 'java-archive',
            purl: 'pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1',
            cpes: ['cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*'],
          },
        }],
      });

      const output = await convertGrypeToHdf(enriched);
      const hdf = parseJSON<HDFResults>(output);
      const req = hdf.baselines[0].requirements.find(r => r.id === 'Grype/CVE-2021-44228');
      expect(req).toBeDefined();

      // cwe[] — malformed entry dropped, valid IDs kept.
      expect(req?.cwe).toEqual(['CWE-502', 'CWE-917']);
      // epss
      expect(req?.epss?.score).toBe(0.97);
      expect(req?.epss?.percentile).toBe(0.999);
      expect(req?.epss?.date).toBe('2026-05-26');
      // kev
      expect(req?.kev?.inKev).toBe(true);
      expect(req?.kev?.dateAdded).toBe('2021-12-10');
      expect(req?.kev?.dueDate).toBe('2021-12-24');
      expect(req?.kev?.notes).toBe('Apply vendor updates');
      // cvss[]
      expect(req?.cvss?.[0].baseScore).toBe(10.0);
      // affectedPackages[] — purl, cpe, and fixedInVersion all populated.
      const pkg = req?.affectedPackages?.[0];
      expect(pkg?.name).toBe('log4j-core');
      expect(pkg?.purl).toContain('pkg:maven');
      expect(pkg?.cpe).toContain('cpe:2.3:a:apache:log4j');
      expect(pkg?.fixedInVersion).toBe('2.17.0');
    });

    it('should omit epss when the entry has no date', async () => {
      // buildEpss returns undefined when the newest entry lacks a publish date.
      const noDate = JSON.stringify({
        descriptor: {name: 'grype', version: '0.85.0'},
        source: {target: {userInput: 'img'}},
        matches: [{
          vulnerability: {
            id: 'CVE-2024-9999',
            severity: 'Medium',
            epss: [{cve: 'CVE-2024-9999', epss: 0.1, percentile: 0.5}],
          },
          matchDetails: [{type: 'exact-direct-match', matcher: 'rpm-matcher'}],
          artifact: {name: 'pkg', version: '1.0.0', type: 'rpm'},
        }],
      });
      const output = await convertGrypeToHdf(noDate);
      const hdf = parseJSON<HDFResults>(output);
      const req = hdf.baselines[0].requirements.find(r => r.id === 'Grype/CVE-2024-9999');
      expect(req?.epss).toBeUndefined();
    });

    it('should emit cvss entries with only the present base fields', async () => {
      // First cvss entry: score but no vector -> baseVector omitted (an empty
      // vector would fail the schema pattern). Second: vector but no score ->
      // baseScore omitted (not coerced to 0).
      const report = JSON.stringify({
        descriptor: {name: 'grype', version: '0.85.0'},
        source: {target: {userInput: 'img'}},
        matches: [{
          vulnerability: {
            id: 'CVE-2024-2222',
            severity: 'High',
            cvss: [
              {version: '3.1', metrics: {baseScore: 7.5}},
              {version: '3.1', vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N'},
            ],
          },
          matchDetails: [{type: 'exact-direct-match', matcher: 'rpm-matcher'}],
          artifact: {name: 'pkg', version: '1.0.0', type: 'rpm'},
        }],
      });
      const output = await convertGrypeToHdf(report);
      const hdf = parseJSON<HDFResults>(output);
      const req = hdf.baselines[0].requirements.find(r => r.id === 'Grype/CVE-2024-2222');
      expect(req?.cvss).toHaveLength(2);
      expect(req?.cvss?.[0].baseScore).toBe(7.5);
      expect(req?.cvss?.[0].baseVector).toBeUndefined();
      expect(req?.cvss?.[1].baseVector).toContain('AV:N');
      expect(req?.cvss?.[1].baseScore).toBeUndefined();
    });

    it('should handle sparse CVE-ecosystem fields', async () => {
      // kev with only inKev set, all-malformed cwe[] (dropped -> undefined), and
      // an epss entry missing score/percentile (coalesced to 0). Exercises the
      // negative branches of buildKev/extractCwe/buildEpss.
      const sparse = JSON.stringify({
        descriptor: {name: 'grype', version: '0.85.0'},
        source: {target: {userInput: 'img'}},
        matches: [{
          vulnerability: {
            id: 'CVE-2024-1111',
            severity: 'Low',
            cwe: ['not-a-cwe', 'GHSA-xxxx'],
            epss: [{cve: 'CVE-2024-1111', date: '2026-05-26'}],
            kev: {inKev: false},
          },
          matchDetails: [{type: 'exact-direct-match', matcher: 'rpm-matcher'}],
          artifact: {name: 'pkg', version: '1.0.0', type: 'rpm'},
        }],
      });
      const output = await convertGrypeToHdf(sparse);
      const hdf = parseJSON<HDFResults>(output);
      const req = hdf.baselines[0].requirements.find(r => r.id === 'Grype/CVE-2024-1111');
      expect(req).toBeDefined();
      // all-malformed cwe -> field omitted
      expect(req?.cwe).toBeUndefined();
      // epss present (has date) but score/percentile defaulted to 0
      expect(req?.epss?.score).toBe(0);
      expect(req?.epss?.percentile).toBe(0);
      // kev present with only inKev
      expect(req?.kev?.inKev).toBe(false);
      expect(req?.kev?.dateAdded).toBeUndefined();
    });

    it('maps a None severity to 0.0 impact via the shared standard map (Go parity)', async () => {
      const input = JSON.stringify({
        descriptor: {name: 'grype', version: '0.85.0'},
        source: {target: {userInput: 'img'}},
        matches: [{
          vulnerability: {id: 'CVE-2024-2222', severity: 'None'},
          matchDetails: [{type: 'exact-direct-match', matcher: 'rpm-matcher'}],
          artifact: {name: 'pkg', version: '1.0.0', type: 'rpm'},
        }],
      });
      const hdf = parseJSON<HDFResults>(await convertGrypeToHdf(input));
      const req = hdf.baselines[0].requirements.find(r => r.id === 'Grype/CVE-2024-2222');
      expect(req).toBeDefined();
      expect(req!.impact).toBe(0.0);
    });

    it('anchors result start_time to the scan timestamp, falling back to Go zero time when absent', async () => {
      const input = loadFixture('amazon.json');
      const hdf = parseJSON<HDFResults>(await convertGrypeToHdf(input));
      // amazon.json carries descriptor.timestamp 2024-08-29T13:47:41.623667-04:00 → UTC.
      expect(hdf.baselines[0].requirements[0].results[0].startTime).toBe('2024-08-29T17:47:41.623Z');

      // No descriptor.timestamp → schema-safe Go zero time.
      const noTs = JSON.stringify({...JSON.parse(input), descriptor: {name: 'grype', version: '0.79.3'}});
      const fallback = parseJSON<HDFResults>(await convertGrypeToHdf(noTs));
      expect(fallback.baselines[0].requirements[0].results[0].startTime).toMatch(/^0001-01-01T00:00:00(\.000)?Z$/);
    });

    it('titles each requirement with the CVE and the scan target', async () => {
      const input = loadFixture('amazon.json');
      const hdf = parseJSON<HDFResults>(await convertGrypeToHdf(input));
      const req = hdf.baselines[0].requirements[0];
      expect(req.title).toMatch(/^Grype found a vulnerability to .+ in cloudwatch_to_s3:latest$/);
    });
  });
});

// Pins the containerImage component surfaced from source.target + distro for an
// image scan, and the artifact fallback when the scan carries no image identity.
describe('grype-to-hdf scan-target component', () => {
  it('emits a containerImage component from source.target + distro', async () => {
    const input = loadFixture('anchore_grype.json');
    const result = parseJSON<HDFResults>(await convertGrypeToHdf(input));
    expect(result.components).toHaveLength(1);
    const c = result.components![0]!;
    const wantRepoDigest =
      'golang@sha256:3f8e3ad3e7c128d29ac3004ac8314967c5ddbfa5bfa7caa59b0de493fc01686a';
    expect(c.type).toBe('containerImage');
    expect(c.name).toBe(wantRepoDigest);
    expect(c.imageId).toBe(
      'sha256:9d993b748f324b8291a4f202c2bc07b3485f7b9c7c799ee8925f657a760749cd',
    );
    expect(c.image).toBe(wantRepoDigest);
    expect(c.osName).toBe('alpine');
    expect(c.osVersion).toBe('3.11.3');
    expect(c.integrity).toEqual([
      {
        algorithm: 'sha256',
        // manifestDigest with the "sha256:" prefix stripped.
        value: '5b6d42c254b9928b3cbc541bbcd52c6e91b239d2246e8e6f9825246980ed1664',
      },
    ]);
    expect(c.labels).toEqual({architecture: 'arm64'});
  });

  it('falls back to a bare artifact component with no image identity', async () => {
    const input = JSON.stringify({
      descriptor: {name: 'grype', version: '0.74.0'},
      source: {type: 'directory', target: {userInput: 'dir:/app'}},
      matches: [],
    });
    const result = parseJSON<HDFResults>(await convertGrypeToHdf(input));
    expect(result.components).toHaveLength(1);
    const c = result.components![0]!;
    expect(c.type).toBe('artifact');
    expect(c.name).toBe('dir:/app');
    expect(c.imageId).toBeUndefined();
    expect(c.image).toBeUndefined();
    expect(c.osName).toBeUndefined();
    expect(c.integrity).toBeUndefined();
    expect(c.labels).toBeUndefined();
  });
});

describe('grype-to-hdf sha512 manifest digest (fpx5 regression)', () => {
  it('labels a sha512 manifest digest correctly with the prefix stripped', async () => {
    const report = JSON.stringify({
      matches: [],
      source: {target: {userInput: 'img', manifestDigest: 'sha512:deadbeef'}},
      descriptor: {name: 'grype', version: '0.1.0'},
    });
    const hdf = JSON.parse(await convertGrypeToHdf(report)) as HDFResults;
    expect(hdf.components?.[0].integrity).toEqual([{algorithm: 'sha512', value: 'deadbeef'}]);
  });
});

describe('unknown-severity convention', () => {
  it('keeps detected vulns failed and marks unrated severities, negligible stays a rating', async () => {
    // Agreed rule: severity never changes status. Unrated (Unknown/absent) ->
    // failed @ 0.5 + severity_rating=unrated tag; negligible -> failed @ 0.0,
    // untagged. Manual-review message preserved.
    const report = JSON.stringify({
      descriptor: {name: 'grype', version: '0.79.3'},
      source: {target: {userInput: 'test-image'}},
      matches: [
        {vulnerability: {id: 'CVE-UNKNOWN', severity: 'Unknown'}, artifact: {name: 'a', version: '1'}},
        {vulnerability: {id: 'CVE-ABSENT'}, artifact: {name: 'b', version: '1'}},
        {vulnerability: {id: 'CVE-NEGLIGIBLE', severity: 'Negligible'}, artifact: {name: 'c', version: '1'}},
        {vulnerability: {id: 'CVE-HIGH', severity: 'High'}, artifact: {name: 'd', version: '1'}},
      ],
    });
    const hdf = JSON.parse(await convertGrypeToHdf(report)) as HDFResults;
    const reqs = hdf.baselines[0].requirements;
    const byId = (id: string) => {
      const r = reqs.find((x) => x.id === id);
      expect(r, id).toBeDefined();
      return r!;
    };

    for (const [id, impact, unrated] of [
      ['Grype/CVE-UNKNOWN', 0.5, true],
      ['Grype/CVE-ABSENT', 0.5, true],
      ['Grype/CVE-NEGLIGIBLE', 0.0, false],
      ['Grype/CVE-HIGH', 0.7, false],
    ] as const) {
      const req = byId(id);
      expect(req.results[0].status, id).toBe('failed');
      expect(req.impact, id).toBe(impact);
      if (unrated) {
        expect(req.tags, id).toMatchObject({severity_rating: 'unrated'});
      } else {
        expect(req.tags, id).not.toHaveProperty('severity_rating');
      }
    }

    for (const id of ['Grype/CVE-UNKNOWN', 'Grype/CVE-ABSENT', 'Grype/CVE-NEGLIGIBLE']) {
      expect(byId(id).results[0].message, id).toContain('Manual review required');
    }
  });
});
