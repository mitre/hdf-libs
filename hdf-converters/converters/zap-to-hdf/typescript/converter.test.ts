import {readFileSync} from 'fs';
import {dirname, join} from 'path';
import {fileURLToPath} from 'url';
import {describe, expect, it} from 'vitest';
import {convertZapToHdf} from './converter';
import {runConverterContractTests} from '../../../shared/typescript/converter-contract.js';
import {expectValidResults} from '../../../test/helpers/expectValidHdf.js';
import {assertRequirementCount} from '../../../shared/typescript/anchor.js';
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

// countAllSiteAlerts parses raw ZAP JSON generically — NOT via the converter's
// parser — and returns the total alert count across EVERY site. The converter
// emits one requirement per alert of every site (the pluginid dedup only
// uniquifies IDs within a site, it does not collapse alerts), so a silent
// per-site drop fails this anchor even when Go/TS agree.
function countAllSiteAlerts(input: string): number {
  const doc = JSON.parse(input) as {site?: Array<{alerts?: unknown[]}>};
  return (doc.site ?? []).reduce((total, s) => total + (s.alerts?.length ?? 0), 0);
}

// Ground-truth anchor (input-derived count; see shared/typescript/anchor.ts):
// the converter emits one requirement per alert of EVERY site, counted
// independently of the converter's parser so a silent per-site drop fails even
// when Go/TS agree. webgoat.json carries 28 alerts across all 4 sites (the old
// single-site behavior dropped 3).
describe('zap-to-hdf ground-truth anchor', () => {
  it('emits one requirement per alert across all sites', async () => {
    const input = loadFixture('webgoat.json');
    assertRequirementCount(
      await convertZapToHdf(input),
      countAllSiteAlerts(input),
      'webgoat.json: one requirement per alert across all sites',
    );
  });
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

    it('should set dataSource name to "OWASP ZAP" with no format', async () => {
      const input = loadFixture('minimal.json');
      const output = await convertZapToHdf(input);
      const hdf = parseJSON<HDFResults>(output);

      expect(hdf.tool?.name).toBe('OWASP ZAP');
      expect(hdf.tool?.format).toBeUndefined() // serialization structures are not formats (kpvj);
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

      expect(hdf.timestamp).toBe('2018-12-06T10:53:11Z');
    });

    it('parses a non-RFC1123 (ISO) @generated via the shared parser as UTC', async () => {
      const doc = JSON.parse(loadFixture('minimal.json'));
      doc['@generated'] = '2020-05-01T12:00:00'; // zone-less ISO -> UTC
      const hdf = parseJSON<HDFResults>(await convertZapToHdf(JSON.stringify(doc)));
      expect(hdf.timestamp).toBe('2020-05-01T12:00:00Z');
    });

    it('omits the document timestamp when @generated is unparseable', async () => {
      const doc = JSON.parse(loadFixture('minimal.json'));
      doc['@generated'] = 'not-a-date';
      const hdf = parseJSON<HDFResults>(await convertZapToHdf(JSON.stringify(doc)));
      expect(hdf.timestamp).toBeUndefined();
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

  describe('cwe', () => {
    it('should promote cweid to first-class cwe[] and drop the cweid tag', async () => {
      const input = loadFixture('minimal.json');
      const output = await convertZapToHdf(input);
      const hdf = parseJSON<HDFResults>(output);

      const req = hdf.baselines[0].requirements.find(r => r.id === '10021');
      expect(req?.cwe).toEqual(['CWE-16']);
      expect(req?.tags?.cweid).toBeUndefined();
    });

    it('should omit cwe[] when the alert carries an empty cweid', async () => {
      const input = loadFixture('minimal.json');
      const output = await convertZapToHdf(input);
      const hdf = parseJSON<HDFResults>(output);

      // Alert 90022 in minimal.json has an empty cweid.
      const req = hdf.baselines[0].requirements.find(r => r.id === '90022');
      expect(req?.cwe).toBeUndefined();
      expect(req?.tags?.cweid).toBeUndefined();
    });

    it('should omit cwe[] for a non-numeric cweid', async () => {
      const zap = {
        '@version': '2.7.0',
        site: [{'@host': 'example.com', alerts: [{pluginid: '1', name: 'X', cweid: 'abc'}]}],
      };
      const output = await convertZapToHdf(JSON.stringify(zap));
      const hdf = parseJSON<HDFResults>(output);
      expect(hdf.baselines[0].requirements[0].cwe).toBeUndefined();
    });
  });

  describe('extra tags', () => {
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

  // requirement.code is synthesized from the representative instance's HTTP
  // request context: "<METHOD> <uri>" + optional "Param:" + optional "Attack:".
  // The representative instance is the first carrying an attack payload (else the
  // first instance), so the DAST payload surfaces on the CODE tab.
  describe('requirement code (CODE tab)', () => {
    async function firstReqCode(zap: unknown): Promise<string | undefined> {
      const output = await convertZapToHdf(JSON.stringify(zap));
      const hdf = parseJSON<HDFResults>(output);
      return hdf.baselines[0].requirements[0].code;
    }

    it('falls back to the first instance when none carry an attack', async () => {
      const input = loadFixture('minimal.json');
      const hdf = parseJSON<HDFResults>(await convertZapToHdf(input));
      const req = hdf.baselines[0].requirements.find(r => r.id === '10021');
      expect(req?.code).toBe('GET https://example.com/login\nParam: X-Content-Type-Options');
    });

    it('prefers the instance carrying the attack payload', async () => {
      const input = loadFixture('minimal.json');
      const hdf = parseJSON<HDFResults>(await convertZapToHdf(input));
      const req = hdf.baselines[0].requirements.find(r => r.id === '90022');
      expect(req?.code).toBe("POST https://example.com/api/login\nParam: username\nAttack: ' OR 1=1 --");
    });

    it('leaves code unset when the alert has no instances (NOT-IN-SOURCE)', async () => {
      const code = await firstReqCode({site: [{'@host': 'h', alerts: [{pluginid: '1', name: 'n'}]}]});
      expect(code).toBeUndefined();
    });

    it('leaves code unset when the instance carries no request context', async () => {
      const code = await firstReqCode({site: [{'@host': 'h', alerts: [{pluginid: '1', name: 'n', instances: [{}]}]}]});
      expect(code).toBeUndefined();
    });

    it('emits the request line only when there is no param or attack', async () => {
      const code = await firstReqCode({site: [{'@host': 'h', alerts: [{pluginid: '1', name: 'n', instances: [{method: 'GET', uri: '/x'}]}]}]});
      expect(code).toBe('GET /x');
    });

    it('emits a Param line with no request line when only param is present', async () => {
      const code = await firstReqCode({site: [{'@host': 'h', alerts: [{pluginid: '1', name: 'n', instances: [{param: 'p'}]}]}]});
      expect(code).toBe('Param: p');
    });

    it('emits an Attack line with no request line when only attack is present', async () => {
      const code = await firstReqCode({site: [{'@host': 'h', alerts: [{pluginid: '1', name: 'n', instances: [{attack: 'a'}]}]}]});
      expect(code).toBe('Attack: a');
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
    // mymacBaseline returns the per-site baseline for host mymac.com (busiest site).
    const mymacBaseline = (hdf: HDFResults) => {
      const b = hdf.baselines.find(b => b.labels?.component === 'mymac.com');
      expect(b, 'no baseline for host mymac.com').toBeDefined();
      return b!;
    };

    it('converts every site to its own baseline + component (no site dropped)', async () => {
      const input = loadFixture('webgoat.json');
      const output = await convertZapToHdf(input);
      const hdf = parseJSON<HDFResults>(output);

      expect(hdf.baselines).toHaveLength(4);
      expect(hdf.components).toHaveLength(4);
      const hosts = hdf.components!.map(c => c.name);
      expect(hosts).toContain('mymac.com');
      expect(hosts).toContain('ciscobinary.openh264.org');
      expect(hosts).toContain('code.jquery.com');
      expect(hosts).toContain('detectportal.firefox.com');
      for (const c of hdf.components!) {
        expect(c.type).toBe('application');
      }
    });

    it('links each baseline to its host and gives it a unique, host-scoped name', async () => {
      const input = loadFixture('webgoat.json');
      const output = await convertZapToHdf(input);
      const hdf = parseJSON<HDFResults>(output);

      const names = new Set<string>();
      for (const b of hdf.baselines) {
        const host = b.labels?.component;
        expect(host, `baseline ${b.name} missing component label`).toBeTruthy();
        expect(names.has(b.name), `baseline name ${b.name} not unique`).toBe(false);
        names.add(b.name);
        expect(b.name).toContain(host!);
      }
    });

    it('keeps the shared pluginid 10021 undeduped across the single-alert hosts', async () => {
      const input = loadFixture('webgoat.json');
      const output = await convertZapToHdf(input);
      const hdf = parseJSON<HDFResults>(output);

      const singles = hdf.baselines.filter(b => b.labels?.component !== 'mymac.com');
      expect(singles).toHaveLength(3);
      for (const b of singles) {
        expect(b.requirements).toHaveLength(1);
        expect(b.requirements[0].id).toBe('10021');
      }
    });

    it('produces 25 requirements for mymac.com', async () => {
      const input = loadFixture('webgoat.json');
      const output = await convertZapToHdf(input);
      const hdf = parseJSON<HDFResults>(output);

      // 25 alerts, 15 unique pluginids, duplicates get .1, .2, etc.
      expect(mymacBaseline(hdf).requirements).toHaveLength(25);
    });

    it('should deduplicate pluginids with .1, .2 suffixes', async () => {
      const input = loadFixture('webgoat.json');
      const output = await convertZapToHdf(input);
      const hdf = parseJSON<HDFResults>(output);

      const ids = mymacBaseline(hdf).requirements.map(r => r.id);
      expect(ids).toContain('90028');
      expect(ids).toContain('90028.1');
      expect(ids).toContain('90028.2');
    });

    it('should set timestamp from @generated', async () => {
      const input = loadFixture('webgoat.json');
      const output = await convertZapToHdf(input);
      const hdf = parseJSON<HDFResults>(output);

      expect(hdf.timestamp).toBe('2018-12-06T10:53:11Z');
    });

    it('should map riskcode 0 to impact 0.3', async () => {
      const input = loadFixture('webgoat.json');
      const output = await convertZapToHdf(input);
      const hdf = parseJSON<HDFResults>(output);

      const req = mymacBaseline(hdf).requirements.find(r => r.id === '90028');
      expect(req?.impact).toBe(0.3);
    });

    it('should map riskcode 3 to impact 0.7', async () => {
      const input = loadFixture('webgoat.json');
      const output = await convertZapToHdf(input);
      const hdf = parseJSON<HDFResults>(output);

      const req = mymacBaseline(hdf).requirements.find(r => r.id === '42');
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
