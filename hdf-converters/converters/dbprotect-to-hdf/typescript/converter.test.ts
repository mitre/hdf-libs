import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { describe, it, expect } from 'vitest';
import { convertDbprotectToHdf } from './converter.js';
import { runConverterContractTests } from '../../../shared/typescript/converter-contract.js';
import { expectValidResults } from '../../../test/helpers/expectValidHdf.js';
import { assertRequirementCount } from '../../../shared/typescript/anchor.js';
import type { HDFResults } from '@mitre/hdf-schema';

const __dirname = dirname(fileURLToPath(import.meta.url));
const FIXTURES_DIR = join(__dirname, '..', 'fixtures');

function loadFixture(name: string): string {
  return readFileSync(join(FIXTURES_DIR, 'input', name), 'utf-8');
}

runConverterContractTests({
  converterName: 'dbprotect-to-hdf',
  convertFn: convertDbprotectToHdf,
  minimalFixture: 'sample-check-results.xml',
});

// Scans the raw Cognos XML generically — deliberately NOT the converter's parser
// — and returns the number of distinct "Check ID" values across all data rows.
// The "Check ID" column is located by its position among <metadata><item>
// elements, then the value at that index is read from each <data><row>. The
// converter emits one requirement per distinct Check ID (rows sharing an id are
// grouped), so the distinct count is the ground truth.
function countDistinctCheckIds(input: string): number {
  const meta = input.slice(input.indexOf('<metadata'), input.indexOf('</metadata>'));
  const names = [...meta.matchAll(/<item\b[^>]*\bname="([^"]*)"/g)].map((m) => m[1]);
  const idx = names.indexOf('Check ID');
  if (idx < 0) throw new Error('fixture lacks a Check ID column');

  const distinct = new Set<string>();
  for (const rowMatch of input.matchAll(/<row>([\s\S]*?)<\/row>/g)) {
    const values = [...rowMatch[1].matchAll(/<value>([\s\S]*?)<\/value>/g)].map((m) => m[1].trim());
    if (idx < values.length) distinct.add(values[idx]);
  }
  return distinct.size;
}

// Ground-truth anchor (input-derived count; see shared/typescript/anchor.ts):
// one requirement per distinct Check ID.
describe('dbprotect-to-hdf ground-truth anchor', () => {
  it('emits one requirement per distinct Check ID (check-results)', async () => {
    const input = loadFixture('sample-check-results.xml');
    assertRequirementCount(
      await convertDbprotectToHdf(input),
      countDistinctCheckIds(input),
      'sample-check-results.xml: one requirement per distinct Check ID',
    );
  });
});

describe('dbprotect to HDF converter', () => {
  describe('check results details', () => {
    it('should produce valid HDF from check results fixture', async () => {
      const output = await convertDbprotectToHdf(loadFixture('sample-check-results.xml'));
      const hdf = JSON.parse(output) as HDFResults;
      expectValidResults(hdf);

      expect(hdf.timestamp).toBeTruthy();
      expect(hdf.generator?.name).toBe('dbprotect-to-hdf');
      expect(hdf.generator?.version).toBe('1.0.0');
      expect(hdf.baselines).toHaveLength(1);
    });

    it('should use "DBProtect Scan" as the baseline name', async () => {
      const hdf = JSON.parse(await convertDbprotectToHdf(loadFixture('sample-check-results.xml'))) as HDFResults;
      expect(hdf.baselines[0]!.name).toBe('DBProtect Scan');
    });

    it('should include baseline title with job name', async () => {
      const hdf = JSON.parse(await convertDbprotectToHdf(loadFixture('sample-check-results.xml'))) as HDFResults;
      expect(hdf.baselines[0]!.title).toContain('Heimdal Test scan report generation');
    });

    it('should include baseline summary with asset info', async () => {
      const hdf = JSON.parse(await convertDbprotectToHdf(loadFixture('sample-check-results.xml'))) as HDFResults;
      expect(hdf.baselines[0]!.summary).toContain('Organization');
      expect(hdf.baselines[0]!.summary).toContain('CONDS181');
    });

    it('should include a sha256 checksum', async () => {
      const hdf = JSON.parse(await convertDbprotectToHdf(loadFixture('sample-check-results.xml'))) as HDFResults;
      const checksum = hdf.baselines[0]!.resultsChecksum;
      expect(checksum?.algorithm).toBe('sha256');
      expect(checksum?.value).toMatch(/^[a-f0-9]{64}$/);
    });

    it('should set tool name to "DBProtect" with no format', async () => {
      const hdf = JSON.parse(await convertDbprotectToHdf(loadFixture('sample-check-results.xml'))) as HDFResults;
      expect(hdf.tool?.name).toBe('DBProtect');
      expect(hdf.tool?.format).toBeUndefined() // serialization structures are not formats (kpvj);
    });

    it('should have 6 unique requirements from 8 rows', async () => {
      const hdf = JSON.parse(await convertDbprotectToHdf(loadFixture('sample-check-results.xml'))) as HDFResults;
      // 8 rows with 6 unique Check IDs: 2986 (2), 2903, 2841, 2801 (2), 2942, 2976
      expect(hdf.baselines[0]!.requirements).toHaveLength(6);
    });

    it('should group results by Check ID', async () => {
      const hdf = JSON.parse(await convertDbprotectToHdf(loadFixture('sample-check-results.xml'))) as HDFResults;
      const req2986 = hdf.baselines[0]!.requirements.find(r => r.id === '2986');
      expect(req2986).toBeDefined();
      expect(req2986!.results).toHaveLength(2);

      const req2801 = hdf.baselines[0]!.requirements.find(r => r.id === '2801');
      expect(req2801).toBeDefined();
      expect(req2801!.results).toHaveLength(2);
    });

    it('should set requirement title from Check column', async () => {
      const hdf = JSON.parse(await convertDbprotectToHdf(loadFixture('sample-check-results.xml'))) as HDFResults;
      const req = hdf.baselines[0]!.requirements.find(r => r.id === '2986');
      expect(req?.title).toBe('Schema ownership');
    });

    it('should set description with task and category', async () => {
      const hdf = JSON.parse(await convertDbprotectToHdf(loadFixture('sample-check-results.xml'))) as HDFResults;
      const req = hdf.baselines[0]!.requirements.find(r => r.id === '2986');
      expect(req?.descriptions).toBeDefined();
      expect(req!.descriptions!.length).toBeGreaterThan(0);
      const defaultDesc = req!.descriptions!.find(d => d.label === 'default');
      expect(defaultDesc).toBeDefined();
      expect(defaultDesc!.data).toContain('Task');
      expect(defaultDesc!.data).toContain('Check Category');
    });
  });

  describe('requirement.code (Heimdall CODE tab)', () => {
    it('serializes the source row as indented, sorted-key JSON', async () => {
      const hdf = JSON.parse(await convertDbprotectToHdf(loadFixture('sample-check-results.xml'))) as HDFResults;
      const req = hdf.baselines[0]!.requirements.find(r => r.id === '2986');
      expect(req?.code).toBeTruthy();
      const code = req!.code!;

      // Two-space indented, not a compact blob.
      expect(code).toContain('\n  "Check": "Schema ownership"');

      // Round-trips back to the source row.
      const row = JSON.parse(code) as Record<string, string>;
      expect(row['Check']).toBe('Schema ownership');
      expect(row['Check Category']).toBe('Improper Access Controls');
      expect(row['Risk DV']).toBe('Medium');
      expect(row['Details']).toBe('Schema name=DatabaseMailUserRole;Database=msdb;Owner name=DatabaseMailUserRole');

      // Keys are emitted in sorted order (the byte-parity contract with the Go twin).
      const sorted = JSON.stringify(row, Object.keys(row).sort(), 2);
      expect(code).toBe(sorted);
    });

    it('populates code for every requirement in the Findings Detail report', async () => {
      const hdf = JSON.parse(await convertDbprotectToHdf(loadFixture('sample-findings-detail.xml'))) as HDFResults;
      for (const req of hdf.baselines[0]!.requirements) {
        expect(req.code).toBeTruthy();
        const row = JSON.parse(req.code!) as Record<string, string>;
        expect(row['Check']).toBeTruthy();
      }
    });
  });

  describe('impact mapping', () => {
    it('should map High risk to 0.7', async () => {
      const hdf = JSON.parse(await convertDbprotectToHdf(loadFixture('sample-check-results.xml'))) as HDFResults;
      const req = hdf.baselines[0]!.requirements.find(r => r.id === '2903');
      expect(req?.impact).toBe(0.7);
    });

    it('should map Medium risk to 0.5', async () => {
      const hdf = JSON.parse(await convertDbprotectToHdf(loadFixture('sample-check-results.xml'))) as HDFResults;
      const req = hdf.baselines[0]!.requirements.find(r => r.id === '2986');
      expect(req?.impact).toBe(0.5);
    });

    it('should map Low risk to 0.3', async () => {
      const hdf = JSON.parse(await convertDbprotectToHdf(loadFixture('sample-check-results.xml'))) as HDFResults;
      const req = hdf.baselines[0]!.requirements.find(r => r.id === '2841');
      expect(req?.impact).toBe(0.3);
    });

    it('should map Informational risk to 0.0', async () => {
      const hdf = JSON.parse(await convertDbprotectToHdf(loadFixture('sample-check-results.xml'))) as HDFResults;
      const req = hdf.baselines[0]!.requirements.find(r => r.id === '2801');
      expect(req?.impact).toBe(0.0);
    });
  });

  describe('status mapping', () => {
    it('should map Fact to notReviewed', async () => {
      const hdf = JSON.parse(await convertDbprotectToHdf(loadFixture('sample-check-results.xml'))) as HDFResults;
      const req = hdf.baselines[0]!.requirements.find(r => r.id === '2986');
      expect(req!.results[0]!.status).toBe('notReviewed');
    });

    it('should map Failed to failed', async () => {
      const hdf = JSON.parse(await convertDbprotectToHdf(loadFixture('sample-check-results.xml'))) as HDFResults;
      const req = hdf.baselines[0]!.requirements.find(r => r.id === '2841');
      expect(req!.results[0]!.status).toBe('failed');
    });

    it('should map Finding to failed', async () => {
      const hdf = JSON.parse(await convertDbprotectToHdf(loadFixture('sample-check-results.xml'))) as HDFResults;
      const req = hdf.baselines[0]!.requirements.find(r => r.id === '2801');
      expect(req!.results[0]!.status).toBe('failed');
    });

    it('should map Not A Finding to passed', async () => {
      const hdf = JSON.parse(await convertDbprotectToHdf(loadFixture('sample-check-results.xml'))) as HDFResults;
      const req = hdf.baselines[0]!.requirements.find(r => r.id === '2942');
      expect(req!.results[0]!.status).toBe('passed');
    });

    it('should map Skipped to notReviewed', async () => {
      const hdf = JSON.parse(await convertDbprotectToHdf(loadFixture('sample-check-results.xml'))) as HDFResults;
      const req = hdf.baselines[0]!.requirements.find(r => r.id === '2976');
      expect(req!.results[0]!.status).toBe('notReviewed');
    });
  });

  describe('backtrace (heimdall2 Failed-check marker)', () => {
    it('sets the marker on a source "Failed" result', async () => {
      const hdf = JSON.parse(await convertDbprotectToHdf(loadFixture('sample-check-results.xml'))) as HDFResults;
      const req = hdf.baselines[0]!.requirements.find(r => r.id === '2841');
      expect(req!.results[0]!.backtrace).toEqual(['DB Protect Failed Check']);
    });

    it('omits the marker on a source "Finding" result (HDF-failed, not literal Failed)', async () => {
      const hdf = JSON.parse(await convertDbprotectToHdf(loadFixture('sample-check-results.xml'))) as HDFResults;
      const req = hdf.baselines[0]!.requirements.find(r => r.id === '2801');
      for (const res of req!.results) {
        expect(res.backtrace).toBeUndefined();
      }
    });

    it('omits the marker on a passing result', async () => {
      const hdf = JSON.parse(await convertDbprotectToHdf(loadFixture('sample-check-results.xml'))) as HDFResults;
      const req = hdf.baselines[0]!.requirements.find(r => r.id === '2942');
      expect(req!.results[0]!.backtrace).toBeUndefined();
    });

    it('omits the marker on implicit-failed Findings Detail rows', async () => {
      const hdf = JSON.parse(await convertDbprotectToHdf(loadFixture('sample-findings-detail.xml'))) as HDFResults;
      for (const req of hdf.baselines[0]!.requirements) {
        for (const res of req.results) {
          expect(res.backtrace).toBeUndefined();
        }
      }
    });
  });

  describe('code description and start time', () => {
    it('should set codeDesc from Details column', async () => {
      const hdf = JSON.parse(await convertDbprotectToHdf(loadFixture('sample-check-results.xml'))) as HDFResults;
      const req = hdf.baselines[0]!.requirements.find(r => r.id === '2986');
      expect(req!.results[0]!.codeDesc).toContain('Schema name=DatabaseMailUserRole');
    });

    it('should set startTime from Date column', async () => {
      const hdf = JSON.parse(await convertDbprotectToHdf(loadFixture('sample-check-results.xml'))) as HDFResults;
      const req = hdf.baselines[0]!.requirements.find(r => r.id === '2986');
      expect(req!.results[0]!.startTime).toBe('2021-02-18T15:57:00Z');
    });

    it('normalizes an ISO-style Date column to UTC', async () => {
      const xml = loadFixture('sample-check-results.xml').replace(/Feb 18 2021 15:57/g, '2021-02-18 15:55');
      const hdf = JSON.parse(await convertDbprotectToHdf(xml)) as HDFResults;
      const req = hdf.baselines[0]!.requirements.find(r => r.id === '2986');
      expect(req!.results[0]!.startTime).toBe('2021-02-18T15:55:00Z');
    });

    it('falls back to the Go zero-value time when the Date column is empty', async () => {
      const xml = loadFixture('sample-check-results.xml').replace(/Feb 18 2021 15:57/g, '');
      const hdf = JSON.parse(await convertDbprotectToHdf(xml)) as HDFResults;
      const req = hdf.baselines[0]!.requirements.find(r => r.id === '2986');
      expect(req!.results[0]!.startTime).toBe('0001-01-01T00:00:00Z');
    });

    it('falls back to the Go zero-value time for an unrecognized month name', async () => {
      const xml = loadFixture('sample-check-results.xml').replace(/Feb 18 2021 15:57/g, 'Xyz 18 2021 15:57');
      const hdf = JSON.parse(await convertDbprotectToHdf(xml)) as HDFResults;
      const req = hdf.baselines[0]!.requirements.find(r => r.id === '2986');
      expect(req!.results[0]!.startTime).toBe('0001-01-01T00:00:00Z');
    });
  });

  describe('NIST tags', () => {
    it('should include default static analysis NIST tags', async () => {
      const hdf = JSON.parse(await convertDbprotectToHdf(loadFixture('sample-check-results.xml'))) as HDFResults;
      const req = hdf.baselines[0]!.requirements.find(r => r.id === '2986');
      expect(req?.tags).toBeDefined();
      const nist = req!.tags!['nist'] as string[];
      expect(nist).toBeDefined();
      expect(nist.length).toBeGreaterThan(0);
    });
  });

  describe('check_category tag', () => {
    it('surfaces the Check Category column as the check_category tag', async () => {
      const hdf = JSON.parse(await convertDbprotectToHdf(loadFixture('sample-check-results.xml'))) as HDFResults;
      const req = hdf.baselines[0]!.requirements.find(r => r.id === '2986');
      expect(req!.tags!['check_category']).toBe('Improper Access Controls');
      const req2903 = hdf.baselines[0]!.requirements.find(r => r.id === '2903');
      expect(req2903!.tags!['check_category']).toBe('Misconfigurations');
    });

    it('surfaces check_category in the Findings Detail report', async () => {
      const hdf = JSON.parse(await convertDbprotectToHdf(loadFixture('sample-findings-detail.xml'))) as HDFResults;
      const req = hdf.baselines[0]!.requirements.find(r => r.id === '2903');
      expect(req!.tags!['check_category']).toBe('Misconfigurations');
    });

    it('omits the check_category tag when the Check Category value is empty', async () => {
      const xml = `<?xml version="1.0"?><dataset><metadata><item><name>Check ID</name><type>xs:string</type></item><item><name>Check</name><type>xs:string</type></item><item><name>Risk DV</name><type>xs:string</type></item><item><name>Details</name><type>xs:string</type></item><item><name>Date</name><type>xs:string</type></item><item><name>Check Category</name><type>xs:string</type></item></metadata><data><row><value>CK1</value><value>Check</value><value>Low</value><value>Details</value><value>Feb 18 2021 15:57</value><value nil="true"/></row></data></dataset>`;
      const hdf = JSON.parse(await convertDbprotectToHdf(xml)) as HDFResults;
      const req = hdf.baselines[0]!.requirements[0];
      expect(req!.tags!['check_category']).toBeUndefined();
    });
  });

  describe('scan target component (database identity)', () => {
    it('builds a database component from the identity columns', async () => {
      const hdf = JSON.parse(await convertDbprotectToHdf(loadFixture('sample-check-results.xml'))) as HDFResults;
      expect(hdf.components).toHaveLength(1);
      const comp = hdf.components![0]!;
      expect(comp.type).toBe('database');
      expect(comp.name).toBe('MSSQLSERVER');
      expect(comp.ipAddress).toBe('10.0.10.204');
      expect(comp.port).toBe(1433);
      expect(comp.engine).toBe('Microsoft SQL Server');
      expect(comp.hostname).toBe('CONDS181');
    });

    it('builds the database component for the findings-detail report too', async () => {
      const hdf = JSON.parse(await convertDbprotectToHdf(loadFixture('sample-findings-detail.xml'))) as HDFResults;
      expect(hdf.components).toHaveLength(1);
      const comp = hdf.components![0]!;
      expect(comp.type).toBe('database');
      expect(comp.name).toBe('MSSQLSERVER');
      expect(comp.ipAddress).toBe('192.168.1.200');
      expect(comp.hostname).toBe('HOST1');
    });

    // Drive the name-fallback and absent branches through crafted single-row XML.
    // cols/vals are positional (Cognos maps metadata items to row values by index).
    const buildXml = (cols: string[], vals: string[]): string =>
      `<?xml version="1.0" encoding="utf-8"?>
<dataset xmlns="http://developer.cognos.com/schemas/xmldata/1/">
  <metadata>${cols.map((c) => `<item name="${c}" type="xs:string"/>`).join('')}</metadata>
  <data><row>${vals.map((v) => `<value>${v}</value>`).join('')}</row></data>
</dataset>`;

    it('names the component IP:Port when no instance is present', async () => {
      const xml = buildXml(['IP Address, Port, Instance', 'Check ID', 'Check'], ['10.0.10.204, 1433', '1', 'x']);
      const hdf = JSON.parse(await convertDbprotectToHdf(xml)) as HDFResults;
      expect(hdf.components![0]!.name).toBe('10.0.10.204:1433');
      expect(hdf.components![0]!.type).toBe('database');
    });

    it('names the component IP alone when neither instance nor port is present', async () => {
      const xml = buildXml(['IP Address, Port, Instance', 'Check ID', 'Check'], ['10.0.10.204', '1', 'x']);
      const hdf = JSON.parse(await convertDbprotectToHdf(xml)) as HDFResults;
      expect(hdf.components![0]!.name).toBe('10.0.10.204');
      expect(hdf.components![0]!.port).toBeUndefined();
    });

    it('names the component from the Asset label when the identity cell is empty', async () => {
      const xml = buildXml(['Asset', 'Check ID', 'Check'], ['CONDS181', '1', 'x']);
      const hdf = JSON.parse(await convertDbprotectToHdf(xml)) as HDFResults;
      expect(hdf.components![0]!.name).toBe('CONDS181');
      expect(hdf.components![0]!.hostname).toBe('CONDS181');
      expect(hdf.components![0]!.ipAddress).toBeUndefined();
    });

    it('drops a non-numeric port', async () => {
      const xml = buildXml(['IP Address, Port, Instance', 'Check ID', 'Check'], ['10.0.10.204, abc, INST', '1', 'x']);
      const hdf = JSON.parse(await convertDbprotectToHdf(xml)) as HDFResults;
      expect(hdf.components![0]!.name).toBe('INST');
      expect(hdf.components![0]!.port).toBeUndefined();
    });

    it('omits components entirely when no identity columns are present (NOT-IN-SOURCE)', async () => {
      const xml = buildXml(['Check ID', 'Check'], ['1', 'x']);
      const hdf = JSON.parse(await convertDbprotectToHdf(xml)) as HDFResults;
      expect(hdf.components).toBeUndefined();
    });
  });

  describe('findings detail', () => {
    it('should produce valid HDF from findings detail fixture', async () => {
      const hdf = JSON.parse(await convertDbprotectToHdf(loadFixture('sample-findings-detail.xml'))) as HDFResults;
      expect(hdf.baselines).toHaveLength(1);
      expect(hdf.baselines[0]!.name).toBe('DBProtect Scan');
    });

    it('should have 3 unique requirements from 4 rows', async () => {
      const hdf = JSON.parse(await convertDbprotectToHdf(loadFixture('sample-findings-detail.xml'))) as HDFResults;
      // 4 rows with 3 unique Check IDs: 2801 (2), 2830, 2903
      expect(hdf.baselines[0]!.requirements).toHaveLength(3);
    });

    it('should treat all findings as failed (no Result Status column)', async () => {
      const hdf = JSON.parse(await convertDbprotectToHdf(loadFixture('sample-findings-detail.xml'))) as HDFResults;
      for (const req of hdf.baselines[0]!.requirements) {
        for (const result of req.results) {
          expect(result.status).toBe('failed');
        }
      }
    });
  });

  describe('edge cases: status mapping and missing fields', () => {
    function makeXml(statusCol: boolean, statusVal: string, riskDV: string = 'High'): string {
      const items = statusCol
        ? '<item><name>Check ID</name><type>xs:string</type></item><item><name>Check</name><type>xs:string</type></item><item><name>Risk DV</name><type>xs:string</type></item><item><name>Result Status</name><type>xs:string</type></item><item><name>Details</name><type>xs:string</type></item><item><name>Date</name><type>xs:string</type></item><item><name>Task</name><type>xs:string</type></item><item><name>Check Category</name><type>xs:string</type></item><item><name>Organization</name><type>xs:string</type></item><item><name>Asset</name><type>xs:string</type></item><item><name>Asset Type</name><type>xs:string</type></item><item><name>IP Address, Port, Instance</name><type>xs:string</type></item><item><name>Job Name</name><type>xs:string</type></item>'
        : '<item><name>Check ID</name><type>xs:string</type></item><item><name>Check</name><type>xs:string</type></item><item><name>Risk DV</name><type>xs:string</type></item><item><name>Details</name><type>xs:string</type></item><item><name>Date</name><type>xs:string</type></item><item><name>Task</name><type>xs:string</type></item><item><name>Check Category</name><type>xs:string</type></item><item><name>Organization</name><type>xs:string</type></item><item><name>Asset</name><type>xs:string</type></item><item><name>Asset Type</name><type>xs:string</type></item><item><name>IP Address, Port, Instance</name><type>xs:string</type></item><item><name>Job Name</name><type>xs:string</type></item>';
      const values = statusCol
        ? `<value>CK1</value><value>Check name</value><value>${riskDV}</value><value>${statusVal}</value><value>Details text</value><value>Feb 18 2021 15:57</value><value>Task1</value><value>Cat1</value><value>Org1</value><value>Asset1</value><value>Database</value><value>10.0.0.1:3306</value><value>TestJob</value>`
        : `<value>CK1</value><value>Check name</value><value>${riskDV}</value><value>Details text</value><value>Feb 18 2021 15:57</value><value>Task1</value><value>Cat1</value><value>Org1</value><value>Asset1</value><value>Database</value><value>10.0.0.1:3306</value><value>TestJob</value>`;
      return `<?xml version="1.0"?><dataset><metadata>${items}</metadata><data><row>${values}</row></data></dataset>`;
    }

    it('should map Fact status to notReviewed', async () => {
      const hdf = JSON.parse(await convertDbprotectToHdf(makeXml(true, 'Fact'))) as HDFResults;
      expect(hdf.baselines[0]!.requirements[0]!.results[0]!.status).toBe('notReviewed');
    });

    it('should map Finding status to failed', async () => {
      const hdf = JSON.parse(await convertDbprotectToHdf(makeXml(true, 'Finding'))) as HDFResults;
      expect(hdf.baselines[0]!.requirements[0]!.results[0]!.status).toBe('failed');
    });

    it('should map Not A Finding status to passed', async () => {
      const hdf = JSON.parse(await convertDbprotectToHdf(makeXml(true, 'Not A Finding'))) as HDFResults;
      expect(hdf.baselines[0]!.requirements[0]!.results[0]!.status).toBe('passed');
    });

    it('should map Skipped/unknown status to notReviewed', async () => {
      const hdf = JSON.parse(await convertDbprotectToHdf(makeXml(true, 'Skipped'))) as HDFResults;
      expect(hdf.baselines[0]!.requirements[0]!.results[0]!.status).toBe('notReviewed');
    });

    it('should map medium risk to 0.5 impact', async () => {
      const hdf = JSON.parse(await convertDbprotectToHdf(makeXml(true, 'Failed', 'Medium'))) as HDFResults;
      expect(hdf.baselines[0]!.requirements[0]!.impact).toBe(0.5);
    });

    it('should map informational risk to 0.0 impact', async () => {
      const hdf = JSON.parse(await convertDbprotectToHdf(makeXml(true, 'Failed', 'Informational'))) as HDFResults;
      expect(hdf.baselines[0]!.requirements[0]!.impact).toBe(0.0);
    });

    it('should use 0.5 for unknown risk level', async () => {
      const hdf = JSON.parse(await convertDbprotectToHdf(makeXml(true, 'Failed', 'UnknownLevel'))) as HDFResults;
      expect(hdf.baselines[0]!.requirements[0]!.impact).toBe(0.5);
    });

    it('should tag severity_rating unrated for an empty Risk DV and omit it for rated values', async () => {
      const unrated = JSON.parse(await convertDbprotectToHdf(makeXml(true, 'Failed', ''))) as HDFResults;
      expect(unrated.baselines[0]!.requirements[0]!.tags!['severity_rating']).toBe('unrated');

      const rated = JSON.parse(await convertDbprotectToHdf(makeXml(true, 'Failed', 'High'))) as HDFResults;
      expect(rated.baselines[0]!.requirements[0]!.tags!['severity_rating']).toBeUndefined();

      // Informational is a rated tier, not unrated.
      const info = JSON.parse(await convertDbprotectToHdf(makeXml(true, 'Failed', 'Informational'))) as HDFResults;
      expect(info.baselines[0]!.requirements[0]!.tags!['severity_rating']).toBeUndefined();
    });

    it('should handle empty date gracefully', async () => {
      const xml = `<?xml version="1.0"?><dataset><metadata><item><name>Check ID</name><type>xs:string</type></item><item><name>Check</name><type>xs:string</type></item><item><name>Risk DV</name><type>xs:string</type></item><item><name>Details</name><type>xs:string</type></item><item><name>Date</name><type>xs:string</type></item><item><name>Task</name><type>xs:string</type></item><item><name>Check Category</name><type>xs:string</type></item><item><name>Organization</name><type>xs:string</type></item><item><name>Asset</name><type>xs:string</type></item><item><name>Asset Type</name><type>xs:string</type></item><item><name>IP Address, Port, Instance</name><type>xs:string</type></item><item><name>Job Name</name><type>xs:string</type></item></metadata><data><row><value>CK1</value><value>Check</value><value>Low</value><value>Details</value><value></value><value>Task</value><value>Cat</value><value>Org</value><value>Asset</value><value>DB</value><value>10.0.0.1</value><value>Job</value></row></data></dataset>`;
      const hdf = JSON.parse(await convertDbprotectToHdf(xml)) as HDFResults;
      expect(hdf.baselines[0]!.requirements).toHaveLength(1);
    });

    it('should handle null values in row data', async () => {
      const xml = `<?xml version="1.0"?><dataset><metadata><item><name>Check ID</name><type>xs:string</type></item><item><name>Check</name><type>xs:string</type></item><item><name>Risk DV</name><type>xs:string</type></item><item><name>Details</name><type>xs:string</type></item><item><name>Date</name><type>xs:string</type></item><item><name>Task</name><type>xs:string</type></item><item><name>Check Category</name><type>xs:string</type></item><item><name>Organization</name><type>xs:string</type></item><item><name>Asset</name><type>xs:string</type></item><item><name>Asset Type</name><type>xs:string</type></item><item><name>IP Address, Port, Instance</name><type>xs:string</type></item><item><name>Job Name</name><type>xs:string</type></item></metadata><data><row><value>CK1</value><value>Check</value><value>Low</value><value nil="true"/><value>invalid date xyz</value><value nil="true"/><value nil="true"/><value nil="true"/><value nil="true"/><value nil="true"/><value nil="true"/><value nil="true"/></row></data></dataset>`;
      const hdf = JSON.parse(await convertDbprotectToHdf(xml)) as HDFResults;
      expect(hdf.baselines[0]!.requirements).toHaveLength(1);
    });
  });

  // The snapshot harness masks the top-level timestamp, so the golden never
  // verifies its value. Pin the exact source-derived value here.
  describe('top-level timestamp (source-derived)', () => {
    it('derives the timestamp from the Start Date column (findings detail)', async () => {
      const hdf = JSON.parse(await convertDbprotectToHdf(loadFixture('sample-findings-detail.xml'))) as HDFResults;
      expect(hdf.timestamp).toBe('2021-02-18T15:55:00Z');
    });

    it('falls back to the per-finding Date column when Start Date is absent (check results)', async () => {
      const hdf = JSON.parse(await convertDbprotectToHdf(loadFixture('sample-check-results.xml'))) as HDFResults;
      expect(hdf.timestamp).toBe('2021-02-18T15:57:00Z');
    });

    it('is deterministic across repeated conversions of the same input', async () => {
      const first = JSON.parse(await convertDbprotectToHdf(loadFixture('sample-findings-detail.xml'))) as HDFResults;
      const second = JSON.parse(await convertDbprotectToHdf(loadFixture('sample-findings-detail.xml'))) as HDFResults;
      expect(first.timestamp).toBe(second.timestamp);
      expect(first.timestamp).toBe('2021-02-18T15:55:00Z');
    });

    it('omits the timestamp when the source carries no parseable scan time', async () => {
      const xml = `<?xml version="1.0"?><dataset><metadata><item><name>Check ID</name><type>xs:string</type></item><item><name>Check</name><type>xs:string</type></item><item><name>Risk DV</name><type>xs:string</type></item><item><name>Details</name><type>xs:string</type></item><item><name>Date</name><type>xs:string</type></item><item><name>Task</name><type>xs:string</type></item><item><name>Check Category</name><type>xs:string</type></item><item><name>Organization</name><type>xs:string</type></item><item><name>Asset</name><type>xs:string</type></item><item><name>Asset Type</name><type>xs:string</type></item><item><name>IP Address, Port, Instance</name><type>xs:string</type></item><item><name>Job Name</name><type>xs:string</type></item></metadata><data><row><value>CK1</value><value>Check</value><value>Low</value><value>Details</value><value>invalid date xyz</value><value>Task</value><value>Cat</value><value>Org</value><value>Asset</value><value>DB</value><value>10.0.0.1</value><value>Job</value></row></data></dataset>`;
      const hdf = JSON.parse(await convertDbprotectToHdf(xml)) as HDFResults;
      expect(hdf.timestamp).toBeUndefined();
    });
  });
});
