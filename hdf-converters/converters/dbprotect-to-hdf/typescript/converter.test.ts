import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { describe, it, expect } from 'vitest';
import { convertDbprotectToHdf } from './converter.js';
import { runConverterContractTests } from '../../../shared/typescript/converter-contract.js';
import { expectValidResults } from '../../../test/helpers/expectValidHdf.js';
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

    it('should set tool name to "DBProtect" and format to "XML"', async () => {
      const hdf = JSON.parse(await convertDbprotectToHdf(loadFixture('sample-check-results.xml'))) as HDFResults;
      expect(hdf.tool?.name).toBe('DBProtect');
      expect(hdf.tool?.format).toBe('XML');
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

    it('falls back to conversion time when the Date column is empty', async () => {
      const before = Date.now();
      const xml = loadFixture('sample-check-results.xml').replace(/Feb 18 2021 15:57/g, '');
      const hdf = JSON.parse(await convertDbprotectToHdf(xml)) as HDFResults;
      const req = hdf.baselines[0]!.requirements.find(r => r.id === '2986');
      expect(new Date(req!.results[0]!.startTime as string).getTime()).toBeGreaterThanOrEqual(before);
    });

    it('falls back to conversion time for an unrecognized month name', async () => {
      const before = Date.now();
      const xml = loadFixture('sample-check-results.xml').replace(/Feb 18 2021 15:57/g, 'Xyz 18 2021 15:57');
      const hdf = JSON.parse(await convertDbprotectToHdf(xml)) as HDFResults;
      const req = hdf.baselines[0]!.requirements.find(r => r.id === '2986');
      expect(new Date(req!.results[0]!.startTime as string).getTime()).toBeGreaterThanOrEqual(before);
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

  describe('target', () => {
    it('should set target name from Asset column', async () => {
      const hdf = JSON.parse(await convertDbprotectToHdf(loadFixture('sample-check-results.xml'))) as HDFResults;
      expect(hdf.components).toBeDefined();
      expect(hdf.components!.length).toBeGreaterThan(0);
      expect(hdf.components![0]!.name).toBe('CONDS181');
    });

    it('should set target type to Host', async () => {
      const hdf = JSON.parse(await convertDbprotectToHdf(loadFixture('sample-check-results.xml'))) as HDFResults;
      expect(hdf.components![0]!.type).toBe('host');
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
});
