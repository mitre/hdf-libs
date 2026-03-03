import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { convertNetsparkerToHdf } from './converter.js';
import type { HdfResults } from '@mitre/hdf-schema';

function loadFixture(name: string): string {
  return readFileSync(resolve(__dirname, '..', 'fixtures', name), 'utf-8');
}

function parseResult(jsonString: string): HdfResults {
  return JSON.parse(jsonString) as HdfResults;
}

function findRequirement(
  result: HdfResults,
  id: string,
) {
  for (const baseline of result.baselines) {
    const req = baseline.requirements?.find(r => r.id === id);
    if (req) return req;
  }
  return undefined;
}

function findDescription(
  descriptions: Array<{ label: string; data: string }>,
  label: string,
) {
  return descriptions.find(d => d.label === label);
}

// ---- Input validation ----

describe('Netsparker to HDF converter', () => {
  it('should reject empty input', async () => {
    await expect(convertNetsparkerToHdf('')).rejects.toThrow('empty input');
  });

  it('should reject invalid XML', async () => {
    await expect(convertNetsparkerToHdf('not xml')).rejects.toThrow();
  });

  // ---- Baseline structure ----

  it('should produce exactly one baseline', async () => {
    const input = loadFixture('input/sample-netsparker-invicti.xml');
    const hdf = parseResult(await convertNetsparkerToHdf(input));
    expect(hdf.baselines).toHaveLength(1);
  });

  it('should produce 3 requirements from fixture', async () => {
    const input = loadFixture('input/sample-netsparker-invicti.xml');
    const hdf = parseResult(await convertNetsparkerToHdf(input));
    expect(hdf.baselines[0]!.requirements).toHaveLength(3);
  });

  it('should use "Netsparker Scan" as baseline name', async () => {
    const input = loadFixture('input/sample-netsparker-invicti.xml');
    const hdf = parseResult(await convertNetsparkerToHdf(input));
    expect(hdf.baselines[0]!.name).toBe('Netsparker Scan');
  });

  it('should include scan ID and URL in baseline title', async () => {
    const input = loadFixture('input/sample-netsparker-invicti.xml');
    const hdf = parseResult(await convertNetsparkerToHdf(input));
    expect(hdf.baselines[0]!.title).toContain('1eb9f18bfec849d2e438afb704b6a011');
    expect(hdf.baselines[0]!.title).toContain('https://foo.bar/');
  });

  it('should include resultsChecksum', async () => {
    const input = loadFixture('input/sample-netsparker-invicti.xml');
    const hdf = parseResult(await convertNetsparkerToHdf(input));
    expect(hdf.baselines[0]!.resultsChecksum).toBeDefined();
    expect(hdf.baselines[0]!.resultsChecksum!.algorithm).toBe('sha256');
    expect(hdf.baselines[0]!.resultsChecksum!.value).toBeTruthy();
  });

  // ---- Generator ----

  it('should set generator name', async () => {
    const input = loadFixture('input/sample-netsparker-invicti.xml');
    const hdf = parseResult(await convertNetsparkerToHdf(input));
    expect(hdf.generator?.name).toBe('netsparker-to-hdf');
  });

  // ---- DataSource ----

  it('should set data source name to Invicti for invicti-enterprise root', async () => {
    const input = loadFixture('input/sample-netsparker-invicti.xml');
    const hdf = parseResult(await convertNetsparkerToHdf(input));
    expect(hdf.dataSource?.name).toContain('Invicti');
    expect(hdf.dataSource?.format).toBe('XML');
  });

  // ---- Target ----

  it('should set target name to scan URL', async () => {
    const input = loadFixture('input/sample-netsparker-invicti.xml');
    const hdf = parseResult(await convertNetsparkerToHdf(input));
    expect(hdf.targets).toBeDefined();
    expect(hdf.targets![0]!.name).toBe('https://foo.bar/');
    expect(hdf.targets![0]!.type).toBe('application');
  });

  // ---- Requirement IDs use LookupId ----

  it('should use LookupId as requirement ID', async () => {
    const input = loadFixture('input/sample-netsparker-invicti.xml');
    const hdf = parseResult(await convertNetsparkerToHdf(input));
    const req = findRequirement(hdf, 'e8b418ae-a532-4b43-5d9b-af9b04bbbca3');
    expect(req).toBeDefined();
  });

  // ---- Requirement title ----

  it('should set requirement title from name element', async () => {
    const input = loadFixture('input/sample-netsparker-invicti.xml');
    const hdf = parseResult(await convertNetsparkerToHdf(input));
    const req = findRequirement(hdf, 'e8b418ae-a532-4b43-5d9b-af9b04bbbca3');
    expect(req?.title).toBe('Weak Ciphers Enabled');
  });

  // ---- Severity → Impact ----

  it('should map Medium severity to 0.5 impact', async () => {
    const input = loadFixture('input/sample-netsparker-invicti.xml');
    const hdf = parseResult(await convertNetsparkerToHdf(input));
    const req = findRequirement(hdf, 'e8b418ae-a532-4b43-5d9b-af9b04bbbca3');
    expect(req?.impact).toBeCloseTo(0.5, 2);
  });

  it('should map Low severity to 0.3 impact', async () => {
    const input = loadFixture('input/sample-netsparker-invicti.xml');
    const hdf = parseResult(await convertNetsparkerToHdf(input));
    const req = findRequirement(hdf, '8d8e6052-221d-41c4-8f1e-af9704473901');
    expect(req?.impact).toBeCloseTo(0.3, 2);
  });

  // ---- Dual NIST mapping: CWE + OWASP ----

  it('should combine CWE and OWASP NIST mappings', async () => {
    const input = loadFixture('input/sample-netsparker-invicti.xml');
    const hdf = parseResult(await convertNetsparkerToHdf(input));
    const req = findRequirement(hdf, 'e8b418ae-a532-4b43-5d9b-af9b04bbbca3');
    expect(req?.tags).toBeDefined();
    const nist = req?.tags?.nist as string[];
    expect(nist).toBeDefined();
    expect(nist.length).toBeGreaterThan(0);
    // OWASP A6 → CM-6 should be in the NIST tags
    expect(nist).toContain('CM-6');
  });

  // ---- Tags ----

  it('should include cweid and owasp tags', async () => {
    const input = loadFixture('input/sample-netsparker-invicti.xml');
    const hdf = parseResult(await convertNetsparkerToHdf(input));
    const req = findRequirement(hdf, 'e8b418ae-a532-4b43-5d9b-af9b04bbbca3');
    expect(req?.tags?.cweid).toBeDefined();
    expect(req?.tags?.owasp).toBeDefined();
    expect(req?.tags?.nist).toBeDefined();
    expect(req?.tags?.cci).toBeDefined();
  });

  // ---- Descriptions ----

  it('should have default description', async () => {
    const input = loadFixture('input/sample-netsparker-invicti.xml');
    const hdf = parseResult(await convertNetsparkerToHdf(input));
    const req = findRequirement(hdf, 'e8b418ae-a532-4b43-5d9b-af9b04bbbca3');
    expect(req?.descriptions).toBeDefined();
    const desc = findDescription(req!.descriptions!, 'default');
    expect(desc).toBeDefined();
    expect(desc!.data.length).toBeGreaterThan(0);
  });

  it('should have fix description when remedial info exists', async () => {
    const input = loadFixture('input/sample-netsparker-invicti.xml');
    const hdf = parseResult(await convertNetsparkerToHdf(input));
    const req = findRequirement(hdf, 'e8b418ae-a532-4b43-5d9b-af9b04bbbca3');
    expect(req?.descriptions).toBeDefined();
    const fix = findDescription(req!.descriptions!, 'fix');
    expect(fix).toBeDefined();
    expect(fix!.data.length).toBeGreaterThan(0);
  });

  // ---- All results are Failed ----

  it('should mark all results as failed', async () => {
    const input = loadFixture('input/sample-netsparker-invicti.xml');
    const hdf = parseResult(await convertNetsparkerToHdf(input));
    for (const baseline of hdf.baselines) {
      for (const req of baseline.requirements ?? []) {
        for (const result of req.results ?? []) {
          expect(result.status).toBe('failed');
        }
      }
    }
  });

  // ---- CodeDesc contains HTTP request info ----

  it('should include HTTP request info in codeDesc', async () => {
    const input = loadFixture('input/sample-netsparker-invicti.xml');
    const hdf = parseResult(await convertNetsparkerToHdf(input));
    const req = findRequirement(hdf, 'e8b418ae-a532-4b43-5d9b-af9b04bbbca3');
    expect(req?.results).toBeDefined();
    expect(req!.results![0]!.codeDesc).toContain('http-request');
    expect(req!.results![0]!.codeDesc).toContain('GET');
  });

  // ---- Message contains HTTP response info ----

  it('should include HTTP response info in message', async () => {
    const input = loadFixture('input/sample-netsparker-invicti.xml');
    const hdf = parseResult(await convertNetsparkerToHdf(input));
    const req = findRequirement(hdf, 'e8b418ae-a532-4b43-5d9b-af9b04bbbca3');
    expect(req?.results).toBeDefined();
    expect(req!.results![0]!.message).toBeDefined();
    expect(req!.results![0]!.message).toContain('http-response');
  });

  // ---- Netsparker root element detection ----

  it('should handle netsparker-enterprise root element', async () => {
    const xml = `<?xml version="1.0" encoding="utf-8" ?>
<netsparker-enterprise generated="03/07/2023 03:15 PM">
  <target>
    <scan-id>abc123</scan-id>
    <url>https://example.com/</url>
    <initiated>05/05/2023 04:57 PM</initiated>
  </target>
  <vulnerabilities>
    <vulnerability>
      <LookupId>test-id-1</LookupId>
      <url>https://example.com/</url>
      <type>TestVuln</type>
      <name>Test Vulnerability</name>
      <severity>High</severity>
      <certainty>100</certainty>
      <confirmed>True</confirmed>
      <state>Present</state>
      <classification>
        <owasp>A1</owasp>
        <cwe>89</cwe>
      </classification>
      <http-request>
        <method>GET</method>
        <content>GET / HTTP/1.1</content>
      </http-request>
      <http-response>
        <status-code>200</status-code>
        <duration>1</duration>
        <content>HTTP/1.1 200 OK</content>
      </http-response>
      <description>SQL Injection</description>
      <impact>Data loss</impact>
      <remedial-actions>Use parameterized queries</remedial-actions>
      <remedial-procedure>Fix the code</remedial-procedure>
    </vulnerability>
  </vulnerabilities>
</netsparker-enterprise>`;

    const hdf = parseResult(await convertNetsparkerToHdf(xml));
    expect(hdf.dataSource?.name).toBe('Netsparker');
  });
});
