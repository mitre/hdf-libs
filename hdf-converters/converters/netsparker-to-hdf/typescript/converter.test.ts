import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { convertNetsparkerToHdf, buildNetsparkerCvss, decodeXmlEntities } from './converter.js';
import { runConverterContractTests } from '../../../shared/typescript/converter-contract.js';
import { assertRequirementCount, countXmlElements } from '../../../shared/typescript/anchor.js';
import { expectValidResults } from '../../../test/helpers/expectValidHdf.js';
import type { HDFResults } from '@mitre/hdf-schema';

function loadFixture(name: string): string {
  return readFileSync(resolve(__dirname, '..', 'fixtures', name), 'utf-8');
}

function parseResult(jsonString: string): HDFResults {
  return JSON.parse(jsonString) as HDFResults;
}

function findRequirement(
  result: HDFResults,
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

runConverterContractTests({
  converterName: 'netsparker-to-hdf',
  convertFn: convertNetsparkerToHdf,
  minimalFixture: 'sample-netsparker-invicti.xml',
});

describe('timestamp parse fallback', () => {
  it('falls back to a default startTime when the initiated date is unparseable', async () => {
    const input = loadFixture('input/sample-netsparker-invicti.xml').replace(/05\/05\/2023 04:57 PM/g, 'not-a-date');
    const hdf = parseResult(await convertNetsparkerToHdf(input));
    expectValidResults(hdf);
  });
});

describe('top-level timestamp from `generated` attribute', () => {
  it('pins the top-level timestamp to the fixture `generated` value', async () => {
    const input = loadFixture('input/sample-netsparker-invicti.xml');
    const hdf = parseResult(await convertNetsparkerToHdf(input));
    // generated="03/07/2023 03:15 PM" parsed as UTC → 2023-03-07T15:15:00Z.
    // The shared snapshot masks this value, so pin it explicitly here.
    expect(hdf.timestamp as unknown as string).toBe('2023-03-07T15:15:00Z');
  });

  it('falls back to a valid timestamp when `generated` is absent', async () => {
    const input = `<?xml version="1.0" encoding="utf-8" ?>
<netsparker-enterprise>
	<target>
		<url>https://example.com/</url>
	</target>
	<vulnerabilities>
		<vulnerability>
			<LookupId>no-generated</LookupId>
			<name>No Generated Vuln</name>
			<severity>Low</severity>
		</vulnerability>
	</vulnerabilities>
</netsparker-enterprise>`;
    const hdf = parseResult(await convertNetsparkerToHdf(input));
    expect(hdf.timestamp).toBeDefined();
    expect(Number.isNaN(new Date(hdf.timestamp as unknown as string).getTime())).toBe(false);
  });
});

describe('Netsparker to HDF converter', () => {
  // Ground-truth anchor (input-derived count; see shared/typescript/anchor.ts).
  // Golden parity proves Go and TS agree, not that either is correct.
  // Netsparker emits one requirement per <vulnerability> element (no
  // grouping/dedup); assert that count derived INDEPENDENTLY from the source
  // XML, catching a silent under-extraction even when both languages agree.
  it('emits one requirement per <vulnerability> (sample-netsparker-invicti.xml)', async () => {
    const input = loadFixture('input/sample-netsparker-invicti.xml');
    const result = await convertNetsparkerToHdf(input);
    assertRequirementCount(
      result,
      countXmlElements(input, 'vulnerability'),
      'sample-netsparker-invicti.xml: one requirement per <vulnerability>',
    );
  });

  // ---- Baseline structure ----

  it('should produce exactly one baseline', async () => {
    const input = loadFixture('input/sample-netsparker-invicti.xml');
    const hdf = parseResult(await convertNetsparkerToHdf(input));
    expectValidResults(hdf);
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

  // ---- Tool ----

  it('should set tool name to Invicti for invicti-enterprise root', async () => {
    const input = loadFixture('input/sample-netsparker-invicti.xml');
    const hdf = parseResult(await convertNetsparkerToHdf(input));
    expect(hdf.tool?.name).toContain('Invicti');
    expect(hdf.tool?.format).toBeUndefined() // serialization structures are not formats (kpvj);
  });

  // ---- Target ----

  it('should set target name to scan URL', async () => {
    const input = loadFixture('input/sample-netsparker-invicti.xml');
    const hdf = parseResult(await convertNetsparkerToHdf(input));
    expect(hdf.components).toBeDefined();
    expect(hdf.components![0]!.name).toBe('https://foo.bar/');
    expect(hdf.components![0]!.type).toBe('application');
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

  it('tags unrated severities with severity_rating: unrated', async () => {
    // Absent <severity> → unrated marker; rated severities — including
    // Information — must not carry the tag.
    const input = `<?xml version="1.0" encoding="utf-8" ?>
<netsparker-enterprise generated="03/07/2023 03:15 PM">
	<target>
		<url>https://example.com/</url>
	</target>
	<vulnerabilities>
		<vulnerability>
			<LookupId>vuln-unrated</LookupId>
			<name>No Severity Vuln</name>
		</vulnerability>
		<vulnerability>
			<LookupId>vuln-high</LookupId>
			<name>High Severity Vuln</name>
			<severity>High</severity>
		</vulnerability>
		<vulnerability>
			<LookupId>vuln-info</LookupId>
			<name>Information Severity Vuln</name>
			<severity>Information</severity>
		</vulnerability>
	</vulnerabilities>
</netsparker-enterprise>`;
    const hdf = parseResult(await convertNetsparkerToHdf(input));
    expect(findRequirement(hdf, 'vuln-unrated')?.tags?.['severity_rating']).toBe('unrated');
    expect(findRequirement(hdf, 'vuln-high')?.tags?.['severity_rating']).toBeUndefined();
    expect(findRequirement(hdf, 'vuln-info')?.tags?.['severity_rating']).toBeUndefined();
  });

  it('maps Critical to 0.9 like the Go twin (shared standard map, not 1.0)', async () => {
    const input = `<?xml version="1.0" encoding="utf-8" ?>
<netsparker-enterprise generated="03/07/2023 03:15 PM">
	<target>
		<url>https://example.com/</url>
	</target>
	<vulnerabilities>
		<vulnerability>
			<LookupId>vuln-critical</LookupId>
			<name>Critical Severity Vuln</name>
			<severity>Critical</severity>
		</vulnerability>
		<vulnerability>
			<LookupId>vuln-bp</LookupId>
			<name>Best Practice Vuln</name>
			<severity>Best_Practice</severity>
		</vulnerability>
	</vulnerabilities>
</netsparker-enterprise>`;
    const hdf = parseResult(await convertNetsparkerToHdf(input));
    expect(findRequirement(hdf, 'vuln-critical')?.impact).toBe(0.9);
    expect(findRequirement(hdf, 'vuln-bp')?.impact).toBe(0.0);
  });

  // ---- Classification tags (capec / wasc / iso27001 / pci32) ----

  it('maps classification fields to tags with the source values', async () => {
    const input = loadFixture('input/sample-netsparker-invicti.xml');
    const hdf = parseResult(await convertNetsparkerToHdf(input));

    // Vuln 1: capec=217, wasc=4, iso27001=A.14.1.3, pci32=6.5.4 (all present).
    const v1 = findRequirement(hdf, 'e8b418ae-a532-4b43-5d9b-af9b04bbbca3');
    expect(v1?.tags?.capec).toBe('217');
    expect(v1?.tags?.wasc).toBe('4');
    expect(v1?.tags?.iso27001).toBe('A.14.1.3');
    expect(v1?.tags?.pci32).toBe('6.5.4');
    // hipaa and owasppc are empty in every fixture vuln → never tagged.
    expect(v1?.tags?.hipaa).toBeUndefined();
    expect(v1?.tags?.owasppc).toBeUndefined();

    // Vuln 2: wasc=15, iso27001=A.14.1.2; capec and pci32 empty → omitted.
    const v2 = findRequirement(hdf, '9c3a51bf-6c1f-47c9-4646-afb704bb8fb0');
    expect(v2?.tags?.wasc).toBe('15');
    expect(v2?.tags?.iso27001).toBe('A.14.1.2');
    expect(v2?.tags?.capec).toBeUndefined();
    expect(v2?.tags?.pci32).toBeUndefined();

    // Vuln 3: capec=103, iso27001=A.14.2.5; wasc empty → omitted.
    const v3 = findRequirement(hdf, '8d8e6052-221d-41c4-8f1e-af9704473901');
    expect(v3?.tags?.capec).toBe('103');
    expect(v3?.tags?.iso27001).toBe('A.14.2.5');
    expect(v3?.tags?.wasc).toBeUndefined();
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

  it('appends <extra-information> to the default description with entities decoded', async () => {
    const input = loadFixture('input/sample-netsparker-invicti.xml');
    const hdf = parseResult(await convertNetsparkerToHdf(input));
    const req = findRequirement(hdf, 'e8b418ae-a532-4b43-5d9b-af9b04bbbca3');
    const desc = findDescription(req!.descriptions!, 'default');
    expect(desc!.data).toContain(
      'Extra-information: List of Supported Weak Ciphers=>TLS_RSA_WITH_AES_128_CBC_SHA256 (0x003C)',
    );
  });

  it('omits the Extra-information line for a vuln without <extra-information>', async () => {
    const input = loadFixture('input/sample-netsparker-invicti.xml');
    const hdf = parseResult(await convertNetsparkerToHdf(input));
    const req = findRequirement(hdf, '8d8e6052-221d-41c4-8f1e-af9704473901');
    const desc = findDescription(req!.descriptions!, 'default');
    expect(desc!.data).not.toContain('Extra-information:');
  });

  it('decodeXmlEntities decodes numeric, hex, and named XML entities (matching Go attribute decoding)', () => {
    expect(decodeXmlEntities('a&#32;b')).toBe('a b');
    expect(decodeXmlEntities('a&#x20;b')).toBe('a b');
    expect(decodeXmlEntities('&lt;x&gt; &quot;q&quot; &apos;a&apos; a&amp;b')).toBe('<x> "q" \'a\' a&b');
    expect(decodeXmlEntities('plain')).toBe('plain');
  });

  // ---- External references → refs[] ----

  it('maps <external-references> anchor links to refs[]', async () => {
    const input = loadFixture('input/sample-netsparker-invicti.xml');
    const hdf = parseResult(await convertNetsparkerToHdf(input));
    const req = findRequirement(hdf, 'e8b418ae-a532-4b43-5d9b-af9b04bbbca3');
    expect(req?.refs).toBeDefined();
    expect(req!.refs).toHaveLength(5);
    expect(req!.refs![0]!.url).toBe('https://wiki.owasp.org/index.php/Insecure_Configuration_Management');
    expect(req!.refs![4]!.url).toBe('https://syslink.pl/cipherlist/');
  });

  it('omits refs[] when the vuln carries no external-references', async () => {
    const input = `<?xml version="1.0" encoding="utf-8" ?>
<netsparker-enterprise>
	<target><url>https://example.com/</url></target>
	<vulnerabilities>
		<vulnerability>
			<LookupId>no-refs</LookupId>
			<name>No Refs Vuln</name>
			<severity>Low</severity>
		</vulnerability>
	</vulnerabilities>
</netsparker-enterprise>`;
    const hdf = parseResult(await convertNetsparkerToHdf(input));
    const req = findRequirement(hdf, 'no-refs');
    expect(req?.refs).toBeUndefined();
  });

  it('skips non-absolute hrefs (relative/fragment/blank) in external-references', async () => {
    const input = `<?xml version="1.0" encoding="utf-8" ?>
<netsparker-enterprise>
	<target><url>https://example.com/</url></target>
	<vulnerabilities>
		<vulnerability>
			<LookupId>mixed-refs</LookupId>
			<name>Mixed Refs Vuln</name>
			<severity>Low</severity>
			<external-references><![CDATA[<a href="https://abs.example/x">abs</a><a href="/relative">rel</a><a href="#frag">f</a><a href="   ">blank</a>]]></external-references>
		</vulnerability>
	</vulnerabilities>
</netsparker-enterprise>`;
    const hdf = parseResult(await convertNetsparkerToHdf(input));
    const req = findRequirement(hdf, 'mixed-refs');
    expect(req?.refs).toHaveLength(1);
    expect(req!.refs![0]!.url).toBe('https://abs.example/x');
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

  // ---- requirement.code holds the raw HTTP request (CODE tab) ----

  it('should set requirement.code to the raw HTTP request content', async () => {
    const input = loadFixture('input/sample-netsparker-invicti.xml');
    const hdf = parseResult(await convertNetsparkerToHdf(input));

    // First vuln: http-request content is "[SSL Connection]"
    const req = findRequirement(hdf, 'e8b418ae-a532-4b43-5d9b-af9b04bbbca3');
    expect(req?.code).toBe('[SSL Connection]');

    // Second vuln: full raw GET request preserved verbatim, no framing
    const req2 = findRequirement(hdf, '9c3a51bf-6c1f-47c9-4646-afb704bb8fb0');
    expect(req2?.code).toContain('GET / HTTP/1.1');
    expect(req2?.code).toContain('Host: mlrcommercial.vams-impl.cms.gov');
    expect(req2?.code).not.toContain('method :');
  });

  it('should leave requirement.code unset when the vuln has no http-request content', async () => {
    const xml = `<?xml version="1.0" encoding="utf-8" ?>
<netsparker-enterprise>
  <target>
    <url>https://example.com/</url>
  </target>
  <vulnerabilities>
    <vulnerability>
      <LookupId>no-http-request</LookupId>
      <name>No Request Vuln</name>
      <severity>Low</severity>
    </vulnerability>
  </vulnerabilities>
</netsparker-enterprise>`;
    const hdf = parseResult(await convertNetsparkerToHdf(xml));
    const req = findRequirement(hdf, 'no-http-request');
    expect(req?.code).toBeUndefined();
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
    expect(hdf.tool?.name).toBe('Netsparker');
  });

  // ---- Edge cases: missing optional fields ----

  it('should handle vulnerability with no classification (no CWE, no OWASP)', async () => {
    const xml = `<?xml version="1.0" encoding="utf-8" ?>
<netsparker-enterprise>
  <target>
    <scan-id>t1</scan-id>
    <url>https://example.com/</url>
    <initiated>01/01/2024 12:00 PM</initiated>
  </target>
  <vulnerabilities>
    <vulnerability>
      <LookupId>no-class-1</LookupId>
      <name>No Classification Vuln</name>
      <severity>Critical</severity>
      <description>Desc text</description>
      <impact>High impact</impact>
      <exploitation-skills>Expert level</exploitation-skills>
      <proof-of-concept>PoC here</proof-of-concept>
      <FirstSeenDate>01/01/2024</FirstSeenDate>
      <LastSeenDate>01/02/2024</LastSeenDate>
      <certainty>100</certainty>
      <type>TestType</type>
      <confirmed>True</confirmed>
    </vulnerability>
  </vulnerabilities>
</netsparker-enterprise>`;
    const hdf = parseResult(await convertNetsparkerToHdf(xml));
    const req = findRequirement(hdf, 'no-class-1');
    expect(req).toBeDefined();
    // With no CWE/OWASP, should fall back to default NIST tags
    // Critical maps to 0.9 via the shared standard map (Go parity).
    expect(req!.impact).toBe(0.9);
    // Should have check description from exploitation-skills + proof-of-concept
    const check = findDescription(req!.descriptions!, 'check');
    expect(check).toBeDefined();
    expect(check!.data).toContain('Expert level');
  });

  it('should handle vulnerability with empty/missing optional fields', async () => {
    const xml = `<?xml version="1.0" encoding="utf-8" ?>
<netsparker-enterprise>
  <target>
    <scan-id>t2</scan-id>
  </target>
  <vulnerabilities>
    <vulnerability>
      <severity>Unknown</severity>
    </vulnerability>
  </vulnerabilities>
</netsparker-enterprise>`;
    const hdf = parseResult(await convertNetsparkerToHdf(xml));
    const req = hdf.baselines[0]!.requirements[0]!;
    // Missing LookupId → empty string
    expect(req.id).toBe('');
    // Missing severity mapping → default 0.5
    expect(req.impact).toBe(0.5);
    // No http-request/response → fallback empty strings in codeDesc
    expect(req.results[0]!.codeDesc).toContain('http-request');
    // Missing target url → 'Unknown'
    expect(hdf.components![0]!.name).toBe('Unknown');
  });

  it('should handle vulnerability with no description but has name', async () => {
    const xml = `<?xml version="1.0" encoding="utf-8" ?>
<netsparker-enterprise>
  <target>
    <url>https://example.com/</url>
  </target>
  <vulnerabilities>
    <vulnerability>
      <LookupId>name-only-1</LookupId>
      <name>FallbackName</name>
      <severity>Information</severity>
      <classification>
        <cwe>abc</cwe>
        <owasp>invalid</owasp>
      </classification>
    </vulnerability>
  </vulnerabilities>
</netsparker-enterprise>`;
    const hdf = parseResult(await convertNetsparkerToHdf(xml));
    const req = findRequirement(hdf, 'name-only-1');
    expect(req).toBeDefined();
    // information maps to 0.0
    expect(req!.impact).toBe(0.0);
    // default desc should use name as fallback
    const desc = findDescription(req!.descriptions!, 'default');
    expect(desc).toBeDefined();
    // formatControlDesc uses classification fields; when those are present, it uses them
    expect(desc!.data.length).toBeGreaterThan(0);
    // Invalid CWE (non-numeric) and invalid OWASP should not crash
    // No fix description since no remedial info
    const fix = findDescription(req!.descriptions!, 'fix');
    expect(fix).toBeUndefined();
  });

  it('should handle best_practice severity mapping', async () => {
    const xml = `<?xml version="1.0" encoding="utf-8" ?>
<netsparker-enterprise>
  <target><url>https://example.com/</url></target>
  <vulnerabilities>
    <vulnerability>
      <LookupId>bp-1</LookupId>
      <name>Best Practice</name>
      <severity>Best_Practice</severity>
    </vulnerability>
  </vulnerabilities>
</netsparker-enterprise>`;
    const hdf = parseResult(await convertNetsparkerToHdf(xml));
    expect(hdf.baselines[0]!.requirements[0]!.impact).toBe(0.0);
  });

  it('should handle vulnerability with no initiated time', async () => {
    const xml = `<?xml version="1.0" encoding="utf-8" ?>
<netsparker-enterprise>
  <target><url>https://example.com/</url></target>
  <vulnerabilities>
    <vulnerability>
      <LookupId>no-time-1</LookupId>
      <name>No Time</name>
      <severity>High</severity>
      <remedial-procedure>Fix it</remedial-procedure>
      <remedy-references>Some ref</remedy-references>
    </vulnerability>
  </vulnerabilities>
</netsparker-enterprise>`;
    const hdf = parseResult(await convertNetsparkerToHdf(xml));
    const req = findRequirement(hdf, 'no-time-1');
    expect(req).toBeDefined();
    expect(req!.impact).toBe(0.7);
    // Fix description from remedial-procedure and remedy-references
    const fix = findDescription(req!.descriptions!, 'fix');
    expect(fix).toBeDefined();
    expect(fix!.data).toContain('Fix it');
    expect(fix!.data).toContain('Some ref');
  });

  it('should reject XML with no vulnerabilities or target', async () => {
    const xml = `<?xml version="1.0" encoding="utf-8" ?>
<netsparker-enterprise>
</netsparker-enterprise>`;
    await expect(convertNetsparkerToHdf(xml)).rejects.toThrow('invalid XML');
  });

  it('should synthesize a passed placeholder for empty vulnerabilities element', async () => {
    const input = loadFixture('input/empty.xml');
    const hdf = parseResult(await convertNetsparkerToHdf(input));
    expect(hdf.baselines).toHaveLength(1);
    const reqs = hdf.baselines[0]!.requirements;
    expect(reqs).toHaveLength(1);
    expect(reqs[0]!.id).toBe('netsparker-no-findings');
    expect(reqs[0]!.results).toHaveLength(1);
    expect(reqs[0]!.results[0]!.status).toBe('passed');
    expect(reqs[0]!.results[0]!.codeDesc).toContain('Invicti');
    expect(reqs[0]!.results[0]!.codeDesc).toContain('https://clean.example.com/');
    expect(reqs[0]!.results[0]!.codeDesc).toContain('zero findings');
  });

  it('should fall back to name for default desc when no description/classification/impact fields', async () => {
    const xml = `<?xml version="1.0" encoding="utf-8" ?>
<netsparker-enterprise>
  <target><url>https://example.com/</url></target>
  <vulnerabilities>
    <vulnerability>
      <LookupId>name-fallback-1</LookupId>
      <name>FallbackName</name>
      <severity>Medium</severity>
    </vulnerability>
  </vulnerabilities>
</netsparker-enterprise>`;
    const hdf = parseResult(await convertNetsparkerToHdf(xml));
    const req = findRequirement(hdf, 'name-fallback-1');
    const desc = findDescription(req!.descriptions!, 'default');
    // With no description/classification/impact, formatControlDesc returns empty, so name is used
    expect(desc!.data).toBe('FallbackName');
  });

  it('should handle vulnerability with only OWASP mapping (no CWE)', async () => {
    const xml = `<?xml version="1.0" encoding="utf-8" ?>
<netsparker-enterprise>
  <target><url>https://example.com/</url></target>
  <vulnerabilities>
    <vulnerability>
      <LookupId>owasp-only-1</LookupId>
      <name>OWASP Only</name>
      <severity>Medium</severity>
      <classification>
        <owasp>A1</owasp>
      </classification>
    </vulnerability>
  </vulnerabilities>
</netsparker-enterprise>`;
    const hdf = parseResult(await convertNetsparkerToHdf(xml));
    const req = findRequirement(hdf, 'owasp-only-1');
    expect(req).toBeDefined();
    // Should have owasp tag but no cweid
    expect(req!.tags?.owasp).toBeDefined();
  });
});

describe('structured CVSS', () => {
  it('populates cvss[] from <cvss> (3.0) and <cvss31> (3.1) blocks', async () => {
    const input = loadFixture('input/sample-netsparker-invicti.xml');
    const hdf = parseResult(await convertNetsparkerToHdf(input));
    const req = findRequirement(hdf, 'e8b418ae-a532-4b43-5d9b-af9b04bbbca3');
    expect(req).toBeDefined();
    expect(req!.cvss).toHaveLength(2);

    const [c30, c31] = req!.cvss!;
    expect(c30!.version).toBe('3.0');
    expect(c30!.baseScore).toBeCloseTo(6.8, 5);
    expect(c30!.baseSeverity).toBe('medium');
    expect(c30!.baseVector).toBe('CVSS:3.0/AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N');

    expect(c31!.version).toBe('3.1');
    expect(c31!.baseScore).toBeCloseTo(6.8, 5);
    expect(c31!.baseVector).toBe('CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N');
  });

  it('omits cvss[] when the vuln carries no CVSS block', async () => {
    const input = loadFixture('input/sample-netsparker-invicti.xml');
    const hdf = parseResult(await convertNetsparkerToHdf(input));
    for (const id of ['9c3a51bf-6c1f-47c9-4646-afb704bb8fb0', '8d8e6052-221d-41c4-8f1e-af9704473901']) {
      const req = findRequirement(hdf, id);
      expect(req).toBeDefined();
      expect(req!.cvss).toBeUndefined();
    }
  });

  it('builds one entry per block, dropping empty blocks (buildNetsparkerCvss)', () => {
    expect(buildNetsparkerCvss({
      cvss: { vector: 'CVSS:3.0/AV:N', score: [{ type: 'Base', value: '6.8' }] },
      cvss31: { vector: 'CVSS:3.1/AV:N', score: [{ type: 'Base', value: '7.5' }] },
    })).toHaveLength(2);

    // vector only, no Base score
    const vectorOnly = buildNetsparkerCvss({ cvss: { vector: 'CVSS:3.1/AV:N' } });
    expect(vectorOnly).toHaveLength(1);
    expect(vectorOnly[0]!.baseScore).toBeUndefined();

    // Base score only, no vector
    const scoreOnly = buildNetsparkerCvss({ cvss31: { score: [{ type: 'Base', value: '4.0' }] } });
    expect(scoreOnly).toHaveLength(1);
    expect(scoreOnly[0]!.baseScore).toBeCloseTo(4.0, 5);
    expect(scoreOnly[0]!.baseVector).toBeUndefined();

    // unparseable / absent Base value and non-Base types → nothing emitted
    expect(buildNetsparkerCvss({ cvss: { score: [{ type: 'Base', value: 'N/A' }] } })).toHaveLength(0);
    expect(buildNetsparkerCvss({ cvss: { score: [{ type: 'Base' }] } })).toHaveLength(0);
    expect(buildNetsparkerCvss({ cvss: { score: [{ type: 'Temporal', value: '6.8' }] } })).toHaveLength(0);
    expect(buildNetsparkerCvss({ cvss: { score: [{ value: '6.8' }] } })).toHaveLength(0);
    expect(buildNetsparkerCvss({})).toHaveLength(0);
    expect(buildNetsparkerCvss(undefined)).toHaveLength(0);
  });
});
