import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { convertVeracodeToHdf } from './converter.js';
import { runConverterContractTests } from '../../../shared/typescript/converter-contract.js';
import { expectValidResults } from '../../../test/helpers/expectValidHdf.js';
import { assertRequirementCount } from '../../../shared/typescript/anchor.js';
import type { HDFResults } from '@mitre/hdf-schema';

const __dirname = dirname(fileURLToPath(import.meta.url));
const fixturesDir = resolve(__dirname, '..', 'fixtures', 'input');

function loadFixture(name: string): string {
  return readFileSync(resolve(fixturesDir, name), 'utf-8');
}

// Dynamic import to avoid compile errors until implementation exists
async function convert(input: string): Promise<string> {
  const mod = await import('./converter.js');
  return mod.convertVeracodeToHdf(input);
}

runConverterContractTests({
  converterName: 'veracode-to-hdf',
  convertFn: convertVeracodeToHdf,
  minimalFixture: 'veracode.xml',
});

// countVeracodeEmissionUnits scans the raw Veracode XML generically — NOT via
// the converter's parser — and returns the number of requirements the converter
// should emit: one per CWE <category> element plus one per DISTINCT SCA cve_id.
// The CWE side emits per-category unconditionally; the CVE side groups/dedups by
// cve_id across components (skipping components whose vulnerabilities attr is
// "0"), so a plain <vulnerability> count would overshoot.
function countVeracodeEmissionUnits(input: string): number {
  let categories = 0;
  const distinctCVE = new Set<string>();
  let componentSkipped = false;
  const tagRe = /<(?:[\w.-]+:)?(category|component|vulnerability)((?:\s[^>]*)?)\/?>/g;
  const attr = (raw: string, name: string): string =>
    new RegExp(`\\b${name}\\s*=\\s*"([^"]*)"`).exec(raw)?.[1] ?? '';
  for (const m of input.matchAll(tagRe)) {
    const tag = m[1]!;
    const rawAttrs = m[2] ?? '';
    if (tag === 'category') {
      categories += 1;
    } else if (tag === 'component') {
      componentSkipped = attr(rawAttrs, 'vulnerabilities') === '0';
    } else if (tag === 'vulnerability' && !componentSkipped) {
      const cve = attr(rawAttrs, 'cve_id');
      if (cve) distinctCVE.add(cve);
    }
  }
  return categories + distinctCVE.size;
}

// Ground-truth anchor (input-derived count; see shared/typescript/anchor.ts):
// one requirement per CWE <category> plus one per distinct SCA cve_id, counted
// independently of the converter's parser so a silent under-extraction fails even
// when Go/TS agree. veracode.xml carries 14 categories + 39 distinct CVEs = 53.
describe('veracode-to-hdf ground-truth anchor', () => {
  it('emits one requirement per CWE category plus one per distinct SCA cve_id', async () => {
    const input = loadFixture('veracode.xml');
    assertRequirementCount(
      await convertVeracodeToHdf(input),
      countVeracodeEmissionUnits(input),
      'veracode.xml: one requirement per CWE category + one per distinct SCA cve_id',
    );
  });
});

describe('Veracode to HDF converter', () => {
  it('should convert sample Veracode XML to valid HDF', async () => {
    const input = loadFixture('veracode.xml');
    const outputStr = await convert(input);
    const output: HDFResults = JSON.parse(outputStr);
    expectValidResults(output);

    expect(output.baselines).toBeDefined();
    expect(output.baselines.length).toBe(1);
    expect(output.components).toBeDefined();
    expect(output.components!.length).toBe(1);
    expect(output.generator).toBeDefined();
  });

  it('should set baseline name to "Veracode Scan"', async () => {
    const input = loadFixture('veracode.xml');
    const output: HDFResults = JSON.parse(await convert(input));

    expect(output.baselines[0]!.name).toBe('Veracode Scan');
  });

  it('should set target type to Application', async () => {
    const input = loadFixture('veracode.xml');
    const output: HDFResults = JSON.parse(await convert(input));

    expect(output.components![0]!.type).toBe('application');
  });

  it('should set data source name to Veracode', async () => {
    const input = loadFixture('veracode.xml');
    const output: HDFResults = JSON.parse(await convert(input));

    expect(output.tool).toBeDefined();
    expect(output.tool!.name).toBe('Veracode');
  });

  it('should produce CWE-based controls from severity categories', async () => {
    const input = loadFixture('veracode.xml');
    const output: HDFResults = JSON.parse(await convert(input));
    const baseline = output.baselines[0]!;

    // Find CWE-based control: categoryid "18"
    const cweControl = baseline.requirements.find(r => r.id === '18');
    expect(cweControl).toBeDefined();
    expect(cweControl!.title).toBe('Command or Argument Injection');

    // Severity level 5 maps to impact 0.9
    expect(cweControl!.impact).toBe(0.9);

    // Should have failed results (static flaws)
    expect(cweControl!.results.length).toBeGreaterThan(0);
    for (const r of cweControl!.results) {
      expect(r.status).toBe('failed');
    }
  });

  it('should produce CVE-based controls from SCA vulnerabilities', async () => {
    const input = loadFixture('veracode.xml');
    const output: HDFResults = JSON.parse(await convert(input));
    const baseline = output.baselines[0]!;

    // Find CVE-based control
    const cveControl = baseline.requirements.find(r => r.id === 'CVE-2017-1000487');
    expect(cveControl).toBeDefined();
    expect(cveControl!.title).toBe('CVE-2017-1000487');

    // Should have non-zero impact
    expect(cveControl!.impact).toBeGreaterThan(0);

    // Should have failed results
    expect(cveControl!.results.length).toBeGreaterThan(0);
    for (const r of cveControl!.results) {
      expect(r.status).toBe('failed');
    }
  });

  it('should have correct control counts', async () => {
    const input = loadFixture('veracode.xml');
    const output: HDFResults = JSON.parse(await convert(input));
    const baseline = output.baselines[0]!;

    // Separate CWE and CVE controls
    const cweControls = baseline.requirements.filter(
      r => !r.id.startsWith('CVE-') && !r.id.startsWith('SRCCLR-')
    );
    const cveControls = baseline.requirements.filter(
      r => r.id.startsWith('CVE-') || r.id.startsWith('SRCCLR-')
    );

    expect(cweControls.length).toBe(14); // categoryid 12 appears at severity 3 and 2
    expect(cveControls.length).toBe(39);
  });

  it('should have correct flaw count in CWE controls', async () => {
    const input = loadFixture('veracode.xml');
    const output: HDFResults = JSON.parse(await convert(input));
    const baseline = output.baselines[0]!;

    // Count total results from CWE controls
    const cweControls = baseline.requirements.filter(
      r => !r.id.startsWith('CVE-') && !r.id.startsWith('SRCCLR-')
    );
    const totalFlaws = cweControls.reduce((sum, c) => sum + c.results.length, 0);
    expect(totalFlaws).toBe(194);
  });

  it('should map NIST tags from CWE IDs', async () => {
    const input = loadFixture('veracode.xml');
    const output: HDFResults = JSON.parse(await convert(input));
    const baseline = output.baselines[0]!;

    // CWE control 18 (Command Injection, CWE-78) should have NIST tags
    const cweControl = baseline.requirements.find(r => r.id === '18');
    expect(cweControl).toBeDefined();
    expect(cweControl!.tags).toBeDefined();
    expect(cweControl!.tags!.nist).toBeDefined();
    expect((cweControl!.tags!.nist as string[]).length).toBeGreaterThan(0);
  });

  it('should map each CWE standards cross-reference to a discrete tag', async () => {
    const input = loadFixture('veracode.xml');
    const output: HDFResults = JSON.parse(await convert(input));
    const baseline = output.baselines[0]!;

    // Category 18 (CWE-78) carries five of the six standards catalogs.
    const cat18 = baseline.requirements.find(r => r.id === '18');
    expect(cat18).toBeDefined();
    expect(cat18!.tags!.owasp).toEqual(['1347']);
    expect(cat18!.tags!.sans).toEqual(['864']);
    expect(cat18!.tags!.certc).toEqual(['1165']);
    expect(cat18!.tags!.certcpp).toEqual(['875']);
    expect(cat18!.tags!.certjava).toEqual(['1134']);

    // owaspmobile is absent from every fixture CWE (NOT-IN-SOURCE): key omitted.
    expect(cat18!.tags!.owaspmobile).toBeUndefined();

    // Category 7 (CWE-245) carries no standards attributes: none present.
    const cat7 = baseline.requirements.find(r => r.id === '7');
    expect(cat7).toBeDefined();
    for (const key of ['owasp', 'sans', 'certc', 'certcpp', 'certjava', 'owaspmobile']) {
      expect(cat7!.tags![key]).toBeUndefined();
    }
  });

  it('should collapse repeated standards values to distinct entries in appearance order', async () => {
    const input = loadFixture('veracode.xml');
    const output: HDFResults = JSON.parse(await convert(input));
    const baseline = output.baselines[0]!;

    // Category 21 (CRLF Injection) spans three CWEs with owasp 1347, 1347, 1355.
    const cat21 = baseline.requirements.find(r => r.id === '21');
    expect(cat21).toBeDefined();
    expect(cat21!.tags!.owasp).toEqual(['1347', '1355']);
  });

  it('should have descriptions on CWE controls', async () => {
    const input = loadFixture('veracode.xml');
    const output: HDFResults = JSON.parse(await convert(input));
    const baseline = output.baselines[0]!;

    const cweControl = baseline.requirements.find(r => r.id === '18');
    expect(cweControl).toBeDefined();
    expect(cweControl!.descriptions!.length).toBeGreaterThan(0);
  });

  it('should include results checksum', async () => {
    const input = loadFixture('veracode.xml');
    const output: HDFResults = JSON.parse(await convert(input));
    const baseline = output.baselines[0]!;

    expect(baseline.resultsChecksum).toBeDefined();
    expect(baseline.resultsChecksum!.algorithm).toBe('sha256');
    expect(baseline.resultsChecksum!.value).toBeTruthy();
  });

  it('should reject summary reports', async () => {
    const summaryXml = `<?xml version="1.0" encoding="ISO-8859-1"?>
<summaryreport xmlns="https://www.veracode.com/schema/reports/export/1.0">
</summaryreport>`;
    await expect(convert(summaryXml)).rejects.toThrow(/summary/i);
  });

  it('should set timestamp from first_build_submitted_date', async () => {
    const input = loadFixture('veracode.xml');
    const output: HDFResults = JSON.parse(await convert(input));

    expect(output.timestamp).toBeDefined();
  });

  it('should synthesize a passed placeholder when input has zero findings', async () => {
    const input = loadFixture('empty.xml');
    const output: HDFResults = JSON.parse(await convert(input));

    expect(output.baselines).toHaveLength(1);
    expect(output.baselines[0]!.requirements).toHaveLength(1);
    const req = output.baselines[0]!.requirements[0]!;
    expect(req.id).toBe('veracode-no-findings');
    expect(req.results).toHaveLength(1);
    expect(req.results[0]!.status).toBe('passed');
    expect(req.results[0]!.codeDesc).toContain('Veracode');
    expect(req.results[0]!.codeDesc).toContain('CleanApp');
  });

  it('should map severity levels to correct impact values', async () => {
    const input = loadFixture('veracode.xml');
    const output: HDFResults = JSON.parse(await convert(input));
    const baseline = output.baselines[0]!;

    // Severity 5 -> 0.9 (categoryid 18)
    const sev5 = baseline.requirements.find(r => r.id === '18');
    expect(sev5!.impact).toBe(0.9);

    // Severity 4 -> 0.7 (categoryid 19)
    const sev4 = baseline.requirements.find(r => r.id === '19');
    expect(sev4!.impact).toBe(0.7);

    // Severity 0 -> 0.0 (categoryid 17 - Code Quality)
    const sev0 = baseline.requirements.find(r => r.id === '17');
    expect(sev0!.impact).toBe(0.0);
  });

  it('maps a word severity through the shared standard map after the numeric aliases (Go parity)', async () => {
    const xml = `<?xml version="1.0"?>
<detailedreport app_name="t" first_build_submitted_date="2021-12-29 22:16:36 UTC">
  <severity level="low">
    <category categoryid="42" categoryname="Word Severity Category">
      <desc><para text="d"/></desc>
      <recommendations><para text="r"/></recommendations>
    </category>
  </severity>
  <severity level="0">
    <category categoryid="43" categoryname="Zero Severity Category">
      <desc><para text="d"/></desc>
      <recommendations><para text="r"/></recommendations>
    </category>
  </severity>
</detailedreport>`;
    const output: HDFResults = JSON.parse(await convert(xml));
    const reqs = output.baselines[0]!.requirements;
    // "low" misses the numeric 0-5 aliases and falls through to the shared
    // standard map (0.3), matching Go's SeverityToImpactWithAliases.
    expect(reqs.find(r => r.id === '42')!.impact).toBe(0.3);
    expect(reqs.find(r => r.id === '43')!.impact).toBe(0.0);
  });
});

describe('veracode structured scoring (CVSS / CWE)', () => {
  it('populates cvss[] from the SCA vulnerability cvss_score with derived severity', async () => {
    const input = loadFixture('veracode.xml');
    const output: HDFResults = JSON.parse(await convert(input));
    const reqs = output.baselines[0]!.requirements;

    const medium = reqs.find(r => r.id === 'CVE-2012-5783')!;
    expect(medium.cvss).toHaveLength(1);
    expect(medium.cvss![0]!.baseScore).toBe(5.8);
    expect(medium.cvss![0]!.version).toBe('3.1');
    expect(medium.cvss![0]!.baseSeverity).toBe('medium');
    expect(medium.cvss![0]!.baseVector).toBeUndefined();

    const high = reqs.find(r => r.id === 'CVE-2021-42550')!;
    expect(high.cvss![0]!.baseScore).toBe(8.5);
    expect(high.cvss![0]!.baseSeverity).toBe('high');
  });

  it('does not emit a tags.cve duplicate (CVE is already the requirement id)', async () => {
    const input = loadFixture('veracode.xml');
    const output: HDFResults = JSON.parse(await convert(input));
    for (const req of output.baselines[0]!.requirements) {
      expect(req.tags?.cve).toBeUndefined();
    }
  });

  it('moves CWE to first-class cwe[] on static and SCA requirements, dropping the freetext tags', async () => {
    const input = loadFixture('veracode.xml');
    const output: HDFResults = JSON.parse(await convert(input));
    const reqs = output.baselines[0]!.requirements;

    const staticReq = reqs.find(r => r.id === '18')!;
    expect(staticReq.cwe).toEqual(['CWE-78']);
    expect(staticReq.tags?.cweid).toBeUndefined();
    expect((staticReq.tags!.nist as string[]).length).toBeGreaterThan(0);

    const cveReq = reqs.find(r => r.id === 'CVE-2012-5783')!;
    expect(cveReq.cwe).toEqual(['CWE-20']);
    expect(cveReq.tags?.cwe).toBeUndefined();
    expect((cveReq.tags!.nist as string[]).length).toBeGreaterThan(0);

    // A CVE vulnerability with an empty cwe_id emits no cwe[].
    const noCwe = reqs.find(r => r.id === 'CVE-2014-3577')!;
    expect(noCwe.cwe).toBeUndefined();
    expect(noCwe.cvss![0]!.baseScore).toBe(5.8);
  });

  it('falls back to component max_cvss_score when the vulnerability carries no cvss_score', async () => {
    const xml = `<?xml version="1.0" encoding="ISO-8859-1"?>
<detailedreport xmlns="https://www.veracode.com/schema/reports/export/1.0" app_name="Fallback" first_build_submitted_date="2021-12-29 22:16:36 UTC">
  <software_composition_analysis>
    <vulnerable_components>
      <component component_id="c1" file_name="lib.jar" vulnerabilities="1" max_cvss_score="6.4" version="1.0" library="lib" library_id="maven:lib:1.0:" vendor="lib">
        <vulnerabilities>
          <vulnerability cve_id="CVE-9999-0001" cvss_score="" severity="3" cwe_id="" first_found_date="2021-12-29 22:18:20 UTC" cve_summary="fallback" severity_desc="Medium"/>
        </vulnerabilities>
      </component>
    </vulnerable_components>
  </software_composition_analysis>
</detailedreport>`;
    const output: HDFResults = JSON.parse(await convert(xml));
    const req = output.baselines[0]!.requirements.find(r => r.id === 'CVE-9999-0001')!;
    expect(req.cvss).toHaveLength(1);
    expect(req.cvss![0]!.baseScore).toBe(6.4);
  });

  it('emits no cvss[] when neither vulnerability nor component carries a score', async () => {
    const xml = `<?xml version="1.0" encoding="ISO-8859-1"?>
<detailedreport xmlns="https://www.veracode.com/schema/reports/export/1.0" app_name="NoScore" first_build_submitted_date="2021-12-29 22:16:36 UTC">
  <software_composition_analysis>
    <vulnerable_components>
      <component component_id="c1" file_name="lib.jar" vulnerabilities="1" max_cvss_score="" version="1.0" library="lib" library_id="maven:lib:1.0:" vendor="lib">
        <vulnerabilities>
          <vulnerability cve_id="CVE-9999-0002" cvss_score="" severity="3" cwe_id="" first_found_date="2021-12-29 22:18:20 UTC" cve_summary="no score" severity_desc="Medium"/>
        </vulnerabilities>
      </component>
    </vulnerable_components>
  </software_composition_analysis>
</detailedreport>`;
    const output: HDFResults = JSON.parse(await convert(xml));
    const req = output.baselines[0]!.requirements.find(r => r.id === 'CVE-9999-0002')!;
    expect(req.cvss).toBeUndefined();
  });

  it('emits no cvss[] when the score is non-numeric', async () => {
    const xml = `<?xml version="1.0" encoding="ISO-8859-1"?>
<detailedreport xmlns="https://www.veracode.com/schema/reports/export/1.0" app_name="BadScore" first_build_submitted_date="2021-12-29 22:16:36 UTC">
  <software_composition_analysis>
    <vulnerable_components>
      <component component_id="c1" file_name="lib.jar" vulnerabilities="1" max_cvss_score="" version="1.0" library="lib" library_id="maven:lib:1.0:" vendor="lib">
        <vulnerabilities>
          <vulnerability cve_id="CVE-9999-0003" cvss_score="not-a-number" severity="3" cwe_id="" first_found_date="2021-12-29 22:18:20 UTC" cve_summary="bad score" severity_desc="Medium"/>
        </vulnerabilities>
      </component>
    </vulnerable_components>
  </software_composition_analysis>
</detailedreport>`;
    const output: HDFResults = JSON.parse(await convert(xml));
    const req = output.baselines[0]!.requirements.find(r => r.id === 'CVE-9999-0003')!;
    expect(req.cvss).toBeUndefined();
  });
});

describe('veracode remediation_status description', () => {
  it('carries the flaws remediation_status as a requirement-level description', async () => {
    const input = loadFixture('veracode.xml');
    const output: HDFResults = JSON.parse(await convert(input));
    const cwe = output.baselines[0]!.requirements.find(r => r.id === '18')!;
    const remStatus = cwe.descriptions!.find(d => d.label === 'remediation_status');
    expect(remStatus).toBeDefined();
    expect(remStatus!.data).toBe('New');
  });

  it('omits the remediation_status description when no flaw carries it', async () => {
    const xml = `<?xml version="1.0" encoding="ISO-8859-1"?>
<detailedreport xmlns="https://www.veracode.com/schema/reports/export/1.0" app_name="NoStatus" first_build_submitted_date="2021-12-29 22:16:36 UTC">
  <severity level="5">
    <category categoryid="99" categoryname="No Status" pcirelated="false">
      <cwe cweid="78" cwename="OS Command Injection" pcirelated="false">
        <staticflaws>
          <flaw severity="5" categoryname="No Status" count="1" issueid="1" module="app.war" type="exec" description="d" cweid="78" sourcefile="A.java" line="1" sourcefilepath="com/x/"/>
        </staticflaws>
      </cwe>
    </category>
  </severity>
</detailedreport>`;
    const output: HDFResults = JSON.parse(await convert(xml));
    const req = output.baselines[0]!.requirements.find(r => r.id === '99')!;
    expect(req.descriptions!.find(d => d.label === 'remediation_status')).toBeUndefined();
  });
});

describe('veracode requirement.code (CODE-tab fill)', () => {
  it('sets a synthesized source-context code on static CWE requirements', async () => {
    const input = loadFixture('veracode.xml');
    const output: HDFResults = JSON.parse(await convert(input));
    const cwe = output.baselines[0]!.requirements.find(r => r.id === '18');
    expect(cwe!.code).toBeDefined();
    expect(cwe!.code).toContain(
      'java.lang.String ping(java.lang.String) at com/veracode/verademo/controller/ToolsController.java:53',
    );
  });

  it('serializes the vulnerability/component entry as indented JSON on SCA CVE requirements', async () => {
    const input = loadFixture('veracode.xml');
    const output: HDFResults = JSON.parse(await convert(input));
    const cve = output.baselines[0]!.requirements.find(r => r.id === 'CVE-2012-5783');
    expect(cve!.code).toBeDefined();
    const parsed = JSON.parse(cve!.code!) as {
      cve_id: string;
      cvss_score: string;
      components: { library: string; file_paths: string[] }[];
    };
    expect(parsed.cve_id).toBe('CVE-2012-5783');
    expect(parsed.cvss_score).toBe('5.8');
    expect(parsed.components.length).toBeGreaterThan(0);
  });
});

describe('veracode requirement.sourceLocation', () => {
  it('promotes the first static flaw source-file:line into sourceLocation', async () => {
    const input = loadFixture('veracode.xml');
    const output: HDFResults = JSON.parse(await convert(input));
    const cwe = output.baselines[0]!.requirements.find(r => r.id === '18');
    expect(cwe!.sourceLocation).toBeDefined();
    expect(cwe!.sourceLocation!.ref).toBe('ToolsController.java\nToolsController.java');
    expect(cwe!.sourceLocation!.line).toBe(53);
  });

  it('emits ref without line on SCA CVE requirements (no source line)', async () => {
    const input = loadFixture('veracode.xml');
    const output: HDFResults = JSON.parse(await convert(input));
    const cve = output.baselines[0]!.requirements.find(r => r.id === 'CVE-2012-5783');
    expect(cve!.sourceLocation).toBeDefined();
    expect(cve!.sourceLocation!.ref).toBeTruthy();
    expect(cve!.sourceLocation!.line).toBeUndefined();
  });
});

describe('veracode result.message (exploitability note)', () => {
  it('maps a static flaw result message from the nested exploitability-adjustment note', async () => {
    const input = loadFixture('veracode.xml');
    const output: HDFResults = JSON.parse(await convert(input));
    const messages = output.baselines[0]!.requirements
      .flatMap(r => r.results)
      .map(res => res.message)
      .filter(Boolean);
    expect(messages).toContain(
      'The source of the tainted data in this web application flaw is not a web request.',
    );
  });

  it('omits message on flaws with no exploitability-adjustment note', async () => {
    const input = loadFixture('veracode.xml');
    const output: HDFResults = JSON.parse(await convert(input));
    // Not every flaw carries an adjustment note, so at least one result must lack a message.
    const withoutMessage = output.baselines[0]!.requirements
      .flatMap(r => r.results)
      .some(res => res.message === undefined);
    expect(withoutMessage).toBe(true);
  });
});

describe('veracode unrated severity marker (CWE path)', () => {
  it('tags severity_rating unrated for an absent severity level and omits it for rated levels', async () => {
    const xml = `<?xml version="1.0" encoding="ISO-8859-1"?>
<detailedreport xmlns="https://www.veracode.com/schema/reports/export/1.0" app_name="Unrated" first_build_submitted_date="2021-12-29 22:16:36 UTC">
  <severity>
    <category categoryid="90" categoryname="No Level" pcirelated="false">
      <cwe cweid="78" cwename="OS Command Injection" pcirelated="false">
        <staticflaws>
          <flaw severity="" categoryname="No Level" count="1" issueid="1" module="app.war" type="exec" description="d" cweid="78" sourcefile="A.java" line="1" sourcefilepath="com/x/"/>
        </staticflaws>
      </cwe>
    </category>
  </severity>
  <severity level="3">
    <category categoryid="91" categoryname="Rated" pcirelated="false">
      <cwe cweid="89" cwename="SQL Injection" pcirelated="false">
        <staticflaws>
          <flaw severity="3" categoryname="Rated" count="1" issueid="2" module="app.war" type="sql" description="d" cweid="89" sourcefile="B.java" line="2" sourcefilepath="com/x/"/>
        </staticflaws>
      </cwe>
    </category>
  </severity>
  <severity level="0">
    <category categoryid="92" categoryname="Informational" pcirelated="false">
      <cwe cweid="94" cwename="Code Injection" pcirelated="false">
        <staticflaws>
          <flaw severity="0" categoryname="Informational" count="1" issueid="3" module="app.war" type="info" description="d" cweid="94" sourcefile="C.java" line="3" sourcefilepath="com/x/"/>
        </staticflaws>
      </cwe>
    </category>
  </severity>
</detailedreport>`;
    const output: HDFResults = JSON.parse(await convert(xml));
    const reqs = output.baselines[0]!.requirements;

    const unrated = reqs.find(r => r.id === '90')!;
    expect(unrated.tags!['severity_rating']).toBe('unrated');

    const rated = reqs.find(r => r.id === '91')!;
    expect(rated.tags!['severity_rating']).toBeUndefined();

    // Level 0 is the rated informational tier, not unrated.
    const info = reqs.find(r => r.id === '92')!;
    expect(info.tags!['severity_rating']).toBeUndefined();
  });
});
