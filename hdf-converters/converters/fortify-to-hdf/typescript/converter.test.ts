import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, it, expect } from 'vitest';
import { convertFortifyToHdf } from './converter.js';
import { runConverterContractTests } from '../../../shared/typescript/converter-contract.js';
import { expectValidResults } from '../../../test/helpers/expectValidHdf.js';
import {
  assertRequirementCount,
  countXmlElements,
} from '../../../shared/typescript/anchor.js';

const FIXTURES_DIR = join(__dirname, '..', 'fixtures');

function loadFixture(name: string): string {
  return readFileSync(join(FIXTURES_DIR, name), 'utf-8');
}

function parseOutput(output: string) {
  return JSON.parse(output) as Record<string, unknown>;
}

function findRequirement(baselines: Array<Record<string, unknown>>, id: string) {
  for (const baseline of baselines) {
    const reqs = baseline.requirements as Array<Record<string, unknown>>;
    const req = reqs.find(r => r.id === id);
    if (req) return req;
  }
  return undefined;
}

runConverterContractTests({
  converterName: 'fortify-to-hdf',
  convertFn: convertFortifyToHdf,
  minimalFixture: 'fortify_webgoat_results.fvdl',
});

// Ground-truth anchor (input-derived count; see shared/typescript/anchor.ts):
// one requirement per FVDL <Description> element, counted from the raw XML
// independently of the converter's parser so a silent under-extraction fails
// even when Go/TS agree.
describe('fortify-to-hdf ground-truth anchor', () => {
  it('emits one requirement per FVDL <Description>', async () => {
    const input = loadFixture('input/fortify_webgoat_results.fvdl');
    assertRequirementCount(
      await convertFortifyToHdf(input),
      countXmlElements(input, 'Description'),
      'fortify_webgoat_results.fvdl: one requirement per FVDL <Description>',
    );
  });
});

describe('Fortify to HDF Converter', () => {
  // --- Real fixture tests ---

  describe('with webgoat FVDL fixture', () => {
    it('should convert real Fortify FVDL to HDF format', async () => {
      const fvdl = loadFixture('input/fortify_webgoat_results.fvdl');
      const output = await convertFortifyToHdf(fvdl);
      const parsed = parseOutput(output);
      expectValidResults(parsed);

      expect(parsed).toBeDefined();
      const baselines = parsed.baselines as Array<Record<string, unknown>>;
      expect(baselines).toBeDefined();
      expect(baselines).toHaveLength(1);
    });

    it('should produce 5 requirements from 5 unique Description classIDs', async () => {
      const fvdl = loadFixture('input/fortify_webgoat_results.fvdl');
      const out = parseOutput(await convertFortifyToHdf(fvdl));
      const bl = out.baselines as Array<Record<string, unknown>>;
      const reqs = bl[0]!.requirements as unknown[];
      expect(reqs).toHaveLength(5);
    });

    it('should set generator correctly', async () => {
      const fvdl = loadFixture('input/fortify_webgoat_results.fvdl');
      const out = parseOutput(await convertFortifyToHdf(fvdl));
      const gen = out.generator as Record<string, unknown>;
      expect(gen.name).toBe('fortify-to-hdf');
      expect(gen.version).toBe('1.0.0');
    });

    it('should set tool correctly', async () => {
      const fvdl = loadFixture('input/fortify_webgoat_results.fvdl');
      const out = parseOutput(await convertFortifyToHdf(fvdl));
      const ds = out.tool as Record<string, unknown>;
      expect(ds.name).toBe('Fortify');
      expect(ds.format).toBe('FVDL');
    });

    it('should set baseline name to Fortify Scan', async () => {
      const fvdl = loadFixture('input/fortify_webgoat_results.fvdl');
      const out = parseOutput(await convertFortifyToHdf(fvdl));
      const bl = out.baselines as Array<Record<string, unknown>>;
      expect(bl[0]!.name).toBe('Fortify Scan');
    });

    it('should set baseline title with Fortify Static Analyzer Scan', async () => {
      const fvdl = loadFixture('input/fortify_webgoat_results.fvdl');
      const out = parseOutput(await convertFortifyToHdf(fvdl));
      const bl = out.baselines as Array<Record<string, unknown>>;
      expect(bl[0]!.title).toContain('Fortify Static Analyzer Scan');
    });

    it('should set baseline summary with UUID', async () => {
      const fvdl = loadFixture('input/fortify_webgoat_results.fvdl');
      const out = parseOutput(await convertFortifyToHdf(fvdl));
      const bl = out.baselines as Array<Record<string, unknown>>;
      expect(bl[0]!.summary).toContain('b5e71375-1a97-4708-a07e-9a7e5fedeafe');
    });

    it('should set baseline version from EngineVersion', async () => {
      const fvdl = loadFixture('input/fortify_webgoat_results.fvdl');
      const out = parseOutput(await convertFortifyToHdf(fvdl));
      const bl = out.baselines as Array<Record<string, unknown>>;
      expect(bl[0]!.version).toBe('19.1.0.2241');
    });

    it('should set resultsChecksum', async () => {
      const fvdl = loadFixture('input/fortify_webgoat_results.fvdl');
      const out = parseOutput(await convertFortifyToHdf(fvdl));
      const bl = out.baselines as Array<Record<string, unknown>>;
      const cs = bl[0]!.resultsChecksum as Record<string, unknown>;
      expect(cs).toBeDefined();
      expect(cs.algorithm).toBe('sha256');
      expect((cs.value as string).length).toBe(64);
    });

    it('should set timestamp from CreatedTS', async () => {
      const fvdl = loadFixture('input/fortify_webgoat_results.fvdl');
      const out = parseOutput(await convertFortifyToHdf(fvdl));
      expect(out.timestamp).toBe('2019-10-02T23:00:39Z');
    });

    it('should set target as Repository type', async () => {
      const fvdl = loadFixture('input/fortify_webgoat_results.fvdl');
      const out = parseOutput(await convertFortifyToHdf(fvdl));
      const targets = out.components as Array<Record<string, unknown>>;
      expect(targets).toHaveLength(1);
      expect(targets[0]!.type).toBe('repository');
    });

    it('should set requirement ID from classID', async () => {
      const fvdl = loadFixture('input/fortify_webgoat_results.fvdl');
      const out = parseOutput(await convertFortifyToHdf(fvdl));
      const bl = out.baselines as Array<Record<string, unknown>>;
      const req = findRequirement(bl, '823FE039-A7FE-4AAD-B976-9EC53FFE4A59');
      expect(req).toBeDefined();
    });

    it('should set requirement title from Abstract (HTML stripped)', async () => {
      const fvdl = loadFixture('input/fortify_webgoat_results.fvdl');
      const out = parseOutput(await convertFortifyToHdf(fvdl));
      const bl = out.baselines as Array<Record<string, unknown>>;
      const req = findRequirement(bl, '823FE039-A7FE-4AAD-B976-9EC53FFE4A59');
      expect(req).toBeDefined();
      expect(req!.title).toBeDefined();
      expect(req!.title as string).not.toContain('<Content>');
      expect(req!.title as string).not.toContain('<Paragraph>');
    });

    it('should compute impact from InstanceSeverity / 5', async () => {
      const fvdl = loadFixture('input/fortify_webgoat_results.fvdl');
      const out = parseOutput(await convertFortifyToHdf(fvdl));
      const bl = out.baselines as Array<Record<string, unknown>>;
      // Path Manipulation has InstanceSeverity=3.0 -> 3.0/5 = 0.6
      const req = findRequirement(bl, '823FE039-A7FE-4AAD-B976-9EC53FFE4A59');
      expect(req).toBeDefined();
      expect(req!.impact).toBe(0.6);
    });

    it('should populate cwe[] from the CWE reference and merge CWE->NIST', async () => {
      const fvdl = loadFixture('input/fortify_webgoat_results.fvdl');
      const out = parseOutput(await convertFortifyToHdf(fvdl));
      const bl = out.baselines as Array<Record<string, unknown>>;

      // "CWE ID 22, CWE ID 73" -> ["CWE-22","CWE-73"].
      const pathManip = findRequirement(bl, '823FE039-A7FE-4AAD-B976-9EC53FFE4A59');
      expect(pathManip!.cwe).toEqual(['CWE-22', 'CWE-73']);

      // CWE-497 maps to NIST SI-11; native reference is AC-4, so both appear.
      const sysInfo = findRequirement(bl, 'FE4EADF2-7055-4C36-863E-5A01C4A0E1A4');
      expect(sysInfo!.cwe).toEqual(['CWE-497']);
      const nist = (sysInfo!.tags as Record<string, unknown>).nist as string[];
      expect(nist).toContain('AC-4');
      expect(nist).toContain('SI-11');

      // CWE-561 has no NIST mapping: cwe[] set, native NIST untouched.
      const deadCode = findRequirement(bl, '3E7BCE41-4A79-49FF-8B8B-3F55F1F2DC5E');
      expect(deadCode!.cwe).toEqual(['CWE-561']);
      expect((deadCode!.tags as Record<string, unknown>).nist).toEqual(['SA-11', 'RA-5']);
    });

    it('should set default description from Explanation (HTML stripped)', async () => {
      const fvdl = loadFixture('input/fortify_webgoat_results.fvdl');
      const out = parseOutput(await convertFortifyToHdf(fvdl));
      const bl = out.baselines as Array<Record<string, unknown>>;
      const req = findRequirement(bl, '823FE039-A7FE-4AAD-B976-9EC53FFE4A59');
      expect(req).toBeDefined();
      const descs = req!.descriptions as Array<Record<string, unknown>>;
      const defaultDesc = descs.find(d => d.label === 'default');
      expect(defaultDesc).toBeDefined();
      expect(defaultDesc!.data as string).not.toContain('<Content>');
      expect((defaultDesc!.data as string).length).toBeGreaterThan(0);
    });

    it('should have NIST tags from Description references', async () => {
      const fvdl = loadFixture('input/fortify_webgoat_results.fvdl');
      const out = parseOutput(await convertFortifyToHdf(fvdl));
      const bl = out.baselines as Array<Record<string, unknown>>;
      const req = findRequirement(bl, '823FE039-A7FE-4AAD-B976-9EC53FFE4A59');
      expect(req).toBeDefined();
      const tags = req!.tags as Record<string, unknown>;
      const nist = tags.nist as string[];
      expect(nist.length).toBeGreaterThan(0);
    });

    it('should surface Description Tips as a "tips" description', async () => {
      const fvdl = loadFixture('input/fortify_webgoat_results.fvdl');
      const out = parseOutput(await convertFortifyToHdf(fvdl));
      const bl = out.baselines as Array<Record<string, unknown>>;

      const pathManip = findRequirement(bl, '823FE039-A7FE-4AAD-B976-9EC53FFE4A59');
      const descs = pathManip!.descriptions as Array<Record<string, unknown>>;
      const tips = descs.find(d => d.label === 'tips');
      expect(tips).toBeDefined();
      const tipsData = tips!.data as string;
      expect(tipsData).toContain('If the program is performing custom input validation');
      // Multiple tips joined into one body.
      expect(tipsData).toContain('Implementation of an effective blacklist');
      expect(tipsData).toContain('\n\n');

      // Entity-escaped markup (&lt;code&gt;) inside a Tip is stripped.
      const exc = findRequirement(bl, '8843F319-8A22-4101-A378-C2B2F2597988');
      const excDescs = exc!.descriptions as Array<Record<string, unknown>>;
      const excTips = (excDescs.find(d => d.label === 'tips')!.data as string);
      expect(excTips).toContain('Thread.sleep()');
      expect(excTips).not.toContain('<code>');
      expect(excTips).not.toContain('&lt;');
    });

    it('should leave a tips description off a Description without Tips', async () => {
      const fvdl = loadFixture('input/fortify_webgoat_results.fvdl');
      const out = parseOutput(await convertFortifyToHdf(fvdl));
      const bl = out.baselines as Array<Record<string, unknown>>;
      const deadCode = findRequirement(bl, '3E7BCE41-4A79-49FF-8B8B-3F55F1F2DC5E');
      const descs = deadCode!.descriptions as Array<Record<string, unknown>>;
      expect(descs.find(d => d.label === 'tips')).toBeUndefined();
    });

    it('should surface external-URL references as refs[]', async () => {
      const fvdl = loadFixture('input/fortify_webgoat_results.fvdl');
      const out = parseOutput(await convertFortifyToHdf(fvdl));
      const bl = out.baselines as Array<Record<string, unknown>>;
      const pathManip = findRequirement(bl, '823FE039-A7FE-4AAD-B976-9EC53FFE4A59');
      const refs = pathManip!.refs as Array<Record<string, unknown>>;
      expect(refs).toHaveLength(2);
      expect(refs[0]!.url).toBe(
        'https://www.securecoding.cert.org/confluence/display/java/FIO00-J.+Do+not+operate+on+files+in+shared+directories',
      );
      expect(refs[1]!.url).toBe(
        'http://www.oracle.com/technetwork/java/seccodeguide-139067.html#5',
      );
    });

    it('should leave refs unset when no reference carries a URL', async () => {
      const fvdl = loadFixture('input/fortify_webgoat_results.fvdl');
      const out = parseOutput(await convertFortifyToHdf(fvdl));
      const bl = out.baselines as Array<Record<string, unknown>>;
      const deadCode = findRequirement(bl, '3E7BCE41-4A79-49FF-8B8B-3F55F1F2DC5E');
      expect(deadCode!.refs).toBeUndefined();
    });

    it('should set all result statuses to failed', async () => {
      const fvdl = loadFixture('input/fortify_webgoat_results.fvdl');
      const out = parseOutput(await convertFortifyToHdf(fvdl));
      const bl = out.baselines as Array<Record<string, unknown>>;
      const reqs = bl[0]!.requirements as Array<Record<string, unknown>>;
      for (const req of reqs) {
        const results = req.results as Array<Record<string, unknown>>;
        for (const res of results) {
          expect(res.status).toBe('failed');
        }
      }
    });

    it('should populate requirement.code with the raw source snippet', async () => {
      const fvdl = loadFixture('input/fortify_webgoat_results.fvdl');
      const out = parseOutput(await convertFortifyToHdf(fvdl));
      const bl = out.baselines as Array<Record<string, unknown>>;
      const req = findRequirement(bl, '823FE039-A7FE-4AAD-B976-9EC53FFE4A59');
      expect(req).toBeDefined();

      const code = req!.code as string;
      expect(code).toBeDefined();
      // Raw source, not the "Path:/StartLine:/Code:" codeDesc wrapper.
      expect(code.startsWith('Path:')).toBe(false);
      expect(code).toContain(
        'System.out.println(MD5.getHashString(new File(element))',
      );

      // The snippet appears verbatim inside the result codeDesc.
      const results = req!.results as Array<Record<string, unknown>>;
      expect(results[0]!.codeDesc as string).toContain(code);

      // Every requirement in this fixture carries a primary-trace snippet.
      const reqs = bl[0]!.requirements as Array<Record<string, unknown>>;
      for (const r of reqs) {
        expect(r.code).toBeDefined();
      }
    });

    it('should leave requirement.code unset when the finding has no snippet', async () => {
      const fvdl = `<?xml version="1.0" encoding="UTF-8"?>
<FVDL xmlns="xmlns://www.fortifysoftware.com/schema/fvdl" version="1.12">
<Vulnerabilities>
  <Vulnerability>
    <ClassInfo><ClassID>C3</ClassID></ClassInfo>
    <InstanceInfo><InstanceID>I3</InstanceID></InstanceInfo>
  </Vulnerability>
</Vulnerabilities>
<Description classID="C3">
  <Abstract>No trace</Abstract>
  <Explanation>Explanation text</Explanation>
</Description>
</FVDL>`;
      const out = parseOutput(await convertFortifyToHdf(fvdl));
      const bl = out.baselines as Array<Record<string, unknown>>;
      const reqs = bl[0]!.requirements as Array<Record<string, unknown>>;
      expect(reqs[0]!.code).toBeUndefined();
    });

    it('should leave requirement.code unset when trace nodes resolve to no snippet', async () => {
      // First node has no snippet attribute; second references a snippet id
      // absent from <Snippets>. Both are skipped → code stays unset.
      const fvdl = `<?xml version="1.0" encoding="UTF-8"?>
<FVDL xmlns="xmlns://www.fortifysoftware.com/schema/fvdl" version="1.12">
<Vulnerabilities>
  <Vulnerability>
    <ClassInfo><ClassID>C9</ClassID></ClassInfo>
    <InstanceInfo><InstanceID>I9</InstanceID></InstanceInfo>
    <AnalysisInfo><Unified><Trace><Primary>
      <Entry><Node isDefault="true"><SourceLocation path="a.java" line="1"/></Node></Entry>
      <Entry><Node isDefault="false"><SourceLocation path="b.java" line="2" snippet="MISSING"/></Node></Entry>
    </Primary></Trace></Unified></AnalysisInfo>
  </Vulnerability>
</Vulnerabilities>
<Description classID="C9"><Abstract>Crafted</Abstract><Explanation>Expl</Explanation></Description>
<Snippets/>
</FVDL>`;
      const out = parseOutput(await convertFortifyToHdf(fvdl));
      const bl = out.baselines as Array<Record<string, unknown>>;
      const reqs = bl[0]!.requirements as Array<Record<string, unknown>>;
      expect(reqs[0]!.code).toBeUndefined();
    });

    it('should include snippet info in code desc', async () => {
      const fvdl = loadFixture('input/fortify_webgoat_results.fvdl');
      const out = parseOutput(await convertFortifyToHdf(fvdl));
      const bl = out.baselines as Array<Record<string, unknown>>;
      const reqs = bl[0]!.requirements as Array<Record<string, unknown>>;
      // At least one requirement should have results with non-empty codeDesc
      let foundSnippet = false;
      for (const req of reqs) {
        const results = req.results as Array<Record<string, unknown>>;
        for (const res of results) {
          if (res.codeDesc && (res.codeDesc as string).length > 0) {
            foundSnippet = true;
          }
        }
      }
      expect(foundSnippet).toBe(true);
    });
  });

  // --- Minimal FVDL test ---

  it('should handle minimal FVDL with no vulnerabilities', async () => {
    const minimalFvdl = `<?xml version="1.0" encoding="UTF-8"?>
<FVDL xmlns="xmlns://www.fortifysoftware.com/schema/fvdl" version="1.12">
<CreatedTS date="2024-01-15" time="10:00:00"/>
<UUID>test-uuid-1234</UUID>
<Build>
  <BuildID>test</BuildID>
  <NumberFiles>0</NumberFiles>
  <SourceBasePath>/tmp/test</SourceBasePath>
  <SourceFiles/>
</Build>
<Vulnerabilities/>
<Description contentType="preformatted" classID="TEST-001">
  <Abstract>Test abstract</Abstract>
  <Explanation>Test explanation</Explanation>
  <Recommendations>Test recommendations</Recommendations>
  <References/>
</Description>
<Snippets/>
<EngineData>
  <EngineVersion>20.0.0</EngineVersion>
  <RulePacks/>
  <Properties type="System"/>
  <CommandLine/>
  <Errors/>
  <MachineInfo/>
</EngineData>
</FVDL>`;

    const output = await convertFortifyToHdf(minimalFvdl);
    const parsed = parseOutput(output);
    const baselines = parsed.baselines as Array<Record<string, unknown>>;
    expect(baselines).toHaveLength(1);
    expect(baselines[0]!.name).toBe('Fortify Scan');
    const reqs = baselines[0]!.requirements as unknown[];
    expect(reqs).toHaveLength(1);
  });

  it('should synthesize a passed placeholder when input has zero findings', async () => {
    const fvdl = loadFixture('input/empty.fvdl');
    const out = parseOutput(await convertFortifyToHdf(fvdl));
    const baselines = out.baselines as Array<Record<string, unknown>>;
    expect(baselines).toHaveLength(1);
    const reqs = baselines[0]!.requirements as Array<Record<string, unknown>>;
    expect(reqs).toHaveLength(1);
    expect(reqs[0]!.id).toBe('fortify-no-findings');
    const results = reqs[0]!.results as Array<Record<string, unknown>>;
    expect(results).toHaveLength(1);
    expect(results[0]!.status).toBe('passed');
    expect(results[0]!.codeDesc as string).toContain('Fortify');
    expect(results[0]!.codeDesc as string).toContain('/src/cleanproject');
  });

  // --- Edge cases: missing optional fields ---

  it('should handle FVDL with no CreatedTS', async () => {
    const fvdl = `<?xml version="1.0" encoding="UTF-8"?>
<FVDL xmlns="xmlns://www.fortifysoftware.com/schema/fvdl" version="1.12">
<Build><BuildID>test-build</BuildID></Build>
<Vulnerabilities/>
<EngineData/>
</FVDL>`;
    const out = parseOutput(await convertFortifyToHdf(fvdl));
    // No timestamp when no CreatedTS
    expect(out.timestamp).toBeUndefined();
    // Target falls back to BuildID when no SourceBasePath
    const targets = out.components as Array<Record<string, unknown>>;
    expect(targets[0]!.name).toBe('test-build');
  });

  it('should handle FVDL with no Build element', async () => {
    const fvdl = `<?xml version="1.0" encoding="UTF-8"?>
<FVDL xmlns="xmlns://www.fortifysoftware.com/schema/fvdl" version="1.12">
<Vulnerabilities/>
</FVDL>`;
    const out = parseOutput(await convertFortifyToHdf(fvdl));
    const targets = out.components as Array<Record<string, unknown>>;
    expect(targets[0]!.name).toBe('Unknown');
  });

  it('should reject XML without FVDL root element', async () => {
    const xml = `<?xml version="1.0"?><other><data/></other>`;
    await expect(convertFortifyToHdf(xml)).rejects.toThrow('invalid FVDL');
  });

  it('should handle description with no Explanation (falls back to title)', async () => {
    const fvdl = `<?xml version="1.0" encoding="UTF-8"?>
<FVDL xmlns="xmlns://www.fortifysoftware.com/schema/fvdl" version="1.12">
<Vulnerabilities>
  <Vulnerability>
    <ClassInfo><ClassID>C1</ClassID><DefaultSeverity>0</DefaultSeverity></ClassInfo>
    <InstanceInfo><InstanceID>I1</InstanceID></InstanceInfo>
  </Vulnerability>
</Vulnerabilities>
<Description classID="C1">
  <Abstract>The title only</Abstract>
</Description>
</FVDL>`;
    const out = parseOutput(await convertFortifyToHdf(fvdl));
    const bl = out.baselines as Array<Record<string, unknown>>;
    const reqs = bl[0]!.requirements as Array<Record<string, unknown>>;
    expect(reqs).toHaveLength(1);
    const descs = reqs[0]!.descriptions as Array<Record<string, unknown>>;
    const defaultDesc = descs.find(d => d.label === 'default');
    // Falls back to title when no Explanation
    expect(defaultDesc!.data).toBe('The title only');
    // Impact should be 0 (0/5)
    expect(reqs[0]!.impact).toBe(0);
  });

  it('should handle vulnerability with no snippet and no SourceLocation path', async () => {
    const fvdl = `<?xml version="1.0" encoding="UTF-8"?>
<FVDL xmlns="xmlns://www.fortifysoftware.com/schema/fvdl" version="1.12">
<Vulnerabilities>
  <Vulnerability>
    <ClassInfo><ClassID>C2</ClassID></ClassInfo>
    <InstanceInfo><InstanceID>I2</InstanceID></InstanceInfo>
    <AnalysisInfo>
      <Unified>
        <Trace>
          <Primary>
            <Entry>
              <Node isDefault="true">
                <SourceLocation line="42"/>
              </Node>
            </Entry>
            <Entry>
              <Node isDefault="false">
                <SourceLocation path="test.java" line="10"/>
              </Node>
            </Entry>
          </Primary>
        </Trace>
      </Unified>
    </AnalysisInfo>
  </Vulnerability>
</Vulnerabilities>
<Description classID="C2">
  <Abstract>Vuln with trace entries</Abstract>
  <Explanation>Some explanation</Explanation>
</Description>
</FVDL>`;
    const out = parseOutput(await convertFortifyToHdf(fvdl));
    const bl = out.baselines as Array<Record<string, unknown>>;
    const reqs = bl[0]!.requirements as Array<Record<string, unknown>>;
    const results = reqs[0]!.results as Array<Record<string, unknown>>;
    // Should have codeDesc with Path from the second entry (first has no path)
    expect(results[0]!.codeDesc).toContain('test.java');
  });

  it('should handle vulnerability with no AnalysisInfo (empty codeDesc fallback)', async () => {
    const fvdl = `<?xml version="1.0" encoding="UTF-8"?>
<FVDL xmlns="xmlns://www.fortifysoftware.com/schema/fvdl" version="1.12">
<Vulnerabilities>
  <Vulnerability>
    <ClassInfo><ClassID>C3</ClassID></ClassInfo>
    <InstanceInfo><InstanceID>I3</InstanceID></InstanceInfo>
  </Vulnerability>
</Vulnerabilities>
<Description classID="C3">
  <Abstract>No trace</Abstract>
  <Explanation>Explanation text</Explanation>
  <References>
    <Reference>
      <Title>SI-10</Title>
      <Author>Standards Mapping - NIST Special Publication 800-53 Revision 4</Author>
    </Reference>
  </References>
</Description>
</FVDL>`;
    const out = parseOutput(await convertFortifyToHdf(fvdl));
    const bl = out.baselines as Array<Record<string, unknown>>;
    const reqs = bl[0]!.requirements as Array<Record<string, unknown>>;
    const results = reqs[0]!.results as Array<Record<string, unknown>>;
    // Fallback codeDesc when no entries
    expect(results[0]!.codeDesc).toContain('ClassID: C3');
    // NIST tag from Reference
    const tags = reqs[0]!.tags as Record<string, unknown>;
    expect(tags.nist).toContain('SI-10');
  });

  it('should fall back to default NIST tags when no NIST reference found', async () => {
    const fvdl = `<?xml version="1.0" encoding="UTF-8"?>
<FVDL xmlns="xmlns://www.fortifysoftware.com/schema/fvdl" version="1.12">
<Vulnerabilities>
  <Vulnerability>
    <ClassInfo><ClassID>C4</ClassID></ClassInfo>
  </Vulnerability>
</Vulnerabilities>
<Description classID="C4">
  <Abstract>No refs</Abstract>
  <Explanation>Explanation</Explanation>
</Description>
</FVDL>`;
    const out = parseOutput(await convertFortifyToHdf(fvdl));
    const bl = out.baselines as Array<Record<string, unknown>>;
    const reqs = bl[0]!.requirements as Array<Record<string, unknown>>;
    const tags = reqs[0]!.tags as Record<string, unknown>;
    const nist = tags.nist as string[];
    expect(nist.length).toBeGreaterThan(0);
  });

  it('should leave cwe unset when the Description has no CWE reference', async () => {
    const fvdl = `<?xml version="1.0" encoding="UTF-8"?>
<FVDL xmlns="xmlns://www.fortifysoftware.com/schema/fvdl" version="1.12">
<Vulnerabilities>
  <Vulnerability>
    <ClassInfo><ClassID>CN</ClassID><DefaultSeverity>3.0</DefaultSeverity></ClassInfo>
    <InstanceInfo><InstanceID>I</InstanceID><InstanceSeverity>3.0</InstanceSeverity></InstanceInfo>
  </Vulnerability>
</Vulnerabilities>
<Description classID="CN">
  <Abstract>No CWE</Abstract><Explanation>e</Explanation>
  <References>
    <Reference><Title>SI-10</Title><Author>Standards Mapping - NIST Special Publication 800-53 Revision 4</Author></Reference>
  </References>
</Description>
</FVDL>`;
    const out = parseOutput(await convertFortifyToHdf(fvdl));
    const bl = out.baselines as Array<Record<string, unknown>>;
    const reqs = bl[0]!.requirements as Array<Record<string, unknown>>;
    expect(reqs[0]!.cwe).toBeUndefined();
    expect((reqs[0]!.tags as Record<string, unknown>).nist).toEqual(['SI-10']);
  });

  it('should leave cwe unset when the CWE reference has no numeric ID', async () => {
    const fvdl = `<?xml version="1.0" encoding="UTF-8"?>
<FVDL xmlns="xmlns://www.fortifysoftware.com/schema/fvdl" version="1.12">
<Vulnerabilities>
  <Vulnerability>
    <ClassInfo><ClassID>CX</ClassID><DefaultSeverity>3.0</DefaultSeverity></ClassInfo>
    <InstanceInfo><InstanceID>I</InstanceID><InstanceSeverity>3.0</InstanceSeverity></InstanceInfo>
  </Vulnerability>
</Vulnerabilities>
<Description classID="CX">
  <Abstract>a</Abstract><Explanation>e</Explanation>
  <References>
    <Reference><Title>Not applicable</Title><Author>Standards Mapping - Common Weakness Enumeration</Author></Reference>
  </References>
</Description>
</FVDL>`;
    const out = parseOutput(await convertFortifyToHdf(fvdl));
    const bl = out.baselines as Array<Record<string, unknown>>;
    const reqs = bl[0]!.requirements as Array<Record<string, unknown>>;
    expect(reqs[0]!.cwe).toBeUndefined();
  });

  it('should derive impact from InstanceSeverity, not DefaultSeverity', async () => {
    const fvdl = `<?xml version="1.0" encoding="UTF-8"?>
<FVDL xmlns="xmlns://www.fortifysoftware.com/schema/fvdl" version="1.12">
<Vulnerabilities>
  <Vulnerability>
    <ClassInfo><ClassID>CDIV</ClassID><DefaultSeverity>5.0</DefaultSeverity></ClassInfo>
    <InstanceInfo><InstanceID>I</InstanceID><InstanceSeverity>1.0</InstanceSeverity></InstanceInfo>
  </Vulnerability>
</Vulnerabilities>
<Description classID="CDIV"><Abstract>Divergent</Abstract><Explanation>e</Explanation></Description>
</FVDL>`;
    const out = parseOutput(await convertFortifyToHdf(fvdl));
    const bl = out.baselines as Array<Record<string, unknown>>;
    const reqs = bl[0]!.requirements as Array<Record<string, unknown>>;
    // 1.0/5 = 0.2, NOT DefaultSeverity 5.0/5 = 1.0
    expect(reqs[0]!.impact).toBe(0.2);
  });

  it('should handle description with classID not matching any vulnerability', async () => {
    const fvdl = `<?xml version="1.0" encoding="UTF-8"?>
<FVDL xmlns="xmlns://www.fortifysoftware.com/schema/fvdl" version="1.12">
<Vulnerabilities/>
<Description classID="orphan">
  <Abstract>Orphaned description</Abstract>
  <Explanation>Explanation</Explanation>
  <Recommendations>Fix it</Recommendations>
</Description>
</FVDL>`;
    const out = parseOutput(await convertFortifyToHdf(fvdl));
    const bl = out.baselines as Array<Record<string, unknown>>;
    const reqs = bl[0]!.requirements as Array<Record<string, unknown>>;
    expect(reqs).toHaveLength(1);
    expect(reqs[0]!.id).toBe('orphan');
    // Fix description from Recommendations
    const descs = reqs[0]!.descriptions as Array<Record<string, unknown>>;
    const fix = descs.find(d => d.label === 'fix');
    expect(fix).toBeDefined();
    expect(fix!.data).toBe('Fix it');
  });

  // The Fortify ClassInfo categorization (kingdom, class_type, subtype, analyzer)
  // must surface as requirement.tags from the representative finding.
  it('should surface ClassInfo categorization as tags', async () => {
    const fvdl = loadFixture('input/fortify_webgoat_results.fvdl');
    const out = parseOutput(await convertFortifyToHdf(fvdl));
    const bl = out.baselines as Array<Record<string, unknown>>;
    const reqs = bl[0]!.requirements as Array<Record<string, unknown>>;

    // Empty Catch Block: all four ClassInfo fields present.
    const exc = findRequirement(bl, '8843F319-8A22-4101-A378-C2B2F2597988')!;
    const excTags = exc.tags as Record<string, unknown>;
    expect(excTags.kingdom).toBe('Errors');
    expect(excTags.class_type).toBe('Poor Error Handling');
    expect(excTags.subtype).toBe('Empty Catch Block');
    expect(excTags.analyzer).toBe('structural');
    // class_type must not clobber the NIST/CCI tags.
    expect(excTags.nist).toBeDefined();

    // Path Manipulation carries no <Subtype> — that key is omitted.
    const pathManip = findRequirement(bl, '823FE039-A7FE-4AAD-B976-9EC53FFE4A59')!;
    const pmTags = pathManip.tags as Record<string, unknown>;
    expect(pmTags.kingdom).toBe('Input Validation and Representation');
    expect(pmTags.class_type).toBe('Path Manipulation');
    expect(pmTags.analyzer).toBe('dataflow');
    expect('subtype' in pmTags).toBe(false);

    void reqs;
  });

  // A Description whose classID matches no vulnerability (no ClassInfo) must not
  // emit any ClassInfo tags.
  it('should omit ClassInfo tags when no vulnerability is present', async () => {
    const fvdl = `<?xml version="1.0" encoding="UTF-8"?>
<FVDL xmlns="xmlns://www.fortifysoftware.com/schema/fvdl" version="1.12">
<Vulnerabilities/>
<Description classID="NOVULN"><Abstract>a</Abstract><Explanation>e</Explanation></Description>
</FVDL>`;
    const out = parseOutput(await convertFortifyToHdf(fvdl));
    const bl = out.baselines as Array<Record<string, unknown>>;
    const reqs = bl[0]!.requirements as Array<Record<string, unknown>>;
    const tags = reqs[0]!.tags as Record<string, unknown>;
    for (const key of ['kingdom', 'class_type', 'subtype', 'analyzer']) {
      expect(key in tags).toBe(false);
    }
  });

  // requirement.sourceLocation promotes the representative finding's file/line
  // locus (primary-trace default node) into the structured, machine-addressable
  // HDF field.
  it('should promote the representative finding locus into sourceLocation', async () => {
    const fvdl = loadFixture('input/fortify_webgoat_results.fvdl');
    const out = parseOutput(await convertFortifyToHdf(fvdl));
    const bl = out.baselines as Array<Record<string, unknown>>;
    const pathManip = findRequirement(bl, '823FE039-A7FE-4AAD-B976-9EC53FFE4A59')!;
    const sl = pathManip.sourceLocation as Record<string, unknown>;
    expect(sl).toBeDefined();
    expect(sl.ref).toBe('webgoat-lessons/challenge/src/main/java/org/owasp/webgoat/challenges/challenge7/MD5.java');
    expect(sl.line).toBe(55);
  });

  // A non-numeric source line must yield ref only, with line omitted.
  it('should omit line when the source line is non-numeric', async () => {
    const fvdl = `<?xml version="1.0" encoding="UTF-8"?>
<FVDL xmlns="xmlns://www.fortifysoftware.com/schema/fvdl" version="1.12">
<Vulnerabilities>
  <Vulnerability>
    <ClassInfo><ClassID>C7</ClassID></ClassInfo>
    <InstanceInfo><InstanceID>I7</InstanceID></InstanceInfo>
    <AnalysisInfo><Unified><Trace><Primary>
      <Entry><Node isDefault="true"><SourceLocation path="a.java" line="notanumber"/></Node></Entry>
    </Primary></Trace></Unified></AnalysisInfo>
  </Vulnerability>
</Vulnerabilities>
<Description classID="C7"><Abstract>a</Abstract><Explanation>e</Explanation></Description>
</FVDL>`;
    const out = parseOutput(await convertFortifyToHdf(fvdl));
    const bl = out.baselines as Array<Record<string, unknown>>;
    const reqs = bl[0]!.requirements as Array<Record<string, unknown>>;
    const sl = reqs[0]!.sourceLocation as Record<string, unknown>;
    expect(sl).toBeDefined();
    expect(sl.ref).toBe('a.java');
    expect('line' in sl).toBe(false);
  });

  // A finding whose representative trace carries no path must leave
  // sourceLocation unset (NOT-IN-SOURCE) rather than fabricating one.
  it('should omit sourceLocation when no primary-trace path is present', async () => {
    const fvdl = `<?xml version="1.0" encoding="UTF-8"?>
<FVDL xmlns="xmlns://www.fortifysoftware.com/schema/fvdl" version="1.12">
<Vulnerabilities>
  <Vulnerability>
    <ClassInfo><ClassID>C8</ClassID></ClassInfo>
    <InstanceInfo><InstanceID>I8</InstanceID></InstanceInfo>
  </Vulnerability>
</Vulnerabilities>
<Description classID="C8"><Abstract>a</Abstract><Explanation>e</Explanation></Description>
</FVDL>`;
    const out = parseOutput(await convertFortifyToHdf(fvdl));
    const bl = out.baselines as Array<Record<string, unknown>>;
    const reqs = bl[0]!.requirements as Array<Record<string, unknown>>;
    expect('sourceLocation' in reqs[0]!).toBe(false);
  });
});

describe('fortify unrated severity marker', () => {
  const buildFvdl = (instanceInfo: string): string => `<?xml version="1.0" encoding="UTF-8"?>
<FVDL xmlns="xmlns://www.fortifysoftware.com/schema/fvdl" version="1.12">
<Vulnerabilities>
  <Vulnerability>
    <ClassInfo><ClassID>CU</ClassID><DefaultSeverity>3.0</DefaultSeverity></ClassInfo>
    ${instanceInfo}
  </Vulnerability>
</Vulnerabilities>
<Description classID="CU"><Abstract>a</Abstract><Explanation>e</Explanation></Description>
</FVDL>`;

  it('tags severity_rating unrated when InstanceSeverity is absent and omits it when rated', async () => {
    const unratedOut = parseOutput(
      await convertFortifyToHdf(buildFvdl('<InstanceInfo><InstanceID>I</InstanceID></InstanceInfo>')),
    );
    const unratedReqs = (unratedOut.baselines as Array<Record<string, unknown>>)[0]!
      .requirements as Array<Record<string, unknown>>;
    expect((unratedReqs[0]!.tags as Record<string, unknown>).severity_rating).toBe('unrated');

    const ratedOut = parseOutput(
      await convertFortifyToHdf(
        buildFvdl('<InstanceInfo><InstanceID>I</InstanceID><InstanceSeverity>3.0</InstanceSeverity></InstanceInfo>'),
      ),
    );
    const ratedReqs = (ratedOut.baselines as Array<Record<string, unknown>>)[0]!
      .requirements as Array<Record<string, unknown>>;
    expect((ratedReqs[0]!.tags as Record<string, unknown>).severity_rating).toBeUndefined();
  });

  it('treats a non-numeric InstanceSeverity as unrated at impact 0, never NaN', async () => {
    // Go hard-errors on a non-numeric float during unmarshal; TS is lenient
    // but must stay schema-valid: impact 0.0 + the unrated marker.
    const out = parseOutput(
      await convertFortifyToHdf(
        buildFvdl('<InstanceInfo><InstanceID>I</InstanceID><InstanceSeverity>abc</InstanceSeverity></InstanceInfo>'),
      ),
    );
    const reqs = (out.baselines as Array<Record<string, unknown>>)[0]!
      .requirements as Array<Record<string, unknown>>;
    expect(reqs[0]!.impact).toBe(0);
    expect((reqs[0]!.tags as Record<string, unknown>).severity_rating).toBe('unrated');
  });
});
