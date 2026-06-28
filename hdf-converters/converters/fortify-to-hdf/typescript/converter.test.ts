import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, it, expect } from 'vitest';
import { convertFortifyToHdf } from './converter.js';
import { runConverterContractTests } from '../../../shared/typescript/converter-contract.js';
import { expectValidResults } from '../../../test/helpers/expectValidHdf.js';

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

    it('should compute impact from DefaultSeverity / 5', async () => {
      const fvdl = loadFixture('input/fortify_webgoat_results.fvdl');
      const out = parseOutput(await convertFortifyToHdf(fvdl));
      const bl = out.baselines as Array<Record<string, unknown>>;
      // Path Manipulation has DefaultSeverity=3.0 -> 3.0/5 = 0.6
      const req = findRequirement(bl, '823FE039-A7FE-4AAD-B976-9EC53FFE4A59');
      expect(req).toBeDefined();
      expect(req!.impact).toBe(0.6);
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
});
