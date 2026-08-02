import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, it, expect } from 'vitest';
import { convertBurpsuiteToHdf } from './converter.js';
import { runConverterContractTests } from '../../../shared/typescript/converter-contract.js';
import { expectValidResults } from '../../../test/helpers/expectValidHdf.js';
import { assertRequirementCount } from '../../../shared/typescript/anchor.js';

const FIXTURES_DIR = join(__dirname, '..', 'fixtures');

function loadFixture(name: string): string {
  return readFileSync(join(FIXTURES_DIR, name), 'utf-8');
}

// Helper to parse HDF JSON output
function parseOutput(output: string) {
  return JSON.parse(output) as Record<string, unknown>;
}

// Helper to find requirement by ID
function findRequirement(baselines: Array<Record<string, unknown>>, id: string) {
  for (const baseline of baselines) {
    const reqs = baseline.requirements as Array<Record<string, unknown>>;
    const req = reqs.find(r => r.id === id);
    if (req) return req;
  }
  return undefined;
}

runConverterContractTests({
  converterName: 'burpsuite-to-hdf',
  convertFn: convertBurpsuiteToHdf,
  minimalFixture: 'zero.webappsecurity.com.xml',
});

describe('BurpSuite to HDF Converter', () => {
  // --- Validation tests ---

  it('should synthesize a passed placeholder for empty issues element', async () => {
    const xml = loadFixture('input/empty.xml');
    const output = await convertBurpsuiteToHdf(xml);
    const parsed = parseOutput(output);
    const baselines = parsed.baselines as Array<Record<string, unknown>>;
    expect(baselines).toHaveLength(1);
    const reqs = baselines[0]!.requirements as Array<Record<string, unknown>>;
    expect(reqs).toHaveLength(1);
    expect(reqs[0]!.id).toBe('burpsuite-no-findings');
    const results = reqs[0]!.results as Array<Record<string, unknown>>;
    expect(results[0]!.status).toBe('passed');
    expect(results[0]!.codeDesc).toContain('Burp Suite');
    expect(results[0]!.codeDesc).toContain('Unknown');
    expect(results[0]!.codeDesc).toContain('zero findings');
  });

  // --- Real fixture tests ---

  describe('with zero.webappsecurity.com fixture', () => {
    let output: string;
    let parsed: Record<string, unknown>;
    let baselines: Array<Record<string, unknown>>;

    // Parse once for all tests in this describe block
    it('should convert real BurpSuite scan to HDF format', async () => {
      const xml = loadFixture('input/zero.webappsecurity.com.xml');
      output = await convertBurpsuiteToHdf(xml);
      parsed = parseOutput(output);
      baselines = parsed.baselines as Array<Record<string, unknown>>;
      expectValidResults(parsed);

      expect(parsed).toBeDefined();
      expect(baselines).toBeDefined();
      expect(baselines).toHaveLength(1);
    });

    it('should produce 14 requirements from 60 issues grouped by type', async () => {
      const xml = loadFixture('input/zero.webappsecurity.com.xml');
      const out = parseOutput(await convertBurpsuiteToHdf(xml));
      const bl = out.baselines as Array<Record<string, unknown>>;
      const reqs = bl[0]!.requirements as unknown[];
      expect(reqs).toHaveLength(14);
    });

    it('should set generator correctly', async () => {
      const xml = loadFixture('input/zero.webappsecurity.com.xml');
      const out = parseOutput(await convertBurpsuiteToHdf(xml));
      const gen = out.generator as Record<string, unknown>;
      expect(gen.name).toBe('burpsuite-to-hdf');
      expect(gen.version).toBe('1.0.0');
    });

    it('should set tool correctly', async () => {
      const xml = loadFixture('input/zero.webappsecurity.com.xml');
      const out = parseOutput(await convertBurpsuiteToHdf(xml));
      const ds = out.tool as Record<string, unknown>;
      expect(ds.name).toBe('BurpSuite');
      expect(ds.format).toBeUndefined() // serialization structures are not formats (kpvj);
      expect(ds.version).toBe('2020.1');
    });

    it('should set baseline name to BurpSuite Scan', async () => {
      const xml = loadFixture('input/zero.webappsecurity.com.xml');
      const out = parseOutput(await convertBurpsuiteToHdf(xml));
      const bl = out.baselines as Array<Record<string, unknown>>;
      expect(bl[0]!.name).toBe('BurpSuite Scan');
    });

    it('should set baseline title with site URL', async () => {
      const xml = loadFixture('input/zero.webappsecurity.com.xml');
      const out = parseOutput(await convertBurpsuiteToHdf(xml));
      const bl = out.baselines as Array<Record<string, unknown>>;
      expect(bl[0]!.title).toContain('http://zero.webappsecurity.com');
    });

    it('should set resultsChecksum', async () => {
      const xml = loadFixture('input/zero.webappsecurity.com.xml');
      const out = parseOutput(await convertBurpsuiteToHdf(xml));
      const bl = out.baselines as Array<Record<string, unknown>>;
      const cs = bl[0]!.resultsChecksum as Record<string, unknown>;
      expect(cs).toBeDefined();
      expect(cs.algorithm).toBe('sha256');
      expect((cs.value as string).length).toBe(64);
    });

    it('should set timestamp from exportTime', async () => {
      const xml = loadFixture('input/zero.webappsecurity.com.xml');
      const out = parseOutput(await convertBurpsuiteToHdf(xml));
      expect(out.timestamp).toBeDefined();
      const ts = new Date(out.timestamp as string);
      expect(ts.getFullYear()).toBe(2020);
    });

    it('should set target as Application type', async () => {
      const xml = loadFixture('input/zero.webappsecurity.com.xml');
      const out = parseOutput(await convertBurpsuiteToHdf(xml));
      const targets = out.components as Array<Record<string, unknown>>;
      expect(targets).toHaveLength(1);
      expect(targets[0]!.name).toBe('http://zero.webappsecurity.com');
      expect(targets[0]!.type).toBe('application');
    });

    it('should map Information severity to 0.3 impact', async () => {
      const xml = loadFixture('input/zero.webappsecurity.com.xml');
      const out = parseOutput(await convertBurpsuiteToHdf(xml));
      const bl = out.baselines as Array<Record<string, unknown>>;
      const req = findRequirement(bl, '2098688');
      expect(req).toBeDefined();
      expect(req!.impact).toBe(0.3);
    });

    it('should map Medium severity to 0.5 impact', async () => {
      const xml = loadFixture('input/zero.webappsecurity.com.xml');
      const out = parseOutput(await convertBurpsuiteToHdf(xml));
      const bl = out.baselines as Array<Record<string, unknown>>;
      const req = findRequirement(bl, '16777472');
      expect(req).toBeDefined();
      expect(req!.impact).toBe(0.5);
    });

    it('should map Low severity to 0.3 impact', async () => {
      const xml = loadFixture('input/zero.webappsecurity.com.xml');
      const out = parseOutput(await convertBurpsuiteToHdf(xml));
      const bl = out.baselines as Array<Record<string, unknown>>;
      const req = findRequirement(bl, '16777984');
      expect(req).toBeDefined();
      expect(req!.impact).toBe(0.3);
    });

    it('should group issues by type with multiple results', async () => {
      const xml = loadFixture('input/zero.webappsecurity.com.xml');
      const out = parseOutput(await convertBurpsuiteToHdf(xml));
      const bl = out.baselines as Array<Record<string, unknown>>;
      const req = findRequirement(bl, '2098688');
      expect(req).toBeDefined();
      const results = req!.results as unknown[];
      expect(results.length).toBeGreaterThan(1);
    });

    it('should set all result statuses to failed', async () => {
      const xml = loadFixture('input/zero.webappsecurity.com.xml');
      const out = parseOutput(await convertBurpsuiteToHdf(xml));
      const bl = out.baselines as Array<Record<string, unknown>>;
      const reqs = bl[0]!.requirements as Array<Record<string, unknown>>;
      for (const req of reqs) {
        const results = req.results as Array<Record<string, unknown>>;
        for (const res of results) {
          expect(res.status).toBe('failed');
        }
      }
    });

    it('should include host IP and URL in code desc', async () => {
      const xml = loadFixture('input/zero.webappsecurity.com.xml');
      const out = parseOutput(await convertBurpsuiteToHdf(xml));
      const bl = out.baselines as Array<Record<string, unknown>>;
      const req = findRequirement(bl, '2098688');
      expect(req).toBeDefined();
      const results = req!.results as Array<Record<string, unknown>>;
      expect(results[0]!.codeDesc).toContain('Host:');
      expect(results[0]!.codeDesc).toContain('54.82.22.214');
      expect(results[0]!.codeDesc).toContain('http://zero.webappsecurity.com');
    });

    it('should include location in code desc', async () => {
      const xml = loadFixture('input/zero.webappsecurity.com.xml');
      const out = parseOutput(await convertBurpsuiteToHdf(xml));
      const bl = out.baselines as Array<Record<string, unknown>>;
      const req = findRequirement(bl, '2098688');
      expect(req).toBeDefined();
      const results = req!.results as Array<Record<string, unknown>>;
      expect(results[0]!.codeDesc).toContain('Location:');
    });

    it('should map CWE from vulnerabilityClassifications to NIST', async () => {
      const xml = loadFixture('input/zero.webappsecurity.com.xml');
      const out = parseOutput(await convertBurpsuiteToHdf(xml));
      const bl = out.baselines as Array<Record<string, unknown>>;
      const req = findRequirement(bl, '2098688');
      expect(req).toBeDefined();
      const tags = req!.tags as Record<string, unknown>;
      const nist = tags.nist as string[];
      expect(nist.length).toBeGreaterThan(0);
    });

    it('should include CCI tags', async () => {
      const xml = loadFixture('input/zero.webappsecurity.com.xml');
      const out = parseOutput(await convertBurpsuiteToHdf(xml));
      const bl = out.baselines as Array<Record<string, unknown>>;
      const req = findRequirement(bl, '2098688');
      expect(req).toBeDefined();
      const tags = req!.tags as Record<string, unknown>;
      const cci = tags.cci as string[];
      expect(cci.length).toBeGreaterThan(0);
    });

    it('should include cweid tag', async () => {
      const xml = loadFixture('input/zero.webappsecurity.com.xml');
      const out = parseOutput(await convertBurpsuiteToHdf(xml));
      const bl = out.baselines as Array<Record<string, unknown>>;
      const req = findRequirement(bl, '2098688');
      expect(req).toBeDefined();
      const tags = req!.tags as Record<string, unknown>;
      expect(tags.cweid).toContain('CWE-942');
    });

    it('should have check description from issueBackground (HTML stripped)', async () => {
      const xml = loadFixture('input/zero.webappsecurity.com.xml');
      const out = parseOutput(await convertBurpsuiteToHdf(xml));
      const bl = out.baselines as Array<Record<string, unknown>>;
      const req = findRequirement(bl, '2098688');
      expect(req).toBeDefined();
      const descs = req!.descriptions as Array<Record<string, unknown>>;
      const check = descs.find(d => d.label === 'check');
      expect(check).toBeDefined();
      expect(check!.data).toContain('cross-origin resource sharing');
      expect(check!.data).not.toContain('<p>');
    });

    it('should have fix description from remediationBackground (HTML stripped)', async () => {
      const xml = loadFixture('input/zero.webappsecurity.com.xml');
      const out = parseOutput(await convertBurpsuiteToHdf(xml));
      const bl = out.baselines as Array<Record<string, unknown>>;
      const req = findRequirement(bl, '2098688');
      expect(req).toBeDefined();
      const descs = req!.descriptions as Array<Record<string, unknown>>;
      const fix = descs.find(d => d.label === 'fix');
      expect(fix).toBeDefined();
      expect(fix!.data).toContain('CORS policy');
      expect(fix!.data).not.toContain('<p>');
    });

    it('should set requirement title from issue name', async () => {
      const xml = loadFixture('input/zero.webappsecurity.com.xml');
      const out = parseOutput(await convertBurpsuiteToHdf(xml));
      const bl = out.baselines as Array<Record<string, unknown>>;
      const req = findRequirement(bl, '2098688');
      expect(req).toBeDefined();
      expect(req!.title).toBe('Cross-origin resource sharing');
    });

    it('should include confidence in tags', async () => {
      const xml = loadFixture('input/zero.webappsecurity.com.xml');
      const out = parseOutput(await convertBurpsuiteToHdf(xml));
      const bl = out.baselines as Array<Record<string, unknown>>;
      const req = findRequirement(bl, '2098688');
      expect(req).toBeDefined();
      const tags = req!.tags as Record<string, unknown>;
      expect(tags.confidence).toBe('Certain');
    });

    it('should fall back to SA-11, RA-5 when no CWE mapping exists', async () => {
      const xml = `<?xml version="1.0"?><issues burpVersion="2020.1" exportTime="Thu Feb 27 09:28:17 EST 2020">
  <issue>
    <serialNumber>1</serialNumber>
    <type>999999</type>
    <name>Test Issue</name>
    <host ip="1.2.3.4">http://test.com</host>
    <path>/test</path>
    <location>/test</location>
    <severity>Low</severity>
    <confidence>Certain</confidence>
  </issue>
</issues>`;
      const out = parseOutput(await convertBurpsuiteToHdf(xml));
      const bl = out.baselines as Array<Record<string, unknown>>;
      const req = findRequirement(bl, '999999');
      expect(req).toBeDefined();
      const tags = req!.tags as Record<string, unknown>;
      const nist = tags.nist as string[];
      expect(nist).toEqual(['SA-11', 'RA-5']);
    });

    it('should handle issue with no issueBackground (uses name as default desc)', async () => {
      const xml = `<?xml version="1.0"?><issues burpVersion="2020.1" exportTime="Thu Feb 27 09:28:17 EST 2020">
  <issue>
    <serialNumber>1</serialNumber>
    <type>111</type>
    <name>No Background</name>
    <host ip="1.2.3.4">http://test.com</host>
    <location>/test</location>
    <severity>Medium</severity>
  </issue>
</issues>`;
      const out = parseOutput(await convertBurpsuiteToHdf(xml));
      const bl = out.baselines as Array<Record<string, unknown>>;
      const req = findRequirement(bl, '111');
      expect(req).toBeDefined();
      const descs = req!.descriptions as Array<Record<string, unknown>>;
      const def = descs.find(d => d.label === 'default');
      expect(def!.data).toBe('No Background');
      // No check or fix descriptions
      expect(descs.find(d => d.label === 'check')).toBeUndefined();
      expect(descs.find(d => d.label === 'fix')).toBeUndefined();
    });

    it('should handle issue with issueDetail in codeDesc', async () => {
      const xml = `<?xml version="1.0"?><issues burpVersion="2020.1" exportTime="Thu Feb 27 09:28:17 EST 2020">
  <issue>
    <serialNumber>1</serialNumber>
    <type>222</type>
    <name>With Detail</name>
    <host ip="1.2.3.4">http://test.com</host>
    <location>/test</location>
    <severity>High</severity>
    <issueDetail><![CDATA[<p>Detail text</p>]]></issueDetail>
  </issue>
</issues>`;
      const out = parseOutput(await convertBurpsuiteToHdf(xml));
      const bl = out.baselines as Array<Record<string, unknown>>;
      const req = findRequirement(bl, '222');
      expect(req).toBeDefined();
      const results = req!.results as Array<Record<string, unknown>>;
      expect(results[0]!.codeDesc).toContain('issueDetail');
    });

    it('should handle empty issues list with synthesized placeholder', async () => {
      const xml = `<?xml version="1.0"?><issues burpVersion="2020.1" exportTime="Thu Feb 27 09:28:17 EST 2020">
</issues>`;
      const out = parseOutput(await convertBurpsuiteToHdf(xml));
      const bl = out.baselines as Array<Record<string, unknown>>;
      const reqs = bl[0]!.requirements as Array<Record<string, unknown>>;
      expect(reqs).toHaveLength(1);
      expect(reqs[0]!.id).toBe('burpsuite-no-findings');
      // Target should be 'Unknown' with no issues
      const targets = out.components as Array<Record<string, unknown>>;
      expect(targets[0]!.name).toBe('Unknown');
    });

    it('should handle issue with no burpVersion', async () => {
      const xml = `<?xml version="1.0"?><issues exportTime="Thu Feb 27 09:28:17 EST 2020">
  <issue>
    <serialNumber>1</serialNumber>
    <type>333</type>
    <name>No Version</name>
    <severity>Low</severity>
    <location>/test</location>
  </issue>
</issues>`;
      const out = parseOutput(await convertBurpsuiteToHdf(xml));
      const ds = out.tool as Record<string, unknown>;
      // No version field when burpVersion is empty
      expect(ds.version).toBeUndefined();
    });

    it('should handle issue with no exportTime', async () => {
      const xml = `<?xml version="1.0"?><issues burpVersion="2020.1">
  <issue>
    <serialNumber>1</serialNumber>
    <type>444</type>
    <name>No Export Time</name>
    <severity>Information</severity>
    <location>/test</location>
  </issue>
</issues>`;
      const out = parseOutput(await convertBurpsuiteToHdf(xml));
      // timestamp should not be set when no exportTime
      expect(out.timestamp).toBeUndefined();
      // Information severity → 0.3 impact
      const bl = out.baselines as Array<Record<string, unknown>>;
      const req = findRequirement(bl, '444');
      expect(req!.impact).toBe(0.3);
    });

    it('should handle unknown severity mapping', async () => {
      const xml = `<?xml version="1.0"?><issues burpVersion="2020.1">
  <issue>
    <serialNumber>1</serialNumber>
    <type>555</type>
    <name>Unknown Sev</name>
    <severity>UnknownLevel</severity>
    <location>/test</location>
  </issue>
</issues>`;
      const out = parseOutput(await convertBurpsuiteToHdf(xml));
      const bl = out.baselines as Array<Record<string, unknown>>;
      const req = findRequirement(bl, '555');
      expect(req!.impact).toBe(0.3); // default fallback
    });
  });
});

// Ground-truth anchor (see shared/typescript/anchor.ts). burpsuite groups issues
// by <type> — one requirement per distinct issue type — counted independently.
describe('burpsuite-to-hdf ground-truth anchor', () => {
  function countDistinctBurpTypes(input: string): number {
    const types = new Set<string>();
    for (const m of input.matchAll(/<type>([^<]*)<\/type>/g)) types.add(m[1]);
    return types.size;
  }

  it('emits one requirement per distinct <issue> <type>', async () => {
    const input = loadFixture('input/zero.webappsecurity.com.xml');
    assertRequirementCount(
      await convertBurpsuiteToHdf(input),
      countDistinctBurpTypes(input),
      'zero.webappsecurity.com.xml: one requirement per distinct <issue> <type>',
    );
  });
});
