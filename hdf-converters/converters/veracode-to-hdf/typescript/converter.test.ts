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
});
