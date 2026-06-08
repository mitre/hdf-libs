import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, it, expect } from 'vitest';
import { convertScoutsuiteToHdf } from './converter.js';
import { runConverterContractTests } from '../../../shared/typescript/converter-contract.js';

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
  converterName: 'scoutsuite-to-hdf',
  convertFn: convertScoutsuiteToHdf,
  minimalFixture: 'scoutsuite_sample.js',
});

describe('ScoutSuite to HDF Converter', () => {
  // --- Validation tests ---

  it('should handle pure JSON without JS prefix', async () => {
    const input = '{"account_id": "123", "provider_name": "AWS", "services": {}, "last_run": {"time": "2021-01-01 00:00:00+0000", "version": "5.0.0", "ruleset_name": "test", "ruleset_about": "test"}}';
    const output = await convertScoutsuiteToHdf(input);
    const parsed = parseOutput(output);
    const baselines = parsed.baselines as Array<Record<string, unknown>>;
    expect(baselines).toHaveLength(1);
    const reqs = baselines[0]!.requirements as Array<Record<string, unknown>>;
    expect(reqs).toHaveLength(1);
    expect(reqs[0]!.id).toBe('scoutsuite-no-findings');
  });

  it('should synthesize a passed placeholder for empty findings', async () => {
    const input = loadFixture('input/empty.js');
    const output = await convertScoutsuiteToHdf(input);
    const parsed = parseOutput(output);
    const baselines = parsed.baselines as Array<Record<string, unknown>>;
    expect(baselines).toHaveLength(1);
    const reqs = baselines[0]!.requirements as Array<Record<string, unknown>>;
    expect(reqs).toHaveLength(1);
    expect(reqs[0]!.id).toBe('scoutsuite-no-findings');
    const results = reqs[0]!.results as Array<Record<string, unknown>>;
    expect(results[0]!.status).toBe('passed');
    expect(results[0]!.codeDesc).toContain('ScoutSuite');
    expect(results[0]!.codeDesc).toContain('000000000000');
    expect(results[0]!.codeDesc).toContain('zero findings');
  });

  // --- Real fixture tests ---

  describe('with scoutsuite_sample.js fixture', () => {
    it('should convert ScoutSuite scan to HDF format', async () => {
      const input = loadFixture('input/scoutsuite_sample.js');
      const output = await convertScoutsuiteToHdf(input);
      const parsed = parseOutput(output);
      const baselines = parsed.baselines as Array<Record<string, unknown>>;
      expect(baselines).toHaveLength(1);
    });

    it('should produce 8 requirements from 8 findings', async () => {
      const input = loadFixture('input/scoutsuite_sample.js');
      const out = parseOutput(await convertScoutsuiteToHdf(input));
      const bl = out.baselines as Array<Record<string, unknown>>;
      const reqs = bl[0]!.requirements as unknown[];
      expect(reqs).toHaveLength(8);
    });

    it('should set generator correctly', async () => {
      const input = loadFixture('input/scoutsuite_sample.js');
      const out = parseOutput(await convertScoutsuiteToHdf(input));
      const gen = out.generator as Record<string, unknown>;
      expect(gen.name).toBe('scoutsuite-to-hdf');
      expect(gen.version).toBe('1.0.0');
    });

    it('should set tool correctly', async () => {
      const input = loadFixture('input/scoutsuite_sample.js');
      const out = parseOutput(await convertScoutsuiteToHdf(input));
      const ds = out.tool as Record<string, unknown>;
      expect(ds.name).toBe('ScoutSuite');
      expect(ds.format).toBe('JSON');
      expect(ds.version).toBe('5.10.2');
    });

    it('should set baseline name to ScoutSuite Scan', async () => {
      const input = loadFixture('input/scoutsuite_sample.js');
      const out = parseOutput(await convertScoutsuiteToHdf(input));
      const bl = out.baselines as Array<Record<string, unknown>>;
      expect(bl[0]!.name).toBe('ScoutSuite Scan');
    });

    it('should set baseline title with ruleset name, provider, and account', async () => {
      const input = loadFixture('input/scoutsuite_sample.js');
      const out = parseOutput(await convertScoutsuiteToHdf(input));
      const bl = out.baselines as Array<Record<string, unknown>>;
      expect(bl[0]!.title).toContain('default');
      expect(bl[0]!.title).toContain('Amazon Web Services');
      expect(bl[0]!.title).toContain('916481805664');
    });

    it('should set resultsChecksum', async () => {
      const input = loadFixture('input/scoutsuite_sample.js');
      const out = parseOutput(await convertScoutsuiteToHdf(input));
      const bl = out.baselines as Array<Record<string, unknown>>;
      const cs = bl[0]!.resultsChecksum as Record<string, unknown>;
      expect(cs).toBeDefined();
      expect(cs.algorithm).toBe('sha256');
      expect((cs.value as string).length).toBe(64);
    });

    it('should set timestamp from last_run.time', async () => {
      const input = loadFixture('input/scoutsuite_sample.js');
      const out = parseOutput(await convertScoutsuiteToHdf(input));
      expect(out.timestamp).toBeDefined();
      const ts = new Date(out.timestamp as string);
      expect(ts.getFullYear()).toBe(2021);
    });

    it('should set target as CloudAccount type', async () => {
      const input = loadFixture('input/scoutsuite_sample.js');
      const out = parseOutput(await convertScoutsuiteToHdf(input));
      const targets = out.components as Array<Record<string, unknown>>;
      expect(targets).toHaveLength(1);
      expect(targets[0]!.name).toContain('916481805664');
      expect(targets[0]!.type).toBe('cloudAccount');
    });

    it('should map danger severity to 0.7 impact', async () => {
      const input = loadFixture('input/scoutsuite_sample.js');
      const out = parseOutput(await convertScoutsuiteToHdf(input));
      const bl = out.baselines as Array<Record<string, unknown>>;
      const req = findRequirement(bl, 'cloudtrail-not-configured');
      expect(req).toBeDefined();
      expect(req!.impact).toBe(0.7);
    });

    it('should map warning severity to 0.5 impact', async () => {
      const input = loadFixture('input/scoutsuite_sample.js');
      const out = parseOutput(await convertScoutsuiteToHdf(input));
      const bl = out.baselines as Array<Record<string, unknown>>;
      const req = findRequirement(bl, 'cloudtrail-duplicated-global-services-logging');
      expect(req).toBeDefined();
      expect(req!.impact).toBe(0.5);
    });

    it('should set failed status when flagged_items > 0', async () => {
      const input = loadFixture('input/scoutsuite_sample.js');
      const out = parseOutput(await convertScoutsuiteToHdf(input));
      const bl = out.baselines as Array<Record<string, unknown>>;
      const req = findRequirement(bl, 'cloudtrail-not-configured');
      expect(req).toBeDefined();
      const results = req!.results as Array<Record<string, unknown>>;
      expect(results[0]!.status).toBe('failed');
    });

    it('should set notReviewed status when checked_items = 0', async () => {
      const input = loadFixture('input/scoutsuite_sample.js');
      const out = parseOutput(await convertScoutsuiteToHdf(input));
      const bl = out.baselines as Array<Record<string, unknown>>;
      const req = findRequirement(bl, 'cloudtrail-duplicated-global-services-logging');
      expect(req).toBeDefined();
      const results = req!.results as Array<Record<string, unknown>>;
      expect(results[0]!.status).toBe('notReviewed');
    });

    it('should map NIST controls from ScoutSuite mappings', async () => {
      const input = loadFixture('input/scoutsuite_sample.js');
      const out = parseOutput(await convertScoutsuiteToHdf(input));
      const bl = out.baselines as Array<Record<string, unknown>>;
      const req = findRequirement(bl, 'cloudtrail-not-configured');
      expect(req).toBeDefined();
      const tags = req!.tags as Record<string, unknown>;
      const nist = tags.nist as string[];
      expect(nist).toContain('AU-12');
    });

    it('should split pipe-delimited NIST controls', async () => {
      const input = loadFixture('input/scoutsuite_sample.js');
      const out = parseOutput(await convertScoutsuiteToHdf(input));
      const bl = out.baselines as Array<Record<string, unknown>>;
      const req = findRequirement(bl, 'cloudtrail-no-cloudwatch-integration');
      expect(req).toBeDefined();
      const tags = req!.tags as Record<string, unknown>;
      const nist = tags.nist as string[];
      expect(nist).toContain('AU-12');
      expect(nist).toContain('SI-4(2)');
    });

    it('should include CCI tags', async () => {
      const input = loadFixture('input/scoutsuite_sample.js');
      const out = parseOutput(await convertScoutsuiteToHdf(input));
      const bl = out.baselines as Array<Record<string, unknown>>;
      const req = findRequirement(bl, 'cloudtrail-not-configured');
      expect(req).toBeDefined();
      const tags = req!.tags as Record<string, unknown>;
      const cci = tags.cci as string[];
      expect(cci.length).toBeGreaterThan(0);
    });

    it('should have default description with rationale', async () => {
      const input = loadFixture('input/scoutsuite_sample.js');
      const out = parseOutput(await convertScoutsuiteToHdf(input));
      const bl = out.baselines as Array<Record<string, unknown>>;
      const req = findRequirement(bl, 'cloudtrail-not-configured');
      expect(req).toBeDefined();
      const descs = req!.descriptions as Array<Record<string, unknown>>;
      const defaultDesc = descs.find(d => d.label === 'default');
      expect(defaultDesc).toBeDefined();
      expect(defaultDesc!.data).toContain('CloudTrail is not configured');
    });

    it('should have fix description from remediation', async () => {
      const input = loadFixture('input/scoutsuite_sample.js');
      const out = parseOutput(await convertScoutsuiteToHdf(input));
      const bl = out.baselines as Array<Record<string, unknown>>;
      const req = findRequirement(bl, 'cloudtrail-no-cloudwatch-integration');
      expect(req).toBeDefined();
      const descs = req!.descriptions as Array<Record<string, unknown>>;
      const fixDesc = descs.find(d => d.label === 'fix');
      expect(fixDesc).toBeDefined();
      expect(fixDesc!.data).toContain('CloudWatch Logs group');
    });

    it('should set requirement title from description field', async () => {
      const input = loadFixture('input/scoutsuite_sample.js');
      const out = parseOutput(await convertScoutsuiteToHdf(input));
      const bl = out.baselines as Array<Record<string, unknown>>;
      const req = findRequirement(bl, 'cloudtrail-not-configured');
      expect(req).toBeDefined();
      expect(req!.title).toBe('CloudTrail Service Not Configured');
    });

    it('should include description in codeDesc', async () => {
      const input = loadFixture('input/scoutsuite_sample.js');
      const out = parseOutput(await convertScoutsuiteToHdf(input));
      const bl = out.baselines as Array<Record<string, unknown>>;
      const req = findRequirement(bl, 'cloudtrail-not-configured');
      expect(req).toBeDefined();
      const results = req!.results as Array<Record<string, unknown>>;
      expect(results[0]!.codeDesc).toContain('CloudTrail Service Not Configured');
    });

    it('should include flagged items message for failed results', async () => {
      const input = loadFixture('input/scoutsuite_sample.js');
      const out = parseOutput(await convertScoutsuiteToHdf(input));
      const bl = out.baselines as Array<Record<string, unknown>>;
      const req = findRequirement(bl, 'cloudtrail-not-configured');
      expect(req).toBeDefined();
      const results = req!.results as Array<Record<string, unknown>>;
      expect(results[0]!.message).toContain('16 flagged items');
    });

    it('should include skip message for notReviewed results', async () => {
      const input = loadFixture('input/scoutsuite_sample.js');
      const out = parseOutput(await convertScoutsuiteToHdf(input));
      const bl = out.baselines as Array<Record<string, unknown>>;
      const req = findRequirement(bl, 'cloudtrail-duplicated-global-services-logging');
      expect(req).toBeDefined();
      const results = req!.results as Array<Record<string, unknown>>;
      expect(results[0]!.message).toContain('no items were checked');
    });
  });
});
