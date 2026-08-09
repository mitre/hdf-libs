import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, it, expect } from 'vitest';
import { convertMsftDefenderDevopsToHdf } from './converter.js';
import { runConverterContractTests } from '../../../shared/typescript/converter-contract.js';
import { assertRequirementCount } from '../../../shared/typescript/anchor.js';
import { expectValidResults } from '../../../test/helpers/expectValidHdf.js';
import type { HDFResults } from '@mitre/hdf-schema';

function loadFixture(name: string): string {
  return readFileSync(join(__dirname, '..', 'fixtures', name), 'utf-8');
}

// Count, per SARIF run, the distinct rule identifiers (result.ruleId, falling
// back to result.rule.id) among that run's results, then sum across runs. MSDO
// delegates to the SARIF converter, which emits one requirement per distinct
// rule PER run (each run becomes its own baseline), so the emission unit is the
// per-run distinct-rule count summed over runs — not a global distinct count.
// Parsed generically, without the converter's parser. minimal.sarif has no
// empty-results runs, so no placeholder skews the count.
function countPerRunDistinctRules(input: string): number {
  const doc = JSON.parse(input) as {
    runs?: Array<{ results?: Array<{ ruleId?: string; rule?: { id?: string } }> }>;
  };
  return (doc.runs ?? []).reduce((sum, run) => {
    const distinct = new Set((run.results ?? []).map((r) => r.ruleId ?? r.rule?.id));
    return sum + distinct.size;
  }, 0);
}

runConverterContractTests({
  converterName: 'msft-defender-devops-to-hdf',
  convertFn: convertMsftDefenderDevopsToHdf,
  minimalFixture: 'minimal.sarif',
});

// Ground-truth anchor (input-derived count; see shared/typescript/anchor.ts).
describe('msft-defender-devops-to-hdf ground-truth anchor', () => {
  it('emits one requirement per distinct rule per run (minimal)', async () => {
    const input = loadFixture('input/minimal.sarif');
    assertRequirementCount(
      await convertMsftDefenderDevopsToHdf(input),
      countPerRunDistinctRules(input),
      'minimal.sarif: one requirement per distinct rule per run',
    );
  });
});

describe('msft-defender-devops-to-hdf', () => {
  // ---- Error handling ----

  describe('error handling', () => {
    it('should reject JSON without runs', async () => {
      await expect(convertMsftDefenderDevopsToHdf('{"version": "2.1.0"}')).rejects.toThrow();
    });
  });

  // ---- Minimal fixture ----

  describe('minimal fixture', () => {
    it('should produce 2 baselines from 2 runs', async () => {
      const input = loadFixture('input/minimal.sarif');
      const result = JSON.parse(await convertMsftDefenderDevopsToHdf(input)) as HDFResults;
      expectValidResults(result);

      expect(result.baselines).toHaveLength(2);
      expect(result.baselines![0]!.requirements!.length).toBeGreaterThan(0);
      expect(result.baselines![1]!.requirements!.length).toBeGreaterThan(0);
    });
  });

  // ---- Full SDA fixture ----

  describe('full SDA fixture', () => {
    it('should produce 7 baselines with correct tool names', async () => {
      const input = loadFixture('input/sda.sarif');
      const result = JSON.parse(await convertMsftDefenderDevopsToHdf(input)) as HDFResults;

      expect(result.baselines).toHaveLength(7);

      const expectedNames = [
        'antimalware', 'bandit', 'credscan', 'eslint',
        'iacfilescanner', 'templateanalyzer', 'checkov',
      ];
      for (let i = 0; i < expectedNames.length; i++) {
        expect(result.baselines![i]!.name).toBe(expectedNames[i]);
      }
    });
  });

  // ---- Empty-baseline placeholder synthesis (issue #80 bug 3) ----

  describe('empty-baseline placeholder synthesis', () => {
    it('should synthesize one passed requirement for each baseline whose SARIF run has no results', async () => {
      const input = loadFixture('input/sda.sarif');
      const result = JSON.parse(await convertMsftDefenderDevopsToHdf(input)) as HDFResults;

      // Baselines 0/1/3 (antimalware/bandit/eslint) had results: [] in SARIF.
      // SARIF v2.1.0 §3.7.2 defines empty results as "analysis completed,
      // no findings" — emit a passed placeholder so HDF's requirements.minItems=1
      // is satisfied.
      const cases = [
        { idx: 0, tool: 'antimalware' },
        { idx: 1, tool: 'bandit' },
        { idx: 3, tool: 'eslint' },
      ];

      for (const { idx, tool } of cases) {
        const baseline = result.baselines![idx]!;
        expect(baseline.name).toBe(tool);
        expect(baseline.requirements).toHaveLength(1);

        const req = baseline.requirements[0]!;
        expect(req.id).toBe(`${tool}-no-findings`);
        expect(req.descriptions).toHaveLength(1);
        expect(req.descriptions![0]!.label).toBe('default');
        expect(req.descriptions![0]!.data).toContain(tool);

        expect(req.results).toHaveLength(1);
        expect(req.results[0]!.status).toBe('passed');
        expect(req.results[0]!.codeDesc).toContain(tool);
        expect(req.results[0]!.codeDesc).toContain('zero findings');
        expect(req.results[0]!.startTime).toBe(result.timestamp);

        // Run-level enrichment tags should still land on synthesized reqs.
        expect(req.tags).toBeDefined();
      }

      // Non-empty baselines unaffected (no synthesized placeholder injected).
      const credscan = result.baselines![2]!;
      expect(credscan.name).toBe('credscan');
      expect(credscan.requirements.length).toBeGreaterThan(0);
      expect(credscan.requirements[0]!.id).not.toBe('credscan-no-findings');
    });
  });

  // ---- Repository target ----

  describe('repository target', () => {
    it('should extract target from versionControlProvenance', async () => {
      const input = loadFixture('input/minimal.sarif');
      const result = JSON.parse(await convertMsftDefenderDevopsToHdf(input)) as HDFResults;

      expect(result.components).toBeDefined();
      expect(result.components!.length).toBeGreaterThan(0);

      const target = result.components![0]!;
      expect(target.type).toBe('repository');
      expect(target.name).toBe('security-devops-action');
      expect(target.url).toContain('github.com');
      expect(target.branch).toBe('main');
      expect(target.commit).toBeDefined();
      expect(target.commit!.length).toBeGreaterThan(0);
    });

    it('should deduplicate targets across runs', async () => {
      const input = loadFixture('input/sda.sarif');
      const result = JSON.parse(await convertMsftDefenderDevopsToHdf(input)) as HDFResults;

      // All 7 runs reference the same repo
      expect(result.components).toHaveLength(1);
    });
  });

  // ---- Tool metadata tags ----

  describe('tool metadata', () => {
    it('should include organization, product, fullName for credscan', async () => {
      const input = loadFixture('input/minimal.sarif');
      const result = JSON.parse(await convertMsftDefenderDevopsToHdf(input)) as HDFResults;

      const req = result.baselines![0]!.requirements![0]!;
      const tags = req.tags as Record<string, unknown>;

      expect(tags.msdo_organization).toBe('Microsoft Corporation');
      expect(tags.msdo_product).toBe('Microsoft Security Credential Scanner Client');
      expect(tags.msdo_fullName).toBe('CredentialScanner 2.5.1.13');
      expect(tags.msdo_rawName).toBe('credscan');
    });

    it('should include only RawName for checkov', async () => {
      const input = loadFixture('input/minimal.sarif');
      const result = JSON.parse(await convertMsftDefenderDevopsToHdf(input)) as HDFResults;

      const req = result.baselines![1]!.requirements![0]!;
      const tags = req.tags as Record<string, unknown>;

      expect(tags.msdo_rawName).toBe('checkov');
      expect(tags.msdo_organization).toBeUndefined();
    });
  });

  // ---- Policy tag ----

  describe('policy tag', () => {
    it('should store policy in requirement tags', async () => {
      const input = loadFixture('input/minimal.sarif');
      const result = JSON.parse(await convertMsftDefenderDevopsToHdf(input)) as HDFResults;

      const req = result.baselines![0]!.requirements![0]!;
      const tags = req.tags as Record<string, unknown>;

      expect(tags.msdo_policy).toBe('Microsoft 2.0.3');
    });
  });

  // ---- Result properties ----

  describe('result properties', () => {
    it('should include CredScan result-level properties', async () => {
      const input = loadFixture('input/minimal.sarif');
      const result = JSON.parse(await convertMsftDefenderDevopsToHdf(input)) as HDFResults;

      const req = result.baselines![0]!.requirements![0]!;
      const tags = req.tags as Record<string, unknown>;
      const props = tags.msdo_properties as Record<string, unknown>;

      expect(props).toBeDefined();
      expect(props.DefectCode).toBe('SecretInFile');
      expect(props.MatchingScore).toBeDefined();
      expect(props.Risk).toBeDefined();
      expect(props.Validation).toBe('NoValidationRequested');
    });
  });

  describe('result rank', () => {
    it('should emit the numeric rank tag for credscan results', async () => {
      const input = loadFixture('input/minimal.sarif');
      const result = JSON.parse(await convertMsftDefenderDevopsToHdf(input)) as HDFResults;

      const req = result.baselines![0]!.requirements![0]!;
      const tags = req.tags as Record<string, unknown>;
      expect(tags.rank).toBe(94);
    });

    it('should omit the rank tag when results carry no rank (checkov)', async () => {
      const input = loadFixture('input/minimal.sarif');
      const result = JSON.parse(await convertMsftDefenderDevopsToHdf(input)) as HDFResults;

      const req = result.baselines![1]!.requirements![0]!;
      const tags = req.tags as Record<string, unknown>;
      expect(tags.rank).toBeUndefined();
    });
  });

  // ---- Generator name ----

  describe('generator', () => {
    it('should use msft-defender-devops-to-hdf generator name', async () => {
      const input = loadFixture('input/minimal.sarif');
      const result = JSON.parse(await convertMsftDefenderDevopsToHdf(input)) as HDFResults;

      expect(result.generator?.name).toBe('msft-defender-devops-to-hdf');
    });
  });

  // ---- Data source ----

  describe('data source', () => {
    it('should use Microsoft Defender for DevOps as data source name', async () => {
      const input = loadFixture('input/minimal.sarif');
      const result = JSON.parse(await convertMsftDefenderDevopsToHdf(input)) as HDFResults;

      expect(result.tool?.name).toBe('Microsoft Defender for DevOps');
    });
  });

  // ---- Delegates base SARIF ----

  describe('base SARIF delegation', () => {
    it('should preserve standard SARIF tags (nist, severity)', async () => {
      const input = loadFixture('input/minimal.sarif');
      const result = JSON.parse(await convertMsftDefenderDevopsToHdf(input)) as HDFResults;

      const req = result.baselines![1]!.requirements![0]!;
      const tags = req.tags as Record<string, unknown>;

      expect(tags.nist).toBeDefined();
      expect(tags.severity).toBeDefined();
    });
  });
});
