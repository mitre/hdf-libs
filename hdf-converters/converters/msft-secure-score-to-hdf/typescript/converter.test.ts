import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { describe, it, expect } from 'vitest';
import { convertMsftSecureScoreToHdf } from './converter.js';
import { runConverterContractTests } from '../../../shared/typescript/converter-contract.js';
import {
  assertRequirementCount,
  countJsonItemsUnderKey,
} from '../../../shared/typescript/anchor.js';
import { expectValidResults } from '../../../test/helpers/expectValidHdf.js';
import type { HDFResults } from '@mitre/hdf-schema';

const __dirname = dirname(fileURLToPath(import.meta.url));
const FIXTURES_DIR = join(__dirname, '..', 'fixtures');

function loadFixture(name: string): string {
  return readFileSync(join(FIXTURES_DIR, 'input', name), 'utf-8');
}

runConverterContractTests({
  converterName: 'msft-secure-score-to-hdf',
  convertFn: convertMsftSecureScoreToHdf,
  minimalFixture: 'minimal.json',
});

// Ground-truth anchor (input-derived count; see shared/typescript/anchor.ts).
// Each secureScore.value[].controlScores[] entry becomes exactly one requirement
// — no grouping — so the source count is the total controlScores length across
// all secureScore entries. "controlScores" is the sole array under that key at
// any depth here, so countJsonItemsUnderKey is unambiguous (unlike "value",
// which appears under both secureScore and profiles).
describe('msft-secure-score-to-hdf ground-truth anchor', () => {
  it('emits one requirement per controlScores[] entry (combined)', async () => {
    const input = loadFixture('combined.json');
    assertRequirementCount(
      await convertMsftSecureScoreToHdf(input),
      countJsonItemsUnderKey(input, 'controlScores'),
      'combined.json: one requirement per secureScore.value[].controlScores[] entry',
    );
  });
});

describe('timestamp parse fallback', () => {
  it('uses a valid startTime when createdDateTime is unparseable', async () => {
    const input = loadFixture('minimal.json').replace(/2024-01-01T00:00:00Z/g, 'not-a-date');
    const hdf = JSON.parse(await convertMsftSecureScoreToHdf(input)) as HDFResults;
    expectValidResults(hdf);
  });

  it('uses a valid startTime when createdDateTime is absent', async () => {
    const input = loadFixture('minimal.json').replace(/"createdDateTime"/g, '"createdDateTimeAbsent"');
    const hdf = JSON.parse(await convertMsftSecureScoreToHdf(input)) as HDFResults;
    expectValidResults(hdf);
  });
});

describe('msft-secure-score to HDF converter', async () => {
  describe('input validation', async () => {
    it('should throw when secureScore is missing', async () => {
      await expect(convertMsftSecureScoreToHdf('{"profiles": {"value": []}}')).rejects.toThrow();
    });

    it('should throw when profiles is missing', async () => {
      await expect(convertMsftSecureScoreToHdf('{"secureScore": {"value": []}}')).rejects.toThrow();
    });
  });

  describe('conversion basics', async () => {
    it('should produce valid HDF from minimal fixture', async () => {
      const output = await convertMsftSecureScoreToHdf(loadFixture('minimal.json'));
      const hdf = JSON.parse(output) as HDFResults;
      expectValidResults(hdf);

      expect(hdf.timestamp).toBeTruthy();
      expect(hdf.generator?.name).toBe('msft-secure-score-to-hdf');
      expect(hdf.generator?.version).toBe('1.0.0');
      expect(hdf.baselines).toHaveLength(1);
      // minimal.json has 3 controlScores
      expect(hdf.baselines[0]!.requirements).toHaveLength(3);
    });

    it('should use "Microsoft Secure Score" as the baseline name', async () => {
      const hdf = JSON.parse(await convertMsftSecureScoreToHdf(loadFixture('minimal.json'))) as HDFResults;
      expect(hdf.baselines[0]!.name).toBe('Microsoft Secure Score');
    });

    it('should include tenant ID in baseline title', async () => {
      const hdf = JSON.parse(await convertMsftSecureScoreToHdf(loadFixture('minimal.json'))) as HDFResults;
      expect(hdf.baselines[0]!.title).toContain('12345678-1234-1234-1234-1234567890abcd');
    });

    it('should include a sha256 checksum', async () => {
      const hdf = JSON.parse(await convertMsftSecureScoreToHdf(loadFixture('minimal.json'))) as HDFResults;
      const checksum = hdf.baselines[0]!.resultsChecksum;
      expect(checksum?.algorithm).toBe('sha256');
      expect(checksum?.value).toMatch(/^[a-f0-9]{64}$/);
    });
  });

  describe('generator and dataSource', async () => {
    it('should set generator name and version', async () => {
      const hdf = JSON.parse(await convertMsftSecureScoreToHdf(loadFixture('minimal.json'))) as HDFResults;
      expect(hdf.generator?.name).toBe('msft-secure-score-to-hdf');
      expect(hdf.generator?.version).toBe('1.0.0');
    });

    it('should set tool name to "Microsoft Secure Score" with no format', async () => {
      const hdf = JSON.parse(await convertMsftSecureScoreToHdf(loadFixture('minimal.json'))) as HDFResults;
      expect(hdf.tool?.name).toBe('Microsoft Secure Score');
      expect(hdf.tool?.format).toBeUndefined() // serialization structures are not formats (kpvj);
    });
  });

  describe('target', async () => {
    it('should set target type to cloudAccount', async () => {
      const hdf = JSON.parse(await convertMsftSecureScoreToHdf(loadFixture('minimal.json'))) as HDFResults;
      expect(hdf.components).toBeDefined();
      expect(hdf.components![0]!.type).toBe('cloudAccount');
    });

    it('should include tenant ID in target name', async () => {
      const hdf = JSON.parse(await convertMsftSecureScoreToHdf(loadFixture('minimal.json'))) as HDFResults;
      expect(hdf.components![0]!.name).toContain('12345678-1234-1234-1234-1234567890abcd');
    });
  });

  describe('requirement IDs', async () => {
    it('should use controlCategory:controlName as ID', async () => {
      const hdf = JSON.parse(await convertMsftSecureScoreToHdf(loadFixture('minimal.json'))) as HDFResults;
      const reqs = hdf.baselines[0]!.requirements;
      const req = reqs.find(r => r.id === 'Apps:McasFirewallLogUpload');
      expect(req).toBeDefined();
    });
  });

  describe('requirement title', async () => {
    it('should use profile title when available', async () => {
      const hdf = JSON.parse(await convertMsftSecureScoreToHdf(loadFixture('minimal.json'))) as HDFResults;
      const req = hdf.baselines[0]!.requirements.find(r => r.id === 'Apps:McasFirewallLogUpload');
      expect(req?.title).toContain('Deploy a log collector');
    });

    it('should fall back to controlCategory:controlName when no profile', async () => {
      const hdf = JSON.parse(await convertMsftSecureScoreToHdf(loadFixture('minimal.json'))) as HDFResults;
      const req = hdf.baselines[0]!.requirements.find(r => r.id === 'Apps:spo_idle_session_timeout');
      expect(req?.title).toContain('spo_idle_session_timeout');
    });
  });

  describe('impact from profile maxScore', async () => {
    it('should compute impact as maxScore/10', async () => {
      const hdf = JSON.parse(await convertMsftSecureScoreToHdf(loadFixture('minimal.json'))) as HDFResults;
      // McasFirewallLogUpload has maxScore=1 → 0.1
      const req = hdf.baselines[0]!.requirements.find(r => r.id === 'Apps:McasFirewallLogUpload');
      expect(req?.impact).toBeCloseTo(0.1, 2);

      // dlp_datalossprevention has maxScore=5 → 0.5
      const req2 = hdf.baselines[0]!.requirements.find(r => r.id === 'Data:dlp_datalossprevention');
      expect(req2?.impact).toBeCloseTo(0.5, 2);
    });

    it('should default to 0.5 when no profile exists', async () => {
      const hdf = JSON.parse(await convertMsftSecureScoreToHdf(loadFixture('minimal.json'))) as HDFResults;
      const req = hdf.baselines[0]!.requirements.find(r => r.id === 'Apps:spo_idle_session_timeout');
      expect(req?.impact).toBeCloseTo(0.5, 2);
    });
  });

  describe('status mapping', async () => {
    it('should map scoreInPercentage 100 to passed', async () => {
      const hdf = JSON.parse(await convertMsftSecureScoreToHdf(loadFixture('minimal.json'))) as HDFResults;
      const req = hdf.baselines[0]!.requirements.find(r => r.id === 'Data:dlp_datalossprevention');
      expect(req?.results[0]?.status).toBe('passed');
    });

    it('should map failing scores to failed', async () => {
      const hdf = JSON.parse(await convertMsftSecureScoreToHdf(loadFixture('minimal.json'))) as HDFResults;
      const req = hdf.baselines[0]!.requirements.find(r => r.id === 'Apps:McasFirewallLogUpload');
      expect(req?.results[0]?.status).toBe('failed');
    });
  });

  describe('code_desc', async () => {
    it('should use implementationStatus as code_desc', async () => {
      const hdf = JSON.parse(await convertMsftSecureScoreToHdf(loadFixture('minimal.json'))) as HDFResults;
      const req = hdf.baselines[0]!.requirements.find(r => r.id === 'Apps:McasFirewallLogUpload');
      expect(req?.results[0]?.codeDesc).toContain('Feature in place: false');
    });
  });

  describe('descriptions', async () => {
    it('should include default description with control description', async () => {
      const hdf = JSON.parse(await convertMsftSecureScoreToHdf(loadFixture('minimal.json'))) as HDFResults;
      const req = hdf.baselines[0]!.requirements.find(r => r.id === 'Apps:McasFirewallLogUpload');
      const defaultDesc = req?.descriptions?.find(d => d.label === 'default');
      expect(defaultDesc).toBeDefined();
      expect(defaultDesc!.data).toContain('Log collectors');
    });

    it('should include fix description from profile remediation', async () => {
      const hdf = JSON.parse(await convertMsftSecureScoreToHdf(loadFixture('minimal.json'))) as HDFResults;
      const req = hdf.baselines[0]!.requirements.find(r => r.id === 'Apps:McasFirewallLogUpload');
      const fix = req?.descriptions?.find(d => d.label === 'fix');
      expect(fix).toBeDefined();
      expect(fix!.data.length).toBeGreaterThan(0);
    });
  });

  describe('refs from profile actionUrl', async () => {
    it('should emit a Reference url from the matching profile actionUrl', async () => {
      const hdf = JSON.parse(await convertMsftSecureScoreToHdf(loadFixture('minimal.json'))) as HDFResults;
      const req = hdf.baselines[0]!.requirements.find(r => r.id === 'Apps:McasFirewallLogUpload');
      expect(req?.refs).toHaveLength(1);
      expect(req?.refs?.[0]?.url).toBe('https://security.microsoft.com/cloudapps/settings?tabid=discovery-autoUpload');

      const req2 = hdf.baselines[0]!.requirements.find(r => r.id === 'Data:dlp_datalossprevention');
      expect(req2?.refs).toHaveLength(1);
      expect(req2?.refs?.[0]?.url).toBe('https://compliance.microsoft.com/datalossprevention?tid=12345678-1234-1234-1234-1234567890abcd');
    });

    it('should omit refs when no matching profile exists', async () => {
      const hdf = JSON.parse(await convertMsftSecureScoreToHdf(loadFixture('minimal.json'))) as HDFResults;
      const req = hdf.baselines[0]!.requirements.find(r => r.id === 'Apps:spo_idle_session_timeout');
      expect(req?.refs).toBeUndefined();
    });
  });

  describe('NIST tags', async () => {
    it('should include default static analysis NIST tags', async () => {
      const hdf = JSON.parse(await convertMsftSecureScoreToHdf(loadFixture('minimal.json'))) as HDFResults;
      const req = hdf.baselines[0]!.requirements.find(r => r.id === 'Apps:McasFirewallLogUpload');
      const nist = req?.tags?.['nist'] as string[];
      expect(nist).toBeDefined();
      expect(nist.length).toBeGreaterThan(0);
    });
  });

  describe('start_time', async () => {
    it('should set start_time from the control lastSynced', async () => {
      const hdf = JSON.parse(await convertMsftSecureScoreToHdf(loadFixture('minimal.json'))) as HDFResults;
      const reqs = hdf.baselines[0]!.requirements;
      // Per-control lastSynced — NOT the score's createdDateTime.
      const mcas = reqs.find(r => r.id === 'Apps:McasFirewallLogUpload');
      expect(mcas?.results[0]?.startTime).toBe('2024-01-01T04:34:13Z');
      const dlp = reqs.find(r => r.id === 'Data:dlp_datalossprevention');
      expect(dlp?.results[0]?.startTime).toBe('2024-01-01T13:58:47Z');
    });

    it('falls back to createdDateTime when a control has no lastSynced', async () => {
      const input = JSON.stringify({
        secureScore: { value: [{
          id: 'run-1',
          azureTenantId: 't-1',
          createdDateTime: '2024-03-14T09:00:00Z',
          controlScores: [
            { controlCategory: 'Apps', controlName: 'no_sync', description: 'd', score: 0, implementationStatus: 'x', scoreInPercentage: 0 },
          ],
        }] },
        profiles: { value: [] },
      });
      const hdf = JSON.parse(await convertMsftSecureScoreToHdf(input)) as HDFResults;
      const req = hdf.baselines[0]!.requirements.find(r => r.id === 'Apps:no_sync');
      expect(req?.results[0]?.startTime).toBe('2024-03-14T09:00:00Z');
    });
  });

  describe('top-level timestamp', async () => {
    it('is source-derived from the score createdDateTime (deterministic)', async () => {
      const hdf = JSON.parse(await convertMsftSecureScoreToHdf(loadFixture('minimal.json'))) as HDFResults;
      expect(hdf.timestamp).toBe('2024-01-01T00:00:00Z');
    });
  });

  describe('full fixture smoke test', async () => {
    it('should convert full combined.json with 68 controls', async () => {
      const hdf = JSON.parse(await convertMsftSecureScoreToHdf(loadFixture('combined.json'))) as HDFResults;
      expect(hdf.baselines).toHaveLength(1);
      expect(hdf.baselines[0]!.requirements).toHaveLength(68);

      // Each requirement should have exactly 1 result
      for (const req of hdf.baselines[0]!.requirements) {
        expect(req.results).toHaveLength(1);
      }
    });
  });

  describe('source categorization/metadata tags', async () => {
    it('maps profile metadata + on flag; omits empty threats', async () => {
      const hdf = JSON.parse(await convertMsftSecureScoreToHdf(loadFixture('minimal.json'))) as HDFResults;
      const reqs = hdf.baselines[0]!.requirements;

      // dlp_datalossprevention: full profile metadata; threats is [] → omitted; on == "true".
      const dlp = reqs.find(r => r.id === 'Data:dlp_datalossprevention')!;
      expect(dlp.tags?.['rank']).toBe(128);
      expect(dlp.tags?.['service']).toBe('MIP');
      expect(dlp.tags?.['tier']).toBe('Core');
      expect(dlp.tags?.['user_impact']).toBe('High');
      expect(dlp.tags?.['action_type']).toBe('Config');
      expect(dlp.tags?.['implementation_cost']).toBe('Medium');
      expect(dlp.tags?.['on']).toBe(true);
      expect(dlp.tags?.['threats']).toBeUndefined();

      // McasFirewallLogUpload: non-empty threats array; on == "false".
      const mcas = reqs.find(r => r.id === 'Apps:McasFirewallLogUpload')!;
      expect(mcas.tags?.['threats']).toEqual(['Data Exfiltration']);
      expect(mcas.tags?.['rank']).toBe(82);
      expect(mcas.tags?.['service']).toBe('MCAS');
      expect(mcas.tags?.['tier']).toBe('Advanced');
      expect(mcas.tags?.['user_impact']).toBe('Low');
      expect(mcas.tags?.['action_type']).toBe('Config');
      expect(mcas.tags?.['implementation_cost']).toBe('Moderate');
      expect(mcas.tags?.['on']).toBe(false);
    });

    it('omits profile tags when no profile matches but still emits on', async () => {
      const hdf = JSON.parse(await convertMsftSecureScoreToHdf(loadFixture('minimal.json'))) as HDFResults;
      const req = hdf.baselines[0]!.requirements.find(r => r.id === 'Apps:spo_idle_session_timeout')!;
      for (const k of ['threats', 'rank', 'service', 'tier', 'user_impact', 'action_type', 'implementation_cost']) {
        expect(req.tags?.[k]).toBeUndefined();
      }
      expect(req.tags?.['on']).toBe(false);
    });

    it('omits on when the control reports no enablement state (combined)', async () => {
      const hdf = JSON.parse(await convertMsftSecureScoreToHdf(loadFixture('combined.json'))) as HDFResults;
      const reqs = hdf.baselines[0]!.requirements;
      const withOn = reqs.filter(r => r.tags !== undefined && 'on' in r.tags);
      const withoutOn = reqs.filter(r => r.tags === undefined || !('on' in r.tags));
      expect(withOn.length).toBeGreaterThan(0);
      expect(withoutOn.length).toBeGreaterThan(0);
    });
  });

  describe('category and maxScore tags (heimdall2 parity)', async () => {
    it('emits category and maxScore from the matched profile', async () => {
      const hdf = JSON.parse(await convertMsftSecureScoreToHdf(loadFixture('minimal.json'))) as HDFResults;
      const reqs = hdf.baselines[0]!.requirements;

      const dlp = reqs.find(r => r.id === 'Data:dlp_datalossprevention')!;
      expect(dlp.tags?.['category']).toBe('Data');
      expect(dlp.tags?.['maxScore']).toBe(5);

      const mcas = reqs.find(r => r.id === 'Apps:McasFirewallLogUpload')!;
      expect(mcas.tags?.['category']).toBe('Apps');
      expect(mcas.tags?.['maxScore']).toBe(1);
    });

    it('omits category and maxScore when no profile matches', async () => {
      const hdf = JSON.parse(await convertMsftSecureScoreToHdf(loadFixture('minimal.json'))) as HDFResults;
      const req = hdf.baselines[0]!.requirements.find(r => r.id === 'Apps:spo_idle_session_timeout')!;
      expect(req.tags?.['category']).toBeUndefined();
      expect(req.tags?.['maxScore']).toBeUndefined();
    });
  });

  describe('multi-profile join (heimdall2 parity)', async () => {
    // Real MS Graph data has unique profile ids; this synthetic input exercises
    // the join path where >1 profile matches a control name.
    it('joins title, fix, and rationale across all matched profiles', async () => {
      const input = JSON.stringify({
        secureScore: { value: [{
          id: 'run-1',
          azureTenantId: 't-1',
          createdDateTime: '2024-03-14T09:00:00Z',
          controlScores: [
            { controlCategory: 'Apps', controlName: 'dup', description: 'd', score: 0, implementationStatus: 'x', scoreInPercentage: 0, lastSynced: '2024-03-14T09:00:00Z' },
          ],
        }] },
        profiles: { value: [
          { id: 'dup', controlCategory: 'Apps', title: 'Title A', maxScore: 3, remediation: 'Fix A', remediationImpact: 'Impact A' },
          { id: 'dup', controlCategory: 'Apps', title: 'Title B', maxScore: 5, remediation: 'Fix B', remediationImpact: 'Impact B' },
        ] },
      });
      const hdf = JSON.parse(await convertMsftSecureScoreToHdf(input)) as HDFResults;
      const req = hdf.baselines[0]!.requirements.find(r => r.id === 'Apps:dup')!;
      expect(req.title).toBe('Title A\nTitle B');
      expect(req.descriptions?.find(d => d.label === 'fix')?.data).toBe('Fix A\nFix B');
      expect(req.descriptions?.find(d => d.label === 'rationale')?.data).toBe('Impact A\nImpact B');
    });
  });
});
