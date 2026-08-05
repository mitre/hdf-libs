import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { describe, it, expect } from 'vitest';
import { convertMsftDefenderCloudToHdf } from './converter.js';
import { runConverterContractTests } from '../../../shared/typescript/converter-contract.js';
import { assertRequirementCount } from '../../../shared/typescript/anchor.js';
import { expectValidResults } from '../../../test/helpers/expectValidHdf.js';
import type { HDFResults } from '@mitre/hdf-schema';

const __dirname = dirname(fileURLToPath(import.meta.url));
const FIXTURES_DIR = join(__dirname, '..', 'fixtures');

function loadFixture(name: string): string {
  return readFileSync(join(FIXTURES_DIR, 'input', name), 'utf-8');
}

// Count distinct value[].name GUIDs in the raw Azure export, generically (no
// converter parser). The converter's emission unit is one requirement per
// DISTINCT assessment name — it groups value[] entries by name — so a plain
// array-length count would over-count if two entries shared a name.
function countDistinctAssessmentNames(input: string): number {
  const doc = JSON.parse(input) as { value?: Array<{ name?: string }> };
  return new Set((doc.value ?? []).map((a) => a.name)).size;
}

runConverterContractTests({
  converterName: 'msft-defender-cloud-to-hdf',
  convertFn: convertMsftDefenderCloudToHdf,
  minimalFixture: 'minimal.json',
});

// Ground-truth anchor (input-derived count; see shared/typescript/anchor.ts).
describe('msft-defender-cloud-to-hdf ground-truth anchor', () => {
  it('emits one requirement per distinct value[].name (sample)', async () => {
    const input = loadFixture('sample.json');
    assertRequirementCount(
      await convertMsftDefenderCloudToHdf(input),
      countDistinctAssessmentNames(input),
      'sample.json: one requirement per distinct value[].name assessment',
    );
  });
});

describe('Microsoft Defender for Cloud to HDF converter', async () => {
  describe('error handling', async () => {
    it('should throw when value array is missing', async () => {
      await expect(convertMsftDefenderCloudToHdf(JSON.stringify({}))).rejects.toThrow(
        'missing or invalid value array',
      );
    });

    it('should throw when value is not an array', async () => {
      await expect(convertMsftDefenderCloudToHdf(JSON.stringify({ value: 'notarray' }))).rejects.toThrow(
        'missing or invalid value array',
      );
    });
  });

  describe('minimal fixture conversion', async () => {
    it('should produce valid HDF structure', async () => {
      const output = await convertMsftDefenderCloudToHdf(loadFixture('minimal.json'));
      const hdf = JSON.parse(output) as HDFResults;

      expect(hdf.timestamp).toBeTruthy();
      expect(hdf.generator?.name).toBe('msft-defender-cloud-to-hdf');
      expect(hdf.generator?.version).toBe('1.0.0');
      expect(hdf.tool?.name).toBe('Microsoft Defender for Cloud');
      expect(hdf.tool?.format).toBeUndefined() // serialization structures are not formats (kpvj);
      expect(hdf.baselines).toHaveLength(1);
      expectValidResults(hdf);
    });

    it('should create 2 requirements from 2 assessments', async () => {
      const hdf = JSON.parse(await convertMsftDefenderCloudToHdf(loadFixture('minimal.json'))) as HDFResults;
      expect(hdf.baselines[0]!.requirements).toHaveLength(2);
    });

    it('should use correct baseline name', async () => {
      const hdf = JSON.parse(await convertMsftDefenderCloudToHdf(loadFixture('minimal.json'))) as HDFResults;
      expect(hdf.baselines[0]!.name).toBe('Microsoft Defender for Cloud Assessments');
    });

    it('should include a sha256 checksum', async () => {
      const hdf = JSON.parse(await convertMsftDefenderCloudToHdf(loadFixture('minimal.json'))) as HDFResults;
      const checksum = hdf.baselines[0]!.resultsChecksum;
      expect(checksum?.algorithm).toBe('sha256');
      expect(checksum?.value).toMatch(/^[a-f0-9]{64}$/);
    });
  });

  describe('sample fixture conversion', async () => {
    it('should produce 6 requirements from 6 assessments', async () => {
      const hdf = JSON.parse(await convertMsftDefenderCloudToHdf(loadFixture('sample.json'))) as HDFResults;
      expect(hdf.baselines[0]!.requirements).toHaveLength(6);
    });
  });

  describe('status mapping', async () => {
    it('should map Healthy to passed', async () => {
      const hdf = JSON.parse(await convertMsftDefenderCloudToHdf(loadFixture('minimal.json'))) as HDFResults;
      const req0 = hdf.baselines[0]!.requirements[0]!;
      expect(req0.results[0]!.status).toBe('passed');
    });

    it('should map Unhealthy to failed', async () => {
      const hdf = JSON.parse(await convertMsftDefenderCloudToHdf(loadFixture('minimal.json'))) as HDFResults;
      const req1 = hdf.baselines[0]!.requirements[1]!;
      expect(req1.results[0]!.status).toBe('failed');
    });

    it('should map NotApplicable to notApplicable', async () => {
      const hdf = JSON.parse(await convertMsftDefenderCloudToHdf(loadFixture('sample.json'))) as HDFResults;
      const req4 = hdf.baselines[0]!.requirements[4]!;
      expect(req4.results[0]!.status).toBe('notApplicable');
    });
  });

  describe('severity mapping', async () => {
    it('should map High severity to 0.7', async () => {
      const hdf = JSON.parse(await convertMsftDefenderCloudToHdf(loadFixture('minimal.json'))) as HDFResults;
      const req1 = hdf.baselines[0]!.requirements[1]!;
      expect(req1.impact).toBe(0.7);
    });

    it('should map Medium severity to 0.5', async () => {
      const hdf = JSON.parse(await convertMsftDefenderCloudToHdf(loadFixture('minimal.json'))) as HDFResults;
      const req0 = hdf.baselines[0]!.requirements[0]!;
      expect(req0.impact).toBe(0.5);
    });

    it('should map Low severity to 0.3', async () => {
      const hdf = JSON.parse(await convertMsftDefenderCloudToHdf(loadFixture('sample.json'))) as HDFResults;
      const req4 = hdf.baselines[0]!.requirements[4]!;
      expect(req4.impact).toBe(0.3);
    });
  });

  describe('target', async () => {
    it('should set target as CloudAccount type', async () => {
      const hdf = JSON.parse(await convertMsftDefenderCloudToHdf(loadFixture('minimal.json'))) as HDFResults;
      expect(hdf.components).toHaveLength(1);
      expect(hdf.components![0]!.type).toBe('cloudAccount');
    });

    it('should include subscription ID in target', async () => {
      const hdf = JSON.parse(await convertMsftDefenderCloudToHdf(loadFixture('minimal.json'))) as HDFResults;
      const target = hdf.components![0]!;
      expect(target.accountId).toBe('a1b2c3d4-e5f6-7890-abcd-ef1234567890');
      expect(target.name).toContain('a1b2c3d4-e5f6-7890-abcd-ef1234567890');
    });

    it('should set Azure as provider', async () => {
      const hdf = JSON.parse(await convertMsftDefenderCloudToHdf(loadFixture('minimal.json'))) as HDFResults;
      expect(hdf.components![0]!.provider).toBe('azure');
    });
  });

  describe('MITRE ATT&CK tags', async () => {
    it('should include tactics from metadata', async () => {
      const hdf = JSON.parse(await convertMsftDefenderCloudToHdf(loadFixture('minimal.json'))) as HDFResults;
      const req0 = hdf.baselines[0]!.requirements[0]!;
      expect(req0.tags?.['tactics']).toContain('Discovery');
      expect(req0.tags?.['tactics']).toContain('Exfiltration');
    });

    it('should include techniques from metadata', async () => {
      const hdf = JSON.parse(await convertMsftDefenderCloudToHdf(loadFixture('minimal.json'))) as HDFResults;
      const req0 = hdf.baselines[0]!.requirements[0]!;
      expect(req0.tags?.['techniques']).toContain('T1046');
      expect(req0.tags?.['techniques']).toContain('T1530');
    });
  });

  describe('categories', async () => {
    it('should include categories in tags', async () => {
      const hdf = JSON.parse(await convertMsftDefenderCloudToHdf(loadFixture('minimal.json'))) as HDFResults;
      const req0 = hdf.baselines[0]!.requirements[0]!;
      expect(req0.tags?.['categories']).toContain('Networking');
    });
  });

  describe('policy definition ID tag', async () => {
    it('should include policy_definition_id as a string tag when present', async () => {
      const hdf = JSON.parse(await convertMsftDefenderCloudToHdf(loadFixture('minimal.json'))) as HDFResults;
      const req0 = hdf.baselines[0]!.requirements[0]!;
      expect(req0.tags?.['policy_definition_id']).toBe(
        '/providers/Microsoft.Authorization/policyDefinitions/aaaa1111-bbbb-2222-cccc-3333dddd4444',
      );
    });

    it('should omit policy_definition_id when source field is absent', async () => {
      const input = JSON.stringify({
        value: [
          {
            id: '/subscriptions/sub1/providers/Microsoft.Security/assessments/nopolicy',
            name: 'nopolicy',
            properties: {
              displayName: 'No policy',
              status: { code: 'Healthy' },
              metadata: {
                description: 'desc',
                severity: 'Low',
                categories: [], tactics: [], techniques: [], threats: [],
              },
              resourceDetails: { id: '/subscriptions/sub1/res' },
            },
          },
        ],
      });
      const hdf = JSON.parse(await convertMsftDefenderCloudToHdf(input)) as HDFResults;
      const req0 = hdf.baselines[0]!.requirements[0]!;
      expect(req0.tags?.['policy_definition_id']).toBeUndefined();
    });
  });

  describe('descriptions', async () => {
    it('should include default description from metadata.description', async () => {
      const hdf = JSON.parse(await convertMsftDefenderCloudToHdf(loadFixture('minimal.json'))) as HDFResults;
      const req0 = hdf.baselines[0]!.requirements[0]!;
      const defaultDesc = req0.descriptions?.find((d: { label: string }) => d.label === 'default');
      expect(defaultDesc?.data).toContain('Private links enforce secure communication');
    });

    it('should include fix description from remediationDescription', async () => {
      const hdf = JSON.parse(await convertMsftDefenderCloudToHdf(loadFixture('minimal.json'))) as HDFResults;
      const req0 = hdf.baselines[0]!.requirements[0]!;
      const fixDesc = req0.descriptions?.find((d: { label: string }) => d.label === 'fix');
      expect(fixDesc?.data).toContain('private endpoint');
    });
  });

  describe('requirement details', async () => {
    it('should use assessment GUID as requirement ID', async () => {
      const hdf = JSON.parse(await convertMsftDefenderCloudToHdf(loadFixture('minimal.json'))) as HDFResults;
      const req0 = hdf.baselines[0]!.requirements[0]!;
      expect(req0.id).toBe('11111111-1111-1111-1111-111111111111');
    });

    it('should use displayName as title', async () => {
      const hdf = JSON.parse(await convertMsftDefenderCloudToHdf(loadFixture('minimal.json'))) as HDFResults;
      const req0 = hdf.baselines[0]!.requirements[0]!;
      expect(req0.title).toBe('Storage account should use a private link connection');
    });

    it('should include resource ID in code_desc', async () => {
      const hdf = JSON.parse(await convertMsftDefenderCloudToHdf(loadFixture('minimal.json'))) as HDFResults;
      const req0 = hdf.baselines[0]!.requirements[0]!;
      expect(req0.results[0]!.codeDesc).toContain('storageAccounts/mystorageacct');
    });

    it('should include status description as message for unhealthy', async () => {
      const hdf = JSON.parse(await convertMsftDefenderCloudToHdf(loadFixture('minimal.json'))) as HDFResults;
      const req1 = hdf.baselines[0]!.requirements[1]!;
      expect(req1.results[0]!.message).toContain('Azure Disk Encryption is not enabled');
    });
  });

  describe('empty value array', async () => {
    it('should synthesize a no-findings passed placeholder when value array is empty', async () => {
      const hdf = JSON.parse(await convertMsftDefenderCloudToHdf(JSON.stringify({ value: [] }))) as HDFResults;
      expect(hdf.baselines).toHaveLength(1);
      expect(hdf.baselines[0]!.requirements).toHaveLength(1);
      const req = hdf.baselines[0]!.requirements[0]!;
      expect(req.id).toBe('msft-defender-cloud-no-findings');
      expect(req.results).toHaveLength(1);
      expect(req.results[0]!.status).toBe('passed');
      expect(req.results[0]!.codeDesc).toContain('Microsoft Defender for Cloud');
      expect(req.results[0]!.codeDesc).toContain('Unknown');
    });

    it('should synthesize a no-findings passed placeholder for the empty fixture', async () => {
      const hdf = JSON.parse(await convertMsftDefenderCloudToHdf(loadFixture('empty.json'))) as HDFResults;
      expect(hdf.baselines).toHaveLength(1);
      expect(hdf.baselines[0]!.requirements).toHaveLength(1);
      const req = hdf.baselines[0]!.requirements[0]!;
      expect(req.id).toBe('msft-defender-cloud-no-findings');
      expect(req.results[0]!.status).toBe('passed');
      expect(req.results[0]!.codeDesc).toContain('Microsoft Defender for Cloud');
    });
  });

  describe('branch coverage — optional metadata fields', () => {
    // Exercises the optional-field push branches in buildRequirement (lines ~118-149)
    // and the four mapStatus cases (line 82): healthy / unhealthy / notapplicable / unknown.
    it('populates tags and descriptions when all optional metadata is present', async () => {
      const input = JSON.stringify({
        value: [
          {
            id: '/subscriptions/aaa-bbb/providers/Microsoft.Security/assessments/a1',
            name: 'a1',
            properties: {
              displayName: 'Rich assessment',
              status: { code: 'Healthy' },
              metadata: {
                description: 'desc',
                remediationDescription: 'fix this',
                severity: 'High',
                categories: ['Compute'],
                tactics: ['Defense Evasion'],
                techniques: ['T1548'],
                threats: ['accountBreach'],
                userImpact: 'High',
                implementationEffort: 'Low',
                assessmentType: 'BuiltIn',
              },
              resourceDetails: { id: '/subscriptions/aaa-bbb/resourceGroups/rg/providers/foo' },
            },
          },
          {
            id: '/subscriptions/aaa-bbb/providers/Microsoft.Security/assessments/a2',
            name: 'a2',
            properties: {
              displayName: 'Unhealthy + NA + Unknown',
              status: { code: 'Unhealthy' },
              metadata: {
                description: 'desc-2',
                severity: 'Medium',
                categories: [], tactics: [], techniques: [], threats: [],
              },
              resourceDetails: { id: 'no-subscription-prefix' },
            },
          },
          {
            id: 'no-slash-after-subscription/subscriptions/ccc-ddd',
            name: 'a3',
            properties: {
              displayName: 'NA',
              status: { code: 'NotApplicable' },
              metadata: {
                description: 'desc-3',
                severity: 'Unknown',
                categories: [], tactics: [], techniques: [], threats: [],
              },
              resourceDetails: { id: '/subscriptions/eee-fff' },
            },
          },
          {
            id: '/subscriptions/aaa-bbb/providers/Microsoft.Security/assessments/a4',
            name: 'a4',
            properties: {
              displayName: 'Unknown status',
              status: { code: 'Stale' },
              metadata: {
                description: 'desc-4',
                severity: 'Low',
                categories: [], tactics: [], techniques: [], threats: [],
              },
              resourceDetails: { id: '/subscriptions/aaa-bbb' },
            },
          },
        ],
      });
      const hdf = JSON.parse(await convertMsftDefenderCloudToHdf(input)) as HDFResults;
      const reqs = hdf.baselines[0]!.requirements;
      expect(reqs.length).toBeGreaterThanOrEqual(4);

      const rich = reqs.find((r) => r.id === 'a1')!;
      expect(rich.tags).toMatchObject({
        categories: ['Compute'],
        tactics: ['Defense Evasion'],
        techniques: ['T1548'],
        threats: ['accountBreach'],
        severity: 'High',
        userImpact: 'High',
        implementationEffort: 'Low',
        assessmentType: 'BuiltIn',
      });
      expect(rich.descriptions.map((d) => d.label)).toContain('fix');
      expect(rich.results[0]!.status).toBe('passed');

      expect(reqs.find((r) => r.id === 'a2')!.results[0]!.status).toBe('failed');
      expect(reqs.find((r) => r.id === 'a3')!.results[0]!.status).toBe('notApplicable');
      expect(reqs.find((r) => r.id === 'a4')!.results[0]!.status).toBe('notReviewed');
    });
  });
});
