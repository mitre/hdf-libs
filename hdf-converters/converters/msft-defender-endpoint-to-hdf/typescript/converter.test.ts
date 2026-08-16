import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { describe, it, expect } from 'vitest';
import { convertMsftDefenderEndpointToHdf } from './converter.js';
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
  converterName: 'msft-defender-endpoint-to-hdf',
  convertFn: convertMsftDefenderEndpointToHdf,
  minimalFixture: 'minimal.json',
});

// Ground-truth anchor (input-derived count; see shared/typescript/anchor.ts).
// Each Graph Security API alert maps to exactly one requirement — no grouping —
// so the source count is the length of value[]. "value" is the sole array under
// that key at any depth in this format, so countJsonItemsUnderKey is unambiguous.
describe('msft-defender-endpoint-to-hdf ground-truth anchor', () => {
  it('emits one requirement per value[] alert (sample)', async () => {
    const input = loadFixture('sample.json');
    assertRequirementCount(
      await convertMsftDefenderEndpointToHdf(input),
      countJsonItemsUnderKey(input, 'value'),
      'sample.json: one requirement per value[] alert',
    );
  });
});

describe('msft-defender-endpoint to HDF converter', async () => {
  describe('error handling', async () => {
    it('should throw when value array is missing', async () => {
      await expect(convertMsftDefenderEndpointToHdf(JSON.stringify({ foo: 'bar' }))).rejects.toThrow(
        'missing or invalid value array',
      );
    });
  });

  describe('startTime fallback', async () => {
    it('uses conversion time when an alert has no activity/created timestamps', async () => {
      const doc = JSON.parse(loadFixture('minimal.json')) as { value: Array<Record<string, unknown>> };
      for (const alert of doc.value) {
        delete alert['firstActivityDateTime'];
        delete alert['createdDateTime'];
      }
      const before = Date.now();
      const hdf = JSON.parse(await convertMsftDefenderEndpointToHdf(JSON.stringify(doc))) as HDFResults;
      expectValidResults(hdf);
      const startTime = hdf.baselines[0]!.requirements[0]!.results[0]!.startTime;
      expect(startTime).toBeDefined();
      expect(new Date(startTime as string | Date).getTime()).toBeGreaterThanOrEqual(before);
    });

    it('falls through to createdDateTime when firstActivityDateTime is present but unparseable', async () => {
      const doc = JSON.parse(loadFixture('minimal.json')) as { value: Array<Record<string, unknown>> };
      for (const alert of doc.value) {
        alert['firstActivityDateTime'] = 'not-a-date';
        alert['createdDateTime'] = '2024-03-04T05:06:07Z';
      }
      const hdf = JSON.parse(await convertMsftDefenderEndpointToHdf(JSON.stringify(doc))) as HDFResults;
      expectValidResults(hdf);
      const startTime = hdf.baselines[0]!.requirements[0]!.results[0]!.startTime;
      // Matches the Go converter: an unparseable firstActivityDateTime must not
      // skip a valid createdDateTime in favor of the conversion time.
      expect(startTime).toBe('2024-03-04T05:06:07Z');
    });
  });

  describe('startTime value pinning', async () => {
    it('pins the per-alert startTime to firstActivityDateTime (canonical UTC ms)', async () => {
      const hdf = JSON.parse(await convertMsftDefenderEndpointToHdf(loadFixture('sample.json'))) as HDFResults;
      // sample alert[0] firstActivityDateTime "2021-01-26T20:31:32.9562661Z"
      // → canonical UTC at millisecond precision.
      const startTime = hdf.baselines[0]!.requirements[0]!.results[0]!.startTime;
      expect(startTime).toBe('2021-01-26T20:31:32.956Z');
    });
  });

  describe('top-level timestamp value pinning', async () => {
    it('pins the top-level timestamp to the latest lastUpdateDateTime across alerts', async () => {
      const hdf = JSON.parse(await convertMsftDefenderEndpointToHdf(loadFixture('sample.json'))) as HDFResults;
      // Latest lastUpdateDateTime is alert[3]'s "2021-01-29T14:30:00.0000000Z".
      expect(hdf.timestamp).toBe('2021-01-29T14:30:00Z');
    });

    it('falls back per alert to lastActivityDateTime when lastUpdateDateTime is absent', async () => {
      const doc = { value: [{ id: 'a', status: 'new', severity: 'low', category: 'Execution', title: 't', description: 'd', lastActivityDateTime: '2023-05-06T07:08:09Z' }] };
      const hdf = JSON.parse(await convertMsftDefenderEndpointToHdf(JSON.stringify(doc))) as HDFResults;
      expect(hdf.timestamp).toBe('2023-05-06T07:08:09Z');
    });

    it('falls back per alert to createdDateTime when lastUpdate/lastActivity are absent', async () => {
      const doc = { value: [{ id: 'a', status: 'new', severity: 'low', category: 'Execution', title: 't', description: 'd', createdDateTime: '2022-02-03T04:05:06Z' }] };
      const hdf = JSON.parse(await convertMsftDefenderEndpointToHdf(JSON.stringify(doc))) as HDFResults;
      expect(hdf.timestamp).toBe('2022-02-03T04:05:06Z');
    });

    it('falls back to the conversion time when no alert carries a parseable time', async () => {
      const before = Date.now();
      const hdf = JSON.parse(await convertMsftDefenderEndpointToHdf(loadFixture('empty.json'))) as HDFResults;
      expect(hdf.timestamp).toBeTruthy();
      expect(new Date(hdf.timestamp as unknown as string).getTime()).toBeGreaterThanOrEqual(before - 1000);
    });
  });

  describe('minimal fixture conversion', async () => {
    it('should produce valid HDF structure from minimal fixture', async () => {
      const output = await convertMsftDefenderEndpointToHdf(loadFixture('minimal.json'));
      const hdf = JSON.parse(output) as HDFResults;

      expect(hdf.timestamp).toBeTruthy();
      expect(hdf.generator?.name).toBe('msft-defender-endpoint-to-hdf');
      expect(hdf.generator?.version).toBe('1.0.0');
      expect(hdf.tool?.name).toBe('Microsoft Defender for Endpoint');
      expect(hdf.baselines).toHaveLength(1);
    });

    it('should produce schema-valid HDF results', async () => {
      const output = await convertMsftDefenderEndpointToHdf(loadFixture('sample.json'));
      const hdf = JSON.parse(output) as HDFResults;
      expectValidResults(hdf);
    });

    it('should convert 1 alert to 1 requirement', async () => {
      const hdf = JSON.parse(await convertMsftDefenderEndpointToHdf(loadFixture('minimal.json'))) as HDFResults;
      expect(hdf.baselines[0]!.requirements).toHaveLength(1);
    });

    it('should use alert ID as requirement ID', async () => {
      const hdf = JSON.parse(await convertMsftDefenderEndpointToHdf(loadFixture('minimal.json'))) as HDFResults;
      expect(hdf.baselines[0]!.requirements[0]!.id).toBe('da637472900382838869_1364969609');
    });
  });

  describe('sample fixture conversion', async () => {
    it('should convert 4 alerts to 4 requirements', async () => {
      const hdf = JSON.parse(await convertMsftDefenderEndpointToHdf(loadFixture('sample.json'))) as HDFResults;
      expect(hdf.baselines[0]!.requirements).toHaveLength(4);
    });
  });

  describe('status mapping', async () => {
    it('should map "new" status to failed', async () => {
      const hdf = JSON.parse(await convertMsftDefenderEndpointToHdf(loadFixture('minimal.json'))) as HDFResults;
      expect(hdf.baselines[0]!.requirements[0]!.results[0]!.status).toBe('failed');
    });

    it('should map "inProgress" status to failed', async () => {
      const hdf = JSON.parse(await convertMsftDefenderEndpointToHdf(loadFixture('sample.json'))) as HDFResults;
      expect(hdf.baselines[0]!.requirements[1]!.results[0]!.status).toBe('failed');
    });

    it('keeps raw failed for a resolved falsePositive (triage rides in an override)', async () => {
      const hdf = JSON.parse(await convertMsftDefenderEndpointToHdf(loadFixture('sample.json'))) as HDFResults;
      expect(hdf.baselines[0]!.requirements[2]!.results[0]!.status).toBe('failed');
    });

    it('should map "resolved" with truePositive classification to failed', async () => {
      const hdf = JSON.parse(await convertMsftDefenderEndpointToHdf(loadFixture('sample.json'))) as HDFResults;
      expect(hdf.baselines[0]!.requirements[3]!.results[0]!.status).toBe('failed');
    });
  });

  describe('structured status overrides from triage', async () => {
    it('emits a falsePositive override with full provenance (assignedTo + resolvedDateTime)', async () => {
      const hdf = JSON.parse(await convertMsftDefenderEndpointToHdf(loadFixture('sample.json'))) as HDFResults;
      const req = hdf.baselines[0]!.requirements[2]!;

      // Raw failure preserved; effective status + disposition reflect the override.
      expect(req.results[0]!.status).toBe('failed');
      expect(req.effectiveStatus).toBe('notApplicable');
      expect(req.disposition).toBe('falsePositive');

      expect(req.statusOverrides).toHaveLength(1);
      const ov = req.statusOverrides![0]!;
      expect(ov.type).toBe('falsePositive');
      expect(ov.status).toBe('notApplicable');
      expect(ov.reason).toBe('notMalicious (falsePositive)');
      expect(ov.appliedBy.identifier).toBe('analyst@contoso.com');
      expect(ov.appliedBy.type).toBe('email');
      expect(String(ov.appliedAt)).toBe('2021-01-28T12:00:00Z');
      expect(String(ov.expiresAt)).toBe('2022-01-28T12:00:00Z');

      // Loose triage tags replaced by the structured override.
      expect(req.tags!['classification']).toBeUndefined();
      expect(req.tags!['determination']).toBeUndefined();
    });

    it('leaves a truePositive alert with no override (raw failed, tags retained)', async () => {
      const hdf = JSON.parse(await convertMsftDefenderEndpointToHdf(loadFixture('sample.json'))) as HDFResults;
      const req = hdf.baselines[0]!.requirements[3]!;
      expect(req.results[0]!.status).toBe('failed');
      expect(req.statusOverrides).toBeUndefined();
      expect(req.effectiveStatus).toBeUndefined();
      expect(req.disposition).toBeUndefined();
      expect(req.tags!['classification']).toBe('truePositive');
      expect(req.tags!['determination']).toBe('malware');
    });

    it('leaves an untriaged alert (classification null) with no override', async () => {
      const hdf = JSON.parse(await convertMsftDefenderEndpointToHdf(loadFixture('minimal.json'))) as HDFResults;
      const req = hdf.baselines[0]!.requirements[0]!;
      expect(req.statusOverrides).toBeUndefined();
      expect(req.effectiveStatus).toBeUndefined();
      expect(req.disposition).toBeUndefined();
    });

    it('emits a waiver override for informationalExpectedActivity (effectiveStatus passed)', async () => {
      const doc = JSON.stringify({
        value: [{
          id: 'a', status: 'resolved', severity: 'low', category: 'Execution', title: 't', description: 'd',
          classification: 'informationalExpectedActivity', determination: 'securityTesting',
          assignedTo: 'redteam', resolvedDateTime: '2023-06-07T08:09:10Z',
        }],
      });
      const hdf = JSON.parse(await convertMsftDefenderEndpointToHdf(doc)) as HDFResults;
      const req = hdf.baselines[0]!.requirements[0]!;
      expect(req.results[0]!.status).toBe('failed');
      expect(req.effectiveStatus).toBe('passed');
      expect(req.disposition).toBe('waiver');

      const ov = req.statusOverrides![0]!;
      expect(ov.type).toBe('waiver');
      expect(ov.reason).toBe('securityTesting (informationalExpectedActivity)');
      // assignedTo without an "@" is typed as a username.
      expect(ov.appliedBy).toMatchObject({ type: 'username', identifier: 'redteam' });
      expect(String(ov.appliedAt)).toBe('2023-06-07T08:09:10Z');
      expect(String(ov.expiresAt)).toBe('2024-06-07T08:09:10Z');
    });

    it('falls back to a system identity and lastUpdateDateTime when no owner/resolved time', async () => {
      const doc = JSON.stringify({
        value: [{
          id: 'a', status: 'resolved', severity: 'low', category: 'Execution', title: 't', description: 'd',
          classification: 'falsePositive', lastUpdateDateTime: '2023-01-02T03:04:05Z',
        }],
      });
      const hdf = JSON.parse(await convertMsftDefenderEndpointToHdf(doc)) as HDFResults;
      const ov = hdf.baselines[0]!.requirements[0]!.statusOverrides![0]!;
      expect(ov.appliedBy).toMatchObject({ type: 'system', identifier: 'Microsoft Defender for Endpoint (automated triage)' });
      expect(ov.reason).toBe('falsePositive');
      expect(String(ov.appliedAt)).toBe('2023-01-02T03:04:05Z');
    });
  });

  describe('severity mapping', async () => {
    it('should map "high" severity to 0.7', async () => {
      const hdf = JSON.parse(await convertMsftDefenderEndpointToHdf(loadFixture('sample.json'))) as HDFResults;
      expect(hdf.baselines[0]!.requirements[0]!.impact).toBe(0.7);
    });

    it('should map "medium" severity to 0.5', async () => {
      const hdf = JSON.parse(await convertMsftDefenderEndpointToHdf(loadFixture('sample.json'))) as HDFResults;
      expect(hdf.baselines[0]!.requirements[1]!.impact).toBe(0.5);
    });

    it('should map "low" severity to 0.3', async () => {
      const hdf = JSON.parse(await convertMsftDefenderEndpointToHdf(loadFixture('minimal.json'))) as HDFResults;
      expect(hdf.baselines[0]!.requirements[0]!.impact).toBe(0.3);
    });

    it('should map "informational" severity to 0.0', async () => {
      const hdf = JSON.parse(await convertMsftDefenderEndpointToHdf(loadFixture('sample.json'))) as HDFResults;
      expect(hdf.baselines[0]!.requirements[2]!.impact).toBe(0.0);
    });

    it('should map "critical" severity to 0.9 like the Go twin (shared standard map)', async () => {
      const doc = { value: [{ id: 'a', status: 'new', severity: 'critical', category: 'Execution', title: 't', description: 'd' }] };
      const hdf = JSON.parse(await convertMsftDefenderEndpointToHdf(JSON.stringify(doc))) as HDFResults;
      expect(hdf.baselines[0]!.requirements[0]!.impact).toBe(0.9);
    });

    it('should default Graph "unSpecified" severity to 0.5', async () => {
      const doc = { value: [{ id: 'a', status: 'new', severity: 'unSpecified', category: 'Execution', title: 't', description: 'd' }] };
      const hdf = JSON.parse(await convertMsftDefenderEndpointToHdf(JSON.stringify(doc))) as HDFResults;
      expect(hdf.baselines[0]!.requirements[0]!.impact).toBe(0.5);
    });

    it('defaults an absent severity field to 0.5 without throwing (Go zero-value parity)', async () => {
      const doc = { value: [{ id: 'a', status: 'new', category: 'Execution', title: 't', description: 'd' }] };
      const hdf = JSON.parse(await convertMsftDefenderEndpointToHdf(JSON.stringify(doc))) as HDFResults;
      expect(hdf.baselines[0]!.requirements[0]!.impact).toBe(0.5);
    });
  });

  describe('targets', async () => {
    it('should create Host target from device evidence', async () => {
      const hdf = JSON.parse(await convertMsftDefenderEndpointToHdf(loadFixture('minimal.json'))) as HDFResults;
      expect(hdf.components).toBeDefined();
      expect(hdf.components!.length).toBeGreaterThan(0);
      const target = hdf.components![0]!;
      expect(target.type).toBe('host');
      expect(target.name).toBe('temp123.middleeast.corp.microsoft.com');
      expect(target.fqdn).toBe('temp123.middleeast.corp.microsoft.com');
      expect(target.osName).toBe('Windows10');
      // MDE device id surfaced as external identifier.
      expect(target.externalIds).toEqual({ mde: '111e6dd8c833c8a052ea231ec1b19adaf497b625' });
      // rbac/health/onboarding surfaced as labels alongside provider.
      expect(target.labels!['rbacGroupName']).toBe('A');
      expect(target.labels!['healthStatus']).toBe('active');
      expect(target.labels!['onboardingStatus']).toBe('onboarded');
      expect(target.labels!['provider']).toBe('azure');
    });

    it('should use mdeDeviceId as name when dns name is absent', async () => {
      const doc = JSON.stringify({
        value: [{
          id: 'a', status: 'new', severity: 'low', category: 'Execution', title: 't', description: 'd',
          evidence: [{ '@odata.type': '#microsoft.graph.security.deviceEvidence', mdeDeviceId: 'abc123' }],
        }],
      });
      const hdf = JSON.parse(await convertMsftDefenderEndpointToHdf(doc)) as HDFResults;
      expect(hdf.components).toHaveLength(1);
      const target = hdf.components![0]!;
      expect(target.type).toBe('host');
      expect(target.name).toBe('abc123');
      expect(target.fqdn).toBeUndefined();
      expect(target.externalIds).toEqual({ mde: 'abc123' });
    });

    it('should deduplicate targets by name', async () => {
      const hdf = JSON.parse(await convertMsftDefenderEndpointToHdf(loadFixture('sample.json'))) as HDFResults;
      // 4 alerts with 4 different devices → 4 targets
      expect(hdf.components).toHaveLength(4);
    });

    it('should deduplicate targets by mdeDeviceId even when dns names differ', async () => {
      const doc = JSON.stringify({
        value: [
          {
            id: 'a', status: 'new', severity: 'low', category: 'Execution', title: 't', description: 'd',
            evidence: [{ '@odata.type': '#microsoft.graph.security.deviceEvidence', deviceDnsName: 'host-a.example.com', mdeDeviceId: 'same-id' }],
          },
          {
            id: 'b', status: 'new', severity: 'low', category: 'Execution', title: 't', description: 'd',
            evidence: [{ '@odata.type': '#microsoft.graph.security.deviceEvidence', deviceDnsName: 'host-a-renamed.example.com', mdeDeviceId: 'same-id' }],
          },
        ],
      });
      const hdf = JSON.parse(await convertMsftDefenderEndpointToHdf(doc)) as HDFResults;
      expect(hdf.components).toHaveLength(1);
      expect(hdf.components![0]!.externalIds).toEqual({ mde: 'same-id' });
    });

    it('should emit no host component when device evidence is absent', async () => {
      const doc = JSON.stringify({
        value: [{
          id: 'a', status: 'new', severity: 'low', category: 'Execution', title: 't', description: 'd',
          tenantId: 'tenant-xyz',
          evidence: [{ '@odata.type': '#microsoft.graph.security.processEvidence', processCommandLine: 'x' }],
        }],
      });
      const hdf = JSON.parse(await convertMsftDefenderEndpointToHdf(doc)) as HDFResults;
      expect(hdf.components).toHaveLength(1);
      const target = hdf.components![0]!;
      expect(target.type).toBe('cloudAccount');
      expect(target.type).not.toBe('host');
      expect(target.externalIds?.['mde']).toBeUndefined();
    });
  });

  describe('MITRE ATT&CK techniques', async () => {
    it('should include MITRE techniques in tags', async () => {
      const hdf = JSON.parse(await convertMsftDefenderEndpointToHdf(loadFixture('minimal.json'))) as HDFResults;
      const tags = hdf.baselines[0]!.requirements[0]!.tags!;
      const mitre = tags['mitre'] as string[];
      expect(mitre).toContain('T1064');
      expect(mitre).toContain('T1085');
      expect(mitre).toContain('T1220');
    });

    it('should omit mitre tag when no techniques present', async () => {
      const hdf = JSON.parse(await convertMsftDefenderEndpointToHdf(loadFixture('sample.json'))) as HDFResults;
      const tags = hdf.baselines[0]!.requirements[2]!.tags!;
      expect(tags['mitre']).toBeUndefined();
    });
  });

  describe('category tag', async () => {
    it('should include category in tags', async () => {
      const hdf = JSON.parse(await convertMsftDefenderEndpointToHdf(loadFixture('minimal.json'))) as HDFResults;
      const tags = hdf.baselines[0]!.requirements[0]!.tags!;
      expect(tags['category']).toBe('Execution');
    });
  });

  describe('descriptions', async () => {
    it('should include default description from alert description', async () => {
      const hdf = JSON.parse(await convertMsftDefenderEndpointToHdf(loadFixture('minimal.json'))) as HDFResults;
      const descs = hdf.baselines[0]!.requirements[0]!.descriptions!;
      const defaultDesc = descs.find(d => d.label === 'default');
      expect(defaultDesc?.data).toContain('Binaries signed by Microsoft');
    });

    it('should include fix description from recommendedActions', async () => {
      const hdf = JSON.parse(await convertMsftDefenderEndpointToHdf(loadFixture('minimal.json'))) as HDFResults;
      const descs = hdf.baselines[0]!.requirements[0]!.descriptions!;
      const fixDesc = descs.find(d => d.label === 'fix');
      expect(fixDesc?.data).toContain('Collect artifacts');
    });
  });

  describe('refs from alertWebUrl', async () => {
    it('should emit a Reference{url} from alertWebUrl', async () => {
      const hdf = JSON.parse(await convertMsftDefenderEndpointToHdf(loadFixture('minimal.json'))) as HDFResults;
      const refs = hdf.baselines[0]!.requirements[0]!.refs!;
      expect(refs).toHaveLength(1);
      expect(refs[0]!.url).toBe('https://security.microsoft.com/alerts/da637472900382838869_1364969609');
      expect(refs[0]!.uri).toBeUndefined();
      expect(refs[0]!.ref).toBeUndefined();
    });

    it('should omit refs when the alert carries no alertWebUrl', async () => {
      // empty.json → no alerts → no-findings requirement has no alertWebUrl.
      const hdf = JSON.parse(await convertMsftDefenderEndpointToHdf(loadFixture('empty.json'))) as HDFResults;
      expect(hdf.baselines[0]!.requirements[0]!.refs).toBeUndefined();
    });
  });

  describe('evidence in code_desc', async () => {
    it('should include device and process evidence in code_desc', async () => {
      const hdf = JSON.parse(await convertMsftDefenderEndpointToHdf(loadFixture('minimal.json'))) as HDFResults;
      const codeDesc = hdf.baselines[0]!.requirements[0]!.results[0]!.codeDesc ?? '';
      expect(codeDesc).toContain('Device: temp123.middleeast.corp.microsoft.com');
      expect(codeDesc).toContain('rundll32.exe');
    });
  });

  describe('classification and determination', async () => {
    it('retains classification/determination as loose tags when there is no override (truePositive)', async () => {
      const hdf = JSON.parse(await convertMsftDefenderEndpointToHdf(loadFixture('sample.json'))) as HDFResults;
      const tags = hdf.baselines[0]!.requirements[3]!.tags!;
      expect(tags['classification']).toBe('truePositive');
      expect(tags['determination']).toBe('malware');
    });

    it('should omit classification and determination when null', async () => {
      const hdf = JSON.parse(await convertMsftDefenderEndpointToHdf(loadFixture('minimal.json'))) as HDFResults;
      const tags = hdf.baselines[0]!.requirements[0]!.tags!;
      expect(tags['classification']).toBeUndefined();
      expect(tags['determination']).toBeUndefined();
    });
  });

  describe('source metadata tags', async () => {
    it('emits incident_id as a number for a canonical integer', async () => {
      const hdf = JSON.parse(await convertMsftDefenderEndpointToHdf(loadFixture('sample.json'))) as HDFResults;
      const tags = hdf.baselines[0]!.requirements[0]!.tags!;
      expect(tags['incident_id']).toBe(1126093);
      expect(typeof tags['incident_id']).toBe('number');
    });

    it('preserves a non-numeric incidentId as a string', async () => {
      const doc = { value: [{ id: 'a', incidentId: 'INC-42', status: 'new', severity: 'low', category: 'Execution', title: 't', description: 'd' }] };
      const hdf = JSON.parse(await convertMsftDefenderEndpointToHdf(JSON.stringify(doc))) as HDFResults;
      const tags = hdf.baselines[0]!.requirements[0]!.tags!;
      expect(tags['incident_id']).toBe('INC-42');
    });

    it('omits incident_id when the alert has no incidentId', async () => {
      const doc = { value: [{ id: 'a', status: 'new', severity: 'low', category: 'Execution', title: 't', description: 'd' }] };
      const hdf = JSON.parse(await convertMsftDefenderEndpointToHdf(JSON.stringify(doc))) as HDFResults;
      const tags = hdf.baselines[0]!.requirements[0]!.tags!;
      expect(tags['incident_id']).toBeUndefined();
    });

    it('emits detection_source and service_source', async () => {
      const hdf = JSON.parse(await convertMsftDefenderEndpointToHdf(loadFixture('sample.json'))) as HDFResults;
      const tags = hdf.baselines[0]!.requirements[0]!.tags!;
      expect(tags['detection_source']).toBe('WindowsDefenderAtp');
      expect(tags['service_source']).toBe('microsoftDefenderForEndpoint');
      const fourth = hdf.baselines[0]!.requirements[3]!.tags!;
      expect(fourth['detection_source']).toBe('WindowsDefenderAv');
    });

    it('omits detection_source and service_source when absent', async () => {
      const doc = { value: [{ id: 'a', incidentId: '1', status: 'new', severity: 'low', category: 'Execution', title: 't', description: 'd' }] };
      const hdf = JSON.parse(await convertMsftDefenderEndpointToHdf(JSON.stringify(doc))) as HDFResults;
      const tags = hdf.baselines[0]!.requirements[0]!.tags!;
      expect(tags['detection_source']).toBeUndefined();
      expect(tags['service_source']).toBeUndefined();
    });

    it('emits threat_family_name when populated', async () => {
      const hdf = JSON.parse(await convertMsftDefenderEndpointToHdf(loadFixture('sample.json'))) as HDFResults;
      const tags = hdf.baselines[0]!.requirements[3]!.tags!;
      expect(tags['threat_family_name']).toBe('Emotet');
    });

    it('omits threat_family_name when source is null', async () => {
      const hdf = JSON.parse(await convertMsftDefenderEndpointToHdf(loadFixture('sample.json'))) as HDFResults;
      const tags = hdf.baselines[0]!.requirements[0]!.tags!;
      expect(tags['threat_family_name']).toBeUndefined();
    });

    it('never emits actor_display_name (null in source)', async () => {
      const hdf = JSON.parse(await convertMsftDefenderEndpointToHdf(loadFixture('sample.json'))) as HDFResults;
      for (const req of hdf.baselines[0]!.requirements) {
        expect(req.tags!['actor_display_name']).toBeUndefined();
      }
    });
  });

  describe('checksum', async () => {
    it('should include sha256 checksum', async () => {
      const hdf = JSON.parse(await convertMsftDefenderEndpointToHdf(loadFixture('minimal.json'))) as HDFResults;
      const checksum = hdf.baselines[0]!.resultsChecksum;
      expect(checksum?.algorithm).toBe('sha256');
      expect(checksum?.value).toMatch(/^[a-f0-9]{64}$/);
    });
  });

  describe('empty value array', async () => {
    it('should synthesize a passed placeholder for empty value array', async () => {
      const hdf = JSON.parse(await convertMsftDefenderEndpointToHdf(loadFixture('empty.json'))) as HDFResults;
      expect(hdf.baselines).toHaveLength(1);
      const reqs = hdf.baselines[0]!.requirements;
      expect(reqs).toHaveLength(1);
      expect(reqs[0]!.id).toBe('msft-defender-endpoint-no-findings');
      expect(reqs[0]!.results[0]!.status).toBe('passed');
      expect(reqs[0]!.results[0]!.codeDesc).toContain('Microsoft Defender for Endpoint');
      expect(reqs[0]!.results[0]!.codeDesc).toContain('zero findings');
    });
  });

  describe('baseline name', async () => {
    it('should use "Microsoft Defender for Endpoint Scan" as baseline name', async () => {
      const hdf = JSON.parse(await convertMsftDefenderEndpointToHdf(loadFixture('minimal.json'))) as HDFResults;
      expect(hdf.baselines[0]!.name).toBe('Microsoft Defender for Endpoint Scan');
    });
  });
});
