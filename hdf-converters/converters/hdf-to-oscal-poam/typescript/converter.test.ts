import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, it, expect } from 'vitest';
import { amendments } from '@mitre/hdf-fixtures';
import { convertHdfToOscalPoam } from './converter.js';
import { convertOscalPoamToHdf } from '../../oscal-to-hdf/typescript/converter-poam.js';
import { hdfStatusToOscalRiskStatus as hdfStatusToOSCAL, nistTagToControlId as nistTagToControlID } from '../../oscal-to-hdf/typescript/shared.js';
import { maskVolatileJson } from '../../../shared/typescript/golden-mask.js';
import { loadSchemaValidator, assertSchemaValid } from '../../../shared/typescript/schema-validation.js';

const __dirname = dirname(fileURLToPath(import.meta.url));

// Only the metadata timestamp carries the conversion moment; every other date
// in a POA&M (milestone deadlines, expiration) is input-derived and stays asserted.
const POAM_VOLATILE_KEYS = ['last-modified'];

describe('convertHdfToOscalPoam', () => {
  it('should reject empty input', async () => {
    await expect(convertHdfToOscalPoam('')).rejects.toThrow('empty input');
  });

  it('should reject invalid JSON', async () => {
    // main's shared guard is the incumbent and words this 'Invalid JSON'; the
    // recovered test carried the branch guard's wording.
    await expect(convertHdfToOscalPoam('{not json')).rejects.toThrow('Invalid JSON');
  });

  it('should convert minimal amendments', async () => {
    const amendments = {
      name: 'test-poam',
      overrides: [
        {
          type: 'poam',
          requirementId: 'AC-1',
          reason: 'Pending remediation',
          status: 'failed',
          appliedBy: { type: 'simple', identifier: 'admin@example.com' },
          appliedAt: '2026-01-15T00:00:00Z',
          expiresAt: '2027-01-15T00:00:00Z',
        },
      ],
    };

    const output = await convertHdfToOscalPoam(JSON.stringify(amendments));
    const doc = JSON.parse(output);

    expect(doc).toHaveProperty('plan-of-action-and-milestones');
    const poam = doc['plan-of-action-and-milestones'];

    // Verify metadata
    expect(poam.metadata.title).toBe('test-poam');
    expect(poam.metadata.version).toBe('1.0.0');
    expect(poam.metadata['oscal-version']).toBe('1.1.2');
    expect(poam.metadata['last-modified']).toBeTruthy();

    // Verify UUID
    expect(poam.uuid).toBeTruthy();
    expect(poam.uuid).toHaveLength(36);

    // Verify import-ssp defaults to "#"
    expect(poam['import-ssp']).toBeDefined();
    expect(poam['import-ssp'].href).toBe('#');

    // Verify poam-items
    expect(poam['poam-items']).toHaveLength(1);
    const item = poam['poam-items'][0];
    expect(item.uuid).toBeTruthy();
    expect(item.title).toBe('AC-1');
    expect(item.description).toBe('Pending remediation');

    // Verify related risks
    expect(item['related-risks']).toHaveLength(1);
    expect(item['related-risks'][0]['risk-uuid']).toBeTruthy();

    // Verify risk
    expect(poam.risks).toHaveLength(1);
    const risk = poam.risks[0];
    expect(risk.uuid).toBe(item['related-risks'][0]['risk-uuid']);
    expect(risk.status).toBe('open');
    expect(risk.description).toBe('Pending remediation');
  });

  it('should use systemRef when provided', async () => {
    const amendments = {
      name: 'test-poam',
      systemRef: 'https://example.com/ssp.json',
      overrides: [
        {
          type: 'poam',
          requirementId: 'AC-1',
          reason: 'test',
          status: 'failed',
          appliedBy: { type: 'simple', identifier: 'admin' },
          appliedAt: '2026-01-01T00:00:00Z',
          expiresAt: '2027-01-01T00:00:00Z',
        },
      ],
    };

    const output = await convertHdfToOscalPoam(JSON.stringify(amendments));
    const doc = JSON.parse(output);

    expect(doc['plan-of-action-and-milestones']['import-ssp'].href).toBe(
      'https://example.com/ssp.json',
    );
  });

  it('should map all HDF statuses correctly', async () => {
    const tests = [
      { hdfStatus: 'passed', oscalStatus: 'closed' },
      { hdfStatus: 'failed', oscalStatus: 'open' },
      { hdfStatus: 'error', oscalStatus: 'open' },
      { hdfStatus: 'notApplicable', oscalStatus: 'closed' },
      { hdfStatus: 'notReviewed', oscalStatus: 'open' },
    ];

    for (const tt of tests) {
      const amendments = {
        name: 'status-test',
        overrides: [
          {
            type: 'poam',
            requirementId: 'AC-1',
            reason: 'test',
            status: tt.hdfStatus,
            appliedBy: { type: 'simple', identifier: 'admin' },
            appliedAt: '2026-01-01T00:00:00Z',
            expiresAt: '2027-01-01T00:00:00Z',
          },
        ],
      };

      const output = await convertHdfToOscalPoam(JSON.stringify(amendments));
      const doc = JSON.parse(output);

      expect(doc['plan-of-action-and-milestones'].risks).toHaveLength(1);
      expect(doc['plan-of-action-and-milestones'].risks[0].status).toBe(tt.oscalStatus);
    }
  });

  it('should handle multiple overrides', async () => {
    const amendments = {
      name: 'multi-test',
      overrides: [
        {
          type: 'poam',
          requirementId: 'AC-1',
          reason: 'First item',
          status: 'failed',
          appliedBy: { type: 'simple', identifier: 'admin' },
          appliedAt: '2026-01-01T00:00:00Z',
          expiresAt: '2027-01-01T00:00:00Z',
        },
        {
          type: 'poam',
          requirementId: 'SI-7 (1)',
          reason: 'Second item',
          status: 'passed',
          appliedBy: { type: 'simple', identifier: 'admin' },
          appliedAt: '2026-01-01T00:00:00Z',
          expiresAt: '2027-01-01T00:00:00Z',
        },
      ],
    };

    const output = await convertHdfToOscalPoam(JSON.stringify(amendments));
    const doc = JSON.parse(output);

    const poam = doc['plan-of-action-and-milestones'];
    expect(poam['poam-items']).toHaveLength(2);
    expect(poam.risks).toHaveLength(2);

    // Verify each item has unique UUID
    expect(poam['poam-items'][0].uuid).not.toBe(poam['poam-items'][1].uuid);

    // Verify titles
    expect(poam['poam-items'][0].title).toBe('AC-1');
    expect(poam['poam-items'][1].title).toBe('SI-7 (1)');

    // Each risk carries the exact requirement id and the FedRAMP impacted control in OSCAL form.
    const riskProp = (i: number, name: string) =>
      (poam.risks[i].props as Array<{ name: string; value: string }>).find((p) => p.name === name)?.value;
    expect(riskProp(0, 'hdf-requirement-id')).toBe('AC-1');
    expect(riskProp(0, 'impacted-control-id')).toBe('ac-1');
    expect(riskProp(1, 'hdf-requirement-id')).toBe('SI-7 (1)');
    expect(riskProp(1, 'impacted-control-id')).toBe('si-7.1');
  });

  it('should carry milestone deadline/status and override type/impact', async () => {
    const amendments = {
      overrides: [{
        type: 'riskAdjustment',
        requirementId: 'AC-1',
        status: 'failed',
        reason: 'residual risk accepted',
        impact: { value: 0.3 },
        appliedBy: { type: 'simple', identifier: 'admin' },
        appliedAt: '2026-01-01T00:00:00Z',
        milestones: [{ description: 'apply patch', estimatedCompletion: '2099-06-30T00:00:00Z', status: 'pending' }],
      }],
    };
    const doc = JSON.parse(await convertHdfToOscalPoam(JSON.stringify(amendments)));
    const risk = doc['plan-of-action-and-milestones'].risks[0];
    const riskProp = (n: string): string | undefined =>
      risk.props.find((p: { name: string; value: string }) => p.name === n)?.value;
    expect(riskProp('override-type')).toBe('riskAdjustment');
    expect(riskProp('override-status')).toBe('failed');
    expect(riskProp('impact-override')).toBe('0.3');
    const rem = risk.remediations[0];
    expect(rem.description).toBe('apply patch');
    expect(rem.props?.find((p: { name: string }) => p.name === 'milestone-status'), 'the milestone status rides on the task').toBeUndefined();
    const taskProp = (n: string): string | undefined =>
      rem.tasks[0].props.find((p: { name: string; value: string }) => p.name === n)?.value;
    // The estimated completion rides on the remediation task's within-date-range end.
    expect(rem.tasks[0].timing['within-date-range'].end).toContain('2099-06-30');
    expect(taskProp('milestone-status')).toBe('pending');
  });

  it('should convert milestones to remediations', async () => {
    const amendments = {
      name: 'milestone-test',
      overrides: [
        {
          type: 'poam',
          requirementId: 'AC-2',
          reason: 'With milestones',
          status: 'failed',
          appliedBy: { type: 'simple', identifier: 'admin' },
          appliedAt: '2026-01-01T00:00:00Z',
          expiresAt: '2027-01-01T00:00:00Z',
          milestones: [
            {
              title: 'Deploy MFA',
              description: 'Deploy MFA solution',
              estimatedCompletion: '2026-06-01T00:00:00Z',
              status: 'pending',
            },
            {
              title: 'Verify MFA',
              description: 'Verify MFA deployment',
              estimatedCompletion: '2026-09-01T00:00:00Z',
              status: 'inProgress',
            },
          ],
        },
      ],
    };

    const output = await convertHdfToOscalPoam(JSON.stringify(amendments));
    const doc = JSON.parse(output);

    expect(doc['plan-of-action-and-milestones'].risks).toHaveLength(1);
    const risk = doc['plan-of-action-and-milestones'].risks[0];
    expect(risk.remediations).toHaveLength(2);

    expect(risk.remediations[0].lifecycle).toBe('planned');
    expect(risk.remediations[0].title).toBe('Deploy MFA');
    expect(risk.remediations[1].title).toBe('Verify MFA');
  });

  it('should include appliedBy in metadata', async () => {
    const amendments = {
      name: 'applied-by-test',
      appliedBy: { type: 'simple', identifier: 'security-team@example.com' },
      overrides: [
        {
          type: 'poam',
          requirementId: 'AC-1',
          reason: 'test',
          status: 'failed',
          appliedBy: { type: 'simple', identifier: 'admin' },
          appliedAt: '2026-01-01T00:00:00Z',
          expiresAt: '2027-01-01T00:00:00Z',
        },
      ],
    };

    const output = await convertHdfToOscalPoam(JSON.stringify(amendments));
    const doc = JSON.parse(output);

    const meta = doc['plan-of-action-and-milestones'].metadata;
    expect(meta['responsible-parties']).toHaveLength(1);
    expect(meta['responsible-parties'][0]['role-id']).toBe('prepared-by');
    // Document applier is party[0]; the distinct per-override applier is surfaced too.
    expect(meta.parties).toHaveLength(2);
    expect(meta.parties[0].name).toBe('security-team@example.com');
    expect(meta.parties[0].uuid).toBe(meta['responsible-parties'][0]['party-uuids'][0]);
    expect(meta.parties.map((p: { name: string }) => p.name)).toContain('admin');
  });

  it('should record expiresAt in risk log', async () => {
    const amendments = {
      name: 'expires-test',
      overrides: [
        {
          type: 'poam',
          requirementId: 'AC-1',
          reason: 'test',
          status: 'failed',
          appliedBy: { type: 'simple', identifier: 'admin' },
          appliedAt: '2026-01-01T00:00:00Z',
          expiresAt: '2027-03-15T12:00:00.000Z',
        },
      ],
    };

    const output = await convertHdfToOscalPoam(JSON.stringify(amendments));
    const doc = JSON.parse(output);

    const risk = doc['plan-of-action-and-milestones'].risks[0];
    expect(risk['risk-log']).toBeDefined();
    expect(risk['risk-log'].entries).toHaveLength(2);
    expect(risk['risk-log'].entries[0].title).toBe('Override applied');
    expect(risk['risk-log'].entries[1].title).toBe('Scheduled review');
    // HDF canonical trimmed-UTC form, byte-identical to the Go converter's output.
    expect(risk['risk-log'].entries[1].start).toBe('2027-03-15T12:00:00Z');
    expect(risk.deadline).toBe('2027-03-15T12:00:00Z');
  });

  it('should generate unique UUIDs', async () => {
    const amendments = {
      name: 'uuid-test',
      overrides: [
        {
          type: 'poam',
          requirementId: 'AC-1',
          reason: 'test 1',
          status: 'failed',
          appliedBy: { type: 'simple', identifier: 'admin' },
          appliedAt: '2026-01-01T00:00:00Z',
          expiresAt: '2027-01-01T00:00:00Z',
        },
        {
          type: 'poam',
          requirementId: 'AC-2',
          reason: 'test 2',
          status: 'failed',
          appliedBy: { type: 'simple', identifier: 'admin' },
          appliedAt: '2026-01-01T00:00:00Z',
          expiresAt: '2027-01-01T00:00:00Z',
        },
      ],
    };

    const output = await convertHdfToOscalPoam(JSON.stringify(amendments));
    const doc = JSON.parse(output);

    const uuids = new Set<string>();
    const poam = doc['plan-of-action-and-milestones'];
    uuids.add(poam.uuid);

    for (const item of poam['poam-items']) {
      expect(uuids.has(item.uuid)).toBe(false);
      uuids.add(item.uuid);
    }
    for (const risk of poam.risks) {
      expect(uuids.has(risk.uuid)).toBe(false);
      uuids.add(risk.uuid);
    }
  });
});

describe('hdfStatusToOSCAL', () => {
  it.each([
    ['passed', 'closed'],
    ['failed', 'open'],
    ['error', 'open'],
    ['notApplicable', 'closed'],
    ['notReviewed', 'open'],
  ])('should map %s to %s', (hdfStatus, oscalStatus) => {
    expect(hdfStatusToOSCAL(hdfStatus)).toBe(oscalStatus);
  });
});

describe('nistTagToControlID', () => {
  it.each([
    ['AC-1', 'ac-1'],
    ['AC-2 (3)', 'ac-2.3'],
    ['SI-7 (1)', 'si-7.1'],
    ['ac-1', 'ac-1'],
    ['unknown', 'unknown'],
  ])('should convert %s to %s', (input, expected) => {
    expect(nistTagToControlID(input)).toBe(expected);
  });
});

// Value-pinning for the exported fields. Mirrors converter_exportfields_test.go
// so Go and TS surface identical data.
describe('hdf-to-oscal-poam export fields', () => {
  const propVal = (props: Array<{ name: string; value: string }> | undefined, name: string) =>
    props?.find((p) => p.name === name)?.value;

  it('sources last-modified/version/remarks and is deterministic', async () => {
    const amendments = {
      name: 'det-test',
      version: '7',
      description: 'Imported advisory ADV-1',
      overrides: [{
        type: 'poam', requirementId: 'AC-1', reason: 'r', status: 'failed',
        appliedBy: { type: 'simple', identifier: 'admin' },
        appliedAt: '2022-03-03T11:00:00Z', expiresAt: '2099-12-31T00:00:00Z',
      }],
    };
    const meta1 = JSON.parse(await convertHdfToOscalPoam(JSON.stringify(amendments)))['plan-of-action-and-milestones'].metadata;
    expect(meta1['last-modified']).toBe('2022-03-03T11:00:00Z');
    expect(meta1.version).toBe('7');
    expect(meta1.remarks).toBe('Imported advisory ADV-1');
    const meta2 = JSON.parse(await convertHdfToOscalPoam(JSON.stringify(amendments)))['plan-of-action-and-milestones'].metadata;
    expect(meta1['last-modified']).toBe(meta2['last-modified']);
  });

  it('picks the newest override appliedAt for last-modified', async () => {
    const amendments = {
      name: 'multi-date',
      overrides: [
        { type: 'poam', requirementId: 'AC-1', reason: 'r1', status: 'failed', appliedBy: { type: 'simple', identifier: 'admin' }, appliedAt: '2022-01-01T00:00:00Z', expiresAt: '2099-12-31T00:00:00Z' },
        { type: 'poam', requirementId: 'AC-2', reason: 'r2', status: 'failed', appliedBy: { type: 'simple', identifier: 'admin' }, appliedAt: '2023-06-15T09:00:00Z', expiresAt: '2099-12-31T00:00:00Z' },
      ],
    };
    const meta = JSON.parse(await convertHdfToOscalPoam(JSON.stringify(amendments)))['plan-of-action-and-milestones'].metadata;
    expect(meta['last-modified']).toBe('2023-06-15T09:00:00Z');
  });

  it('maps cvss to a risk characterization with facets and an origin actor', async () => {
    const amendments = {
      name: 'cvss-test',
      overrides: [{
        type: 'riskAdjustment', requirementId: 'CVE-2021-44228', reason: 'adjusted', status: 'failed',
        appliedBy: { type: 'simple', identifier: 'analyst' },
        appliedAt: '2022-03-03T11:00:00Z', expiresAt: '2099-12-31T00:00:00Z',
        cvss: {
          version: '3.1', baseScore: 9.8, baseSeverity: 'critical',
          baseVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
        },
      }],
    };
    const poam = JSON.parse(await convertHdfToOscalPoam(JSON.stringify(amendments)))['plan-of-action-and-milestones'];
    const ch = poam.risks[0].characterizations[0];
    expect(ch.origin.actors[0].type).toBe('party');
    expect(ch.origin.actors[0]['actor-uuid']).toBe(poam.metadata.parties[0].uuid);
    const facet = (n: string) => ch.facets.find((f: { name: string; value: string }) => f.name === n)?.value;
    expect(facet('base_score')).toBe('9.8');
    expect(facet('base_severity')).toBe('critical');
    expect(facet('base_vector')).toBe('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H');
    for (const f of ch.facets) expect(f.system).toBe('http://www.first.org/cvss/v3.1');
  });

  it('maps evidence to observations linked from the poam-item', async () => {
    const amendments = {
      name: 'evidence-test',
      overrides: [{
        type: 'poam', requirementId: 'CVE-2021-44228', reason: 'r', status: 'failed',
        appliedBy: { type: 'simple', identifier: 'vendor' },
        appliedAt: '2022-03-03T11:00:00Z', expiresAt: '2099-12-31T00:00:00Z',
        evidence: [{ type: 'url', data: 'https://psirt.example.com/ADV-1', description: 'CSAF VEX advisory' }],
      }],
    };
    const poam = JSON.parse(await convertHdfToOscalPoam(JSON.stringify(amendments)))['plan-of-action-and-milestones'];
    expect(poam.observations).toHaveLength(1);
    const obs = poam.observations[0];
    expect(obs.description).toBe('CSAF VEX advisory');
    expect(obs.methods).toEqual(['EXAMINE']);
    expect(obs.collected).toBe('2022-03-03T11:00:00Z');
    expect(obs['relevant-evidence'][0].href).toBe('https://psirt.example.com/ADV-1');
    expect(poam['poam-items'][0]['related-observations'][0]['observation-uuid']).toBe(obs.uuid);
  });

  it('maps justification onto a risk prop', async () => {
    const amendments = {
      name: 'just-test',
      overrides: [{
        type: 'falsePositive', requirementId: 'CVE-2021-44228', reason: 'no java', status: 'passed',
        justification: 'component_not_present',
        appliedBy: { type: 'simple', identifier: 'vendor' },
        appliedAt: '2022-03-03T11:00:00Z', expiresAt: '2099-12-31T00:00:00Z',
      }],
    };
    const poam = JSON.parse(await convertHdfToOscalPoam(JSON.stringify(amendments)))['plan-of-action-and-milestones'];
    expect(propVal(poam.risks[0].props, 'justification')).toBe('component_not_present');
  });

  it('maps external references onto back-matter resources', async () => {
    const amendments = {
      name: 'ref-test',
      overrides: [{
        type: 'poam', requirementId: 'CVE-2021-44228', reason: 'r', status: 'failed',
        appliedBy: { type: 'simple', identifier: 'vendor' },
        appliedAt: '2022-03-03T11:00:00Z', expiresAt: '2099-12-31T00:00:00Z',
        externalReferences: [{ sourceName: 'cve', externalId: 'CVE-2021-44228', href: 'https://nvd.nist.gov/vuln/detail/CVE-2021-44228', description: 'NVD entry' }],
      }],
    };
    const poam = JSON.parse(await convertHdfToOscalPoam(JSON.stringify(amendments)))['plan-of-action-and-milestones'];
    const res = poam['back-matter'].resources[0];
    expect(res.title).toBe('cve');
    expect(res.description).toBe('NVD entry');
    expect(res.rlinks[0].href).toBe('https://nvd.nist.gov/vuln/detail/CVE-2021-44228');
    expect(propVal(res.props, 'external-id')).toBe('CVE-2021-44228');
  });

  it('maps approvedBy onto a distinct responsible-party role', async () => {
    const amendments = {
      name: 'approve-test',
      appliedBy: { type: 'simple', identifier: 'preparer' },
      approvedBy: { type: 'simple', identifier: 'official' },
      overrides: [{
        type: 'poam', requirementId: 'AC-1', reason: 'r', status: 'failed',
        appliedBy: { type: 'simple', identifier: 'preparer' },
        appliedAt: '2022-03-03T11:00:00Z', expiresAt: '2099-12-31T00:00:00Z',
      }],
    };
    const meta = JSON.parse(await convertHdfToOscalPoam(JSON.stringify(amendments)))['plan-of-action-and-milestones'].metadata;
    const approved = meta['responsible-parties'].find((rp: { 'role-id': string }) => rp['role-id'] === 'approved-by');
    expect(approved).toBeDefined();
    const party = meta.parties.find((p: { uuid: string }) => p.uuid === approved['party-uuids'][0]);
    expect(party.name).toBe('official');
    expect(meta.roles.some((r: { id: string }) => r.id === 'approved-by')).toBe(true);
  });

  it('carries minor props and milestone completion attribution', async () => {
    const amendments = {
      name: 'minor-test',
      amendmentId: 'AMD-42',
      labels: { zone: 'prod', env: 'gov', 'app.kubernetes.io/name': 'portal' },
      overrides: [{
        type: 'poam', requirementId: 'AC-1', reason: 'r', status: 'failed',
        baselineRef: 'nist-800-53r5', componentRef: 'comp-uuid-1',
        appliedBy: { type: 'simple', identifier: 'admin' },
        appliedAt: '2022-03-03T11:00:00Z', expiresAt: '2099-12-31T00:00:00Z',
        milestones: [{ description: 'patch', estimatedCompletion: '2099-06-30T00:00:00Z', status: 'completed', completedAt: '2023-01-01T00:00:00Z', completedBy: { type: 'simple', identifier: 'ops' } }],
      }],
    };
    const poam = JSON.parse(await convertHdfToOscalPoam(JSON.stringify(amendments)))['plan-of-action-and-milestones'];
    expect(propVal(poam.metadata.props, 'amendment-id')).toBe('AMD-42');
    // Labels are key/value pairs grouped in sorted key order, with keys kept verbatim.
    const labels = (poam.metadata.props as Array<{ name: string; value: string; class?: string; group?: string }>)
      .filter((p) => p.class === 'amendment-label')
      .map((p) => [p.name, p.value, p.group]);
    expect(labels).toEqual([
      ['label-key', 'app.kubernetes.io/name', 'label-1'],
      ['label-value', 'portal', 'label-1'],
      ['label-key', 'env', 'label-2'],
      ['label-value', 'gov', 'label-2'],
      ['label-key', 'zone', 'label-3'],
      ['label-value', 'prod', 'label-3'],
    ]);
    const risk = poam.risks[0];
    expect(propVal(risk.props, 'baseline-ref')).toBe('nist-800-53r5');
    expect(propVal(risk.props, 'component-ref')).toBe('comp-uuid-1');
    const task = risk.remediations[0].tasks[0];
    expect(propVal(task.props, 'completed-by'), 'completedBy rides on a responsible role, not a prop').toBeUndefined();
    expect(task['responsible-roles']).toHaveLength(1);
    expect(task['responsible-roles'][0]['role-id']).toBe('completed-by');
    const completer = poam.metadata.parties.find((p: { uuid: string }) => p.uuid === task['responsible-roles'][0]['party-uuids'][0]);
    expect(completer.name).toBe('ops');
    expect(poam.metadata.roles).toContainEqual({ id: 'completed-by', title: 'Completed By' });
    expect(propVal(task.props, 'completed-at')).toBe('2023-01-01T00:00:00Z');
  });

  // Mirrors the Go TestExport_MilestoneTitles.
  it('carries a milestone title exactly and marks an untitled milestone', async () => {
    const amendments = {
      name: 'titles',
      overrides: [{
        type: 'poam', requirementId: 'AC-1', reason: 'r',
        appliedBy: { type: 'simple', identifier: 'admin' },
        appliedAt: '2026-01-15T00:00:00Z', expiresAt: '2099-12-31T00:00:00Z',
        milestones: [
          { title: 'Deploy OpenSSH 9.8p1', description: 'Upgrade OpenSSH on every host.', estimatedCompletion: '2099-12-31T00:00:00Z', status: 'pending' },
          { description: 'Isolate the affected host\non a restricted VLAN.', estimatedCompletion: '2099-12-31T00:00:00Z', status: 'pending' },
        ],
      }],
    };
    type Titled = { title: string; props?: Array<{ name: string; value: string; ns?: string }> };
    const carried = (o: Titled) => ({
      title: o.title,
      marker: (o.props ?? []).some((p) => p.name === 'absent-field' && p.value === 'title' && p.ns === 'https://mitre.github.io/hdf-libs/ns/oscal'),
    });
    const rems = JSON.parse(await convertHdfToOscalPoam(JSON.stringify(amendments)))['plan-of-action-and-milestones'].risks[0].remediations;
    expect(rems).toHaveLength(2);
    [{ title: 'Deploy OpenSSH 9.8p1', marker: false }, { title: 'Milestone 2', marker: true }].forEach((want, i) => {
      expect(rems[i].tasks).toHaveLength(1);
      expect(carried(rems[i]), `remediation ${i + 1}`).toEqual(want);
      expect(carried(rems[i].tasks[0]), `task ${i + 1}`).toEqual(want);
    });
  });
});

// Whole-output equality with the SAME golden the Go TestGoldenParity asserts.
// Fresh UUIDs and the conversion timestamp are masked (see golden-mask.ts) —
// the UUID reference graph survives masking, so wiring differences still fail.
describe('hdf-to-oscal-poam golden parity', () => {
  it('matches the uc-01-fixed golden (TS↔Go parity)', async () => {
    const out = await convertHdfToOscalPoam(amendments.uc01Fixed.read());
    const golden = readFileSync(
      join(__dirname, '..', 'fixtures', 'expected', 'uc-01-fixed.oscal-poam.json'),
      'utf-8',
    );

    expect(maskVolatileJson(JSON.parse(out), POAM_VOLATILE_KEYS)).toEqual(
      maskVolatileJson(JSON.parse(golden), POAM_VOLATILE_KEYS),
    );
  });
});

// Mirrors the Go TestConvertHDFToOSCALPOAM_NISTRequirementIDImpactedControl.
describe('NIST requirement id impacted-control-id', () => {
  const schemas = ['oscal_poam_schema-v1.1.2.json', 'oscal_poam_schema-v1.2.3.json'].map(
    (file) => [file, loadSchemaValidator(join(__dirname, '..', 'schemas', file))] as const,
  );

  it.each([
    ['AC-2 (3)', 'ac-2.3'],
    ['ac-2 (3)', 'ac-2.3'],
    ['Ac-2(3)', 'ac-2.3'],
    ['AC-02 03', 'ac-2.3'],
    ['AC-8 c 1', 'ac-8'],
    ['AC-2 (3) (a)', 'ac-2.3'],
    ['Si-2', 'si-2'],
    ['AC-99', ''],
    ['SV-257778', ''],
    ['CVE-2021-44228', ''],
  ])('maps %s to %j', async (requirementId, want) => {
    const input = JSON.stringify({
      name: 'test-poam',
      overrides: [{
        type: 'poam',
        requirementId,
        reason: 'Pending remediation',
        status: 'failed',
        appliedBy: { type: 'simple', identifier: 'admin@example.com' },
        appliedAt: '2026-01-15T00:00:00Z',
        expiresAt: '2099-12-31T00:00:00Z',
      }],
    });
    const doc = JSON.parse(await convertHdfToOscalPoam(input));
    const risks = doc['plan-of-action-and-milestones'].risks;
    expect(risks).toHaveLength(1);
    const props = (risks[0].props as Array<{ name: string; value: string; ns?: string }>).filter((p) => p.name === 'impacted-control-id');
    for (const p of props) expect(p.ns).toBe('https://fedramp.gov/ns/oscal');
    expect(props.map((p) => p.value)).toEqual(want === '' ? [] : [want]);
    for (const [file, validate] of schemas) {
      assertSchemaValid(validate, file, doc);
    }
  });
});

interface RoundTripCases {
  excluded: { document: string[]; override: string[] };
  cases: Array<{ name: string; amendments: Record<string, unknown> }>;
}

const ROUND_TRIP = JSON.parse(
  readFileSync(join(__dirname, '..', '..', '..', 'shared', 'oscal-poam-roundtrip-cases.json'), 'utf-8'),
) as RoundTripCases;

/** An amendments document without the fields the round-trip contract excludes. */
function withoutExcluded(doc: Record<string, unknown>): Record<string, unknown> {
  const copy = JSON.parse(JSON.stringify(doc)) as Record<string, unknown>;
  for (const k of ROUND_TRIP.excluded.document) delete copy[k];
  for (const o of (copy.overrides ?? []) as Array<Record<string, unknown>>) {
    for (const k of ROUND_TRIP.excluded.override) delete o[k];
  }
  return copy;
}

/** Compares two JSON objects key by key, so a failure names the field. */
function expectSameFields(path: string, want: Record<string, unknown>, got: Record<string, unknown>): void {
  for (const k of new Set([...Object.keys(want), ...Object.keys(got)])) {
    expect.soft(Object.hasOwn(got, k), `${path}.${k}: present in only one of source and result`).toBe(Object.hasOwn(want, k));
    expect.soft(got[k], `${path}.${k}`).toStrictEqual(want[k]);
  }
}

type SchemaNode = { properties?: Record<string, SchemaNode>; items?: SchemaNode; $ref?: string; $defs?: Record<string, SchemaNode> };

/** The $defs of the source schemas an amendments document draws on, with the document itself under ''. */
function hdfSchemaDefs(): Map<string, SchemaNode> {
  const dir = join(__dirname, '..', '..', '..', '..', 'hdf-schema', 'src', 'schemas');
  const defs = new Map<string, SchemaNode>();
  for (const f of ['hdf-amendments.schema.json', 'primitives/amendments.schema.json', 'primitives/common.schema.json', 'primitives/affected-package.schema.json', 'primitives/cvss.schema.json']) {
    const schema = JSON.parse(readFileSync(join(dir, f), 'utf-8')) as SchemaNode;
    if (f === 'hdf-amendments.schema.json') defs.set('', schema);
    for (const [name, def] of Object.entries(schema.$defs ?? {})) defs.set(name, def);
  }
  return defs;
}

/** Whether a dot-separated JSON property path names a property of the def, following $ref and array items by def name. */
function schemaHasProperty(defs: Map<string, SchemaNode>, def: string, path: string): boolean {
  let node = defs.get(def);
  for (const name of path.split('.')) {
    let next = node?.properties?.[name];
    if (!next) return false;
    if (next.items) next = next.items;
    if (next.$ref) next = defs.get(next.$ref.slice(next.$ref.lastIndexOf('/') + 1));
    node = next;
  }
  return true;
}

/** Maps the OSCAL object carrying a field marker, and the marker's group, to the HDF def whose fields it names. Mirrors Go's markerContexts. */
const MARKER_CONTEXTS: Array<[RegExp, RegExp, string]> = [
  [/^metadata$/, /^$/, ''],
  [/^metadata$/, /^label-[1-9][0-9]*$/, 'label'],
  [/^metadata\.parties\[\d+\]$/, /^$/, 'Identity'],
  [/^risks\[\d+\]$/, /^$/, 'Standalone_Override'],
  [/^risks\[\d+\]$/, /^package-[1-9][0-9]*$/, 'Affected_Package'],
  [/^risks\[\d+\]\.characterizations\[\d+\]$/, /^$/, 'Cvss'],
  [/^risks\[\d+\]\.remediations\[\d+\](\.tasks\[\d+\])?$/, /^$/, 'Milestone'],
  [/^observations\[\d+\]$/, /^$/, 'Evidence'],
  [/^back-matter\.resources\[\d+\]$/, /^$/, 'External_Reference'],
];

/** Every empty-field and absent-field marker in a decoded POA&M, with the object that carries it. */
function collectFieldMarkers(node: unknown, path: string, out: Array<{ path: string; group: string; field: string }>): void {
  if (Array.isArray(node)) {
    node.forEach((child, i) => collectFieldMarkers(child, `${path}[${i}]`, out));
  } else if (node !== null && typeof node === 'object') {
    for (const [k, child] of Object.entries(node)) {
      if (k !== 'props') {
        collectFieldMarkers(child, path === '' ? k : `${path}.${k}`, out);
        continue;
      }
      for (const p of child as Array<{ name: string; value: string; ns?: string; group?: string }>) {
        if ((p.name === 'empty-field' || p.name === 'absent-field') && p.ns === 'https://mitre.github.io/hdf-libs/ns/oscal') {
          out.push({ path, group: p.group ?? '', field: p.value });
        }
      }
    }
  }
}

// Mirrors the Go TestConvertHDFToOSCALPOAM_FieldMarkersNameHDFProperties: every
// empty-field and absent-field value is an HDF JSON property name, dot-separated
// relative to the object carrying the marker, or the field within its prop group
// (ADR-0014 §1.7.5).
describe('hdf-to-oscal-poam field marker names (ADR-0014 §1.7.5)', () => {
  it('name HDF properties in every round-trip case', async () => {
    const defs = hdfSchemaDefs();
    const seen = new Set<string>();
    for (const c of ROUND_TRIP.cases) {
      const doc = JSON.parse(await convertHdfToOscalPoam(JSON.stringify(c.amendments)));
      const markers: Array<{ path: string; group: string; field: string }> = [];
      collectFieldMarkers(doc['plan-of-action-and-milestones'], '', markers);
      for (const m of markers) {
        const contexts = MARKER_CONTEXTS.filter(([path, group]) => path.test(m.path) && group.test(m.group));
        expect.soft(contexts, `${c.name}: a marker at ${m.path} (group ${m.group}) has no HDF context`).not.toHaveLength(0);
        for (const [, , def] of contexts) {
          seen.add(def);
          const named = def === 'label' ? ['key', 'value'].includes(m.field) : schemaHasProperty(defs, def, m.field);
          expect.soft(named, `${c.name}: ${m.field} at ${m.path} is not a ${def || 'document'} property`).toBe(true);
        }
      }
    }
    expect([...seen].sort()).toEqual(['', 'Affected_Package', 'Evidence', 'External_Reference', 'Identity', 'Milestone', 'Standalone_Override', 'label']);
  });
});

// Mirrors the Go TestConvertHDFToOSCALPOAM_RoundTrip over the same shared case
// table: HDF amendments -> OSCAL POA&M -> HDF returns every ADR-0014 §4.6 field
// exactly, and the contract's exclusions are the only differences.
describe('hdf-to-oscal-poam round trip (ADR-0014 §4.6)', () => {
  const validateHdf = loadSchemaValidator(
    join(__dirname, '..', '..', '..', '..', 'hdf-validators', 'go', 'schemas', 'hdf-amendments.schema.json'),
  );
  const schemas = ['oscal_poam_schema-v1.1.2.json', 'oscal_poam_schema-v1.2.3.json'].map(
    (file) => [file, loadSchemaValidator(join(__dirname, '..', 'schemas', file))] as const,
  );

  it('the first case is the Standalone_Override schema examples', () => {
    const schema = JSON.parse(
      readFileSync(join(__dirname, '..', '..', '..', '..', 'hdf-schema', 'src', 'schemas', 'primitives', 'amendments.schema.json'), 'utf-8'),
    ) as { $defs: { Standalone_Override: { examples: unknown[] } } };
    expect(schema.$defs.Standalone_Override.examples).toHaveLength(7);
    expect(ROUND_TRIP.cases[0]!.amendments.overrides).toStrictEqual(schema.$defs.Standalone_Override.examples);
  });

  it.each(ROUND_TRIP.cases.map((c) => [c.name, c] as const))('%s', async (_name, c) => {
    assertSchemaValid(validateHdf, 'the case', c.amendments);
    const poam = await convertHdfToOscalPoam(JSON.stringify(c.amendments));
    for (const [file, validate] of schemas) {
      assertSchemaValid(validate, file, JSON.parse(poam));
    }
    const back = JSON.parse(await convertOscalPoamToHdf(poam)) as Record<string, unknown>;

    const want = withoutExcluded(c.amendments);
    const got = withoutExcluded(back);
    const wantOverrides = want.overrides as Array<Record<string, unknown>>;
    const gotOverrides = got.overrides as Array<Record<string, unknown>>;
    delete want.overrides;
    delete got.overrides;
    expectSameFields('document', want, got);
    expect(gotOverrides).toHaveLength(wantOverrides.length);
    wantOverrides.forEach((o, i) => expectSameFields(`overrides[${i}]`, o, gotOverrides[i]!));
  });
});
