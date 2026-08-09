import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, it, expect } from 'vitest';
import { amendments } from '@mitre/hdf-fixtures';
import { convertHdfToOscalPoam } from './converter.js';
import { hdfStatusToOscalRiskStatus as hdfStatusToOSCAL, nistTagToControlId as nistTagToControlID } from '../../oscal-to-hdf/typescript/shared.js';
import { maskVolatileJson } from '../../../shared/typescript/golden-mask.js';

const __dirname = dirname(fileURLToPath(import.meta.url));

// Only the metadata timestamp carries the conversion moment; every other date
// in a POA&M (milestone deadlines, expiration) is input-derived and stays asserted.
const POAM_VOLATILE_KEYS = ['last-modified'];

describe('convertHdfToOscalPoam', () => {
  it('should reject empty input', async () => {
    await expect(convertHdfToOscalPoam('')).rejects.toThrow('empty input');
  });

  it('should reject invalid JSON', async () => {
    await expect(convertHdfToOscalPoam('{not json')).rejects.toThrow('failed to parse JSON');
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

    // Verify risk props contain impacted-control-id in OSCAL format (first prop)
    expect(poam.risks[0].props[0].name).toBe('impacted-control-id');
    expect(poam.risks[0].props[0].value).toBe('ac-1');

    expect(poam.risks[1].props[0].name).toBe('impacted-control-id');
    expect(poam.risks[1].props[0].value).toBe('si-7.1');
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
    expect(riskProp('impact-override')).toBe('0.3');
    const rem = risk.remediations[0];
    const remProp = (n: string): string | undefined =>
      rem.props.find((p: { name: string; value: string }) => p.name === n)?.value;
    // The estimated completion rides on the remediation task's within-date-range end.
    expect(rem.tasks[0].timing['within-date-range'].end).toContain('2099-06-30');
    expect(remProp('milestone-status')).toBe('pending');
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
              description: 'Deploy MFA solution',
              estimatedCompletion: '2026-06-01T00:00:00Z',
              status: 'pending',
            },
            {
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
    expect(risk.remediations[0].title).toBe('Deploy MFA solution');
    expect(risk.remediations[1].title).toBe('Verify MFA deployment');
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
    expect(risk['risk-log'].entries).toHaveLength(1);
    // Whole-second RFC3339, byte-identical to the Go converter's output.
    expect(risk['risk-log'].entries[0].start).toBe('2027-03-15T12:00:00Z');
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
      labels: { zone: 'prod', env: 'gov' },
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
    expect(propVal(poam.metadata.props, 'env')).toBe('gov');
    const risk = poam.risks[0];
    expect(propVal(risk.props, 'baseline-ref')).toBe('nist-800-53r5');
    expect(propVal(risk.props, 'component-ref')).toBe('comp-uuid-1');
    const task = risk.remediations[0].tasks[0];
    expect(propVal(task.props, 'completed-by')).toBe('ops');
    expect(propVal(task.props, 'completed-at')).toBe('2023-01-01T00:00:00Z');
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
