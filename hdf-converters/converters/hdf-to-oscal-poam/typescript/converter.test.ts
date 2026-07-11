import { describe, it, expect } from 'vitest';
import { convertHdfToOscalPoam } from './converter.js';
import { hdfStatusToOscalRiskStatus as hdfStatusToOSCAL, nistTagToControlId as nistTagToControlID } from '../../oscal-to-hdf/typescript/shared.js';

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
    expect(remProp('estimated-completion')).toContain('2099-06-30');
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
    expect(meta.parties).toHaveLength(1);
    expect(meta.parties[0].name).toBe('security-team@example.com');
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
    expect(risk['risk-log'].entries[0].start).toBe('2027-03-15T12:00:00.000Z');
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
