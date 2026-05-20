import { describe, it, expect } from 'vitest';
import { generateDelta, generateUpgrade } from '../src/delta.js';
import type { LinkRecord, DeltaOptions } from '../src/delta-types.js';
import { makeBaseline, makeRequirement } from './helpers.js';

describe('generateDelta', () => {
  it('should preserve old code for matched requirements', () => {
    const newBaseline = makeBaseline({
      name: 'test-profile',
      requirements: [
        makeRequirement({
          id: 'SV-001',
          title: 'Updated title',
          impact: 0.7,
        }),
      ],
    });

    const linkRecords: LinkRecord[] = [
      {
        oldId: 'V-001',
        newId: 'SV-001',
        matchMethod: 'srgDeterministic',
        confidence: 1.0,
        relationship: 'primary',
        potentialMismatch: false,
      },
    ];

    const oldCodeMap = new Map([['V-001', "  describe command('audit') do\n    its('stdout') { should match /enabled/ }\n  end"]]);

    const result = generateDelta(newBaseline, linkRecords, oldCodeMap, undefined, 1);

    expect(result.profile.controls.size).toBe(1);
    const control = result.profile.controls.get('controls/SV-001.rb')!;
    expect(control).toContain("control 'SV-001' do");
    expect(control).toContain('Updated title');
    expect(control).toContain("describe command('audit')");
    expect(control).not.toContain('TODO');
  });

  it('should generate stubs for unmatched requirements', () => {
    const newBaseline = makeBaseline({
      name: 'test-profile',
      requirements: [
        makeRequirement({ id: 'SV-002', title: 'New control' }),
      ],
    });

    const linkRecords: LinkRecord[] = [
      {
        oldId: null,
        newId: 'SV-002',
        matchMethod: 'none',
        confidence: 0,
        relationship: 'no-match',
        potentialMismatch: false,
      },
    ];

    const result = generateDelta(newBaseline, linkRecords, new Map(), undefined, 0);

    const control = result.profile.controls.get('controls/SV-002.rb')!;
    expect(control).toContain('TODO');
    expect(control).not.toContain("describe command");
  });

  it('should use old code for related matches', () => {
    const newBaseline = makeBaseline({
      name: 'test-profile',
      requirements: [
        makeRequirement({ id: 'SV-001', title: 'Primary control' }),
        makeRequirement({ id: 'SV-002', title: 'Related control' }),
      ],
    });

    const linkRecords: LinkRecord[] = [
      {
        oldId: 'V-001',
        newId: 'SV-001',
        matchMethod: 'srgDeterministic',
        confidence: 1.0,
        relationship: 'primary',
        potentialMismatch: false,
      },
      {
        oldId: 'V-001',
        newId: 'SV-002',
        matchMethod: 'srgDeterministic',
        confidence: 1.0,
        relationship: 'related',
        potentialMismatch: false,
      },
    ];

    const oldCodeMap = new Map([['V-001', '  describe service("sshd") do\n    it { should be_running }\n  end']]);

    const result = generateDelta(newBaseline, linkRecords, oldCodeMap, undefined, 1);

    expect(result.profile.controls.size).toBe(2);
    const c1 = result.profile.controls.get('controls/SV-001.rb')!;
    const c2 = result.profile.controls.get('controls/SV-002.rb')!;
    expect(c1).toContain('describe service("sshd")');
    expect(c2).toContain('describe service("sshd")');
  });

  it('should compute SAF CLI-compatible statistics', () => {
    const newBaseline = makeBaseline({
      name: 'test-profile',
      requirements: [
        makeRequirement({ id: 'SV-001' }),
        makeRequirement({ id: 'SV-002' }),
        makeRequirement({ id: 'SV-003' }),
      ],
    });

    const linkRecords: LinkRecord[] = [
      {
        oldId: 'V-001', newId: 'SV-001', matchMethod: 'srgDeterministic',
        confidence: 1.0, relationship: 'primary', potentialMismatch: false,
      },
      {
        oldId: 'V-001', newId: 'SV-002', matchMethod: 'srgDeterministic',
        confidence: 1.0, relationship: 'related', potentialMismatch: false,
      },
      {
        oldId: null, newId: 'SV-003', matchMethod: 'none',
        confidence: 0, relationship: 'no-match', potentialMismatch: false,
      },
    ];

    const result = generateDelta(newBaseline, linkRecords, new Map([['V-001', '  # code']]), undefined, 2);

    expect(result.statistics.newControlsLength).toBe(3);
    expect(result.statistics.oldControlsLength).toBe(2);
    expect(result.statistics.match).toBe(1);
    expect(result.statistics.dupMatch).toBe(1);
    expect(result.statistics.noMatch).toBe(1);
    expect(result.statistics.posMisMatch).toBe(0);
    expect(result.statistics.totalMappedControls).toBe(2);
    // Invariant: totalMapped + noMatch = newControlsLength
    expect(result.statistics.totalMappedControls + result.statistics.noMatch)
      .toBe(result.statistics.newControlsLength);
  });

  it('should handle empty match result', () => {
    const newBaseline = makeBaseline({
      name: 'test-profile',
      requirements: [
        makeRequirement({ id: 'SV-001' }),
        makeRequirement({ id: 'SV-002' }),
      ],
    });

    const result = generateDelta(newBaseline, [], new Map(), undefined, 0);

    expect(result.profile.controls.size).toBe(2);
    expect(result.statistics.newControlsLength).toBe(2);
    expect(result.statistics.match).toBe(0);
  });

  it('should respect noCode option', () => {
    const newBaseline = makeBaseline({
      name: 'test-profile',
      requirements: [makeRequirement({ id: 'SV-001' })],
    });

    const linkRecords: LinkRecord[] = [
      {
        oldId: 'V-001', newId: 'SV-001', matchMethod: 'exactId',
        confidence: 1.0, relationship: 'primary', potentialMismatch: false,
      },
    ];
    const oldCodeMap = new Map([['V-001', '  describe command("test") do\n  end']]);

    const opts: DeltaOptions = { noCode: true };
    const result = generateDelta(newBaseline, linkRecords, oldCodeMap, opts, 1);

    const control = result.profile.controls.get('controls/SV-001.rb')!;
    expect(control).toContain('TODO');
    expect(control).not.toContain('describe command');
  });

  it('should generate valid inspec.yml from new baseline', () => {
    const newBaseline = makeBaseline({
      name: 'updated-stig',
      requirements: [makeRequirement({ id: 'SV-001' })],
      title: 'Updated STIG Profile',
    });

    const result = generateDelta(newBaseline, [], new Map(), undefined, 0);

    expect(result.profile.inspecYml).toContain('name: updated-stig');
    expect(result.profile.inspecYml).toContain('title: Updated STIG Profile');
  });

  it('drops unmatched-current requirements by default (matches SAF semantics)', () => {
    const current = makeBaseline({
      name: 'current',
      requirements: [
        makeRequirement({ id: 'SV-001' }),
        makeRequirement({ id: 'SV-099' }),
      ],
    });
    const upstream = makeBaseline({
      name: 'upstream',
      requirements: [makeRequirement({ id: 'SV-001' })],
    });
    const links: LinkRecord[] = [
      { oldId: 'SV-001', newId: 'SV-001', matchMethod: 'srgDeterministic',
        confidence: 1.0, relationship: 'primary', potentialMismatch: false },
    ];

    const result = generateUpgrade(current, upstream, links, {});

    const ids = result.baseline.requirements.map((r) => r.id);
    expect(ids).toContain('SV-001');
    expect(ids).not.toContain('SV-099');
  });

  it('preserves unmatched-current when keepUnmatched is true', () => {
    const current = makeBaseline({
      name: 'current',
      requirements: [
        makeRequirement({ id: 'SV-001' }),
        makeRequirement({ id: 'SV-099' }),
      ],
    });
    const upstream = makeBaseline({
      name: 'upstream',
      requirements: [makeRequirement({ id: 'SV-001' })],
    });
    const links: LinkRecord[] = [
      { oldId: 'SV-001', newId: 'SV-001', matchMethod: 'srgDeterministic',
        confidence: 1.0, relationship: 'primary', potentialMismatch: false },
    ];

    const result = generateUpgrade(current, upstream, links, { keepUnmatched: true });

    const ids = result.baseline.requirements.map((r) => r.id);
    expect(ids).toContain('SV-001');
    expect(ids).toContain('SV-099');
  });

  it('counts links with potentialMismatch into posMisMatch (not match)', () => {
    const current = makeBaseline({
      name: 'current',
      requirements: [makeRequirement({ id: 'SV-001' })],
    });
    const upstream = makeBaseline({
      name: 'upstream',
      requirements: [makeRequirement({ id: 'SV-001' })],
    });
    const links: LinkRecord[] = [
      { oldId: 'SV-001', newId: 'SV-001', matchMethod: 'srgCciTiebreak',
        confidence: 0.55, relationship: 'primary', potentialMismatch: true },
    ];

    const result = generateUpgrade(current, upstream, links, {});

    expect(result.statistics.posMisMatch).toBe(1);
    expect(result.statistics.match).toBe(0);
  });

  it('should handle singleFile option', () => {
    const newBaseline = makeBaseline({
      name: 'test-profile',
      requirements: [
        makeRequirement({ id: 'SV-001' }),
        makeRequirement({ id: 'SV-002' }),
      ],
    });

    const result = generateDelta(newBaseline, [], new Map(), { singleFile: true }, 0);

    expect(result.profile.controls.size).toBe(1);
    expect(result.profile.controls.has('controls/controls.rb')).toBe(true);
    const content = result.profile.controls.get('controls/controls.rb')!;
    expect(content).toContain("control 'SV-001'");
    expect(content).toContain("control 'SV-002'");
  });
});
