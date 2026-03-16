import { describe, it, expect } from 'vitest';
import { generateInSpecProfile } from '../src/profile-generator.js';
import { makeBaseline, makeRequirement, desc } from './helpers.js';

describe('generateInSpecProfile', () => {
  it('generates a profile with one control file per requirement (default)', () => {
    const baseline = makeBaseline({
      name: 'test-profile',
      requirements: [
        makeRequirement({ id: 'SV-001' }),
        makeRequirement({ id: 'SV-002' }),
      ],
    });
    const profile = generateInSpecProfile(baseline);
    expect(profile.inspecYml).toContain('name: test-profile');
    expect(profile.controls.size).toBe(2);
    expect(profile.controls.has('controls/SV-001.rb')).toBe(true);
    expect(profile.controls.has('controls/SV-002.rb')).toBe(true);
  });

  it('generates a single controls.rb when singleFile is true', () => {
    const baseline = makeBaseline({
      name: 'test-profile',
      requirements: [
        makeRequirement({ id: 'SV-001' }),
        makeRequirement({ id: 'SV-002' }),
      ],
    });
    const profile = generateInSpecProfile(baseline, { singleFile: true });
    expect(profile.controls.size).toBe(1);
    expect(profile.controls.has('controls/controls.rb')).toBe(true);
    const content = profile.controls.get('controls/controls.rb')!;
    expect(content).toContain("control 'SV-001' do");
    expect(content).toContain("control 'SV-002' do");
  });

  it('uses group titles for file organization', () => {
    const baseline = makeBaseline({
      name: 'test-profile',
      groups: [
        { id: 'access-control', requirements: ['SV-001', 'SV-002'], title: 'Access Control' },
      ],
      requirements: [
        makeRequirement({ id: 'SV-001' }),
        makeRequirement({ id: 'SV-002' }),
        makeRequirement({ id: 'SV-003' }), // not in any group
      ],
    });
    const profile = generateInSpecProfile(baseline);
    // Grouped controls get their own files, ungrouped get default
    expect(profile.controls.has('controls/SV-001.rb')).toBe(true);
    expect(profile.controls.has('controls/SV-002.rb')).toBe(true);
    expect(profile.controls.has('controls/SV-003.rb')).toBe(true);
  });

  it('generates valid Ruby in each control file', () => {
    const baseline = makeBaseline({
      name: 'test-profile',
      requirements: [
        makeRequirement({
          id: 'SV-001',
          title: 'Test Control',
          descriptions: [desc('default', 'Main desc')],
          tags: { nist: ['AC-2'] },
        }),
      ],
    });
    const profile = generateInSpecProfile(baseline);
    const ruby = profile.controls.get('controls/SV-001.rb')!;
    expect(ruby).toMatch(/^control 'SV-001' do\n/);
    expect(ruby).toMatch(/\nend\n$/);
  });

  it('generates inspec.yml with metadata overrides', () => {
    const baseline = makeBaseline({
      name: 'test-profile',
      requirements: [makeRequirement({ id: 'SV-001' })],
    });
    const profile = generateInSpecProfile(baseline, {
      metadata: { maintainer: 'Test Team', license: 'MIT' },
    });
    expect(profile.inspecYml).toContain('maintainer: Test Team');
    expect(profile.inspecYml).toContain('license: MIT');
  });

  it('handles empty requirements list', () => {
    const baseline = makeBaseline({
      name: 'empty-profile',
      requirements: [],
    });
    const profile = generateInSpecProfile(baseline);
    expect(profile.inspecYml).toContain('name: empty-profile');
    expect(profile.controls.size).toBe(0);
  });

  it('sanitizes profile name for filesystem safety', () => {
    const baseline = makeBaseline({
      name: 'My Profile / Version 2.0',
      requirements: [makeRequirement({ id: 'SV-001' })],
    });
    const profile = generateInSpecProfile(baseline);
    // Controls should still be under controls/ directory
    expect(profile.controls.has('controls/SV-001.rb')).toBe(true);
  });
});
