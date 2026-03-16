import { readFileSync } from 'fs';
import { resolve, dirname } from 'path';
import { fileURLToPath } from 'url';
import { describe, it, expect } from 'vitest';
import type { HdfBaseline } from '@mitre/hdf-schema';
import { generateInSpecProfile } from '../src/profile-generator.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const fixturePath = resolve(__dirname, 'fixtures', 'win2022-stig-baseline.json');

function loadFixture(): HdfBaseline {
  return JSON.parse(readFileSync(fixturePath, 'utf-8')) as HdfBaseline;
}

describe('integration: Windows Server 2022 STIG baseline', () => {
  const baseline = loadFixture();

  it('loads fixture with expected metadata', () => {
    expect(baseline.name).toBe('microsoft-windows-server-2022-stig-baseline');
    expect(baseline.title).toBe(
      'Microsoft Windows Server 2022 Security Technical Implementation Guide',
    );
    expect(baseline.requirements.length).toBe(18);
  });

  it('generates a control file for every requirement', () => {
    const profile = generateInSpecProfile(baseline);
    expect(profile.controls.size).toBe(18);
    for (const req of baseline.requirements) {
      expect(profile.controls.has(`controls/${req.id}.rb`)).toBe(true);
    }
  });

  it('generates valid Ruby control blocks', () => {
    const profile = generateInSpecProfile(baseline);
    for (const [filename, ruby] of profile.controls) {
      const id = filename.replace('controls/', '').replace('.rb', '');
      expect(ruby).toMatch(new RegExp(`^control '${id}' do\\n`));
      expect(ruby).toMatch(/\nend\n$/);
    }
  });

  it('preserves STIG metadata in control tags', () => {
    const profile = generateInSpecProfile(baseline);
    // SV-254238 has CCI, NIST, severity tags
    const sv238 = profile.controls.get('controls/SV-254238.rb')!;
    expect(sv238).toContain("tag cci: ['CCI-000366']");
    expect(sv238).toContain("tag nist: ['CM-6 b']");
    expect(sv238).toContain("tag severity: 'medium'");
    expect(sv238).toContain("tag stig_id: 'WN22-00-000010'");
  });

  it('handles controls with multiple CCIs and NIST tags', () => {
    const profile = generateInSpecProfile(baseline);
    // SV-254240 has multiple CCIs and NIST mappings
    const sv240 = profile.controls.get('controls/SV-254240.rb')!;
    expect(sv240).toContain("'CCI-000366'");
    expect(sv240).toContain("'CCI-001312'");
    expect(sv240).toContain("'CM-6 b'");
    expect(sv240).toContain("'SI-11 a'");
  });

  it('includes check and fix descriptions', () => {
    const profile = generateInSpecProfile(baseline);
    const sv238 = profile.controls.get('controls/SV-254238.rb')!;
    expect(sv238).toContain("desc 'check'");
    expect(sv238).toContain("desc 'fix'");
  });

  it('generates inspec.yml with real STIG metadata', () => {
    const profile = generateInSpecProfile(baseline);
    expect(profile.inspecYml).toContain(
      'name: microsoft-windows-server-2022-stig-baseline',
    );
    expect(profile.inspecYml).toContain(
      'title: Microsoft Windows Server 2022 Security Technical Implementation Guide',
    );
    expect(profile.inspecYml).toContain("version: '2.7.0'");
    expect(profile.inspecYml).toContain('maintainer: MITRE SAF Team');
    expect(profile.inspecYml).toContain('license: Apache-2.0');
  });

  it('generates single-file mode with all controls', () => {
    const profile = generateInSpecProfile(baseline, { singleFile: true });
    expect(profile.controls.size).toBe(1);
    const content = profile.controls.get('controls/controls.rb')!;
    for (const req of baseline.requirements) {
      expect(content).toContain(`control '${req.id}' do`);
    }
  });

  it('applies metadata overrides to real baseline', () => {
    const profile = generateInSpecProfile(baseline, {
      metadata: {
        maintainer: 'Custom Team',
        version: '99.0.0',
      },
    });
    expect(profile.inspecYml).toContain('maintainer: Custom Team');
    expect(profile.inspecYml).toContain("version: '99.0.0'");
    // Original values should be overridden
    expect(profile.inspecYml).not.toContain('maintainer: MITRE SAF Team');
    expect(profile.inspecYml).not.toContain("version: '2.7.0'");
  });

  it('handles high-impact controls correctly', () => {
    const profile = generateInSpecProfile(baseline);
    // SV-254240 has impact 0.7 (high)
    const sv240 = profile.controls.get('controls/SV-254240.rb')!;
    expect(sv240).toContain('impact 0.7');
    expect(sv240).toContain("tag severity: 'high'");
  });

  it('preserves multi-line descriptions', () => {
    const profile = generateInSpecProfile(baseline);
    // SV-254240 has a long multi-paragraph description
    const sv240 = profile.controls.get('controls/SV-254240.rb')!;
    expect(sv240).toContain('web browser');
    expect(sv240).toContain('administrative account');
  });
});
