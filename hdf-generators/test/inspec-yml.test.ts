import { describe, it, expect } from 'vitest';
import { generateInSpecYml } from '../src/inspec-yml.js';
import { makeBaseline, makeRequirement } from './helpers.js';

describe('generateInSpecYml', () => {
  const minimalBaseline = makeBaseline({
    name: 'my-profile',
    requirements: [makeRequirement({ id: 'SV-001' })],
  });

  it('generates valid YAML with profile name', () => {
    const yml = generateInSpecYml(minimalBaseline);
    expect(yml).toContain('name: my-profile');
  });

  it('includes default inspec_version constraint', () => {
    const yml = generateInSpecYml(minimalBaseline);
    expect(yml).toContain("inspec_version: '>= 7.0'");
  });

  it('allows overriding inspec_version', () => {
    const yml = generateInSpecYml(minimalBaseline, { inspecVersion: '~>5.0' });
    expect(yml).toContain("inspec_version: '~>5.0'");
  });

  it('includes title when present', () => {
    const baseline = makeBaseline({
      name: 'my-profile',
      title: 'My Security Profile',
      requirements: [makeRequirement({ id: 'SV-001' })],
    });
    const yml = generateInSpecYml(baseline);
    expect(yml).toContain('title: My Security Profile');
  });

  it('includes summary when present', () => {
    const baseline = makeBaseline({
      name: 'my-profile',
      summary: 'A test profile for security checks',
      requirements: [makeRequirement({ id: 'SV-001' })],
    });
    const yml = generateInSpecYml(baseline);
    expect(yml).toContain('summary: A test profile for security checks');
  });

  it('includes version when present', () => {
    const baseline = makeBaseline({
      name: 'my-profile',
      version: '1.2.3',
      requirements: [makeRequirement({ id: 'SV-001' })],
    });
    const yml = generateInSpecYml(baseline);
    expect(yml).toContain("version: '1.2.3'");
  });

  it('includes maintainer from options metadata', () => {
    const yml = generateInSpecYml(minimalBaseline, {
      metadata: { maintainer: 'MITRE SAF Team' },
    });
    expect(yml).toContain('maintainer: MITRE SAF Team');
  });

  it('includes copyright from options metadata', () => {
    const yml = generateInSpecYml(minimalBaseline, {
      metadata: { copyright: 'MITRE Corporation' },
    });
    expect(yml).toContain('copyright: MITRE Corporation');
  });

  it('includes license from options metadata', () => {
    const yml = generateInSpecYml(minimalBaseline, {
      metadata: { license: 'Apache-2.0' },
    });
    expect(yml).toContain('license: Apache-2.0');
  });

  it('metadata version overrides baseline version', () => {
    const baseline = makeBaseline({
      name: 'my-profile',
      version: '1.0.0',
      requirements: [makeRequirement({ id: 'SV-001' })],
    });
    const yml = generateInSpecYml(baseline, {
      metadata: { version: '2.0.0' },
    });
    expect(yml).toContain("version: '2.0.0'");
    expect(yml).not.toContain("version: '1.0.0'");
  });

  it('version uses the benchmark release as <version>.<release>.0', () => {
    const baseline = makeBaseline({
      name: 'my-profile',
      version: '2',
      extensions: { passthrough: { benchmarkRelease: '9' } },
      requirements: [makeRequirement({ id: 'SV-001' })],
    });
    const yml = generateInSpecYml(baseline);
    expect(yml).toContain("version: '2.9.0'");
    expect(yml).not.toContain("version: '2'\n");
  });

  it('version stays plain when no benchmark release is carried', () => {
    const baseline = makeBaseline({
      name: 'my-profile',
      version: '2',
      extensions: { passthrough: { releaseInfo: 'Release: 9 Benchmark Date: 01 Jul 2026' } },
      requirements: [makeRequirement({ id: 'SV-001' })],
    });
    const yml = generateInSpecYml(baseline);
    expect(yml).toContain("version: '2'\n");
  });

  it('non-integer release leaves the version plain', () => {
    const baseline = makeBaseline({
      name: 'my-profile',
      version: '3',
      extensions: { passthrough: { benchmarkRelease: '3.5' } },
      requirements: [makeRequirement({ id: 'SV-001' })],
    });
    const yml = generateInSpecYml(baseline);
    expect(yml).toContain("version: '3'\n");
    expect(yml).not.toContain('3.3.5');
  });

  it('quotes scalars that YAML would otherwise misread', () => {
    const baseline = makeBaseline({
      name: 'my-profile',
      summary: "Comments go to: disa.stig_spt@mail.mil. It's required.",
      maintainer: 'Team @ MITRE',
      copyright: 'MITRE Corporation: 2026',
      requirements: [makeRequirement({ id: 'SV-001' })],
    });
    const yml = generateInSpecYml(baseline);
    expect(yml).toContain("summary: 'Comments go to: disa.stig_spt@mail.mil. It''s required.'");
    expect(yml).toContain("maintainer: 'Team @ MITRE'");
    expect(yml).toContain("copyright: 'MITRE Corporation: 2026'");
  });

  // Shared with the Go suite: the same Baseline must yield these bytes in both languages.
  it('parity vector: identical bytes to the Go generator', () => {
    const baseline = makeBaseline({
      name: 'rhel-9-stig',
      title: 'Red Hat Enterprise Linux 9 Security Technical Implementation Guide',
      summary: "Comments go to: disa.stig_spt@mail.mil. It's required.",
      version: '2',
      extensions: { passthrough: { benchmarkRelease: '9' } },
      requirements: [makeRequirement({ id: 'SV-001' })],
    });
    const expected =
      'name: rhel-9-stig\n' +
      'title: Red Hat Enterprise Linux 9 Security Technical Implementation Guide\n' +
      "summary: 'Comments go to: disa.stig_spt@mail.mil. It''s required.'\n" +
      "version: '2.9.0'\n" +
      "inspec_version: '>= 7.0'\n";
    expect(generateInSpecYml(baseline)).toBe(expected);
  });

  it('metadata version beats the benchmark release', () => {
    const baseline = makeBaseline({
      name: 'my-profile',
      version: '2',
      extensions: { passthrough: { benchmarkRelease: '9' } },
      requirements: [makeRequirement({ id: 'SV-001' })],
    });
    const yml = generateInSpecYml(baseline, { metadata: { version: '3.0.0' } });
    expect(yml).toContain("version: '3.0.0'");
    expect(yml).not.toContain("version: '2.9.0'");
  });

  it('renders supports array', () => {
    const baseline = makeBaseline({
      name: 'my-profile',
      supports: [{ platformName: 'ubuntu' }, { platformName: 'redhat' }],
      requirements: [makeRequirement({ id: 'SV-001' })],
    });
    const yml = generateInSpecYml(baseline);
    expect(yml).toContain('supports:');
    expect(yml).toContain('platform-name: ubuntu');
    expect(yml).toContain('platform-name: redhat');
  });

  it('renders depends array', () => {
    const baseline = makeBaseline({
      name: 'my-profile',
      depends: [
        { name: 'base-profile', git: 'https://github.com/org/base.git' },
      ],
      requirements: [makeRequirement({ id: 'SV-001' })],
    });
    const yml = generateInSpecYml(baseline);
    expect(yml).toContain('depends:');
    expect(yml).toContain('name: base-profile');
    expect(yml).toContain("git: 'https://github.com/org/base.git'");
  });

  it('renders inputs array', () => {
    const baseline = makeBaseline({
      name: 'my-profile',
      inputs: [{ disable_slow_controls: true }],
      requirements: [makeRequirement({ id: 'SV-001' })],
    });
    const yml = generateInSpecYml(baseline);
    expect(yml).toContain('inputs:');
    expect(yml).toContain('disable_slow_controls');
  });

  it('omits empty optional fields', () => {
    const yml = generateInSpecYml(minimalBaseline);
    expect(yml).not.toContain('title:');
    expect(yml).not.toContain('summary:');
    expect(yml).not.toContain('depends:');
    expect(yml).not.toContain('supports:');
  });

  it('renders supports with platform, family, and release', () => {
    const baseline = makeBaseline({
      name: 'my-profile',
      supports: [
        { platform: 'os', platformFamily: 'redhat', platformName: 'centos', release: '7' },
      ],
      requirements: [makeRequirement({ id: 'SV-001' })],
    });
    const yml = generateInSpecYml(baseline);
    expect(yml).toContain('platform-name: centos');
    expect(yml).toContain('platform-family: redhat');
    expect(yml).toContain('platform: os');
    expect(yml).toContain('release: 7');
  });

  it('renders depends with path and branch', () => {
    const baseline = makeBaseline({
      name: 'my-profile',
      depends: [
        { name: 'local-dep', path: '../base-profile' },
        { name: 'branched', git: 'https://github.com/org/repo.git', branch: 'develop' },
      ],
      requirements: [makeRequirement({ id: 'SV-001' })],
    });
    const yml = generateInSpecYml(baseline);
    expect(yml).toContain('path: ../base-profile');
    expect(yml).toContain('branch: develop');
  });

  it('renders depends with compliance and supermarket', () => {
    const baseline = makeBaseline({
      name: 'my-profile',
      depends: [
        { name: 'auto-dep', compliance: 'admin/my-profile' },
        { name: 'market-dep', supermarket: 'hardening/os-hardening' },
      ],
      requirements: [makeRequirement({ id: 'SV-001' })],
    });
    const yml = generateInSpecYml(baseline);
    expect(yml).toContain('compliance: admin/my-profile');
    expect(yml).toContain('supermarket: hardening/os-hardening');
  });

  it('renders depends with url', () => {
    const baseline = makeBaseline({
      name: 'my-profile',
      depends: [
        { name: 'url-dep', url: 'https://example.com/profile.tar.gz' },
      ],
      requirements: [makeRequirement({ id: 'SV-001' })],
    });
    const yml = generateInSpecYml(baseline);
    expect(yml).toContain("url: 'https://example.com/profile.tar.gz'");
  });

  it('renders inputs with number and string values', () => {
    const baseline = makeBaseline({
      name: 'my-profile',
      inputs: [
        { max_retries: 3 },
        { server_name: 'prod-host' },
      ],
      requirements: [makeRequirement({ id: 'SV-001' })],
    });
    const yml = generateInSpecYml(baseline);
    expect(yml).toContain('max_retries: 3');
    expect(yml).toContain('server_name: prod-host');
  });

  it('renders inputs with object values as JSON', () => {
    const baseline = makeBaseline({
      name: 'my-profile',
      inputs: [
        { config: { key: 'value' } },
      ],
      requirements: [makeRequirement({ id: 'SV-001' })],
    });
    const yml = generateInSpecYml(baseline);
    expect(yml).toContain('config: {"key":"value"}');
  });
});
