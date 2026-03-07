import { describe, it, expect } from 'vitest';
import type { HdfResults } from '@mitre/hdf-schema';
import { buildExtensionGraph } from '../src/index.js';
import { makeRequirement, makeBaseline } from './helpers.js';

describe('integration: single baseline (no extensions)', () => {
  const results: HdfResults = {
    baselines: [
      makeBaseline({
        name: 'rhel9-stig-baseline',
        requirements: [
          makeRequirement({ id: 'SV-001', code: 'describe sshd_config do\n  its("PermitRootLogin") { should eq "no" }\nend', impact: 0.7, title: 'Disable root login' }),
          makeRequirement({ id: 'SV-002', code: 'describe package("aide") do\n  it { should be_installed }\nend', impact: 0.5, title: 'Install AIDE' }),
          makeRequirement({ id: 'SV-003', impact: 0.0, title: 'N/A control' }),
        ],
      }),
    ],
  } as HdfResults;

  it('builds graph with one baseline and all requirements', () => {
    const graph = buildExtensionGraph(results);
    expect(graph.baselines).toHaveLength(1);
    expect(graph.requirements).toHaveLength(3);
    expect(graph.rootBaselines).toHaveLength(1);
  });

  it('all requirements are their own root', () => {
    const graph = buildExtensionGraph(results);
    for (const req of graph.requirements) {
      expect(req.root).toBe(req);
      expect(req.isRedundant).toBe(false);
      expect(req.extendsFrom).toHaveLength(0);
      expect(req.extendedBy).toHaveLength(0);
      expect(req.modifications).toEqual([]);
      expect(req.extensionChain).toHaveLength(1);
    }
  });

  it('fullCode contains baseline header for requirements with code', () => {
    const graph = buildExtensionGraph(results);
    const sv001 = graph.findRequirements('SV-001')[0]!;
    expect(sv001.fullCode).toContain('# rhel9-stig-baseline');
    expect(sv001.fullCode).toContain('PermitRootLogin');
  });

  it('fullCode is empty for requirements without code', () => {
    const graph = buildExtensionGraph(results);
    const sv003 = graph.findRequirements('SV-003')[0]!;
    expect(sv003.fullCode).toBe('');
  });
});

describe('integration: two-layer overlay', () => {
  const results: HdfResults = {
    baselines: [
      makeBaseline({
        name: 'rhel9-stig-baseline',
        requirements: [
          makeRequirement({ id: 'SV-001', code: 'describe sshd_config do\n  its("PermitRootLogin") { should eq "no" }\nend', impact: 0.7, title: 'Disable root login' }),
          makeRequirement({ id: 'SV-002', code: 'describe package("aide") do\n  it { should be_installed }\nend', impact: 0.5, title: 'Install AIDE' }),
          makeRequirement({ id: 'SV-003', code: 'describe file("/etc/shadow") do\n  it { should exist }\nend', impact: 0.3, title: 'Shadow file exists' }),
        ],
      }),
      makeBaseline({
        name: 'cms-rhel9-overlay',
        parentBaseline: 'rhel9-stig-baseline',
        requirements: [
          makeRequirement({ id: 'SV-001', code: '', impact: 0.7, title: 'Disable root login' }),
          makeRequirement({ id: 'SV-002', code: 'describe package("aide") do\n  it { should be_installed }\n  its("version") { should cmp >= "0.16" }\nend', impact: 0.5, title: 'Install AIDE (CMS)' }),
          makeRequirement({ id: 'SV-003', code: '', impact: 0.0, title: 'Shadow file exists' }),
        ],
      }),
    ],
  } as HdfResults;

  it('links baselines correctly', () => {
    const graph = buildExtensionGraph(results);
    const base = graph.findBaseline('rhel9-stig-baseline')!;
    const overlay = graph.findBaseline('cms-rhel9-overlay')!;

    expect(base.extendedBy).toContain(overlay);
    expect(overlay.extendsFrom).toContain(base);
    expect(graph.rootBaselines).toHaveLength(1);
    expect(graph.rootBaselines[0]).toBe(base);
  });

  it('SV-001 overlay is redundant (empty code, same impact)', () => {
    const graph = buildExtensionGraph(results);
    const overlaySV001 = graph.baselines[1]!.requirements[0]!;

    expect(overlaySV001.isRedundant).toBe(true);
    expect(overlaySV001.root).toBe(graph.baselines[0]!.requirements[0]);
    expect(overlaySV001.modifications).toEqual([]);
  });

  it('SV-002 overlay has modified code and title', () => {
    const graph = buildExtensionGraph(results);
    const overlaySV002 = graph.baselines[1]!.requirements[1]!;

    expect(overlaySV002.isRedundant).toBe(false);
    expect(overlaySV002.fullCode).toContain('cms-rhel9-overlay');
    expect(overlaySV002.fullCode).toContain('version');
    expect(overlaySV002.fullCode).toContain('rhel9-stig-baseline');
    expect(overlaySV002.modifications.some((m) => m.field === 'title')).toBe(true);
  });

  it('SV-003 overlay changes impact to 0.0 (disabling control)', () => {
    const graph = buildExtensionGraph(results);
    const overlaySV003 = graph.baselines[1]!.requirements[2]!;

    expect(overlaySV003.isRedundant).toBe(true); // empty code
    const impactMod = overlaySV003.modifications.find((m) => m.field === 'impact');
    expect(impactMod).toBeDefined();
    expect(impactMod!.originalValue).toBe(0.3);
    expect(impactMod!.newValue).toBe(0.0);
  });

  it('extension chain is correct for overlay requirements', () => {
    const graph = buildExtensionGraph(results);
    const overlaySV002 = graph.baselines[1]!.requirements[1]!;
    const chain = overlaySV002.extensionChain;

    expect(chain).toHaveLength(2);
    expect(chain[0]!.data.name).toBe('rhel9-stig-baseline');
    expect(chain[1]!.data.name).toBe('cms-rhel9-overlay');
  });
});

describe('integration: three-layer extension chain', () => {
  const results: HdfResults = {
    baselines: [
      makeBaseline({
        name: 'disa-rhel7-stig',
        requirements: [
          makeRequirement({ id: 'V-71849', code: 'describe sshd_config do\n  its("ClientAliveInterval") { should cmp <= 600 }\nend', impact: 0.5, title: 'SSH timeout' }),
          makeRequirement({ id: 'V-71855', code: 'describe shadow.where { user == "root" } do\n  its("max_days") { should cmp <= 60 }\nend', impact: 0.7, title: 'Password max age' }),
        ],
      }),
      makeBaseline({
        name: 'cms-rhel7-overlay',
        parentBaseline: 'disa-rhel7-stig',
        requirements: [
          makeRequirement({ id: 'V-71849', code: 'describe sshd_config do\n  its("ClientAliveInterval") { should cmp <= 300 }\nend', impact: 0.5, title: 'SSH timeout (CMS)' }),
          makeRequirement({ id: 'V-71855', code: '', impact: 0.7, title: 'Password max age' }),
        ],
      }),
      makeBaseline({
        name: 'project-specific-overlay',
        parentBaseline: 'cms-rhel7-overlay',
        requirements: [
          makeRequirement({ id: 'V-71849', code: 'describe sshd_config do\n  its("ClientAliveInterval") { should cmp <= 120 }\nend', impact: 0.9, title: 'SSH timeout (project)' }),
          makeRequirement({ id: 'V-71855', code: '', impact: 0.0, title: 'Password max age (waived)' }),
        ],
      }),
    ],
  } as HdfResults;

  it('builds a three-node baseline chain', () => {
    const graph = buildExtensionGraph(results);
    expect(graph.baselines).toHaveLength(3);
    expect(graph.rootBaselines).toHaveLength(1);
    expect(graph.rootBaselines[0]!.data.name).toBe('disa-rhel7-stig');

    const disa = graph.findBaseline('disa-rhel7-stig')!;
    const cms = graph.findBaseline('cms-rhel7-overlay')!;
    const proj = graph.findBaseline('project-specific-overlay')!;

    expect(disa.extendedBy).toContain(cms);
    expect(cms.extendedBy).toContain(proj);
    expect(proj.extendsFrom).toContain(cms);
  });

  it('V-71849 fullCode has all three layers top-to-bottom', () => {
    const graph = buildExtensionGraph(results);
    const projReq = graph.baselines[2]!.requirements[0]!;
    const full = projReq.fullCode;

    expect(full).toContain('project-specific-overlay');
    expect(full).toContain('120');
    expect(full).toContain('cms-rhel7-overlay');
    expect(full).toContain('300');
    expect(full).toContain('disa-rhel7-stig');
    expect(full).toContain('600');

    const projIdx = full.indexOf('120');
    const cmsIdx = full.indexOf('300');
    const disaIdx = full.indexOf('600');
    expect(projIdx).toBeLessThan(cmsIdx);
    expect(cmsIdx).toBeLessThan(disaIdx);
  });

  it('V-71849 root is the DISA baseline requirement', () => {
    const graph = buildExtensionGraph(results);
    const projReq = graph.baselines[2]!.requirements[0]!;
    const disaReq = graph.baselines[0]!.requirements[0]!;

    expect(projReq.root).toBe(disaReq);
  });

  it('V-71849 extension chain has three entries', () => {
    const graph = buildExtensionGraph(results);
    const projReq = graph.baselines[2]!.requirements[0]!;
    expect(projReq.extensionChain.map((b) => b.data.name)).toEqual([
      'disa-rhel7-stig',
      'cms-rhel7-overlay',
      'project-specific-overlay',
    ]);
  });

  it('V-71849 project overlay detects impact and title changes vs CMS parent', () => {
    const graph = buildExtensionGraph(results);
    const projReq = graph.baselines[2]!.requirements[0]!;
    const mods = projReq.modifications;

    expect(mods.some((m) => m.field === 'impact' && m.originalValue === 0.5 && m.newValue === 0.9)).toBe(true);
    expect(mods.some((m) => m.field === 'title')).toBe(true);
  });

  it('V-71855 redundant overlays skip to base code', () => {
    const graph = buildExtensionGraph(results);
    const projReq = graph.baselines[2]!.requirements[1]!;

    expect(projReq.isRedundant).toBe(true);
    expect(projReq.fullCode).toContain('disa-rhel7-stig');
    expect(projReq.fullCode).toContain('max_days');
    expect(projReq.fullCode).not.toContain('cms-rhel7-overlay');
    expect(projReq.fullCode).not.toContain('project-specific-overlay');
  });
});

describe('integration: wrapper pattern (multiple independents)', () => {
  const results: HdfResults = {
    baselines: [
      makeBaseline({
        name: 'k8s-stig-baseline',
        requirements: [
          makeRequirement({ id: 'K8S-001', code: 'describe kubelet do\n  it { should be_running }\nend', impact: 0.5 }),
        ],
      }),
      makeBaseline({
        name: 'rhel9-stig-baseline',
        requirements: [
          makeRequirement({ id: 'SV-001', code: 'describe sshd_config do\n  its("PermitRootLogin") { should eq "no" }\nend', impact: 0.7 }),
        ],
      }),
      makeBaseline({
        name: 'wrapper-profile',
        requirements: [],
        depends: [{ name: 'k8s-stig-baseline' }, { name: 'rhel9-stig-baseline' }],
      }),
    ],
  } as HdfResults;

  it('wrapper has no parent and no requirements', () => {
    const graph = buildExtensionGraph(results);
    const wrapper = graph.findBaseline('wrapper-profile')!;

    expect(wrapper.extendsFrom).toHaveLength(0);
    expect(wrapper.extendedBy).toHaveLength(0);
    expect(wrapper.requirements).toHaveLength(0);
  });

  it('independent baselines are unlinked', () => {
    const graph = buildExtensionGraph(results);
    const k8s = graph.findBaseline('k8s-stig-baseline')!;
    const rhel = graph.findBaseline('rhel9-stig-baseline')!;

    expect(k8s.extendsFrom).toHaveLength(0);
    expect(k8s.extendedBy).toHaveLength(0);
    expect(rhel.extendsFrom).toHaveLength(0);
    expect(rhel.extendedBy).toHaveLength(0);
  });

  it('all three baselines are roots', () => {
    const graph = buildExtensionGraph(results);
    expect(graph.rootBaselines).toHaveLength(3);
  });
});

describe('integration: edge cases', () => {
  it('handles dangling parentBaseline gracefully', () => {
    const results: HdfResults = {
      baselines: [
        makeBaseline({
          name: 'orphan-overlay',
          parentBaseline: 'deleted-baseline',
          requirements: [makeRequirement({ id: 'R1', code: 'some code' })],
        }),
      ],
    } as HdfResults;

    const graph = buildExtensionGraph(results);
    const orphan = graph.findBaseline('orphan-overlay')!;

    expect(orphan.extendsFrom).toHaveLength(0);
    expect(orphan.requirements[0]!.root).toBe(orphan.requirements[0]);
    expect(orphan.requirements[0]!.isRedundant).toBe(false);
    expect(orphan.requirements[0]!.extensionChain).toHaveLength(1);
  });

  it('handles duplicate requirement ids within same baseline', () => {
    const results: HdfResults = {
      baselines: [
        makeBaseline({
          name: 'base',
          requirements: [
            makeRequirement({ id: 'R1', code: 'first' }),
            makeRequirement({ id: 'R1', code: 'second' }),
          ],
        }),
      ],
    } as HdfResults;

    const graph = buildExtensionGraph(results);
    expect(graph.findRequirements('R1')).toHaveLength(2);
  });

  it('handles baseline with empty requirements array', () => {
    const results: HdfResults = {
      baselines: [makeBaseline({ name: 'empty', requirements: [] })],
    } as HdfResults;

    const graph = buildExtensionGraph(results);
    expect(graph.baselines).toHaveLength(1);
    expect(graph.requirements).toHaveLength(0);
  });
});
