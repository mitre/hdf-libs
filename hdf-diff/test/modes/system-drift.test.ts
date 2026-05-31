import { describe, it, expect } from 'vitest';
import { diffSystems, diffHdf } from '../../src/diff.js';
import type { HDFComparison, ComponentDiff } from '../../src/types.js';
import type { PackageDiff } from '../../src/sbom.js';

// -- Inline fixtures ----------------------------------------------------------

const systemV1 = {
  name: 'Portal-Prod',
  authorizationStatus: 'authorized',
  categorizationLevel: 'moderate',
  components: [
    {
      name: 'WebTier',
      type: 'application',
      baselineRefs: ['RHEL9-STIG'],
      description: 'Web servers',
    },
    {
      name: 'DatabaseTier',
      type: 'database',
      baselineRefs: ['PostgreSQL-STIG'],
      description: 'Database servers',
    },
    {
      name: 'LegacyAPI',
      type: 'service',
      description: 'Old API being decommissioned',
    },
  ],
};

const systemV2 = {
  name: 'Portal-Prod',
  authorizationStatus: 'conditionallyAuthorized',
  categorizationLevel: 'moderate',
  components: [
    {
      name: 'WebTier',
      type: 'application',
      baselineRefs: ['RHEL9-STIG', 'Container-STIG'],
      description: 'Web servers (containerized)',
    },
    {
      name: 'DatabaseTier',
      type: 'database',
      baselineRefs: ['PostgreSQL-STIG'],
      description: 'Database servers',
    },
    {
      name: 'CacheTier',
      type: 'application',
      description: 'New Redis cache layer',
    },
  ],
};

function findComponent(diff: HDFComparison, name: string): ComponentDiff | undefined {
  return diff.componentDiffs?.find((c) => c.name === name);
}

// -- Tests --------------------------------------------------------------------

describe('system drift comparison mode', () => {
  describe('top-level metadata', () => {
    it('should set comparisonMode to systemDrift', () => {
      const diff = diffSystems(systemV1, systemV2);
      expect(diff.comparisonMode).toBe('systemDrift');
    });

    it('should have formatVersion 1.0.0', () => {
      const diff = diffSystems(systemV1, systemV2);
      expect(diff.formatVersion).toBe('1.0.0');
    });

    it('should include a timestamp', () => {
      const diff = diffSystems(systemV1, systemV2);
      expect(diff.timestamp).toBeDefined();
      expect(typeof diff.timestamp).toBe('string');
    });
  });

  describe('sources', () => {
    it('should have 2 sources', () => {
      const diff = diffSystems(systemV1, systemV2);
      expect(diff.sources).toHaveLength(2);
    });

    it('should label sources with system name', () => {
      const diff = diffSystems(systemV1, systemV2);
      expect(diff.sources[0]!.label).toBe('Portal-Prod (old)');
      expect(diff.sources[1]!.label).toBe('Portal-Prod (new)');
    });

    it('should use old/new roles', () => {
      const diff = diffSystems(systemV1, systemV2);
      expect(diff.sources[0]!.role).toBe('old');
      expect(diff.sources[1]!.role).toBe('new');
    });
  });

  describe('component states', () => {
    it('should mark WebTier as updated (baselineRefs and description changed)', () => {
      const diff = diffSystems(systemV1, systemV2);
      const comp = findComponent(diff, 'WebTier');
      expect(comp).toBeDefined();
      expect(comp!.state).toBe('updated');
    });

    it('should mark DatabaseTier as unchanged', () => {
      const diff = diffSystems(systemV1, systemV2);
      const comp = findComponent(diff, 'DatabaseTier');
      expect(comp).toBeDefined();
      expect(comp!.state).toBe('unchanged');
    });

    it('should mark LegacyAPI as absent (removed in v2)', () => {
      const diff = diffSystems(systemV1, systemV2);
      const comp = findComponent(diff, 'LegacyAPI');
      expect(comp).toBeDefined();
      expect(comp!.state).toBe('absent');
      expect(comp!.before).not.toBeNull();
      expect(comp!.after).toBeNull();
    });

    it('should mark CacheTier as new (added in v2)', () => {
      const diff = diffSystems(systemV1, systemV2);
      const comp = findComponent(diff, 'CacheTier');
      expect(comp).toBeDefined();
      expect(comp!.state).toBe('new');
      expect(comp!.before).toBeNull();
      expect(comp!.after).not.toBeNull();
    });
  });

  describe('field changes for WebTier', () => {
    it('should have fieldChanges for baselineRefs and description', () => {
      const diff = diffSystems(systemV1, systemV2);
      const comp = findComponent(diff, 'WebTier');
      expect(comp).toBeDefined();
      expect(comp!.fieldChanges.length).toBeGreaterThanOrEqual(2);

      const changedPaths = comp!.fieldChanges.map((fc) => fc.path);
      expect(changedPaths).toContain('baselineRefs');
      expect(changedPaths).toContain('description');
    });

    it('should record baselineRefs change as replace', () => {
      const diff = diffSystems(systemV1, systemV2);
      const comp = findComponent(diff, 'WebTier');
      const baselineChange = comp!.fieldChanges.find((fc) => fc.path === 'baselineRefs');
      expect(baselineChange).toBeDefined();
      expect(baselineChange!.op).toBe('replace');
      expect(baselineChange!.oldValue).toEqual(['RHEL9-STIG']);
      expect(baselineChange!.newValue).toEqual(['RHEL9-STIG', 'Container-STIG']);
    });

    it('should record description change as replace', () => {
      const diff = diffSystems(systemV1, systemV2);
      const comp = findComponent(diff, 'WebTier');
      const descChange = comp!.fieldChanges.find((fc) => fc.path === 'description');
      expect(descChange).toBeDefined();
      expect(descChange!.op).toBe('replace');
      expect(descChange!.oldValue).toBe('Web servers');
      expect(descChange!.newValue).toBe('Web servers (containerized)');
    });
  });

  describe('authorization status change', () => {
    it('should detect authorizationStatus change in system-level field changes', () => {
      const diff = diffSystems(systemV1, systemV2);
      expect(diff.extensions).toBeDefined();
      const sysChanges = diff.extensions!['systemFieldChanges'] as Array<Record<string, unknown>>;
      expect(sysChanges).toBeDefined();
      const authChange = sysChanges.find((fc) => fc['path'] === 'authorizationStatus');
      expect(authChange).toBeDefined();
      expect(authChange!['op']).toBe('replace');
      expect(authChange!['oldValue']).toBe('authorized');
      expect(authChange!['newValue']).toBe('conditionallyAuthorized');
    });

    it('should not have system-level field changes when systems are identical', () => {
      const diff = diffSystems(systemV1, systemV1);
      expect(diff.extensions).toBeUndefined();
    });
  });

  describe('summary counts', () => {
    it('should have correct totals', () => {
      const diff = diffSystems(systemV1, systemV2);
      expect(diff.summary.total).toBe(4); // WebTier, DatabaseTier, LegacyAPI, CacheTier
      expect(diff.summary.matchedCount).toBe(2); // WebTier (updated) + DatabaseTier (unchanged)
      expect(diff.summary.unmatchedOldCount).toBe(1); // LegacyAPI
      expect(diff.summary.unmatchedNewCount).toBe(1); // CacheTier
      expect(diff.summary.updated).toBe(1); // WebTier
      expect(diff.summary.unchanged).toBe(1); // DatabaseTier
      expect(diff.summary.absent).toBe(1); // LegacyAPI
      expect(diff.summary.new).toBe(1); // CacheTier
    });

    it('should have zero fixed and regressed', () => {
      const diff = diffSystems(systemV1, systemV2);
      expect(diff.summary.fixed).toBe(0);
      expect(diff.summary.regressed).toBe(0);
    });
  });

  describe('empty arrays for non-applicable fields', () => {
    it('should have empty requirementDiffs array', () => {
      const diff = diffSystems(systemV1, systemV2);
      expect(diff.requirementDiffs).toEqual([]);
    });

    it('should have empty baselineDiffs array', () => {
      const diff = diffSystems(systemV1, systemV2);
      expect(diff.baselineDiffs).toEqual([]);
    });
  });

  describe('auto-detection via diffHdf', () => {
    it('should auto-select systemDrift mode when both inputs are system documents', () => {
      const diff = diffHdf(systemV1, systemV2);
      expect(diff.comparisonMode).toBe('systemDrift');
    });

    it('should not auto-select when comparisonMode is explicitly set', () => {
      const diff = diffHdf(systemV1, systemV2, { comparisonMode: 'temporal' });
      expect(diff.comparisonMode).toBe('temporal');
    });
  });

  describe('identical systems', () => {
    it('should classify all components as unchanged', () => {
      const diff = diffSystems(systemV1, systemV1);
      for (const comp of diff.componentDiffs!) {
        expect(comp.state).toBe('unchanged');
      }
    });
  });

  describe('before/after snapshots', () => {
    it('should include full component snapshots in before/after', () => {
      const diff = diffSystems(systemV1, systemV2);
      const comp = findComponent(diff, 'WebTier');
      expect(comp!.before).toBeDefined();
      expect(comp!.after).toBeDefined();
      expect((comp!.before as Record<string, unknown>)['description']).toBe('Web servers');
      expect((comp!.after as Record<string, unknown>)['description']).toBe('Web servers (containerized)');
    });
  });

  describe('component diffs are sorted by name', () => {
    it('should return componentDiffs sorted alphabetically by name', () => {
      const diff = diffSystems(systemV1, systemV2);
      const names = diff.componentDiffs!.map((c) => c.name);
      const sorted = [...names].sort();
      expect(names).toEqual(sorted);
    });
  });

  describe('componentId-based matching', () => {
    it('should match components by componentId when available', () => {
      const old = {
        name: 'System',
        components: [
          { componentId: 'aaa-111', name: 'OldName', type: 'application' },
        ],
      };
      const updated = {
        name: 'System',
        components: [
          { componentId: 'aaa-111', name: 'RenamedApp', type: 'application', description: 'now with description' },
        ],
      };
      const diff = diffSystems(old, updated);
      const comp = diff.componentDiffs!.find((c) => c.name === 'RenamedApp');
      expect(comp).toBeDefined();
      expect(comp!.state).toBe('updated');
      // Should NOT show OldName as absent and RenamedApp as new
      expect(diff.componentDiffs!.find((c) => c.state === 'absent')).toBeUndefined();
      expect(diff.componentDiffs!.find((c) => c.state === 'new')).toBeUndefined();
    });

    it('should fall back to name matching when componentId is absent', () => {
      const old = {
        name: 'System',
        components: [{ name: 'App', type: 'application' }],
      };
      const updated = {
        name: 'System',
        components: [{ name: 'App', type: 'application', description: 'added' }],
      };
      const diff = diffSystems(old, updated);
      expect(diff.componentDiffs).toHaveLength(1);
      expect(diff.componentDiffs![0]!.state).toBe('updated');
    });
  });

  describe('data flow diffing', () => {
    it('should detect added data flows', () => {
      const old = { name: 'System', components: [], dataFlows: [] };
      const updated = {
        name: 'System',
        components: [],
        dataFlows: [{ from: 'aaa', to: 'bbb', protocol: 'HTTPS' }],
      };
      const diff = diffSystems(old, updated);
      expect(diff.extensions).toBeDefined();
      const flowChanges = diff.extensions!['dataFlowChanges'] as Array<Record<string, unknown>>;
      expect(flowChanges).toHaveLength(1);
      expect(flowChanges[0]!['state']).toBe('added');
    });

    it('should detect removed data flows', () => {
      const old = {
        name: 'System',
        components: [],
        dataFlows: [{ from: 'aaa', to: 'bbb', protocol: 'HTTPS' }],
      };
      const updated = { name: 'System', components: [], dataFlows: [] };
      const diff = diffSystems(old, updated);
      const flowChanges = diff.extensions!['dataFlowChanges'] as Array<Record<string, unknown>>;
      expect(flowChanges).toHaveLength(1);
      expect(flowChanges[0]!['state']).toBe('removed');
    });

    it('should detect modified data flows', () => {
      const old = {
        name: 'System',
        components: [],
        dataFlows: [{ from: 'aaa', to: 'bbb', protocol: 'HTTP' }],
      };
      const updated = {
        name: 'System',
        components: [],
        dataFlows: [{ from: 'aaa', to: 'bbb', protocol: 'HTTPS', port: 443 }],
      };
      const diff = diffSystems(old, updated);
      const flowChanges = diff.extensions!['dataFlowChanges'] as Array<Record<string, unknown>>;
      expect(flowChanges).toHaveLength(1);
      expect(flowChanges[0]!['state']).toBe('updated');
    });

    it('should not add dataFlowChanges when no flows exist', () => {
      const diff = diffSystems(systemV1, systemV2);
      expect(diff.extensions?.['dataFlowChanges']).toBeUndefined();
    });
  });

  describe('embedded SBOM diffing', () => {
    const cdxOld = {
      bomFormat: 'CycloneDX', specVersion: '1.5',
      components: [
        { 'bom-ref': 'a', name: 'lodash', version: '4.17.20', purl: 'pkg:npm/lodash@4.17.20' },
        { 'bom-ref': 'b', name: 'express', version: '4.18.0', purl: 'pkg:npm/express@4.18.0' },
      ],
    };
    const cdxNew = {
      bomFormat: 'CycloneDX', specVersion: '1.5',
      components: [
        { 'bom-ref': 'a', name: 'lodash', version: '4.17.21', purl: 'pkg:npm/lodash@4.17.21' },
        { 'bom-ref': 'c', name: 'axios', version: '1.6.0', purl: 'pkg:npm/axios@1.6.0' },
      ],
    };

    it('should diff embedded SBOMs and produce packageDiffs', () => {
      const old = {
        name: 'System',
        components: [{ componentId: 'comp-1', name: 'WebApp', type: 'application', sbom: cdxOld, sbomFormat: 'cyclonedx' }],
      };
      const updated = {
        name: 'System',
        components: [{ componentId: 'comp-1', name: 'WebApp', type: 'application', sbom: cdxNew, sbomFormat: 'cyclonedx' }],
      };
      const diff = diffSystems(old, updated);
      expect(diff.packageDiffs).toBeDefined();
      expect(diff.packageDiffs!.length).toBeGreaterThan(0);
      const lodash = diff.packageDiffs!.find((p: PackageDiff) => p.name === 'lodash');
      expect(lodash?.state).toBe('updated');
      const express = diff.packageDiffs!.find((p: PackageDiff) => p.name === 'express');
      expect(express?.state).toBe('removed');
      const axios = diff.packageDiffs!.find((p: PackageDiff) => p.name === 'axios');
      expect(axios?.state).toBe('added');
    });

    it('should not produce packageDiffs when no SBOMs exist', () => {
      const diff = diffSystems(systemV1, systemV2);
      expect(diff.packageDiffs).toBeUndefined();
    });
  });
});
