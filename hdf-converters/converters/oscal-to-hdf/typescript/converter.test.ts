import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { describe, it, expect } from 'vitest';
import { detectOscalDocumentType } from './detect.js';
import { convertOscalCatalogToHdf } from './converter-catalog.js';
import { convertOscalProfileToHdf } from './converter-profile.js';
import { convertOscalComponentToHdf } from './converter-component.js';
import { convertOscalSspToHdf } from './converter-ssp.js';
import { convertOscalSapToHdf } from './converter-sap.js';
import { convertOscalPoamToHdf } from './converter-poam.js';
import { convertOscalSarToHdf } from './converter-sar.js';
import {
  controlIdToNistTag,
  controlIdsToNistTags,
  extractControlIdFromObjectiveId,
  oscalStatusToHdf,
  extractPropValue,
  extractAllPropValues,
  flattenParts,
  flattenPartsByName,
  extractRiskSeverity,
  extractMetadata,
  nistTagToControlId,
  impactToSeverity,
  hdfStatusToOscalRiskStatus,
  parseOscalDocument,
  toKebabCase,
} from './shared.js';
import type { HDFResults, HDFBaseline } from '@mitre/hdf-schema';
import type { HDFSystem } from '@mitre/hdf-schema';
import type { HDFPlan } from '@mitre/hdf-schema';
import type { HDFAmendments } from '@mitre/hdf-schema';

const __dirname = dirname(fileURLToPath(import.meta.url));
const FIXTURES_DIR = join(__dirname, '..', 'fixtures');

function loadFixture(name: string): string {
  return readFileSync(join(FIXTURES_DIR, 'input', name), 'utf-8');
}

// ---------------------------------------------------------------------------
// Detection
// ---------------------------------------------------------------------------

describe('detectOscalDocumentType', () => {
  it('should detect catalog', () => {
    expect(detectOscalDocumentType(loadFixture('catalog-moderate-resolved.json'))).toBe('catalog');
  });

  it('should detect profile', () => {
    expect(detectOscalDocumentType(loadFixture('profile-moderate.json'))).toBe('profile');
  });

  it('should detect component-definition', () => {
    expect(detectOscalDocumentType(loadFixture('component-example.json'))).toBe('component-definition');
  });

  it('should detect system-security-plan', () => {
    expect(detectOscalDocumentType(loadFixture('ssp-example.json'))).toBe('system-security-plan');
  });

  it('should detect assessment-plan', () => {
    expect(detectOscalDocumentType(loadFixture('sap-fedramp.json'))).toBe('assessment-plan');
  });

  it('should detect assessment-results', () => {
    expect(detectOscalDocumentType(loadFixture('sar-fedramp.json'))).toBe('assessment-results');
  });

  it('should detect plan-of-action-and-milestones', () => {
    expect(detectOscalDocumentType(loadFixture('poam-fedramp.json'))).toBe('plan-of-action-and-milestones');
  });

  it('should throw on invalid JSON', () => {
    expect(() => detectOscalDocumentType('not json')).toThrow();
  });

  it('should throw on unrecognized document', () => {
    expect(() => detectOscalDocumentType('{"unknown-root": {}}')).toThrow('unrecognized OSCAL document');
  });
});

// ---------------------------------------------------------------------------
// Catalog converter
// ---------------------------------------------------------------------------

describe('convertOscalCatalogToHdf', () => {
  it('should throw on empty input', async () => {
    await expect(convertOscalCatalogToHdf('')).rejects.toThrow('empty input');
  });

  it('should throw on invalid JSON', async () => {
    await expect(convertOscalCatalogToHdf('not json')).rejects.toThrow();
  });

  it('should throw when root key is not catalog', async () => {
    await expect(
      convertOscalCatalogToHdf(loadFixture('profile-moderate.json')),
    ).rejects.toThrow('not a catalog');
  });

  it('should convert resolved catalog to HDF baseline', async () => {
    const output = await convertOscalCatalogToHdf(
      loadFixture('catalog-moderate-resolved.json'),
    );
    const baseline = JSON.parse(output) as HDFBaseline;

    // 287 controls+enhancements in moderate resolved catalog
    expect(baseline.requirements).toHaveLength(287);

    expect(baseline.name).toBeTruthy();
    expect(baseline.title).toContain('800-53');
    expect(baseline.version).toBe('5.2.0');
    expect(baseline.status).toBe('loaded');

    expect(baseline.generator?.name).toBe('hdf-converters');
    expect(baseline.integrity?.algorithm).toBe('sha256');
  });

  it('should produce correct groups', async () => {
    const output = await convertOscalCatalogToHdf(
      loadFixture('catalog-moderate-resolved.json'),
    );
    const baseline = JSON.parse(output) as HDFBaseline;

    // Control families with controls in moderate resolved catalog
    expect(baseline.groups!.length).toBeGreaterThanOrEqual(18);
    expect(baseline.groups?.[0]?.id).toBe('ac');
    expect(baseline.groups?.[0]?.title).toBe('Access Control');
  });

  it('should produce AC-1 with correct descriptions', async () => {
    const output = await convertOscalCatalogToHdf(
      loadFixture('catalog-moderate-resolved.json'),
    );
    const baseline = JSON.parse(output) as HDFBaseline;

    const ac1 = baseline.requirements.find(r => r.id === 'AC-1');
    expect(ac1).toBeDefined();
    expect(ac1!.title).toBe('Policy and Procedures');
    expect(ac1!.impact).toBe(0.5);

    const labels = ac1!.descriptions?.map(d => d.label) ?? [];
    expect(labels).toContain('default');
    expect(labels).toContain('rationale');
    expect(labels).toContain('check');

    expect(ac1!.tags?.['nist']).toEqual(['AC-1']);
  });

  it('should include control enhancements', async () => {
    const output = await convertOscalCatalogToHdf(
      loadFixture('catalog-moderate-resolved.json'),
    );
    const baseline = JSON.parse(output) as HDFBaseline;

    const ac21 = baseline.requirements.find(r => r.id === 'AC-2 (1)');
    expect(ac21).toBeDefined();
    expect(ac21!.title).toBeTruthy();
  });

  it('should produce valid round-trip JSON', async () => {
    const output = await convertOscalCatalogToHdf(
      loadFixture('catalog-moderate-resolved.json'),
    );
    const baseline = JSON.parse(output) as HDFBaseline;
    const roundtrip = JSON.parse(JSON.stringify(baseline)) as HDFBaseline;
    expect(roundtrip.name).toBe(baseline.name);
    expect(roundtrip.requirements).toHaveLength(baseline.requirements.length);
  });

  it('should group references pointing to valid requirement IDs', async () => {
    const output = await convertOscalCatalogToHdf(
      loadFixture('catalog-moderate-resolved.json'),
    );
    const baseline = JSON.parse(output) as HDFBaseline;

    const reqIDs = new Set(baseline.requirements.map(r => r.id));
    for (const g of baseline.groups ?? []) {
      for (const rid of g.requirements ?? []) {
        expect(reqIDs.has(rid)).toBe(true);
      }
    }
  });
});

// ---------------------------------------------------------------------------
// Profile converter
// ---------------------------------------------------------------------------

describe('convertOscalProfileToHdf', () => {
  it('should throw on empty profile input', async () => {
    await expect(
      convertOscalProfileToHdf('', loadFixture('catalog-800-53-rev5.json')),
    ).rejects.toThrow('empty profile');
  });

  it('should throw on empty catalog input', async () => {
    await expect(
      convertOscalProfileToHdf(loadFixture('profile-moderate.json'), ''),
    ).rejects.toThrow('empty catalog');
  });

  it('should throw when profile is not a profile', async () => {
    const cat = loadFixture('catalog-800-53-rev5.json');
    await expect(convertOscalProfileToHdf(cat, cat)).rejects.toThrow('not a profile');
  });

  it('should throw when catalog is not a catalog', async () => {
    const prof = loadFixture('profile-moderate.json');
    await expect(convertOscalProfileToHdf(prof, prof)).rejects.toThrow('not a catalog');
  });

  it('should resolve moderate profile to 287 controls', async () => {
    const output = await convertOscalProfileToHdf(
      loadFixture('profile-moderate.json'),
      loadFixture('catalog-800-53-rev5.json'),
    );
    const baseline = JSON.parse(output) as HDFBaseline;
    expect(baseline.requirements).toHaveLength(287);
  });

  it('should match pre-resolved catalog control count', async () => {
    const profileOutput = await convertOscalProfileToHdf(
      loadFixture('profile-moderate.json'),
      loadFixture('catalog-800-53-rev5.json'),
    );
    const catalogOutput = await convertOscalCatalogToHdf(
      loadFixture('catalog-moderate-resolved.json'),
    );

    const profileBaseline = JSON.parse(profileOutput) as HDFBaseline;
    const catalogBaseline = JSON.parse(catalogOutput) as HDFBaseline;

    expect(profileBaseline.requirements).toHaveLength(
      catalogBaseline.requirements.length,
    );

    // Same set of IDs
    const profileIds = new Set(profileBaseline.requirements.map(r => r.id));
    const catalogIds = new Set(catalogBaseline.requirements.map(r => r.id));
    for (const id of catalogIds) {
      expect(profileIds.has(id)).toBe(true);
    }
  });

  it('should use profile metadata instead of catalog metadata', async () => {
    const output = await convertOscalProfileToHdf(
      loadFixture('profile-moderate.json'),
      loadFixture('catalog-800-53-rev5.json'),
    );
    const baseline = JSON.parse(output) as HDFBaseline;
    expect(baseline.title).toContain('MODERATE');
  });

  it('should reject profiles with alter directives', async () => {
    await expect(
      convertOscalProfileToHdf(
        loadFixture('profile-redhat-fedramp-high.json'),
        loadFixture('catalog-800-53-rev5.json'),
      ),
    ).rejects.toThrow('alter');
  });
}, 30000);

// ---------------------------------------------------------------------------
// Component Definition converter
// ---------------------------------------------------------------------------

describe('convertOscalComponentToHdf', () => {
  it('should throw on empty input', async () => {
    await expect(convertOscalComponentToHdf('')).rejects.toThrow('empty input');
  });

  it('should throw on invalid JSON', async () => {
    await expect(convertOscalComponentToHdf('not json')).rejects.toThrow();
  });

  it('should convert component fixture to HDF baseline', async () => {
    const output = await convertOscalComponentToHdf(
      loadFixture('component-example.json'),
    );
    const baseline = JSON.parse(output) as HDFBaseline;

    expect(baseline.name).toBeTruthy();
    expect(baseline.status).toBe('loaded');
    expect(baseline.generator?.name).toBe('hdf-converters');
    expect(baseline.integrity?.algorithm).toBe('sha256');
    expect(baseline.requirements.length).toBeGreaterThan(0);

    // Requirements should have NIST-notation IDs
    for (const req of baseline.requirements) {
      expect(req.id).toMatch(/^[A-Z]{2}-\d+/);
      expect(req.tags?.['nist']).toBeDefined();
    }
  });
});

// ---------------------------------------------------------------------------
// SSP converter
// ---------------------------------------------------------------------------

describe('convertOscalSspToHdf', () => {
  it('should throw on empty input', async () => {
    await expect(convertOscalSspToHdf('')).rejects.toThrow('empty input');
  });

  it('should throw on invalid JSON', async () => {
    await expect(convertOscalSspToHdf('not json')).rejects.toThrow();
  });

  it('should convert SSP example fixture', async () => {
    const output = await convertOscalSspToHdf(loadFixture('ssp-example.json'));
    const system = JSON.parse(output) as HDFSystem;

    expect(system.name).toBeTruthy();
    expect(system.integrity?.algorithm).toBe('sha256');
    expect(system.generator?.name).toBe('hdf-converters');
    expect(system.components).toBeDefined();
  });

  it('should convert SSP FedRAMP fixture', async () => {
    const output = await convertOscalSspToHdf(loadFixture('ssp-fedramp.json'));
    const system = JSON.parse(output) as HDFSystem;

    expect(system.name).toBeTruthy();
    expect(system.components).toBeDefined();
  });
});

// ---------------------------------------------------------------------------
// SAP converter
// ---------------------------------------------------------------------------

describe('convertOscalSapToHdf', () => {
  it('should throw on empty input', async () => {
    await expect(convertOscalSapToHdf('')).rejects.toThrow('empty input');
  });

  it('should throw on invalid JSON', async () => {
    await expect(convertOscalSapToHdf('not json')).rejects.toThrow();
  });

  it('should convert SAP FedRAMP fixture', async () => {
    const output = await convertOscalSapToHdf(loadFixture('sap-fedramp.json'));
    const plan = JSON.parse(output) as HDFPlan;

    expect(plan.name).toBeTruthy();
    expect(plan.integrity?.algorithm).toBe('sha256');
    expect(plan.generator?.name).toBe('hdf-converters');
    expect(plan.assessments).toBeDefined();
    expect(plan.assessments.length).toBeGreaterThan(0);
  });
});

// ---------------------------------------------------------------------------
// POA&M converter
// ---------------------------------------------------------------------------

describe('convertOscalPoamToHdf', () => {
  it('should throw on empty input', async () => {
    await expect(convertOscalPoamToHdf('')).rejects.toThrow('empty input');
  });

  it('should throw on invalid JSON', async () => {
    await expect(convertOscalPoamToHdf('not json')).rejects.toThrow();
  });

  it('should convert POA&M FedRAMP fixture', async () => {
    const output = await convertOscalPoamToHdf(loadFixture('poam-fedramp.json'));
    const amendments = JSON.parse(output) as HDFAmendments;

    expect(amendments.name).toBeTruthy();
    expect(amendments.integrity?.algorithm).toBe('sha256');
    expect(amendments.generator?.name).toBe('hdf-converters');
    expect(amendments.overrides).toBeDefined();
    expect(amendments.overrides.length).toBeGreaterThan(0);

    // Each override should have required fields
    for (const override of amendments.overrides) {
      expect(override.type).toBe('poam');
      expect(override.requirementId).toBeTruthy();
      expect(override.reason).toBeTruthy();
      expect(override.status).toBeTruthy();
    }
  });
});

// ---------------------------------------------------------------------------
// SAR converter
// ---------------------------------------------------------------------------

describe('convertOscalSarToHdf', () => {
  it('should throw on empty input', async () => {
    await expect(convertOscalSarToHdf('')).rejects.toThrow('empty input');
  });

  it('should throw on invalid JSON', async () => {
    await expect(convertOscalSarToHdf('not json')).rejects.toThrow();
  });

  it('should throw on wrong document type', async () => {
    await expect(
      convertOscalSarToHdf(loadFixture('catalog-moderate-resolved.json')),
    ).rejects.toThrow('not an assessment-results');
  });

  it('should convert SAR FedRAMP fixture', async () => {
    const output = await convertOscalSarToHdf(loadFixture('sar-fedramp.json'));
    const results = JSON.parse(output) as HDFResults;

    expect(results.baselines).toBeDefined();
    expect(results.baselines.length).toBeGreaterThan(0);

    expect(results.generator?.name).toBe('oscal-assessment-results-to-hdf');
    expect(results.tool?.name).toBe('OSCAL Assessment Results');
    expect(results.planRef).toBeTruthy();
  });

  it('should have requirements with NIST-notation IDs', async () => {
    const output = await convertOscalSarToHdf(loadFixture('sar-fedramp.json'));
    const results = JSON.parse(output) as HDFResults;

    const firstBaseline = results.baselines[0]!;
    expect(firstBaseline.requirements.length).toBeGreaterThan(0);

    for (const req of firstBaseline.requirements) {
      expect(req.id).toMatch(/^[A-Z]{2}-\d+/);
    }
  });

  it('should map satisfied/not-satisfied statuses', async () => {
    const output = await convertOscalSarToHdf(loadFixture('sar-fedramp.json'));
    const results = JSON.parse(output) as HDFResults;

    const firstBaseline = results.baselines[0]!;
    let passedCount = 0;
    let failedCount = 0;

    for (const req of firstBaseline.requirements) {
      for (const r of req.results) {
        if (r.status === 'passed') passedCount++;
        if (r.status === 'failed') failedCount++;
      }
    }

    expect(passedCount).toBeGreaterThan(0);
    expect(failedCount).toBeGreaterThan(0);
  });

  it('should include default description on every requirement', async () => {
    const output = await convertOscalSarToHdf(loadFixture('sar-fedramp.json'));
    const results = JSON.parse(output) as HDFResults;

    const firstBaseline = results.baselines[0]!;
    for (const req of firstBaseline.requirements) {
      const hasDefault = req.descriptions?.some(d => d.label === 'default');
      expect(hasDefault).toBe(true);
    }
  });

  it('should have multiple result sets (baselines)', async () => {
    const output = await convertOscalSarToHdf(loadFixture('sar-fedramp.json'));
    const results = JSON.parse(output) as HDFResults;

    // FedRAMP SAR fixture has 3 result sets
    expect(results.baselines).toHaveLength(3);
  });

  it('should produce valid round-trip JSON', async () => {
    const output = await convertOscalSarToHdf(loadFixture('sar-fedramp.json'));
    const results = JSON.parse(output) as HDFResults;
    const roundtrip = JSON.parse(JSON.stringify(results)) as HDFResults;
    expect(roundtrip.baselines).toHaveLength(results.baselines.length);
    expect(roundtrip.generator?.name).toBe(results.generator?.name);
  });

  it('should include integrity on baselines', async () => {
    const output = await convertOscalSarToHdf(loadFixture('sar-fedramp.json'));
    const results = JSON.parse(output) as HDFResults;

    expect(results.baselines[0]!.integrity?.algorithm).toBe('sha256');
    expect(results.baselines[0]!.integrity?.checksum).toMatch(/^[a-f0-9]{64}$/);
  });
});

// ---------------------------------------------------------------------------
// Shared utilities
// ---------------------------------------------------------------------------

describe('OSCAL shared helpers', () => {
  describe('controlIdToNistTag', () => {
    it('converts simple control IDs', () => {
      expect(controlIdToNistTag('ac-1')).toBe('AC-1');
    });

    it('converts enhancement control IDs', () => {
      expect(controlIdToNistTag('ac-2.3')).toBe('AC-2 (3)');
    });

    it('converts si-7.1', () => {
      expect(controlIdToNistTag('si-7.1')).toBe('SI-7 (1)');
    });
  });

  describe('controlIdsToNistTags', () => {
    it('deduplicates IDs', () => {
      expect(controlIdsToNistTags(['ac-1', 'ac-2', 'ac-1'])).toEqual(['AC-1', 'AC-2']);
    });

    it('handles empty array', () => {
      expect(controlIdsToNistTags([])).toEqual([]);
    });
  });

  describe('extractControlIdFromObjectiveId', () => {
    it('extracts from objective ID', () => {
      expect(extractControlIdFromObjectiveId('ac-1.a.1_obj.1')).toBe('ac-1');
    });

    it('extracts from enhancement objective ID', () => {
      expect(extractControlIdFromObjectiveId('ac-2.3')).toBe('ac-2.3');
    });

    it('returns original if no match', () => {
      expect(extractControlIdFromObjectiveId('foobar')).toBe('foobar');
    });
  });

  describe('oscalStatusToHdf', () => {
    it('maps satisfied to passed', () => {
      expect(oscalStatusToHdf('satisfied')).toBe('passed');
    });

    it('maps closed to passed', () => {
      expect(oscalStatusToHdf('closed')).toBe('passed');
    });

    it('maps not-satisfied to failed', () => {
      expect(oscalStatusToHdf('not-satisfied')).toBe('failed');
    });

    it('maps open to failed', () => {
      expect(oscalStatusToHdf('open')).toBe('failed');
    });

    it('returns undefined for unknown status', () => {
      expect(oscalStatusToHdf('in-progress')).toBeUndefined();
    });

    it('handles mixed case and whitespace', () => {
      expect(oscalStatusToHdf('  SATISFIED  ')).toBe('passed');
      expect(oscalStatusToHdf('NOT-SATISFIED')).toBe('failed');
    });
  });

  describe('extractPropValue', () => {
    it('returns undefined for undefined props', () => {
      expect(extractPropValue(undefined, 'name')).toBeUndefined();
    });

    it('returns undefined if prop not found', () => {
      expect(extractPropValue([{ name: 'other', value: 'x' }], 'name')).toBeUndefined();
    });

    it('finds prop by name', () => {
      expect(extractPropValue([{ name: 'label', value: 'AC-1' }], 'label')).toBe('AC-1');
    });

    it('respects namespace filter', () => {
      const props = [
        { name: 'label', value: 'wrong', ns: 'other-ns' },
        { name: 'label', value: 'correct', ns: 'my-ns' },
      ];
      expect(extractPropValue(props, 'label', 'my-ns')).toBe('correct');
    });

    it('ignores namespace when ns param is undefined', () => {
      const props = [{ name: 'label', value: 'val', ns: 'any-ns' }];
      expect(extractPropValue(props, 'label')).toBe('val');
    });
  });

  describe('extractAllPropValues', () => {
    it('returns empty array for undefined props', () => {
      expect(extractAllPropValues(undefined, 'name')).toEqual([]);
    });

    it('returns all matching values', () => {
      const props = [
        { name: 'tag', value: 'a' },
        { name: 'other', value: 'b' },
        { name: 'tag', value: 'c' },
      ];
      expect(extractAllPropValues(props, 'tag')).toEqual(['a', 'c']);
    });

    it('respects namespace filter', () => {
      const props = [
        { name: 'tag', value: 'a', ns: 'ns1' },
        { name: 'tag', value: 'b', ns: 'ns2' },
      ];
      expect(extractAllPropValues(props, 'tag', 'ns1')).toEqual(['a']);
    });
  });

  describe('flattenParts', () => {
    it('returns empty string for undefined', () => {
      expect(flattenParts(undefined)).toBe('');
    });

    it('returns empty string for empty array', () => {
      expect(flattenParts([])).toBe('');
    });

    it('concatenates prose from nested parts', () => {
      const parts = [
        { name: 'a', prose: 'line1', parts: [{ name: 'b', prose: 'line2' }] },
        { name: 'c', prose: 'line3' },
      ];
      expect(flattenParts(parts)).toBe('line1\nline2\nline3');
    });

    it('skips parts without prose', () => {
      const parts = [
        { name: 'a' },
        { name: 'b', prose: 'text' },
      ];
      expect(flattenParts(parts)).toBe('text');
    });
  });

  describe('flattenPartsByName', () => {
    it('returns empty string for undefined', () => {
      expect(flattenPartsByName(undefined, 'statement')).toBe('');
    });

    it('only includes parts matching name', () => {
      const parts = [
        { name: 'statement', prose: 'stmt text' },
        { name: 'guidance', prose: 'guidance text' },
        { name: 'statement', prose: 'stmt2 text', parts: [{ name: 'sub', prose: 'nested' }] },
      ];
      expect(flattenPartsByName(parts, 'statement')).toBe('stmt text\nstmt2 text\nnested');
    });

    it('returns empty string when no parts match', () => {
      const parts = [{ name: 'guidance', prose: 'text' }];
      expect(flattenPartsByName(parts, 'statement')).toBe('');
    });
  });

  describe('extractRiskSeverity', () => {
    it('returns default for undefined characterizations', () => {
      expect(extractRiskSeverity(undefined, 0.5)).toBe(0.5);
    });

    it('returns default when no matching facets', () => {
      const chars = [{ facets: [{ name: 'other', value: 'high' }] }];
      expect(extractRiskSeverity(chars, 0.5)).toBe(0.5);
    });

    it('returns default for characterization with no facets', () => {
      expect(extractRiskSeverity([{}] as any, 0.5)).toBe(0.5);
    });

    it('maps critical to 0.9', () => {
      const chars = [{ facets: [{ name: 'impact', value: 'critical' }] }];
      expect(extractRiskSeverity(chars, 0.5)).toBe(0.9);
    });

    it('maps high to 0.7', () => {
      const chars = [{ facets: [{ name: 'risk', value: 'high' }] }];
      expect(extractRiskSeverity(chars, 0.5)).toBe(0.7);
    });

    it('maps moderate to 0.5', () => {
      const chars = [{ facets: [{ name: 'impact', value: 'moderate' }] }];
      expect(extractRiskSeverity(chars, 0.3)).toBe(0.5);
    });

    it('maps medium to 0.5', () => {
      const chars = [{ facets: [{ name: 'impact', value: 'medium' }] }];
      expect(extractRiskSeverity(chars, 0.3)).toBe(0.5);
    });

    it('maps low to 0.3', () => {
      const chars = [{ facets: [{ name: 'likelihood', value: 'low' }] }];
      expect(extractRiskSeverity(chars, 0.5)).toBe(0.3);
    });

    it('maps info to 0.0', () => {
      const chars = [{ facets: [{ name: 'impact', value: 'info' }] }];
      expect(extractRiskSeverity(chars, 0.5)).toBe(0.0);
    });

    it('maps informational to 0.0', () => {
      const chars = [{ facets: [{ name: 'impact', value: 'informational' }] }];
      expect(extractRiskSeverity(chars, 0.5)).toBe(0.0);
    });

    it('maps none to 0.0', () => {
      const chars = [{ facets: [{ name: 'impact', value: 'none' }] }];
      expect(extractRiskSeverity(chars, 0.5)).toBe(0.0);
    });
  });

  describe('extractMetadata', () => {
    it('extracts all fields', () => {
      const meta = {
        title: 'Test',
        version: '1.0',
        'oscal-version': '1.1.2',
        'last-modified': '2024-01-01T00:00:00Z',
      };
      const result = extractMetadata(meta as any);
      expect(result.title).toBe('Test');
      expect(result.version).toBe('1.0');
      expect(result.oscalVersion).toBe('1.1.2');
      expect(result.lastModified).toBe('2024-01-01T00:00:00Z');
    });
  });

  describe('nistTagToControlId', () => {
    it('converts simple tag', () => {
      expect(nistTagToControlId('AC-1')).toBe('ac-1');
    });

    it('converts enhancement tag', () => {
      expect(nistTagToControlId('AC-2 (3)')).toBe('ac-2.3');
    });

    it('handles whitespace', () => {
      expect(nistTagToControlId('  SI-7 (1)  ')).toBe('si-7.1');
    });
  });

  describe('impactToSeverity', () => {
    it('maps 0.9+ to critical', () => {
      expect(impactToSeverity(0.9)).toBe('critical');
      expect(impactToSeverity(1.0)).toBe('critical');
    });

    it('maps 0.7-0.89 to high', () => {
      expect(impactToSeverity(0.7)).toBe('high');
      expect(impactToSeverity(0.89)).toBe('high');
    });

    it('maps 0.4-0.69 to moderate', () => {
      expect(impactToSeverity(0.4)).toBe('moderate');
      expect(impactToSeverity(0.5)).toBe('moderate');
    });

    it('maps 0.1-0.39 to low', () => {
      expect(impactToSeverity(0.1)).toBe('low');
      expect(impactToSeverity(0.3)).toBe('low');
    });

    it('maps 0.0 to info', () => {
      expect(impactToSeverity(0.0)).toBe('info');
      expect(impactToSeverity(0.09)).toBe('info');
    });
  });

  describe('hdfStatusToOscalRiskStatus', () => {
    it('maps passed to closed', () => {
      expect(hdfStatusToOscalRiskStatus('passed')).toBe('closed');
    });

    it('maps notApplicable to closed', () => {
      expect(hdfStatusToOscalRiskStatus('notApplicable')).toBe('closed');
    });

    it('maps failed to open', () => {
      expect(hdfStatusToOscalRiskStatus('failed')).toBe('open');
    });

    it('maps error to open', () => {
      expect(hdfStatusToOscalRiskStatus('error')).toBe('open');
    });

    it('maps unknown to open', () => {
      expect(hdfStatusToOscalRiskStatus('something')).toBe('open');
    });
  });

  describe('parseOscalDocument', () => {
    it('throws on empty input', () => {
      expect(() => parseOscalDocument('', 'catalog', 'test')).toThrow('test: empty input');
    });

    it('throws on whitespace-only input', () => {
      expect(() => parseOscalDocument('  \n  ', 'catalog', 'test')).toThrow('test: empty input');
    });

    it('throws on invalid JSON', () => {
      expect(() => parseOscalDocument('not json', 'catalog', 'test')).toThrow('test: failed to parse JSON');
    });

    it('throws on wrong document type', () => {
      expect(() => parseOscalDocument('{"profile":{}}', 'catalog', 'test')).toThrow('test: expected catalog document');
    });

    it('returns the document when valid', () => {
      const result = parseOscalDocument('{"catalog":{"uuid":"123","metadata":{"title":"T","version":"1","oscal-version":"1.1.2","last-modified":"now"}}}', 'catalog', 'test');
      expect(result.uuid).toBe('123');
    });
  });

  describe('toKebabCase', () => {
    it('converts title to kebab case', () => {
      expect(toKebabCase('My Test Title', 'fallback')).toBe('my-test-title');
    });

    it('returns fallback for empty title', () => {
      expect(toKebabCase('', 'fallback')).toBe('fallback');
    });

    it('collapses consecutive dashes', () => {
      expect(toKebabCase('A -- B -- C', 'fb')).toBe('a-b-c');
    });

    it('strips leading and trailing dashes', () => {
      expect(toKebabCase('--hello--', 'fb')).toBe('hello');
    });

    it('truncates to 80 characters', () => {
      const longTitle = 'a'.repeat(100);
      expect(toKebabCase(longTitle, 'fb').length).toBe(80);
    });

    it('handles special characters', () => {
      expect(toKebabCase('Hello, World! (Test)', 'fb')).toBe('hello-world-test');
    });
  });
});

// ---------------------------------------------------------------------------
// Profile converter edge cases
// ---------------------------------------------------------------------------

describe('convertOscalProfileToHdf edge cases', () => {
  it('should throw on profile with no imports', async () => {
    const profileDoc = JSON.stringify({
      profile: {
        uuid: '123',
        metadata: { title: 'T', version: '1', 'oscal-version': '1.1.2', 'last-modified': 'now' },
        imports: [],
      },
    });
    const catalogDoc = JSON.stringify({
      catalog: {
        uuid: '456',
        metadata: { title: 'C', version: '1', 'oscal-version': '1.1.2', 'last-modified': 'now' },
        groups: [],
      },
    });
    await expect(convertOscalProfileToHdf(profileDoc, catalogDoc)).rejects.toThrow('no imports');
  });

  it('should throw on profile with multiple imports', async () => {
    const profileDoc = JSON.stringify({
      profile: {
        uuid: '123',
        metadata: { title: 'T', version: '1', 'oscal-version': '1.1.2', 'last-modified': 'now' },
        imports: [
          { href: 'catalog1.json' },
          { href: 'catalog2.json' },
        ],
      },
    });
    const catalogDoc = JSON.stringify({
      catalog: {
        uuid: '456',
        metadata: { title: 'C', version: '1', 'oscal-version': '1.1.2', 'last-modified': 'now' },
        groups: [],
      },
    });
    await expect(convertOscalProfileToHdf(profileDoc, catalogDoc)).rejects.toThrow('2 imports');
  });

  it('should handle profile that includes all controls', async () => {
    const profileDoc = JSON.stringify({
      profile: {
        uuid: '123',
        metadata: { title: 'All Controls Profile', version: '1', 'oscal-version': '1.1.2', 'last-modified': 'now' },
        imports: [{ href: 'catalog.json' }],
      },
    });
    const catalogDoc = JSON.stringify({
      catalog: {
        uuid: '456',
        metadata: { title: 'Catalog', version: '1', 'oscal-version': '1.1.2', 'last-modified': 'now' },
        groups: [{
          id: 'ac',
          title: 'Access Control',
          controls: [{
            id: 'ac-1',
            title: 'Policy',
            parts: [{ name: 'statement', prose: 'Develop policy.' }],
          }],
        }],
      },
    });
    const output = await convertOscalProfileToHdf(profileDoc, catalogDoc);
    const baseline = JSON.parse(output) as HDFBaseline;
    expect(baseline.requirements).toHaveLength(1);
    expect(baseline.requirements[0]!.id).toBe('AC-1');
  });

  it('should handle profile with exclude-controls', async () => {
    const profileDoc = JSON.stringify({
      profile: {
        uuid: '123',
        metadata: { title: 'Exclude Test', version: '1', 'oscal-version': '1.1.2', 'last-modified': 'now' },
        imports: [{
          href: 'catalog.json',
          'exclude-controls': [{ 'with-ids': ['ac-2'] }],
        }],
      },
    });
    const catalogDoc = JSON.stringify({
      catalog: {
        uuid: '456',
        metadata: { title: 'Catalog', version: '1', 'oscal-version': '1.1.2', 'last-modified': 'now' },
        groups: [{
          id: 'ac',
          title: 'Access Control',
          controls: [
            { id: 'ac-1', title: 'Policy', parts: [{ name: 'statement', prose: 'P1.' }] },
            { id: 'ac-2', title: 'Account Mgmt', parts: [{ name: 'statement', prose: 'P2.' }] },
            { id: 'ac-3', title: 'Access Enforcement', parts: [{ name: 'statement', prose: 'P3.' }] },
          ],
        }],
      },
    });
    const output = await convertOscalProfileToHdf(profileDoc, catalogDoc);
    const baseline = JSON.parse(output) as HDFBaseline;
    expect(baseline.requirements.map(r => r.id)).toEqual(['AC-1', 'AC-3']);
  });

  it('should apply parameter overrides to control prose', async () => {
    const profileDoc = JSON.stringify({
      profile: {
        uuid: '123',
        metadata: { title: 'Param Test', version: '1', 'oscal-version': '1.1.2', 'last-modified': 'now' },
        imports: [{ href: 'catalog.json' }],
        modify: {
          'set-parameters': [
            { 'param-id': 'ac-1_prm_1', values: ['annually'] },
          ],
        },
      },
    });
    const catalogDoc = JSON.stringify({
      catalog: {
        uuid: '456',
        metadata: { title: 'Catalog', version: '1', 'oscal-version': '1.1.2', 'last-modified': 'now' },
        groups: [{
          id: 'ac',
          title: 'Access Control',
          controls: [{
            id: 'ac-1',
            title: 'Policy',
            params: [{ id: 'ac-1_prm_1', label: 'frequency' }],
            parts: [{
              name: 'statement',
              prose: 'Review policy {{ insert: param, ac-1_prm_1 }}.',
            }],
          }],
        }],
      },
    });
    const output = await convertOscalProfileToHdf(profileDoc, catalogDoc);
    const baseline = JSON.parse(output) as HDFBaseline;
    const desc = baseline.requirements[0]!.descriptions?.find(d => d.label === 'default');
    expect(desc?.data).toContain('annually');
  });

  it('should handle profile with include-controls and specific with-ids', async () => {
    const profileDoc = JSON.stringify({
      profile: {
        uuid: '123',
        metadata: { title: 'Select Test', version: '1', 'oscal-version': '1.1.2', 'last-modified': 'now' },
        imports: [{
          href: 'catalog.json',
          'include-controls': [{ 'with-ids': ['ac-1'] }],
        }],
      },
    });
    const catalogDoc = JSON.stringify({
      catalog: {
        uuid: '456',
        metadata: { title: 'Catalog', version: '1', 'oscal-version': '1.1.2', 'last-modified': 'now' },
        groups: [{
          id: 'ac',
          title: 'Access Control',
          controls: [
            { id: 'ac-1', title: 'Policy', parts: [{ name: 'statement', prose: 'P1.' }] },
            { id: 'ac-2', title: 'Acct', parts: [{ name: 'statement', prose: 'P2.' }] },
          ],
        }],
      },
    });
    const output = await convertOscalProfileToHdf(profileDoc, catalogDoc);
    const baseline = JSON.parse(output) as HDFBaseline;
    expect(baseline.requirements).toHaveLength(1);
    expect(baseline.requirements[0]!.id).toBe('AC-1');
  });

  it('should handle catalog with top-level controls (outside groups)', async () => {
    const profileDoc = JSON.stringify({
      profile: {
        uuid: '123',
        metadata: { title: 'Top Level', version: '1', 'oscal-version': '1.1.2', 'last-modified': 'now' },
        imports: [{ href: 'catalog.json' }],
      },
    });
    const catalogDoc = JSON.stringify({
      catalog: {
        uuid: '456',
        metadata: { title: 'Catalog', version: '1', 'oscal-version': '1.1.2', 'last-modified': 'now' },
        controls: [
          { id: 'ac-1', title: 'Policy', parts: [{ name: 'statement', prose: 'P1.' }] },
        ],
      },
    });
    const output = await convertOscalProfileToHdf(profileDoc, catalogDoc);
    const baseline = JSON.parse(output) as HDFBaseline;
    expect(baseline.requirements).toHaveLength(1);
  });

  it('should handle profile with set-parameters with no values', async () => {
    const profileDoc = JSON.stringify({
      profile: {
        uuid: '123',
        metadata: { title: 'Empty Params', version: '1', 'oscal-version': '1.1.2', 'last-modified': 'now' },
        imports: [{ href: 'catalog.json' }],
        modify: {
          'set-parameters': [
            { 'param-id': 'ac-1_prm_1' },
          ],
        },
      },
    });
    const catalogDoc = JSON.stringify({
      catalog: {
        uuid: '456',
        metadata: { title: 'Catalog', version: '1', 'oscal-version': '1.1.2', 'last-modified': 'now' },
        groups: [{
          id: 'ac',
          title: 'Access Control',
          controls: [{ id: 'ac-1', title: 'Policy', params: [{ id: 'ac-1_prm_1', label: 'freq' }] }],
        }],
      },
    });
    const output = await convertOscalProfileToHdf(profileDoc, catalogDoc);
    const baseline = JSON.parse(output) as HDFBaseline;
    expect(baseline.requirements).toHaveLength(1);
  });

  it('should filter control enhancements in include-controls', async () => {
    const profileDoc = JSON.stringify({
      profile: {
        uuid: '123',
        metadata: { title: 'Enh Test', version: '1', 'oscal-version': '1.1.2', 'last-modified': 'now' },
        imports: [{
          href: 'catalog.json',
          'include-controls': [{ 'with-ids': ['ac-2', 'ac-2.1'] }],
        }],
      },
    });
    const catalogDoc = JSON.stringify({
      catalog: {
        uuid: '456',
        metadata: { title: 'Catalog', version: '1', 'oscal-version': '1.1.2', 'last-modified': 'now' },
        groups: [{
          id: 'ac',
          title: 'Access Control',
          controls: [{
            id: 'ac-2',
            title: 'Account',
            controls: [
              { id: 'ac-2.1', title: 'Automated Mgmt' },
              { id: 'ac-2.2', title: 'Removal' },
            ],
          }],
        }],
      },
    });
    const output = await convertOscalProfileToHdf(profileDoc, catalogDoc);
    const baseline = JSON.parse(output) as HDFBaseline;
    const ids = baseline.requirements.map(r => r.id);
    expect(ids).toContain('AC-2');
    expect(ids).toContain('AC-2 (1)');
    expect(ids).not.toContain('AC-2 (2)');
  });
}, 30000);

// ---------------------------------------------------------------------------
// SSP converter edge cases
// ---------------------------------------------------------------------------

describe('convertOscalSspToHdf edge cases', () => {
  it('should throw on wrong document type', async () => {
    await expect(
      convertOscalSspToHdf(JSON.stringify({ catalog: {} })),
    ).rejects.toThrow('not a system-security-plan');
  });

  it('should handle SSP with no system-characteristics', async () => {
    const doc = JSON.stringify({
      'system-security-plan': {
        uuid: '123',
        metadata: { title: 'Test SSP', version: '1', 'oscal-version': '1.1.2', 'last-modified': 'now' },
      },
    });
    const output = await convertOscalSspToHdf(doc);
    const system = JSON.parse(output) as HDFSystem;
    expect(system.name).toBe('Test SSP');
  });

  it('should use system-name over metadata title', async () => {
    const doc = JSON.stringify({
      'system-security-plan': {
        uuid: '123',
        metadata: { title: 'Metadata Title', version: '1', 'oscal-version': '1.1.2', 'last-modified': 'now' },
        'system-characteristics': { 'system-name': 'System Name' },
      },
    });
    const output = await convertOscalSspToHdf(doc);
    const system = JSON.parse(output) as HDFSystem;
    expect(system.name).toBe('System Name');
  });

  it('should fall back to oscal-ssp when no name found', async () => {
    const doc = JSON.stringify({
      'system-security-plan': {
        uuid: '123',
        metadata: { version: '1', 'oscal-version': '1.1.2', 'last-modified': 'now' },
      },
    });
    const output = await convertOscalSspToHdf(doc);
    const system = JSON.parse(output) as HDFSystem;
    expect(system.name).toBe('oscal-ssp');
  });

  it('should map security-impact-level to categorization level', async () => {
    const doc = JSON.stringify({
      'system-security-plan': {
        uuid: '123',
        metadata: { title: 'SSP', version: '1', 'oscal-version': '1.1.2', 'last-modified': 'now' },
        'system-characteristics': {
          'system-name': 'Test',
          'security-impact-level': {
            'security-objective-confidentiality': 'fips-199-moderate',
            'security-objective-integrity': 'fips-199-low',
            'security-objective-availability': 'fips-199-low',
          },
        },
      },
    });
    const output = await convertOscalSspToHdf(doc);
    const system = JSON.parse(output) as HDFSystem;
    expect(system.categorizationLevel).toBe('moderate');
  });

  it('should map high FIPS level', async () => {
    const doc = JSON.stringify({
      'system-security-plan': {
        uuid: '123',
        metadata: { title: 'SSP', version: '1', 'oscal-version': '1.1.2', 'last-modified': 'now' },
        'system-characteristics': {
          'system-name': 'Test',
          'security-impact-level': {
            'security-objective-confidentiality': 'high',
            'security-objective-integrity': 'low',
            'security-objective-availability': 'low',
          },
        },
      },
    });
    const output = await convertOscalSspToHdf(doc);
    const system = JSON.parse(output) as HDFSystem;
    expect(system.categorizationLevel).toBe('high');
  });

  it('should map security-sensitivity-level as fallback', async () => {
    const doc = JSON.stringify({
      'system-security-plan': {
        uuid: '123',
        metadata: { title: 'SSP', version: '1', 'oscal-version': '1.1.2', 'last-modified': 'now' },
        'system-characteristics': {
          'system-name': 'Test',
          'security-sensitivity-level': 'low',
        },
      },
    });
    const output = await convertOscalSspToHdf(doc);
    const system = JSON.parse(output) as HDFSystem;
    expect(system.categorizationLevel).toBe('low');
  });

  it('should handle medium as moderate in sensitivity level', async () => {
    const doc = JSON.stringify({
      'system-security-plan': {
        uuid: '123',
        metadata: { title: 'SSP', version: '1', 'oscal-version': '1.1.2', 'last-modified': 'now' },
        'system-characteristics': {
          'system-name': 'Test',
          'security-sensitivity-level': 'medium',
        },
      },
    });
    const output = await convertOscalSspToHdf(doc);
    const system = JSON.parse(output) as HDFSystem;
    expect(system.categorizationLevel).toBe('moderate');
  });

  it('should handle unknown sensitivity level', async () => {
    const doc = JSON.stringify({
      'system-security-plan': {
        uuid: '123',
        metadata: { title: 'SSP', version: '1', 'oscal-version': '1.1.2', 'last-modified': 'now' },
        'system-characteristics': {
          'system-name': 'Test',
          'security-sensitivity-level': 'unknown',
        },
      },
    });
    const output = await convertOscalSspToHdf(doc);
    const system = JSON.parse(output) as HDFSystem;
    expect(system.categorizationLevel).toBeUndefined();
  });

  it('should map authorization status from system status', async () => {
    for (const [state, expected] of [
      ['operational', 'authorized'],
      ['under-development', 'pendingAuthorization'],
      ['disposition', 'revoked'],
      ['other', 'notYetRequested'],
      ['unknown-state', undefined],
    ] as const) {
      const doc = JSON.stringify({
        'system-security-plan': {
          uuid: '123',
          metadata: { title: 'SSP', version: '1', 'oscal-version': '1.1.2', 'last-modified': 'now' },
          'system-characteristics': {
            'system-name': 'Test',
            status: { state },
          },
        },
      });
      const output = await convertOscalSspToHdf(doc);
      const system = JSON.parse(output) as HDFSystem;
      expect(system.authorizationStatus).toBe(expected);
    }
  });

  it('should map authorization-boundary description', async () => {
    const doc = JSON.stringify({
      'system-security-plan': {
        uuid: '123',
        metadata: { title: 'SSP', version: '1', 'oscal-version': '1.1.2', 'last-modified': 'now' },
        'system-characteristics': {
          'system-name': 'Test',
          description: 'System desc',
          'authorization-boundary': { description: 'Boundary desc' },
        },
      },
    });
    const output = await convertOscalSspToHdf(doc);
    const system = JSON.parse(output) as HDFSystem;
    expect(system.description).toContain('System desc');
    expect(system.description).toContain('Boundary desc');
    expect(system.boundaryDescription).toBe('Boundary desc');
  });

  it('should map system-ids', async () => {
    const doc = JSON.stringify({
      'system-security-plan': {
        uuid: '123',
        metadata: { title: 'SSP', version: '1', 'oscal-version': '1.1.2', 'last-modified': 'now' },
        'system-characteristics': {
          'system-name': 'Test',
          'system-ids': [{ id: 'SYS-001', 'identifier-type': 'https://fedramp.gov' }],
        },
      },
    });
    const output = await convertOscalSspToHdf(doc);
    const system = JSON.parse(output) as HDFSystem;
    expect(system.identifier).toBe('SYS-001');
    expect(system.identifierScheme).toBe('https://fedramp.gov');
  });

  it('should map OSCAL component types to HDF types', async () => {
    for (const [oscalType, expectedType] of [
      ['software', 'application'],
      ['this-system', 'application'],
      ['service', 'application'],
      ['hardware', 'host'],
      ['network', 'network'],
      ['database', 'database'],
      ['storage', 'artifact'],
      ['unknown', 'application'],
    ] as const) {
      const doc = JSON.stringify({
        'system-security-plan': {
          uuid: '123',
          metadata: { title: 'SSP', version: '1', 'oscal-version': '1.1.2', 'last-modified': 'now' },
          'system-implementation': {
            components: [{ uuid: 'comp-1', title: 'Comp', type: oscalType, description: 'Desc' }],
          },
        },
      });
      const output = await convertOscalSspToHdf(doc);
      const system = JSON.parse(output) as HDFSystem;
      expect(system.components[0]!.type).toBe(expectedType);
    }
  });

  it('should build component control map from control-implementation', async () => {
    const doc = JSON.stringify({
      'system-security-plan': {
        uuid: '123',
        metadata: { title: 'SSP', version: '1', 'oscal-version': '1.1.2', 'last-modified': 'now' },
        'system-implementation': {
          components: [{ uuid: 'comp-1', title: 'Web App', type: 'software' }],
        },
        'control-implementation': {
          'implemented-requirements': [
            {
              'control-id': 'ac-1',
              'by-components': [{ 'component-uuid': 'comp-1', description: 'Impl' }],
            },
            {
              'control-id': 'ac-2',
              statements: [
                { 'by-components': [{ 'component-uuid': 'comp-1', description: 'Impl' }] },
              ],
            },
          ],
        },
      },
    });
    const output = await convertOscalSspToHdf(doc);
    const system = JSON.parse(output) as HDFSystem;
    const comp = system.components[0]!;
    expect((comp as any).baselineRefs).toContain('AC-1');
    expect((comp as any).baselineRefs).toContain('AC-2');
  });

  it('should handle all unknown FIPS levels returning null categorization', async () => {
    const doc = JSON.stringify({
      'system-security-plan': {
        uuid: '123',
        metadata: { title: 'SSP', version: '1', 'oscal-version': '1.1.2', 'last-modified': 'now' },
        'system-characteristics': {
          'system-name': 'Test',
          'security-impact-level': {
            'security-objective-confidentiality': 'unknown',
            'security-objective-integrity': '',
            'security-objective-availability': '',
          },
        },
      },
    });
    const output = await convertOscalSspToHdf(doc);
    const system = JSON.parse(output) as HDFSystem;
    expect(system.categorizationLevel).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// SAP converter edge cases
// ---------------------------------------------------------------------------

describe('convertOscalSapToHdf edge cases', () => {
  it('should throw on wrong document type', async () => {
    await expect(
      convertOscalSapToHdf(JSON.stringify({ catalog: {} })),
    ).rejects.toThrow('not an assessment-plan');
  });

  it('should handle SAP with no reviewed-controls', async () => {
    const doc = JSON.stringify({
      'assessment-plan': {
        uuid: '123',
        metadata: { title: 'SAP', version: '1', 'oscal-version': '1.1.2', 'last-modified': 'now' },
        'import-ssp': { href: 'ssp.json' },
      },
    });
    const output = await convertOscalSapToHdf(doc);
    const plan = JSON.parse(output) as HDFPlan;
    expect(plan.assessments).toHaveLength(1);
    expect(plan.assessments[0]!.baselineRef).toBe('oscal-assessment-plan');
  });

  it('should handle include-all in control-selections', async () => {
    const doc = JSON.stringify({
      'assessment-plan': {
        uuid: '123',
        metadata: { title: 'SAP', version: '1', 'oscal-version': '1.1.2', 'last-modified': 'now' },
        'import-ssp': { href: 'ssp.json' },
        'reviewed-controls': {
          'control-selections': [{
            'include-all': {},
          }],
        },
      },
    });
    const output = await convertOscalSapToHdf(doc);
    const plan = JSON.parse(output) as HDFPlan;
    expect(plan.assessments[0]!.baselineRef).toBe('ssp.json');
  });

  it('should handle include-all without import-ssp', async () => {
    const doc = JSON.stringify({
      'assessment-plan': {
        uuid: '123',
        metadata: { title: 'SAP', version: '1', 'oscal-version': '1.1.2', 'last-modified': 'now' },
        'reviewed-controls': {
          'control-selections': [{
            'include-all': {},
          }],
        },
      },
    });
    const output = await convertOscalSapToHdf(doc);
    const plan = JSON.parse(output) as HDFPlan;
    expect(plan.assessments[0]!.baselineRef).toBe('all-controls');
  });

  it('should handle include-controls in control-selections', async () => {
    const doc = JSON.stringify({
      'assessment-plan': {
        uuid: '123',
        metadata: { title: 'SAP', version: '1', 'oscal-version': '1.1.2', 'last-modified': 'now' },
        'reviewed-controls': {
          'control-selections': [{
            'include-controls': [{ 'control-id': 'ac-1' }, { 'control-id': 'ac-2' }],
          }],
        },
      },
    });
    const output = await convertOscalSapToHdf(doc);
    const plan = JSON.parse(output) as HDFPlan;
    expect(plan.assessments[0]!.baselineRef).toBe('AC-1,AC-2');
  });

  it('should handle control-objective-selections', async () => {
    const doc = JSON.stringify({
      'assessment-plan': {
        uuid: '123',
        metadata: { title: 'SAP', version: '1', 'oscal-version': '1.1.2', 'last-modified': 'now' },
        'reviewed-controls': {
          'control-objective-selections': [{
            'include-objectives': [{ 'objective-id': 'ac-1.a.1_obj.1' }],
            description: 'Objective test',
          }],
        },
      },
    });
    const output = await convertOscalSapToHdf(doc);
    const plan = JSON.parse(output) as HDFPlan;
    expect(plan.assessments).toHaveLength(1);
    expect(plan.assessments[0]!.description).toBe('Objective test');
  });

  it('should handle control-objective-selections with include-all', async () => {
    const doc = JSON.stringify({
      'assessment-plan': {
        uuid: '123',
        metadata: { title: 'SAP', version: '1', 'oscal-version': '1.1.2', 'last-modified': 'now' },
        'import-ssp': { href: 'ssp.json' },
        'reviewed-controls': {
          'control-objective-selections': [{
            'include-all': {},
          }],
        },
      },
    });
    const output = await convertOscalSapToHdf(doc);
    const plan = JSON.parse(output) as HDFPlan;
    expect(plan.assessments[0]!.baselineRef).toBe('ssp.json');
  });

  it('should handle control-objective-selections include-all without import-ssp', async () => {
    const doc = JSON.stringify({
      'assessment-plan': {
        uuid: '123',
        metadata: { title: 'SAP', version: '1', 'oscal-version': '1.1.2', 'last-modified': 'now' },
        'reviewed-controls': {
          'control-objective-selections': [{
            'include-all': {},
          }],
        },
      },
    });
    const output = await convertOscalSapToHdf(doc);
    const plan = JSON.parse(output) as HDFPlan;
    expect(plan.assessments[0]!.baselineRef).toBe('all-objectives');
  });

  it('should extract runner config from assessment-platforms', async () => {
    const doc = JSON.stringify({
      'assessment-plan': {
        uuid: '123',
        metadata: { title: 'SAP', version: '1', 'oscal-version': '1.1.2', 'last-modified': 'now' },
        'assessment-assets': {
          'assessment-platforms': [{ uuid: 'p1', title: 'Nessus Scanner' }],
        },
        'reviewed-controls': {
          'control-selections': [{ 'include-all': {} }],
        },
      },
    });
    const output = await convertOscalSapToHdf(doc);
    const plan = JSON.parse(output) as HDFPlan;
    expect(plan.assessments[0]!.runner?.name).toBe('Nessus Scanner');
  });

  it('should extract runner config from components fallback', async () => {
    const doc = JSON.stringify({
      'assessment-plan': {
        uuid: '123',
        metadata: { title: 'SAP', version: '1', 'oscal-version': '1.1.2', 'last-modified': 'now' },
        'assessment-assets': {
          components: [{
            uuid: 'c1',
            title: 'Scanner',
            type: 'software',
            props: [{ name: 'version', value: '10.0' }],
          }],
        },
        'reviewed-controls': {
          'control-selections': [{ 'include-all': {} }],
        },
      },
    });
    const output = await convertOscalSapToHdf(doc);
    const plan = JSON.parse(output) as HDFPlan;
    expect(plan.assessments[0]!.runner?.name).toBe('Scanner');
    expect(plan.assessments[0]!.runner?.version).toBe('10.0');
  });

  it('should extract target selector from assessment-subjects', async () => {
    const doc = JSON.stringify({
      'assessment-plan': {
        uuid: '123',
        metadata: { title: 'SAP', version: '1', 'oscal-version': '1.1.2', 'last-modified': 'now' },
        'assessment-subjects': [
          { type: 'component', 'include-all': {} },
          { type: 'inventory-item' },
        ],
        'reviewed-controls': {
          'control-selections': [{ 'include-all': {} }],
        },
      },
    });
    const output = await convertOscalSapToHdf(doc);
    const plan = JSON.parse(output) as HDFPlan;
    expect(plan.assessments[0]!.targetSelector).toBeDefined();
    expect(plan.assessments[0]!.targetSelector!['subject-type']).toBe('component,inventory-item');
    expect(plan.assessments[0]!.targetSelector!['include-component']).toBe('all');
  });

  it('should determine plan type from assessment-type prop', async () => {
    for (const [aType, expected] of [
      ['automated', 'automated'],
      ['manual', 'manual'],
    ] as const) {
      const doc = JSON.stringify({
        'assessment-plan': {
          uuid: '123',
          metadata: {
            title: 'SAP',
            version: '1',
            'oscal-version': '1.1.2',
            'last-modified': 'now',
            props: [{ name: 'assessment-type', value: aType }],
          },
          'reviewed-controls': {
            'control-selections': [{ 'include-all': {} }],
          },
        },
      });
      const output = await convertOscalSapToHdf(doc);
      const plan = JSON.parse(output) as HDFPlan;
      expect(plan.type).toBe(expected);
    }
  });

  it('should determine hybrid plan type from tasks', async () => {
    const doc = JSON.stringify({
      'assessment-plan': {
        uuid: '123',
        metadata: { title: 'SAP', version: '1', 'oscal-version': '1.1.2', 'last-modified': 'now' },
        tasks: [{ uuid: 't1', type: 'milestone', title: 'Task 1' }],
        'reviewed-controls': {
          'control-selections': [{ 'include-all': {} }],
        },
      },
    });
    const output = await convertOscalSapToHdf(doc);
    const plan = JSON.parse(output) as HDFPlan;
    expect(plan.type).toBe('hybrid');
  });

  it('should build description from metadata remarks', async () => {
    const doc = JSON.stringify({
      'assessment-plan': {
        uuid: '123',
        metadata: {
          title: 'SAP',
          version: '1',
          'oscal-version': '1.1.2',
          'last-modified': 'now',
          remarks: 'Important notes',
        },
        'reviewed-controls': {
          'control-selections': [{ 'include-all': {} }],
        },
      },
    });
    const output = await convertOscalSapToHdf(doc);
    const plan = JSON.parse(output) as HDFPlan;
    expect(plan.description).toContain('Important notes');
  });

  it('should build description from terms-and-conditions', async () => {
    const doc = JSON.stringify({
      'assessment-plan': {
        uuid: '123',
        metadata: {
          title: 'SAP',
          version: '1',
          'oscal-version': '1.1.2',
          'last-modified': 'now',
          remarks: 'Notes',
        },
        'terms-and-conditions': {
          parts: [{ name: 'terms', prose: 'Must comply with standards.' }],
        },
        'reviewed-controls': {
          'control-selections': [{ 'include-all': {} }],
        },
      },
    });
    const output = await convertOscalSapToHdf(doc);
    const plan = JSON.parse(output) as HDFPlan;
    expect(plan.description).toContain('Terms and Conditions');
    expect(plan.description).toContain('Must comply with standards');
  });

  it('should handle empty reviewed-controls with fallback assessment', async () => {
    const doc = JSON.stringify({
      'assessment-plan': {
        uuid: '123',
        metadata: { title: 'SAP', version: '1', 'oscal-version': '1.1.2', 'last-modified': 'now' },
        'reviewed-controls': {},
      },
    });
    const output = await convertOscalSapToHdf(doc);
    const plan = JSON.parse(output) as HDFPlan;
    expect(plan.assessments).toHaveLength(1);
    expect(plan.assessments[0]!.baselineRef).toBe('oscal-assessment-plan');
  });

  it('should handle control-selection with description', async () => {
    const doc = JSON.stringify({
      'assessment-plan': {
        uuid: '123',
        metadata: { title: 'SAP', version: '1', 'oscal-version': '1.1.2', 'last-modified': 'now' },
        'reviewed-controls': {
          'control-selections': [{
            description: 'Selected for annual review',
            'include-all': {},
          }],
        },
      },
    });
    const output = await convertOscalSapToHdf(doc);
    const plan = JSON.parse(output) as HDFPlan;
    expect(plan.assessments[0]!.description).toBe('Selected for annual review');
  });

  it('should handle control-selection falling back to import-ssp', async () => {
    const doc = JSON.stringify({
      'assessment-plan': {
        uuid: '123',
        metadata: { title: 'SAP', version: '1', 'oscal-version': '1.1.2', 'last-modified': 'now' },
        'import-ssp': { href: 'ssp-ref.json' },
        'reviewed-controls': {
          'control-selections': [{}],
        },
      },
    });
    const output = await convertOscalSapToHdf(doc);
    const plan = JSON.parse(output) as HDFPlan;
    expect(plan.assessments[0]!.baselineRef).toBe('ssp-ref.json');
  });

  it('should fallback to oscal-assessment-plan baselineRef', async () => {
    const doc = JSON.stringify({
      'assessment-plan': {
        uuid: '123',
        metadata: { title: 'SAP', version: '1', 'oscal-version': '1.1.2', 'last-modified': 'now' },
        'reviewed-controls': {
          'control-selections': [{}],
        },
      },
    });
    const output = await convertOscalSapToHdf(doc);
    const plan = JSON.parse(output) as HDFPlan;
    expect(plan.assessments[0]!.baselineRef).toBe('oscal-assessment-plan');
  });

  it('should handle empty assessment-subjects', async () => {
    const doc = JSON.stringify({
      'assessment-plan': {
        uuid: '123',
        metadata: { title: 'SAP', version: '1', 'oscal-version': '1.1.2', 'last-modified': 'now' },
        'assessment-subjects': [],
        'reviewed-controls': {
          'control-selections': [{ 'include-all': {} }],
        },
      },
    });
    const output = await convertOscalSapToHdf(doc);
    const plan = JSON.parse(output) as HDFPlan;
    expect(plan.assessments[0]!.targetSelector).toBeUndefined();
  });

  it('should handle assessment-subject with no type', async () => {
    const doc = JSON.stringify({
      'assessment-plan': {
        uuid: '123',
        metadata: { title: 'SAP', version: '1', 'oscal-version': '1.1.2', 'last-modified': 'now' },
        'assessment-subjects': [{}],
        'reviewed-controls': {
          'control-selections': [{ 'include-all': {} }],
        },
      },
    });
    const output = await convertOscalSapToHdf(doc);
    const plan = JSON.parse(output) as HDFPlan;
    // With no type or include-all, selector is empty -> null -> undefined
    expect(plan.assessments[0]!.targetSelector).toBeUndefined();
  });

  it('should handle assessment-assets with no platforms and no components', async () => {
    const doc = JSON.stringify({
      'assessment-plan': {
        uuid: '123',
        metadata: { title: 'SAP', version: '1', 'oscal-version': '1.1.2', 'last-modified': 'now' },
        'assessment-assets': {},
        'reviewed-controls': {
          'control-selections': [{ 'include-all': {} }],
        },
      },
    });
    const output = await convertOscalSapToHdf(doc);
    const plan = JSON.parse(output) as HDFPlan;
    expect(plan.assessments[0]!.runner).toBeUndefined();
  });

  it('should handle assessment-platform with no title', async () => {
    const doc = JSON.stringify({
      'assessment-plan': {
        uuid: '123',
        metadata: { title: 'SAP', version: '1', 'oscal-version': '1.1.2', 'last-modified': 'now' },
        'assessment-assets': {
          'assessment-platforms': [{ uuid: 'p1' }],
        },
        'reviewed-controls': {
          'control-selections': [{ 'include-all': {} }],
        },
      },
    });
    const output = await convertOscalSapToHdf(doc);
    const plan = JSON.parse(output) as HDFPlan;
    expect(plan.assessments[0]!.runner).toBeDefined();
    expect(plan.assessments[0]!.runner?.name).toBeUndefined();
  });

  it('should handle components with no version prop', async () => {
    const doc = JSON.stringify({
      'assessment-plan': {
        uuid: '123',
        metadata: { title: 'SAP', version: '1', 'oscal-version': '1.1.2', 'last-modified': 'now' },
        'assessment-assets': {
          components: [{ uuid: 'c1', title: 'Scanner', type: 'software' }],
        },
        'reviewed-controls': {
          'control-selections': [{ 'include-all': {} }],
        },
      },
    });
    const output = await convertOscalSapToHdf(doc);
    const plan = JSON.parse(output) as HDFPlan;
    expect(plan.assessments[0]!.runner?.name).toBe('Scanner');
    expect(plan.assessments[0]!.runner?.version).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// POA&M converter edge cases
// ---------------------------------------------------------------------------

describe('convertOscalPoamToHdf edge cases', () => {
  it('should throw on wrong document type', async () => {
    await expect(
      convertOscalPoamToHdf(JSON.stringify({ catalog: {} })),
    ).rejects.toThrow('not a plan-of-action-and-milestones');
  });

  it('should handle POAM item with no related-risks', async () => {
    const doc = JSON.stringify({
      'plan-of-action-and-milestones': {
        uuid: '123',
        metadata: {
          title: 'POAM',
          version: '1',
          'oscal-version': '1.1.2',
          'last-modified': '2024-01-01T00:00:00Z',
          'responsible-parties': [{ 'role-id': 'prepared-by', 'party-uuids': ['user-1'] }],
        },
        'poam-items': [{
          uuid: 'item-1',
          title: 'Finding 1',
          description: 'A finding',
        }],
      },
    });
    const output = await convertOscalPoamToHdf(doc);
    const amendments = JSON.parse(output) as HDFAmendments;
    expect(amendments.overrides).toHaveLength(1);
    expect(amendments.overrides[0]!.status).toBe('failed');
  });

  it('should extract requirement ID from POAM-ID prop', async () => {
    const doc = JSON.stringify({
      'plan-of-action-and-milestones': {
        uuid: '123',
        metadata: {
          title: 'POAM',
          version: '1',
          'oscal-version': '1.1.2',
          'last-modified': '2024-01-01T00:00:00Z',
        },
        'poam-items': [{
          uuid: 'item-1',
          title: 'Finding 1',
          description: 'Desc',
          props: [{ name: 'POAM-ID', value: 'V-12345' }],
        }],
      },
    });
    const output = await convertOscalPoamToHdf(doc);
    const amendments = JSON.parse(output) as HDFAmendments;
    expect(amendments.overrides[0]!.requirementId).toBe('V-12345');
  });

  it('should fall back to title for requirement ID', async () => {
    const doc = JSON.stringify({
      'plan-of-action-and-milestones': {
        uuid: '123',
        metadata: {
          title: 'POAM',
          version: '1',
          'oscal-version': '1.1.2',
          'last-modified': '2024-01-01T00:00:00Z',
        },
        'poam-items': [{
          uuid: 'item-1',
          title: 'AC-1 Finding',
        }],
      },
    });
    const output = await convertOscalPoamToHdf(doc);
    const amendments = JSON.parse(output) as HDFAmendments;
    expect(amendments.overrides[0]!.requirementId).toBe('AC-1 Finding');
  });

  it('should fall back to unknown for requirement ID', async () => {
    const doc = JSON.stringify({
      'plan-of-action-and-milestones': {
        uuid: '123',
        metadata: {
          title: 'POAM',
          version: '1',
          'oscal-version': '1.1.2',
          'last-modified': '2024-01-01T00:00:00Z',
        },
        'poam-items': [{ uuid: 'item-1' }],
      },
    });
    const output = await convertOscalPoamToHdf(doc);
    const amendments = JSON.parse(output) as HDFAmendments;
    expect(amendments.overrides[0]!.requirementId).toBe('unknown');
  });

  it('should extract control ID from risk impacted-control-id', async () => {
    const doc = JSON.stringify({
      'plan-of-action-and-milestones': {
        uuid: '123',
        metadata: {
          title: 'POAM',
          version: '1',
          'oscal-version': '1.1.2',
          'last-modified': '2024-01-01T00:00:00Z',
        },
        risks: [{
          uuid: 'risk-1',
          title: 'Risk',
          status: 'open',
          props: [{ name: 'impacted-control-id', value: 'ac-2' }],
        }],
        'poam-items': [{
          uuid: 'item-1',
          title: 'Finding',
          'related-risks': [{ 'risk-uuid': 'risk-1' }],
        }],
      },
    });
    const output = await convertOscalPoamToHdf(doc);
    const amendments = JSON.parse(output) as HDFAmendments;
    expect(amendments.overrides[0]!.requirementId).toBe('AC-2');
  });

  it('should map risk status to override status', async () => {
    const doc = JSON.stringify({
      'plan-of-action-and-milestones': {
        uuid: '123',
        metadata: {
          title: 'POAM',
          version: '1',
          'oscal-version': '1.1.2',
          'last-modified': '2024-01-01T00:00:00Z',
        },
        risks: [{
          uuid: 'risk-1',
          title: 'Risk',
          status: 'closed',
        }],
        'poam-items': [{
          uuid: 'item-1',
          title: 'Finding',
          'related-risks': [{ 'risk-uuid': 'risk-1' }],
        }],
      },
    });
    const output = await convertOscalPoamToHdf(doc);
    const amendments = JSON.parse(output) as HDFAmendments;
    expect(amendments.overrides[0]!.status).toBe('passed');
  });

  it('should extract milestones from risk remediations', async () => {
    const doc = JSON.stringify({
      'plan-of-action-and-milestones': {
        uuid: '123',
        metadata: {
          title: 'POAM',
          version: '1',
          'oscal-version': '1.1.2',
          'last-modified': '2024-01-01T00:00:00Z',
        },
        risks: [{
          uuid: 'risk-1',
          title: 'Risk',
          status: 'open',
          remediations: [
            { lifecycle: 'planned', title: 'Fix', description: 'Apply patch' },
            { lifecycle: 'completed', title: 'Done', description: 'Already fixed' },
          ],
        }],
        'poam-items': [{
          uuid: 'item-1',
          title: 'Finding',
          'related-risks': [{ 'risk-uuid': 'risk-1' }],
        }],
      },
    });
    const output = await convertOscalPoamToHdf(doc);
    const amendments = JSON.parse(output) as HDFAmendments;
    const milestones = amendments.overrides[0]!.milestones ?? [];
    // Only planned lifecycle should be included
    expect(milestones).toHaveLength(1);
    expect(milestones[0]!.description).toContain('Fix');
    expect(milestones[0]!.description).toContain('Apply patch');
  });

  it('should extract appliedBy from prepared-by responsible-party', async () => {
    const doc = JSON.stringify({
      'plan-of-action-and-milestones': {
        uuid: '123',
        metadata: {
          title: 'POAM',
          version: '1',
          'oscal-version': '1.1.2',
          'last-modified': '2024-01-01T00:00:00Z',
          'responsible-parties': [
            { 'role-id': 'prepared-by', 'party-uuids': ['user-abc'] },
          ],
        },
        'poam-items': [{ uuid: 'item-1', title: 'F' }],
      },
    });
    const output = await convertOscalPoamToHdf(doc);
    const amendments = JSON.parse(output) as HDFAmendments;
    expect(amendments.appliedBy?.identifier).toBe('user-abc');
  });

  it('should fall back to first responsible party', async () => {
    const doc = JSON.stringify({
      'plan-of-action-and-milestones': {
        uuid: '123',
        metadata: {
          title: 'POAM',
          version: '1',
          'oscal-version': '1.1.2',
          'last-modified': '2024-01-01T00:00:00Z',
          'responsible-parties': [
            { 'role-id': 'other-role', 'party-uuids': ['user-xyz'] },
          ],
        },
        'poam-items': [{ uuid: 'item-1', title: 'F' }],
      },
    });
    const output = await convertOscalPoamToHdf(doc);
    const amendments = JSON.parse(output) as HDFAmendments;
    // poamItemAppliedBy uses prepared-by first, then first party
    expect(amendments.overrides[0]!.appliedBy?.identifier).toBe('user-xyz');
  });

  it('should fall back to system appliedBy when no responsible-parties', async () => {
    const doc = JSON.stringify({
      'plan-of-action-and-milestones': {
        uuid: '123',
        metadata: {
          title: 'POAM',
          version: '1',
          'oscal-version': '1.1.2',
          'last-modified': '2024-01-01T00:00:00Z',
        },
        'poam-items': [{ uuid: 'item-1', title: 'F' }],
      },
    });
    const output = await convertOscalPoamToHdf(doc);
    const amendments = JSON.parse(output) as HDFAmendments;
    expect(amendments.overrides[0]!.appliedBy?.identifier).toBe('oscal-poam-converter');
  });

  it('should use item description as reason, falling back to title', async () => {
    const doc = JSON.stringify({
      'plan-of-action-and-milestones': {
        uuid: '123',
        metadata: {
          title: 'POAM',
          version: '1',
          'oscal-version': '1.1.2',
          'last-modified': '2024-01-01T00:00:00Z',
        },
        'poam-items': [{ uuid: 'item-1', title: 'My Title' }],
      },
    });
    const output = await convertOscalPoamToHdf(doc);
    const amendments = JSON.parse(output) as HDFAmendments;
    expect(amendments.overrides[0]!.reason).toBe('My Title');
  });

  it('should fall back to default reason', async () => {
    const doc = JSON.stringify({
      'plan-of-action-and-milestones': {
        uuid: '123',
        metadata: {
          title: 'POAM',
          version: '1',
          'oscal-version': '1.1.2',
          'last-modified': '2024-01-01T00:00:00Z',
        },
        'poam-items': [{ uuid: 'item-1' }],
      },
    });
    const output = await convertOscalPoamToHdf(doc);
    const amendments = JSON.parse(output) as HDFAmendments;
    expect(amendments.overrides[0]!.reason).toBe('POA&M item');
  });

  it('should handle poamItemAppliedAt with invalid date', async () => {
    const doc = JSON.stringify({
      'plan-of-action-and-milestones': {
        uuid: '123',
        metadata: {
          title: 'POAM',
          version: '1',
          'oscal-version': '1.1.2',
          'last-modified': 'not-a-date',
        },
        'poam-items': [{ uuid: 'item-1', title: 'F' }],
      },
    });
    const output = await convertOscalPoamToHdf(doc);
    const amendments = JSON.parse(output) as HDFAmendments;
    // Should still produce output (falls back to new Date())
    expect(amendments.overrides[0]!.appliedAt).toBeTruthy();
  });

  it('should extract systemRef from import-ssp', async () => {
    const doc = JSON.stringify({
      'plan-of-action-and-milestones': {
        uuid: '123',
        metadata: {
          title: 'POAM',
          version: '1',
          'oscal-version': '1.1.2',
          'last-modified': '2024-01-01T00:00:00Z',
        },
        'import-ssp': { href: 'ssp-ref.json' },
        'poam-items': [{ uuid: 'item-1', title: 'F' }],
      },
    });
    const output = await convertOscalPoamToHdf(doc);
    const amendments = JSON.parse(output) as HDFAmendments;
    expect(amendments.systemRef).toBe('ssp-ref.json');
  });

  it('should handle risk with unrecognized status', async () => {
    const doc = JSON.stringify({
      'plan-of-action-and-milestones': {
        uuid: '123',
        metadata: {
          title: 'POAM',
          version: '1',
          'oscal-version': '1.1.2',
          'last-modified': '2024-01-01T00:00:00Z',
        },
        risks: [{
          uuid: 'risk-1',
          title: 'Risk',
          status: 'investigating',
        }],
        'poam-items': [{
          uuid: 'item-1',
          title: 'Finding',
          'related-risks': [{ 'risk-uuid': 'risk-1' }],
        }],
      },
    });
    const output = await convertOscalPoamToHdf(doc);
    const amendments = JSON.parse(output) as HDFAmendments;
    // oscalStatusToHdf returns undefined for 'investigating', so falls through to default 'failed'
    expect(amendments.overrides[0]!.status).toBe('failed');
  });
});

// ---------------------------------------------------------------------------
// Component converter edge cases
// ---------------------------------------------------------------------------

describe('convertOscalComponentToHdf edge cases', () => {
  it('should throw when document has no components', async () => {
    const doc = JSON.stringify({
      'component-definition': {
        uuid: '123',
        metadata: { title: 'Empty', version: '1', 'oscal-version': '1.1.2', 'last-modified': 'now' },
        components: [],
      },
    });
    await expect(convertOscalComponentToHdf(doc)).rejects.toThrow('no components');
  });

  it('should throw when wrong document type', async () => {
    await expect(
      convertOscalComponentToHdf(JSON.stringify({ catalog: {} })),
    ).rejects.toThrow('not a component-definition');
  });

  it('should handle component with no control-implementations', async () => {
    const doc = JSON.stringify({
      'component-definition': {
        uuid: '123',
        metadata: { title: 'Comp Def', version: '1', 'oscal-version': '1.1.2', 'last-modified': 'now' },
        components: [{
          uuid: 'c1',
          title: 'My Component',
          type: 'software',
        }],
      },
    });
    const output = await convertOscalComponentToHdf(doc);
    const baseline = JSON.parse(output) as HDFBaseline;
    expect(baseline.requirements).toHaveLength(0);
    expect(baseline.name).toContain('my-component');
  });

  it('should handle implemented-requirement with statements', async () => {
    const doc = JSON.stringify({
      'component-definition': {
        uuid: '123',
        metadata: { title: 'Comp Def', version: '1', 'oscal-version': '1.1.2', 'last-modified': 'now' },
        components: [{
          uuid: 'c1',
          title: 'Component',
          type: 'software',
          'control-implementations': [{
            uuid: 'ci1',
            source: 'catalog.json',
            'implemented-requirements': [{
              uuid: 'ir1',
              'control-id': 'ac-1',
              description: 'Main desc',
              statements: [
                {
                  'statement-id': 'ac-1_smt.a',
                  description: 'Statement desc',
                  remarks: 'Remarks here',
                },
              ],
            }],
          }],
        }],
      },
    });
    const output = await convertOscalComponentToHdf(doc);
    const baseline = JSON.parse(output) as HDFBaseline;
    const req = baseline.requirements[0]!;
    expect(req.descriptions!.length).toBeGreaterThanOrEqual(3);
    const labels = req.descriptions!.map(d => d.label);
    expect(labels).toContain('ac-1_smt.a');
    expect(labels).toContain('ac-1_smt.a-remarks');
  });
});
