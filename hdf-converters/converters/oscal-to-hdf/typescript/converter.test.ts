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
import type { HdfResults, HdfBaseline } from '@mitre/hdf-schema';
import type { HdfSystem } from '@mitre/hdf-schema';
import type { HdfPlan } from '@mitre/hdf-schema';
import type { HdfAmendments } from '@mitre/hdf-schema';

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
    const baseline = JSON.parse(output) as HdfBaseline;

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
    const baseline = JSON.parse(output) as HdfBaseline;

    // Control families with controls in moderate resolved catalog
    expect(baseline.groups!.length).toBeGreaterThanOrEqual(18);
    expect(baseline.groups?.[0]?.id).toBe('ac');
    expect(baseline.groups?.[0]?.title).toBe('Access Control');
  });

  it('should produce AC-1 with correct descriptions', async () => {
    const output = await convertOscalCatalogToHdf(
      loadFixture('catalog-moderate-resolved.json'),
    );
    const baseline = JSON.parse(output) as HdfBaseline;

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
    const baseline = JSON.parse(output) as HdfBaseline;

    const ac21 = baseline.requirements.find(r => r.id === 'AC-2 (1)');
    expect(ac21).toBeDefined();
    expect(ac21!.title).toBeTruthy();
  });

  it('should produce valid round-trip JSON', async () => {
    const output = await convertOscalCatalogToHdf(
      loadFixture('catalog-moderate-resolved.json'),
    );
    const baseline = JSON.parse(output) as HdfBaseline;
    const roundtrip = JSON.parse(JSON.stringify(baseline)) as HdfBaseline;
    expect(roundtrip.name).toBe(baseline.name);
    expect(roundtrip.requirements).toHaveLength(baseline.requirements.length);
  });

  it('should group references pointing to valid requirement IDs', async () => {
    const output = await convertOscalCatalogToHdf(
      loadFixture('catalog-moderate-resolved.json'),
    );
    const baseline = JSON.parse(output) as HdfBaseline;

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
    const baseline = JSON.parse(output) as HdfBaseline;
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

    const profileBaseline = JSON.parse(profileOutput) as HdfBaseline;
    const catalogBaseline = JSON.parse(catalogOutput) as HdfBaseline;

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
    const baseline = JSON.parse(output) as HdfBaseline;
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
}, { timeout: 30000 });

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
    const baseline = JSON.parse(output) as HdfBaseline;

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
    const system = JSON.parse(output) as HdfSystem;

    expect(system.name).toBeTruthy();
    expect(system.integrity?.algorithm).toBe('sha256');
    expect(system.generator?.name).toBe('hdf-converters');
    expect(system.components).toBeDefined();
  });

  it('should convert SSP FedRAMP fixture', async () => {
    const output = await convertOscalSspToHdf(loadFixture('ssp-fedramp.json'));
    const system = JSON.parse(output) as HdfSystem;

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
    const plan = JSON.parse(output) as HdfPlan;

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
    const amendments = JSON.parse(output) as HdfAmendments;

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
    const results = JSON.parse(output) as HdfResults;

    expect(results.baselines).toBeDefined();
    expect(results.baselines.length).toBeGreaterThan(0);

    expect(results.generator?.name).toBe('oscal-assessment-results-to-hdf');
    expect(results.tool?.name).toBe('OSCAL Assessment Results');
    expect(results.planRef).toBeTruthy();
  });

  it('should have requirements with NIST-notation IDs', async () => {
    const output = await convertOscalSarToHdf(loadFixture('sar-fedramp.json'));
    const results = JSON.parse(output) as HdfResults;

    const firstBaseline = results.baselines[0]!;
    expect(firstBaseline.requirements.length).toBeGreaterThan(0);

    for (const req of firstBaseline.requirements) {
      expect(req.id).toMatch(/^[A-Z]{2}-\d+/);
    }
  });

  it('should map satisfied/not-satisfied statuses', async () => {
    const output = await convertOscalSarToHdf(loadFixture('sar-fedramp.json'));
    const results = JSON.parse(output) as HdfResults;

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
    const results = JSON.parse(output) as HdfResults;

    const firstBaseline = results.baselines[0]!;
    for (const req of firstBaseline.requirements) {
      const hasDefault = req.descriptions?.some(d => d.label === 'default');
      expect(hasDefault).toBe(true);
    }
  });

  it('should have multiple result sets (baselines)', async () => {
    const output = await convertOscalSarToHdf(loadFixture('sar-fedramp.json'));
    const results = JSON.parse(output) as HdfResults;

    // FedRAMP SAR fixture has 3 result sets
    expect(results.baselines).toHaveLength(3);
  });

  it('should produce valid round-trip JSON', async () => {
    const output = await convertOscalSarToHdf(loadFixture('sar-fedramp.json'));
    const results = JSON.parse(output) as HdfResults;
    const roundtrip = JSON.parse(JSON.stringify(results)) as HdfResults;
    expect(roundtrip.baselines).toHaveLength(results.baselines.length);
    expect(roundtrip.generator?.name).toBe(results.generator?.name);
  });

  it('should include integrity on baselines', async () => {
    const output = await convertOscalSarToHdf(loadFixture('sar-fedramp.json'));
    const results = JSON.parse(output) as HdfResults;

    expect(results.baselines[0]!.integrity?.algorithm).toBe('sha256');
    expect(results.baselines[0]!.integrity?.checksum).toMatch(/^[a-f0-9]{64}$/);
  });
});
