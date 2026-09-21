import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { describe, it, expect, vi, afterEach } from 'vitest';
import { detectOscalDocumentType } from './detect.js';
import { convertOscalCatalogToHdf } from './converter-catalog.js';
import { convertOscalProfileToHdf } from './converter-profile.js';
import { convertOscalComponentToHdf } from './converter-component.js';
import { convertOscalSspToHdf } from './converter-ssp.js';
import { convertOscalSapToHdf } from './converter-sap.js';
import { convertOscalPoamToHdf } from './converter-poam.js';
import { convertOscalSarToHdf, sarRequirementId } from './converter-sar.js';
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
  nistTagToControlRef,
  confirmedControlId,
  impactToSeverity,
  hdfStatusToOscalRiskStatus,
  parseOscalDocument,
  toKebabCase,
  descriptionLabelProp,
  descriptionLabel,
} from './shared.js';
import {
  assertRequirementCount,
  countJsonItemsUnderKey,
} from '../../../shared/typescript/anchor.js';
import { expectValidResults } from '../../../test/helpers/expectValidHdf.js';
import type { HDFResults, HDFBaseline } from '@mitre/hdf-schema';
import type { HDFSystem } from '@mitre/hdf-schema';
import type { HDFPlan } from '@mitre/hdf-schema';
import type { HDFAmendments } from '@mitre/hdf-schema';
import type { Oscal } from './types.js';

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

    expect(baseline.generator?.name).toBe('oscal-catalog-to-hdf');
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

  // Ground-truth anchor for the CATALOG dispatch path only. oscal-to-hdf handles
  // several OSCAL document types with different emission units; the catalog path
  // emits exactly one requirement per control, including nested controls[] at any
  // depth. The count is derived independently of the converter (a generic JSON
  // walk over "controls" arrays — see shared/typescript/anchor.ts), so a silent
  // under-extraction fails even when Go and TS agree. Do NOT anchor the
  // SSP/SAR/POA&M/component paths this way — their emission units differ.
  it('emits one requirement per control (nested controls[] at any depth)', async () => {
    const input = loadFixture('catalog-moderate-resolved.json');
    assertRequirementCount(
      await convertOscalCatalogToHdf(input),
      countJsonItemsUnderKey(input, 'controls'),
      'catalog-moderate-resolved.json: one requirement per control (nested controls[] at any depth)',
    );
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
    expect(baseline.generator?.name).toBe('oscal-component-to-hdf');
    expect(baseline.integrity?.algorithm).toBe('sha256');
    expect(baseline.requirements.length).toBeGreaterThan(0);

    // Requirements should have NIST-notation IDs
    for (const req of baseline.requirements) {
      expect(req.id).toMatch(/^[0-9a-f-]{36}\/[A-Z]{2}-\d+/);
      expect(req.tags?.['nist']).toBeDefined();
    }
  });

  it('should convert every component of a multi-component definition', async () => {
    const output = await convertOscalComponentToHdf(
      loadFixture('component-definition-multi.json'),
    );
    const baseline = JSON.parse(output) as HDFBaseline;

    // Two components (comp_aa, comp_ab) with two implemented requirements
    // each, in document order.
    const ids = baseline.requirements.map((r) => r.id);
    expect(ids).toEqual([
      '8220b305-0271-45f9-8a21-40ab6f197f70/AC-1',
      '8220b305-0271-45f9-8a21-40ab6f197f70/AC-3',
      '8220b305-0271-45f9-8a21-40ab6f197f71/AC-1',
      '8220b305-0271-45f9-8a21-40ab6f197f71/AT-1',
    ]);

    // The point of qualifying: ac-1 is implemented by both components, and the
    // two requirements must stay distinguishable. Duplicate ids are unmatchable
    // to hdf-diff and unaddressable by an amendment.
    expect(new Set(ids).size).toBe(ids.length);

    // The bare control stays in the nist tag, and the component is readable
    // without parsing the id.
    expect(baseline.requirements[0]!.tags!.nist).toEqual(['AC-1']);
    expect(baseline.requirements[2]!.tags!.nist).toEqual(['AC-1']);
    expect(baseline.requirements[0]!.tags!.component).toBe('comp_aa');
    expect(baseline.requirements[2]!.tags!.component).toBe('comp_ab');
    expect(baseline.requirements[0]!.descriptions[0]!.data).toContain('from comp aa');
    expect(baseline.requirements[3]!.descriptions[0]!.data).toContain('from comp ab');

    // A multi-component definition is named for the definition, not component #1.
    expect(baseline.name).toBe('comp-def-a');
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
    expect(system.generator?.name).toBe('oscal-ssp-to-hdf');
    expect(system.components).toBeDefined();
  });

  it('should convert SSP FedRAMP fixture', async () => {
    const output = await convertOscalSspToHdf(loadFixture('ssp-fedramp.json'));
    const system = JSON.parse(output) as HDFSystem;

    expect(system.name).toBeTruthy();
    expect(system.components).toBeDefined();
  });

  it('should set componentId to each OSCAL component uuid, distinguishing same-title components', async () => {
    const duplicateTitleComponentUuid = 'a3ca96ea-f853-4539-9db3-bf9694f7e0dc';
    const doc = JSON.parse(loadFixture('ssp-example.json')) as Oscal;
    const sourceComponents = doc['system-security-plan']!['system-implementation'].components;
    const loggingServer = sourceComponents.find((c) => c.title === 'Logging Server');
    expect(loggingServer).toBeDefined();
    sourceComponents.push({ ...structuredClone(loggingServer!), uuid: duplicateTitleComponentUuid });

    const system = JSON.parse(await convertOscalSspToHdf(JSON.stringify(doc))) as HDFSystem;

    expect(system.components.map((c) => c.componentId)).toEqual(sourceComponents.map((c) => c.uuid));
    const loggingServerIds = system.components
      .filter((c) => c.name === 'Logging Server')
      .map((c) => c.componentId);
    expect(loggingServerIds).toEqual(['e00acdcf-911b-437d-a42f-b0b558cc4f03', duplicateTitleComponentUuid]);
  });

  it('should carry FedRAMP component uuids verbatim as componentId', async () => {
    const input = loadFixture('ssp-fedramp.json');
    const sourceUuids = (JSON.parse(input) as Oscal)['system-security-plan']!['system-implementation'].components.map(
      (c) => c.uuid,
    );
    expect(sourceUuids).toContain('77A1614A-57B3-4B32-9FEE-613A6520EC58');

    const system = JSON.parse(await convertOscalSspToHdf(input)) as HDFSystem;

    expect(system.components.map((c) => c.componentId)).toEqual(sourceUuids);
  });

  it('should omit componentId when an OSCAL component has no uuid', async () => {
    const doc = JSON.stringify({
      'system-security-plan': {
        uuid: 'd7456980-9277-4dcb-83cf-f8ff0442623b',
        metadata: { title: 'SSP', version: '1', 'oscal-version': '1.1.2', 'last-modified': '2024-01-01T00:00:00Z' },
        'system-implementation': {
          components: [{ uuid: '', title: 'No UUID', type: 'software' }],
        },
      },
    });

    const system = JSON.parse(await convertOscalSspToHdf(doc)) as HDFSystem;

    expect(system.components[0]!.name).toBe('No UUID');
    expect(system.components[0]).not.toHaveProperty('componentId');
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
    expect(plan.generator?.name).toBe('oscal-sap-to-hdf');
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
    expect(amendments.generator?.name).toBe('oscal-poam-to-hdf');
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
    expectValidResults(results);

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

  it('maps risk statement and remediation into descriptions', async () => {
    const output = await convertOscalSarToHdf(loadFixture('sar-fedramp.json'));
    const results = JSON.parse(output) as HDFResults;
    const reqs = results.baselines[0]!.requirements;

    const ac1 = reqs.find(r => r.id === 'AC-1')!;
    const statement = ac1.descriptions?.find(d => d.label === 'statement');
    expect(statement?.data).toBe(
      'This is a statement about the identified risk.\n\nTCW: Risk Statement..\n\nScans: N/A.\n\nPen Risk Statement.\n\nRET: Risk Statement.',
    );
    const remediation = ac1.descriptions?.find(d => d.label === 'remediation');
    expect(remediation?.data).toMatch(/^Remediation Title: A description of the recommended remediation\./);
  });

  it('joins multiple remediations from a single risk', async () => {
    const output = await convertOscalSarToHdf(loadFixture('sar-fedramp.json'));
    const results = JSON.parse(output) as HDFResults;
    const cm2 = results.baselines[0]!.requirements.find(r => r.id === 'CM-2 (1)')!;

    const remediation = cm2.descriptions?.find(d => d.label === 'remediation');
    expect(remediation?.data).toContain(
      "Tool's Recommendation: A description of the recommended remediation as provided by the tool.",
    );
    expect(remediation?.data).toContain(
      "Assessor's Recommendation: A description of the recommended remediation as provided by the assessor.",
    );
    expect(remediation?.data).toContain('\n\n');
  });

  it('maps relevant-evidence prose and resolvable URLs into evidence/refs', async () => {
    const output = await convertOscalSarToHdf(loadFixture('sar-fedramp.json'));
    const results = JSON.parse(output) as HDFResults;
    const reqs = results.baselines[0]!.requirements;

    const cm2 = reqs.find(r => r.id === 'CM-2 (1)')!;
    const evidence = cm2.descriptions?.find(d => d.label === 'evidence');
    expect(evidence?.data).toContain('A screen shot showing the system impact when patch is applied.');
    expect(evidence?.data).toContain('Vendor detail describing why this happens.');

    // Duplicate evidence URLs collapse to a single ref.
    expect(cm2.refs).toHaveLength(1);
    expect(cm2.refs![0]!.url).toBe('https://vendor.site/article/describing/something.htm');

    // AC-1's evidence hrefs are intra-document fragments only → prose captured, no refs.
    const ac1 = reqs.find(r => r.id === 'AC-1')!;
    expect(ac1.descriptions?.some(d => d.label === 'evidence')).toBe(true);
    expect(ac1.refs).toBeUndefined();
  });

  it('omits statement/remediation/evidence/refs when the source carries none', async () => {
    const output = await convertOscalSarToHdf(loadFixture('sar-fedramp.json'));
    const results = JSON.parse(output) as HDFResults;
    // AU-1 relates to no risk and to an observation with no relevant-evidence.
    const au1 = results.baselines[0]!.requirements.find(r => r.id === 'AU-1')!;

    expect(au1.descriptions?.some(d => d.label === 'statement')).toBe(false);
    expect(au1.descriptions?.some(d => d.label === 'remediation')).toBe(false);
    expect(au1.descriptions?.some(d => d.label === 'evidence')).toBe(false);
    expect(au1.refs).toBeUndefined();
  });

  it('maps result startTime from the correlated observation collected time', async () => {
    const output = await convertOscalSarToHdf(loadFixture('sar-fedramp.json'));
    const results = JSON.parse(output) as HDFResults;
    const reqs = results.baselines[0]!.requirements;

    // Every finding correlates to observations whose `collected` is
    // 2023-05-10T00:00:00Z; startTime must be that value, NOT the result's
    // assessment-period start (2023-03-01T00:00:00Z).
    for (const id of ['AC-1', 'AU-1', 'RA-5', 'CM-2 (1)', 'AT-2', 'CA-8 (1)']) {
      const req = reqs.find(r => r.id === id)!;
      const startTime = req.results[0]!.startTime;
      expect(new Date(startTime as string | Date).toISOString()).toBe('2023-05-10T00:00:00.000Z');
    }
  });

  it('falls back to result start, then conversion time, when no observation collected time exists', async () => {
    const doc = JSON.parse(loadFixture('sar-fedramp.json')) as {
      'assessment-results': {
        results: Array<{
          start?: unknown;
          observations?: Array<Record<string, unknown>>;
        } & Record<string, unknown>>;
      };
    };
    // Strip every observation `collected` so the primary source is absent; the
    // result's `start` (2023-03-01T00:00:00Z) must then supply startTime.
    for (const r of doc['assessment-results'].results) {
      for (const o of r.observations ?? []) delete o['collected'];
    }
    let output = await convertOscalSarToHdf(JSON.stringify(doc));
    let results = JSON.parse(output) as HDFResults;
    expectValidResults(results);
    let startTime = results.baselines[0]!.requirements[0]!.results[0]!.startTime;
    expect(new Date(startTime as string | Date).toISOString()).toBe('2023-03-01T00:00:00.000Z');

    // Also drop the result `start`: startTime must fall to a fresh conversion
    // time, never the 1970 epoch placeholder.
    for (const r of doc['assessment-results'].results) delete r['start'];
    const before = Date.now();
    output = await convertOscalSarToHdf(JSON.stringify(doc));
    results = JSON.parse(output) as HDFResults;
    expectValidResults(results);
    startTime = results.baselines[0]!.requirements[0]!.results[0]!.startTime;
    expect(new Date(startTime as string | Date).getTime()).toBeGreaterThanOrEqual(before);
  });

  it('should only include result sets that have findings', async () => {
    const output = await convertOscalSarToHdf(loadFixture('sar-fedramp.json'));
    const results = JSON.parse(output) as HDFResults;

    // The FedRAMP SAR fixture has 3 result sets but only 1 carries findings;
    // the empty ones are skipped (an empty baseline violates minItems=1).
    expect(results.baselines).toHaveLength(1);
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

  it('derives tags.cci from the NIST control, omitting it when unmapped', async () => {
    const output = await convertOscalSarToHdf(loadFixture('sar-fedramp.json'));
    const results = JSON.parse(output) as HDFResults;
    const reqs = results.baselines[0]!.requirements;

    // RA-5 maps to a CCI via the standard NIST→CCI table.
    const ra5 = reqs.find(r => r.id === 'RA-5')!;
    expect(ra5.tags.nist).toEqual(['RA-5']);
    expect(ra5.tags.cci as string[]).toContain('CCI-001643');

    // AC-1 has no NIST→CCI mapping, so tags.cci must be absent.
    const ac1 = reqs.find(r => r.id === 'AC-1')!;
    expect(ac1.tags.nist).toEqual(['AC-1']);
    expect(ac1.tags.cci).toBeUndefined();
  });
});

describe('convertOscalSarToHdf prose homes', () => {
  const NS = 'https://mitre.github.io/hdf-libs/ns/oscal';

  // Builds a one-result SAR from raw findings, observations and risks, so each
  // test states exactly the prose homes it reads.
  const sarWithProse = (findings: unknown[], observations: unknown[], risks: unknown[]): string =>
    JSON.stringify({
      'assessment-results': {
        uuid: '11111111-1111-4111-8111-111111111111',
        metadata: { title: 't', 'last-modified': '2026-01-01T00:00:00Z', version: '1', 'oscal-version': '1.1.2' },
        'import-ap': { href: '#' },
        results: [{
          uuid: '22222222-2222-4222-8222-222222222222', title: 'r', description: 'd', start: '2026-01-01T00:00:00Z',
          'reviewed-controls': { 'control-selections': [{ 'include-all': {} }] },
          findings, observations, risks,
        }],
      },
    });

  const finding = (uuid: string, extra: Record<string, unknown> = {}, targetDescription?: string) => ({
    uuid, title: 't', description: `d-${uuid}`,
    target: {
      type: 'objective-id', 'target-id': 'ac-1', status: { state: 'not-satisfied' },
      ...(targetDescription !== undefined ? { description: targetDescription } : {}),
    },
    ...extra,
  });
  const observation = (uuid: string, evidence?: unknown[]) => ({
    uuid, description: 'observation prose', methods: ['TEST'], collected: '2026-01-01T00:00:00Z',
    ...(evidence ? { 'relevant-evidence': evidence } : {}),
  });
  const label = (value: string, ns: string | null = NS) => [{ name: 'description-label', value, ...(ns !== null ? { ns } : {}) }];

  const onlyRequirement = async (input: string) => {
    const hdf = JSON.parse(await convertOscalSarToHdf(input)) as HDFResults;
    expect(hdf.baselines).toHaveLength(1);
    expect(hdf.baselines[0]!.requirements).toHaveLength(1);
    return hdf.baselines[0]!.requirements[0]!;
  };
  const desc = (req: { descriptions?: Array<{ label: string; data: string }> }, l: string) =>
    req.descriptions?.find((d) => d.label === l)?.data;

  it('exports the description-label helpers', () => {
    expect(descriptionLabelProp('check')).toEqual({ name: 'description-label', ns: NS, value: 'check' });
    expect(descriptionLabel([{ name: 'other', ns: NS, value: 'x' }, descriptionLabelProp('fix')])).toBe('fix');
    expect(descriptionLabel(label('fix', null))).toBe('');
    expect(descriptionLabel(label('fix', 'https://example.org/ns/oscal'))).toBe('');
    expect(descriptionLabel(undefined)).toBe('');
    expect(() => descriptionLabelProp('')).toThrow('oscal: description label "" yields no description-label prop');
  });

  it('reads rationale from finding.target.description, not observation descriptions', async () => {
    const req = await onlyRequirement(sarWithProse([
      finding('f1', { 'related-observations': [{ 'observation-uuid': 'o1' }] }, 'first\nconclusion\n'),
      finding('f2'),
      finding('f3', {}, 'second'),
    ], [observation('o1')], []));
    expect(desc(req, 'rationale')).toBe('first\nconclusion\n\nsecond');
  });

  it('emits no rationale when no target carries a description', async () => {
    const req = await onlyRequirement(sarWithProse([
      finding('f1', { 'related-observations': [{ 'observation-uuid': 'o1' }] }),
    ], [observation('o1')], []));
    expect(desc(req, 'rationale')).toBeUndefined();
  });

  it('reads labelled evidence and fix remediations back exactly', async () => {
    const req = await onlyRequirement(sarWithProse([
      finding('f1', { 'related-observations': [{ 'observation-uuid': 'o1' }], 'related-risks': [{ 'risk-uuid': 'r1' }] }),
    ], [observation('o1', [
      { description: 'Check line', remarks: 'Check line\n  full check\n', props: label('check') },
      { description: 'plain evidence' },
    ])], [{
      uuid: 'r1', title: 'Risk', description: 'rd', statement: 'rs', status: 'open',
      remediations: [
        { uuid: 'm1', lifecycle: 'recommendation', title: 'Recommended fix', description: 'do\nthis', props: label('fix') },
        { uuid: 'm2', lifecycle: 'accepted', title: 'waiver', description: 'accepted' },
      ],
    }]));
    expect(desc(req, 'check')).toBe('Check line\n  full check\n');
    expect(desc(req, 'fix')).toBe('do\nthis');
    expect(desc(req, 'remediation')).toBe('waiver: accepted');
    expect(desc(req, 'evidence')).toBe('plain evidence');
  });

  it('reads a labelled evidence entry without remarks from its description', async () => {
    const req = await onlyRequirement(sarWithProse([
      finding('f1', { 'related-observations': [{ 'observation-uuid': 'o1' }, { 'observation-uuid': 'o1' }] }),
    ], [observation('o1', [{ description: 'single-line fix', props: label('fix') }])], []));
    expect(desc(req, 'fix')).toBe('single-line fix');
    expect(desc(req, 'evidence')).toBeUndefined();
    expect(desc(req, 'check')).toBeUndefined();
  });

  it('imports unlabelled or foreign-labelled evidence and remediations as before', async () => {
    const req = await onlyRequirement(sarWithProse([
      finding('f1', { 'related-observations': [{ 'observation-uuid': 'o1' }], 'related-risks': [{ 'risk-uuid': 'r1' }] }),
    ], [observation('o1', [
      { description: 'no label', remarks: 'remark one' },
      { description: 'no ns', remarks: 'remark two', props: label('check', null) },
      { description: 'other ns', props: label('fix', 'https://example.org/ns/oscal') },
      { description: 'unknown value', props: label('rationale') },
    ])], [{
      uuid: 'r1', title: 'Risk', description: 'rd', statement: 'rs', status: 'open',
      remediations: [
        { uuid: 'm1', lifecycle: 'recommendation', title: 'Recommended fix', description: 'patch it' },
        { uuid: 'm2', lifecycle: 'recommendation', title: 'Vendor', description: 'upgrade', props: label('fix', null) },
        { uuid: 'm3', lifecycle: 'recommendation', title: 'Checker', description: 'look', props: label('check') },
      ],
    }]));
    expect(desc(req, 'check')).toBeUndefined();
    expect(desc(req, 'fix')).toBeUndefined();
    expect(desc(req, 'remediation')).toBe('Recommended fix: patch it\n\nVendor: upgrade\n\nChecker: look');
    expect(desc(req, 'evidence')).toBe('no label\nno ns\nother ns\nunknown value');
  });

  it('joins labelled prose across merged findings in finding order', async () => {
    const req = await onlyRequirement(sarWithProse([
      finding('f1', { 'related-observations': [{ 'observation-uuid': 'o1' }], 'related-risks': [{ 'risk-uuid': 'r1' }] }),
      finding('f2', {
        'related-observations': [{ 'observation-uuid': 'o2' }, { 'observation-uuid': 'o1' }, { 'observation-uuid': 'missing' }],
        'related-risks': [{ 'risk-uuid': 'r1' }, { 'risk-uuid': 'r2' }, { 'risk-uuid': 'missing' }],
      }),
    ], [
      observation('o1', [{ description: 'c1', remarks: 'check one', props: label('check') }]),
      observation('o2', [
        { description: 'c2', remarks: 'check two', props: label('check') },
        { description: 'f2', remarks: 'fix two', props: label('fix') },
      ]),
    ], [{
      uuid: 'r1', title: 'Risk', description: 'rd', statement: 'rs', status: 'open',
      remediations: [{ uuid: 'm1', lifecycle: 'recommendation', title: 'Recommended fix', description: 'fix one', props: label('fix') }],
    }, { uuid: 'r2', title: 'Risk', description: 'rd', statement: 'rs', status: 'open' }]));
    expect(desc(req, 'check')).toBe('check one\ncheck two');
    expect(desc(req, 'fix')).toBe('fix one\nfix two');
  });
});

describe('convertOscalSarToHdf requirement ids', () => {
  const NS = 'https://mitre.github.io/hdf-libs/ns/oscal';

  afterEach(() => {
    vi.restoreAllMocks();
  });

  const sar = (findings: unknown[]): string =>
    JSON.stringify({
      'assessment-results': {
        uuid: '11111111-1111-4111-8111-111111111111',
        metadata: { title: 't', 'last-modified': '2026-01-01T00:00:00Z', version: '1', 'oscal-version': '1.1.2' },
        'import-ap': { href: '#' },
        results: [{
          uuid: '22222222-2222-4222-8222-222222222222', title: 'r', description: 'd', start: '2026-01-01T00:00:00Z',
          'reviewed-controls': { 'control-selections': [{ 'include-all': {} }] },
          findings, observations: [], risks: [],
        }],
      },
    });
  // One finding per target id, each with its own uuid and title.
  const sarFindings = (...targetIds: string[]): string =>
    sar(targetIds.map((id, i) => ({
      uuid: `f${i + 1}`, title: `Finding ${i + 1}`, description: 'd',
      target: { type: 'objective-id', 'target-id': id, status: { state: 'satisfied' } },
    })));
  const requirementIds = (hdf: HDFResults): Record<string, number> =>
    Object.fromEntries(hdf.baselines[0]!.requirements.map((r) => [r.id, r.results.length]));

  const foreignNS = 'https://example.org/ns/oscal';
  it.each([
    ['objective groups under its control', 'ac-1.a.1_obj.1', undefined, 'AC-1'],
    ['statement groups under its control', 'au-1_smt.a', undefined, 'AU-1'],
    ['enhancement statement', 'cm-2.1_smt.c', undefined, 'CM-2 (1)'],
    ['enhancement objective', 'ca-8.1_obj', undefined, 'CA-8 (1)'],
    ['whole control', 'ac-2.3', undefined, 'AC-2 (3)'],
    ['STIG rule id is verbatim', 'sv-230221r858734_rule', undefined, 'sv-230221r858734_rule'],
    ['uppercase rule id is verbatim', 'SV-230221r858734_rule', undefined, 'SV-230221r858734_rule'],
    ['uppercase look-alike of an unknown family is verbatim', 'SV-230221', undefined, 'SV-230221'],
    ['uppercase control groups', 'AC-1', undefined, 'AC-1'],
    ['uppercase objective groups under its control', 'AC-2.3_OBJ.A', undefined, 'AC-2 (3)'],
    ['mixed-case part groups under its control', 'ac-1.A_obj', undefined, 'AC-1'],
    ['zero-padded control groups canonically', 'ac-01_obj.a', undefined, 'AC-1'],
    ['zero-padded enhancement groups canonically', 'ac-02.03_obj', undefined, 'AC-2 (3)'],
    ['empty part after the suffix is verbatim', 'ac-1_obj.', undefined, 'ac-1_obj.'],
    ['XCCDF rule id is verbatim', 'xccdf_org.ssgproject.content_rule_accounts_tmout', undefined, 'xccdf_org.ssgproject.content_rule_accounts_tmout'],
    ['unconfirmed control is verbatim', 'zz-9_obj.1', undefined, 'zz-9_obj.1'],
    ['HDF prop wins over a NIST target', 'ac-1', [{ name: 'hdf-requirement-id', ns: NS, value: 'SV-1' }], 'SV-1'],
    ['HDF prop keeps a statement id', 'ac-8_smt.c.1', [{ name: 'hdf-requirement-id', ns: NS, value: 'AC-8 c 1' }], 'AC-8 c 1'],
    ['HDF prop remarks hold the exact id', 'line_one_line_two', [{ name: 'hdf-requirement-id', ns: NS, value: 'line one line two', remarks: 'line one\nline two' }], 'line one\nline two'],
    ['pre-ADR prop without ns is read', 'sv-1', [{ name: 'hdf-requirement-id', value: 'SV-1' }], 'SV-1'],
    ["foreign-namespace prop is not HDF's", 'ac-1', [{ name: 'hdf-requirement-id', ns: foreignNS, value: 'SV-1' }], 'AC-1'],
    ['empty HDF prop falls back to the target', 'ac-1', [{ name: 'hdf-requirement-id', ns: NS, value: '' }], 'AC-1'],
  ])('sarRequirementId: %s', (_name, targetId, props, expected) => {
    const f = { uuid: 'f', title: 't', description: 'd', props, target: { type: 'objective-id', 'target-id': targetId, status: { state: 'satisfied' } } };
    expect(sarRequirementId(f as never)).toBe(expected);
  });

  it('sarRequirementId: empty target-id has no requirement id', () => {
    const f = { uuid: 'f', title: 't', description: 'd', props: [{ name: 'hdf-requirement-id', ns: NS, value: 'SV-1' }], target: { type: 'objective-id', 'target-id': '', status: { state: 'satisfied' } } };
    expect(sarRequirementId(f as never)).toBeUndefined();
  });

  it('groups foreign targets only under roster-confirmed controls, never merging look-alikes', async () => {
    const input = sarFindings(
      'sv-230221r858734_rule',
      'ac-2.3_obj.a',
      'sv-230221r991589_rule',
      'xccdf_org.ssgproject.content_rule_accounts_tmout',
      'ac-2.3_smt.b',
      'xccdf_org.ssgproject.content_rule_audit_rules_login_events',
      'au-1_smt.a',
      'zz-9_obj.1',
      'zz-9_obj.2',
      'ac-2.3',
    );
    const hdf = JSON.parse(await convertOscalSarToHdf(input)) as HDFResults;
    expectValidResults(hdf);
    const reqs = hdf.baselines[0]!.requirements;
    expect(reqs.map((r) => r.id)).toEqual([
      'sv-230221r858734_rule',
      'AC-2 (3)',
      'sv-230221r991589_rule',
      'xccdf_org.ssgproject.content_rule_accounts_tmout',
      'xccdf_org.ssgproject.content_rule_audit_rules_login_events',
      'AU-1',
      'zz-9_obj.1',
      'zz-9_obj.2',
    ]);
    expect(requirementIds(hdf)['AC-2 (3)']).toBe(3);
    expect(reqs.find((r) => r.id === 'AC-2 (3)')!.tags.nist).toEqual(['AC-2 (3)']);
    const sv = reqs.find((r) => r.id === 'sv-230221r858734_rule')!;
    expect(sv.tags.nist).toEqual([]);
    expect(sv.controlType).toBeUndefined();
    expect(sv.title).toBe('Finding 1');
  });

  it('ignores letter case when grouping, keeping look-alikes verbatim and apart', async () => {
    const hdf = JSON.parse(await convertOscalSarToHdf(
      sarFindings('ac-2.3_obj.a', 'AC-2.3_OBJ.B', 'Ac-2.3', 'SV-230221r858734_rule', 'SV-230221', 'sv-230221', 'ac-1.A_obj'),
    )) as HDFResults;
    const reqs = hdf.baselines[0]!.requirements;
    expect(reqs.map((r) => r.id)).toEqual(['AC-2 (3)', 'SV-230221r858734_rule', 'SV-230221', 'sv-230221', 'AC-1']);
    expect(requirementIds(hdf)['AC-2 (3)']).toBe(3);
    expect(reqs[0]!.tags.nist).toEqual(['AC-2 (3)']);
  });

  it('groups zero-padded targets under the canonical control and tag', async () => {
    const hdf = JSON.parse(await convertOscalSarToHdf(sarFindings('ac-01_obj.a', 'ac-1_obj.b', 'ac-02.03_obj', 'ac-2.3'))) as HDFResults;
    const reqs = hdf.baselines[0]!.requirements;
    expect(requirementIds(hdf)).toEqual({ 'AC-1': 2, 'AC-2 (3)': 2 });
    expect(reqs[0]!.id).toBe('AC-1');
    expect(reqs.find((r) => r.id === 'AC-1')!.tags.nist).toEqual(['AC-1']);
    expect(reqs.find((r) => r.id === 'AC-2 (3)')!.tags.nist).toEqual(['AC-2 (3)']);
  });

  it('quotes titles in warnings literally, matching Go', async () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    const result = (uuid: string, title: string, findings?: unknown[]) => ({
      uuid, title, description: 'd', start: '2026-01-01T00:00:00Z',
      'reviewed-controls': { 'control-selections': [{ 'include-all': {} }] },
      ...(findings ? { findings } : {}),
    });
    await convertOscalSarToHdf(JSON.stringify({
      'assessment-results': {
        uuid: '11111111-1111-4111-8111-111111111111',
        metadata: { title: 't', 'last-modified': '2026-01-01T00:00:00Z', version: '1', 'oscal-version': '1.1.2' },
        'import-ap': { href: '#' },
        results: [
          result('33333333-3333-4333-8333-333333333333', 'Q3 "annual" review'),
          result('44444444-4444-4444-8444-444444444444', 'Q4 "final" review', [{
            uuid: 'f1', title: 'say "hi"', description: 'd',
            target: { type: 'objective-id', 'target-id': '', status: { state: 'satisfied' } },
          }]),
        ],
      },
    }));
    const warnings = warn.mock.calls.map((c) => c[0] as string);
    expect(warnings).toContain('WARNING: Skipping assessment result "Q3 "annual" review": no findings (empty result set)');
    expect(warnings).toContain('WARNING: Skipping finding "f1" titled "say "hi"": empty target-id');
    expect(warnings).toContain('WARNING: Skipping assessment result "Q4 "final" review": no finding has a target-id');
  });

  it('drops findings beyond the cap with the same warning as Go', async () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    const cap = 100_000;
    const finding = (uuid: string, targetId: string) => ({
      uuid, title: 't', description: 'd', target: { type: 'objective-id', 'target-id': targetId, status: { state: 'satisfied' } },
    });
    const findings = Array.from({ length: cap }, () => finding('f', 'ac-1'));
    findings.push(finding('over', 'sv-1'));
    const hdf = JSON.parse(await convertOscalSarToHdf(sar(findings))) as HDFResults;
    expect(requirementIds(hdf)).toEqual({ 'AC-1': cap });
    const truncations = warn.mock.calls.map((c) => c[0] as string).filter((w) => w.includes('Input truncated at'));
    expect(truncations).toEqual(['WARNING: Input truncated at 100000 finding items (original: 100001)']);
  }, 60_000);

  it('reads the HDF requirement id prop ahead of the target and groups by it', async () => {
    const prop = (value: string) => [{ name: 'hdf-requirement-id', ns: NS, value }];
    const finding = (uuid: string, title: string, targetId: string, props?: unknown[]) => ({
      uuid, title, description: 'd', ...(props ? { props } : {}),
      target: { type: 'objective-id', 'target-id': targetId, status: { state: 'satisfied' } },
    });
    const hdf = JSON.parse(await convertOscalSarToHdf(sar([
      finding('f1', 't1', 'sv-230221r858734_rule', prop('SV-230221r858734_rule')),
      finding('f2', 't2', 'ac-8_smt.c.1', prop('AC-8 c 1')),
      finding('f3', 't3', 'sv-230221r858734_rule', prop('SV-230221r858734_rule')),
      finding('f4', '', 'ac-8.a_obj.1'),
    ]))) as HDFResults;
    const reqs = hdf.baselines[0]!.requirements;
    expect(requirementIds(hdf)).toEqual({ 'SV-230221r858734_rule': 2, 'AC-8 c 1': 1, 'AC-8': 1 });
    expect(reqs[0]!.id).toBe('SV-230221r858734_rule');
    expect(reqs.find((r) => r.id === 'AC-8 c 1')!.tags.nist).toEqual(['AC-8']);
    expect(reqs.find((r) => r.id === 'AC-8')!.title).toBe('AC-8');
  });

  it('skips a finding with an empty target-id with a warning, and a result left with none', async () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    let hdf = JSON.parse(await convertOscalSarToHdf(sarFindings('', 'ac-1', ''))) as HDFResults;
    expect(requirementIds(hdf)).toEqual({ 'AC-1': 1 });
    let warnings = warn.mock.calls.map((c) => c[0] as string);
    expect(warnings).toContain('WARNING: Skipping finding "f1" titled "Finding 1": empty target-id');
    expect(warnings).toContain('WARNING: Skipping finding "f3" titled "Finding 3": empty target-id');
    expect(warnings.some((w) => w.includes('"f2"'))).toBe(false);

    warn.mockClear();
    hdf = JSON.parse(await convertOscalSarToHdf(sarFindings(''))) as HDFResults;
    expect(hdf.baselines).toEqual([]);
    warnings = warn.mock.calls.map((c) => c[0] as string);
    expect(warnings).toContain('WARNING: Skipping finding "f1" titled "Finding 1": empty target-id');
    expect(warnings).toContain('WARNING: Skipping assessment result "r": no finding has a target-id');
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
    const casesPath = join(__dirname, '..', 'go', 'testdata', 'nist-tag-control-id-cases.json');
    const { cases } = JSON.parse(readFileSync(casesPath, 'utf-8')) as {
      cases: Array<{ input: string; controlId: string; statementId: string }>;
    };

    it('has cases', () => {
      expect(cases.length).toBeGreaterThan(0);
    });

    it.each(cases)('maps $input the same as the Go peer', ({ input, controlId, statementId }) => {
      expect(nistTagToControlId(input)).toBe(controlId);
      expect(nistTagToControlRef(input)).toEqual({ controlId, statementId });
    });
  });

  describe('confirmedControlId', () => {
    const casesPath = join(__dirname, '..', 'go', 'testdata', 'oscal-control-target-cases.json');
    const { cases } = JSON.parse(readFileSync(casesPath, 'utf-8')) as {
      cases: Array<{ input: string; controlId: string }>;
    };

    it('has cases', () => {
      expect(cases.length).toBeGreaterThan(0);
    });

    it.each(cases)('confirms $input the same as the Go peer', ({ input, controlId }) => {
      expect(confirmedControlId(input)).toBe(controlId === '' ? undefined : controlId);
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
      expect(impactToSeverity(0.09)).toBe('low');
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
  // Mirrors the Go TestConvertPOAMToHDF_PreADRDocument over the same hdf-cli v3.6.0
  // export and v3.6.0 import (go/testdata/provenance.txt): a pre-ADR HDF POA&M imports through the pre-ADR
  // mapping (ADR-0014 §4.3), except that an item with no impacted-control-id is
  // skipped with a warning rather than named by its title or "unknown".
  it('reads a pre-ADR HDF POA&M through the pre-ADR mapping', async () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    const testdata = join(__dirname, '..', 'go', 'testdata');
    const comparable = (doc: Record<string, unknown>) => {
      delete doc.generator;
      delete doc.integrity;
      for (const o of doc.overrides as Array<Record<string, unknown>>) delete o.previousChecksum;
      return doc;
    };
    const got = comparable(JSON.parse(await convertOscalPoamToHdf(readFileSync(join(testdata, 'poam-pre-adr.json'), 'utf-8'))));
    expect(warn.mock.calls.map((c) => c[0] as string)).toContain(
      'WARNING: Skipping poam-item "6f81f9fe-06ff-418f-b294-04e613bad22d" titled "": its pre-ADR risk has no impacted-control-id',
    );
    warn.mockRestore();
    const want = comparable(JSON.parse(readFileSync(join(testdata, 'poam-pre-adr.v3.6.0-import.json'), 'utf-8')));
    const overrides = want.overrides as Array<Record<string, unknown>>;
    expect(overrides.at(-1)!.requirementId, 'the released importer named the id-less item unknown').toBe('unknown');
    want.overrides = overrides.slice(0, -1);
    expect(got).toStrictEqual(want);
  });

  it('should throw on wrong document type', async () => {
    await expect(
      convertOscalPoamToHdf(JSON.stringify({ catalog: {} })),
    ).rejects.toThrow('not a plan-of-action-and-milestones');
  });

  // A POA&M override requires a real deadline (risk.deadline) — the converter
  // fails loud without one. This wraps a single poam-item with a deadline-bearing
  // related risk so edge-case tests can exercise non-date behavior. Extra
  // metadata / top-level keys and extra risk fields can be merged in.
  function poamDocWithDeadline(
    poamItem: Record<string, unknown>,
    opts: { metadata?: Record<string, unknown>; top?: Record<string, unknown>; risk?: Record<string, unknown> } = {},
  ): string {
    return JSON.stringify({
      'plan-of-action-and-milestones': {
        uuid: '123',
        metadata: {
          title: 'POAM',
          version: '1',
          'oscal-version': '1.1.2',
          'last-modified': '2024-01-01T00:00:00Z',
          ...opts.metadata,
        },
        risks: [{ uuid: 'r-deadline', title: 'R', status: 'open', deadline: '2025-01-01T00:00:00Z', ...opts.risk }],
        'poam-items': [{ 'related-risks': [{ 'risk-uuid': 'r-deadline' }], ...poamItem }],
        ...opts.top,
      },
    });
  }

  it('should fail loud on a POAM item with no derivable deadline', async () => {
    const doc = JSON.stringify({
      'plan-of-action-and-milestones': {
        uuid: '123',
        metadata: {
          title: 'POAM',
          version: '1',
          'oscal-version': '1.1.2',
          'last-modified': '2024-01-01T00:00:00Z',
        },
        'poam-items': [{ uuid: 'item-1', title: 'Finding 1', description: 'A finding' }],
      },
    });
    await expect(convertOscalPoamToHdf(doc)).rejects.toThrow('requires a time commitment');
  });

  it('should extract requirement ID from POAM-ID prop', async () => {
    const doc = poamDocWithDeadline({
      uuid: 'item-1',
      title: 'Finding 1',
      description: 'Desc',
      props: [{ name: 'POAM-ID', value: 'V-12345' }],
    });
    const output = await convertOscalPoamToHdf(doc);
    const amendments = JSON.parse(output) as HDFAmendments;
    expect(amendments.overrides[0]!.requirementId).toBe('V-12345');
  });

  it('should fall back to title for requirement ID', async () => {
    const doc = poamDocWithDeadline({ uuid: 'item-1', title: 'AC-1 Finding' });
    const output = await convertOscalPoamToHdf(doc);
    const amendments = JSON.parse(output) as HDFAmendments;
    expect(amendments.overrides[0]!.requirementId).toBe('AC-1 Finding');
  });

  it('should fall back to unknown for requirement ID', async () => {
    const doc = poamDocWithDeadline({ uuid: 'item-1' });
    const output = await convertOscalPoamToHdf(doc);
    const amendments = JSON.parse(output) as HDFAmendments;
    expect(amendments.overrides[0]!.requirementId).toBe('unknown');
  });

  it('should extract control ID from risk impacted-control-id', async () => {
    const doc = poamDocWithDeadline(
      { uuid: 'item-1', title: 'Finding' },
      { risk: { props: [{ name: 'impacted-control-id', value: 'ac-2' }] } },
    );
    const output = await convertOscalPoamToHdf(doc);
    const amendments = JSON.parse(output) as HDFAmendments;
    expect(amendments.overrides[0]!.requirementId).toBe('AC-2');
  });

  it('should map risk status to override status', async () => {
    const doc = poamDocWithDeadline({ uuid: 'item-1', title: 'Finding' }, { risk: { status: 'closed' } });
    const output = await convertOscalPoamToHdf(doc);
    const amendments = JSON.parse(output) as HDFAmendments;
    expect(amendments.overrides[0]!.status).toBe('passed');
  });

  it('should extract milestones from planned remediation tasks', async () => {
    const doc = poamDocWithDeadline(
      { uuid: 'item-1', title: 'Finding' },
      {
        risk: {
          remediations: [
            {
              lifecycle: 'planned',
              title: 'Fix',
              description: 'Apply patch',
              tasks: [
                {
                  uuid: 't1',
                  type: 'milestone',
                  title: 'Patch step',
                  timing: { 'within-date-range': { start: '2024-06-01T00:00:00Z', end: '2024-06-15T00:00:00Z' } },
                },
              ],
            },
            { lifecycle: 'completed', title: 'Done', description: 'Already fixed' },
          ],
        },
      },
    );
    const output = await convertOscalPoamToHdf(doc);
    const amendments = JSON.parse(output) as HDFAmendments;
    const milestones = amendments.overrides[0]!.milestones ?? [];
    // Only the planned remediation's task, dated from its within-date-range end.
    expect(milestones).toHaveLength(1);
    expect(milestones[0]!.description).toBe('Patch step');
    expect(milestones[0]!.estimatedCompletion).toBe('2024-06-15T00:00:00Z');
  });

  it('should extract appliedBy from prepared-by responsible-party', async () => {
    const doc = poamDocWithDeadline(
      { uuid: 'item-1', title: 'F' },
      { metadata: { 'responsible-parties': [{ 'role-id': 'prepared-by', 'party-uuids': ['user-abc'] }] } },
    );
    const output = await convertOscalPoamToHdf(doc);
    const amendments = JSON.parse(output) as HDFAmendments;
    expect(amendments.appliedBy?.identifier).toBe('user-abc');
  });

  it('should fall back to first responsible party', async () => {
    const doc = poamDocWithDeadline(
      { uuid: 'item-1', title: 'F' },
      { metadata: { 'responsible-parties': [{ 'role-id': 'other-role', 'party-uuids': ['user-xyz'] }] } },
    );
    const output = await convertOscalPoamToHdf(doc);
    const amendments = JSON.parse(output) as HDFAmendments;
    // poamItemAppliedBy uses prepared-by first, then first party
    expect(amendments.overrides[0]!.appliedBy?.identifier).toBe('user-xyz');
  });

  it('should fall back to system appliedBy when no responsible-parties', async () => {
    const doc = poamDocWithDeadline({ uuid: 'item-1', title: 'F' });
    const output = await convertOscalPoamToHdf(doc);
    const amendments = JSON.parse(output) as HDFAmendments;
    expect(amendments.overrides[0]!.appliedBy?.identifier).toBe('oscal-poam-converter');
  });

  it('should use item description as reason, falling back to title', async () => {
    const doc = poamDocWithDeadline({ uuid: 'item-1', title: 'My Title' });
    const output = await convertOscalPoamToHdf(doc);
    const amendments = JSON.parse(output) as HDFAmendments;
    expect(amendments.overrides[0]!.reason).toBe('My Title');
  });

  it('should fall back to default reason', async () => {
    const doc = poamDocWithDeadline({ uuid: 'item-1' });
    const output = await convertOscalPoamToHdf(doc);
    const amendments = JSON.parse(output) as HDFAmendments;
    expect(amendments.overrides[0]!.reason).toBe('POA&M item');
  });

  it('should fail loud on an invalid metadata.last-modified', async () => {
    const doc = poamDocWithDeadline({ uuid: 'item-1', title: 'F' }, { metadata: { 'last-modified': 'not-a-date' } });
    await expect(convertOscalPoamToHdf(doc)).rejects.toThrow('metadata.last-modified');
  });

  it('should extract systemRef from import-ssp', async () => {
    const doc = poamDocWithDeadline({ uuid: 'item-1', title: 'F' }, { top: { 'import-ssp': { href: 'ssp-ref.json' } } });
    const output = await convertOscalPoamToHdf(doc);
    const amendments = JSON.parse(output) as HDFAmendments;
    expect(amendments.systemRef).toBe('ssp-ref.json');
  });

  it('should handle risk with unrecognized status', async () => {
    const doc = poamDocWithDeadline({ uuid: 'item-1', title: 'Finding' }, { risk: { status: 'investigating' } });
    const output = await convertOscalPoamToHdf(doc);
    const amendments = JSON.parse(output) as HDFAmendments;
    // oscalStatusToHdf returns undefined for 'investigating', so falls through to default 'failed'
    expect(amendments.overrides[0]!.status).toBe('failed');
  });

  // Mirrors the Go peers: HDF's own constraints on an imported document
  // (Evidence.data, Milestone.title, StandaloneOverride.requirementId) are not
  // constraints a foreign OSCAL POA&M has to satisfy.
  const HDF_NS = 'https://mitre.github.io/hdf-libs/ns/oscal';
  const hdfProducedRiskProps = (extra: Array<Record<string, unknown>> = []) => ({
    props: [
      { name: 'override-type', ns: HDF_NS, value: 'waiver' },
      { name: 'hdf-requirement-id', ns: HDF_NS, value: 'CVE-2021-44228' },
      ...extra,
    ],
  });

  it('skips an evidence observation that carries no payload', async () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    const doc = poamDocWithDeadline(
      {
        uuid: 'item-1',
        title: 'Finding',
        'related-observations': [{ 'observation-uuid': 'obs-bare' }, { 'observation-uuid': 'obs-dangling' }, { 'observation-uuid': 'obs-href' }],
      },
      {
        risk: hdfProducedRiskProps(),
        top: {
          observations: [
            { uuid: 'obs-bare', description: 'Reviewed the change ticket', types: ['url'], collected: '2026-01-02T03:04:05Z' },
            { uuid: 'obs-dangling', description: 'd', types: ['file'], collected: '2026-01-02T03:04:05Z', links: [{ href: '#missing', rel: 'evidence' }] },
            { uuid: 'obs-href', description: 'd', types: ['url'], collected: '2026-01-02T03:04:05Z', 'relevant-evidence': [{ href: 'https://example.com/advisory' }] },
          ],
        },
      },
    );
    const amendments = JSON.parse(await convertOscalPoamToHdf(doc)) as HDFAmendments;
    const warnings = warn.mock.calls.map((c) => c[0] as string);
    warn.mockRestore();

    expect(amendments.overrides[0]!.evidence).toHaveLength(1);
    expect(amendments.overrides[0]!.evidence![0]!.data).toBe('https://example.com/advisory');
    expect(warnings).toContain('WARNING: Skipping evidence observation "obs-bare": no relevant-evidence href and no evidence resource');
    expect(warnings).toContain('WARNING: Skipping evidence observation "obs-dangling": no relevant-evidence href and no evidence resource');
  });

  it('drops a milestone title that is not the single line HDF carries', async () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    const task = (uuid: string, title: string) => ({
      uuid,
      type: 'milestone',
      title,
      timing: { 'within-date-range': { start: '2026-01-01T00:00:00Z', end: '2099-12-31T00:00:00Z' } },
    });
    const doc = poamDocWithDeadline(
      { uuid: 'item-1', title: 'Finding' },
      {
        risk: {
          ...hdfProducedRiskProps(),
          remediations: [{
            uuid: 'rem-1',
            lifecycle: 'planned',
            title: 'Fix',
            description: 'Patch the web tier',
            tasks: [task('t-ok', 'Deploy OpenSSH 9.8p1'), task('t-empty', ''), task('t-space', ' leading space'), task('t-wrapped', 'two\nlines')],
          }],
        },
      },
    );
    const amendments = JSON.parse(await convertOscalPoamToHdf(doc)) as HDFAmendments;
    const warnings = warn.mock.calls.map((c) => c[0] as string);
    warn.mockRestore();

    const milestones = amendments.overrides[0]!.milestones!;
    expect(milestones).toHaveLength(4);
    expect(milestones[0]!.title).toBe('Deploy OpenSSH 9.8p1');
    for (const ms of milestones.slice(1)) {
      expect(ms.title).toBeUndefined();
      expect(ms.description).toBe('Patch the web tier');
    }
    expect(warnings).toContain('WARNING: Dropping the title of task "t-empty": "" is not the single line Milestone.title is');
    expect(warnings).toContain('WARNING: Dropping the title of task "t-space": " leading space" is not the single line Milestone.title is');
    expect(warnings).toContain('WARNING: Dropping the title of task "t-wrapped": "two\\nlines" is not the single line Milestone.title is');
  });

  it('skips an HDF-produced risk that names no requirement, and fails when nothing is left', async () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    const doc = poamDocWithDeadline(
      { uuid: 'item-1', title: 'Some item' },
      { risk: { props: [{ name: 'override-type', ns: HDF_NS, value: 'waiver' }] } },
    );
    await expect(convertOscalPoamToHdf(doc)).rejects.toThrow('no poam-item names a requirement');
    const warnings = warn.mock.calls.map((c) => c[0] as string);
    warn.mockRestore();
    expect(warnings).toContain('WARNING: Skipping poam-item "item-1" titled "Some item": its HDF-produced risk has no hdf-requirement-id');
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
