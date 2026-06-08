import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import {
  IdentityType,
  OverrideType,
  ResultStatus,
  type HDFAmendments,
} from '@mitre/hdf-schema';
import { convertCsafVexToHdf } from '../../csaf-vex-to-hdf/typescript/converter.js';
import { convertHdfToCsafVex, productIDsFor, stripProductsLine } from './converter.js';

const TEST_VERSION = 'test';

function loadInput(name: string): string {
  return readFileSync(join(__dirname, '..', 'fixtures', 'input', name), 'utf-8');
}

describe('convertHdfToCsafVex — known_not_affected export', () => {
  it('produces three vulnerabilities with flags from the sec-vex amendments', () => {
    const out = convertHdfToCsafVex(loadInput('sec-vex-amendments.json'), TEST_VERSION);
    const doc = JSON.parse(out);
    expect(doc.document.category).toBe('csaf_vex');
    expect(doc.vulnerabilities).toHaveLength(3);
    for (const v of doc.vulnerabilities) {
      expect(v.product_status.known_not_affected.length).toBeGreaterThan(0);
      expect(v.flags).toHaveLength(1);
      expect(v.flags[0].label).toBe('component_not_present');
    }
  });
});

describe('convertHdfToCsafVex — fixed import becomes known_affected on export', () => {
  it('open POA&M does not emit as fixed', () => {
    const out = convertHdfToCsafVex(loadInput('uc-01-fixed-amendments.json'), TEST_VERSION);
    const doc = JSON.parse(out);
    expect(doc.vulnerabilities).toHaveLength(1);
    const v = doc.vulnerabilities[0];
    expect(v.product_status.fixed).toBeUndefined();
    expect(v.product_status.known_affected.length).toBeGreaterThan(0);
    expect(v.remediations?.length).toBeGreaterThan(0);
  });
});

describe('convertHdfToCsafVex — round trip', () => {
  it('preserves canonical fields through CSAF -> HDF -> CSAF', async () => {
    const csafInput = readFileSync(
      join(
        __dirname,
        '..',
        '..',
        'csaf-vex-to-hdf',
        'fixtures',
        'input',
        'sec-vex-2022-0001.json',
      ),
      'utf-8',
    );
    const amendments = await convertCsafVexToHdf(csafInput, TEST_VERSION);
    const hdfBytes = JSON.stringify(amendments);
    const csafOut = convertHdfToCsafVex(hdfBytes, TEST_VERSION);
    const round = JSON.parse(csafOut);

    expect(round.vulnerabilities.map((v: { cve: string }) => v.cve)).toEqual([
      'CVE-2021-44228',
      'CVE-2021-45046',
      'CVE-2021-45105',
    ]);
    for (const v of round.vulnerabilities) {
      // CSAFPID-0001 in the source resolved against a
      // product_version_range branch (no specific version), so the
      // structured AffectedPackage walker drops it — the schema requires a
      // concrete name+version+ecosystem, purl, or cpe. On re-export, the
      // exporter falls back to the HDFPID-0001 placeholder; CVE identity,
      // status, and justification all still round-trip.
      expect(v.product_status.known_not_affected).toContain('HDFPID-0001');
      expect(v.flags[0].label).toBe('component_not_present');
    }
  });
});

describe('convertHdfToCsafVex — POA&M with all milestones complete promotes to fixed', () => {
  it('emits product_status.fixed + vendor_fix remediation when every milestone is completed', () => {
    const closedPoam: HDFAmendments = {
      name: 'Closed POAM',
      overrides: [
        {
          type: OverrideType.Poam,
          requirementId: 'CVE-2025-1000',
          status: ResultStatus.Failed,
          appliedAt: new Date('2026-01-01T00:00:00Z'),
          expiresAt: new Date('2027-01-01T00:00:00Z'),
          appliedBy: { type: IdentityType.Simple, identifier: 'ops' },
          reason: 'Vendor confirmed patch applied',
          milestones: [
            {
              description: 'Apply 1.2.4',
              status: 'completed' as never,
              estimatedCompletion: new Date('2026-02-01T00:00:00Z'),
            },
          ],
        } as never,
      ],
    };
    const out = convertHdfToCsafVex(JSON.stringify(closedPoam), TEST_VERSION);
    const doc = JSON.parse(out);
    expect(doc.vulnerabilities[0].product_status.fixed).toBeDefined();
    expect(doc.vulnerabilities[0].product_status.known_affected).toBeUndefined();
    expect(doc.vulnerabilities[0].remediations[0].category).toBe('vendor_fix');
  });
});

describe('convertHdfToCsafVex — non-CVE overrides are skipped', () => {
  function syntheticAmendments(overrides: HDFAmendments['overrides']): string {
    return JSON.stringify({
      name: 'Mixed',
      overrides,
    });
  }

  it('drops non-CVE requirementIds and keeps CVE-shaped ones', () => {
    const out = convertHdfToCsafVex(
      syntheticAmendments([
        {
          type: OverrideType.FalsePositive,
          requirementId: 'AC-2',
          status: ResultStatus.Passed,
          appliedAt: new Date('2026-01-01T00:00:00Z'),
          expiresAt: new Date('2027-01-01T00:00:00Z'),
          appliedBy: { type: IdentityType.Simple, identifier: 'alice' },
          reason: 'compensating control',
        } as never,
        {
          type: OverrideType.FalsePositive,
          requirementId: 'CVE-2024-99999',
          status: ResultStatus.Passed,
          appliedAt: new Date('2026-01-01T00:00:00Z'),
          expiresAt: new Date('2027-01-01T00:00:00Z'),
          appliedBy: { type: IdentityType.Simple, identifier: 'alice' },
          reason: 'not affected',
        } as never,
      ]),
      TEST_VERSION,
    );
    const doc = JSON.parse(out);
    expect(doc.vulnerabilities).toHaveLength(1);
    expect(doc.vulnerabilities[0].cve).toBe('CVE-2024-99999');
  });

  it('errors when no CVE overrides remain', () => {
    expect(() =>
      convertHdfToCsafVex(
        syntheticAmendments([
          {
            type: OverrideType.Attestation,
            requirementId: 'AC-1',
            status: ResultStatus.Passed,
            appliedAt: new Date('2026-01-01T00:00:00Z'),
            expiresAt: new Date('2027-01-01T00:00:00Z'),
            appliedBy: { type: IdentityType.Simple, identifier: 'x' },
            reason: 'manual',
          } as never,
        ]),
        TEST_VERSION,
      ),
    ).toThrow(/no overrides with CVE-shaped requirementIds/);
  });
});

describe('convertHdfToCsafVex — sparse-field defensive paths', () => {
  const minimal: HDFAmendments = {
    overrides: [
      {
        type: OverrideType.FalsePositive,
        requirementId: 'CVE-2026-1234',
        status: ResultStatus.Passed,
        appliedAt: new Date('2026-01-01T00:00:00Z'),
        expiresAt: new Date('2027-01-01T00:00:00Z'),
        appliedBy: { type: IdentityType.Simple, identifier: 'op' },
        reason: 'not affected',
        evidence: [
          { type: 'url' as never, data: 'https://example.com/x' },
          { type: 'url' as never, data: 'https://example.com/x' }, // dedup
          { type: 'url' as never, data: '' }, // dropped
        ],
      } as never,
    ],
  } as never;

  it('drops evidence without URL data and dedups references; tolerates missing description and name', () => {
    const out = convertHdfToCsafVex(JSON.stringify(minimal), TEST_VERSION);
    const doc = JSON.parse(out);
    expect(doc.vulnerabilities[0].references).toHaveLength(1);
    expect(doc.document.title).toBe('HDF Amendments exported as CSAF VEX');
  });
});

describe('convertHdfToCsafVex — open POA&M without milestones', () => {
  it('emits known_affected without remediations when milestones array is absent', () => {
    const noMilestonePoam: HDFAmendments = {
      overrides: [
        {
          type: OverrideType.Poam,
          requirementId: 'CVE-2026-3000',
          status: ResultStatus.Failed,
          appliedAt: new Date('2026-01-01T00:00:00Z'),
          expiresAt: new Date('2027-01-01T00:00:00Z'),
          appliedBy: { type: IdentityType.Simple, identifier: 'ops' },
          reason: 'tracking remediation',
        } as never,
      ],
    } as never;
    const out = convertHdfToCsafVex(JSON.stringify(noMilestonePoam), TEST_VERSION);
    const doc = JSON.parse(out);
    expect(doc.vulnerabilities[0].product_status.known_affected).toBeDefined();
    expect(doc.vulnerabilities[0].remediations).toBeUndefined();
  });
});

describe('convertHdfToCsafVex — affected override without milestones', () => {
  it('waiver (affected) override emits known_affected without remediations', () => {
    const waiver: HDFAmendments = {
      overrides: [
        {
          type: OverrideType.Waiver,
          requirementId: 'CVE-2026-2000',
          status: ResultStatus.Passed,
          appliedAt: new Date('2026-01-01T00:00:00Z'),
          expiresAt: new Date('2027-01-01T00:00:00Z'),
          appliedBy: { type: IdentityType.Simple, identifier: 'ao' },
          reason: '',
        } as never,
      ],
    } as never;
    const out = convertHdfToCsafVex(JSON.stringify(waiver), TEST_VERSION);
    const doc = JSON.parse(out);
    expect(doc.vulnerabilities[0].product_status.known_affected).toBeDefined();
    expect(doc.vulnerabilities[0].remediations).toBeUndefined();
    expect(doc.vulnerabilities[0].threats).toBeUndefined();
  });
});

describe('convertHdfToCsafVex — edge cases', () => {
  it('rejects invalid JSON', () => {
    expect(() => convertHdfToCsafVex('not json', TEST_VERSION)).toThrow();
  });
  it('rejects oversized input', () => {
    expect(() => convertHdfToCsafVex('x'.repeat(51 * 1024 * 1024), TEST_VERSION)).toThrow();
  });
});

describe('helpers', () => {
  it('productIDsFor prefers affectedPackages over componentRef and reason', () => {
    expect(
      productIDsFor({
        affectedPackages: [{ purl: 'pkg:npm/x@1.0' }],
        componentRef: 'COMP-IGNORED',
        reason: 'Products: ALSO-IGNORED',
      } as never),
    ).toEqual(['pkg:npm/x@1.0']);
  });
  it('productIDsFor skips affectedPackages entries with no identifying field', () => {
    // Empty affectedPackages array → falls through to legacy fallback.
    expect(
      productIDsFor({ affectedPackages: [{}], reason: 'prose\nProducts: X' } as never),
    ).toEqual(['X']);
  });
  it('productIDsFor prefers componentRef when affectedPackages is unset', () => {
    expect(productIDsFor({ componentRef: 'COMP-1', reason: 'Products: IGNORED' } as never)).toEqual([
      'COMP-1',
    ]);
  });
  it('productIDsFor parses the Products line', () => {
    expect(
      productIDsFor({ reason: 'prose\nProducts: CSAFPID-1, CSAFPID-2' } as never),
    ).toEqual(['CSAFPID-1', 'CSAFPID-2']);
  });
  it('productIDsFor falls back to default', () => {
    expect(productIDsFor({ reason: 'no products line' } as never)).toEqual(['HDFPID-0001']);
  });
  it('stripProductsLine removes the tail', () => {
    expect(stripProductsLine('prose\nProducts: A, B')).toBe('prose');
    expect(stripProductsLine('only prose')).toBe('only prose');
  });
});
