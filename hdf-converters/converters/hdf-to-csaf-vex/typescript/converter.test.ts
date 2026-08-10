import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import {
  IdentityType,
  OverrideType,
  ResultStatus,
  type HDFAmendments,
} from '@mitre/hdf-schema';
import { amendments as sharedAmendments } from '@mitre/hdf-fixtures';
import { convertCsafVexToHdf } from '../../csaf-vex-to-hdf/typescript/converter.js';
import { convertHdfToCsafVex, productIDsFor, stripProductsLine } from './converter.js';

const TEST_VERSION = 'test';

// uc-01-fixed-amendments.json lives in the shared corpus (hdf-to-oscal-poam
// consumes it too); the other inputs are local to this converter.
function loadInput(name: string): string {
  if (name === 'uc-01-fixed-amendments.json') return sharedAmendments.uc01Fixed.read();
  return readFileSync(join(__dirname, '..', 'fixtures', 'input', name), 'utf-8');
}

function loadGolden(name: string): string {
  return readFileSync(join(__dirname, '..', 'fixtures', 'expected', name), 'utf-8');
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

describe('convertHdfToCsafVex — fixedInVersion export', () => {
  it('maps fixedInVersion to a first_fixed product + vendor_fix remediation', () => {
    const amendments: HDFAmendments = {
      overrides: [
        {
          type: OverrideType.FalsePositive,
          requirementId: 'CVE-2026-9999',
          status: ResultStatus.Passed,
          appliedAt: new Date('2026-01-01T00:00:00Z'),
          expiresAt: new Date('2099-12-31T00:00:00Z'),
          appliedBy: { type: IdentityType.Simple, identifier: 'team' },
          reason: 'patched upstream',
          affectedPackages: [
            { name: 'abc', version: '4.2', purl: 'pkg:npm/abc@4.2', fixedInVersion: '4.5' },
          ],
        } as never,
      ],
    } as never;
    const out = convertHdfToCsafVex(JSON.stringify(amendments), TEST_VERSION);
    const doc = JSON.parse(out);
    const v = doc.vulnerabilities[0];
    expect(v.product_status.first_fixed).toContain('pkg:npm/abc@4.5');
    expect(v.product_status.fixed).toContain('pkg:npm/abc@4.5');
    const vf = v.remediations.find(
      (r: { category: string }) => r.category === 'vendor_fix',
    );
    expect(vf.details).toBe('Fixed in 4.5');
    expect(vf.product_ids).toEqual(['pkg:npm/abc@4.5']);
    const ids = doc.product_tree.full_product_names.map(
      (p: { product_id: string }) => p.product_id,
    );
    expect(ids).toContain('pkg:npm/abc@4.5');
  });
});

describe('convertHdfToCsafVex — product_tree ordering', () => {
  it('emits product ids globally sorted (parity with Go), not in CVE/group order', () => {
    const amendments: HDFAmendments = {
      overrides: [
        {
          type: OverrideType.FalsePositive,
          requirementId: 'CVE-2026-0001',
          status: ResultStatus.Passed,
          appliedAt: new Date('2026-01-01T00:00:00Z'),
          expiresAt: new Date('2099-12-31T00:00:00Z'),
          appliedBy: { type: IdentityType.Simple, identifier: 'team' },
          reason: 'x',
          affectedPackages: [{ purl: 'pkg:npm/zzz@1.0' }],
        },
        {
          type: OverrideType.FalsePositive,
          requirementId: 'CVE-2026-0002',
          status: ResultStatus.Passed,
          appliedAt: new Date('2026-01-01T00:00:00Z'),
          expiresAt: new Date('2099-12-31T00:00:00Z'),
          appliedBy: { type: IdentityType.Simple, identifier: 'team' },
          reason: 'x',
          affectedPackages: [{ purl: 'pkg:npm/aaa@1.0' }],
        },
      ] as never,
    } as never;
    const doc = JSON.parse(convertHdfToCsafVex(JSON.stringify(amendments), TEST_VERSION));
    const ids = doc.product_tree.full_product_names.map(
      (p: { product_id: string }) => p.product_id,
    );
    expect(ids).toEqual(['pkg:npm/aaa@1.0', 'pkg:npm/zzz@1.0']);
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

describe('convertHdfToCsafVex — cvss scores', () => {
  it('emits a consumer-supplied cvss block as a CSAF score', () => {
    const amendments = {
      overrides: [{
        type: 'falsePositive',
        requirementId: 'CVE-2021-44228',
        status: 'notApplicable',
        reason: 'not reachable',
        componentRef: 'pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1',
        appliedBy: { type: 'simple', identifier: 'a' },
        appliedAt: '2026-01-01T00:00:00Z',
        cvss: {
          version: '3.1',
          baseVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
          baseScore: 10,
          baseSeverity: 'critical',
        },
      }],
    };
    const out = JSON.parse(convertHdfToCsafVex(JSON.stringify(amendments), TEST_VERSION));
    const vuln = out.vulnerabilities.find((x: { cve: string }) => x.cve === 'CVE-2021-44228');
    expect(vuln.scores[0].cvss_v3.baseScore).toBe(10);
    expect(vuln.scores[0].cvss_v3.vectorString).toContain('CVSS:3.1');
    expect(vuln.scores[0].cvss_v3.version).toBe('3.1');
    expect(vuln.scores[0].products.length).toBeGreaterThan(0);
  });

  const cvssOverride = (cvss: Record<string, unknown>): string =>
    JSON.stringify({
      overrides: [{
        type: 'falsePositive', requirementId: 'CVE-2000-0001', status: 'notApplicable', reason: 'r',
        componentRef: 'pkg:x', appliedBy: { type: 'simple', identifier: 'a' }, appliedAt: '2026-01-01T00:00:00Z', cvss,
      }],
    });

  it('keys the score by CVSS version (v4, v2)', () => {
    const v4 = JSON.parse(convertHdfToCsafVex(cvssOverride({ version: '4.0', baseScore: 9.3, baseVector: 'CVSS:4.0/AV:N' }), TEST_VERSION));
    expect(v4.vulnerabilities[0].scores[0].cvss_v4.version).toBe('4.0');
    const v2 = JSON.parse(convertHdfToCsafVex(cvssOverride({ version: '2.0', baseScore: 7.5, baseVector: 'AV:N/AC:L/Au:N/C:P/I:P/A:P' }), TEST_VERSION));
    expect(v2.vulnerabilities[0].scores[0].cvss_v2.version).toBe('2.0');
  });

  it('emits no score when the cvss block has neither vector nor baseScore', () => {
    const out = JSON.parse(convertHdfToCsafVex(cvssOverride({ version: '3.1' }), TEST_VERSION));
    const vuln = out.vulnerabilities.find((x: { cve: string }) => x.cve === 'CVE-2000-0001');
    expect(vuln?.scores).toBeUndefined();
  });
});

describe('convertHdfToCsafVex — new field exports', () => {
  it('surfaces reason as a description note on not_affected statements', () => {
    const out = JSON.parse(convertHdfToCsafVex(loadInput('sec-vex-amendments.json'), TEST_VERSION));
    expect(out.vulnerabilities).toHaveLength(3);
    for (const v of out.vulnerabilities) {
      expect(v.notes).toHaveLength(1);
      expect(v.notes[0].category).toBe('description');
      expect(v.notes[0].text.length).toBeGreaterThan(0);
    }
  });

  it('emits product_identification_helper.purl and round-trips the package identity', async () => {
    const purl = 'pkg:npm/left-pad@1.3.0';
    const amendments: HDFAmendments = {
      name: 'purl round-trip',
      overrides: [
        {
          type: OverrideType.FalsePositive,
          requirementId: 'CVE-2026-7777',
          status: ResultStatus.Passed,
          appliedAt: new Date('2026-01-01T00:00:00Z'),
          expiresAt: new Date('2099-12-31T00:00:00Z'),
          appliedBy: { type: IdentityType.Simple, identifier: 'team' },
          justification: 'component_not_present' as never,
          reason: 'left-pad is not bundled',
          affectedPackages: [
            { name: 'left-pad', version: '1.3.0', ecosystem: 'npm' as never, purl },
          ],
        } as never,
      ],
    } as never;
    const out = convertHdfToCsafVex(JSON.stringify(amendments), TEST_VERSION);
    const doc = JSON.parse(out);
    expect(doc.product_tree.full_product_names).toHaveLength(1);
    const fpn = doc.product_tree.full_product_names[0];
    expect(fpn.product_id).toBe(purl);
    expect(fpn.product_identification_helper.purl).toBe(purl);

    const roundTripped = await convertCsafVexToHdf(out, TEST_VERSION);
    expect(roundTripped.overrides).toHaveLength(1);
    expect(roundTripped.overrides[0].affectedPackages?.[0].purl).toBe(purl);
  });

  it('emits product_identification_helper.cpe for a cpe-only package', () => {
    const cpe = 'cpe:2.3:a:openssl:openssl:1.1.1k:*:*:*:*:*:*:*';
    const amendments: HDFAmendments = {
      name: 'cpe helper',
      overrides: [
        {
          type: OverrideType.FalsePositive,
          requirementId: 'CVE-2026-8888',
          status: ResultStatus.Passed,
          appliedAt: new Date('2026-01-01T00:00:00Z'),
          expiresAt: new Date('2099-12-31T00:00:00Z'),
          appliedBy: { type: IdentityType.Simple, identifier: 'team' },
          justification: 'component_not_present' as never,
          reason: 'not affected',
          affectedPackages: [{ cpe } as never],
        } as never,
      ],
    } as never;
    const doc = JSON.parse(convertHdfToCsafVex(JSON.stringify(amendments), TEST_VERSION));
    expect(doc.product_tree.full_product_names[0].product_identification_helper.cpe).toBe(cpe);
  });

  it('surfaces externalReferences[].href as references, skipping href-less entries', () => {
    const amendments: HDFAmendments = {
      name: 'external refs',
      overrides: [
        {
          type: OverrideType.FalsePositive,
          requirementId: 'CVE-2026-6666',
          status: ResultStatus.Passed,
          appliedAt: new Date('2026-01-01T00:00:00Z'),
          expiresAt: new Date('2099-12-31T00:00:00Z'),
          appliedBy: { type: IdentityType.Simple, identifier: 'team' },
          justification: 'component_not_present' as never,
          reason: 'not affected',
          externalReferences: [
            { sourceName: 'stix', href: 'https://cti.example.com/indicator/42', description: 'STIX indicator' },
            { sourceName: 'cve', externalId: 'CVE-2026-6666' },
          ],
        } as never,
      ],
    } as never;
    const doc = JSON.parse(convertHdfToCsafVex(JSON.stringify(amendments), TEST_VERSION));
    const refs = doc.vulnerabilities[0].references;
    expect(refs).toHaveLength(1);
    expect(refs[0].url).toBe('https://cti.example.com/indicator/42');
    expect(refs[0].summary).toBe('STIX indicator');
  });

  it('renders milestone completedAt (preferred over estimate) as remediation date', () => {
    const amendments: HDFAmendments = {
      name: 'milestone dates',
      overrides: [
        {
          type: OverrideType.Poam,
          requirementId: 'CVE-2026-5555',
          status: ResultStatus.Failed,
          appliedAt: new Date('2026-01-01T00:00:00Z'),
          expiresAt: new Date('2099-12-31T00:00:00Z'),
          appliedBy: { type: IdentityType.Simple, identifier: 'ops' },
          reason: 'tracking',
          milestones: [
            {
              description: 'apply patch',
              status: 'completed' as never,
              estimatedCompletion: new Date('2026-02-01T00:00:00Z'),
              completedAt: new Date('2026-03-15T00:00:00Z'),
            },
          ],
        } as never,
      ],
    } as never;
    const doc = JSON.parse(convertHdfToCsafVex(JSON.stringify(amendments), TEST_VERSION));
    expect(doc.vulnerabilities[0].remediations[0].date).toBe('2026-03-15T00:00:00Z');
  });
});

// Byte-for-byte equality with the SAME golden files the Go TestGoldenParity
// asserts against — this is what keeps the TS and Go exporters from drifting.
describe('convertHdfToCsafVex — golden parity', () => {
  it.each(['sec-vex-amendments', 'uc-01-fixed-amendments'])(
    'matches the %s golden byte-for-byte (TS↔Go parity)',
    (name) => {
      expect(convertHdfToCsafVex(loadInput(`${name}.json`), TEST_VERSION)).toBe(
        loadGolden(`${name}.csaf-vex.json`),
      );
    },
  );
});
