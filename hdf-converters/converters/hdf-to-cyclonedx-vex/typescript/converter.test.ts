import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import {
  IdentityType,
  Justification,
  MilestoneStatus,
  OverrideType,
  ResultStatus,
  type HDFAmendments,
} from '@mitre/hdf-schema';
import { convertCyclonedxVexToHdf } from '../../cyclonedx-vex-to-hdf/typescript/converter.js';
import {
  allMilestonesCompleted,
  convertHdfToCyclonedxVex,
  productIDsFor,
  stripReasonAnnotations,
} from './converter.js';

const TEST_VERSION = 'test';

function loadInput(name: string): string {
  return readFileSync(join(__dirname, '..', 'fixtures', 'input', name), 'utf-8');
}

describe('convertHdfToCyclonedxVex — not_affected export', () => {
  it('produces a CycloneDX VEX envelope with one vulnerability', () => {
    const out = convertHdfToCyclonedxVex(
      loadInput('case1-not_affected-amendments.json'),
      TEST_VERSION,
    );
    const bom = JSON.parse(out);
    expect(bom.bomFormat).toBe('CycloneDX');
    expect(bom.specVersion).toBe('1.4');
    expect(bom.vulnerabilities).toHaveLength(1);
    const v = bom.vulnerabilities[0];
    expect(v.id).toBe('CVE-2021-44228');
    expect(v.analysis.state).toBe('not_affected');
    expect(v.analysis.justification).toBe('code_not_present');
    expect(v.affects).toHaveLength(1);
    expect(v.affects[0].ref).not.toBe('');
  });
});

describe('convertHdfToCyclonedxVex — open POA&M', () => {
  it('emits exploitable (NOT resolved) and workaround_available response', () => {
    const out = convertHdfToCyclonedxVex(
      loadInput('case1-fixed-amendments.json'),
      TEST_VERSION,
    );
    const bom = JSON.parse(out);
    expect(bom.vulnerabilities).toHaveLength(1);
    const v = bom.vulnerabilities[0];
    expect(v.analysis.state).toBe('exploitable');
    expect(v.analysis.response).toContain('workaround_available');
  });
});

describe('convertHdfToCyclonedxVex — closed POA&M', () => {
  it('all-milestones-completed promotes to resolved + update response', () => {
    const closed: HDFAmendments = {
      overrides: [
        {
          type: OverrideType.Poam,
          requirementId: 'CVE-2025-1000',
          status: ResultStatus.Failed,
          appliedAt: new Date('2026-01-01T00:00:00Z'),
          expiresAt: new Date('2027-01-01T00:00:00Z'),
          appliedBy: { type: IdentityType.Simple, identifier: 'ops' },
          reason: 'Vendor patch verified',
          milestones: [
            {
              description: 'Apply 1.2.4',
              status: MilestoneStatus.Completed,
              estimatedCompletion: new Date('2026-02-01T00:00:00Z'),
            },
          ],
        } as never,
      ],
    } as never;
    const out = convertHdfToCyclonedxVex(JSON.stringify(closed), TEST_VERSION);
    const bom = JSON.parse(out);
    expect(bom.vulnerabilities[0].analysis.state).toBe('resolved');
    expect(bom.vulnerabilities[0].analysis.response).toContain('update');
  });
});

describe('convertHdfToCyclonedxVex — round trip', () => {
  it('preserves CVE, status, justification, and product ref through CycloneDX -> HDF -> CycloneDX', async () => {
    const orig = readFileSync(
      join(
        __dirname,
        '..',
        '..',
        'cyclonedx-vex-to-hdf',
        'fixtures',
        'input',
        'case1-vex-not_affected.json',
      ),
      'utf-8',
    );
    const amendments = await convertCyclonedxVexToHdf(orig, TEST_VERSION);
    const hdfBytes = JSON.stringify(amendments);
    const out = convertHdfToCyclonedxVex(hdfBytes, TEST_VERSION);
    const round = JSON.parse(out);

    expect(round.vulnerabilities).toHaveLength(1);
    const v = round.vulnerabilities[0];
    expect(v.id).toBe('CVE-2021-44228');
    expect(v.analysis.state).toBe('not_affected');
    expect(v.analysis.justification).toBe('code_not_present');
    expect(v.affects[0].ref).not.toBe('');
  });
});

describe('convertHdfToCyclonedxVex — HDF-only justification omitted', () => {
  it('omits analysis.justification when the HDF value has no CycloneDX equivalent', () => {
    const amendments: HDFAmendments = {
      overrides: [
        {
          type: OverrideType.FalsePositive,
          requirementId: 'CVE-2026-9999',
          status: ResultStatus.Passed,
          appliedAt: new Date('2026-01-01T00:00:00Z'),
          expiresAt: new Date('2027-01-01T00:00:00Z'),
          appliedBy: { type: IdentityType.Simple, identifier: 'team' },
          reason: 'No equivalent CycloneDX value\nProducts: pkg:npm/x@1.0',
          justification: Justification.VulnerableCodeNotPresent,
        } as never,
      ],
    } as never;
    const out = convertHdfToCyclonedxVex(JSON.stringify(amendments), TEST_VERSION);
    const bom = JSON.parse(out);
    expect(bom.vulnerabilities[0].analysis.justification).toBeUndefined();
  });
});

describe('convertHdfToCyclonedxVex — affectedPackages preserve name/version in components', () => {
  it('emits component name+version+purl+cpe when affectedPackages carries them', () => {
    const amendments: HDFAmendments = {
      overrides: [
        {
          type: OverrideType.FalsePositive,
          requirementId: 'CVE-2026-5555',
          status: ResultStatus.Passed,
          appliedAt: new Date('2026-01-01T00:00:00Z'),
          expiresAt: new Date('2027-01-01T00:00:00Z'),
          appliedBy: { type: IdentityType.Simple, identifier: 'team' },
          reason: 'structured',
          affectedPackages: [
            {
              name: 'ABC',
              version: '4.2',
              ecosystem: 'generic',
              purl: 'pkg:npm/abc@4.2',
              cpe: 'cpe:2.3:a:acme:abc:4.2:*:*:*:*:*:*:*',
            },
          ],
        } as never,
      ],
    } as never;
    const out = convertHdfToCyclonedxVex(JSON.stringify(amendments), TEST_VERSION);
    const bom = JSON.parse(out);
    expect(bom.components).toHaveLength(1);
    expect(bom.components[0]).toEqual({
      type: 'application',
      name: 'ABC',
      'bom-ref': 'pkg:npm/abc@4.2',
      version: '4.2',
      purl: 'pkg:npm/abc@4.2',
      cpe: 'cpe:2.3:a:acme:abc:4.2:*:*:*:*:*:*:*',
    });
  });

  it('falls back to pid-only component when affectedPackages is absent (legacy path)', () => {
    const amendments: HDFAmendments = {
      overrides: [
        {
          type: OverrideType.FalsePositive,
          requirementId: 'CVE-2026-6666',
          status: ResultStatus.Passed,
          appliedAt: new Date('2026-01-01T00:00:00Z'),
          expiresAt: new Date('2027-01-01T00:00:00Z'),
          appliedBy: { type: IdentityType.Simple, identifier: 'team' },
          reason: 'legacy\nProducts: pkg:npm/legacy@1.0',
        } as never,
      ],
    } as never;
    const out = convertHdfToCyclonedxVex(JSON.stringify(amendments), TEST_VERSION);
    const bom = JSON.parse(out);
    expect(bom.components).toHaveLength(1);
    expect(bom.components[0].name).toBe('pkg:npm/legacy@1.0');
    expect(bom.components[0].purl).toBe('pkg:npm/legacy@1.0');
    expect(bom.components[0].version).toBeUndefined();
  });

  it('promotes cpe-only legacy product id to component.cpe', () => {
    const amendments: HDFAmendments = {
      overrides: [
        {
          type: OverrideType.FalsePositive,
          requirementId: 'CVE-2026-7777',
          status: ResultStatus.Passed,
          appliedAt: new Date('2026-01-01T00:00:00Z'),
          expiresAt: new Date('2027-01-01T00:00:00Z'),
          appliedBy: { type: IdentityType.Simple, identifier: 'team' },
          reason: 'cpe-only',
          componentRef: 'cpe:2.3:a:openssl:openssl:1.1.1k:*:*:*:*:*:*:*',
        } as never,
      ],
    } as never;
    const out = convertHdfToCyclonedxVex(JSON.stringify(amendments), TEST_VERSION);
    const bom = JSON.parse(out);
    expect(bom.components[0].cpe).toBe('cpe:2.3:a:openssl:openssl:1.1.1k:*:*:*:*:*:*:*');
  });
});

describe('convertHdfToCyclonedxVex — fixedInVersion mapping', () => {
  it('maps fixedInVersion to affects[].versions as a vers range (unaffected)', () => {
    const amendments: HDFAmendments = {
      overrides: [
        {
          type: OverrideType.FalsePositive,
          requirementId: 'CVE-2026-7777',
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
    const out = convertHdfToCyclonedxVex(JSON.stringify(amendments), TEST_VERSION);
    const bom = JSON.parse(out);
    expect(bom.vulnerabilities[0].affects[0].versions).toEqual([
      { version: '4.2', status: 'affected' },
      { range: 'vers:npm/>=4.5', status: 'unaffected' },
    ]);
    expect(bom.vulnerabilities[0].recommendation).toBeUndefined();
  });

  it('falls back to a recommendation when fixedInVersion has no vers type', () => {
    const amendments: HDFAmendments = {
      overrides: [
        {
          type: OverrideType.FalsePositive,
          requirementId: 'CVE-2026-8888',
          status: ResultStatus.Passed,
          appliedAt: new Date('2026-01-01T00:00:00Z'),
          expiresAt: new Date('2099-12-31T00:00:00Z'),
          appliedBy: { type: IdentityType.Simple, identifier: 'team' },
          reason: 'patched upstream',
          affectedPackages: [
            { cpe: 'cpe:2.3:a:acme:abc:4.2:*:*:*:*:*:*:*', fixedInVersion: '4.5' },
          ],
        } as never,
      ],
    } as never;
    const out = convertHdfToCyclonedxVex(JSON.stringify(amendments), TEST_VERSION);
    const bom = JSON.parse(out);
    expect(bom.vulnerabilities[0].recommendation).toBe('Upgrade to 4.5');
    expect(bom.vulnerabilities[0].affects[0].versions).toBeUndefined();
  });
});

describe('convertHdfToCyclonedxVex — CycloneDX-specific justification', () => {
  it('emits requires_configuration from the structured justification field', () => {
    const amendments: HDFAmendments = {
      overrides: [
        {
          type: OverrideType.FalsePositive,
          requirementId: 'CVE-2026-1234',
          status: ResultStatus.Passed,
          appliedAt: new Date('2026-01-01T00:00:00Z'),
          expiresAt: new Date('2027-01-01T00:00:00Z'),
          appliedBy: { type: IdentityType.Simple, identifier: 'team' },
          reason: 'Configuration prevents the issue.\nProducts: pkg:npm/x@1.0',
          justification: Justification.RequiresConfiguration,
        } as never,
      ],
    } as never;
    const out = convertHdfToCyclonedxVex(JSON.stringify(amendments), TEST_VERSION);
    const bom = JSON.parse(out);
    expect(bom.vulnerabilities[0].analysis.justification).toBe('requires_configuration');
  });
});

describe('convertHdfToCyclonedxVex — non-CVE overrides skipped', () => {
  it('drops non-CVE requirementIds', () => {
    const mix: HDFAmendments = {
      overrides: [
        {
          type: OverrideType.FalsePositive,
          requirementId: 'AC-2',
          status: ResultStatus.Passed,
          appliedAt: new Date('2026-01-01T00:00:00Z'),
          expiresAt: new Date('2027-01-01T00:00:00Z'),
          appliedBy: { type: IdentityType.Simple, identifier: 'a' },
          reason: 'policy',
        } as never,
        {
          type: OverrideType.FalsePositive,
          requirementId: 'CVE-2024-99999',
          status: ResultStatus.Passed,
          appliedAt: new Date('2026-01-01T00:00:00Z'),
          expiresAt: new Date('2027-01-01T00:00:00Z'),
          appliedBy: { type: IdentityType.Simple, identifier: 'a' },
          reason: 'not affected',
          justification: Justification.ComponentNotPresent,
        } as never,
      ],
    } as never;
    const out = convertHdfToCyclonedxVex(JSON.stringify(mix), TEST_VERSION);
    const bom = JSON.parse(out);
    expect(bom.vulnerabilities).toHaveLength(1);
    expect(bom.vulnerabilities[0].id).toBe('CVE-2024-99999');
  });

  it('errors when no CVE-shaped overrides remain', () => {
    const noCVE: HDFAmendments = {
      overrides: [
        {
          type: OverrideType.Attestation,
          requirementId: 'NIST-AC-1',
          status: ResultStatus.Passed,
          appliedAt: new Date('2026-01-01T00:00:00Z'),
          expiresAt: new Date('2027-01-01T00:00:00Z'),
          appliedBy: { type: IdentityType.Simple, identifier: 'a' },
          reason: 'manual',
        } as never,
      ],
    } as never;
    expect(() => convertHdfToCyclonedxVex(JSON.stringify(noCVE), TEST_VERSION)).toThrow(
      /no overrides with CVE-shaped requirementIds/,
    );
  });
});

describe('convertHdfToCyclonedxVex — multi-product + email identity', () => {
  it('sorts components by bom-ref and emits author email when identity type is Email', () => {
    const a: HDFAmendments = {
      appliedBy: { type: IdentityType.Email, identifier: 'ops@example.com' },
      overrides: [
        {
          type: OverrideType.FalsePositive,
          requirementId: 'CVE-2026-5000',
          status: ResultStatus.Passed,
          appliedAt: new Date('2026-01-01T00:00:00Z'),
          expiresAt: new Date('2027-01-01T00:00:00Z'),
          appliedBy: { type: IdentityType.Email, identifier: 'ops@example.com' },
          reason: 'multi-product\nProducts: zeta, alpha',
          justification: Justification.ComponentNotPresent,
        } as never,
      ],
    } as never;
    const out = convertHdfToCyclonedxVex(JSON.stringify(a), TEST_VERSION);
    const bom = JSON.parse(out);
    expect(bom.components.map((c: { 'bom-ref': string }) => c['bom-ref'])).toEqual(['alpha', 'zeta']);
    expect(bom.metadata.authors[0].email).toBe('ops@example.com');
    expect(bom.metadata.authors[0].name).toBeUndefined();
  });
});

describe('convertHdfToCyclonedxVex — amendmentId and sparse reason', () => {
  it('uses amendmentId in serialNumber when present and tolerates undefined reason', () => {
    const a: HDFAmendments = {
      amendmentId: 'AMD-42',
      overrides: [
        {
          type: OverrideType.FalsePositive,
          requirementId: 'CVE-2026-6000',
          status: ResultStatus.Passed,
          appliedAt: new Date('2026-01-01T00:00:00Z'),
          expiresAt: new Date('2027-01-01T00:00:00Z'),
          appliedBy: { type: IdentityType.Simple, identifier: 'a' },
          // reason intentionally undefined to exercise the ?? '' defensive arm
          justification: Justification.ComponentNotPresent,
        } as never,
      ],
    } as never;
    const out = convertHdfToCyclonedxVex(JSON.stringify(a), TEST_VERSION);
    const bom = JSON.parse(out);
    expect(bom.serialNumber).toBe('urn:uuid:AMD-42');
    expect(bom.vulnerabilities[0].affects[0].ref).toBe('HDFPID-0001');
  });
});

describe('convertHdfToCyclonedxVex — edge cases', () => {
  it('rejects invalid JSON', () => {
    expect(() => convertHdfToCyclonedxVex('not json', TEST_VERSION)).toThrow();
  });
  it('rejects oversized input', () => {
    expect(() => convertHdfToCyclonedxVex('x'.repeat(51 * 1024 * 1024), TEST_VERSION)).toThrow();
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
    expect(
      productIDsFor({ affectedPackages: [{}], reason: 'prose\nProducts: X' } as never),
    ).toEqual(['X']);
  });
  it('productIDsFor prefers componentRef when affectedPackages is unset', () => {
    expect(productIDsFor({ componentRef: 'pkg:npm/x@1.0', reason: 'Products: IGNORED' } as never)).toEqual([
      'pkg:npm/x@1.0',
    ]);
  });
  it('productIDsFor parses the Products line', () => {
    expect(productIDsFor({ reason: 'prose\nProducts: A, B' } as never)).toEqual(['A', 'B']);
  });
  it('productIDsFor falls back to default', () => {
    expect(productIDsFor({ reason: 'no products' } as never)).toEqual(['HDFPID-0001']);
  });
  it('stripReasonAnnotations removes Products/VEX justification/Response lines', () => {
    expect(
      stripReasonAnnotations(
        'prose\nProducts: A\nVEX justification: code_not_present\nResponse: update',
      ),
    ).toBe('prose');
    expect(stripReasonAnnotations('only prose')).toBe('only prose');
  });
  it('allMilestonesCompleted handles empty / mixed / all-complete', () => {
    expect(allMilestonesCompleted({} as never)).toBe(false);
    expect(allMilestonesCompleted({ milestones: [{ status: MilestoneStatus.Pending }] } as never)).toBe(false);
    expect(
      allMilestonesCompleted({
        milestones: [{ status: MilestoneStatus.Completed }, { status: MilestoneStatus.Completed }],
      } as never),
    ).toBe(true);
    expect(
      allMilestonesCompleted({
        milestones: [{ status: MilestoneStatus.Completed }, { status: MilestoneStatus.Pending }],
      } as never),
    ).toBe(false);
  });
});

describe('convertHdfToCyclonedxVex — cvss ratings', () => {
  it('emits a consumer-supplied cvss block as a CycloneDX rating', () => {
    const amendments = { overrides: [{
      type: 'falsePositive', requirementId: 'CVE-2021-44228', status: 'notApplicable', reason: 'nr',
      componentRef: 'pkg:maven/log4j@2.14.1',
      appliedBy: { type: 'simple', identifier: 'a' }, appliedAt: '2026-01-01T00:00:00Z',
      cvss: { version: '3.1', baseVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', baseScore: 10, baseSeverity: 'critical' },
    }] };
    const out = JSON.parse(convertHdfToCyclonedxVex(JSON.stringify(amendments), TEST_VERSION));
    const vuln = out.vulnerabilities.find((x: { id: string }) => x.id === 'CVE-2021-44228');
    expect(vuln.ratings[0].score).toBe(10);
    expect(vuln.ratings[0].method).toBe('CVSSv31');
    expect(vuln.ratings[0].vector).toContain('CVSS:3.1');
    expect(vuln.ratings[0].severity).toBe('critical');
  });

  const ratingMethod = (version: string): string | undefined => {
    const input = JSON.stringify({
      overrides: [{
        type: 'falsePositive', requirementId: 'CVE-2000-0001', status: 'notApplicable', reason: 'r',
        componentRef: 'pkg:x', appliedBy: { type: 'simple', identifier: 'a' }, appliedAt: '2026-01-01T00:00:00Z',
        cvss: { version, baseScore: 5 },
      }],
    });
    const out = JSON.parse(convertHdfToCyclonedxVex(input, TEST_VERSION));
    return out.vulnerabilities[0].ratings[0].method;
  };

  it('maps the rating method by CVSS version', () => {
    expect(ratingMethod('4.0')).toBe('CVSSv4');
    expect(ratingMethod('3.0')).toBe('CVSSv3');
    expect(ratingMethod('2.0')).toBe('CVSSv2');
    expect(ratingMethod('9.9')).toBe('other');
  });

  it('emits no rating when the cvss block has neither vector nor baseScore', () => {
    const input = JSON.stringify({
      overrides: [{
        type: 'falsePositive', requirementId: 'CVE-2000-0002', status: 'notApplicable', reason: 'r',
        componentRef: 'pkg:x', appliedBy: { type: 'simple', identifier: 'a' }, appliedAt: '2026-01-01T00:00:00Z',
        cvss: { version: '3.1' },
      }],
    });
    const out = JSON.parse(convertHdfToCyclonedxVex(input, TEST_VERSION));
    expect(out.vulnerabilities[0].ratings).toBeUndefined();
  });
});
