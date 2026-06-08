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
import { convertOpenVexToHdf } from '../../openvex-to-hdf/typescript/converter.js';
import { convertHdfToOpenVex, productsFor, stripProductsLine } from './converter.js';

const TEST_VERSION = 'test';

function loadInput(name: string): string {
  return readFileSync(join(__dirname, '..', 'fixtures', 'input', name), 'utf-8');
}

describe('convertHdfToOpenVex — not_affected export', () => {
  it('produces an OpenVEX document with the canonical fields', async () => {
    const out = await convertHdfToOpenVex(
      loadInput('spring-boot-log4j-amendments.json'),
      TEST_VERSION,
    );
    const doc = JSON.parse(out);
    expect(doc['@context']).toContain('openvex.dev');
    expect(doc.statements).toHaveLength(1);
    const s = doc.statements[0];
    expect(s.vulnerability.name).toBe('CVE-2021-44228');
    expect(s.status).toBe('not_affected');
    expect(s.justification).toBe('vulnerable_code_not_in_execute_path');
    expect(s.products[0]['@id']).toContain('spring-boot');
  });
});

describe('convertHdfToOpenVex — multi-status export', () => {
  it('open POA&M from VEX fixed stays affected, not_affected stays not_affected', async () => {
    const out = await convertHdfToOpenVex(loadInput('multi-status-amendments.json'), TEST_VERSION);
    const doc = JSON.parse(out);
    const byCVE = new Map<string, { status: string; action_statement?: string; justification?: string }>(
      doc.statements.map((s: { vulnerability: { name: string }; status: string; action_statement?: string; justification?: string }) => [
        s.vulnerability.name,
        { status: s.status, action_statement: s.action_statement, justification: s.justification },
      ]),
    );

    const na = byCVE.get('CVE-2024-1000');
    expect(na?.status).toBe('not_affected');
    expect(na?.justification).toBe('component_not_present');

    const fixed = byCVE.get('CVE-2024-2000');
    expect(fixed?.status).toBe('affected'); // open POA&M
    expect(fixed?.action_statement).toMatch(/vendor reports fix/);
  });
});

describe('convertHdfToOpenVex — round trip', () => {
  it('preserves CVE id, status, justification, and product PURL through OpenVEX -> HDF -> OpenVEX', async () => {
    const orig = readFileSync(
      join(
        __dirname,
        '..',
        '..',
        'openvex-to-hdf',
        'fixtures',
        'input',
        'spring-boot-log4j.openvex.json',
      ),
      'utf-8',
    );
    const amendments = await convertOpenVexToHdf(orig, TEST_VERSION);
    const hdfBytes = JSON.stringify(amendments);
    const out = await convertHdfToOpenVex(hdfBytes, TEST_VERSION);
    const round = JSON.parse(out);

    expect(round.statements).toHaveLength(1);
    const s = round.statements[0];
    expect(s.vulnerability.name).toBe('CVE-2021-44228');
    expect(s.status).toBe('not_affected');
    expect(s.justification).toBe('vulnerable_code_not_in_execute_path');
    expect(s.products[0]['@id']).toBe('pkg:maven/org.springframework.boot/spring-boot@2.6.0-M3');
  });
});

describe('convertHdfToOpenVex — closed POA&M', () => {
  it('all-milestones-completed promotes to fixed with action_statement from milestone', async () => {
    const closed: HDFAmendments = {
      overrides: [
        {
          type: OverrideType.Poam,
          requirementId: 'CVE-2025-1234',
          status: ResultStatus.Failed,
          appliedAt: new Date('2026-01-01T00:00:00Z'),
          expiresAt: new Date('2027-01-01T00:00:00Z'),
          appliedBy: { type: IdentityType.Simple, identifier: 'ops' },
          reason: 'Patch applied',
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
    const out = await convertHdfToOpenVex(JSON.stringify(closed), TEST_VERSION);
    const doc = JSON.parse(out);
    const s = doc.statements[0];
    expect(s.status).toBe('fixed');
    expect(s.action_statement).toBe('Apply 1.2.4');
  });
});

describe('convertHdfToOpenVex — non-CVE overrides skipped', () => {
  it('drops non-CVE requirementIds and keeps CVE-shaped ones', async () => {
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
    const out = await convertHdfToOpenVex(JSON.stringify(mix), TEST_VERSION);
    const doc = JSON.parse(out);
    expect(doc.statements).toHaveLength(1);
    expect(doc.statements[0].vulnerability.name).toBe('CVE-2024-99999');
  });

  it('errors when no CVE-shaped overrides remain', async () => {
    const noCVE: HDFAmendments = {
      overrides: [
        {
          type: OverrideType.Attestation,
          requirementId: 'NIST-AC-1',
          status: ResultStatus.Passed,
          appliedAt: new Date('2026-01-01T00:00:00Z'),
          expiresAt: new Date('2027-01-01T00:00:00Z'),
          appliedBy: { type: IdentityType.Simple, identifier: 'a' },
          reason: 'policy',
        } as never,
      ],
    } as never;
    await expect(convertHdfToOpenVex(JSON.stringify(noCVE), TEST_VERSION)).rejects.toThrow(
      /no overrides with CVE-shaped requirementIds/,
    );
  });
});

describe('convertHdfToOpenVex — amendmentId becomes document @id', () => {
  it('uses amendmentId in the document @id when present', async () => {
    const a: HDFAmendments = {
      amendmentId: 'ABC-999',
      overrides: [
        {
          type: OverrideType.FalsePositive,
          requirementId: 'CVE-2024-99999',
          status: ResultStatus.Passed,
          appliedAt: new Date('2026-01-01T00:00:00Z'),
          expiresAt: new Date('2027-01-01T00:00:00Z'),
          appliedBy: { type: IdentityType.Simple, identifier: 'a' },
          reason: '',
          justification: Justification.ComponentNotPresent,
        } as never,
      ],
    } as never;
    const out = await convertHdfToOpenVex(JSON.stringify(a), TEST_VERSION);
    const doc = JSON.parse(out);
    expect(doc['@id']).toContain('vex-ABC-999');
  });
});

describe('convertHdfToOpenVex — closed POA&M with empty milestone description', () => {
  it('falls back to default action_statement when milestone has no description', async () => {
    const closed: HDFAmendments = {
      overrides: [
        {
          type: OverrideType.Poam,
          requirementId: 'CVE-2027-5000',
          status: ResultStatus.Failed,
          appliedAt: new Date('2026-01-01T00:00:00Z'),
          expiresAt: new Date('2027-01-01T00:00:00Z'),
          appliedBy: { type: IdentityType.Simple, identifier: 'ops' },
          reason: 'Patch applied',
          milestones: [
            { description: '', status: MilestoneStatus.Completed, estimatedCompletion: new Date('2026-02-01T00:00:00Z') },
          ],
        } as never,
      ],
    } as never;
    const out = await convertHdfToOpenVex(JSON.stringify(closed), TEST_VERSION);
    const doc = JSON.parse(out);
    expect(doc.statements[0].status).toBe('fixed');
    expect(doc.statements[0].action_statement).toMatch(/Fix applied/);
  });
});

describe('convertHdfToOpenVex — edge cases', () => {
  it('rejects invalid JSON', async () => {
    await expect(convertHdfToOpenVex('not json', TEST_VERSION)).rejects.toThrow();
  });
  it('rejects oversized input', async () => {
    await expect(convertHdfToOpenVex('x'.repeat(51 * 1024 * 1024), TEST_VERSION)).rejects.toThrow();
  });
});

describe('helpers', () => {
  it('productsFor prefers affectedPackages over componentRef and reason', () => {
    expect(
      productsFor({
        affectedPackages: [{ purl: 'pkg:npm/x@1.0' }],
        componentRef: 'COMP-IGNORED',
        reason: 'Products: ALSO-IGNORED',
      } as never),
    ).toEqual([{ '@id': 'pkg:npm/x@1.0' }]);
  });
  it('productsFor skips affectedPackages entries with no identifying field', () => {
    expect(
      productsFor({ affectedPackages: [{}], reason: 'prose\nProducts: X' } as never),
    ).toEqual([{ '@id': 'X' }]);
  });
  it('productsFor prefers componentRef when affectedPackages is unset', () => {
    expect(productsFor({ componentRef: 'COMP-1', reason: 'Products: IGNORED' } as never)).toEqual([
      { '@id': 'COMP-1' },
    ]);
  });
  it('productsFor parses the Products line', () => {
    expect(productsFor({ reason: 'prose\nProducts: A, B' } as never)).toEqual([
      { '@id': 'A' },
      { '@id': 'B' },
    ]);
  });
  it('productsFor falls back to default', () => {
    expect(productsFor({ reason: 'no products' } as never)).toEqual([{ '@id': 'HDFPID-0001' }]);
  });
  it('stripProductsLine removes the tail', () => {
    expect(stripProductsLine('prose\nProducts: A')).toBe('prose');
  });
});
