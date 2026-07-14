import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import {
  Justification,
  MilestoneStatus,
  OverrideType,
  ResultStatus,
} from '@mitre/hdf-schema';
import { expectValidAmendments } from '../../../test/helpers/expectValidHdf.js';
import { assertOverrideCount } from '../../../shared/typescript/anchor.js';
import { convertCsafVexToHdf } from './converter.js';

const TEST_VERSION = 'test';

function loadInput(name: string): string {
  return readFileSync(join(__dirname, '..', 'fixtures', 'input', name), 'utf-8');
}

describe('convertCsafVexToHdf — not_affected use case', () => {
  it('produces a falsePositive override carrying the threat detail', async () => {
    const result = await convertCsafVexToHdf(
      loadInput('2022-evd-uc-01-na-001.json'),
      TEST_VERSION,
    );
    expectValidAmendments(result);
    expect(result.overrides).toHaveLength(1);
    const o = result.overrides[0];
    expect(o.requirementId).toBe('CVE-2021-44228');
    expect(o.type).toBe(OverrideType.FalsePositive);
    expect(o.status).toBe(ResultStatus.Passed);
    expect(o.justification).toBeUndefined();
    expect(o.reason).toContain('Class with vulnerable code was removed');
    expect(o.reason).not.toContain('CSAFPID-0001');
    // CSAFPID-0001 resolves through product_tree's vendor/product_name/
    // product_version branch hierarchy → name "ABC", version "4.2".
    expect(o.affectedPackages).toBeDefined();
    expect(o.affectedPackages?.[0]?.name).toBe('ABC');
    expect(o.affectedPackages?.[0]?.version).toBe('4.2');
  });
});

describe('convertCsafVexToHdf — fixed use case', () => {
  it('produces a POA&M pinned to failed with a pending milestone', async () => {
    const result = await convertCsafVexToHdf(
      loadInput('2022-evd-uc-01-f-001.json'),
      TEST_VERSION,
    );
    expect(result.overrides).toHaveLength(1);
    const o = result.overrides[0];
    expect(o.type).toBe(OverrideType.Poam);
    expect(o.status).toBe(ResultStatus.Failed);
    expect(o.milestones).toHaveLength(1);
    expect(o.milestones?.[0].status).toBe(MilestoneStatus.Pending);
  });
});

describe('convertCsafVexToHdf — sec-vex example with flags', () => {
  it('produces three falsePositive overrides each with component_not_present justification', async () => {
    const result = await convertCsafVexToHdf(loadInput('sec-vex-2022-0001.json'), TEST_VERSION);
    expect(result.overrides).toHaveLength(3);
    for (const o of result.overrides) {
      expect(o.type).toBe(OverrideType.FalsePositive);
      expect(o.justification).toBe(Justification.ComponentNotPresent);
      expect(o.evidence?.length ?? 0).toBeGreaterThan(0);
    }
  });

  it('first evidence is the advisory URI built from publisher.namespace + tracking.id', async () => {
    const result = await convertCsafVexToHdf(loadInput('sec-vex-2022-0001.json'), TEST_VERSION);
    expect(result.overrides[0].evidence?.[0].data).toContain('github.com/secvisogram');
  });
});

describe('convertCsafVexToHdf — empty actionable statements', () => {
  it.each([
    ['2022-evd-uc-01-a-001.json', 'known_affected'],
    ['2022-evd-uc-01-ui-001.json', 'under_investigation'],
  ])('errors on %s (%s)', async (file) => {
    await expect(convertCsafVexToHdf(loadInput(file), TEST_VERSION)).rejects.toThrow(
      /no actionable statements/,
    );
  });
});

describe('convertCsafVexToHdf — sparse field fallbacks', () => {
  // Exercises the optional-field fallback branches: missing publisher.name,
  // missing publisher.namespace, missing tracking.version, and a CVE with
  // no notes/threats/flags so buildReason falls through to the template.
  const sparse = {
    document: {
      category: 'csaf_vex',
      csaf_version: '2.0',
      publisher: { category: 'vendor' },
      tracking: {
        id: 'SPARSE-1',
        status: 'final',
        version: '',
        current_release_date: '2026-01-01T00:00:00Z',
        initial_release_date: '2026-01-01T00:00:00Z',
      },
    },
    vulnerabilities: [
      {
        cve: 'CVE-2026-1',
        product_status: { known_not_affected: ['P1'] },
      },
    ],
  };

  it('uses system identity when publisher.name is missing', async () => {
    const result = await convertCsafVexToHdf(JSON.stringify(sparse), TEST_VERSION);
    expect(result.appliedBy?.type).toBe('system');
    expect(result.appliedBy?.identifier).toBe('csaf-vex-import');
  });

  it('falls back to tracking.id-only advisory URI when no publisher.namespace', async () => {
    const result = await convertCsafVexToHdf(JSON.stringify(sparse), TEST_VERSION);
    expect(result.overrides[0].evidence?.[0].data).toBe('SPARSE-1');
  });

  it('reason falls through to default template when no notes/threats/flags', async () => {
    const result = await convertCsafVexToHdf(JSON.stringify(sparse), TEST_VERSION);
    expect(result.overrides[0].reason).toMatch(/Imported from CSAF VEX/);
    expect(result.overrides[0].reason).not.toContain('Products:');
  });

  it('POAM milestone uses default action template when no remediation prose', async () => {
    const fixedOnly = {
      ...sparse,
      vulnerabilities: [{ cve: 'CVE-2026-2', product_status: { fixed: ['P1'] } }],
    };
    const result = await convertCsafVexToHdf(JSON.stringify(fixedOnly), TEST_VERSION);
    expect(result.overrides[0].milestones?.[0].description).toMatch(/vendor reports fix/);
  });

  it('vendor_fix remediation becomes the milestone description when present', async () => {
    const fixedWithRem = {
      ...sparse,
      vulnerabilities: [
        {
          cve: 'CVE-2026-3',
          product_status: { fixed: ['P1'] },
          remediations: [
            { category: 'vendor_fix', details: 'Apply patch 1.2.4', product_ids: ['P1'] },
            // also exercises the product-scope filter ignoring non-overlapping items
            { category: 'workaround', details: 'unrelated', product_ids: ['OTHER'] },
          ],
        },
      ],
    };
    const result = await convertCsafVexToHdf(JSON.stringify(fixedWithRem), TEST_VERSION);
    expect(result.overrides[0].milestones?.[0].description).toBe('Apply patch 1.2.4');
  });

  it('empty product_status bucket produces no override (errors)', async () => {
    const noProducts = {
      ...sparse,
      vulnerabilities: [{ cve: 'CVE-2026-4', product_status: { known_not_affected: [] } }],
    };
    await expect(convertCsafVexToHdf(JSON.stringify(noProducts), TEST_VERSION)).rejects.toThrow(
      /no actionable statements/,
    );
  });

  it('product_tree purl in product_identification_helper resolves to a purl-only AffectedPackage', async () => {
    const withHelperPurl = {
      ...sparse,
      product_tree: {
        full_product_names: [
          {
            name: 'OpenSSL 1.1.1k',
            product_id: 'P1',
            product_identification_helper: { purl: 'pkg:rpm/openssl@1.1.1k' },
          },
        ],
      },
    };
    const result = await convertCsafVexToHdf(JSON.stringify(withHelperPurl), TEST_VERSION);
    expect(result.overrides[0].affectedPackages).toBeDefined();
    expect(result.overrides[0].affectedPackages?.[0].purl).toBe('pkg:rpm/openssl@1.1.1k');
  });

  it('product_tree cpe in product_identification_helper resolves to a cpe-only AffectedPackage', async () => {
    const withHelperCpe = {
      ...sparse,
      product_tree: {
        full_product_names: [
          {
            name: 'OpenSSL 1.1.1k',
            product_id: 'P1',
            product_identification_helper: {
              cpe: 'cpe:2.3:a:openssl:openssl:1.1.1k:*:*:*:*:*:*:*',
            },
          },
        ],
      },
    };
    const result = await convertCsafVexToHdf(JSON.stringify(withHelperCpe), TEST_VERSION);
    expect(result.overrides[0].affectedPackages?.[0].cpe).toBe(
      'cpe:2.3:a:openssl:openssl:1.1.1k:*:*:*:*:*:*:*',
    );
  });

  it('product_tree leaf with no helper and no version-ancestor is dropped from affectedPackages', async () => {
    const noHelperNoAncestor = {
      ...sparse,
      product_tree: {
        full_product_names: [{ name: 'X', product_id: 'P1' }],
      },
    };
    const result = await convertCsafVexToHdf(JSON.stringify(noHelperNoAncestor), TEST_VERSION);
    expect(result.overrides[0].affectedPackages ?? []).toHaveLength(0);
  });

  it('product_tree resolves productIDs unknown to the tree as missing (no entry)', async () => {
    const referencedButMissing = {
      ...sparse,
      product_tree: {
        full_product_names: [
          {
            name: 'OpenSSL',
            product_id: 'OTHER',
            product_identification_helper: { purl: 'pkg:rpm/openssl@1.0' },
          },
        ],
      },
      vulnerabilities: [
        { cve: 'CVE-2026-1', product_status: { known_not_affected: ['P1'] } },
      ],
    };
    const result = await convertCsafVexToHdf(JSON.stringify(referencedButMissing), TEST_VERSION);
    expect(result.overrides[0].affectedPackages ?? []).toHaveLength(0);
  });

  it('flag with non-overlapping product_ids does not contribute a justification line', async () => {
    const flaggedOtherProduct = {
      ...sparse,
      vulnerabilities: [
        {
          cve: 'CVE-2026-6',
          product_status: { known_not_affected: ['P1'] },
          flags: [{ label: 'component_not_present', product_ids: ['OTHER'] }],
        },
      ],
    };
    const result = await convertCsafVexToHdf(JSON.stringify(flaggedOtherProduct), TEST_VERSION);
    expect(result.overrides[0].justification).toBeUndefined();
    expect(result.overrides[0].reason).not.toContain('VEX justification');
  });

  it('note with empty text and non-description category are ignored', async () => {
    const noisyNotes = {
      ...sparse,
      vulnerabilities: [
        {
          cve: 'CVE-2026-9',
          product_status: { known_not_affected: ['P1'] },
          notes: [
            { category: 'description', text: '' }, // empty text -> skipped
            { category: 'summary', text: 'TLDR' }, // wrong category -> skipped
            { category: 'description', text: 'kept' },
          ],
        },
      ],
    };
    const result = await convertCsafVexToHdf(JSON.stringify(noisyNotes), TEST_VERSION);
    expect(result.overrides[0].reason).toContain('kept');
    expect(result.overrides[0].reason).not.toContain('TLDR');
  });

  it('flag with unknown label leaves justification undefined', async () => {
    const flagUnknown = {
      ...sparse,
      vulnerabilities: [
        {
          cve: 'CVE-2026-11',
          product_status: { known_not_affected: ['P1'] },
          flags: [{ label: 'some_unknown_csaf_extension', product_ids: ['P1'] }],
        },
      ],
    };
    const result = await convertCsafVexToHdf(JSON.stringify(flagUnknown), TEST_VERSION);
    expect(result.overrides[0].justification).toBeUndefined();
  });

  it('remediation scoped to other product is skipped in firstActionRemediation', async () => {
    const remOther = {
      ...sparse,
      vulnerabilities: [
        {
          cve: 'CVE-2026-12',
          product_status: { fixed: ['P1'] },
          remediations: [
            { category: 'vendor_fix', details: 'Apply patch P2', product_ids: ['OTHER'] },
            { category: 'no_fix_planned' as const, details: 'wrong category', product_ids: ['P1'] },
          ],
        },
      ],
    };
    const result = await convertCsafVexToHdf(JSON.stringify(remOther), TEST_VERSION);
    expect(result.overrides[0].milestones?.[0].description).toMatch(/vendor reports fix/);
  });

  it('flag without label is ignored', async () => {
    const flagNoLabel = {
      ...sparse,
      vulnerabilities: [
        {
          cve: 'CVE-2026-10',
          product_status: { known_not_affected: ['P1'] },
          flags: [
            { product_ids: ['P1'] } as { label?: string; product_ids?: string[] },
            { label: 'component_not_present', product_ids: ['P1'] },
          ],
        },
      ],
    };
    const result = await convertCsafVexToHdf(JSON.stringify(flagNoLabel), TEST_VERSION);
    expect(result.overrides[0].justification).toBe(Justification.ComponentNotPresent);
  });

  it('threat without details and threat scoped to other product are both filtered out of reason', async () => {
    const noisyThreats = {
      ...sparse,
      vulnerabilities: [
        {
          cve: 'CVE-2026-8',
          product_status: { known_not_affected: ['P1'] },
          threats: [
            { category: 'impact' }, // no details -> dropped
            { category: 'impact', details: 'irrelevant', product_ids: ['OTHER'] }, // wrong product -> dropped
            { category: 'impact', details: 'really applies', product_ids: ['P1'] },
          ],
        },
      ],
    };
    const result = await convertCsafVexToHdf(JSON.stringify(noisyThreats), TEST_VERSION);
    expect(result.overrides[0].reason).toContain('really applies');
    expect(result.overrides[0].reason).not.toContain('irrelevant');
  });

  it('vulnerability reference with no URL is dropped from evidence; summary missing falls to category', async () => {
    const refsMixed = {
      ...sparse,
      vulnerabilities: [
        {
          cve: 'CVE-2026-13',
          product_status: { known_not_affected: ['P1'] },
          references: [
            { category: 'external', summary: '' }, // no URL - skipped
            { category: 'external', url: 'https://example.com/a' }, // no summary - falls to category
            { url: 'https://example.com/b' }, // no summary AND no category
          ],
        },
      ],
    };
    const result = await convertCsafVexToHdf(JSON.stringify(refsMixed), TEST_VERSION);
    // advisory evidence + the two URL-bearing refs = 3 entries; the URL-less one was dropped
    expect(result.overrides[0].evidence?.length).toBe(3);
  });

  it('flag without product_ids is not matched as a justification', async () => {
    const flagNoIds = {
      ...sparse,
      vulnerabilities: [
        {
          cve: 'CVE-2026-14',
          product_status: { known_not_affected: ['P1'] },
          flags: [{ label: 'component_not_present' }],
        },
      ],
    };
    const result = await convertCsafVexToHdf(JSON.stringify(flagNoIds), TEST_VERSION);
    expect(result.overrides[0].justification).toBeUndefined();
  });

  it('publisher with no category produces identity without description', async () => {
    const noCat = {
      document: {
        category: 'csaf_vex',
        csaf_version: '2.0',
        publisher: { name: 'NoCat Publisher' },
        tracking: {
          id: 'NC-1',
          status: 'final',
          version: '1',
          current_release_date: '2026-01-01T00:00:00Z',
          initial_release_date: '2026-01-01T00:00:00Z',
        },
      },
      vulnerabilities: [
        { cve: 'CVE-2026-7', product_status: { known_not_affected: ['P1'] } },
      ],
    };
    const result = await convertCsafVexToHdf(JSON.stringify(noCat), TEST_VERSION);
    expect(result.appliedBy?.identifier).toBe('NoCat Publisher');
    expect(result.appliedBy?.description).toBeUndefined();
  });
});

describe('convertCsafVexToHdf — edge cases', () => {
  it('rejects non-VEX CSAF profiles', async () => {
    const input = JSON.stringify({
      document: {
        category: 'csaf_security_advisory',
        csaf_version: '2.0',
        publisher: { category: 'vendor', name: 'Acme' },
        tracking: {
          id: 'X',
          status: 'final',
          version: '1',
          current_release_date: '2026-01-01T00:00:00Z',
          initial_release_date: '2026-01-01T00:00:00Z',
        },
      },
    });
    await expect(convertCsafVexToHdf(input, TEST_VERSION)).rejects.toThrow(/csaf_vex/);
  });

  it('rejects oversized input', async () => {
    const oversize = 'x'.repeat(51 * 1024 * 1024);
    await expect(convertCsafVexToHdf(oversize, TEST_VERSION)).rejects.toThrow();
  });

  it('rejects invalid JSON', async () => {
    await expect(convertCsafVexToHdf('not json', TEST_VERSION)).rejects.toThrow();
  });
});

// Ground-truth anchor (see shared/typescript/anchor.ts). csaf-vex emits one
// override per actionable status bucket (known_not_affected, fixed/first_fixed)
// on each CVE-bearing vulnerability — counted independently from the source.
describe('csaf-vex-to-hdf ground-truth anchor', () => {
  function countActionableBuckets(input: string): number {
    const doc = JSON.parse(input) as {
      vulnerabilities?: Array<{
        cve?: string;
        product_status?: { known_not_affected?: string[]; fixed?: string[]; first_fixed?: string[] };
      }>;
    };
    let n = 0;
    for (const v of doc.vulnerabilities ?? []) {
      if (!v.cve || !v.product_status) continue;
      if ((v.product_status.known_not_affected?.length ?? 0) > 0) n += 1;
      if ((v.product_status.fixed?.length ?? 0) > 0 || (v.product_status.first_fixed?.length ?? 0) > 0)
        n += 1;
    }
    return n;
  }

  it('emits one override per actionable status bucket (sec-vex)', async () => {
    const input = loadInput('sec-vex-2022-0001.json');
    assertOverrideCount(
      await convertCsafVexToHdf(input, TEST_VERSION),
      countActionableBuckets(input),
      'sec-vex-2022-0001.json: one override per actionable status bucket',
    );
  });
});
