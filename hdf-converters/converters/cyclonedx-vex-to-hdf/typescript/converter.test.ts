import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import {
  Justification,
  MilestoneStatus,
  OverrideType,
  ResultStatus,
} from '@mitre/hdf-schema';
import {
  bestProductID,
  convertCyclonedxVexToHdf,
  firstActionFromResponse,
  productIDsForVuln,
} from './converter.js';

const TEST_VERSION = 'test';

function loadInput(name: string): string {
  return readFileSync(join(__dirname, '..', 'fixtures', 'input', name), 'utf-8');
}

describe('convertCyclonedxVexToHdf — not_affected', () => {
  it('produces a falsePositive override with justification + product@version', async () => {
    const result = await convertCyclonedxVexToHdf(
      loadInput('case1-vex-not_affected.json'),
      TEST_VERSION,
    );
    expect(result.overrides).toHaveLength(1);
    const o = result.overrides[0];
    expect(o.requirementId).toBe('CVE-2021-44228');
    expect(o.type).toBe(OverrideType.FalsePositive);
    expect(o.status).toBe(ResultStatus.Passed);
    expect(o.justification).toBe(Justification.ComponentNotPresent);
    expect(o.reason).toContain('Products: ABC@4.2');
    expect(o.reason).toContain('Class with vulnerable code was removed');
  });
});

describe('convertCyclonedxVexToHdf — resolved', () => {
  it('produces an open POA&M pinned to failed', async () => {
    const result = await convertCyclonedxVexToHdf(
      loadInput('case1-vex-fixed.json'),
      TEST_VERSION,
    );
    expect(result.overrides).toHaveLength(1);
    const o = result.overrides[0];
    expect(o.type).toBe(OverrideType.Poam);
    expect(o.status).toBe(ResultStatus.Failed);
    expect(o.milestones?.[0].status).toBe(MilestoneStatus.Pending);
  });
});

describe('convertCyclonedxVexToHdf — empty actionable', () => {
  it.each(['case1-vex-affected.json', 'case1-vex-under_investigation.json'])(
    'errors on %s',
    async (file) => {
      await expect(convertCyclonedxVexToHdf(loadInput(file), TEST_VERSION)).rejects.toThrow(
        /no actionable VEX statements/,
      );
    },
  );
});

describe('convertCyclonedxVexToHdf — CycloneDX-specific justification', () => {
  it('lands in the structured justification field (HDF enum extended in v3.2.x)', async () => {
    const input = JSON.stringify({
      bomFormat: 'CycloneDX',
      specVersion: '1.4',
      metadata: { timestamp: '2026-01-01T00:00:00Z', component: { name: 'X', version: '1', 'bom-ref': 'px' } },
      vulnerabilities: [
        {
          id: 'CVE-2026-1234',
          analysis: {
            state: 'not_affected',
            justification: 'requires_configuration',
            detail: 'Needs explicit opt-in',
          },
          affects: [{ ref: 'px' }],
        },
      ],
    });
    const result = await convertCyclonedxVexToHdf(input, TEST_VERSION);
    expect(result.overrides[0].justification).toBe(Justification.RequiresConfiguration);
    expect(result.overrides[0].reason).not.toContain('VEX justification:');
  });
});

describe('convertCyclonedxVexToHdf — edge cases', () => {
  it('rejects non-CycloneDX', async () => {
    await expect(
      convertCyclonedxVexToHdf(JSON.stringify({ bomFormat: 'SPDX' }), TEST_VERSION),
    ).rejects.toThrow(/CycloneDX/);
  });
  it('rejects invalid JSON', async () => {
    await expect(convertCyclonedxVexToHdf('not json', TEST_VERSION)).rejects.toThrow();
  });
  it('rejects oversized input', async () => {
    await expect(
      convertCyclonedxVexToHdf('x'.repeat(51 * 1024 * 1024), TEST_VERSION),
    ).rejects.toThrow();
  });
});

describe('convertCyclonedxVexToHdf — vulnerability description + affects edge cases', () => {
  it('promotes top-level description, dedups duplicate refs, and uses ref-as-id when no lookup match', async () => {
    const input = JSON.stringify({
      bomFormat: 'CycloneDX',
      specVersion: '1.4',
      metadata: { timestamp: '2026-01-01T00:00:00Z' },
      vulnerabilities: [
        {
          id: 'CVE-2026-1',
          description: 'top-level description text',
          analysis: { state: 'not_affected', justification: 'code_not_present' },
          affects: [
            { ref: 'product-A' }, // no component in lookup -> ref is the id
            { ref: 'product-A' }, // dedup
            { ref: '' }, // skipped
          ],
        },
      ],
    });
    const result = await convertCyclonedxVexToHdf(input, TEST_VERSION);
    const reason = result.overrides[0].reason;
    expect(reason).toContain('top-level description text');
    expect(reason).toContain('Products: product-A');
    expect(reason).not.toContain('product-A, product-A');
  });
});

describe('convertCyclonedxVexToHdf — additional references and components', () => {
  it('preserves vulnerability.references URLs in evidence and resolves top-level components', async () => {
    const input = JSON.stringify({
      bomFormat: 'CycloneDX',
      specVersion: '1.4',
      metadata: { timestamp: '2026-01-01T00:00:00Z' },
      components: [
        { name: 'libfoo', version: '1.0.0', 'bom-ref': 'pkg-foo', purl: 'pkg:npm/libfoo@1.0.0' },
      ],
      vulnerabilities: [
        {
          id: 'CVE-2026-1',
          analysis: { state: 'not_affected', justification: 'code_not_present' },
          affects: [{ ref: 'pkg-foo' }],
          references: [
            { id: 'GHSA-xxx', source: { name: 'GitHub', url: 'https://github.com/advisories/GHSA-xxx' } },
            { id: 'no-url', source: { name: 'X' } }, // skipped (no URL)
          ],
        },
      ],
    });
    const result = await convertCyclonedxVexToHdf(input, TEST_VERSION);
    const evidence = result.overrides[0].evidence ?? [];
    expect(evidence.some((e) => e.data === 'https://github.com/advisories/GHSA-xxx')).toBe(true);
    expect(result.overrides[0].reason).toContain('Products: pkg:npm/libfoo@1.0.0');
  });
});

describe('convertCyclonedxVexToHdf — publisher identity', () => {
  it('uses metadata.authors.email when present', async () => {
    const input = JSON.stringify({
      bomFormat: 'CycloneDX',
      specVersion: '1.4',
      metadata: {
        timestamp: '2026-01-01T00:00:00Z',
        component: { name: 'X', version: '1', 'bom-ref': 'px' },
        authors: [{ name: 'Alice', email: 'alice@example.com' }],
      },
      vulnerabilities: [
        {
          id: 'CVE-2026-1',
          analysis: { state: 'not_affected', justification: 'code_not_present' },
          affects: [{ ref: 'px' }],
        },
      ],
    });
    const result = await convertCyclonedxVexToHdf(input, TEST_VERSION);
    expect(result.appliedBy?.identifier).toBe('alice@example.com');
    expect(result.appliedBy?.type).toBe('email');
  });

  it('uses metadata.authors.name when no email present', async () => {
    const input = JSON.stringify({
      bomFormat: 'CycloneDX',
      specVersion: '1.4',
      metadata: {
        timestamp: '2026-01-01T00:00:00Z',
        component: { name: 'X', version: '1', 'bom-ref': 'px' },
        authors: [{ name: 'Bob' }],
      },
      vulnerabilities: [
        {
          id: 'CVE-2026-1',
          analysis: { state: 'not_affected', justification: 'code_not_present' },
          affects: [{ ref: 'px' }],
        },
      ],
    });
    const result = await convertCyclonedxVexToHdf(input, TEST_VERSION);
    expect(result.appliedBy?.identifier).toBe('Bob');
    expect(result.appliedBy?.type).toBe('simple');
  });

  it('falls back to metadata.tools when no authors', async () => {
    const input = JSON.stringify({
      bomFormat: 'CycloneDX',
      specVersion: '1.4',
      metadata: {
        timestamp: '2026-01-01T00:00:00Z',
        component: { name: 'X', version: '1', 'bom-ref': 'px' },
        tools: [{ vendor: 'Acme', name: 'VEX Maker' }],
      },
      vulnerabilities: [
        {
          id: 'CVE-2026-1',
          analysis: { state: 'not_affected', justification: 'code_not_present' },
          affects: [{ ref: 'px' }],
        },
      ],
    });
    const result = await convertCyclonedxVexToHdf(input, TEST_VERSION);
    expect(result.appliedBy?.identifier).toBe('Acme VEX Maker');
    expect(result.appliedBy?.type).toBe('system');
  });

  it('skips authors and tools with no usable identifier and falls back', async () => {
    const input = JSON.stringify({
      bomFormat: 'CycloneDX',
      specVersion: '1.4',
      metadata: {
        timestamp: '2026-01-01T00:00:00Z',
        component: { name: 'X', version: '1', 'bom-ref': 'px' },
        authors: [{}], // no email, no name
        tools: [{}], // no vendor, no name
      },
      components: [{ name: 'NoBomRef' }], // component without bom-ref is skipped
      vulnerabilities: [
        {
          id: 'CVE-2026-1',
          analysis: { state: 'not_affected', justification: 'code_not_present' },
          affects: [{ ref: 'px' }],
        },
      ],
    });
    const result = await convertCyclonedxVexToHdf(input, TEST_VERSION);
    expect(result.appliedBy?.identifier).toBe('cyclonedx-vex-import');
  });

  it('falls back to system import default when no authors and no tools', async () => {
    const input = JSON.stringify({
      bomFormat: 'CycloneDX',
      specVersion: '1.4',
      metadata: { timestamp: '2026-01-01T00:00:00Z', component: { name: 'X', version: '1', 'bom-ref': 'px' } },
      vulnerabilities: [
        {
          id: 'CVE-2026-1',
          analysis: { state: 'not_affected', justification: 'code_not_present' },
          affects: [{ ref: 'px' }],
        },
      ],
    });
    const result = await convertCyclonedxVexToHdf(input, TEST_VERSION);
    expect(result.appliedBy?.identifier).toBe('cyclonedx-vex-import');
  });
});

describe('helpers', () => {
  it('firstActionFromResponse maps known values', () => {
    expect(firstActionFromResponse(['update'])).toMatch(/Apply vendor update/);
    expect(firstActionFromResponse(['rollback'])).toMatch(/Roll back/);
    expect(firstActionFromResponse(['workaround_available'])).toMatch(/workaround/);
    expect(firstActionFromResponse(['will_not_fix'])).toBe('');
    expect(firstActionFromResponse([])).toBe('');
  });

  it('bestProductID prefers purl, then name@version, then name, then bom-ref, then fallback', () => {
    expect(bestProductID({ purl: 'pkg:npm/x@1.0', name: 'x', version: '1.0' }, 'f')).toBe('pkg:npm/x@1.0');
    expect(bestProductID({ name: 'x', version: '1.0' }, 'f')).toBe('x@1.0');
    expect(bestProductID({ name: 'x' }, 'f')).toBe('x');
    expect(bestProductID({ 'bom-ref': 'B' }, 'f')).toBe('B');
    expect(bestProductID({}, 'f')).toBe('f');
  });

  it('productIDsForVuln falls back to unknown-product when no affects', () => {
    expect(productIDsForVuln({ id: 'CVE-X' }, new Map())).toEqual(['unknown-product']);
  });
});
