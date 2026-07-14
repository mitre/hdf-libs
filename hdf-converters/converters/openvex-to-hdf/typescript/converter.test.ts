import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import {
  IdentityType,
  Justification,
  MilestoneStatus,
  OverrideType,
  ResultStatus,
} from '@mitre/hdf-schema';
import { expectValidAmendments } from '../../../test/helpers/expectValidHdf.js';
import { assertOverrideCount } from '../../../shared/typescript/anchor.js';
import { convertOpenVexToHdf } from './converter.js';

const TEST_VERSION = 'test';

function loadInput(name: string): string {
  return readFileSync(join(__dirname, '..', 'fixtures', 'input', name), 'utf-8');
}

describe('convertOpenVexToHdf — Spring Boot Log4j example', () => {
  it('produces a falsePositive override with justification + supplier evidence', async () => {
    const input = loadInput('spring-boot-log4j.openvex.json');
    const result = await convertOpenVexToHdf(input, TEST_VERSION);

    expectValidAmendments(result);

    expect(result.name).toContain('Spring Builds');
    expect(result.overrides).toHaveLength(1);

    const o = result.overrides[0];
    expect(o.requirementId).toBe('CVE-2021-44228');
    expect(o.type).toBe(OverrideType.FalsePositive);
    expect(o.status).toBe(ResultStatus.Passed);
    expect(o.justification).toBe(Justification.VulnerableCodeNotInExecutePath);
    expect(o.reason).toContain('Spring Boot users');
    expect(o.reason).not.toContain('Products:');
    expect(o.affectedPackages).toBeDefined();
    expect(o.affectedPackages?.map((p) => p.purl)).toContain(
      'pkg:maven/org.springframework.boot/spring-boot@2.6.0-M3',
    );
    expect(o.evidence).toHaveLength(1);
    expect(o.evidence?.[0].type).toBe('url');
  });

});

describe('convertOpenVexToHdf — multi-status fixture', () => {
  it('emits amendments only for not_affected and fixed; skips affected + under_investigation', async () => {
    const input = loadInput('multi-status.openvex.json');
    const result = await convertOpenVexToHdf(input, TEST_VERSION);

    expect(result.overrides).toHaveLength(2);

    const byCVE = new Map(result.overrides.map((o) => [o.requirementId, o]));

    const na = byCVE.get('CVE-2024-1000')!;
    expect(na.type).toBe(OverrideType.FalsePositive);
    expect(na.justification).toBe(Justification.ComponentNotPresent);

    const fixed = byCVE.get('CVE-2024-2000')!;
    expect(fixed.type).toBe(OverrideType.Poam);
    expect(fixed.status).toBe(ResultStatus.Failed);
    expect(fixed.milestones).toHaveLength(1);
    expect(fixed.milestones?.[0].status).toBe(MilestoneStatus.Pending);
    expect(fixed.reason).toContain('Upgrade to 1.2.4 or later');

    expect(byCVE.has('CVE-2024-3000')).toBe(false);
    expect(byCVE.has('CVE-2024-4000')).toBe(false);
  });
});

describe('convertOpenVexToHdf — empty actionable statements', () => {
  it('errors when only affected/under_investigation present (overrides.minItems=1)', async () => {
    const input = loadInput('empty.openvex.json');
    await expect(convertOpenVexToHdf(input, TEST_VERSION)).rejects.toThrow(
      /no actionable statements/,
    );
  });
});

describe('convertOpenVexToHdf — edge cases', () => {
  it('rejects oversized input', async () => {
    const oversize = 'x'.repeat(51 * 1024 * 1024);
    await expect(convertOpenVexToHdf(oversize, TEST_VERSION)).rejects.toThrow();
  });

  it('rejects invalid JSON', async () => {
    await expect(convertOpenVexToHdf('not json', TEST_VERSION)).rejects.toThrow();
  });

  it('skips statements without vulnerability identifier, keeps well-formed ones', async () => {
    const input = JSON.stringify({
      '@context': 'https://openvex.dev/ns/v0.2.0',
      '@id': 'https://example.com/empty-vuln',
      author: 'test',
      timestamp: '2026-01-01T00:00:00Z',
      statements: [
        { vulnerability: {}, status: 'not_affected' },
        {
          vulnerability: { name: 'CVE-2024-9999' },
          status: 'not_affected',
          justification: 'component_not_present',
        },
      ],
    });
    const result = await convertOpenVexToHdf(input, TEST_VERSION);
    expect(result.overrides).toHaveLength(1);
    expect(result.overrides[0].requirementId).toBe('CVE-2024-9999');
  });

  it('falls back to system identity when no author and emits status-derived reason for sparse statements', async () => {
    const input = JSON.stringify({
      '@context': 'https://openvex.dev/ns/v0.2.0',
      '@id': '',
      timestamp: '2026-01-01T00:00:00Z',
      // not_affected with no justification / impact / action / products —
      // buildReason has nothing to assemble and falls back.
      statements: [{ vulnerability: { name: 'CVE-2026-1234' }, status: 'not_affected' }],
    });
    const result = await convertOpenVexToHdf(input, TEST_VERSION);
    expect(result.appliedBy?.type).toBe(IdentityType.System);
    expect(result.appliedBy?.identifier).toBe('openvex-import');
    expect(result.overrides[0].reason).toMatch(/Imported from OpenVEX status/);
  });

  it('classifies email-bearing author as email identity', async () => {
    const input = loadInput('spring-boot-log4j.openvex.json');
    const result = await convertOpenVexToHdf(input, TEST_VERSION);
    expect(result.appliedBy?.type).toBe(IdentityType.Email);
  });
});

// Ground-truth anchor (see shared/typescript/anchor.ts). openvex emits one
// override per statement whose status is actionable — every status except
// 'affected' and 'under_investigation' — counted independently from the source.
describe('openvex-to-hdf ground-truth anchor', () => {
  function countActionableStatements(input: string): number {
    const doc = JSON.parse(input) as { statements?: Array<{ status?: string }> };
    return (doc.statements ?? []).filter(
      (s) => s.status !== 'affected' && s.status !== 'under_investigation',
    ).length;
  }

  it('emits one override per actionable statement (multi-status)', async () => {
    const input = loadInput('multi-status.openvex.json');
    assertOverrideCount(
      await convertOpenVexToHdf(input, TEST_VERSION),
      countActionableStatements(input),
      'multi-status.openvex.json: one override per actionable statement',
    );
  });
});
