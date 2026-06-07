import { describe, expect, it } from 'vitest';
import {
  Justification,
  OverrideType,
  ResultStatus,
} from '@mitre/hdf-schema';
import {
  exportStatusFor,
  importTargetFor,
  normalizeJustification,
  normalizeStatus,
  supplierEvidence,
  VexStatus,
} from './mapping.js';

describe('normalizeStatus', () => {
  it.each([
    ['not_affected', VexStatus.NotAffected],
    ['known_not_affected', VexStatus.NotAffected],
    ['false_positive', VexStatus.NotAffected],
    ['affected', VexStatus.Affected],
    ['known_affected', VexStatus.Affected],
    ['exploitable', VexStatus.Affected],
    ['fixed', VexStatus.Fixed],
    ['first_fixed', VexStatus.Fixed],
    ['resolved', VexStatus.Fixed],
    ['resolved_with_pedigree', VexStatus.Fixed],
    ['under_investigation', VexStatus.UnderInvestigation],
    ['in_triage', VexStatus.UnderInvestigation],
    ['  NOT_AFFECTED  ', VexStatus.NotAffected],
  ])('maps %s', (raw, expected) => {
    expect(normalizeStatus(raw)).toBe(expected);
  });

  it.each(['', 'garbage', 'recommended', 'last_affected'])(
    'returns undefined for %s',
    (raw) => {
      expect(normalizeStatus(raw)).toBeUndefined();
    },
  );
});

describe('normalizeJustification', () => {
  it.each([
    ['component_not_present', Justification.ComponentNotPresent],
    ['code_not_present', Justification.ComponentNotPresent],
    ['vulnerable_code_not_present', Justification.VulnerableCodeNotPresent],
    [
      'vulnerable_code_not_in_execute_path',
      Justification.VulnerableCodeNotInExecutePath,
    ],
    ['code_not_reachable', Justification.VulnerableCodeNotInExecutePath],
    [
      'vulnerable_code_cannot_be_controlled_by_adversary',
      Justification.VulnerableCodeCannotBeControlledByAdversary,
    ],
    [
      'inline_mitigations_already_exist',
      Justification.InlineMitigationsAlreadyExist,
    ],
    [
      'protected_by_mitigating_control',
      Justification.InlineMitigationsAlreadyExist,
    ],
  ])('maps %s', (raw, expected) => {
    expect(normalizeJustification(raw)).toBe(expected);
  });

  it.each([
    '',
    'requires_configuration',
    'protected_by_compiler',
    'garbage',
  ])('returns undefined for %s (importer must preserve raw)', (raw) => {
    expect(normalizeJustification(raw)).toBeUndefined();
  });
});

describe('importTargetFor', () => {
  it('not_affected → falsePositive + passed + justification', () => {
    const target = importTargetFor(VexStatus.NotAffected);
    expect(target).toBeDefined();
    expect(target!.overrideType).toBe(OverrideType.FalsePositive);
    expect(target!.status).toBe(ResultStatus.Passed);
    expect(target!.setJustification).toBe(true);
  });

  it('fixed → POAM pinned to failed pending re-scan (real system has not been verified)', () => {
    const target = importTargetFor(VexStatus.Fixed);
    expect(target).toBeDefined();
    expect(target!.overrideType).toBe(OverrideType.Poam);
    expect(target!.status).toBe(ResultStatus.Failed);
    expect(target!.poamActionTemplate).not.toBe('');
  });

  it('affected → no amendment (informational; consumer acts later)', () => {
    expect(importTargetFor(VexStatus.Affected)).toBeUndefined();
  });

  it('under_investigation → no amendment', () => {
    expect(importTargetFor(VexStatus.UnderInvestigation)).toBeUndefined();
  });
});

const baseOverride = (
  type: OverrideType,
  justification?: Justification,
) => ({
  appliedAt: new Date('2026-06-06'),
  appliedBy: { type: 'simple', identifier: 'test' },
  expiresAt: new Date('2027-06-06'),
  reason: 'test',
  requirementId: 'AC-1',
  type,
  justification,
});

describe('exportStatusFor', () => {
  it('returns undefined for no override (consumer has not acted)', () => {
    expect(exportStatusFor(undefined, false, false)).toBeUndefined();
  });

  it('justification set → not_affected (regardless of override type)', () => {
    const o = baseOverride(OverrideType.FalsePositive, Justification.ComponentNotPresent);
    expect(exportStatusFor(o as never, false, false)).toBe(VexStatus.NotAffected);
  });

  it('waiver → affected', () => {
    expect(
      exportStatusFor(baseOverride(OverrideType.Waiver) as never, false, false),
    ).toBe(VexStatus.Affected);
  });

  it('riskAdjustment → affected', () => {
    expect(
      exportStatusFor(
        baseOverride(OverrideType.RiskAdjustment) as never,
        false,
        false,
      ),
    ).toBe(VexStatus.Affected);
  });

  it('operationalRequirement → affected', () => {
    expect(
      exportStatusFor(
        baseOverride(OverrideType.OperationalRequirement) as never,
        false,
        false,
      ),
    ).toBe(VexStatus.Affected);
  });

  it('poam, milestones complete AND closure chained → fixed', () => {
    expect(
      exportStatusFor(baseOverride(OverrideType.Poam) as never, true, true),
    ).toBe(VexStatus.Fixed);
  });

  it('poam, milestones complete but NOT chained → affected', () => {
    expect(
      exportStatusFor(baseOverride(OverrideType.Poam) as never, true, false),
    ).toBe(VexStatus.Affected);
  });

  it('poam, milestones not complete → affected', () => {
    expect(
      exportStatusFor(baseOverride(OverrideType.Poam) as never, false, false),
    ).toBe(VexStatus.Affected);
  });

  it.each([OverrideType.FalsePositive, OverrideType.Attestation, OverrideType.Inherited])(
    '%s with no justification → not_affected',
    (type) => {
      expect(exportStatusFor(baseOverride(type) as never, false, false)).toBe(
        VexStatus.NotAffected,
      );
    },
  );
});

describe('supplierEvidence', () => {
  it('builds a URL evidence entry from a source URI', () => {
    const ev = supplierEvidence(
      'https://example.com/openvex.json',
      'OpenVEX from Vendor X',
    );
    expect(ev).toBeDefined();
    expect(ev!.type).toBe('url');
    expect(ev!.data).toBe('https://example.com/openvex.json');
    expect(ev!.description).toBe('OpenVEX from Vendor X');
  });

  it('falls back to default description when caller has none', () => {
    const ev = supplierEvidence('https://example.com/openvex.json');
    expect(ev!.description).toBe('Upstream VEX statement');
  });

  it('returns undefined for empty URI (no fabrication)', () => {
    expect(supplierEvidence('')).toBeUndefined();
    expect(supplierEvidence('   ')).toBeUndefined();
  });
});
