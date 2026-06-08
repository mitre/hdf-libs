import { describe, expect, it } from 'vitest';
import {
  Justification,
  OverrideType,
  ResultStatus,
} from '@mitre/hdf-schema';
import {
  affectedPackageFromIdentifier,
  affectedPackageToIdentifier,
  affectedPackagesFromIdentifiers,
  exportStatusFor,
  importTargetFor,
  justificationForCycloneDX,
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
    // CycloneDX-specific reachability values now in the HDF enum.
    ['requires_configuration', Justification.RequiresConfiguration],
    ['requires_dependency', Justification.RequiresDependency],
    ['requires_environment', Justification.RequiresEnvironment],
    ['protected_by_compiler', Justification.ProtectedByCompiler],
    ['protected_at_runtime', Justification.ProtectedAtRuntime],
    ['protected_at_perimeter', Justification.ProtectedAtPerimeter],
  ])('maps %s', (raw, expected) => {
    expect(normalizeJustification(raw)).toBe(expected);
  });

  it.each(['', 'garbage', 'some_future_ecosystem_label'])(
    'returns undefined for %s (future ecosystems should extend the enum)',
    (raw) => {
      expect(normalizeJustification(raw)).toBeUndefined();
    },
  );
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

describe('justificationForCycloneDX', () => {
  it.each([
    [Justification.ComponentNotPresent, 'code_not_present'],
    [Justification.VulnerableCodeNotInExecutePath, 'code_not_reachable'],
    [Justification.InlineMitigationsAlreadyExist, 'protected_by_mitigating_control'],
  ])('translates long-form %s to CycloneDX short-form', (hdfValue, cdxValue) => {
    expect(justificationForCycloneDX(hdfValue)).toBe(cdxValue);
  });

  it.each([
    Justification.RequiresConfiguration,
    Justification.RequiresDependency,
    Justification.RequiresEnvironment,
    Justification.ProtectedByCompiler,
    Justification.ProtectedAtRuntime,
    Justification.ProtectedAtPerimeter,
  ])('passes CycloneDX-specific value %s through unchanged', (v) => {
    expect(justificationForCycloneDX(v)).toBe(String(v));
  });

  it.each([
    Justification.VulnerableCodeNotPresent,
    Justification.VulnerableCodeCannotBeControlledByAdversary,
  ])('returns undefined for %s (no CycloneDX equivalent)', (v) => {
    expect(justificationForCycloneDX(v)).toBeUndefined();
  });
});

describe('affectedPackageFromIdentifier', () => {
  it('parses a purl into name+version+ecosystem', () => {
    const pkg = affectedPackageFromIdentifier('pkg:npm/lodash@4.17.20');
    expect(pkg).toEqual({
      purl: 'pkg:npm/lodash@4.17.20',
      name: 'lodash',
      version: '4.17.20',
      ecosystem: 'npm',
    });
  });

  it('falls back to ecosystem=generic for unknown purl type segments', () => {
    const pkg = affectedPackageFromIdentifier('pkg:apk/wolfi/git@2.39.0-r1');
    expect(pkg?.purl).toBe('pkg:apk/wolfi/git@2.39.0-r1');
    expect(pkg?.ecosystem).toBe('generic');
  });

  it('preserves a malformed pkg: identifier as purl-only', () => {
    // parsePurl returns null when the type segment is missing — preserve
    // the raw string verbatim rather than dropping the entry.
    const pkg = affectedPackageFromIdentifier('pkg:');
    expect(pkg).toEqual({ purl: 'pkg:' });
  });

  it('recognizes a CPE 2.3 identifier and emits cpe-only', () => {
    const pkg = affectedPackageFromIdentifier(
      'cpe:2.3:a:openssl:openssl:1.1.1k:*:*:*:*:*:*:*',
    );
    expect(pkg).toEqual({
      cpe: 'cpe:2.3:a:openssl:openssl:1.1.1k:*:*:*:*:*:*:*',
    });
  });

  it('returns undefined for opaque identifiers (schema forbids fabricating identity)', () => {
    expect(affectedPackageFromIdentifier('acme-internal-lib')).toBeUndefined();
    expect(affectedPackageFromIdentifier('')).toBeUndefined();
  });
});

describe('affectedPackagesFromIdentifiers', () => {
  it('dedupes by purl/cpe key and drops unresolvable entries', () => {
    const out = affectedPackagesFromIdentifiers([
      'pkg:npm/lodash@4.17.20',
      'pkg:npm/lodash@4.17.20', // dedup
      'opaque-string', // dropped
      '', // dropped
      'cpe:2.3:a:openssl:openssl:1.1.1k:*:*:*:*:*:*:*',
    ]);
    expect(out).toHaveLength(2);
    expect(out[0].purl).toBe('pkg:npm/lodash@4.17.20');
    expect(out[1].cpe).toBe('cpe:2.3:a:openssl:openssl:1.1.1k:*:*:*:*:*:*:*');
  });
});

describe('affectedPackageToIdentifier', () => {
  it('prefers purl over cpe and name+version', () => {
    expect(
      affectedPackageToIdentifier({
        purl: 'pkg:npm/x@1.0',
        cpe: 'cpe:2.3:a:vendor:x:1.0:*:*:*:*:*:*:*',
        name: 'x',
        version: '1.0',
      }),
    ).toBe('pkg:npm/x@1.0');
  });

  it('uses cpe when purl is absent', () => {
    expect(
      affectedPackageToIdentifier({
        cpe: 'cpe:2.3:a:vendor:x:1.0:*:*:*:*:*:*:*',
      }),
    ).toBe('cpe:2.3:a:vendor:x:1.0:*:*:*:*:*:*:*');
  });

  it('falls back to name@version when neither purl nor cpe is set', () => {
    expect(affectedPackageToIdentifier({ name: 'x', version: '1.0' })).toBe('x@1.0');
  });

  it('returns name alone when version is missing', () => {
    expect(affectedPackageToIdentifier({ name: 'x' })).toBe('x');
  });

  it('returns undefined for an empty AffectedPackage', () => {
    expect(affectedPackageToIdentifier({})).toBeUndefined();
  });
});
