import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import {
  CVSSSeverity,
  Justification,
  MilestoneStatus,
  OverrideType,
  ResultStatus,
  Version,
} from '@mitre/hdf-schema';
import { expectValidAmendments } from '../../../test/helpers/expectValidHdf.js';
import {
  buildCvss,
  convertSpdxVexToHdf,
  cveIdentifier,
  cvssSeverity,
  cvssVersion,
  packageIdentifier,
} from './converter.js';

const TEST_VERSION = 'test';

function loadInput(name: string): string {
  return readFileSync(join(__dirname, '..', 'fixtures', 'input', name), 'utf-8');
}

describe('convertSpdxVexToHdf — sample shape', () => {
  it('emits exactly 2 overrides (not_affected + fixed); affected/under_investigation skipped', async () => {
    const result = await convertSpdxVexToHdf(loadInput('sample.spdx.json'), TEST_VERSION);
    expectValidAmendments(result);

    expect(result.name).toBe('SPDX VEX statements from sbom-cve-check');
    expect(result.generator?.name).toBe('spdx-vex-to-hdf');
    expect(result.generator?.version).toBe(TEST_VERSION);
    expect(result.appliedBy?.identifier).toBe('sbom-cve-check');
    expect(result.appliedBy?.type).toBe('system');

    expect(result.overrides).toHaveLength(2);
    const cves = result.overrides.map((o) => o.requirementId);
    expect(cves).toContain('CVE-2024-30002');
    expect(cves).toContain('CVE-2024-30003');
    expect(cves).not.toContain('CVE-2024-30001'); // affected -> skipped
    expect(cves).not.toContain('CVE-2024-30004'); // under_investigation -> skipped
  });
});

describe('convertSpdxVexToHdf — not_affected override', () => {
  it('produces a falsePositive/passed override with camelCase justification', async () => {
    const result = await convertSpdxVexToHdf(loadInput('sample.spdx.json'), TEST_VERSION);
    const o = result.overrides.find((x) => x.requirementId === 'CVE-2024-30002');
    expect(o).toBeDefined();
    expect(o?.type).toBe(OverrideType.FalsePositive);
    expect(o?.status).toBe(ResultStatus.Passed);
    expect(o?.justification).toBe(Justification.VulnerableCodeNotInExecutePath);

    expect(o?.reason).toContain('not_affected VEX assessment');
    expect(o?.reason).toContain('not reachable in the shipped configuration');
    expect(o?.reason).toContain('Reviewed by examplevendor security team');

    expect(o?.affectedPackages).toHaveLength(1);
    expect(o?.affectedPackages?.[0].cpe).toBe(
      'cpe:2.3:a:examplevendor:example-lib:1.0.0:*:*:*:*:*:*:*',
    );

    // AppliedAt from CreationInfo1; ExpiresAt = +365d.
    expect(new Date(o!.appliedAt).toISOString()).toBe('2026-08-10T16:39:41.000Z');
    expect(new Date(o!.expiresAt).toISOString()).toBe('2027-08-10T16:39:41.000Z');

    expect(o?.evidence?.length).toBeGreaterThan(0);
    // The committed fixture's only CVSS is on the affected (skipped) CVE.
    expect(o?.cvss).toBeUndefined();
  });
});

describe('convertSpdxVexToHdf — fixed override', () => {
  it('produces an open POA&M pinned to failed with a pending milestone', async () => {
    const result = await convertSpdxVexToHdf(loadInput('sample.spdx.json'), TEST_VERSION);
    const o = result.overrides.find((x) => x.requirementId === 'CVE-2024-30003');
    expect(o).toBeDefined();
    expect(o?.type).toBe(OverrideType.Poam);
    expect(o?.status).toBe(ResultStatus.Failed);
    expect(o?.justification).toBeUndefined();
    expect(o?.milestones?.[0].status).toBe(MilestoneStatus.Pending);
    expect(o?.reason).toContain('Patched in the 2.3.1 build');
    expect(o?.affectedPackages?.[0].cpe).toBe(
      'cpe:2.3:a:examplevendor:sample-utils:2.3.1:*:*:*:*:*:*:*',
    );
  });
});

// The committed fixture cannot exercise CVSS -> override.cvss because its only
// CVSS relationship is on the AFFECTED (skipped) CVE. This focused test uses a
// hand-built minimal SPDX-3 snippet where a not_affected CVE also carries a
// CvssV3 relationship.
describe('convertSpdxVexToHdf — CVSS mapping onto an actionable override', () => {
  it('maps CvssV3 onto override.cvss', async () => {
    const input = JSON.stringify({
      '@context': 'https://spdx.org/rdf/3.0.1/spdx-context.jsonld',
      '@graph': [
        { type: 'CreationInfo', '@id': '_:C1', created: '2026-01-01T00:00:00Z', createdBy: ['agent-1'] },
        { type: 'SoftwareAgent', spdxId: 'agent-1', name: 'scanner' },
        {
          type: 'software_Package',
          spdxId: 'pkg-1',
          name: 'libx',
          externalIdentifier: [{ externalIdentifierType: 'cpe23', identifier: 'cpe:2.3:a:v:libx:1.0:*:*:*:*:*:*:*' }],
        },
        {
          type: 'security_Vulnerability',
          spdxId: 'vuln-1',
          creationInfo: '_:C1',
          description: 'desc',
          externalIdentifier: [{ externalIdentifierType: 'cve', identifier: 'CVE-2026-9999' }],
        },
        {
          type: 'security_CvssV3VulnAssessmentRelationship',
          from: 'vuln-1',
          to: ['pkg-1'],
          security_score: '7.5',
          security_severity: 'high',
          security_vectorString: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H',
          creationInfo: '_:C1',
        },
        {
          type: 'security_VexNotAffectedVulnAssessmentRelationship',
          from: 'vuln-1',
          to: ['pkg-1'],
          security_justificationType: 'vulnerableCodeNotInExecutePath',
          security_statusNotes: 'not reachable',
          creationInfo: '_:C1',
        },
      ],
    });
    const result = await convertSpdxVexToHdf(input, TEST_VERSION);
    expectValidAmendments(result);
    expect(result.overrides).toHaveLength(1);
    const cvss = result.overrides[0].cvss;
    expect(cvss).toBeDefined();
    expect(cvss?.baseScore).toBeCloseTo(7.5, 3);
    expect(cvss?.baseVector).toBe('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H');
    expect(cvss?.baseSeverity).toBe(CVSSSeverity.High);
    expect(cvss?.version).toBe(Version.The31);
    expect(cvss?.source).toBe('CVE-2026-9999');
  });
});

describe('convertSpdxVexToHdf — edge cases', () => {
  it('errors when there are no actionable statements', async () => {
    await expect(
      convertSpdxVexToHdf(loadInput('no-actionable.spdx.json'), TEST_VERSION),
    ).rejects.toThrow(/no actionable VEX statements/);
  });

  it('rejects invalid JSON', async () => {
    await expect(convertSpdxVexToHdf('not json', TEST_VERSION)).rejects.toThrow();
  });

  it('rejects an empty @graph', async () => {
    await expect(
      convertSpdxVexToHdf(JSON.stringify({ '@context': 'x', '@graph': [] }), TEST_VERSION),
    ).rejects.toThrow(/@graph/);
  });

  it('rejects oversized input', async () => {
    await expect(convertSpdxVexToHdf('x'.repeat(51 * 1024 * 1024), TEST_VERSION)).rejects.toThrow();
  });
});

describe('helpers', () => {
  it('cvssVersion derives from vector prefix then relationship subtype', () => {
    expect(cvssVersion('security_CvssV3VulnAssessmentRelationship', 'CVSS:3.1/AV:N')).toBe(Version.The31);
    expect(cvssVersion('security_CvssV3VulnAssessmentRelationship', 'CVSS:3.0/AV:N')).toBe(Version.The30);
    expect(cvssVersion('security_CvssV4VulnAssessmentRelationship', 'CVSS:4.0/AV:N')).toBe(Version.The40);
    expect(cvssVersion('security_CvssV2VulnAssessmentRelationship', 'AV:N/AC:L')).toBe(Version.The20);
    expect(cvssVersion('security_CvssV3VulnAssessmentRelationship', '')).toBe(Version.The31);
  });

  it('cvssSeverity maps known labels and returns undefined otherwise', () => {
    expect(cvssSeverity('critical')).toBe(CVSSSeverity.Critical);
    expect(cvssSeverity(' HIGH ')).toBe(CVSSSeverity.High);
    expect(cvssSeverity('none')).toBe(CVSSSeverity.None);
    expect(cvssSeverity('bogus')).toBeUndefined();
    expect(cvssSeverity(undefined)).toBeUndefined();
  });

  it('cveIdentifier reads the cve externalIdentifier', () => {
    expect(
      cveIdentifier({ externalIdentifier: [{ externalIdentifierType: 'cve', identifier: 'CVE-1' }] }),
    ).toBe('CVE-1');
    expect(cveIdentifier(undefined)).toBe('');
    expect(cveIdentifier({})).toBe('');
  });

  it('packageIdentifier prefers purl over cpe23', () => {
    expect(
      packageIdentifier({
        externalIdentifier: [
          { externalIdentifierType: 'cpe23', identifier: 'cpe:2.3:a:v:x:1:*:*:*:*:*:*:*' },
          { externalIdentifierType: 'purl', identifier: 'pkg:generic/x@1.0' },
        ],
      }),
    ).toBe('pkg:generic/x@1.0');
    expect(
      packageIdentifier({
        externalIdentifier: [{ externalIdentifierType: 'cpe23', identifier: 'cpe:2.3:a:v:x:1:*:*:*:*:*:*:*' }],
      }),
    ).toBe('cpe:2.3:a:v:x:1:*:*:*:*:*:*:*');
    expect(packageIdentifier({})).toBe('');
  });

  it('buildCvss populates all present fields', () => {
    const cvss = buildCvss(
      {
        type: 'security_CvssV3VulnAssessmentRelationship',
        security_score: '9.8',
        security_severity: 'critical',
        security_vectorString: 'CVSS:3.1/AV:N',
      },
      'CVE-X',
    );
    expect(cvss.baseScore).toBeCloseTo(9.8, 3);
    expect(cvss.baseSeverity).toBe(CVSSSeverity.Critical);
    expect(cvss.version).toBe(Version.The31);
    expect(cvss.source).toBe('CVE-X');
  });
});
