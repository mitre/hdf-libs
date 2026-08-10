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
    expect(cvssVersion('security_CvssV2VulnAssessmentRelationship', 'CVSS:2.0/AV:N')).toBe(Version.The20);
    expect(cvssVersion('security_CvssV2VulnAssessmentRelationship', 'AV:N/AC:L')).toBe(Version.The20);
    expect(cvssVersion('security_CvssV3VulnAssessmentRelationship', '')).toBe(Version.The31);
    // Unknown vector version prefix falls through the switch to subtype/default.
    expect(cvssVersion('security_CvssV4VulnAssessmentRelationship', 'CVSS:9.9/AV:N')).toBe(Version.The40);
    // Undefined relType + vector -> exercises the `?? ''` legs and the default.
    expect(cvssVersion(undefined, undefined)).toBe(Version.The31);
  });

  it('cvssSeverity maps every known label and returns undefined otherwise', () => {
    expect(cvssSeverity('critical')).toBe(CVSSSeverity.Critical);
    expect(cvssSeverity(' HIGH ')).toBe(CVSSSeverity.High);
    expect(cvssSeverity('medium')).toBe(CVSSSeverity.Medium);
    expect(cvssSeverity('low')).toBe(CVSSSeverity.Low);
    expect(cvssSeverity('none')).toBe(CVSSSeverity.None);
    expect(cvssSeverity('bogus')).toBeUndefined();
    expect(cvssSeverity(undefined)).toBeUndefined();
  });

  it('cveIdentifier reads the cve externalIdentifier and skips non-matches', () => {
    expect(
      cveIdentifier({ externalIdentifier: [{ externalIdentifierType: 'cve', identifier: 'CVE-1' }] }),
    ).toBe('CVE-1');
    // A cve entry with no identifier is skipped; a later valid one wins. Also
    // exercises an entry with no externalIdentifierType (the `?? ''` leg).
    expect(
      cveIdentifier({
        externalIdentifier: [
          { identifier: 'ignored-no-type' },
          { externalIdentifierType: 'cve' },
          { externalIdentifierType: 'cve', identifier: 'CVE-2' },
        ],
      }),
    ).toBe('CVE-2');
    expect(cveIdentifier(undefined)).toBe('');
    expect(cveIdentifier({})).toBe('');
  });

  it('packageIdentifier prefers purl, accepts cpe22, keeps the first cpe, and handles typeless entries', () => {
    expect(
      packageIdentifier({
        externalIdentifier: [
          { externalIdentifierType: 'cpe23', identifier: 'cpe:2.3:a:v:x:1:*:*:*:*:*:*:*' },
          { externalIdentifierType: 'purl', identifier: 'pkg:generic/x@1.0' },
        ],
      }),
    ).toBe('pkg:generic/x@1.0');
    // First cpe wins (the `!cpe` false leg on the second); cpe22 is accepted.
    expect(
      packageIdentifier({
        externalIdentifier: [
          { identifier: 'no-type-ignored' },
          { externalIdentifierType: 'cpe22', identifier: 'cpe:/a:v:x:1' },
          { externalIdentifierType: 'cpe23', identifier: 'cpe:2.3:a:v:x:1:*:*:*:*:*:*:*' },
        ],
      }),
    ).toBe('cpe:/a:v:x:1');
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

  it('buildCvss omits absent/invalid sub-fields but still sets version', () => {
    // Empty score, empty vector, unknown severity, empty cve -> only version.
    const bare = buildCvss(
      {
        type: 'security_CvssV2VulnAssessmentRelationship',
        security_score: '',
        security_severity: 'bogus',
        security_vectorString: '',
      },
      '',
    );
    expect(bare.version).toBe(Version.The20);
    expect(bare.baseScore).toBeUndefined();
    expect(bare.baseVector).toBeUndefined();
    expect(bare.baseSeverity).toBeUndefined();
    expect(bare.source).toBeUndefined();

    // Non-numeric score -> baseScore omitted (NaN branch).
    const nan = buildCvss(
      { type: 'security_CvssV3VulnAssessmentRelationship', security_score: 'abc' },
      'CVE-Y',
    );
    expect(nan.baseScore).toBeUndefined();
    expect(nan.source).toBe('CVE-Y');
  });
});

/**
 * Fallback / defensive branch coverage. Each test feeds a hand-built minimal
 * SPDX-3 document through convertSpdxVexToHdf to reach the branches the
 * happy-path snapshot never hits.
 */
describe('convertSpdxVexToHdf — fallback branch coverage', () => {
  const CPE = 'cpe:2.3:a:v:libx:1.0:*:*:*:*:*:*:*';
  const YEAR_MS = 365 * 24 * 60 * 60 * 1000;

  function pkg(spdxId: string, extra: Record<string, unknown> = {}): Record<string, unknown> {
    return {
      type: 'software_Package',
      spdxId,
      externalIdentifier: [{ externalIdentifierType: 'cpe23', identifier: CPE }],
      ...extra,
    };
  }

  function notAffected(from: string, extra: Record<string, unknown> = {}): Record<string, unknown> {
    return {
      type: 'security_VexNotAffectedVulnAssessmentRelationship',
      relationshipType: 'doesNotAffect',
      from,
      to: ['pkg-1'],
      security_justificationType: 'vulnerableCodeNotInExecutePath',
      ...extra,
    };
  }

  it('falls back to now() and the default identity when creationInfo/agent do not resolve', async () => {
    const before = Date.now();
    const input = JSON.stringify({
      '@context': 'x',
      '@graph': [
        pkg('pkg-1'),
        {
          type: 'security_Vulnerability',
          spdxId: 'vuln-1',
          creationInfo: '_:alsoMissing',
          description: 'd',
          externalIdentifier: [{ externalIdentifierType: 'cve', identifier: 'CVE-1' }],
        },
        notAffected('vuln-1', { creationInfo: '_:missing', security_statusNotes: 'n' }),
      ],
    });
    const result = await convertSpdxVexToHdf(input, TEST_VERSION);
    // No resolvable SpdxDocument/agent -> document + override identity default.
    expect(result.appliedBy?.identifier).toBe('spdx-vex-import');
    expect(result.name).toBe('SPDX VEX statements');
    const o = result.overrides[0];
    expect(o.appliedBy.identifier).toBe('spdx-vex-import');
    const appliedAt = new Date(o.appliedAt).getTime();
    expect(appliedAt).toBeGreaterThanOrEqual(before - 1000);
    expect(appliedAt).toBeLessThanOrEqual(Date.now() + 1000);
    expect(new Date(o.expiresAt).getTime() - appliedAt).toBe(YEAR_MS);
  });

  it('falls back from a dangling relationship ref to the vulnerability creationInfo', async () => {
    const input = JSON.stringify({
      '@context': 'x',
      '@graph': [
        { type: 'CreationInfo', '@id': '_:V', created: '2025-05-05T00:00:00Z', createdBy: [] },
        pkg('pkg-1'),
        {
          type: 'security_Vulnerability',
          spdxId: 'vuln-1',
          creationInfo: '_:V',
          externalIdentifier: [{ externalIdentifierType: 'cve', identifier: 'CVE-1' }],
        },
        notAffected('vuln-1', { creationInfo: '_:missing' }),
      ],
    });
    const result = await convertSpdxVexToHdf(input, TEST_VERSION);
    const o = result.overrides[0];
    // appliedAt comes from the vuln's CreationInfo, not now().
    expect(new Date(o.appliedAt).toISOString()).toBe('2025-05-05T00:00:00.000Z');
    // createdBy [] -> no agent -> override appliedBy defaults.
    expect(o.appliedBy.identifier).toBe('spdx-vex-import');
  });

  it('treats a relationship with no creationInfo field and a created-less CreationInfo as now()', async () => {
    const before = Date.now();
    const input = JSON.stringify({
      '@context': 'x',
      '@graph': [
        { type: 'CreationInfo', '@id': '_:V' }, // no `created`
        pkg('pkg-1'),
        {
          type: 'security_Vulnerability',
          spdxId: 'vuln-1',
          creationInfo: '_:V',
          externalIdentifier: [{ externalIdentifierType: 'cve', identifier: 'CVE-1' }],
        },
        notAffected('vuln-1'), // no creationInfo field at all
      ],
    });
    const result = await convertSpdxVexToHdf(input, TEST_VERSION);
    expect(new Date(result.overrides[0].appliedAt).getTime()).toBeGreaterThanOrEqual(before - 1000);
  });

  it('treats an unparseable created timestamp as now()', async () => {
    const before = Date.now();
    const input = JSON.stringify({
      '@context': 'x',
      '@graph': [
        { type: 'CreationInfo', '@id': '_:V', created: 'not-a-date' },
        pkg('pkg-1'),
        {
          type: 'security_Vulnerability',
          spdxId: 'vuln-1',
          externalIdentifier: [{ externalIdentifierType: 'cve', identifier: 'CVE-1' }],
        },
        notAffected('vuln-1', { creationInfo: '_:V' }),
      ],
    });
    const result = await convertSpdxVexToHdf(input, TEST_VERSION);
    expect(new Date(result.overrides[0].appliedAt).getTime()).toBeGreaterThanOrEqual(before - 1000);
  });

  it('documentIdentity resolves the SpdxDocument creation agent', async () => {
    const input = JSON.stringify({
      '@context': 'x',
      '@graph': [
        { type: 'CreationInfo', '@id': '_:C1', created: '2026-01-01T00:00:00Z', createdBy: ['agent-1'] },
        { type: 'SoftwareAgent', spdxId: 'agent-1', name: 'docAgent' },
        { type: 'SpdxDocument', spdxId: 'doc-1', creationInfo: '_:C1' },
        pkg('pkg-1'),
        {
          type: 'security_Vulnerability',
          spdxId: 'vuln-1',
          creationInfo: '_:C1',
          externalIdentifier: [{ externalIdentifierType: 'cve', identifier: 'CVE-1' }],
        },
        notAffected('vuln-1'),
      ],
    });
    const result = await convertSpdxVexToHdf(input, TEST_VERSION);
    expect(result.appliedBy?.identifier).toBe('docAgent');
    expect(result.name).toBe('SPDX VEX statements from docAgent');
  });

  it('documentIdentity falls through an unresolvable SpdxDocument to a bare SoftwareAgent', async () => {
    const input = JSON.stringify({
      '@context': 'x',
      '@graph': [
        { type: 'CreationInfo', '@id': '_:C1', created: '2026-01-01T00:00:00Z', createdBy: ['ghost'] },
        { type: 'SpdxDocument', spdxId: 'doc-1', creationInfo: '_:C1' }, // agent 'ghost' not present
        { type: 'SoftwareAgent', spdxId: 'agent-2', name: 'strayAgent' },
        pkg('pkg-1'),
        {
          type: 'security_Vulnerability',
          spdxId: 'vuln-1',
          externalIdentifier: [{ externalIdentifierType: 'cve', identifier: 'CVE-1' }],
        },
        notAffected('vuln-1'),
      ],
    });
    const result = await convertSpdxVexToHdf(input, TEST_VERSION);
    // SpdxDocument identity is default (ghost unresolved) -> fall through to agent.
    expect(result.appliedBy?.identifier).toBe('strayAgent');
  });

  it('documentIdentity uses a bare SoftwareAgent when there is no SpdxDocument', async () => {
    const input = JSON.stringify({
      '@context': 'x',
      '@graph': [
        { type: 'SoftwareAgent', spdxId: 'agent-3', name: 'onlyAgent' },
        { type: 'SoftwareAgent', spdxId: 'agent-x' }, // no name -> not indexed
        pkg('pkg-1'),
        {
          type: 'security_Vulnerability',
          spdxId: 'vuln-1',
          externalIdentifier: [{ externalIdentifierType: 'cve', identifier: 'CVE-1' }],
        },
        notAffected('vuln-1'),
      ],
    });
    const result = await convertSpdxVexToHdf(input, TEST_VERSION);
    expect(result.appliedBy?.identifier).toBe('onlyAgent');
  });

  it('override appliedBy returns default when a resolvable CreationInfo has no matching agent', async () => {
    const input = JSON.stringify({
      '@context': 'x',
      '@graph': [
        { type: 'CreationInfo', '@id': '_:C1', created: '2026-01-01T00:00:00Z', createdBy: ['ghost'] },
        pkg('pkg-1'),
        {
          type: 'security_Vulnerability',
          spdxId: 'vuln-1',
          externalIdentifier: [{ externalIdentifierType: 'cve', identifier: 'CVE-1' }],
        },
        notAffected('vuln-1', { creationInfo: '_:C1' }),
      ],
    });
    const result = await convertSpdxVexToHdf(input, TEST_VERSION);
    expect(result.overrides[0].appliedBy.identifier).toBe('spdx-vex-import');
  });

  it('buildReason falls back to the POA&M template for a bare fixed statement', async () => {
    const input = JSON.stringify({
      '@context': 'x',
      '@graph': [
        pkg('pkg-1'),
        {
          type: 'security_Vulnerability',
          spdxId: 'vuln-1',
          externalIdentifier: [{ externalIdentifierType: 'cve', identifier: 'CVE-1' }],
        },
        { type: 'security_VexFixedVulnAssessmentRelationship', relationshipType: 'fixedIn', from: 'vuln-1', to: ['pkg-1'] },
      ],
    });
    const result = await convertSpdxVexToHdf(input, TEST_VERSION);
    expect(result.overrides[0].reason).toBe('vendor reports fix; apply and re-scan to verify');
  });

  it('buildReason falls back to a status stub for a bare not_affected statement', async () => {
    const input = JSON.stringify({
      '@context': 'x',
      '@graph': [
        pkg('pkg-1'),
        {
          type: 'security_Vulnerability',
          spdxId: 'vuln-1',
          externalIdentifier: [{ externalIdentifierType: 'cve', identifier: 'CVE-1' }],
        },
        notAffected('vuln-1'), // no description/impact/statusNotes
      ],
    });
    const result = await convertSpdxVexToHdf(input, TEST_VERSION);
    expect(result.overrides[0].reason).toBe('Imported from SPDX VEX relationship "doesNotAffect"');
  });

  it('buildReason uses only the vulnerability description when statusNotes/impact are absent', async () => {
    const input = JSON.stringify({
      '@context': 'x',
      '@graph': [
        pkg('pkg-1'),
        {
          type: 'security_Vulnerability',
          spdxId: 'vuln-1',
          description: 'only-description',
          externalIdentifier: [{ externalIdentifierType: 'cve', identifier: 'CVE-1' }],
        },
        notAffected('vuln-1'),
      ],
    });
    const result = await convertSpdxVexToHdf(input, TEST_VERSION);
    expect(result.overrides[0].reason).toBe('only-description');
  });

  it('resolveAffectedPackages skips dangling refs and identifier-less packages, keeps purls', async () => {
    const input = JSON.stringify({
      '@context': 'x',
      '@graph': [
        { type: 'software_Package', spdxId: 'pkg-purl', externalIdentifier: [{ externalIdentifierType: 'purl', identifier: 'pkg:generic/libx@1.0' }] },
        { type: 'software_Package', spdxId: 'pkg-bare' }, // no identifier -> skipped
        {
          type: 'security_Vulnerability',
          spdxId: 'vuln-1',
          externalIdentifier: [{ externalIdentifierType: 'cve', identifier: 'CVE-1' }],
        },
        {
          type: 'security_VexNotAffectedVulnAssessmentRelationship',
          relationshipType: 'doesNotAffect',
          from: 'vuln-1',
          to: ['missing-pkg', 'pkg-purl', 'pkg-bare'],
          security_justificationType: 'vulnerableCodeNotInExecutePath',
        },
      ],
    });
    const result = await convertSpdxVexToHdf(input, TEST_VERSION);
    const o = result.overrides[0];
    expect(o.affectedPackages).toHaveLength(1);
    expect(o.affectedPackages?.[0].purl).toBe('pkg:generic/libx@1.0');
  });

  it('supplierEvidenceFor merges externalRef + identifierLocator URLs and dedups', async () => {
    const input = JSON.stringify({
      '@context': 'x',
      '@graph': [
        pkg('pkg-1'),
        {
          type: 'security_Vulnerability',
          spdxId: 'vuln-1',
          externalRef: [{ locator: ['https://a', 'https://dup', ''] }],
          externalIdentifier: [
            { externalIdentifierType: 'cve', identifier: 'CVE-1', identifierLocator: ['https://dup', 'https://b'] },
          ],
        },
        notAffected('vuln-1'),
      ],
    });
    const result = await convertSpdxVexToHdf(input, TEST_VERSION);
    const evidence = result.overrides[0].evidence ?? [];
    const urls = evidence.map((e) => e.data);
    expect(urls).toEqual(['https://a', 'https://dup', 'https://b']);
    expect(urls.filter((u) => u === 'https://dup')).toHaveLength(1);
  });

  it('emits no evidence when the vulnerability carries no reference URLs', async () => {
    const input = JSON.stringify({
      '@context': 'x',
      '@graph': [
        pkg('pkg-1'),
        {
          type: 'security_Vulnerability',
          spdxId: 'vuln-1',
          externalIdentifier: [{ externalIdentifierType: 'cve', identifier: 'CVE-1' }],
        },
        notAffected('vuln-1'),
      ],
    });
    const result = await convertSpdxVexToHdf(input, TEST_VERSION);
    expect(result.overrides[0].evidence).toBeUndefined();
  });

  it('rejects a document with no @graph key at all', async () => {
    await expect(
      convertSpdxVexToHdf(JSON.stringify({ '@context': 'x' }), TEST_VERSION),
    ).rejects.toThrow(/@graph/);
  });

  it('skips a typeless element and a relationship with no `from`, keeping valid ones', async () => {
    const input = JSON.stringify({
      '@context': 'x',
      '@graph': [
        {}, // no type -> skipped by the loop guard
        pkg('pkg-1'),
        {
          type: 'security_Vulnerability',
          spdxId: 'vuln-1',
          externalIdentifier: [{ externalIdentifierType: 'cve', identifier: 'CVE-1' }],
        },
        // No `from` -> vuln undefined -> no CVE -> dropped (no override).
        { type: 'security_VexNotAffectedVulnAssessmentRelationship', to: ['pkg-1'] },
        notAffected('vuln-1'),
      ],
    });
    const result = await convertSpdxVexToHdf(input, TEST_VERSION);
    expect(result.overrides).toHaveLength(1);
    expect(result.overrides[0].requirementId).toBe('CVE-1');
  });

  it('buildReason stub tolerates a not_affected relationship with no relationshipType', async () => {
    const input = JSON.stringify({
      '@context': 'x',
      '@graph': [
        pkg('pkg-1'),
        {
          type: 'security_Vulnerability',
          spdxId: 'vuln-1',
          externalIdentifier: [{ externalIdentifierType: 'cve', identifier: 'CVE-1' }],
        },
        // No relationshipType, no description/impact/statusNotes.
        {
          type: 'security_VexNotAffectedVulnAssessmentRelationship',
          from: 'vuln-1',
          to: ['pkg-1'],
          security_justificationType: 'vulnerableCodeNotInExecutePath',
        },
      ],
    });
    const result = await convertSpdxVexToHdf(input, TEST_VERSION);
    expect(result.overrides[0].reason).toBe('Imported from SPDX VEX relationship ""');
  });

  it('handles a vulnerability whose externalRef entries carry no locator array', async () => {
    const input = JSON.stringify({
      '@context': 'x',
      '@graph': [
        pkg('pkg-1'),
        {
          type: 'security_Vulnerability',
          spdxId: 'vuln-1',
          externalRef: [{}], // externalRef present, but no locator
          externalIdentifier: [{ externalIdentifierType: 'cve', identifier: 'CVE-1' }],
        },
        notAffected('vuln-1'),
      ],
    });
    const result = await convertSpdxVexToHdf(input, TEST_VERSION);
    expect(result.overrides[0].evidence).toBeUndefined();
  });

  it('maps a CVSS relationship with partial fields onto an actionable override', async () => {
    const input = JSON.stringify({
      '@context': 'x',
      '@graph': [
        pkg('pkg-1'),
        {
          type: 'security_Vulnerability',
          spdxId: 'vuln-1',
          externalIdentifier: [{ externalIdentifierType: 'cve', identifier: 'CVE-1' }],
        },
        // Only a score; no vector, unknown severity -> version-only + baseScore.
        {
          type: 'security_CvssV2VulnAssessmentRelationship',
          from: 'vuln-1',
          to: ['pkg-1'],
          security_score: '5.0',
          security_severity: 'unknown-band',
        },
        notAffected('vuln-1'),
      ],
    });
    const result = await convertSpdxVexToHdf(input, TEST_VERSION);
    const cvss = result.overrides[0].cvss;
    expect(cvss).toBeDefined();
    expect(cvss?.version).toBe(Version.The20);
    expect(cvss?.baseScore).toBeCloseTo(5.0, 3);
    expect(cvss?.baseVector).toBeUndefined();
    expect(cvss?.baseSeverity).toBeUndefined();
  });
});
