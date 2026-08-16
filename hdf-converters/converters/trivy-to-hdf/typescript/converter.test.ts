import {readFileSync} from 'fs';
import {join} from 'path';
import {describe, expect, it} from 'vitest';
import {convertTrivyToHdf} from './converter.js';
import {expectValidResults} from '../../../test/helpers/expectValidHdf.js';
import type {EvaluatedRequirement, HDFResults} from '@mitre/hdf-schema';

const INPUT_DIR = join(__dirname, '..', 'fixtures', 'input');

function loadFixture(name: string): string {
  return readFileSync(join(INPUT_DIR, name), 'utf-8');
}
function delegateFixture(converter: string, name: string): string {
  return readFileSync(join(__dirname, '..', '..', converter, 'fixtures', 'input', name), 'utf-8');
}
async function convert(name: string): Promise<HDFResults> {
  return JSON.parse(await convertTrivyToHdf(loadFixture(name), '0.1.0')) as HDFResults;
}
function findReq(hdf: HDFResults, id: string): EvaluatedRequirement | undefined {
  return hdf.baselines[0].requirements.find((r) => r.id === id);
}

describe('trivy-to-hdf native conversion', () => {
  it('converts container-image vulnerabilities with rich fields', async () => {
    const hdf = await convert('image-webgoat.json');
    expectValidResults(hdf);

    expect(hdf.baselines[0].name).toBe('Trivy Scan');
    expect(hdf.baselines[0].title).toBe('webgoat/webgoat:latest');
    expect(hdf.tool?.name).toBe('Trivy');
    expect(hdf.tool?.version).toBe('0.74.0');
    expect(hdf.timestamp).toBeTruthy();

    expect(hdf.components).toHaveLength(1);
    expect(hdf.components?.[0].type).toBe('containerImage');
    expect(hdf.components?.[0].osName).toBe('ubuntu');
    expect(hdf.components?.[0].osVersion).toBe('24.04');

    const v = findReq(hdf, 'Trivy/CVE-2025-6965');
    expect(v).toBeDefined();
    expect(v?.impact).toBe(0.5);
    expect(v?.results[0].status).toBe('failed');
    expect(v?.cwe).toEqual(['CWE-197']);
    expect(v?.verificationMethod).toBe('automated');
    expect(v?.code).toBeTruthy();
    expect(v?.refs?.length).toBeGreaterThan(0);

    // Multi-source CVSS with provider sources.
    expect((v?.cvss?.length ?? 0)).toBeGreaterThanOrEqual(2);
    const sources = new Set((v?.cvss ?? []).map((c) => c.source));
    expect(sources.has('nvd')).toBe(true);

    expect(v?.affectedPackages?.[0].purl).toContain('pkg:deb/');
    expect(v?.affectedPackages?.[0].ecosystem).toBe('deb');
    expect(v?.tags).toHaveProperty('nist');
  });

  it('converts licenses (no affectedPackages; package in tags)', async () => {
    const hdf = await convert('image-webgoat.json');
    const lic = hdf.baselines[0].requirements.find((r) => r.id.startsWith('Trivy/license'));
    expect(lic).toBeDefined();
    expect(lic?.results[0].status).toBe('failed');
    expect(lic?.tags).toHaveProperty('package');
  });

  it('converts misconfigurations and secrets from a filesystem scan', async () => {
    const hdf = await convert('fs-misconfig-secret.json');
    expectValidResults(hdf);

    expect(hdf.components?.[0].type).toBe('artifact');
    expect(hdf.components?.[0].name).toBe('testdata');

    const mc = findReq(hdf, 'Trivy/DS-0001');
    expect(mc).toBeDefined();
    expect(mc?.results[0].status).toBe('failed');
    expect(mc?.sourceLocation?.ref).toBe('Dockerfile');
    expect(mc?.sourceLocation?.line).toBe(1);

    const sec = findReq(hdf, 'Trivy/secret/aws-access-key-id@app.env:2');
    expect(sec).toBeDefined();
    expect(sec?.results[0].status).toBe('failed');
    expect(sec?.impact).toBe(0.9);
    expect(sec?.results[0].codeDesc).toContain('****');
    expect(sec?.sourceLocation?.ref).toBe('app.env');
  });

  it('synthesizes a no-findings requirement for a clean scan', async () => {
    const hdf = await convert('empty.json');
    expectValidResults(hdf);
    expect(hdf.baselines[0].requirements).toHaveLength(1);
    const req = hdf.baselines[0].requirements[0];
    expect(req.id).toBe('trivy-no-findings');
    expect(req.results[0].status).toBe('passed');
    expect(req.results[0].codeDesc).toContain('Trivy');
  });

  it('handles edge cases: PASS/EXCEPTION misconfig status, unknown ecosystem, missing optional fields', async () => {
    const synthetic = JSON.stringify({
      SchemaVersion: 2,
      ArtifactName: 'synthetic',
      ArtifactType: 'container_image', // container image with NO Metadata
      CreatedAt: '2026-08-14T00:00:00Z',
      Trivy: {Version: '0.74.0'},
      Results: [
        {
          Target: 't',
          Class: 'os-pkgs',
          Type: 'alpine',
          Vulnerabilities: [
            {
              VulnerabilityID: 'CVE-X',
              PkgName: 'p',
              InstalledVersion: '1',
              Severity: 'UNKNOWN', // default impact 0.5
              PkgIdentifier: {PURL: 'pkg:weird/p@1'}, // unknown ecosystem
              CVSS: {nvd: {V40Vector: 'CVSS:4.0/AV:N', V40Score: 7.0, V2Vector: 'AV:N/AC:L', V2Score: 5.0}},
            },
            {}, // maximally sparse: no id/pkg/severity/purl — exercises the fallback arms
          ],
        },
        {
          Target: 'Dockerfile',
          Class: 'config',
          Type: 'dockerfile',
          // AVDID fallback, no CauseMetadata/Message/Resolution/References.
          Misconfigurations: [
            {ID: 'OK-1', Title: 'passed check', Severity: 'LOW', Status: 'PASS'},
            {AVDID: 'AVD-1', Title: 'exception', Severity: 'LOW', Status: 'EXCEPTION'},
            {ID: 'BARE-1', Severity: 'LOW', Status: 'FAIL'}, // no Title/Description/Message
          ],
        },
        // Sparse secret: no Title (RuleID fallback), no Category/Match.
        {Target: 'f', Class: 'secret', Secrets: [{RuleID: 'r', Severity: 'HIGH', StartLine: 5}]},
        // Sparse license: no Category/FilePath/Link/Confidence.
        {Target: 'L', Class: 'license', Licenses: [{PkgName: 'pk', Name: 'MIT', Severity: 'LOW'}]},
      ],
    });
    const hdf = JSON.parse(await convertTrivyToHdf(synthetic, '0.1.0')) as HDFResults;

    const v = findReq(hdf, 'Trivy/CVE-X');
    expect(v?.impact).toBe(0.5);
    expect(v?.affectedPackages?.[0].ecosystem).toBeUndefined(); // unknown PURL type
    expect(v?.cvss?.some((c) => c.version === '4.0')).toBe(true);
    expect(v?.cvss?.some((c) => c.version === '2.0')).toBe(true);
    expect(v?.sourceLocation).toBeUndefined(); // no PkgPath
    expect(v?.refs).toBeUndefined(); // no urls

    expect(findReq(hdf, 'Trivy/OK-1')?.results[0].status).toBe('passed');
    expect(findReq(hdf, 'Trivy/AVD-1')?.results[0].status).toBe('notApplicable');
    // container image without Metadata still yields a container component.
    expect(hdf.components?.[0].type).toBe('containerImage');
    // Sparse secret/license still produce requirements.
    expect(findReq(hdf, 'Trivy/secret/r@f:5')?.results[0].status).toBe('failed');
    expect(findReq(hdf, 'Trivy/license/pk/MIT')?.refs).toBeUndefined();
    // The package-less vuln emits no affectedPackages (would be schema-invalid).
    expect(findReq(hdf, 'Trivy/')?.affectedPackages).toBeUndefined();
  });

  it('omits misconfig_type when Type is absent or empty', async () => {
    // Tags are presence-based: an absent or empty Type must omit the key
    // entirely, never emit "misconfig_type": "". Pins the direction the Go
    // peer must match.
    const synthetic = JSON.stringify({
      SchemaVersion: 2,
      ArtifactName: 'x',
      ArtifactType: 'filesystem',
      Results: [
        {
          Target: 'Dockerfile',
          Class: 'config',
          Misconfigurations: [
            {ID: 'M-TYPE-ABSENT', Title: 't', Severity: 'LOW', Status: 'FAIL'},
            {ID: 'M-TYPE-EMPTY', Title: 't', Severity: 'LOW', Status: 'FAIL', Type: ''},
            {ID: 'M-TYPE-SET', Title: 't', Severity: 'LOW', Status: 'FAIL', Type: 'Dockerfile Security Check'},
          ],
        },
      ],
    });
    const hdf = JSON.parse(await convertTrivyToHdf(synthetic, '0.1.0')) as HDFResults;
    for (const id of ['Trivy/M-TYPE-ABSENT', 'Trivy/M-TYPE-EMPTY']) {
      const req = findReq(hdf, id);
      expect(req, id).toBeDefined();
      expect(req?.tags).not.toHaveProperty('misconfig_type');
    }
    expect(findReq(hdf, 'Trivy/M-TYPE-SET')?.tags).toMatchObject({misconfig_type: 'Dockerfile Security Check'});
  });

  it('renders Severity: UNKNOWN for absent, empty-string, and null Severity', async () => {
    // The Go peer uses firstNonEmpty(v.Severity, "UNKNOWN"), which catches
    // the explicit empty string; all three sparse shapes must agree.
    const synthetic = JSON.stringify({
      SchemaVersion: 2,
      ArtifactName: 'x',
      ArtifactType: 'filesystem',
      Results: [
        {
          Class: 'os-pkgs',
          Vulnerabilities: [
            {VulnerabilityID: 'CVE-SEV-ABSENT', PkgName: 'p', InstalledVersion: '1'},
            {VulnerabilityID: 'CVE-SEV-EMPTY', PkgName: 'p', InstalledVersion: '1', Severity: ''},
            {VulnerabilityID: 'CVE-SEV-NULL', PkgName: 'p', InstalledVersion: '1', Severity: null},
          ],
        },
      ],
    });
    const hdf = JSON.parse(await convertTrivyToHdf(synthetic, '0.1.0')) as HDFResults;
    for (const id of ['Trivy/CVE-SEV-ABSENT', 'Trivy/CVE-SEV-EMPTY', 'Trivy/CVE-SEV-NULL']) {
      expect(findReq(hdf, id)?.results[0].message, id).toBe('Severity: UNKNOWN');
    }
  });

  it('throws on invalid, empty, and unrecognized input', async () => {
    await expect(convertTrivyToHdf('not json')).rejects.toThrow();
    await expect(convertTrivyToHdf('')).rejects.toThrow();
    await expect(convertTrivyToHdf('{"foo":"bar"}')).rejects.toThrow();
    await expect(convertTrivyToHdf('[1,2]')).rejects.toThrow(); // JSON array, not an object
    await expect(convertTrivyToHdf('null')).rejects.toThrow();
  });
});

describe('trivy-to-hdf routing', () => {
  it('delegates SARIF input to the SARIF converter', async () => {
    const hdf = JSON.parse(await convertTrivyToHdf(delegateFixture('sarif-to-hdf', 'gosec.sarif'), '0.1.0')) as HDFResults;
    expect(hdf.baselines.length).toBeGreaterThan(0);
    expect(hdf.baselines[0].name).not.toBe('Trivy Scan');
  });

  it('delegates CycloneDX input to the CycloneDX converter', async () => {
    const hdf = JSON.parse(
      await convertTrivyToHdf(delegateFixture('cyclonedx-to-hdf', 'minimal-vulns.json'), '0.1.0'),
    ) as HDFResults;
    expect(hdf.baselines.length).toBeGreaterThan(0);
    expect(hdf.baselines[0].name).not.toBe('Trivy Scan');
  });

  it('delegates ASFF input to the ASFF converter', async () => {
    const hdf = JSON.parse(
      await convertTrivyToHdf(delegateFixture('asff-to-hdf', 'trivy_sample.json'), '0.1.0'),
    ) as HDFResults;
    expect(hdf.baselines.length).toBeGreaterThan(0);
    expect(hdf.baselines[0].name).not.toBe('Trivy Scan');
  });

  it('delegates GitLab input to the GitLab converter', async () => {
    const hdf = JSON.parse(
      await convertTrivyToHdf(delegateFixture('gitlab-to-hdf', 'minimal-sast.json'), '0.1.0'),
    ) as HDFResults;
    expect(hdf.baselines.length).toBeGreaterThan(0);
    expect(hdf.baselines[0].name).not.toBe('Trivy Scan');
  });
});
