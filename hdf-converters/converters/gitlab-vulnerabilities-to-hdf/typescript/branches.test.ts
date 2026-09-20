import { describe, expect, it } from 'vitest';
import { convertGitlabVulnerabilitiesToHdf, type Envelope, type Vulnerability } from './converter';
import { parseJSON } from '@mitre/hdf-utilities';
import { IdentityType, OverrideType, ResultStatus, type EvaluatedRequirement, type HDFResults } from '@mitre/hdf-schema';

// Twin of go/branches_test.go: the location variants, scan statuses and
// absent-field defaults the recorded corpus never exercises, driven through
// the public converter with minimal envelopes.

const FETCHED_AT = '2026-09-20T19:50:18Z';

function envelope(overrides: Partial<Envelope> = {}): Envelope {
  return {
    metadata: { enterprise: true, version: '18.9.1-ee' },
    project: { id: 'gid://gitlab/Project/9', fullPath: 'g/p', webUrl: 'https://gitlab.example.com/g/p', vulnerabilityStatistic: { total: 1 } },
    vulnerabilities: [],
    fetchedAt: FETCHED_AT,
    ...overrides,
  };
}

function vuln(fields: Partial<Vulnerability>): Vulnerability {
  return { id: 'gid://gitlab/Vulnerability/1', uuid: 'u-1', title: 'T', severity: 'HIGH', reportType: 'SAST', state: 'DETECTED', detectedAt: '2026-09-01T00:00:00Z', updatedAt: '2026-09-01T00:00:00Z', ...fields };
}

async function convert(env: Envelope): Promise<HDFResults> {
  return parseJSON<HDFResults>(await convertGitlabVulnerabilitiesToHdf(JSON.stringify(env)));
}

async function convertOne(fields: Partial<Vulnerability>, project?: Envelope['project']): Promise<EvaluatedRequirement> {
  const env = envelope({ vulnerabilities: [vuln(fields)] });
  if (project) env.project = project;
  const result = await convert(env);
  return result.baselines[0]!.requirements[0]!;
}

describe('gitlab-vulnerabilities-to-hdf location variants', () => {
  it.each([
    ['no location', {}, 'Report type: SAST'],
    ['sast line range, class and method', { location: { __typename: 'VulnerabilityLocationSast', file: 'a.go', startLine: '3', endLine: '9', vulnerableClass: 'Handler', vulnerableMethod: 'Serve' } }, 'File: a.go | Line: 3-9 | Class: Handler | Method: Serve'],
    ['sast same start and end', { location: { __typename: 'VulnerabilityLocationSast', file: 'a.go', startLine: '3', endLine: '3' } }, 'File: a.go | Line: 3'],
    ['secret detection', { location: { __typename: 'VulnerabilityLocationSecretDetection', file: '.env', startLine: '1' } }, 'File: .env | Line: 1'],
    ['dependency scanning', { location: { __typename: 'VulnerabilityLocationDependencyScanning', file: 'package-lock.json', dependency: { version: '4.17.20', package: { name: 'lodash' } } } }, 'File: package-lock.json | Package: lodash@4.17.20'],
    ['dependency without version', { location: { __typename: 'VulnerabilityLocationDependencyScanning', dependency: { package: { name: 'zlib' } } } }, 'Package: zlib'],
    ['container scanning', { location: { __typename: 'VulnerabilityLocationContainerScanning', image: 'registry/app:1.0', operatingSystem: 'debian:12', dependency: { package: { name: 'openssl' } } } }, 'Image: registry/app:1.0 | OS: debian:12 | Package: openssl'],
    ['dast', { location: { __typename: 'VulnerabilityLocationDast', hostname: 'https://app.example.com', path: '/login', requestMethod: 'POST', param: 'user' } }, 'URL: https://app.example.com/login | Method: POST | Param: user'],
    ['known variant with nothing to say', { location: { __typename: 'VulnerabilityLocationSast' } }, 'Report type: SAST'],
    ['unknown variant falls back to JSON', { location: { __typename: 'VulnerabilityLocationFuture', file: 'x' } }, 'Location: {"__typename":"VulnerabilityLocationFuture","file":"x"}'],
  ])('%s', async (_name, fields, want) => {
    const req = await convertOne(fields as Partial<Vulnerability>);
    expect(req.results[0]!.codeDesc).toBe(want);
  });

  it('promotes the file locus into sourceLocation with line fallbacks', async () => {
    let req = await convertOne({ location: { __typename: 'VulnerabilityLocationSast', file: 'f.go', endLine: '12' } });
    expect(req.sourceLocation).toEqual({ ref: 'f.go', line: 12 });
    req = await convertOne({ location: { __typename: 'VulnerabilityLocationSast', file: 'f.go', startLine: '12abc' } });
    expect(req.sourceLocation).toEqual({ ref: 'f.go' });
    req = await convertOne({ location: { __typename: 'VulnerabilityLocationDast', hostname: 'h' } });
    expect(req.sourceLocation).toBeUndefined();
  });
});

describe('gitlab-vulnerabilities-to-hdf absent fields', () => {
  it('fills every default when GitLab returns a bare node and project', async () => {
    const result = await convert(envelope({
      project: { fullPath: 'g/p', vulnerabilityStatistic: { total: 1 } },
      vulnerabilities: [{ state: 'DETECTED' }],
    }));
    expect(result.components).toEqual([{ name: 'g/p', type: 'repository', labels: { 'gitlab/project-id': '', 'gitlab/full-path': 'g/p' } }]);
    expect(result.tool).toEqual({ name: 'GitLab Vulnerability Report', version: '18.9.1-ee' });
    const b = result.baselines[0]!;
    expect(b.name).toBe('GitLab Vulnerability Report: Generic');
    expect(b.summary).toBe('Scanner: unknown');
    const req = b.requirements[0]!;
    expect(req.id).toBe('');
    expect(req.impact).toBe(0.5);
    expect(req.tags['severity_rating']).toBe('unrated');
    expect(req.descriptions).toEqual([{ label: 'default', data: '' }]);
    expect(req.results[0]!.codeDesc).toBe('Report type: ');
    expect(String(req.results[0]!.startTime)).toBe(FETCHED_AT);
    expect(req.refs).toBeUndefined();
    expect(req.tags['gitlab/scanner']).toBeNull();
    expect(req.tags['gitlab/initialDetectedPipeline']).toBeNull();
    expect(req.tags['gitlab/dismissalReason']).toBeNull();
    expect(req.tags['gitlab/falsePositive']).toBe(false);
    expect(req.tags['gitlab/stateTransitionCount']).toBe(0);
    expect(req.tags.nist).toEqual(['SA-11', 'RA-5']);
    expect(req.statusOverrides).toBeUndefined();
  });

  it('collects refs, identifier extras, CWE mappings and the fix description', async () => {
    const req = await convertOne({
      description: '',
      solution: 'Patch it',
      webUrl: 'https://gitlab.example.com/g/p/-/security/vulnerabilities/1',
      identifiers: [
        { externalType: 'cwe', externalId: 'CWE-79', url: 'https://cwe.mitre.org/data/definitions/79.html' },
        { externalType: 'cwe', externalId: 'abc' },
        { externalType: 'cve', externalId: 'CVE-2024-0001', url: 'https://nvd.nist.gov/vuln/detail/CVE-2024-0001' },
        { externalType: '', externalId: 'ignored' },
      ],
      links: [{ url: 'https://example.com/advisory' }, { url: 'https://cwe.mitre.org/data/definitions/79.html' }, {}],
      scanner: { name: 'Semgrep' },
      latestDetectedPipeline: { iid: '7', sha: 'abc', ref: 'main', createdAt: 'not-a-time' },
    });
    expect(req.descriptions).toEqual([{ label: 'default', data: 'T' }, { label: 'fix', data: 'Patch it' }]);
    expect(req.refs!.map((r) => r.url)).toEqual([
      'https://gitlab.example.com/g/p/-/security/vulnerabilities/1',
      'https://cwe.mitre.org/data/definitions/79.html',
      'https://nvd.nist.gov/vuln/detail/CVE-2024-0001',
      'https://example.com/advisory',
    ]);
    expect(req.tags.nist).toEqual(['SI-10']);
    expect(req.tags.cwe).toEqual(['CWE-79', 'abc']);
    expect(req.tags.cve).toEqual(['CVE-2024-0001']);
    expect(req.tags['gitlab/scanner']).toEqual({ name: 'Semgrep', vendor: '', externalId: '' });
    expect(String(req.results[0]!.startTime)).toBe('2026-09-01T00:00:00Z');
  });

  it('labels unknown report types verbatim and orders baselines by name', async () => {
    const result = await convert(envelope({ vulnerabilities: [vuln({ uuid: 'a', reportType: 'SOMETHING_NEW' }), vuln({ uuid: 'b', reportType: 'DAST' })] }));
    expect(result.baselines.map((b) => b.title)).toEqual(['DAST', 'SOMETHING_NEW']);
  });
});

describe('gitlab-vulnerabilities-to-hdf decision branches', () => {
  it('treats an unknown or missing dismissal reason as a waiver to notApplicable', async () => {
    let req = await convertOne({ state: 'DISMISSED', dismissalReason: 'FUTURE_REASON', dismissedAt: '2026-09-02T00:00:00Z', dismissedBy: { username: 'r' } });
    expect(req.statusOverrides![0]).toMatchObject({ type: OverrideType.Waiver, status: ResultStatus.NotApplicable, reason: 'Dismissed as FUTURE_REASON in GitLab' });
    req = await convertOne({ state: 'DISMISSED', dismissalReason: null, stateComment: '   ' });
    expect(req.statusOverrides![0]).toMatchObject({ type: OverrideType.Waiver, reason: 'Dismissed as NOT_APPLICABLE in GitLab' });
    expect(String(req.statusOverrides![0]!.appliedAt)).toBe('2026-09-01T00:00:00Z');
  });

  it('skips CONFIRMED and scanner-resolved RESOLVED transitions and a leading revert', async () => {
    const req = await convertOne({
      state: 'RESOLVED',
      resolvedOnDefaultBranch: true,
      stateTransitions: { nodes: [
        { fromState: 'DETECTED', toState: 'DETECTED', createdAt: '2026-09-01T01:00:00Z' },
        { fromState: 'DETECTED', toState: 'CONFIRMED', createdAt: '2026-09-01T02:00:00Z', comment: 'yes' },
        { fromState: 'CONFIRMED', toState: 'RESOLVED', createdAt: '2026-09-01T03:00:00Z', comment: 'gone' },
      ] },
    });
    expect(req.results[0]!.status).toBe(ResultStatus.Passed);
    expect(req.statusOverrides).toBeUndefined();
  });

  it('dates a transition without createdAt from the node and attributes a missing author to the system', async () => {
    const req = await convertOne({
      state: 'DISMISSED',
      dismissalReason: 'FALSE_POSITIVE',
      stateTransitions: { nodes: [{ toState: 'DISMISSED', dismissalReason: 'FALSE_POSITIVE', createdAt: '', comment: null, author: null }] },
    });
    const o = req.statusOverrides![0]!;
    expect(String(o.appliedAt)).toBe('2026-09-01T00:00:00Z');
    expect(o.reason).toBe('Dismissed as FALSE_POSITIVE in GitLab');
    expect(o.appliedBy).toEqual({ type: IdentityType.System, identifier: 'gitlab', description: 'GitLab automatic state change' });
    expect(o.externalReferences).toBeUndefined();
  });

  it('prefers a public email and drops an empty display name', async () => {
    const req = await convertOne({
      state: 'CONFIRMED', confirmedAt: '2026-09-02T00:00:00Z',
      severityOverrides: { nodes: [
        { originalSeverity: 'HIGH', newSeverity: 'LOW', createdAt: '2026-09-03T00:00:00Z', author: { username: 'u', name: '', publicEmail: 'u@example.com' } },
        { originalSeverity: 'LOW', newSeverity: '', author: { name: 'Nobody' } },
      ] },
    });
    expect(req.impact).toBe(0.7);
    // Newest first: the dated change (09-03) precedes the undated one, which
    // falls back to the node's updatedAt (09-01).
    const [dated, undated] = req.statusOverrides!;
    expect(dated!.appliedBy).toEqual({ type: IdentityType.Email, identifier: 'u@example.com' });
    expect(dated!.impact).toEqual({ value: 0.3 });
    expect(String(dated!.appliedAt)).toBe('2026-09-03T00:00:00Z');
    expect(undated!.appliedBy.type).toBe(IdentityType.System);
    expect(undated!.impact).toEqual({ value: 0.5 });
    expect(undated!.reason).toBe('Severity changed from LOW to  in GitLab');
    expect(String(undated!.appliedAt)).toBe('2026-09-01T00:00:00Z');
    expect(req.effectiveImpact).toBe(0.3);
    expect(req.disposition).toBe(OverrideType.RiskAdjustment);
  });

  it('synthesizes the current decision for each state when no history came back', async () => {
    const resolved = await convertOne({ state: 'RESOLVED', resolvedAt: '2026-09-04T00:00:00Z', resolvedBy: { username: 'r', name: 'R' } });
    expect(resolved.statusOverrides![0]).toMatchObject({ type: OverrideType.Attestation, appliedBy: { type: 'username', identifier: 'r', description: 'R' } });
    expect(String(resolved.statusOverrides![0]!.appliedAt)).toBe('2026-09-04T00:00:00Z');
    const confirmed = await convertOne({ state: 'CONFIRMED', confirmedAt: '2026-09-04T00:00:00Z', confirmedBy: { username: 'c' } });
    expect(confirmed.statusOverrides).toBeUndefined();
    expect(confirmed.tags['gitlab/confirmedBy']).toBe('c');
  });
});

describe('gitlab-vulnerabilities-to-hdf ingestion branches', () => {
  const project = (summary: Record<string, unknown> | null, statistic: { total: number } | null = null) => ({
    fullPath: 'g/p', vulnerabilityStatistic: statistic,
    latestDefaultBranchPipeline: { iid: '3', securityReportSummary: summary as never },
  });
  const scans = (...statuses: Array<{ status?: string; errors?: string[] }>) => ({ vulnerabilitiesCount: 0, scans: { nodes: statuses } });

  it.each([
    ['PREPARING counts as never ingested', { sast: scans({ status: 'PREPARING' }) }, /never ingested .*requires GitLab Ultimate/],
    ['a scan with no status is reported as unknown', { sast: scans({}) }, /sast: status unknown/],
    ['JOB_FAILED carries the errors', { sast: scans({ status: 'JOB_FAILED', errors: ['exit 1', 'oom'] }) }, /sast: JOB_FAILED \(exit 1; oom\)/],
    ['no sections at all', {}, /no security scanner has run on the default branch/],
    ['null summary', null, /no security scanner has run on the default branch/],
    ['sections without scans', { sast: { vulnerabilitiesCount: 0 }, dast: null }, /no security scanner has run/],
  ])('%s', async (_name, summary, want) => {
    await expect(convert(envelope({ project: project(summary) }))).rejects.toThrow(want);
  });

  it('accepts a succeeded scan even when the statistic row is missing', async () => {
    const result = await convert(envelope({ project: project({ dast: scans({ status: 'SUCCEEDED' }), sast: scans({ status: 'REPORT_ERROR' }) }) }));
    expect(result.baselines[0]!.summary).toBe('Ingested scanner types: dast');
    expect(result.baselines[0]!.requirements.map((r) => r.id)).toEqual(['gitlab-vulnerability-report-no-findings-dast']);
  });

  it('renders a populated report with no summary as one generic no-findings requirement', async () => {
    const result = await convert(envelope({ project: { fullPath: 'g/p', vulnerabilityStatistic: { total: 0 } } }));
    expect(result.baselines[0]!.requirements.map((r) => r.id)).toEqual(['gitlab-vulnerability-report-no-findings-generic']);
    expect(result.components[0]!.commit).toBeUndefined();
  });
});

describe('gitlab-vulnerabilities-to-hdf input guards', () => {
  it.each([
    ['whitespace', '   ', /empty input/],
    ['invalid JSON', '{not json', /invalid envelope JSON/],
    ['a bare string', '"x"', /project.fullPath missing/],
    ['missing metadata', JSON.stringify({ project: { fullPath: 'g/p' }, vulnerabilities: [] }), /Community Edition/],
    ['bad fetchedAt', JSON.stringify(envelope({ fetchedAt: 'yesterday' })), /fetchedAt "yesterday" is not a valid timestamp/],
  ])('rejects %s', async (_name, input, want) => {
    await expect(convertGitlabVulnerabilitiesToHdf(input)).rejects.toThrow(want);
  });
});
