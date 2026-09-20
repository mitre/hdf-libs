import { readFileSync } from 'fs';
import { dirname, join } from 'path';
import { fileURLToPath } from 'url';
import { describe, expect, it } from 'vitest';
import { convertGitlabVulnerabilitiesToHdf } from './converter';
import { runConverterContractTests } from '../../../shared/typescript/converter-contract.js';
import { expectValidResults } from '../../../test/helpers/expectValidHdf.js';
import { assertRequirementCount, countJsonItemsUnderKey } from '../../../shared/typescript/anchor.js';
import { parseJSON } from '@mitre/hdf-utilities';
import { OverrideType, ResultStatus, type EvaluatedRequirement, type HDFResults } from '@mitre/hdf-schema';

const __dirname = dirname(fileURLToPath(import.meta.url));
const FIXTURES_DIR = join(__dirname, '..', 'fixtures');

function loadFixture(name: string): string {
  return readFileSync(join(FIXTURES_DIR, 'input', name), 'utf-8');
}

async function convert(name: string): Promise<HDFResults> {
  return parseJSON<HDFResults>(await convertGitlabVulnerabilitiesToHdf(loadFixture(name)));
}

function requirementByGID(result: HDFResults, id: string): EvaluatedRequirement {
  const want = `gid://gitlab/Vulnerability/${id}`;
  for (const b of result.baselines) {
    const hit = b.requirements.find((r) => r.tags['gitlab/id'] === want);
    if (hit) return hit;
  }
  throw new Error(`no requirement carries gitlab/id ${want}`);
}

runConverterContractTests({
  converterName: 'gitlab-vulnerabilities-to-hdf',
  convertFn: convertGitlabVulnerabilitiesToHdf,
  minimalFixture: 'clean.json',
});

describe('gitlab-vulnerabilities-to-hdf ground-truth anchor', () => {
  it('emits one requirement per vulnerabilities[] node', async () => {
    const input = loadFixture('triaged.json');
    assertRequirementCount(
      await convertGitlabVulnerabilitiesToHdf(input),
      countJsonItemsUnderKey(input, 'vulnerabilities'),
      'triaged.json: one requirement per vulnerabilities[]',
    );
  });
});

describe('gitlab-vulnerabilities-to-hdf output validity', () => {
  it.each(['triaged.json', 'clean.json'])('%s validates against hdf-results', async (name) => {
    expectValidResults(await convert(name));
  });
});

describe('gitlab-vulnerabilities-to-hdf triage mapping', () => {
  it('keeps raw failed and emits a falsePositive override for a FALSE_POSITIVE dismissal', async () => {
    const req = requirementByGID(await convert('triaged.json'), '50');
    expect(req.results[0]!.status).toBe(ResultStatus.Failed);
    expect(req.statusOverrides).toHaveLength(1);
    const o = req.statusOverrides![0]!;
    expect(o.type).toBe(OverrideType.FalsePositive);
    expect(o.status).toBe(ResultStatus.NotApplicable);
    expect(o.reason).toBe('The flagged value is a documented demo credential, not a real secret.');
    expect(o.appliedBy).toEqual({ type: 'username', identifier: 'sec-reviewer', description: 'Security Reviewer' });
    expect(String(o.appliedAt)).toBe('2026-09-20T19:27:19Z');
    expect(String(o.expiresAt)).toBe('2027-09-20T19:27:19Z');
    expect(o.externalReferences).toEqual([{ sourceName: 'GitLab Vulnerability Report', href: 'https://gitlab.example.com/security-demo/juice-shop/-/security/vulnerabilities/50' }]);
    expect(req.disposition).toBe(OverrideType.FalsePositive);
    expect(req.effectiveStatus).toBe(ResultStatus.NotApplicable);
    expect(req.effectiveImpact).toBeUndefined();
  });

  it.each([
    ['1', 'ACCEPTABLE_RISK', OverrideType.Waiver, ResultStatus.Passed, undefined],
    ['94', 'MITIGATING_CONTROL', OverrideType.Waiver, ResultStatus.Passed, 'inline_mitigations_already_exist'],
    ['88', 'USED_IN_TESTS', OverrideType.Waiver, ResultStatus.NotApplicable, 'vulnerable_code_not_in_execute_path'],
    ['85', 'NOT_APPLICABLE', OverrideType.Waiver, ResultStatus.NotApplicable, undefined],
  ])('finding %s dismissed as %s → %s/%s', async (id, reason, type, status, justification) => {
    const req = requirementByGID(await convert('triaged.json'), id);
    expect(req.tags['gitlab/dismissalReason']).toBe(reason);
    expect(req.results[0]!.status).toBe(ResultStatus.Failed);
    const o = req.statusOverrides![0]!;
    expect(o.type).toBe(type);
    expect(o.status).toBe(status);
    expect(o.justification).toBe(justification);
    expect(req.effectiveStatus).toBe(status);
    expect(req.disposition).toBe(type);
  });

  it('attests a human resolution the scanner has not yet confirmed', async () => {
    const req = requirementByGID(await convert('triaged.json'), '72');
    expect(req.results[0]!.status).toBe(ResultStatus.Failed);
    expect(req.statusOverrides![0]!.type).toBe(OverrideType.Attestation);
    expect(req.effectiveStatus).toBe(ResultStatus.Passed);
    expect(req.tags['gitlab/resolvedOnDefaultBranch']).toBe(false);
  });

  it('treats a resolution the scanner has confirmed as a raw pass with no override', async () => {
    const env = JSON.parse(loadFixture('triaged.json'));
    const node = env.vulnerabilities.find((v: { id: string }) => v.id === 'gid://gitlab/Vulnerability/72');
    node.resolvedOnDefaultBranch = true;
    node.presentOnDefaultBranch = false;
    env.vulnerabilities = [node];
    const result = parseJSON<HDFResults>(await convertGitlabVulnerabilitiesToHdf(JSON.stringify(env)));
    const req = requirementByGID(result, '72');
    expect(req.results[0]!.status).toBe(ResultStatus.Passed);
    expect(req.statusOverrides).toBeUndefined();
    expect(req.disposition).toBeUndefined();
    expect(req.tags['gitlab/resolvedOnDefaultBranch']).toBe(true);
    expect(req.tags['gitlab/resolvedBy']).toBe('sec-reviewer');
  });

  it('falls back to the fetch time when a decision carries no usable timestamp', async () => {
    const env = JSON.parse(loadFixture('triaged.json'));
    const node = env.vulnerabilities.find((v: { id: string }) => v.id === 'gid://gitlab/Vulnerability/1');
    node.stateTransitions = { nodes: [] };
    node.dismissedAt = null;
    node.updatedAt = 'not-a-time';
    node.detectedAt = '';
    env.vulnerabilities = [node];
    const result = parseJSON<HDFResults>(await convertGitlabVulnerabilitiesToHdf(JSON.stringify(env)));
    const o = requirementByGID(result, '1').statusOverrides![0]!;
    expect(String(o.appliedAt)).toBe('2026-09-20T19:50:18Z');
    expect(String(o.expiresAt)).toBe('2027-09-20T19:50:18Z');
  });

  it('flags a history that disagrees with the current state and lets the current state win', async () => {
    const env = JSON.parse(loadFixture('triaged.json'));
    const node = env.vulnerabilities.find((v: { id: string }) => v.id === 'gid://gitlab/Vulnerability/85');
    node.state = 'CONFIRMED';
    node.dismissalReason = null;
    env.vulnerabilities = [node];
    const req = requirementByGID(parseJSON<HDFResults>(await convertGitlabVulnerabilitiesToHdf(JSON.stringify(env))), '85');
    expect(req.tags['gitlab/stateHistoryInconsistent']).toBe(true);
    expect(req.tags['gitlab/state']).toBe('CONFIRMED');
    expect(req.statusOverrides).toHaveLength(1);
    expect(req.statusOverrides![0]!.type).toBe(OverrideType.Waiver);
    expect(req.effectiveStatus).toBe(ResultStatus.NotApplicable);
  });

  it('emits no override for DETECTED or CONFIRMED findings', async () => {
    const result = await convert('triaged.json');
    for (const id of ['43', '97']) {
      const req = requirementByGID(result, id);
      expect(req.statusOverrides).toBeUndefined();
      expect(req.disposition).toBeUndefined();
      expect(req.effectiveStatus).toBeUndefined();
    }
    expect(requirementByGID(result, '97').tags['gitlab/confirmedBy']).toBe('sec-reviewer');
  });

  it('keeps a reverted decision as expired history and lets the re-dismissal govern', async () => {
    const req = requirementByGID(await convert('triaged.json'), '80');
    expect(req.statusOverrides).toHaveLength(2);
    const [current, superseded] = req.statusOverrides!;
    expect(current!.type).toBe(OverrideType.FalsePositive);
    expect(superseded!.type).toBe(OverrideType.Waiver);
    expect(String(superseded!.expiresAt)).toBe('2026-09-20T19:27:20Z');
    expect(req.disposition).toBe(OverrideType.FalsePositive);
    expect(req.effectiveStatus).toBe(ResultStatus.NotApplicable);
    expect(req.tags['gitlab/stateTransitionCount']).toBe(3);
  });

  it('turns a severity change into an impact-only riskAdjustment', async () => {
    const req = requirementByGID(await convert('triaged.json'), '66');
    expect(req.impact).toBe(0.5);
    expect(req.statusOverrides).toHaveLength(1);
    const o = req.statusOverrides![0]!;
    expect(o.type).toBe(OverrideType.RiskAdjustment);
    expect(o.status).toBeUndefined();
    expect(o.impact).toEqual({ value: 0.3 });
    expect(req.effectiveImpact).toBe(0.3);
    expect(req.disposition).toBe(OverrideType.RiskAdjustment);
    expect(req.effectiveStatus).toBe(ResultStatus.Failed);
  });
});

describe('gitlab-vulnerabilities-to-hdf document', () => {
  it('groups by report type and pre-fills repository provenance', async () => {
    const result = await convert('triaged.json');
    expect(result.baselines.map((b) => b.name)).toEqual(['GitLab Vulnerability Report: SAST', 'GitLab Vulnerability Report: Secret Detection']);
    expect(result.baselines.map((b) => b.requirements.length)).toEqual([94, 3]);
    expect(result.tool).toEqual({ name: 'GitLab Vulnerability Report', version: '18.9.1-ee' });
    expect(String(result.timestamp)).toBe('2026-09-20T19:50:18Z');
    expect(result.components).toEqual([{
      name: 'security-demo/juice-shop',
      type: 'repository',
      url: 'https://gitlab.example.com/security-demo/juice-shop',
      branch: 'master',
      commit: '556a44e4001434ea7a242f29ede789565066082d',
      labels: { 'gitlab/project-id': 'gid://gitlab/Project/1', 'gitlab/full-path': 'security-demo/juice-shop' },
    }]);
  });

  it('renders an ingested-but-clean report as one no-findings requirement per scanner type', async () => {
    const result = await convert('clean.json');
    expect(result.baselines).toHaveLength(1);
    const req = result.baselines[0]!.requirements[0]!;
    expect(req.id).toBe('gitlab-vulnerability-report-no-findings-secret_detection');
    expect(req.results[0]!.status).toBe(ResultStatus.Passed);
    expect(req.results[0]!.codeDesc).toBe('GitLab Vulnerability Report for security-demo/web-goat lists zero Secret Detection vulnerabilities after a successful scan ingestion.');
  });

  it('refuses a report that ingestion never populated', async () => {
    await expect(convertGitlabVulnerabilitiesToHdf(loadFixture('report-error.json'))).rejects.toThrow(/sast: REPORT_ERROR/);
    await expect(convertGitlabVulnerabilitiesToHdf(loadFixture('empty.json'))).rejects.toThrow(/no default-branch pipeline/);
  });

  it('refuses Community Edition and non-envelopes', async () => {
    const ce = JSON.parse(loadFixture('clean.json'));
    ce.metadata.enterprise = false;
    await expect(convertGitlabVulnerabilitiesToHdf(JSON.stringify(ce))).rejects.toThrow(/Community Edition/);
    await expect(convertGitlabVulnerabilitiesToHdf('{"vulnerabilities":[]}')).rejects.toThrow(/project.fullPath/);
    await expect(convertGitlabVulnerabilitiesToHdf('[]')).rejects.toThrow(/project.fullPath/);
    const ci = readFileSync(join(FIXTURES_DIR, '..', '..', 'gitlab-to-hdf', 'fixtures', 'input', 'minimal-sast.json'), 'utf-8');
    await expect(convertGitlabVulnerabilitiesToHdf(ci)).rejects.toThrow();
  });
});
