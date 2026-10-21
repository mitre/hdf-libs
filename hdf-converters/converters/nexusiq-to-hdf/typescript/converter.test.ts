import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { validateResults } from '@mitre/hdf-validators';
import {
  affectedPackage,
  convertNexusIQToHdf,
  expectedRequirementCount,
  externalReferences,
  impactFor,
  threatCategory,
} from './converter.js';
import { fingerprintObject, nexusiqFingerprint } from './fingerprint.js';

const here = dirname(fileURLToPath(import.meta.url));
const fixture = (name: string): string => readFileSync(join(here, '..', 'fixtures', 'input', name), 'utf8');

type Doc = any;

async function convert(name: string): Promise<Doc> {
  return JSON.parse(await convertNexusIQToHdf(fixture(name), '1.0.0'));
}

function requirement(doc: Doc, id: string): Doc {
  const r = doc.baselines[0].requirements.find((x: Doc) => x.id === id);
  expect(r, id).toBeDefined();
  return r;
}

describe('nexusiq-to-hdf contract', () => {
  it('rejects empty input and invalid JSON', async () => {
    await expect(convertNexusIQToHdf('  ')).rejects.toThrow();
    await expect(convertNexusIQToHdf('not json')).rejects.toThrow();
  });

  it.each([
    '{"foo":1}',
    '[]',
    '{"applicationId":"a","scanId":"s"}',
    '{"applicationId":"a","policyEvaluationResult":{"alerts":[]}}',
    '{"scanId":"s","policyEvaluationResult":{"alerts":[]}}',
    '{"applicationId":5,"scanId":"s","policyEvaluationResult":{"alerts":[]}}',
    '{"applicationId":"a","scanId":"s","policyEvaluationResult":[]}',
    '{"applicationId":"a","scanId":"s","policyEvaluationResult":{"alerts":{}}}',
  ])('rejects %s', async (input) => {
    await expect(convertNexusIQToHdf(input)).rejects.toThrow();
  });
});

describe('nexusiq-to-hdf document', () => {
  it('emits one requirement per alert in source order', async () => {
    const doc = await convert('policy-evaluation.json');
    const source = JSON.parse(fixture('policy-evaluation.json'));
    const ids = doc.baselines[0].requirements.map((r: Doc) => r.id);
    expect(ids).toEqual(source.policyEvaluationResult.alerts.map((a: Doc) => a.trigger.policyViolationId));
    expect(ids).toHaveLength(15);
  });

  it('identifies the producer, the tool and the application', async () => {
    const doc = await convert('policy-evaluation.json');
    expect(doc.generator).toEqual({ name: 'nexusiq-to-hdf', version: '1.0.0' });
    expect(doc.tool).toEqual({ name: 'Nexus IQ Server', format: 'json' });
    expect(doc.components).toEqual([
      {
        type: 'application',
        name: 'example-org_example-app_dev',
        externalIds: { 'nexus-iq': 'example-org_example-app_dev' },
      },
    ]);
  });

  it('carries the report links as root externalReferences', async () => {
    const doc = await convert('policy-evaluation.json');
    expect(doc.externalReferences.map((r: Doc) => r.mediaType)).toEqual([
      'text/html',
      'application/pdf',
      'application/json',
    ]);
    for (const r of doc.externalReferences) expect(r.sourceName).toBe('nexus-iq');
  });

  it('carries the scan context on the baseline', async () => {
    const b = (await convert('policy-evaluation.json')).baselines[0];
    expect(b.title).toBe('Nexus IQ policy evaluation of example-org_example-app_dev (build stage)');
    expect(b.statusMessage).toBeUndefined();
    const ctx = b.extensions.passthrough.nexusiq;
    expect(ctx).toMatchObject({ scanId: '0a1b2c3d4e5f60718293a4b5c6d7e8f9', stage: 'build', policyAction: 'Warning' });
    expect(ctx.summary.criticalPolicyViolationCount).toBe(7);
    expect(ctx.summary).not.toHaveProperty('alerts');
    expect(ctx.summary).not.toHaveProperty('sastAlerts');
  });

  it('validates against the HDF results schema', async () => {
    for (const name of ['policy-evaluation.json', 'empty.json']) {
      const v = validateResults(JSON.parse(await convertNexusIQToHdf(fixture(name))));
      expect(v.valid, `${name}: ${JSON.stringify(v.errors)}`).toBe(true);
    }
  });
});

describe('nexusiq-to-hdf alerts', () => {
  it('maps a security violation', async () => {
    const r = requirement(await convert('policy-evaluation.json'), 'e27fb118b0d940248ae27e451b1e9314');
    expect(r.title).toBe('urllib3 2.7.0 (whl) — Security-High');
    expect(r.impact).toBeCloseTo(0.9);
    expect(r.externalReferences).toEqual([{ sourceName: 'cve', externalId: 'CVE-2026-97687', rel: 'definition' }]);
    expect(r.refs).toEqual([{ url: 'https://nvd.nist.gov/vuln/detail/CVE-2026-97687' }]);
    expect(r.affectedPackages).toEqual([
      { name: 'urllib3', version: '2.7.0', ecosystem: 'pypi', purl: 'pkg:pypi/urllib3@2.7.0' },
    ]);
    expect(r.tags).toMatchObject({
      nist: ['SI-2', 'RA-5'],
      policyName: 'Security-High',
      threatLevel: 9,
      threatCategory: 'critical',
      actions: ['warn'],
      constraints: ['CVSS >=7 and <10'],
      conditionTypes: ['SecurityVulnerabilitySeverity', 'SecurityVulnerabilityStatus'],
      componentHash: ['bd774de92f860e8e0cc6'],
      cvssScore: 8.1,
      cve: ['CVE-2026-97687'],
    });
    const res = r.results[0];
    expect(res.status).toBe('failed');
    expect(res.codeDesc).toContain('with severity >= 7 (severity = 8.1)');
    expect(res.message).toBe(
      'dependency:/./app/module-a.zip/requirements.txt/urllib3==2.7.0\ndependency:/./app/requirements.txt/urllib3==2.7.0',
    );
    expect(res.resource).toBe('package');
    expect(res.resourceId).toBe('pkg:pypi/urllib3@2.7.0');
  });

  it('keeps the wheel and the sdist apart', async () => {
    const doc = await convert('policy-evaluation.json');
    expect(requirement(doc, 'dda0346a9a71412890af075da3a50c60').title).toBe('urllib3 2.7.0 (tar.gz) — Security-High');
  });

  it('describes the policy and its conditions', async () => {
    const r = requirement(await convert('policy-evaluation.json'), 'e27fb118b0d940248ae27e451b1e9314');
    expect(r.descriptions).toEqual([
      {
        label: 'default',
        data: 'Nexus IQ policy Security-High (threat level 9, critical) was violated by urllib3 2.7.0 (whl).',
      },
      {
        label: 'check',
        data: 'CVSS >=7 and <10:\nSecurity Vulnerability Severity >= 7\nSecurity Vulnerability Severity < 10\nSecurity Vulnerability Status is not NOT_APPLICABLE',
      },
    ]);
  });

  it('carries each alert as the result rawSourceRecord', async () => {
    const doc = await convert('policy-evaluation.json');
    const alerts = JSON.parse(fixture('policy-evaluation.json')).policyEvaluationResult.alerts;
    doc.baselines[0].requirements.forEach((r: Doc, i: number) => {
      const rec = r.results[0].rawSourceRecord;
      expect(rec.pointer).toBe(`/policyEvaluationResult/alerts/${i}`);
      expect(rec.mediaType).toBe('application/json');
      expect(JSON.parse(rec.content)).toEqual(alerts[i]);
    });
  });

  it('maps a quality violation without a CVE', async () => {
    const r = requirement(await convert('policy-evaluation.json'), '63fd0bc6f1764894a1259b87ba3da80a');
    expect(r.title).toBe('defusedxml 0.7.1 (tar.gz) — Quality-Architecture-Age GT 5 Years');
    expect(r.impact).toBeCloseTo(0.3);
    expect(r.tags.nist).toEqual(['CM-8']);
    expect(r.tags).not.toHaveProperty('actions');
    expect(r.tags).not.toHaveProperty('cvssScore');
    expect(r.tags).not.toHaveProperty('cve');
    expect(r).not.toHaveProperty('externalReferences');
    expect(r.results[0].codeDesc).toBe('Found component older than 5 years\nFound component younger than 10 years');
  });

  it('gives an unidentified component no package identity', async () => {
    const r = requirement(await convert('policy-evaluation.json'), '23b1b964c6544fae9b48d92f121b13e8');
    expect(r.title).toBe('Unknown component ./app/module-a.zip — Other-Component-Unknown');
    expect(r.impact).toBe(1);
    expect(r).not.toHaveProperty('affectedPackages');
    expect(r.results[0]).not.toHaveProperty('resourceId');
    expect(r.tags).not.toHaveProperty('componentIdentifier');
  });

  it('gives an alert without a violation id a positional id', async () => {
    const doc = JSON.parse(
      await convertNexusIQToHdf(
        '{"applicationId":"a","scanId":"s","policyEvaluationResult":{"alerts":[{"trigger":{"policyName":"P","threatLevel":5,"componentFacts":[]},"actions":[]}]}}',
      ),
    );
    const r = doc.baselines[0].requirements[0];
    expect(r.id).toBe('nexusiq-alert-0');
    expect(r.title).toBe('Unknown component — P');
    expect(r.results[0].codeDesc).toBe('Unknown component violated P');
  });
});

// Every optional field absent or empty: the shapes a trimmed or older result
// file could carry. Go asserts the same document in TestSparseAlerts.
const SPARSE = JSON.stringify({
  applicationId: 'app',
  scanId: 'scan',
  policyEvaluationResult: {
    alerts: [
      {},
      { trigger: { policyName: 'P', componentFacts: [{ componentIdentifier: { format: 'maven' }, displayName: { name: 'shown' } }] } },
      { trigger: { componentFacts: [{ componentIdentifier: { format: 'npm', coordinates: {} } }] } },
      { trigger: { componentFacts: [{ componentIdentifier: null, constraintFacts: [{ conditionFacts: [{ summary: 's' }] }] }] } },
      { trigger: { componentFacts: [{ componentIdentifier: { format: 'pypi', coordinates: { name: 'n' } }, constraintFacts: [{}] }] } },
    ],
  },
});

describe('nexusiq-to-hdf sparse input', () => {
  it('converts alerts with every optional field missing', async () => {
    const doc = JSON.parse(await convertNexusIQToHdf(SPARSE));
    const reqs = doc.baselines[0].requirements;
    expect(reqs.map((r: Doc) => r.title)).toEqual([
      'Unknown component — ',
      'shown — P',
      'Unknown component — ',
      'Unknown component — ',
      'n — ',
    ]);
    expect(reqs.map((r: Doc) => r.id)).toEqual([
      'nexusiq-alert-0', 'nexusiq-alert-1', 'nexusiq-alert-2', 'nexusiq-alert-3', 'nexusiq-alert-4',
    ]);
    expect(reqs[0].impact).toBe(0);
    expect(reqs[0].tags.threatCategory).toBe('none');
    expect(reqs[1]).not.toHaveProperty('affectedPackages');
    expect(reqs[3].descriptions[1].data).toBe(':\ns');
    expect(reqs[4].descriptions[1].data).toBe(':');
    expect(reqs[4].tags.componentIdentifier).toEqual([{ format: 'pypi', coordinates: { name: 'n' } }]);
    expect(doc.baselines[0].title).toBe('Nexus IQ policy evaluation of app');
    expect(doc).not.toHaveProperty('externalReferences');
    expect(doc.baselines[0].extensions.passthrough.nexusiq).toEqual({ applicationId: 'app', scanId: 'scan', summary: {} });
    expect(validateResults(doc).valid).toBe(true);
  });

  it('registers its fingerprint once', async () => {
    const { register } = await import('./fingerprint.js');
    const { getFingerprint } = await import('../../../shared/typescript/registry.js');
    register();
    register();
    expect(getFingerprint('nexusiq-to-hdf')?.label).toBe('Nexus IQ');
  });
});

describe('nexusiq-to-hdf helpers', () => {
  it('bands threat levels the way Sonatype does', () => {
    const want: Record<number, string> = { 0: 'none', 1: 'low', 2: 'moderate', 3: 'moderate', 4: 'severe', 7: 'severe', 8: 'critical', 10: 'critical' };
    for (const [level, band] of Object.entries(want)) expect(threatCategory(Number(level))).toBe(band);
  });

  it('clamps out-of-range threat levels', () => {
    expect(impactFor(-3)).toBe(0);
    expect(impactFor(12)).toBe(1);
  });

  it('builds a purl only for pypi, and normalizes its name', () => {
    expect(affectedPackage({ componentIdentifier: { format: 'npm', coordinates: { packageId: 'lodash', version: '4.17.20' } } })).toEqual({
      name: 'lodash',
      version: '4.17.20',
      ecosystem: 'npm',
    });
    expect(
      affectedPackage({ componentIdentifier: { format: 'pypi', coordinates: { name: 'Typing_Extensions', version: '4.12.2' } } })?.purl,
    ).toBe('pkg:pypi/typing-extensions@4.12.2');
    expect(affectedPackage({ componentIdentifier: { format: 'pypi', coordinates: { name: 'x', version: '1.0+local' } } })?.purl).toBeUndefined();
    expect(affectedPackage({ componentIdentifier: { format: 'a-name', coordinates: { name: 'openssl', version: '1.0' } } })?.ecosystem).toBe('generic');
    expect(affectedPackage({ componentIdentifier: null })).toBeUndefined();
  });

  it('does not call a non-CVE vulnerability id a CVE', () => {
    const refs = externalReferences({
      componentFacts: [{ constraintFacts: [{ conditionFacts: [{ reference: { value: 'sonatype-2024-0001', type: 'SECURITY_VULNERABILITY_REFID' } }] }] }],
    });
    expect(refs).toEqual([{ sourceName: 'nexus-iq', externalId: 'sonatype-2024-0001', rel: 'definition' }]);
  });
});

describe('nexusiq-to-hdf no findings', () => {
  it('converts a clean scan to a passing no-findings requirement', async () => {
    const reqs = (await convert('empty.json')).baselines[0].requirements;
    expect(reqs).toHaveLength(1);
    expect(reqs[0].id).toBe('nexusiq-no-findings');
    expect(reqs[0].results[0].status).toBe('passed');
    expect(reqs[0].results[0].codeDesc).toContain('example-org_example-app_dev');
  });

  it.each([
    '{"applicationId":"a","scanId":"s","policyEvaluationResult":{"alerts":null,"criticalPolicyViolationCount":0}}',
    '{"applicationId":"a","scanId":"s","policyEvaluationResult":{}}',
  ])('treats null or missing alerts with zero counters as clean: %s', async (input) => {
    const doc = JSON.parse(await convertNexusIQToHdf(input));
    expect(doc.baselines[0].requirements[0].id).toBe('nexusiq-no-findings');
  });

  it('rejects null alerts when the counters report violations', async () => {
    await expect(
      convertNexusIQToHdf(
        '{"applicationId":"a","scanId":"s","policyEvaluationResult":{"alerts":null,"criticalPolicyViolationCount":2,"severePolicyViolationCount":1}}',
      ),
    ).rejects.toThrow('3 policy violations');
  });

  it('reports SAST alerts it does not convert', async () => {
    const doc = JSON.parse(
      await convertNexusIQToHdf('{"applicationId":"a","scanId":"s","policyEvaluationResult":{"alerts":[],"sastAlerts":[{},{}]}}'),
    );
    const b = doc.baselines[0];
    expect(b.statusMessage).toContain('2 SAST alerts');
    expect(b.extensions.passthrough.nexusiq.unconvertedSastAlerts).toBe(2);
  });

  it('counts the requirements a result must convert to', () => {
    expect(expectedRequirementCount(fixture('policy-evaluation.json'))).toBe(15);
    expect(expectedRequirementCount(fixture('empty.json'))).toBe(1);
    expect(() => expectedRequirementCount('{}')).toThrow();
  });
});

describe('nexusiq fingerprint', () => {
  it('matches result files and rejects other shapes', () => {
    expect(nexusiqFingerprint.fingerprint(JSON.parse(fixture('policy-evaluation.json')))).toBe(1);
    expect(nexusiqFingerprint.fingerprint(JSON.parse(fixture('empty.json')))).toBe(0.9);
    for (const input of [
      'a string',
      null,
      [],
      { scanId: 's', policyEvaluationResult: {} },
      { applicationId: 'a', policyEvaluationResult: {} },
      { applicationId: 'a', scanId: 's' },
      { applicationId: 'a', scanId: 's', policyEvaluationResult: [] },
    ]) {
      expect(nexusiqFingerprint.fingerprint(input)).toBe(0);
    }
  });

  it('weakens without a violation id to confirm', () => {
    expect(fingerprintObject({ applicationId: 'a', scanId: 's', policyEvaluationResult: { alerts: [{ trigger: {} }] } })).toBe(0.9);
  });
});
