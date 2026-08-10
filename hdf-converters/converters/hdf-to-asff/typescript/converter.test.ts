import {readFileSync} from 'fs';
import {join, dirname} from 'path';
import {fileURLToPath} from 'url';
import {describe, it, expect} from 'vitest';
import {convertHdfToAsff} from './converter.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const FIXTURES = join(__dirname, '..', 'fixtures');
const VERSION = '0.1.0';

function input(name: string): string {
  return readFileSync(join(FIXTURES, 'input', name), 'utf-8');
}
function golden(name: string): string {
  return readFileSync(join(FIXTURES, 'expected', name), 'utf-8');
}
function findings(out: string): Record<string, unknown>[] {
  const env = JSON.parse(out) as {Findings: Record<string, unknown>[]};
  return env.Findings;
}
function convert(name: string): Record<string, unknown>[] {
  return findings(convertHdfToAsff(input(name), VERSION));
}

describe('hdf-to-asff converter', () => {
  it('throws on invalid / empty / structureless input', () => {
    expect(() => convertHdfToAsff('')).toThrow();
    expect(() => convertHdfToAsff('not json')).toThrow();
    expect(() => convertHdfToAsff('{"foo":1}')).toThrow();
  });

  it('emits the required ASFF top-level attributes', () => {
    for (const f of convert('compliance.json')) {
      for (const k of [
        'SchemaVersion', 'Id', 'ProductArn', 'GeneratorId', 'AwsAccountId',
        'CreatedAt', 'UpdatedAt', 'Title', 'Description', 'Types', 'Severity',
        'Resources', 'Compliance',
      ]) {
        expect(f, `required attribute ${k}`).toHaveProperty(k);
      }
      expect(f.SchemaVersion).toBe('2018-10-08');
      expect((f.Resources as unknown[]).length).toBeGreaterThan(0);
    }
  });

  it('routes CVE findings to the Vulnerabilities/CVE type and others to config checks', () => {
    for (const f of convert('cve.json')) {
      expect(f.Types).toEqual(['Software and Configuration Checks/Vulnerabilities/CVE']);
    }
    for (const f of convert('compliance.json')) {
      expect(f.Types).toEqual(['Software and Configuration Checks']);
    }
  });

  it('recovers AwsAccountId from a cloudAccount component', () => {
    expect(convert('cloudaccount.json')[0].AwsAccountId).toBe('123456789123');
  });

  it('uses a placeholder account id when there is no cloudAccount component', () => {
    expect(convert('cve.json')[0].AwsAccountId).toBe('000000000000');
  });

  it('marks override-suppressed requirements as SUPPRESSED', () => {
    const doc = JSON.stringify({
      baselines: [{
        name: 'b',
        requirements: [{
          id: 'C-1',
          title: 't',
          results: [{status: 'failed', codeDesc: 'c', startTime: '2024-01-01T00:00:00Z'}],
          effectiveStatus: 'passed',
          statusOverrides: [{type: 'waiver'}],
        }],
      }],
    });
    const f = findings(convertHdfToAsff(doc, VERSION))[0];
    expect(f.Workflow).toEqual({Status: 'SUPPRESSED'});
    expect((f.Compliance as Record<string, unknown>).Status).toBe('PASSED');
  });

  it('recovers AwsAccountId from a cloudAccount component accountId field', () => {
    const doc = JSON.stringify({
      components: [{type: 'cloudAccount', accountId: '999888777666'}],
      baselines: [{name: 'b', requirements: [{id: 'C-1', results: [{status: 'passed', startTime: '2024-01-01T00:00:00Z'}]}]}],
    });
    expect(findings(convertHdfToAsff(doc, VERSION))[0].AwsAccountId).toBe('999888777666');
  });

  function byGenerator(fs: Record<string, unknown>[], gen: string): Record<string, unknown> {
    const f = fs.find((x) => x.GeneratorId === gen);
    if (!f) throw new Error(`GeneratorId ${gen} not found`);
    return f;
  }

  it('maps requirement.cvss[] to Vulnerabilities[] with Id/Cvss/ReferenceUrls', () => {
    const f = byGenerator(convert('cve.json'), '156888');
    const vulns = f.Vulnerabilities as Record<string, unknown>[];
    expect(vulns).toHaveLength(1);
    expect(vulns[0].Id).toBe('CVE-2022-21291');
    const cvss = vulns[0].Cvss as Record<string, unknown>[];
    expect(cvss[0]).toEqual({
      Version: '3.0',
      BaseScore: 5.3,
      BaseVector: 'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N',
      Source: 'CVE-2022-21291',
    });
    expect(vulns[0].ReferenceUrls).toEqual([
      'https://www.oracle.com/a/tech/docs/cpujan2022cvrf.xml',
      'https://www.oracle.com/security-alerts/cpujan2022.html#AppendixJAVA',
    ]);
  });

  it('keeps a zero base score and omits ReferenceUrls when a requirement has no refs', () => {
    const f = byGenerator(convert('cve.json'), '10223');
    const v = (f.Vulnerabilities as Record<string, unknown>[])[0];
    expect((v.Cvss as Record<string, unknown>[])[0].BaseScore).toBe(0);
    expect(v).not.toHaveProperty('ReferenceUrls');
  });

  it('maps tags.nist + tags.cci to Compliance.RelatedRequirements', () => {
    const f = byGenerator(convert('compliance.json'), 'SV-204393');
    expect((f.Compliance as Record<string, unknown>).RelatedRequirements).toEqual([
      'AC-8 a', 'AC-8.1 (ii)', 'CCI-000048',
    ]);
  });

  it('maps a ReasonCode/Description message to Compliance.StatusReasons', () => {
    const f = byGenerator(convert('cloudaccount.json'), '1.1');
    expect((f.Compliance as Record<string, unknown>).StatusReasons).toEqual([{
      ReasonCode: 'CLOUDTRAIL_MULTI_REGION_NOT_PRESENT',
      Description: 'Multi region CloudTrail with the required configuration does not exist in the account',
    }]);
  });

  it('does not turn a free-form message into StatusReasons', () => {
    const f = byGenerator(convert('cve.json'), '156888');
    expect(f.Compliance as Record<string, unknown>).not.toHaveProperty('StatusReasons');
  });

  it('carries tool / generator / baseline version on ProductFields', () => {
    const pf = convert('cve.json')[0].ProductFields as Record<string, unknown>;
    expect(pf['hdf/tool']).toBe('Nessus');
    expect(pf['hdf/generator']).toBe('nessus-to-hdf');
    expect(pf['hdf/baseline_version']).toBe('1.0.0');
    const cpf = convert('cloudaccount.json')[0].ProductFields as Record<string, unknown>;
    expect(cpf).not.toHaveProperty('hdf/baseline_version');
  });

  it('is byte-identical to the Go golden output (TS<->Go parity)', () => {
    for (const name of ['compliance', 'cve', 'cloudaccount']) {
      expect(convertHdfToAsff(input(`${name}.json`), VERSION)).toBe(golden(`${name}.asff.json`));
    }
  });
});
