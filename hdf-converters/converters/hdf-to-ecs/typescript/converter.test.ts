import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { describe, it, expect } from 'vitest';
import { convertHdfToEcs } from './converter.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const FIXTURES = join(__dirname, '..', 'fixtures');
const VERSION = '0.1.0';

function input(name: string): string {
  return readFileSync(join(FIXTURES, 'input', name), 'utf-8');
}
function golden(name: string): string {
  return readFileSync(join(FIXTURES, 'expected', name), 'utf-8');
}
function lines(out: string): Record<string, unknown>[] {
  expect(out.endsWith('\n')).toBe(true);
  return out
    .trimEnd()
    .split('\n')
    .map((l) => JSON.parse(l) as Record<string, unknown>);
}
function obj(v: unknown): Record<string, unknown> {
  return v as Record<string, unknown>;
}

describe('hdf-to-ecs converter', () => {
  it('throws on empty and invalid input', () => {
    expect(() => convertHdfToEcs('')).toThrow();
    expect(() => convertHdfToEcs('not json')).toThrow();
    expect(() => convertHdfToEcs('{"foo":1}')).toThrow();
  });

  it('maps compliance results to ECS events', () => {
    const out = lines(convertHdfToEcs(input('compliance.json'), VERSION));
    expect(out).toHaveLength(3);
    const wantOutcome: Record<string, string> = {
      'SV-204393': 'failure',
      'SV-204405': 'success',
      'SV-204424': 'failure',
    };
    for (const o of out) {
      expect(obj(o.ecs).version).toBe('9.4.0');
      const event = obj(o.event);
      const rule = obj(o.rule);
      expect(event.outcome).toBe(wantOutcome[rule.id as string]);
      expect(event.category).toEqual(['configuration']);
      expect(rule.ruleset).toBe('Red Hat Enterprise Linux 7 Security Technical Implementation Guide');
      expect(obj(o.host).name).toBe('localhost.localdomain');
      expect(obj(o.host).ip).toBe('127.0.0.1');
      expect(obj(o.observer).name).toBe('XCCDF');
      expect(o.vulnerability).toBeUndefined();
      const hdf = obj(o.hdf);
      expect(hdf.nist).toBeDefined();
      expect(hdf.cci).toBeDefined();
      expect(hdf.exporter_version).toBe(VERSION);
    }
  });

  it('maps CVE findings to vulnerability.*', () => {
    const out = lines(convertHdfToEcs(input('cve.json'), VERSION));
    expect(out).toHaveLength(3);
    for (const o of out) {
      expect(obj(o.event).category).toContain('vulnerability');
      const vuln = obj(o.vulnerability);
      expect((vuln.id as string).startsWith('CVE-')).toBe(true);
      expect(vuln.enumeration).toBe('CVE');
      expect(vuln.classification).toBe('CVSS');
      expect(obj(vuln.score).base).toBeDefined();
      expect(obj(vuln.scanner).vendor).toBe('Nessus');
    }
  });

  it('is raw-primary: waived failure keeps outcome=failure + hdf.suppressed, lossless history', () => {
    const out = lines(convertHdfToEcs(input('override.json'), VERSION));
    expect(out).toHaveLength(1);
    const o = out[0];
    expect(obj(o.event).outcome).toBe('failure'); // raw verdict, not the waiver
    const hdf = obj(o.hdf);
    expect(hdf.status).toBe('failed');
    expect(hdf.suppressed).toBe(true); // acceptance axis
    expect(hdf.effective_status).toBe('passed');
    expect(hdf.disposition).toBe('waiver');
    expect(hdf.overridden).toBe(true);
    expect(hdf.status_overrides).toHaveLength(1);
    expect(obj((hdf.status_overrides as unknown[])[0]).type).toBe('waiver');
    // host projected (componentId -> host.id); observer omitted (no tool/generator)
    expect(obj(o.host).name).toBe('rhel9-server-01');
    expect(obj(o.host).id).toBe('8f3b2c1a-0000-4a00-8000-000000000001');
    expect(o.observer).toBeUndefined();
  });

  it('risk-adjusted failure stays outcome=failure + not suppressed (still actionable)', () => {
    const o = lines(convertHdfToEcs(input('riskadjust.json'), VERSION))[0];
    expect(obj(o.event).outcome).toBe('failure');
    const hdf = obj(o.hdf);
    expect(hdf.suppressed).toBe(false); // risk adjustment does NOT suppress
    expect(hdf.disposition).toBe('riskAdjustment');
  });

  // U+2028/U+2029 in string data must be escaped identically to Go's encoder.
  it('escapes U+2028/U+2029 for Go parity', () => {
    const LS = String.fromCharCode(0x2028);
    const PS = String.fromCharCode(0x2029);
    const doc = JSON.stringify({
      baselines: [
        {
          name: 'b',
          requirements: [
            {
              id: 'X',
              title: `a${LS}b${PS}c`,
              tags: {},
              results: [{ status: 'passed', codeDesc: 'c', startTime: '2024-01-01T00:00:00Z' }],
            },
          ],
        },
      ],
    });
    const line = convertHdfToEcs(doc, VERSION).trimEnd();
    expect(line).toContain('\\u2028');
    expect(line).toContain('\\u2029');
    expect(line).not.toContain(LS);
    expect(line).not.toContain(PS);
    expect(() => JSON.parse(line)).not.toThrow();
  });

  it('projects ATT&CK tags to threat.* (array and scalar tag forms)', () => {
    const doc = JSON.stringify({
      baselines: [
        {
          name: 'b',
          requirements: [
            {
              id: 'X',
              title: 't',
              tags: { mitre_attack: ['T1059', 'T1078'], attack: 'T1110' },
              results: [{ status: 'failed', codeDesc: 'c', startTime: '2024-01-01T00:00:00Z' }],
            },
          ],
        },
      ],
    });
    const o = lines(convertHdfToEcs(doc, VERSION))[0];
    const threat = obj(o.threat);
    expect(threat.framework).toBe('MITRE ATT&CK');
    const ids = (threat.technique as Record<string, unknown>[]).map((tc) => tc.id);
    expect(ids).toEqual(['T1059', 'T1078', 'T1110']);
  });

  it('falls back to generator for observer.* when tool is absent', () => {
    const doc = JSON.stringify({
      generator: { name: 'grype-to-hdf', version: '1.2.3' },
      baselines: [
        {
          name: 'b',
          requirements: [
            {
              id: 'X',
              tags: {},
              results: [{ status: 'passed', codeDesc: 'c', startTime: '2024-01-01T00:00:00Z' }],
            },
          ],
        },
      ],
    });
    const observer = obj(lines(convertHdfToEcs(doc, VERSION))[0].observer);
    expect(observer.name).toBe('grype-to-hdf');
    expect(observer.version).toBe('1.2.3');
    expect(observer.type).toBe('scanner');
    expect(observer.product).toBeUndefined();
  });

  it('handles a requirement with no results (fallback timestamp, notReviewed → unknown)', () => {
    const doc = JSON.stringify({
      timestamp: '2025-01-01T00:00:00Z',
      baselines: [{ name: 'b', requirements: [{ id: 'X', tags: {}, results: [] }] }],
    });
    const o = lines(convertHdfToEcs(doc, VERSION))[0];
    expect(o['@timestamp']).toBe('2025-01-01T00:00:00Z'); // fell back to doc timestamp
    expect(obj(o.event).outcome).toBe('unknown'); // notReviewed → unknown
    expect(obj(o.hdf).status).toBe('notReviewed');
  });

  it('maps all five Result_Status values to event.outcome (lossless in hdf.status)', () => {
    const cases: Record<string, string> = {
      passed: 'success',
      failed: 'failure',
      notApplicable: 'unknown',
      notReviewed: 'unknown',
      error: 'unknown',
    };
    for (const [status, outcome] of Object.entries(cases)) {
      const doc = JSON.stringify({
        baselines: [
          {
            name: 'b',
            requirements: [
              {
                id: 'X',
                tags: {},
                results: [{ status, codeDesc: 'c', startTime: '2024-01-01T00:00:00Z' }],
              },
            ],
          },
        ],
      });
      const o = lines(convertHdfToEcs(doc, VERSION))[0];
      expect(obj(o.event).outcome).toBe(outcome);
      expect(obj(o.hdf).status).toBe(status); // lossless five-value status
    }
  });

  it('falls back vulnerability.id to the requirement id when cvss has no source', () => {
    const doc = JSON.stringify({
      baselines: [
        {
          name: 'b',
          requirements: [
            {
              id: 'GHSA-abcd-1234',
              tags: {},
              cvss: [{ baseScore: 7.5, version: '3.1' }], // no source
              results: [{ status: 'failed', codeDesc: 'c', startTime: '2024-01-01T00:00:00Z' }],
            },
          ],
        },
      ],
    });
    const vuln = obj(lines(convertHdfToEcs(doc, VERSION))[0].vulnerability);
    expect(vuln.id).toBe('GHSA-abcd-1234'); // fell back to requirement id
    expect(vuln.enumeration).toBeUndefined(); // not a CVE
  });

  it('degrades gracefully: non-default descriptions, url-less refs, startTime-less results', () => {
    const doc = JSON.stringify({
      timestamp: '2025-06-01T00:00:00Z',
      baselines: [
        {
          name: 'b',
          requirements: [
            {
              id: 'X',
              tags: {},
              descriptions: [{ label: 'rationale', data: 'r' }], // no 'default'
              refs: [{ name: 'ref-without-url' }], // no url
              results: [{ status: 'passed', codeDesc: 'c' }], // no startTime
            },
          ],
        },
      ],
    });
    const o = lines(convertHdfToEcs(doc, VERSION))[0];
    expect(o['@timestamp']).toBe('2025-06-01T00:00:00Z'); // result lacks startTime → doc fallback
    const rule = obj(o.rule);
    expect(rule.description).toBeUndefined(); // no default description
    expect(rule.reference).toBeUndefined(); // ref carries no url
  });

  // Byte-for-byte equality with the SAME golden files the Go test asserts
  // against — this is the TS↔Go parity guarantee.
  it('matches golden NDJSON byte-for-byte (TS↔Go parity)', () => {
    for (const name of ['compliance', 'cve', 'override', 'riskadjust']) {
      expect(convertHdfToEcs(input(`${name}.json`), VERSION)).toBe(golden(`${name}.ndjson`));
    }
  });
});
