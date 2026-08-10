import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { describe, it, expect } from 'vitest';
import { convertHdfToSplunk } from './converter.js';

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
  return out
    .trimEnd()
    .split('\n')
    .map((l) => JSON.parse(l) as Record<string, unknown>);
}
function obj(v: unknown): Record<string, unknown> {
  return v as Record<string, unknown>;
}

describe('hdf-to-splunk converter', () => {
  it('throws on invalid / empty / structureless input', () => {
    expect(() => convertHdfToSplunk('')).toThrow();
    expect(() => convertHdfToSplunk('not json')).toThrow();
    expect(() => convertHdfToSplunk('{"foo":1}')).toThrow();
  });

  it('emits HEC envelopes with the stable sourcetype + mirrored indexed fields', () => {
    const out = lines(convertHdfToSplunk(input('compliance.json'), VERSION));
    expect(out).toHaveLength(3);
    for (const o of out) {
      expect(o.sourcetype).toBe('hdf:results');
      expect(o.source).toBe('hdf-exporter');
      const event = obj(o.event);
      const fields = obj(o.fields);
      expect(fields.signature).toBe(event.signature);
      expect(fields.hdf_status).toBe(event.hdf_status);
      expect(fields.severity).toBe(event.severity);
      // pure compliance: no cvss/cve
      expect(event.cvss).toBeUndefined();
      expect(event.cve).toBeUndefined();
      // CIM severity enum
      expect(['critical', 'high', 'medium', 'low', 'informational']).toContain(event.severity);
    }
  });

  it('projects CVE findings with cve + numeric cvss', () => {
    const out = lines(convertHdfToSplunk(input('cve.json'), VERSION));
    expect(out).toHaveLength(3);
    for (const o of out) {
      const event = obj(o.event);
      expect(String(event.cve)).toContain('CVE-');
      expect(typeof event.cvss).toBe('number');
      expect(event.cvss as number).toBeGreaterThanOrEqual(0);
      expect(event.cvss as number).toBeLessThanOrEqual(10);
      expect(obj(o.fields).cvss).toBe(event.cvss);
    }
  });

  it('is raw-primary: waiver keeps hdf_status=failed + suppressed, emits integer epoch time', () => {
    const out = lines(convertHdfToSplunk(input('override.json'), VERSION));
    expect(out).toHaveLength(1);
    const o = out[0];
    expect(o.time).toBe(1704067200); // 2024-01-01T00:00:00Z, integer epoch seconds
    expect(o.host).toBe('rhel9-server-01');
    const event = obj(o.event);
    expect(event.hdf_status).toBe('failed'); // raw verdict drives hdf_status
    expect(event.suppressed).toBe(true); // acceptance axis promoted
    expect(obj(o.fields).suppressed).toBe(true); // mirrored into indexed fields
    const hdf = obj(event.hdf);
    expect(hdf.status).toBe('failed'); // lossless raw preserved
    expect(hdf.suppressed).toBe(true);
    expect(hdf.effective_status).toBe('passed');
    expect(hdf.disposition).toBe('waiver');
    expect(hdf.overridden).toBe(true);
  });

  it('risk-adjusted failure stays hdf_status=failed + not suppressed (still actionable)', () => {
    const o = lines(convertHdfToSplunk(input('riskadjust.json'), VERSION))[0];
    const event = obj(o.event);
    expect(event.hdf_status).toBe('failed');
    expect(event.suppressed).toBe(false); // risk adjustment does NOT suppress
    expect(obj(o.fields).suppressed).toBe(false);
  });

  it('sets category from the first cwe id', () => {
    const doc = JSON.stringify({
      baselines: [
        {
          name: 'b',
          requirements: [
            {
              id: 'X',
              title: 't',
              impact: 0.5,
              cwe: ['CWE-79', 'CWE-89'],
              results: [{ status: 'failed', codeDesc: 'c', startTime: '2024-01-01T00:00:00Z' }],
            },
          ],
        },
      ],
    });
    const o = lines(convertHdfToSplunk(doc, VERSION))[0];
    expect(obj(o.event).category).toBe('CWE-79');
  });

  it('maps impact to the CIM severity enum across all bands', () => {
    const sevForImpact = (impact: number) => {
      const doc = JSON.stringify({
        baselines: [
          { name: 'b', requirements: [{ id: 'X', impact, results: [{ status: 'failed', codeDesc: 'c', startTime: '2024-01-01T00:00:00Z' }] }] },
        ],
      });
      return obj(lines(convertHdfToSplunk(doc, VERSION))[0].event).severity;
    };
    expect(sevForImpact(0.95)).toBe('critical');
    expect(sevForImpact(0.75)).toBe('high');
    expect(sevForImpact(0.5)).toBe('medium');
    expect(sevForImpact(0.2)).toBe('low');
    expect(sevForImpact(0.05)).toBe('low'); // any impact >0 is low; only 0.0 is informational (shared banding)
    expect(sevForImpact(0.0)).toBe('informational');
  });

  it('falls back severity to a normalized source string when impact is absent', () => {
    const mk = (extra: Record<string, unknown>) =>
      JSON.stringify({
        baselines: [
          {
            name: 'b',
            requirements: [
              { id: 'X', title: 't', ...extra, results: [{ status: 'failed', codeDesc: 'c', startTime: '2024-01-01T00:00:00Z' }] },
            ],
          },
        ],
      });
    const sev = (doc: string) => obj(lines(convertHdfToSplunk(doc, VERSION))[0].event).severity;
    expect(sev(mk({ severity: 'high' }))).toBe('high'); // recognized enum passes through
    expect(sev(mk({ severity: 'bogus' }))).toBe('informational'); // unknown -> informational
    expect(sev(mk({}))).toBe('informational'); // no impact, no severity
  });

  it('resolves dest through fqdn -> name -> ip, and omits host/time when absent', () => {
    // only ipAddress on the component -> dest/host = ip
    const ipDoc = JSON.stringify({
      components: [{ ipAddress: '10.0.0.9' }],
      baselines: [{ name: 'b', requirements: [{ id: 'X', impact: 0.5, results: [{ status: 'failed', codeDesc: 'c', startTime: '2024-01-01T00:00:00Z' }] }] }],
    });
    const ip = lines(convertHdfToSplunk(ipDoc, VERSION))[0];
    expect(ip.host).toBe('10.0.0.9');
    expect(obj(ip.event).dest).toBe('10.0.0.9');

    // no component and no parseable timestamp -> dest/host omitted, time omitted
    const bareDoc = JSON.stringify({
      baselines: [{ name: 'b', requirements: [{ id: 'X', impact: 0.5, results: [{ status: 'failed', codeDesc: 'c' }] }] }],
    });
    const bare = lines(convertHdfToSplunk(bareDoc, VERSION))[0];
    expect(bare.host).toBeUndefined();
    expect(obj(bare.event).dest).toBeUndefined();
    expect(bare.time).toBeUndefined();
  });

  it('emits cvss but omits cve when the cvss source is not a CVE', () => {
    const doc = JSON.stringify({
      baselines: [
        {
          name: 'b',
          requirements: [
            {
              id: 'GHSA-xxxx',
              impact: 0.5,
              cvss: [{ baseScore: 7.5, source: 'GHSA-xxxx-yyyy-zzzz' }],
              results: [{ status: 'failed', codeDesc: 'c', startTime: '2024-01-01T00:00:00Z' }],
            },
          ],
        },
      ],
    });
    const event = obj(lines(convertHdfToSplunk(doc, VERSION))[0].event);
    expect(event.cvss).toBe(7.5);
    expect(event.cve).toBeUndefined(); // non-CVE source -> no cve field
  });

  it('surfaces source_location, verification_method, baseline metadata + full component', () => {
    const o = lines(convertHdfToSplunk(input('override.json'), VERSION))[0];
    const event = obj(o.event);
    const hdf = obj(event.hdf);

    // source_location round-trips {ref, line}
    const sl = obj(hdf.source_location);
    expect(sl.ref).toBe('controls/stig.rb');
    expect(sl.line).toBe(1);

    // baseline metadata beyond name
    expect(hdf.baseline_version).toBe('1.0.0');
    expect(hdf.baseline_title).toBe('RHEL 9 STIG Baseline');
    expect(obj(hdf.baseline_checksum).algorithm).toBe('sha256');
    expect(obj(hdf.baseline_checksum).value).toBe('abc123');
    expect((hdf.groups as unknown[]).length).toBe(1);
    expect(obj((hdf.groups as unknown[])[0]).id).toBe('controls/stig.rb');

    // full component + CIM promotions
    const comp = obj(hdf.component);
    expect(comp.componentId).toBe('8f3b2c1a-0000-4a00-8000-000000000001');
    expect(comp.ipAddress).toBe('10.0.0.50');
    expect(comp.osName).toBe('Red Hat Enterprise Linux 9');
    expect(comp.osVersion).toBe('9.3');
    expect(event.os).toBe('Red Hat Enterprise Linux 9');
    expect(event.dest_ip).toBe('10.0.0.50');
    expect(obj(o.fields).dest_ip).toBe('10.0.0.50');

    // verificationMethod absent here -> key omitted
    expect(hdf.verification_method).toBeUndefined();

    // verification_method carries through where the source has it; cve baseline
    // has version but no title/checksum/groups -> those stay absent
    const cveHdf = obj(obj(lines(convertHdfToSplunk(input('cve.json'), VERSION))[0].event).hdf);
    expect(cveHdf.verification_method).toBe('automated');
    expect(cveHdf.baseline_version).toBe('1.0.0');
    expect(cveHdf.baseline_title).toBeUndefined();
    expect(cveHdf.groups).toBeUndefined();
  });

  it('is byte-identical to the Go golden output (TS<->Go parity)', () => {
    for (const name of ['compliance', 'cve', 'override', 'riskadjust']) {
      expect(convertHdfToSplunk(input(`${name}.json`), VERSION)).toBe(golden(`${name}.ndjson`));
    }
  });
});
