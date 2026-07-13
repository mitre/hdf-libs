import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { describe, it, expect } from 'vitest';
import { convertHdfToOcsf } from './converter.js';

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

// Minimal single-requirement HDF doc for exercising specific branches.
function doc(req: Record<string, unknown>, extra: Record<string, unknown> = {}): string {
  return JSON.stringify({ ...extra, baselines: [{ name: 'b', requirements: [req] }] });
}
const baseResult = { status: 'failed', codeDesc: 'c', startTime: '2024-01-01T00:00:00Z' };

describe('hdf-to-ocsf converter', () => {
  it('throws on invalid / empty / structureless input', () => {
    expect(() => convertHdfToOcsf('')).toThrow();
    expect(() => convertHdfToOcsf('not json')).toThrow();
    expect(() => convertHdfToOcsf('{"foo":1}')).toThrow();
  });

  it('routes CVE findings to 2002 and others to 2003', () => {
    for (const o of lines(convertHdfToOcsf(input('compliance.json'), VERSION))) {
      expect(o.class_uid).toBe(2003);
      expect(o.category_uid).toBe(2);
      expect(o.type_uid).toBe(200301);
      expect(o.compliance).toBeDefined();
      expect(o.vulnerabilities).toBeUndefined();
    }
    for (const o of lines(convertHdfToOcsf(input('cve.json'), VERSION))) {
      expect(o.class_uid).toBe(2002);
      expect(o.type_uid).toBe(200201);
      expect(o.vulnerabilities).toBeDefined();
      expect(o.compliance).toBeUndefined();
    }
  });

  it('is raw-primary: a waived failure stays Fail + Suppressed, never masked', () => {
    const o = lines(convertHdfToOcsf(input('override.json'), VERSION))[0];
    expect(obj(o.compliance).status_id).toBe(3); // Fail — raw verdict preserved
    expect(obj(o.compliance).status).toBe('Fail'); // OCSF caption of status_id
    expect(o.status_id).toBe(3); // Suppressed — the waiver drove raw-fail to non-failing
    expect(o.comment).toBe('waiver: Risk accepted per ISSM approval — compensating control in place');
    expect(obj(obj(o.unmapped).hdf_requirement)).toBeDefined();
  });

  it('risk-adjusted failure stays Fail + New (actionable, not suppressed)', () => {
    const o = lines(convertHdfToOcsf(input('riskadjust.json'), VERSION))[0];
    expect(obj(o.compliance).status_id).toBe(3); // raw verdict Fail
    expect(obj(o.compliance).status).toBe('Fail');
    expect(o.status_id).toBe(1); // New — risk adjustment does NOT suppress
  });

  it('supports the canonical actionable-failures query on enums only', () => {
    const actionable = (o: Record<string, unknown>) => {
      const c = obj(o.compliance);
      return c?.status_id === 3 && (o.status_id === 1 || o.status_id === 2);
    };
    const comp = lines(convertHdfToOcsf(input('compliance.json'), VERSION)).filter(actionable);
    expect(comp).toHaveLength(2); // two open fails, no waivers
    const ov = lines(convertHdfToOcsf(input('override.json'), VERSION));
    expect(ov.every((o) => !actionable(o))).toBe(true); // waived fail excluded
  });

  it('carries framework tags on a vuln finding (finding_info.tags), not on compliance findings', () => {
    // CVE + NIST/CCI -> Vulnerability Finding (no compliance.checks[]); framework
    // mapping rides on finding_info.tags so it stays queryable, not buried in unmapped.
    const cve = lines(
      convertHdfToOcsf(
        doc({ id: 'CVE-2024-1', impact: 0.7, cvss: [{ baseScore: 7.5, source: 'CVE-2024-1' }], tags: { nist: ['SI-2', 'RA-5'], cci: ['CCI-000366'] }, results: [baseResult] }),
        VERSION,
      ),
    )[0];
    expect(cve.class_uid).toBe(2002);
    const tags = obj(cve.finding_info).tags as Record<string, unknown>[];
    expect(tags).toHaveLength(2);
    expect(tags[0]).toEqual({ name: 'nist', values: ['SI-2', 'RA-5'] });
    expect(tags[1]).toEqual({ name: 'cci', values: ['CCI-000366'] });

    // compliance finding: frameworks via compliance.checks[], no finding_info.tags
    const comp = lines(convertHdfToOcsf(doc({ id: 'V-1', impact: 0.5, tags: { nist: ['AC-6'] }, results: [baseResult] }), VERSION))[0];
    expect(obj(comp.finding_info).tags).toBeUndefined();
    expect(obj(comp.compliance).checks).toBeDefined();
  });

  it('renders a whole-number CVSS base_score as OCSF float_t (10.0, not 10)', () => {
    const out = convertHdfToOcsf(
      doc({ id: 'CVE-x', impact: 0.7, cvss: [{ baseScore: 10, version: '3.1', source: 'CVE-x' }], results: [baseResult] }),
      VERSION,
    );
    expect(out).toContain('"base_score":10.0');
    expect(out).not.toContain('"base_score":10,');
  });

  it('carries CVE + numeric cvss + related_cwes', () => {
    for (const o of lines(convertHdfToOcsf(input('cve.json'), VERSION))) {
      const cve = obj(obj((o.vulnerabilities as unknown[])[0]).cve);
      expect(String(cve.uid)).toContain('CVE-');
      const cvss = obj((cve.cvss as unknown[])[0]);
      expect(typeof cvss.base_score).toBe('number');
      expect(cvss.version).toBeTruthy();
    }
  });

  it('maps severity_id across impact bands and a source-severity fallback', () => {
    const sev = (r: Record<string, unknown>) => lines(convertHdfToOcsf(doc({ id: 'X', ...r, results: [baseResult] }), VERSION))[0].severity_id;
    expect(sev({ impact: 0.95 })).toBe(5);
    expect(sev({ impact: 0.75 })).toBe(4);
    expect(sev({ impact: 0.5 })).toBe(3);
    expect(sev({ impact: 0.2 })).toBe(2);
    expect(sev({ impact: 0.0 })).toBe(1);
    expect(sev({ severity: 'high' })).toBe(4); // no impact -> string
    expect(sev({ severity: 'none' })).toBe(1);
    expect(sev({})).toBe(0); // nothing -> Unknown
  });

  it('classifies os.type_id and falls back through device identifiers', () => {
    const os = (osName: string) =>
      obj(obj(lines(convertHdfToOcsf(doc({ id: 'X', impact: 0.5, results: [baseResult] }, { components: [{ name: 'h', osName }] }), VERSION))[0].device).os).type_id;
    expect(os('Windows Server 2019')).toBe(100);
    expect(os('Red Hat Enterprise Linux 8')).toBe(200);
    expect(os('macOS 14')).toBe(300);
    expect(os('Appliance')).toBe(0);

    // ip-only component still yields a device; no component -> no device
    const ipOnly = lines(convertHdfToOcsf(doc({ id: 'X', impact: 0.5, results: [baseResult] }, { components: [{ ipAddress: '10.0.0.9' }] }), VERSION))[0];
    expect(obj(ipOnly.device).ip).toBe('10.0.0.9');
    const noComp = lines(convertHdfToOcsf(doc({ id: 'X', impact: 0.5, results: [baseResult] }), VERSION))[0];
    expect(noComp.device).toBeUndefined();
  });

  it('builds the override comment from disposition and/or justification', () => {
    const comment = (r: Record<string, unknown>) => lines(convertHdfToOcsf(doc({ id: 'X', impact: 0.5, results: [baseResult], ...r }), VERSION))[0].comment;
    expect(comment({ disposition: 'waiver', statusOverrides: [{ reason: 'accepted' }] })).toBe('waiver: accepted');
    expect(comment({ disposition: 'falsePositive' })).toBe('falsePositive');
    expect(comment({ statusOverrides: [{ reason: 'r only' }] })).toBe('r only');
    expect(comment({})).toBeUndefined(); // no override -> no comment
  });

  it('always emits OCSF-required time and metadata.product (with fallbacks)', () => {
    // no parseable timestamp -> time = 0 sentinel (still present); no tool/generator -> product = exporter identity
    const o = lines(convertHdfToOcsf(doc({ id: 'X', impact: 0.5, results: [{ status: 'failed', codeDesc: 'c' }] }), VERSION))[0];
    expect(o.time).toBe(0);
    expect(obj(obj(o.metadata).product).name).toBe('hdf-to-ocsf');
    expect(obj(obj(o.metadata).product).version).toBe(VERSION);
    // parseable timestamp -> integer epoch millis
    const withTime = lines(convertHdfToOcsf(doc({ id: 'X', impact: 0.5, results: [baseResult] }), VERSION))[0];
    expect(withTime.time).toBe(1704067200000);
  });

  it('covers severity-string bands, compliance Warning, and generator fallback', () => {
    const sev = (s: string) => lines(convertHdfToOcsf(doc({ id: 'X', severity: s, results: [baseResult] }), VERSION))[0].severity_id;
    expect(sev('critical')).toBe(5);
    expect(sev('medium')).toBe(3);
    expect(sev('low')).toBe(2);
    expect(sev('informational')).toBe(1);

    // error/notApplicable/notReviewed -> compliance.status_id 2 (Warning); the
    // sibling string is the OCSF caption "Warning" (HDF granularity in unmapped)
    for (const status of ['error', 'notApplicable', 'notReviewed']) {
      const o = lines(convertHdfToOcsf(doc({ id: 'X', impact: 0.5, results: [{ status, codeDesc: 'c', startTime: '2024-01-01T00:00:00Z' }] }), VERSION))[0];
      expect(obj(o.compliance).status_id).toBe(2);
      expect(obj(o.compliance).status).toBe('Warning');
      expect(obj(obj(o.unmapped).hdf_requirement)).toBeDefined(); // exact HDF status preserved here
    }

    // no tool, but a generator -> metadata.product from generator
    const g = lines(convertHdfToOcsf(doc({ id: 'X', impact: 0.5, results: [baseResult] }, { generator: { name: 'grype-to-hdf', version: '1.2.3' } }), VERSION))[0];
    expect(obj(obj(g.metadata).product).name).toBe('grype-to-hdf');
  });

  it('covers vuln cve.uid fallback, related_cwes, references, and empty device', () => {
    // cvss with a non-CVE source -> cve.uid falls back to the requirement id; cwe -> related_cwes; refs -> references
    const o = lines(
      convertHdfToOcsf(
        doc({
          id: 'GHSA-xxxx',
          impact: 0.5,
          cvss: [{ baseScore: 7.5, version: '3.1', source: 'GHSA-xxxx-yyyy' }],
          cwe: ['CWE-79'],
          refs: [{ url: 'https://advisory.example/GHSA-xxxx' }],
          results: [baseResult],
        }),
        VERSION,
      ),
    )[0];
    const cve = obj(obj((o.vulnerabilities as unknown[])[0]).cve);
    expect(cve.uid).toBe('GHSA-xxxx'); // fell back to requirement id
    expect(cve.related_cwes).toEqual([{ uid: 'CWE-79' }]);
    expect(obj((o.vulnerabilities as unknown[])[0]).references).toEqual(['https://advisory.example/GHSA-xxxx']);

    // component with no identifying attribute -> no device
    const noDev = lines(convertHdfToOcsf(doc({ id: 'X', impact: 0.5, results: [baseResult] }, { components: [{ description: 'x' }] }), VERSION))[0];
    expect(noDev.device).toBeUndefined();
  });

  it('classifies additional OS families (ubuntu, darwin)', () => {
    const os = (osName: string) =>
      obj(obj(lines(convertHdfToOcsf(doc({ id: 'X', impact: 0.5, results: [baseResult] }, { components: [{ name: 'h', osName }] }), VERSION))[0].device).os).type_id;
    expect(os('Ubuntu 22.04')).toBe(200);
    expect(os('Darwin Kernel')).toBe(300);
  });

  it('handles a nameless baseline and a tool with a format (vendor_name)', () => {
    const out = convertHdfToOcsf(
      JSON.stringify({
        tool: { name: 'Nessus', format: 'nessus' },
        baselines: [{ requirements: [{ id: 'X', impact: 0.5, tags: { nist: ['AC-1'] }, results: [baseResult] }] }],
      }),
      VERSION,
    );
    const o = lines(out)[0];
    // nameless baseline -> standards has no baseline entry, only the framework
    expect(obj(o.compliance).standards).toEqual(['NIST SP 800-53']);
    // tool.format -> metadata.product.vendor_name
    expect(obj(obj(o.metadata).product).vendor_name).toBe('nessus');
  });

  it('maps notApplicable / notReviewed / error all to compliance.status_id 2 (Warning)', () => {
    const out = lines(convertHdfToOcsf(input('warnings.json'), VERSION));
    expect(out).toHaveLength(3);
    for (const o of out) {
      expect(o.class_uid).toBe(2003);
      expect(obj(o.compliance).status_id).toBe(2);
      expect(obj(o.compliance).status).toBe('Warning');
      expect(o.status_id).toBe(1); // not suppressed — still New
    }
  });

  it('is byte-identical to the Go golden output (TS<->Go parity)', () => {
    for (const name of ['compliance', 'cve', 'override', 'riskadjust', 'warnings', 'scalartag']) {
      expect(convertHdfToOcsf(input(`${name}.json`), VERSION)).toBe(golden(`${name}.ndjson`));
    }
  });
});
