import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { describe, it, expect } from 'vitest';
import { normalizeSafSupplement, parseResults } from './index.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const fixturesDir = join(__dirname, '..', 'testdata', 'saf-supplement');

// Minimal schema-valid v3 results base; extra top-level keys are spliced in per test.
function validV3WithExtra(extra: Record<string, unknown>): string {
  return JSON.stringify({
    timestamp: '2026-01-01T00:00:00Z',
    generator: { name: 't', version: '0.0.1' },
    statistics: { duration: 0.1 },
    baselines: [{
      name: 'B',
      resultsChecksum: { algorithm: 'sha256', value: '0'.repeat(64) },
      requirements: [{
        id: 'x', title: 't', impact: 0, tags: {},
        descriptions: [{ label: 'default', data: 'd' }],
        results: [{ status: 'passed', codeDesc: 'd', startTime: '2026-01-01T00:00:00Z' }],
      }],
    }],
    ...extra,
  });
}

describe('normalizeSafSupplement', () => {
  it('rewrites a legacy target into a components[] cloudAccount entry', () => {
    const { output, warnings } = normalizeSafSupplement(
      validV3WithExtra({ target: { id: 'prod-account', type: 'cloudAccount', boundary: 'sparc' } }),
    );
    const doc = JSON.parse(output);
    expect('target' in doc).toBe(false);
    expect(doc.components).toHaveLength(1);
    expect(doc.components[0]).toMatchObject({
      type: 'cloudAccount', name: 'prod-account', accountId: 'prod-account', labels: { boundary: 'sparc' },
    });
    expect(warnings.length).toBeGreaterThan(0);
  });

  it('rewrites a legacy passthrough under extensions.passthrough', () => {
    const { output, warnings } = normalizeSafSupplement(
      validV3WithExtra({ passthrough: { audit: { runId: 'r-123' } } }),
    );
    const doc = JSON.parse(output);
    expect('passthrough' in doc).toBe(false);
    expect(doc.extensions.passthrough.audit.runId).toBe('r-123');
    expect(warnings.length).toBeGreaterThan(0);
  });

  // `extensions` is a closed object, so an undefined sibling may not stay: it is
  // moved INTO passthrough. Leaving it would normalize legacy input into a
  // document the schema rejects. The data survives, one level down.
  it('relocates an undefined extensions sibling into passthrough', () => {
    const { output, warnings } = normalizeSafSupplement(
      validV3WithExtra({ extensions: { foo: 'bar' }, passthrough: { audit: { runId: 'r-1' } } }),
    );
    const doc = JSON.parse(output);
    expect(doc.extensions.foo).toBeUndefined();
    expect(doc.extensions.passthrough.foo).toBe('bar');
    expect(doc.extensions.passthrough.audit.runId).toBe('r-1');
    expect(warnings.some((w: string) => w.includes('extensions.foo was moved into'))).toBe(true);
  });

  // A sibling whose name already exists inside passthrough cannot be moved
  // there; it is dropped with a warning rather than clobbering carried data.
  it('reports a sibling it cannot relocate instead of clobbering passthrough', () => {
    const { output, warnings } = normalizeSafSupplement(
      validV3WithExtra({
        extensions: { audit: 'sibling' },
        passthrough: { audit: { runId: 'r-1' } },
      }),
    );
    const doc = JSON.parse(output);
    expect(doc.extensions.passthrough.audit.runId).toBe('r-1');
    expect(warnings.some((w: string) => w.includes('extensions.audit was dropped'))).toBe(true);
  });

  it('passes a doc with no legacy keys through byte-identical with no warnings', () => {
    const input = validV3WithExtra({});
    const { output, warnings } = normalizeSafSupplement(input);
    expect(output).toBe(input);
    expect(warnings).toHaveLength(0);
  });

  it('merges a target into a matching existing component rather than duplicating', () => {
    const { output } = normalizeSafSupplement(
      validV3WithExtra({
        components: [{ name: 'prod-account', type: 'cloudAccount' }],
        target: { id: 'prod-account', type: 'cloudAccount', boundary: 'sparc' },
      }),
    );
    const doc = JSON.parse(output);
    expect(doc.components).toHaveLength(1);
    expect(doc.components[0].labels.boundary).toBe('sparc');
  });

  // The component the v2→v3 upgrade derives from an InSpec `platform` object.
  const platformDerived = () => ({ name: 'redhat', osName: 'redhat', osVersion: '9.8', type: 'host' });
  const componentsOf = (extra: Record<string, unknown>) => {
    const { output } = normalizeSafSupplement(validV3WithExtra(extra));
    expect(parseResults(output).success).toBe(true);
    return JSON.parse(output).components as Array<Record<string, unknown>>;
  };

  it('uses a legacy target name as the component identity', () => {
    const comps = componentsOf({ target: { type: 'host', name: 'my-host-01', labels: {} } });
    expect(comps).toHaveLength(1);
    expect(comps[0].name).toBe('my-host-01');
  });

  it('prefers target.id over target.name', () => {
    const comps = componentsOf({ target: { id: 'prod-account', name: 'Production', type: 'cloudAccount' } });
    expect(comps[0]).toMatchObject({ name: 'prod-account', accountId: 'prod-account' });
  });

  // accountId is the provider's account identifier, so only target.id may fill it.
  it('does not stamp a display name into accountId', () => {
    const comps = componentsOf({ target: { name: 'Production', type: 'cloudAccount' } });
    expect(comps).toHaveLength(1);
    expect(comps[0]).toEqual({ type: 'cloudAccount', name: 'Production' });
  });

  // The first-class target.boundary is the SAF carrier; a labels.boundary entry does not
  // displace it.
  it('lets the boundary field win over a boundary label', () => {
    const comps = componentsOf({
      target: { type: 'host', name: 'my-host-01', boundary: 'sparc', labels: { boundary: 'legacy-zone', environment: 'prod' } },
    });
    expect(comps[0].labels).toEqual({ boundary: 'sparc', environment: 'prod' });
  });

  // Component labels are string-valued, so a non-string target label is skipped.
  it('carries string target labels alongside the boundary label', () => {
    const comps = componentsOf({
      target: { type: 'host', name: 'my-host-01', boundary: 'sparc', labels: { environment: 'prod', rack: 7 } },
    });
    expect(comps[0].labels).toEqual({ environment: 'prod', boundary: 'sparc' });
  });

  it('does not override labels the component already carries', () => {
    const comps = componentsOf({
      components: [{ name: 'my-host-01', type: 'host', labels: { environment: 'stage' } }],
      target: { type: 'host', name: 'my-host-01', labels: { environment: 'prod', team: 'ops' } },
    });
    expect(comps).toHaveLength(1);
    expect(comps[0].labels).toEqual({ environment: 'stage', team: 'ops' });
  });

  it('merges a target into the platform-derived component (one assessed host)', () => {
    const comps = componentsOf({
      components: [platformDerived()],
      target: { type: 'host', name: 'my-host-01', labels: { environment: 'prod' } },
    });
    expect(comps).toEqual([{
      name: 'my-host-01', type: 'host', osName: 'redhat', osVersion: '9.8', labels: { environment: 'prod' },
    }]);
  });

  it('keeps the platform name when the target carries no identity', () => {
    const comps = componentsOf({ components: [platformDerived()], target: { type: 'host', boundary: 'sparc' } });
    expect(comps).toHaveLength(1);
    expect(comps[0]).toMatchObject({ name: 'redhat', labels: { boundary: 'sparc' } });
  });

  // A component that carries its own identity is a distinct thing, never renamed.
  it.each([
    ['has componentId', [{ ...platformDerived(), componentId: '6f1c1c3e-8f43-4d2a-9a57-0d5a3c2b7e11' }]],
    ['name is not the OS', [{ ...platformDerived(), name: 'web-01' }]],
    ['different type', [{ name: 'redhat', osName: 'redhat', type: 'containerImage' }]],
    ['more than one exists', [platformDerived(), { name: 'db-01', type: 'database' }]],
  ])('does not merge into a distinct component (%s)', (_label, existing) => {
    const comps = componentsOf({ components: existing, target: { type: 'host', name: 'my-host-01' } });
    expect(comps).toHaveLength(existing.length + 1);
    expect(comps.slice(0, existing.length)).toEqual(existing);
    expect(comps[existing.length].name).toBe('my-host-01');
  });

  it('leaves an unmapped target type in place for the schema to reject', () => {
    const { output, warnings } = normalizeSafSupplement(
      validV3WithExtra({ target: { id: 'x', type: 'not-a-real-type' } }),
    );
    const doc = JSON.parse(output);
    expect('target' in doc).toBe(true);
    expect(warnings.length).toBeGreaterThan(0);
  });

  // camfd wiring: parseResults runs the normalizer before ajv validation, so a
  // SAF-supplemented doc (which ajv would otherwise reject on unevaluatedProperties)
  // parses, with target as a component and the deprecation warning surfaced.
  it('parseResults accepts a SAF-supplemented doc and surfaces the warning', () => {
    const input = readFileSync(join(fixturesDir, 'legacy-in.json'), 'utf-8');
    const r = parseResults(input);
    expect(r.success).toBe(true);
    const comps = (r.data?.components ?? []) as Array<{ name?: string; type?: string }>;
    expect(comps.some((c) => c.name === 'prod-account' && c.type === 'cloudAccount')).toBe(true);
    expect(r.warnings && r.warnings.length).toBeGreaterThan(0);
  });

  // Cross-language parity: TS normalizes the shared legacy-in fixture to the same
  // v3 document the Go suite asserts (deep-equal; key order differs across langs).
  it('matches the shared legacy-in / v3-out fixture pair (Go parity)', () => {
    const input = readFileSync(join(fixturesDir, 'legacy-in.json'), 'utf-8');
    const expected = JSON.parse(readFileSync(join(fixturesDir, 'v3-out.json'), 'utf-8'));
    const { output } = normalizeSafSupplement(input);
    expect(JSON.parse(output)).toEqual(expected);
  });
});
