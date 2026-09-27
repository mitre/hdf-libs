import { describe, it, expect } from 'vitest';
import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import type { HDFResults } from '@mitre/hdf-schema';
import { results as sharedResults } from '@mitre/hdf-fixtures';
import { merge, type MergeSource } from '../src/merge.js';
import { engineVersion } from '../src/index.js';
import { validateResults } from '@mitre/hdf-validators';

// merge-grype/merge-zap live in the shared corpus (@mitre/hdf-fixtures), read
// here and by go/merge_test.go; merge-gosec is still local to this package.
// Both languages read the SAME bytes and assert the SAME expectations.
const testdata = join(dirname(fileURLToPath(import.meta.url)), '..', 'testdata');
const load = (name: string): HDFResults => {
  const raw =
    name === 'merge-grype.json'
      ? sharedResults.mergeGrype.read()
      : name === 'merge-zap.json'
        ? sharedResults.mergeZap.read()
        : readFileSync(join(testdata, name), 'utf-8');
  return JSON.parse(raw) as HDFResults;
};

function threeScanners(): MergeSource[] {
  return [
    { name: 'gosec.hdf.json', doc: load('merge-gosec.json') },
    { name: 'zap.hdf.json', doc: load('merge-zap.json') },
    { name: 'grype.hdf.json', doc: load('merge-grype.json') },
  ];
}

const names = (r: HDFResults): string[] => r.baselines.map((b) => b.name);

// Everything about a baseline except the two fields merge rewrites.
function withoutNameAndLabels(b: HDFResults['baselines'][number]): Omit<typeof b, 'name' | 'labels'> {
  const copy: Partial<typeof b> = { ...b };
  delete copy.name;
  delete copy.labels;
  return copy as Omit<typeof b, 'name' | 'labels'>;
}

describe('hdf-engine merge — cross-language parity with go/merge_test.go', () => {
  it('one baseline per input baseline, renamed <tool>/<original>, every requirement kept', () => {
    const { results, warnings } = merge(threeScanners());
    expect(warnings).toEqual([]);
    expect(names(results)).toEqual([
      'gosec/gosec Scan',
      'owasp zap/OWASP ZAP Scan: ciscobinary.openh264.org',
      'owasp zap/OWASP ZAP Scan: code.jquery.com',
      'owasp zap/OWASP ZAP Scan: detectportal.firefox.com',
      'owasp zap/OWASP ZAP Scan: mymac.com',
      'grype/tensorflow/tensorflow:latest',
    ]);
    expect(results.baselines.reduce((n, b) => n + b.requirements.length, 0)).toBe(57);
  });

  it('provenance labels: tool / toolVersion / sourceDocument, existing labels preserved', () => {
    const { results } = merge(threeScanners());
    expect(results.baselines[0].labels).toEqual({ tool: 'gosec', toolVersion: 'dev', sourceDocument: 'gosec.hdf.json' });
    expect(results.baselines[0].extensions).toHaveProperty('gosec');
    expect(results.baselines[1].labels).toEqual({
      component: 'ciscobinary.openh264.org',
      tool: 'owasp zap',
      toolVersion: '2.7.0',
      sourceDocument: 'zap.hdf.json',
    });
    expect(results.baselines[5].labels).toEqual({ tool: 'grype', toolVersion: '0.79.3', sourceDocument: 'grype.hdf.json' });
  });

  it('root: generator hdf-merge@engineVersion, no tool, latest timestamp, component union, sources verbatim', () => {
    const { results } = merge(threeScanners());
    expect(results.generator).toEqual({ name: 'hdf-merge', version: engineVersion });
    expect(results.tool).toBeUndefined();
    expect(results.timestamp).toBe('2026-07-12T22:56:36.173673Z');
    expect(results.components).toHaveLength(5);
    const ext = results.extensions?.['hdf-merge'] as { version: string; sources: Record<string, unknown>[] };
    expect(ext.version).toBe(engineVersion);
    expect(ext.sources).toHaveLength(3);
    expect(ext.sources[0]).toEqual({
      index: 0,
      name: 'gosec.hdf.json',
      tool: { name: 'gosec', version: 'dev' },
      generator: { name: 'gosec-to-hdf', version: '1.0.0' },
      timestamp: '2026-07-12T22:56:36.173673Z',
    });
  });

  it('is deterministic: identical inputs serialize identically', () => {
    const a = JSON.stringify(merge(threeScanners()).results);
    const b = JSON.stringify(merge(threeScanners()).results);
    expect(a).toBe(b);
  });

  it('warns on name collisions and label overwrites; merged roots prefix by generator', () => {
    const g = load('merge-gosec.json');
    const first = merge([
      { name: 'a.json', doc: g },
      { name: 'b.json', doc: g },
    ]);
    expect(names(first.results)).toEqual(['gosec/gosec Scan', 'gosec/gosec Scan']);
    expect(first.warnings).toEqual([{ kind: 'duplicate-baseline-name', name: 'gosec/gosec Scan', indices: [0, 1] }]);

    const again = merge([{ name: 'merged.json', doc: first.results }]);
    expect(names(again.results)).toEqual(['hdf-merge/gosec/gosec Scan', 'hdf-merge/gosec/gosec Scan']);
    expect(again.warnings.filter((w) => w.kind === 'duplicate-baseline-name')).toHaveLength(1);
    expect(again.warnings.filter((w) => w.kind === 'label-overwritten')).toHaveLength(6);
    expect(again.results.baselines[0].labels?.tool).toBe('hdf-merge');
    expect(again.results.baselines[0].labels?.sourceDocument).toBe('merged.json');
  });

  it('rejects an empty source list', () => {
    expect(() => merge([])).toThrow();
  });
});

// Rules the three-scanner happy path cannot distinguish (parity with the Go
// tests of the same names). Inputs that need a shape no committed real fixture
// has are DERIVED from a real fixture in-test — never fabricated.
describe('hdf-engine merge — rule coverage, parity with go/merge_test.go', () => {
  it('latest timestamp is not the first input', () => {
    const { results } = merge([
      { name: 'grype.hdf.json', doc: load('merge-grype.json') },
      { name: 'gosec.hdf.json', doc: load('merge-gosec.json') },
      { name: 'zap.hdf.json', doc: load('merge-zap.json') },
    ]);
    expect(results.timestamp).toBe('2026-07-12T22:56:36.173673Z');
    expect(results.baselines[0].name).toBe('grype/tensorflow/tensorflow:latest');
    expect(results.baselines[1].name).toBe('gosec/gosec Scan');
  });

  it('no timestamp on any input → omitted, not invented', () => {
    const g = load('merge-gosec.json');
    delete g.timestamp;
    const { results } = merge([{ name: 'g.json', doc: g }]);
    expect(results.timestamp).toBeUndefined();
    const ext = results.extensions?.['hdf-merge'] as { sources: Record<string, unknown>[] };
    expect(ext.sources[0]).not.toHaveProperty('timestamp');
  });

  it('prefix fallbacks: trimmed lower-case tool → generator → doc<N>', () => {
    const spaced = load('merge-gosec.json');
    spaced.tool = { ...spaced.tool, name: '  GoSec ' };
    const noTool = load('merge-gosec.json');
    delete noTool.tool;
    const bare = load('merge-gosec.json');
    delete bare.tool;
    delete bare.generator;
    const { results, warnings } = merge([
      { name: 'spaced.json', doc: spaced },
      { name: 'notool.json', doc: noTool },
      { name: 'bare.json', doc: bare },
    ]);
    expect(names(results)).toEqual(['gosec/gosec Scan', 'gosec-to-hdf/gosec Scan', 'doc2/gosec Scan']);
    expect(results.baselines[0].labels?.tool).toBe('gosec');
    expect(results.baselines[1].labels?.tool).toBe('gosec-to-hdf');
    expect(results.baselines[2].labels).toEqual({ tool: 'doc2', sourceDocument: 'bare.json' });
    expect(warnings).toEqual([]);
  });

  it('components sharing a componentId are kept once; those without one are all kept', () => {
    const id = '11111111-1111-4111-8111-111111111111';
    const a = load('merge-grype.json');
    a.components![0].componentId = id;
    const b = load('merge-grype.json');
    b.components![0].componentId = id;
    const { results } = merge([
      { name: 'a.json', doc: a },
      { name: 'b.json', doc: b },
      { name: 'zap.json', doc: load('merge-zap.json') },
    ]);
    expect(results.components).toHaveLength(5);
    expect(results.components![0].componentId).toBe(id);
    expect(results.components![1].componentId).toBeUndefined();
    expect(validateResults(results).valid).toBe(true);
  });

  it('re-merge replaces tool/sourceDocument, removes the stale toolVersion, and names each label', () => {
    const first = merge([{ name: 'zap.hdf.json', doc: load('merge-zap.json') }]).results;
    expect(first.baselines[0].labels?.toolVersion).toBe('2.7.0');
    const { results, warnings } = merge([{ name: 'merged.json', doc: first }]);
    for (const b of results.baselines) {
      expect(b.labels).not.toHaveProperty('toolVersion');
      expect(b.labels?.tool).toBe('hdf-merge');
      expect(b.labels?.sourceDocument).toBe('merged.json');
      expect(b.labels).toHaveProperty('component');
    }
    const byLabel: Record<string, number[]> = {};
    for (const w of warnings) {
      expect(w.kind).toBe('label-overwritten');
      (byLabel[w.label!] ??= []).push(w.indices[0]);
    }
    expect(byLabel).toEqual({ tool: [0, 1, 2, 3], toolVersion: [0, 1, 2, 3], sourceDocument: [0, 1, 2, 3] });
  });

  it('a single document is the identity apart from names, labels and the root; the input is not mutated', () => {
    const input = load('merge-zap.json');
    const { results, warnings } = merge([{ name: 'zap.hdf.json', doc: input }]);
    expect(warnings).toEqual([]);
    expect(results.baselines).toHaveLength(input.baselines.length);
    input.baselines.forEach((want, i) => {
      expect(withoutNameAndLabels(results.baselines[i])).toEqual(withoutNameAndLabels(want));
    });
    expect(results.components).toEqual(input.components);
    expect(input.baselines[0].name).toBe('OWASP ZAP Scan: ciscobinary.openh264.org');
    expect(input.baselines[0].labels).toEqual({ component: 'ciscobinary.openh264.org' });
  });

  it('the three-scanner merge validates against hdf-results (TS validators)', () => {
    const { results } = merge(threeScanners());
    const res = validateResults(results);
    expect(res.valid).toBe(true);
  });
});
