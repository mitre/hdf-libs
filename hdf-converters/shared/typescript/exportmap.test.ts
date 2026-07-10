import { describe, it, expect } from 'vitest';
import {
  asMap,
  asArr,
  getStr,
  setIf,
  stringSlice,
  worstOfResults,
  statusOf,
  isFailing,
  firstComponent,
  firstResultStartTime,
  defaultDescription,
  firstRefURL,
  eventID,
  canonicalize,
  stringifyLine,
  runExport,
  firstCVE,
  epochSeconds,
  epochMillis,
} from './exportmap.js';

function mkResults(...statuses: string[]): Record<string, unknown> {
  return { results: statuses.map((s) => ({ status: s })) };
}

describe('exportmap status roll-up', () => {
  it('worstOfResults picks the most-significant status', () => {
    expect(worstOfResults(mkResults('passed', 'failed'))).toBe('failed');
    expect(worstOfResults(mkResults('passed', 'passed'))).toBe('passed');
    expect(worstOfResults(mkResults('error', 'passed'))).toBe('error');
    expect(worstOfResults(mkResults('notApplicable'))).toBe('notApplicable');
    expect(worstOfResults(mkResults())).toBe('notReviewed');
  });

  it('statusOf resolves rollup + overridden + suppressed', () => {
    let st = statusOf(mkResults('failed'));
    expect(st).toEqual({ raw: 'failed', effective: '', rollup: 'failed', overridden: false, suppressed: false });

    st = statusOf({ ...mkResults('failed'), effectiveStatus: 'passed' });
    expect(st.raw).toBe('failed'); // lossless roll-up preserved
    expect(st.effective).toBe('passed');
    expect(st.rollup).toBe('passed');
    expect(st.overridden).toBe(true);
    expect(st.suppressed).toBe(true); // raw-failing driven non-failing

    // override present but no effective status: not suppressed (conservative)
    st = statusOf({ ...mkResults('failed'), statusOverrides: [{ type: 'waiver' }] });
    expect(st.overridden).toBe(true);
    expect(st.rollup).toBe('failed');
    expect(st.suppressed).toBe(false);
  });

  it('suppressed axis: waiver/FP suppress, riskAdjustment stays actionable', () => {
    for (const eff of ['passed', 'notApplicable']) {
      expect(statusOf({ ...mkResults('failed'), effectiveStatus: eff }).suppressed).toBe(true);
    }
    // riskAdjustment: effectiveStatus stays failed → still actionable
    const ra = statusOf({
      ...mkResults('failed'),
      effectiveStatus: 'failed',
      statusOverrides: [{ type: 'riskAdjustment', impact: { value: 0.2 } }],
    });
    expect(ra.overridden).toBe(true);
    expect(ra.suppressed).toBe(false);
    // passing / errored findings are never suppressed
    expect(statusOf({ ...mkResults('passed'), effectiveStatus: 'passed' }).suppressed).toBe(false);
    expect(statusOf({ ...mkResults('error'), effectiveStatus: 'passed' }).suppressed).toBe(false);
    expect(isFailing('failed')).toBe(true);
    expect(isFailing('error')).toBe(false);
    expect(isFailing('passed')).toBe(false);
  });
});

describe('exportmap generic access', () => {
  it('asMap / asArr distinguish shapes', () => {
    expect(asMap({ a: 1 })).toEqual({ a: 1 });
    expect(asMap([1])).toBeUndefined();
    expect(asArr([1, 2])).toHaveLength(2);
    expect(asArr({})).toBeUndefined();
  });

  it('getStr returns "" for non-string / missing / undefined map', () => {
    expect(getStr({ a: 'x' }, 'a')).toBe('x');
    expect(getStr({ a: 1 }, 'a')).toBe('');
    expect(getStr(undefined, 'a')).toBe('');
  });

  it('setIf skips empty values', () => {
    const m: Record<string, unknown> = {};
    setIf(m, 'keep', 'v');
    setIf(m, 'drop', '');
    expect(m).toEqual({ keep: 'v' });
  });

  it('stringSlice coerces string or string[]', () => {
    expect(stringSlice('x')).toEqual(['x']);
    expect(stringSlice(['a', 1, 'b'])).toEqual(['a', 'b']);
    expect(stringSlice(42)).toEqual([]);
  });
});

describe('exportmap extraction', () => {
  it('pulls first component / start time / default description / ref url', () => {
    const doc = { components: [{ name: 'web' }] };
    expect(getStr(firstComponent(doc), 'name')).toBe('web');
    expect(firstComponent({})).toBeUndefined();

    const req = {
      results: [{ startTime: '2024-01-01T00:00:00Z' }],
      descriptions: [{ label: 'default', data: 'desc' }],
      refs: [{ url: 'https://x' }],
    };
    expect(firstResultStartTime(req, 'fb')).toBe('2024-01-01T00:00:00Z');
    expect(firstResultStartTime({}, 'fb')).toBe('fb');
    expect(defaultDescription(req)).toBe('desc');
    expect(firstRefURL(req)).toBe('https://x');
  });

  it('eventID joins component | baseline | control', () => {
    expect(eventID({ componentId: 'c1' }, 'base', 'V-1')).toBe('c1|base|V-1');
    expect(eventID(undefined, 'base', 'V-1')).toBe('|base|V-1');
  });
});

describe('exportmap canonical serialization', () => {
  it('canonicalize sorts keys deeply and stringifyLine leaves & unescaped', () => {
    const out = stringifyLine(canonicalize({ b: 1, a: { d: 2, c: 'x&y' } }));
    expect(out).toBe('{"a":{"c":"x&y","d":2},"b":1}');
  });
});

describe('exportmap shared driver + helpers', () => {
  it('runExport fans out one canonical line per requirement, in order', () => {
    const input = JSON.stringify({
      timestamp: '2024-01-01T00:00:00Z',
      baselines: [
        { name: 'b1', requirements: [{ id: 'A' }, { id: 'B' }] },
        { name: 'b2', requirements: [{ id: 'C' }] },
      ],
    });
    const out = runExport(input, 'test-exporter', (req, baseline, docTimestamp) => ({
      id: getStr(req, 'id'),
      baseline: getStr(baseline, 'name'),
      ts: docTimestamp,
    }));
    expect(out).toBe(
      '{"baseline":"b1","id":"A","ts":"2024-01-01T00:00:00Z"}\n' +
        '{"baseline":"b1","id":"B","ts":"2024-01-01T00:00:00Z"}\n' +
        '{"baseline":"b2","id":"C","ts":"2024-01-01T00:00:00Z"}\n',
    );
  });

  it('runExport threads doc-level context to the builder', () => {
    let seen = false;
    runExport(
      JSON.stringify({ tool: { name: 't' }, components: [{ name: 'h' }], baselines: [{ requirements: [{ id: 'X' }] }] }),
      'x',
      (_req, _baseline, _ts, tool, _generator, component) => {
        expect(getStr(tool, 'name')).toBe('t');
        expect(getStr(component, 'name')).toBe('h');
        seen = true;
        return {};
      },
    );
    expect(seen).toBe(true);
  });

  it('runExport throws on invalid/structureless input and returns "" for empty baselines', () => {
    const noop = () => ({});
    expect(() => runExport('', 'x', noop)).toThrow();
    expect(() => runExport('not json', 'x', noop)).toThrow();
    expect(() => runExport('{"foo":1}', 'x', noop)).toThrow(/missing baselines/);
    expect(runExport('{"baselines":[]}', 'x', noop)).toBe('');
  });

  it('firstCVE finds the first CVE-prefixed source (case-insensitive)', () => {
    expect(firstCVE([{ source: 'GHSA-xxxx' }, { source: 'cve-2024-1234' }])).toBe('cve-2024-1234');
    expect(firstCVE([{ source: 'NOTCVE' }])).toBe('');
    expect(firstCVE([])).toBe('');
  });

  it('epoch helpers scale the canonical parse, undefined when unparseable', () => {
    expect(epochSeconds('2024-01-01T00:00:00Z')).toBe(1704067200);
    expect(epochSeconds('')).toBeUndefined();
    expect(epochMillis('2024-01-01T00:00:00Z')).toBe(1704067200000);
    expect(epochMillis('')).toBeUndefined();
  });
});
