import { describe, it, expect } from 'vitest';
import type { HDFResults } from '@mitre/hdf-schema';
import {
  ContextualizedBaseline,
  ContextualizedRequirement,
  ExtensionGraph,
} from '../src/index.js';
import { makeRequirement, makeBaseline } from './helpers.js';

describe('ContextualizedBaseline', () => {
  it('wraps an EvaluatedBaseline with the original data accessible', () => {
    const baseline = makeBaseline({
      name: 'test-baseline',
      requirements: [makeRequirement({ id: 'REQ-1' })],
    });
    const results = { baselines: [baseline] } as HDFResults;

    const ctx = new ContextualizedBaseline(baseline, results);

    expect(ctx.data).toBe(baseline);
    expect(ctx.sourcedFrom).toBe(results);
    expect(ctx.data.name).toBe('test-baseline');
  });

  it('initializes with empty extension arrays', () => {
    const baseline = makeBaseline({
      name: 'test-baseline',
      requirements: [makeRequirement({ id: 'REQ-1' })],
    });
    const results = { baselines: [baseline] } as HDFResults;

    const ctx = new ContextualizedBaseline(baseline, results);

    expect(ctx.extendsFrom).toEqual([]);
    expect(ctx.extendedBy).toEqual([]);
  });

  it('provides access to wrapped requirements', () => {
    const req = makeRequirement({ id: 'REQ-1' });
    const baseline = makeBaseline({
      name: 'test-baseline',
      requirements: [req],
    });
    const results = { baselines: [baseline] } as HDFResults;

    const ctx = new ContextualizedBaseline(baseline, results);

    expect(ctx.requirements).toHaveLength(1);
    expect(ctx.requirements[0]).toBeInstanceOf(ContextualizedRequirement);
    expect(ctx.requirements[0]!.data).toBe(req);
  });
});

describe('ContextualizedRequirement', () => {
  it('wraps an EvaluatedRequirement with the original data accessible', () => {
    const req = makeRequirement({ id: 'REQ-1', code: 'describe ...' });
    const baseline = makeBaseline({ name: 'base', requirements: [req] });
    const results = { baselines: [baseline] } as HDFResults;
    const ctxBaseline = new ContextualizedBaseline(baseline, results);

    const ctxReq = ctxBaseline.requirements[0]!;

    expect(ctxReq.data).toBe(req);
    expect(ctxReq.sourcedFrom).toBe(ctxBaseline);
    expect(ctxReq.data.id).toBe('REQ-1');
  });

  it('initializes with empty extension arrays', () => {
    const req = makeRequirement({ id: 'REQ-1' });
    const baseline = makeBaseline({ name: 'base', requirements: [req] });
    const results = { baselines: [baseline] } as HDFResults;
    const ctxBaseline = new ContextualizedBaseline(baseline, results);

    const ctxReq = ctxBaseline.requirements[0]!;

    expect(ctxReq.extendsFrom).toEqual([]);
    expect(ctxReq.extendedBy).toEqual([]);
  });
});

describe('ExtensionGraph', () => {
  it('constructs with baselines and requirements arrays', () => {
    const graph = new ExtensionGraph([], []);

    expect(graph.baselines).toEqual([]);
    expect(graph.requirements).toEqual([]);
  });

  it('holds contextualized baselines and requirements', () => {
    const req = makeRequirement({ id: 'REQ-1' });
    const baseline = makeBaseline({ name: 'base', requirements: [req] });
    const results = { baselines: [baseline] } as HDFResults;
    const ctxBaseline = new ContextualizedBaseline(baseline, results);
    const ctxReq = ctxBaseline.requirements[0]!;

    const graph = new ExtensionGraph([ctxBaseline], [ctxReq]);

    expect(graph.baselines).toHaveLength(1);
    expect(graph.requirements).toHaveLength(1);
    expect(graph.baselines[0]!.data.name).toBe('base');
    expect(graph.requirements[0]!.data.id).toBe('REQ-1');
  });

  it('finds baselines by name', () => {
    const b1 = makeBaseline({ name: 'alpha', requirements: [] });
    const b2 = makeBaseline({ name: 'beta', requirements: [] });
    const results = { baselines: [b1, b2] } as HDFResults;
    const ctx1 = new ContextualizedBaseline(b1, results);
    const ctx2 = new ContextualizedBaseline(b2, results);

    const graph = new ExtensionGraph([ctx1, ctx2], []);

    expect(graph.findBaseline('alpha')).toBe(ctx1);
    expect(graph.findBaseline('beta')).toBe(ctx2);
    expect(graph.findBaseline('gamma')).toBeUndefined();
  });

  it('finds requirements by id', () => {
    const r1 = makeRequirement({ id: 'SV-001' });
    const r2 = makeRequirement({ id: 'SV-002' });
    const baseline = makeBaseline({ name: 'base', requirements: [r1, r2] });
    const results = { baselines: [baseline] } as HDFResults;
    const ctxBaseline = new ContextualizedBaseline(baseline, results);

    const graph = new ExtensionGraph([ctxBaseline], ctxBaseline.requirements);

    const found = graph.findRequirements('SV-001');
    expect(found).toHaveLength(1);
    expect(found[0]!.data.id).toBe('SV-001');

    expect(graph.findRequirements('SV-999')).toEqual([]);
  });

  it('returns root baselines (those with no parent)', () => {
    const b1 = makeBaseline({ name: 'root-baseline', requirements: [] });
    const b2 = makeBaseline({ name: 'overlay', requirements: [], parentBaseline: 'root-baseline' });
    const results = { baselines: [b1, b2] } as HDFResults;
    const ctx1 = new ContextualizedBaseline(b1, results);
    const ctx2 = new ContextualizedBaseline(b2, results);

    const graph = new ExtensionGraph([ctx1, ctx2], []);

    const roots = graph.rootBaselines;
    expect(roots).toHaveLength(1);
    expect(roots[0]!.data.name).toBe('root-baseline');
  });
});
