import { describe, expect, it } from 'vitest';
import { readFileSync } from 'fs';
import { join } from 'path';
import {
  loadBindings,
  bindingFaults,
  schemaFragments,
  unknownKeys,
  CLOSED_KEYS,
  FILESYSTEM_FIELDS,
  resourceNames,
} from '../src/bindings.js';

const HERE = new URL('.', import.meta.url).pathname;
const SRC = join(HERE, '..', 'src');
const contract = JSON.parse(readFileSync(join(SRC, 'mcp-contract.golden.json'), 'utf-8'));
const toolsList = JSON.parse(readFileSync(join(SRC, 'tools-list.golden.json'), 'utf-8'));

// The table is the one input that could quietly become the API itself, so these checks
// are the guarantee it stays a mapping. Each fault class is exercised BOTH ways — a
// fixture carrying the fault and one without — because a checker that always returns
// empty would satisfy a one-sided test.
describe('the no-fragment rule', () => {
  it.each(['type', 'properties', '$ref', 'oneOf', 'allOf'])('rejects a %s key anywhere', (key) => {
    const table = { tools: { hdf_query: { fields: { status: { [key]: 'string' } } } } };
    expect(schemaFragments(table)).toHaveLength(1);
  });

  it('rejects items when it is a schema rather than the scalar naming a field', () => {
    expect(schemaFragments({ tools: { t: { items: { type: 'string' } } } }).length).toBeGreaterThan(0);
  });

  it('accepts items as the scalar naming an output field', () => {
    expect(schemaFragments({ tools: { t: { items: 'requirements' } } })).toEqual([]);
  });

  it('passes a table that carries no schema', () => {
    const table = { tools: { hdf_open: { method: 'get', path: '/documents/{id}' } } };
    expect(schemaFragments(table)).toEqual([]);
  });
});

describe('the closed key set', () => {
  it('rejects a key outside the set', () => {
    expect(unknownKeys({ tools: { t: { method: 'get', summary: 'nope' } } })).toEqual([
      '/tools/t/summary',
    ]);
  });

  it('accepts tool, resource and field NAMES as data rather than keys', () => {
    const table = {
      tools: { anything_at_all: { method: 'get', fields: { whatever: { placement: 'query' } } } },
      resources: { some_resource: { method: 'get', path: '/catalog' } },
    };
    expect(unknownKeys(table)).toEqual([]);
  });

  it('names every key the grammar admits, so the set cannot silently shrink', () => {
    for (const key of ['method', 'path', 'placement', 'bodyRef', 'drop', 'fullResponse']) {
      expect(CLOSED_KEYS.has(key)).toBe(true);
    }
  });
});

describe('coverage faults against the live surface', () => {
  const surface = { toolsList, contract };

  it('has a non-trivial surface, so the checks below cannot pass vacuously', () => {
    expect(toolsList.tools.length).toBeGreaterThan(5);
    expect(Object.keys(contract.fullShapes).length).toBeGreaterThan(5);
  });

  it('faults a tool that is neither bound nor recorded absent', () => {
    const faults = bindingFaults({ tools: {} }, surface);
    expect(faults.some((f) => f.includes('not bound and not recorded absent'))).toBe(true);
    expect(faults.length).toBeGreaterThanOrEqual(toolsList.tools.length);
  });

  it('accepts a tool recorded absent WITH a reason, and faults one without', () => {
    const name = toolsList.tools[0].name;
    const withReason = bindingFaults(
      { tools: {}, absent: [{ tool: name, reason: 'covered by another route' }] },
      surface,
    );
    expect(withReason.some((f) => f.startsWith(`${name}: not bound`))).toBe(false);

    const without = bindingFaults({ tools: {}, absent: [{ tool: name } as never] }, surface);
    expect(without.some((f) => f.includes('carries no reason'))).toBe(true);
  });

  it('faults a filesystem-shaped field that is exposed instead of dropped', () => {
    // hdf_aggregate.sources is filesystem-shaped and required by the MCP.
    const faults = bindingFaults(
      { tools: { hdf_aggregate: { fields: { sources: { placement: 'query' } } } } },
      surface,
    );
    expect(faults.some((f) => f === 'hdf_aggregate.sources: filesystem-shaped and must be dropped, not exposed')).toBe(true);
  });

  it('faults a drop with no reason', () => {
    const faults = bindingFaults(
      { tools: { hdf_open: { drop: [{ name: 'source' } as never] } } },
      surface,
    );
    expect(faults.some((f) => f === 'hdf_open: drops source with no reason')).toBe(true);
  });

  it('faults a hand-set class on a real tool, because it derives from readOnlyHint', () => {
    const faults = bindingFaults({ tools: { hdf_query: { class: 'read' } } }, surface);
    expect(faults).toContain('hdf_query: declares class, which must derive from readOnlyHint');
  });

  it('faults a fullResponse naming a shape the contract does not carry', () => {
    const faults = bindingFaults(
      { tools: { hdf_query: { fullResponse: 'query.invented' } } },
      surface,
    );
    expect(faults).toContain('hdf_query: fullResponse names query.invented, absent from the contract');
  });

  it('accepts a fullResponse that the contract does carry', () => {
    const real = Object.keys(contract.fullShapes)[0];
    const faults = bindingFaults({ tools: { hdf_query: { fullResponse: real } } }, surface);
    expect(faults.some((f) => f.includes('absent from the contract'))).toBe(false);
  });

  // The gate is only worth having if the fields it guards are the ones the MCP actually
  // exposes, so the list is checked against the live surface rather than trusted.
  it('every filesystem-shaped name it guards really appears in the MCP surface', () => {
    const live = new Set(
      toolsList.tools.flatMap((t: { inputSchema?: { properties?: object } }) =>
        Object.keys(t.inputSchema?.properties ?? {}),
      ),
    );
    const unused = [...FILESYSTEM_FIELDS].filter((f) => !live.has(f) && f !== 'path');
    expect(unused).toEqual([]);
  });
});

// The goldens in src/ are TRACKED copies of hdf-cli's, because this package's generator
// must run from the published tarball and cannot reach hdf-cli's internal testdata. That
// makes drift possible, so it is checked here rather than trusted: --check reports any
// copy that differs without writing.
describe('the synced contract goldens', () => {
  it('match hdf-cli, so the tracked copies cannot go stale silently', async () => {
    const { syncGoldens } = await import('../scripts/sync-mcp-golden.mjs');
    expect(syncGoldens({ check: true })).toEqual([]);
  });
});

// Resources are half of the coverage AC and were initially unchecked — the package's own
// coverage gate is what surfaced that, which is the argument for the gate.
describe('resource coverage', () => {
  const surface = { toolsList, contract };

  it('reads both the concrete resources and the templates, through the golden nesting', () => {
    const names = resourceNames(contract);
    expect(names).toContain('hdf-converter-catalog');
    expect(names).toContain('hdf-enum');
    expect(names).toContain('hdf-session-transcript');
    expect(names.length).toBeGreaterThan(20);
  });

  it('faults a resource that is neither bound nor recorded absent', () => {
    const faults = bindingFaults({ tools: {}, resources: {} }, surface);
    expect(faults).toContain('hdf-converter-catalog: resource not bound and not recorded absent');
  });

  it('accepts a resource recorded absent with a reason — the session transcript is the ADR case', () => {
    const faults = bindingFaults(
      { tools: {}, absent: [{ resource: 'hdf-session-transcript', reason: 'MCP-only; no HTTP analogue' }] },
      surface,
    );
    expect(faults.some((f) => f.startsWith('hdf-session-transcript:'))).toBe(false);
  });

  it('accepts a bound resource', () => {
    const faults = bindingFaults(
      { tools: {}, resources: { 'hdf-converter-catalog': { method: 'get', path: '/catalog/converters' } } },
      surface,
    );
    expect(faults.some((f) => f.startsWith('hdf-converter-catalog:'))).toBe(false);
  });
});

describe('loading', () => {
  it('refuses a file that does not parse to a mapping, rather than returning a shell', () => {
    expect(() => loadBindings('- just\n- a list\n')).toThrow(/did not parse to a mapping/);
    expect(() => loadBindings('')).toThrow(/did not parse to a mapping/);
  });

  it('parses a conformant table', () => {
    const table = loadBindings('tools:\n  hdf_open:\n    method: get\n    path: /documents/{id}\n');
    expect(table.tools?.hdf_open?.method).toBe('get');
  });

  // Arrays appear in `drop` and `absent`, so both walkers must descend into them.
  it('walks into arrays, where drop and absent entries live', () => {
    expect(schemaFragments({ absent: [{ reason: 'x', type: 'string' }] })).toEqual([
      '/absent/0/type',
    ]);
    expect(unknownKeys({ absent: [{ reason: 'x', bogus: 1 }] })).toEqual(['/absent/0/bogus']);
  });
});
