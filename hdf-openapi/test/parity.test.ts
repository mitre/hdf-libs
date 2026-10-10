import { readFileSync } from 'fs';
import { join } from 'path';
import { describe, expect, it } from 'vitest';
import { loadBindings } from '../src/bindings.js';
import { generateApiDocument } from '../src/generate-api.js';
import { parityFindings, type ParityInput } from '../src/parity.js';

const SRC = join(new URL('.', import.meta.url).pathname, '..', 'src');
const read = (name: string): unknown => JSON.parse(readFileSync(join(SRC, name), 'utf-8'));

const baseline = (): ParityInput => ({
  toolsList: read('tools-list.golden.json') as ParityInput['toolsList'],
  contract: read('mcp-contract.golden.json') as ParityInput['contract'],
  table: loadBindings(readFileSync(join(SRC, 'bindings.yaml'), 'utf-8')),
  doc: generateApiDocument(),
});

/** Deep clone so a plant cannot leak into the next case. */
const clone = <T>(value: T): T => JSON.parse(JSON.stringify(value)) as T;

// Parity is the gate that turns MCP/HTTP drift from a discovery into a test failure. Its
// only credible evidence is that each drift class actually trips it, so every case here
// plants one and asserts the KIND reported — a check that fires on everything is as
// useless as one that fires on nothing.
describe('parity holds on the tracked contract', () => {
  it('reports nothing on the real golden, table and document', () => {
    expect(parityFindings(baseline())).toEqual([]);
  });
});

describe('parity fails on each of the eight drift classes', () => {
  it('1. an unbound tool', () => {
    const input = baseline();
    input.toolsList = clone(input.toolsList);
    input.toolsList.tools.push({
      name: 'hdf_teleport',
      description: 'a tool the table has never heard of',
      inputSchema: { type: 'object', properties: {} },
      annotations: { readOnlyHint: true },
    });
    const findings = parityFindings(input);
    expect(findings.map((f) => f.kind)).toContain('unbound-tool');
    expect(findings.filter((f) => f.kind === 'unbound-tool').map((f) => f.subject)).toEqual([
      'hdf_teleport',
    ]);
  });

  it('2. a stale binding, naming a tool the MCP no longer serves', () => {
    const input = baseline();
    input.toolsList = clone(input.toolsList);
    input.toolsList.tools = input.toolsList.tools.filter((t) => t.name !== 'hdf_query');
    const findings = parityFindings(input);
    expect(findings.map((f) => f.kind)).toContain('stale-binding');
    expect(findings.find((f) => f.kind === 'stale-binding')?.subject).toBe('hdf_query');
  });

  it('3. a parameter the MCP gained and the table never placed', () => {
    const input = baseline();
    input.toolsList = clone(input.toolsList);
    const query = input.toolsList.tools.find((t) => t.name === 'hdf_query')!;
    query.inputSchema.properties!.sortOrder = { type: 'string' };
    const findings = parityFindings(input);
    expect(findings.map((f) => f.kind)).toContain('parameter');
    expect(findings.filter((f) => f.kind === 'parameter').map((f) => f.subject)).toEqual([
      'hdf_query.sortOrder',
    ]);
  });

  it('4. an enum whose values moved under a placed parameter', () => {
    const input = baseline();
    input.toolsList = clone(input.toolsList);
    const query = input.toolsList.tools.find((t) => t.name === 'hdf_query')!;
    // hdf_query.status is an ARRAY of enum values, so the vocabulary lives on `items`.
    const status = query.inputSchema.properties!.status as { items?: { enum?: unknown[] } };
    expect(status.items?.enum, 'hdf_query.status must carry an enum for this plant to mean anything')
      .toBeDefined();
    status.items!.enum = [...status.items!.enum!, 'teleported'];
    const findings = parityFindings(input);
    expect(findings.map((f) => f.kind)).toContain('enum');
    expect(findings.filter((f) => f.kind === 'enum').map((f) => f.subject)).toEqual([
      'hdf_query.status',
    ]);
  });

  it('5. a resource the MCP serves and the table does not bind', () => {
    const input = baseline();
    input.contract = clone(input.contract);
    input.contract.resources.resources.push({
      name: 'hdf-teleport-catalog',
      uri: 'hdf://catalog/teleports',
      mimeType: 'application/json',
      description: 'unbound',
    });
    const findings = parityFindings(input);
    expect(findings.map((f) => f.kind)).toContain('resource');
    expect(findings.filter((f) => f.kind === 'resource').map((f) => f.subject)).toEqual([
      'hdf-teleport-catalog',
    ]);
  });

  it('6. an error code the MCP can emit and the table maps nowhere', () => {
    const input = baseline();
    input.contract = clone(input.contract);
    input.contract.errorCodes.push('TELEPORT_FAILED');
    const findings = parityFindings(input);
    expect(findings.map((f) => f.kind)).toContain('error-code');
    expect(findings.filter((f) => f.kind === 'error-code').map((f) => f.subject)).toEqual([
      'TELEPORT_FAILED',
    ]);
  });

  it('7. a fullShapes field the document does not carry', () => {
    const input = baseline();
    input.contract = clone(input.contract);
    const shape = input.contract.fullShapes['query.full'] as {
      properties: Record<string, unknown>;
    };
    shape.properties.teleportedAt = { type: 'string' };
    const findings = parityFindings(input);
    expect(findings.map((f) => f.kind)).toContain('full-shape-field');
    expect(findings.filter((f) => f.kind === 'full-shape-field').map((f) => f.subject)).toEqual([
      'query.full.teleportedAt',
    ]);
  });

  it('8. a readOnlyHint flip, which changes the method the operation must use', () => {
    const input = baseline();
    input.toolsList = clone(input.toolsList);
    const query = input.toolsList.tools.find((t) => t.name === 'hdf_query')!;
    expect(query.annotations?.readOnlyHint, 'hdf_query must be read-only upstream').toBe(true);
    query.annotations!.readOnlyHint = false;
    const findings = parityFindings(input);
    expect(findings.map((f) => f.kind)).toContain('read-only-hint');
    expect(findings.filter((f) => f.kind === 'read-only-hint').map((f) => f.subject)).toEqual([
      'hdf_query',
    ]);
  });
});

// A finding carries the name of the thing that drifted, because the failure message is the
// whole value of a drift gate — "parity failed" sends the reader back to the diff.
describe('a finding says what drifted', () => {
  it('names its subject and gives a detail for every kind it can report', () => {
    const input = baseline();
    input.toolsList = clone(input.toolsList);
    input.toolsList.tools.push({
      name: 'hdf_teleport',
      description: 'unbound',
      inputSchema: { type: 'object', properties: {} },
      annotations: { readOnlyHint: true },
    });
    const findings = parityFindings(input);
    expect(findings.length).toBeGreaterThan(0);
    for (const finding of findings) {
      expect(finding.subject.length).toBeGreaterThan(0);
      expect(finding.detail.length).toBeGreaterThan(10);
    }
  });
});

// The eight classes above plant drift in the GOLDEN. Each class also has a path where the
// drift is on the document's side — the table places a field and the document does not
// carry it — and those reports were written but unexercised, which is how a drift gate
// ends up with branches that have never once fired.
describe('parity reports drift that sits on the document side', () => {
  it('a field the table both places and drops', () => {
    const input = baseline();
    input.table = clone(input.table);
    const query = input.table.tools!.hdf_query!;
    query.drop = [...(query.drop ?? []), { name: 'status', reason: 'planted' }];
    const findings = parityFindings(input);
    expect(findings.map((f) => f.kind)).toContain('parameter');
    expect(findings.find((f) => f.subject === 'hdf_query.status')?.detail).toMatch(
      /both placed in query and dropped/,
    );
  });

  it('a query parameter the table placed and the document does not declare', () => {
    const input = baseline();
    input.doc = clone(input.doc);
    const op = input.doc.paths['/documents/{id}/requirements']!.get!;
    op.parameters = (op.parameters as { name: string }[]).filter((p) => p.name !== 'severity');
    const findings = parityFindings(input);
    expect(findings.map((f) => f.kind)).toContain('parameter');
    expect(findings.find((f) => f.subject.endsWith('.severity'))?.detail).toMatch(
      /absent from get/,
    );
  });

  it('a body property the table placed and the document does not declare', () => {
    const input = baseline();
    input.doc = clone(input.doc);
    const body = input.doc.paths['/validations']!.post!.requestBody as {
      content: Record<string, { schema: { properties: Record<string, unknown> } }>;
    };
    delete body.content['application/json']!.schema.properties.content;
    const findings = parityFindings(input);
    expect(findings.map((f) => f.kind)).toContain('parameter');
    expect(findings.find((f) => f.subject === 'hdf_validate.content')?.detail).toMatch(
      /absent from the emitted body/,
    );
  });

  it('a resource binding the MCP no longer serves', () => {
    const input = baseline();
    input.contract = clone(input.contract);
    input.contract.resources.resources = input.contract.resources.resources.filter(
      (r) => r.name !== 'hdf-converter-catalog',
    );
    const findings = parityFindings(input);
    const stale = findings.filter((f) => f.kind === 'stale-binding');
    expect(stale.map((f) => f.subject)).toContain('hdf-converter-catalog');
  });

  it('a fullShapes component the document never emitted', () => {
    const input = baseline();
    input.doc = clone(input.doc);
    delete input.doc.components.schemas['query.full'];
    const findings = parityFindings(input);
    expect(findings.find((f) => f.subject === 'query.full')?.detail).toMatch(
      /no component for it/,
    );
  });

  // The generator hard-fails before this can happen on the real table, so the skip exists
  // only so parity does not double-report what the build already refused.
  it('skips a filesystem field rather than reporting it twice', () => {
    const input = baseline();
    input.table = clone(input.table);
    input.table.tools!.hdf_query!.fields!.path = { placement: 'query' };
    const subjects = parityFindings(input).map((f) => f.subject);
    expect(subjects).not.toContain('hdf_query.path');
  });
});
