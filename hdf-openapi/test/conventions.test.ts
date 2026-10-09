import { describe, expect, it } from 'vitest';
import { mkdtempSync, readFileSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { loadConventions, componentName } from '../src/conventions.js';
import { validateExample } from '../src/validate-example.js';
import { loadBindings, bindingFaults } from '../src/bindings.js';

const HERE = new URL('.', import.meta.url).pathname;
const SRC = join(HERE, '..', 'src');
const components = JSON.parse(
  readFileSync(join(SRC, '..', 'dist', 'hdf-components.oas.json'), 'utf-8'),
) as { components: { schemas: Record<string, unknown> } };
const conventions = loadConventions();

// These are the only hand-authored shapes the document admits, so the conditions ADR-0008
// §2 attaches to that privilege are enforced rather than trusted.
describe('the conventions components', () => {
  it('there are some to check, so the checks below cannot pass vacuously', () => {
    expect(conventions.length).toBeGreaterThan(3);
  });

  it.each(conventions.map((c) => [c.file, c] as const))('%s declares 2020-12', (_f, c) => {
    expect(c.schema.$schema).toBe('https://json-schema.org/draft/2020-12/schema');
  });

  // An example a consumer copies is the first thing they run, so it is validated against
  // the schema it illustrates rather than merely present.
  // Through the exported helper rather than a private copy of the ajv setup: the check the
  // suite runs and the one a consumer can run must be the same code.
  it.each(conventions.map((c) => [c.file, c] as const))('%s has a valid example', (_f, c) => {
    const examples = c.schema.examples as unknown[] | undefined;
    expect(Array.isArray(examples) && examples.length > 0).toBe(true);
    const faults = validateExample(c.schema, components.components.schemas);
    expect(faults, `${c.file}: ${JSON.stringify(faults)}`).toEqual([]);
  });

  // The privilege is to author shapes the generator has no source for — NOT to restate a
  // document type, which would create a second definition free to drift from the schema.
  it('none redefines an HDF document type', () => {
    const roots = Object.keys(components.components.schemas).filter((n) => n.startsWith('Hdf'));
    expect(roots.length).toBe(8);
    const offenders = conventions.filter((c) => roots.includes(c.name));
    expect(offenders.map((c) => c.file)).toEqual([]);
  });

  // The ingest request is allowed to REFERENCE the roots; that is how a schema change
  // reaches it without an edit here.
  it('the ingest request references all eight roots rather than restating one', () => {
    const ingest = conventions.find((c) => c.name === 'IngestRequest');
    expect(ingest).toBeDefined();
    const refs = (JSON.stringify(ingest!.schema).match(/#\/components\/schemas\/Hdf\w+/g) ?? [])
      .map((r) => r.split('/').pop());
    expect(new Set(refs).size).toBe(8);
  });

  it('derives a component name the table can reference', () => {
    expect(componentName('Token Request')).toBe('TokenRequest');
    // An acronym keeps its case, which is why the table references APIKeyExchangeRequest.
    expect(componentName('API Key Exchange Request')).toBe('APIKeyExchangeRequest');
    // A title that reduces to no words yields '' rather than throwing on an index read.
    expect(componentName('---')).toBe('');
  });
});

describe('the synthetic operations', () => {
  const table = loadBindings(readFileSync(join(SRC, 'bindings.yaml'), 'utf-8'));
  const toolsList = JSON.parse(readFileSync(join(SRC, 'tools-list.golden.json'), 'utf-8'));
  const contract = JSON.parse(readFileSync(join(SRC, 'mcp-contract.golden.json'), 'utf-8'));
  const names = conventions.map((c) => c.name);
  const surface = { toolsList, contract, conventions: names };

  it('every shape they name resolves to a reflected shape or a conventions component', () => {
    expect(bindingFaults(table, surface)).toEqual([]);
  });

  it('faults a name that resolves to neither', () => {
    const broken = { ...table, synthetic: { ingest: { class: 'write', scopes: [], bodyRef: 'Invented' } } };
    expect(bindingFaults(broken, surface).some((f) => f.includes('neither a reflected shape'))).toBe(true);
  });

  it('faults a synthetic operation with no hand-set class or scopes', () => {
    const faults = bindingFaults({ ...table, synthetic: { ingest: {} } }, surface);
    expect(faults).toContain('synthetic ingest: no class, which is hand-set here');
    expect(faults).toContain('synthetic ingest: no scopes, which are hand-set here');
  });

  it('the four operations ADR-0008 §2 names are all present', () => {
    expect(Object.keys(table.synthetic ?? {}).sort()).toEqual([
      'delete',
      'exchangeApiKey',
      'ingest',
      'issueToken',
    ]);
  });
});

// The component name is derived from the title, so a titleless file has no name the table
// could reference — it must fail loudly rather than load as an unnameable shape.
describe('loading', () => {
  it('refuses a component with no title', () => {
    const dir = mkdtempSync(join(tmpdir(), 'conventions-'));
    writeFileSync(join(dir, 'untitled.yaml'), 'type: object\n');
    expect(() => loadConventions(dir)).toThrow(/carries no title/);
  });

  it('ignores files that are not YAML components', () => {
    const dir = mkdtempSync(join(tmpdir(), 'conventions-'));
    writeFileSync(join(dir, 'README.md'), '# not a component\n');
    writeFileSync(join(dir, 'one.yaml'), 'title: One\ntype: object\n');
    expect(loadConventions(dir).map((c) => c.name)).toEqual(['One']);
  });
});
