import { describe, it, expect, beforeAll } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { diffHdf } from '../../src/diff.js';
import { render } from '../../src/renderers/index.js';
import { renderJson } from '../../src/renderers/json.js';
import { renderMarkdown } from '../../src/renderers/markdown.js';
import { renderTerminal } from '../../src/renderers/terminal.js';
import { renderCsv } from '../../src/renderers/csv.js';
import type { HDFComparison } from '../../src/types.js';

const __dirname = dirname(fileURLToPath(import.meta.url));

function loadFixture(name: string): Record<string, unknown> {
  const filePath = resolve(__dirname, '..', 'fixtures', name);
  return JSON.parse(readFileSync(filePath, 'utf-8')) as Record<string, unknown>;
}

describe('render (dispatch function)', () => {
  let comparison: HDFComparison;

  beforeAll(() => {
    const scanBefore = loadFixture('scan-before.json');
    const scanAfter = loadFixture('scan-after.json');
    comparison = diffHdf(scanBefore, scanAfter);
  });

  it('should dispatch to renderJson for format "json"', () => {
    const fromRender = render(comparison, 'json');
    const fromDirect = renderJson(comparison);
    expect(fromRender).toBe(fromDirect);
  });

  it('should dispatch to renderMarkdown for format "markdown"', () => {
    const fromRender = render(comparison, 'markdown');
    const fromDirect = renderMarkdown(comparison);
    expect(fromRender).toBe(fromDirect);
  });

  it('should dispatch to renderTerminal for format "terminal"', () => {
    const opts = { color: false } as const;
    const fromRender = render(comparison, 'terminal', opts);
    const fromDirect = renderTerminal(comparison, opts);
    expect(fromRender).toBe(fromDirect);
  });

  it('should dispatch to renderCsv for format "csv"', () => {
    const fromRender = render(comparison, 'csv');
    const fromDirect = renderCsv(comparison);
    expect(fromRender).toBe(fromDirect);
  });

  it('should pass options through to the underlying renderer', () => {
    const opts = { detail: 'summary' as const };
    const fromRender = render(comparison, 'json', opts);
    const fromDirect = renderJson(comparison, opts);
    expect(fromRender).toBe(fromDirect);
  });
});
