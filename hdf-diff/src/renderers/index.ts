export { renderJson } from './json.js';
export { renderMarkdown } from './markdown.js';
export { renderTerminal } from './terminal.js';
export { renderCsv } from './csv.js';
export type { DetailLevel, RenderOptions } from './types.js';

import type { HDFComparison } from '../types.js';
import type { RenderOptions } from './types.js';
import { renderJson } from './json.js';
import { renderMarkdown } from './markdown.js';
import { renderTerminal } from './terminal.js';
import { renderCsv } from './csv.js';

/**
 * Convenience function to render a comparison in any supported format.
 *
 * @param comparison - The HDFComparison document to render
 * @param format - Output format: 'json', 'markdown', 'terminal', or 'csv'
 * @param options - Rendering options (detail level, filters, color)
 * @returns The rendered string
 */
export function render(
  comparison: HDFComparison,
  format: 'json' | 'markdown' | 'terminal' | 'csv',
  options?: RenderOptions,
): string {
  switch (format) {
    case 'json':
      return renderJson(comparison, options);
    case 'markdown':
      return renderMarkdown(comparison, options);
    case 'terminal':
      return renderTerminal(comparison, options);
    case 'csv':
      return renderCsv(comparison, options);
  }
}
