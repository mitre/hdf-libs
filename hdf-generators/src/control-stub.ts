import type { BaselineRequirement } from '@mitre/hdf-schema';
import { escapeQuotes } from './ruby-escape.js';

/**
 * Detects when a code string already starts with `control 'ID' do`,
 * meaning it's a complete InSpec control file — not a body fragment.
 */
const FULL_CONTROL_BLOCK = /^\s*control\s+['"]([^'"]+)['"]\s+do\b/;

/**
 * Generate a Ruby InSpec control stub from an HDF BaselineRequirement.
 *
 * Output follows the InSpec DSL ordering convention:
 *   control 'ID' do
 *     title ...
 *     desc ...
 *     desc 'check', ...
 *     impact ...
 *     tag key: value
 *     <code or stub comment>
 *   end
 */
export function generateControlStub(req: BaselineRequirement): string {
  // If code is already a complete `control 'ID' do ... end` block (e.g.
  // from `-c controls/` reading whole .rb files), emit it as-is — wrapping
  // it again would produce nested control blocks, which InSpec rejects.
  // When the inner ID differs from req.id (e.g. an upgrade rename match
  // where current's code was carried into a renamed requirement), rewrite
  // the wrapper to match req.id so the file remains valid InSpec.
  if (req.code) {
    const m = FULL_CONTROL_BLOCK.exec(req.code);
    if (m && m[1] !== undefined) {
      const innerID = m[1];
      if (innerID === req.id) {
        return req.code;
      }
      const start = m.index + m[0].indexOf(innerID);
      return req.code.slice(0, start) + req.id + req.code.slice(start + innerID.length);
    }
  }

  const lines: string[] = [];

  lines.push(`control '${req.id}' do`);

  // Title
  if (req.title) {
    lines.push(`  title ${escapeQuotes(req.title)}`);
  }

  // Descriptions: default first (as bare `desc`), then labeled
  const defaultDesc = req.descriptions.find((d) => d.label === 'default');
  if (defaultDesc) {
    lines.push(`  desc ${escapeQuotes(defaultDesc.data)}`);
  }

  const seenDefault = new Set<string>();
  for (const d of req.descriptions) {
    if (d.label === 'default') {
      if (seenDefault.has('default')) {
        continue; // skip duplicate default
      }
      seenDefault.add('default');
      continue; // already emitted above as bare desc
    }
    lines.push(`  desc '${d.label}', ${escapeQuotes(d.data)}`);
  }

  // Impact — always render with at least one decimal place for 0 and whole numbers
  if (req.impact !== undefined) {
    const impactStr = Number.isInteger(req.impact)
      ? req.impact.toFixed(1)
      : String(req.impact);
    lines.push(`  impact ${impactStr}`);
  }

  // Tags
  for (const [key, value] of Object.entries(req.tags)) {
    lines.push(`  ${formatTag(key, value)}`);
  }

  // Code body or stub placeholder
  if (req.code) {
    lines.push('');
    lines.push(req.code);
  } else {
    lines.push('');
    lines.push('  # TODO: Add InSpec test code here');
  }

  lines.push('end');
  lines.push(''); // trailing newline

  return lines.join('\n');
}

/** Format a single tag key-value pair as Ruby DSL. */
function formatTag(key: string, value: unknown): string {
  if (value === null || value === undefined) {
    return `tag ${key}: nil`;
  }

  if (Array.isArray(value)) {
    // Ruby array syntax: tag key: ['val1', 'val2']
    const items = value.map((v: unknown) => `'${String(v)}'`).join(', ');
    return `tag ${key}: [${items}]`;
  }

  if (typeof value === 'boolean') {
    return `tag ${key}: ${value}`;
  }

  if (typeof value === 'string') {
    return `tag ${key}: ${escapeQuotes(value)}`;
  }

  // Fallback for other types (numbers, objects)
  return `tag ${key}: ${JSON.stringify(value)}`;
}
