import type { BaselineRequirement } from '@mitre/hdf-schema';
import { escapeQuotes } from './ruby-escape.js';

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
