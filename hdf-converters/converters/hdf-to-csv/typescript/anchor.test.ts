import { describe, it, expect } from 'vitest';
import { results } from '@mitre/hdf-fixtures';
import { countHdfResultRequirements } from '../../../shared/typescript/anchor.js';
import { convertHdfToCsv } from './converter.js';

// Count CSV data rows (excluding the header) with a minimal quote-aware scan, so
// newlines inside quoted fields are not miscounted as rows.
function countCsvDataRows(csv: string): number {
  let rows = 0;
  let inQuotes = false;
  let sawField = false;
  for (let i = 0; i < csv.length; i++) {
    const ch = csv[i];
    if (ch === '"') {
      if (inQuotes && csv[i + 1] === '"') {
        i++; // escaped quote
      } else {
        inQuotes = !inQuotes;
      }
      sawField = true;
    } else if (ch === '\n' && !inQuotes) {
      if (sawField) rows++;
      sawField = false;
    } else if (ch !== '\r') {
      sawField = true;
    }
  }
  if (sawField) rows++; // final row with no trailing newline
  return rows - 1; // minus the header row
}

// Export-side ground-truth anchor: hdf-to-csv FANS OUT one data row per
// (requirement × target), where targets are the document's components (or a
// single empty target when there are none). Mirrors Go.
describe('hdf-to-csv output-count anchor', () => {
  it('emits one data row per (requirement × target)', () => {
    const input = results.inspecMultilayered.read();
    const reqs = countHdfResultRequirements(input);
    expect(reqs).toBeGreaterThan(1);
    const components = (JSON.parse(input) as { components?: unknown[] }).components?.length ?? 0;
    const want = reqs * Math.max(components, 1);

    const got = countCsvDataRows(convertHdfToCsv(input));
    expect(got, 'one CSV data row per (requirement × target)').toBe(want);
  });
});
