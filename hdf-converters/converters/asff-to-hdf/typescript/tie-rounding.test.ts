import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { describe, it, expect } from 'vitest';
import { convertAsffToHdf } from './converter.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const input = readFileSync(join(__dirname, '..', 'fixtures', 'input', 'tie-rounding.json'), 'utf-8');

// The Go peer asserts these same two strings on this same fixture. toFixed
// rounds a tie away from zero; Go's fmt rounds it to even, which is why Go
// routes through hdfutil.FormatFixed instead. If someone ever "fixes" this side
// to match fmt, these fail.
describe('asff-to-hdf renders exact ties the way Go now does', () => {
  it('rounds 7.25 to 7.3 at one decimal and 0.03125 to 0.0313 at four', async () => {
    const hdf = JSON.parse(await convertAsffToHdf(input, '0.1.0'));
    const messages = (hdf.baselines[0].requirements as Array<Record<string, unknown>>)
      .flatMap((r) => (r.results as Array<Record<string, unknown>>) ?? [])
      .map((r) => String(r.message ?? ''))
      .join('\n');

    expect(messages).not.toBe('');
    expect(messages).toContain('CVSS 3.1 7.3');
    expect(messages).toContain('EPSS 0.0313');
    expect(messages).not.toContain('CVSS 3.1 7.2');
    expect(messages).not.toContain('EPSS 0.0312');
  });
});
