import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, it, expect } from 'vitest';
import type { Description } from '@mitre/hdf-schema';
import { ensureDefaultDescription } from './converterutil.js';

// The Go peer reads the same ../testdata/ensure-default-description-cases.json.
interface Case {
  name: string;
  descriptions: Description[];
  data: string;
  want: Description[];
}

const { cases } = JSON.parse(
  readFileSync(
    join(dirname(fileURLToPath(import.meta.url)), '..', 'testdata', 'ensure-default-description-cases.json'),
    'utf-8',
  ),
) as { cases: Case[] };

describe('ensureDefaultDescription', () => {
  it('has vectors to run', () => {
    expect(cases.length).toBeGreaterThan(0);
  });

  it.each(cases.map((c) => [c.name, c] as const))('%s', (_name, c) => {
    expect(ensureDefaultDescription(c.descriptions, c.data)).toEqual(c.want);
  });

  it('defaults the synthesized data to empty', () => {
    expect(ensureDefaultDescription([])).toEqual([{ label: 'default', data: '' }]);
  });

  it('does not write into the input', () => {
    const input: Description[] = [{ label: 'check', data: 'c' }];
    ensureDefaultDescription(input, 'd');
    expect(input).toEqual([{ label: 'check', data: 'c' }]);
  });
});
