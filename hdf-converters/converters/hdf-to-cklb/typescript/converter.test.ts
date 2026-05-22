import { describe, it, expect } from 'vitest';
import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { convertHdfToCklb } from './converter.js';
import { convertCklToHdf } from '../../ckl-to-hdf/typescript/converter.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const cklFixture = join(__dirname, '..', '..', 'ckl-to-hdf', 'fixtures', 'input', 'firefox-stig.ckl');

interface CklbRule {
  group_id?: string;
  status: string;
  ccis?: string[];
}

describe('hdf-to-cklb Converter', () => {
  it('round-trips CKL -> HDF -> CKLB preserving content and CKLB shape', async () => {
    const ckl = readFileSync(cklFixture, 'utf-8');
    const hdf = await convertCklToHdf(ckl);

    const out = convertHdfToCklb(hdf);
    const parsed = JSON.parse(out);

    expect(parsed.cklb_version).toBeTruthy();
    expect(parsed.stigs[0].rules).toHaveLength(6);
    expect(parsed.target_data.host_name).toBe('EXAMPLE-HOST');

    // V-251545 is Open (snake_case CKLB status) and carries CCI-002605.
    const rules: CklbRule[] = parsed.stigs[0].rules;
    const open = rules.find(r => r.status === 'open' && (r.ccis ?? []).includes('CCI-002605'));
    expect(open).toBeDefined();
  });

  it('synthesizes a valid CKLB from arbitrary HDF (no passthrough extensions)', () => {
    const input = JSON.stringify({
      baselines: [{
        name: 'Synth Baseline',
        version: '1.0.0',
        title: 'Synthesized',
        maintainer: 'Test',
        supports: [],
        attributes: [],
        groups: [],
        checksum: { algorithm: 'sha256', value: 'abc' },
        requirements: [{
          id: 'GEN-001',
          title: 'Generic Requirement',
          descriptions: [{ label: 'default', data: 'A generic check' }],
          impact: 0.5,
          tags: { nist: ['SI-2 c'] },
          sourceLocation: { ref: 'GEN-001', line: 1 },
          results: [{ status: 'failed', codeDesc: 'Check', startTime: '2026-01-29T18:00:00.000Z' }]
        }]
      }],
      components: [],
      statistics: { duration: 0 }
    });

    const out = convertHdfToCklb(input);
    const parsed = JSON.parse(out);

    const rules: CklbRule[] = parsed.stigs[0].rules;
    const gen = rules.find(r => r.group_id === 'GEN-001');
    expect(gen).toBeDefined();
    expect(gen?.ccis?.length ?? 0).toBeGreaterThan(0);
  });

  it('throws on invalid input', () => {
    expect(() => convertHdfToCklb('not valid json')).toThrow();
    expect(() => convertHdfToCklb('{"baselines":[]}')).toThrow();
  });
});
