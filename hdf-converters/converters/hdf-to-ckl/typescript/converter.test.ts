import { describe, it, expect } from 'vitest';
import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { convertHdfToCkl } from './converter.js';
import { convertCklToHdf } from '../../ckl-to-hdf/typescript/converter.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const cklFixture = join(__dirname, '..', '..', 'ckl-to-hdf', 'fixtures', 'input', 'firefox-stig.ckl');

describe('hdf-to-ckl Converter', () => {
  describe('Round-trip', () => {
    it('should round-trip a ckl through HDF and back to ckl', async () => {
      const cklStr = readFileSync(cklFixture, 'utf-8');
      const hdf = await convertCklToHdf(cklStr);

      const out = convertHdfToCkl(hdf);

      expect(out).toContain('<CHECKLIST>');
      expect(out).toContain('V-251545');
      // STATUS must be a child element, not a VULN attribute (valid CKL).
      expect(out).toContain('<STATUS>Open</STATUS>');
      expect(out).not.toMatch(/<VULN[^>]*STATUS="/);
      expect(out).toContain('CCI-002605');
      expect(out).toContain('EXAMPLE-HOST');
    });
  });

  describe('Synthesis from arbitrary HDF', () => {
    it('should synthesize a valid ckl from HDF with no checklist extensions', () => {
      const input = JSON.stringify({
        baselines: [{
          name: 'Synthetic Baseline',
          version: '1.0.0',
          title: 'Synthetic',
          maintainer: 'Test',
          supports: [],
          inputs: [],
          groups: [],
          checksum: { algorithm: 'sha256', value: 'abc' },
          requirements: [{
            id: 'GEN-001',
            title: 'Generic Requirement',
            descriptions: [{ label: 'default', data: 'A generic requirement description' }],
            impact: 0.5,
            tags: { nist: ['SI-2 c'] },
            sourceLocation: { ref: 'GEN-001', line: 1 },
            results: [{ status: 'failed', codeDesc: 'Test', startTime: '2026-01-29T18:00:00.000Z' }]
          }]
        }],
        components: [],
        statistics: { duration: 0 }
      });

      const out = convertHdfToCkl(input);

      expect(out).toContain('<CHECKLIST>');
      expect(out).toContain('GEN-001');
      // CCI synthesized from the NIST tag (SI-2 c -> CCI).
      expect(out).toContain('CCI-');
    });
  });

  describe('Error handling', () => {
    it('should throw on invalid JSON', () => {
      expect(() => convertHdfToCkl('not valid json')).toThrow();
    });

    it('should throw on HDF with no baselines', () => {
      expect(() => convertHdfToCkl('{"baselines":[]}')).toThrow();
    });
  });
});
