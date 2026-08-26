import { describe, it, expect } from 'vitest';
import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import * as testhdf from '@mitre/hdf-schema/testhdf';
import { resultsCorpus } from '../../../shared/typescript/schema-corpus.js';
import { convertHdfToCsv } from './converter.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const fixturesDir = join(__dirname, '..', 'fixtures');

function loadFixture(type: 'input' | 'expected', filename: string): string {
  return readFileSync(join(fixturesDir, type, filename), 'utf-8');
}

describe('hdfcsv Converter', () => {
  describe('Basic conversion', () => {
    it('should convert minimal HDF to CSV', () => {
      const input = loadFixture('input', 'minimal.json');
      const expected = loadFixture('expected', 'minimal.csv');

      const result = convertHdfToCsv(input);

      expect(result).toBe(expected);
    });

    it('should handle empty baselines array', () => {
      const input = JSON.stringify({
        baselines: [],
        components: [],
        statistics: { duration: 0 }
      });

      // baselines carries no minItems, so an assessment that evaluated nothing
      // is valid HDF and still converts — to an empty report.
      expect(convertHdfToCsv(input)).toBe('');
    });

    // A baseline with an empty requirements array is malformed, not empty:
    // requirements carries minItems 1. It was previously converted to an empty
    // report, which is indistinguishable from a valid assessment that evaluated
    // nothing — and top-level baselines, which genuinely has no minItems, is the
    // shape that legitimately produces that. Mirrors the Go peer.
    it('rejects a baseline with an empty requirements array', () => {
      const input = JSON.stringify({
        baselines: [{
          name: 'Empty Baseline',
          version: '1.0.0',
          title: 'Test',
          maintainer: 'Test',
          supports: [],
          attributes: [],
          groups: [],
          checksum: { algorithm: 'sha256', value: 'abc' },
          requirements: []
        }],
        components: [],
        statistics: { duration: 0 }
      });

      expect(() => convertHdfToCsv(input)).toThrow(
        'hdf-to-csv: baseline "Empty Baseline" has no requirements',
      );
    });
  });

  describe('Export field-loss columns', () => {
    const input = loadFixture('input', 'minimal.json');
    const result = convertHdfToCsv(input);
    const lines = result.split('\n');
    const header = lines[0];

    it('appends the new columns to the header in a stable order', () => {
      expect(header).toContain(
        'Result Message,Effective Status,Effective Impact,Disposition,' +
          'Override Reason,Applied By,Expires At,CVSS,CWE,EPSS,KEV,' +
          'Target FQDN,Target IP'
      );
    });

    it('emits component fqdn/ipAddress on every row', () => {
      // Present on all three data rows (single component).
      const fqdnCount = (result.match(/test-server-01\.example\.com/g) ?? []).length;
      expect(fqdnCount).toBe(3);
      expect(result).toContain('10.1.2.3');
    });

    it('surfaces override provenance and effective posture for the waived control', () => {
      const row = lines.find(l => l.startsWith('Example STIG Baseline,1.0.0,')
        && l.includes('SV-123457'));
      expect(row).toBeDefined();
      // Raw Status stays failed; Effective Status/Impact reflect the override.
      expect(row).toContain(',failed,'); // raw Status column
      expect(row).toContain('falsePositive');
      expect(row).toContain('Authentication logging is handled by an external SIEM');
      expect(row).toContain(',jdoe,');
      expect(row).toContain('2099-12-31T00:00:00Z');
    });

    it('surfaces the CVSS/CWE/EPSS/KEV quartet for the CVE finding', () => {
      const row = lines.find(l => l.includes('CVE-2021-44228'));
      expect(row).toBeDefined();
      expect(row).toContain('10.0');
      expect(row).toContain('CWE-502; CWE-917');
      expect(row).toContain('0.94360');
      // KEV boolean present as its own cell.
      expect(row).toContain(',true,');
    });
  });

  describe('Multiple baselines and targets', () => {
    it('should handle multiple baselines', () => {
      const input = JSON.stringify(testhdf.doc(
        testhdf.baseline('Baseline 1', testhdf.req('REQ-001', {
          title: 'Test Requirement', desc: 'Test description', impact: 0.5,
          tags: { severity: 'medium' }, status: 'passed',
        })),
        testhdf.baseline('Baseline 2', testhdf.req('REQ-002', {
          title: 'Another Requirement', desc: 'Another description', impact: 0.7,
          tags: { severity: 'high' }, status: 'failed',
        })),
      ));

      const result = convertHdfToCsv(input);
      const lines = result.split('\n').filter(l => l.trim());

      // Header + 2 requirement rows
      expect(lines.length).toBe(3);
      expect(result).toContain('Baseline 1');
      expect(result).toContain('Baseline 2');
    });

    it('should handle multiple targets', () => {
      const input = JSON.stringify({
        baselines: [{
          name: 'Test Baseline',
          version: '1.0.0',
          title: 'Test',
          maintainer: 'Test',
          supports: [],
          attributes: [],
          groups: [],
          checksum: { algorithm: 'sha256', value: 'abc' },
          requirements: [{
            id: 'REQ-001',
            title: 'Test Requirement',
            descriptions: [{ label: 'default', data: 'Test description' }],
            impact: 0.5,
            tags: { severity: 'medium' },
            sourceLocation: { ref: 'REQ-001', line: 1 },
            results: [{ status: 'passed', codeDesc: 'Test', startTime: '2026-01-29T18:00:00.000Z' }]
          }]
        }],
        components: [
          { name: 'target1', type: 'host' },
          { name: 'target2', type: 'container' }
        ],
        statistics: { duration: 0 }
      });

      const result = convertHdfToCsv(input);

      // Each target should appear in output
      expect(result).toContain('target1,host');
      expect(result).toContain('target2,container');
    });
  });

  describe('Field extraction', () => {
    it('should extract NIST controls from tags', () => {
      const input = JSON.stringify(testhdf.doc(testhdf.baseline('Test',
        testhdf.req('REQ-001', {
          title: 'Test', desc: 'Test', impact: 0.5,
          tags: { nist: ['AC-2', 'AC-3', 'IA-5 (1)'], severity: 'medium' }, status: 'passed',
        }))));

      const result = convertHdfToCsv(input);

      expect(result).toContain('AC-2; AC-3; IA-5 (1)');
    });

    it('should extract CCI controls from tags', () => {
      const input = JSON.stringify(testhdf.doc(testhdf.baseline('Test',
        testhdf.req('REQ-001', {
          title: 'Test', desc: 'Test', impact: 0.5,
          tags: { cci: ['CCI-000001', 'CCI-000002'], severity: 'medium' }, status: 'passed',
        }))));

      const result = convertHdfToCsv(input);

      expect(result).toContain('CCI-000001; CCI-000002');
    });

    it('should extract result message from failed results', () => {
      const input = JSON.stringify({
        baselines: [{
          name: 'Test',
          version: '1.0.0',
          title: 'Test',
          maintainer: 'Test',
          supports: [],
          attributes: [],
          groups: [],
          checksum: { algorithm: 'sha256', value: 'abc' },
          requirements: [{
            id: 'REQ-001',
            title: 'Test',
            descriptions: [{ label: 'default', data: 'Test' }],
            impact: 0.5,
            tags: { severity: 'medium' },
            sourceLocation: { ref: 'REQ-001', line: 1 },
            results: [{
              status: 'failed',
              codeDesc: 'Test',
              message: 'Security control not implemented',
              startTime: '2026-01-29T18:00:00.000Z'
            }]
          }]
        }],
        components: [],
        statistics: { duration: 0 }
      });

      const result = convertHdfToCsv(input);

      expect(result).toContain('Security control not implemented');
    });

    it('should use first result for status when multiple results exist', () => {
      const input = JSON.stringify({
        baselines: [{
          name: 'Test',
          version: '1.0.0',
          title: 'Test',
          maintainer: 'Test',
          supports: [],
          attributes: [],
          groups: [],
          checksum: { algorithm: 'sha256', value: 'abc' },
          requirements: [{
            id: 'REQ-001',
            title: 'Test',
            descriptions: [{ label: 'default', data: 'Test' }],
            impact: 0.5,
            tags: { severity: 'medium' },
            sourceLocation: { ref: 'REQ-001', line: 1 },
            results: [
              { status: 'failed', codeDesc: 'Test 1', message: 'First failure', startTime: '2026-01-29T18:00:00.000Z' },
              { status: 'passed', codeDesc: 'Test 2', startTime: '2026-01-29T18:00:01.000Z' }
            ]
          }]
        }],
        components: [],
        statistics: { duration: 0 }
      });

      const result = convertHdfToCsv(input);

      // Should use first result
      expect(result).toContain('failed');
      expect(result).toContain('First failure');
    });
  });

  describe('CSV injection protection', () => {
    it('should sanitize formulas in descriptions', () => {
      const input = JSON.stringify(testhdf.doc(testhdf.baseline('Test',
        testhdf.req('REQ-001', {
          title: '=1+1', desc: '=SUM(A1:A10)', impact: 0.5,
          tags: { severity: 'medium' }, status: 'passed',
        }))));

      const result = convertHdfToCsv(input);

      // Formulas should be prefixed with '
      expect(result).toContain("'=1+1");
      expect(result).toContain("'=SUM(A1:A10)");
    });

    it('should sanitize all formula trigger characters', () => {
      const dangerous = (id: string, title: string) =>
        testhdf.req(id, {
          title, desc: 'test', impact: 0.5, tags: { severity: 'medium' }, status: 'passed',
        });
      const input = JSON.stringify(testhdf.doc(testhdf.baseline('Test',
        dangerous('REQ-001', '+dangerous'),
        dangerous('REQ-002', '-dangerous'),
        dangerous('REQ-003', '@dangerous'),
      )));

      const result = convertHdfToCsv(input);

      expect(result).toContain("'+dangerous");
      expect(result).toContain("'-dangerous");
      expect(result).toContain("'@dangerous");
    });
  });

  describe('Error handling', () => {
    it('should throw on invalid JSON', () => {
      expect(() => convertHdfToCsv('not valid json')).toThrow();
    });

    it('should throw on missing baselines field', () => {
      expect(() => convertHdfToCsv('{}')).toThrow();
    });

    it('should throw on invalid HDF structure', () => {
      expect(() => convertHdfToCsv('{ "baselines": "not an array" }')).toThrow();
    });
  });

  describe('edge cases: missing optional fields', () => {
    it('should handle requirement with no tags', () => {
      const input = JSON.stringify({
        baselines: [{
          name: 'B1',
          requirements: [{
            id: 'R1',
            title: 'Test',
            descriptions: [{ label: 'default', data: 'desc' }],
            impact: 0.5,
            tags: {},
            results: [{ status: 'passed', codeDesc: 'Test', startTime: '2025-01-01T00:00:00Z' }]
          }]
        }],
        components: [],
      });
      const result = convertHdfToCsv(input);
      expect(result).toContain('R1');
    });

    it('should handle requirement with no default description', () => {
      const input = JSON.stringify({
        baselines: [{
          name: 'B1',
          requirements: [{
            id: 'R1',
            descriptions: [{ label: 'check', data: 'check data' }],
            impact: 0.5,
            tags: {},
            results: [{ status: 'passed', codeDesc: 'Test', startTime: '2025-01-01T00:00:00Z' }]
          }]
        }],
        components: [],
      });
      const result = convertHdfToCsv(input);
      expect(result).toContain('R1');
    });

    it('should handle severity as array in tags', () => {
      const input = JSON.stringify({
        baselines: [{
          name: 'B1',
          requirements: [{
            id: 'R1',
            descriptions: [{ label: 'default', data: 'desc' }],
            impact: 0.5,
            tags: { severity: ['high', 'medium'] },
            results: [{ status: 'passed', codeDesc: 'Test', startTime: '2025-01-01T00:00:00Z' }]
          }]
        }],
        components: [],
      });
      const result = convertHdfToCsv(input);
      expect(result).toContain('high');
    });

    it('should handle no targets (default empty target)', () => {
      const input = JSON.stringify({
        baselines: [{
          name: 'B1',
          requirements: [{
            id: 'R1',
            descriptions: [{ label: 'default', data: 'desc' }],
            impact: 0.2,
            tags: {},
            results: [{ status: 'passed', codeDesc: 'Test', startTime: '2025-01-01T00:00:00Z' }]
          }]
        }],
      });
      const result = convertHdfToCsv(input);
      expect(result).toContain('R1');
      expect(result).toContain('low'); // impact 0.2 → low severity
    });

    it('should handle impact >= 0.7 as high severity', () => {
      const input = JSON.stringify({
        baselines: [{
          name: 'B1',
          requirements: [{
            id: 'R1',
            descriptions: [{ label: 'default', data: 'desc' }],
            impact: 0.8,
            tags: {},
            results: [{ status: 'failed', codeDesc: 'Test', startTime: '2025-01-01T00:00:00Z', message: 'fail msg' }]
          }]
        }],
        components: [{ name: 't1', type: 'host' }],
      });
      const result = convertHdfToCsv(input);
      expect(result).toContain('high');
    });

    it('should handle null/undefined tags gracefully in extractArrayFromTags', () => {
      const input = JSON.stringify({
        baselines: [{
          name: 'B1',
          requirements: [{
            id: 'R1',
            descriptions: [{ label: 'default', data: 'desc' }],
            impact: 0.5,
            results: [{ status: 'passed', codeDesc: 'Test', startTime: '2025-01-01T00:00:00Z' }]
          }]
        }],
        components: [],
      });
      const result = convertHdfToCsv(input);
      expect(result).toContain('R1');
    });

    it('should handle requirement with no title and no version', () => {
      const input = JSON.stringify({
        baselines: [{
          name: 'B1',
          requirements: [{
            id: 'R1',
            descriptions: [{ label: 'default', data: 'desc' }],
            impact: 0.5,
            tags: { nist: ['AC-1'] },
            results: [{ status: 'passed', codeDesc: 'Test', startTime: '2025-01-01T00:00:00Z' }]
          }]
        }],
        components: [],
      });
      const result = convertHdfToCsv(input);
      expect(result).toContain('AC-1');
    });
  });
});

// A requirement with no results is malformed: hdf-results puts minItems 1 on
// results, no requirement in this repo's HDF fixtures carries an empty one, and
// "not evaluated" already has its own representation as a result with status
// notReviewed. So there is no legitimate producer, and the converter rejects
// rather than emitting a row whose blank Status cell is indistinguishable from a
// genuinely blank one. Mirrors the Go peer.
describe('hdf-to-csv malformed input', () => {
  const emptyResults = JSON.stringify({
    baselines: [
      {
        name: 'b',
        requirements: [
          {
            id: 'V-1',
            impact: 0,
            tags: {},
            descriptions: [{ label: 'default', data: 'd' }],
            results: [],
          },
        ],
      },
    ],
  });

  it('rejects a requirement with no results', () => {
    expect(() => convertHdfToCsv(emptyResults)).toThrow(
      'hdf-to-csv: requirement "V-1" has no results',
    );
  });

  // The shared guard owns this wording so the two languages cannot drift; before,
  // Go said "invalid" and this side "Invalid", and neither carried the prefix.
  it('reports the canonical missing-baselines message', () => {
    expect(() => convertHdfToCsv('{}')).toThrow(
      'hdf-to-csv: invalid HDF structure: missing baselines field',
    );
  });
});

// The two languages are compared against one another rather than each against
// its own expectations. Go owns the golden
// (go test ./converters/hdf-to-csv/go/ -update); this side only verifies, so
// neither language can quietly redefine parity to match itself.
describe('hdf-to-csv corpus output parity', () => {
  const golden = JSON.parse(
    readFileSync(join(fixturesDir, 'expected', 'corpus-outputs.json'), 'utf-8'),
  ) as Record<string, string>;

  it('covers every corpus case', () => {
    expect(Object.keys(golden).sort()).toEqual(resultsCorpus().map((c) => c.name).sort());
  });

  it.each(resultsCorpus().map((c) => [c.name, c] as const))(
    'emits what the Go peer emits for %s',
    (name, c) => {
      let actual: string;
      try {
        actual = convertHdfToCsv(c.input);
      } catch {
        actual = 'REJECTED';
      }
      expect(actual, `TypeScript and Go diverged on corpus case ${name}`).toBe(golden[name]);
    },
  );
});

// Both shapes reach the same guard: an absent id must not be named "undefined"
// in the message (the column coercion was added for exactly that, and the
// message needed it too), and a null results must not throw a TypeError from
// the destructure before the guard can report it. Go reaches both by way of a
// zero-value string and a nil slice; these pin that TypeScript agrees.
describe('hdf-to-csv malformed results shapes', () => {
  const doc = (requirement: Record<string, unknown>) =>
    JSON.stringify({ baselines: [{ name: 'b', requirements: [requirement] }] });

  const base = {
    impact: 0,
    tags: {},
    descriptions: [{ label: 'default', data: 'd' }],
  };

  it('names an absent id as empty, never "undefined"', () => {
    expect(() => convertHdfToCsv(doc({ ...base, results: [] }))).toThrow(
      'hdf-to-csv: requirement "" has no results',
    );
  });

  it('reports a null results rather than throwing a TypeError', () => {
    expect(() => convertHdfToCsv(doc({ ...base, id: 'V-1', results: null }))).toThrow(
      'hdf-to-csv: requirement "V-1" has no results',
    );
  });
});

// Impact's canonical precision is 2 decimal places — it is defined on 0.0-1.0
// with a natural 0.01 grid, which is why hdf-utilities' roundImpact rounds to
// that grid wherever impact is computed. Rendering it at one decimal discarded
// the second digit of every value that used it (0.45 became "0.5"), silently, in
// a compliance artifact.
//
// Precision alone does not settle the digits: Go's fmt rounds halves to even
// while toFixed rounds them away from zero, so raising the precision only moved
// the tie from 0.25 to 0.125. Go now formats through a helper matching toFixed's
// rule; the tie values themselves are pinned by the parity fixtures.
//
// CVSS keeps one decimal: that is the precision the CVSS spec defines and the
// source carries. Mirrors the Go peer.
describe('hdf-to-csv numeric precision', () => {
  const COL = { impact: 14, effectiveImpact: 23, cvss: 28 };

  it.each([
    ['two-decimal impact is preserved', 0.45, 7.5, '0.45', '7.5'],
    ['the tie value both languages once disagreed on', 0.25, 2.5, '0.25', '2.5'],
    ['one-decimal impact is padded to canonical precision', 0.5, 9.8, '0.50', '9.8'],
    ['a whole impact keeps the grid', 1, 10, '1.00', '10.0'],
  ])('%s', (_label, impact, cvss, wantImpact, wantCvss) => {
    const out = convertHdfToCsv(
      JSON.stringify({
        baselines: [
          {
            name: 'b',
            requirements: [
              {
                id: 'V-1',
                impact,
                effectiveImpact: impact,
                tags: {},
                cvss: [{ baseScore: cvss }],
                descriptions: [{ label: 'default', data: 'd' }],
                results: [{ status: 'passed', codeDesc: 'c', startTime: '2020-01-01T00:00:00Z' }],
              },
            ],
          },
        ],
      }),
    );

    const row = out.trim().split('\n')[1]!.split(',');
    expect(row[COL.impact], 'Impact').toBe(wantImpact);
    expect(row[COL.effectiveImpact], 'Effective Impact').toBe(wantImpact);
    expect(row[COL.cvss], 'CVSS keeps the source precision').toBe(wantCvss);
  });
});

// Awkward-but-plausible HDF shapes that once made the two languages disagree on
// cell VALUES rather than on whether to convert at all — splits the shared
// corpus cannot see, because it is about converter contracts. Go owns the golden
// (go test ./converters/hdf-to-csv/go/ -update); this side only verifies.
describe('hdf-to-csv parity shapes', () => {
  const shapes = (
    JSON.parse(readFileSync(join(fixturesDir, 'input', 'parity-shapes.json'), 'utf-8')) as {
      shapes: Record<string, unknown>;
    }
  ).shapes;
  const golden = JSON.parse(
    readFileSync(join(fixturesDir, 'expected', 'parity-outputs.json'), 'utf-8'),
  ) as Record<string, string>;

  it('covers every shape', () => {
    expect(Object.keys(golden).sort()).toEqual(Object.keys(shapes).sort());
  });

  it.each(Object.keys(shapes).sort())('emits what the Go peer emits for %s', (name) => {
    let actual: string;
    try {
      actual = convertHdfToCsv(JSON.stringify(shapes[name]));
    } catch {
      actual = 'REJECTED';
    }
    expect(actual, `TypeScript and Go diverged on shape ${name}`).toBe(golden[name]);
  });
});

// requirements and descriptions both carry minItems 1 on top of being required,
// so absent or empty is malformed input — the same reasoning that made an empty
// results array a rejection. Top-level baselines is deliberately excluded: it
// carries no minItems, so an assessment that evaluated nothing is legal HDF.
// Mirrors the Go peer case for case.
describe('hdf-to-csv malformed containers', () => {
  it.each([
    ['baseline with no requirements key', { baselines: [{ name: 'b' }] },
      'hdf-to-csv: baseline "b" has no requirements'],
    ['baseline with empty requirements', { baselines: [{ name: 'b', requirements: [] }] },
      'hdf-to-csv: baseline "b" has no requirements'],
    ['requirement with no descriptions key',
      { baselines: [{ name: 'b', requirements: [{ id: 'V-1', impact: 0, tags: {}, results: [{ status: 'passed', codeDesc: 'c', startTime: '2020-01-01T00:00:00Z' }] }] }] },
      'hdf-to-csv: requirement "V-1" has no descriptions'],
    ['requirement with empty descriptions',
      { baselines: [{ name: 'b', requirements: [{ id: 'V-1', impact: 0, tags: {}, descriptions: [], results: [{ status: 'passed', codeDesc: 'c', startTime: '2020-01-01T00:00:00Z' }] }] }] },
      'hdf-to-csv: requirement "V-1" has no descriptions'],
  ])('rejects a %s', (_label, doc, want) => {
    expect(() => convertHdfToCsv(JSON.stringify(doc))).toThrow(want);
  });

  it('still converts an assessment with zero baselines', () => {
    expect(convertHdfToCsv('{"baselines":[]}')).toBe('');
  });
});
