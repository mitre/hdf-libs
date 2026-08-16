import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { describe, it, expect } from 'vitest';
import { convertConveyorToHdf } from './converter.js';
import { runConverterContractTests } from '../../../shared/typescript/converter-contract.js';
import { expectValidResults } from '../../../test/helpers/expectValidHdf.js';
import { assertRequirementCount } from '../../../shared/typescript/anchor.js';
import type { HDFResults } from '@mitre/hdf-schema';

const __dirname = dirname(fileURLToPath(import.meta.url));
const FIXTURES_DIR = join(__dirname, '..', 'fixtures');

function loadFixture(name: string): string {
  return readFileSync(join(FIXTURES_DIR, 'input', name), 'utf-8');
}

runConverterContractTests({
  converterName: 'conveyor-to-hdf',
  convertFn: convertConveyorToHdf,
  minimalFixture: 'sample-results.json',
});

// Parses raw Conveyor JSON generically — deliberately NOT the converter's parser
// — and returns the number of entries in the api_response.results map. The
// converter emits one requirement per result (distributed across per-scanner
// baselines), so this map size is the ground truth. results is a JSON object
// keyed by result id, not an array.
function countConveyorResults(input: string): number {
  const doc = JSON.parse(input) as { api_response?: { results?: Record<string, unknown> } };
  return Object.keys(doc.api_response?.results ?? {}).length;
}

// Ground-truth anchor (input-derived count; see shared/typescript/anchor.ts):
// one requirement per api_response.results entry.
describe('conveyor-to-hdf ground-truth anchor', () => {
  it('emits one requirement per api_response.results entry (sample-results)', async () => {
    const input = loadFixture('sample-results.json');
    assertRequirementCount(
      await convertConveyorToHdf(input),
      countConveyorResults(input),
      'sample-results.json: one requirement per api_response.results entry',
    );
  });
});

describe('timestamp parse fallback', () => {
  it('falls back to a valid startTime when service_started is unparseable', async () => {
    const input = loadFixture('sample-results.json').replace(/2023-08-31T12:23:51\.158629Z/g, 'not-a-date');
    const hdf = JSON.parse(await convertConveyorToHdf(input)) as HDFResults;
    expectValidResults(hdf);
  });
});

// Value-pinning: the shared snapshot masks the top-level timestamp, so these
// assertions pin the exact source-derived values (per the u6j3/timestamp audit)
// and must stay byte-parity with the Go converter's pinned tests.
describe('source-derived timestamps and tool.version', async () => {
  it('pins result startTime to service_started', async () => {
    const hdf = JSON.parse(await convertConveyorToHdf(loadFixture('sample-results.json'))) as HDFResults;
    const clamav = hdf.baselines.find(b => b.title?.includes('Clamav'));
    expect(clamav).toBeDefined();
    const req = clamav!.requirements.find(
      r => r.id === '033ecf8f77772375c638c1874f881a2aa300aae7073c23280554edf007174602',
    );
    expect(req).toBeDefined();
    // service_started = 2023-08-28T12:23:54.164548Z → trimmed-UTC millis.
    expect(req!.results[0]!.startTime).toBe('2023-08-28T12:23:54.164Z');
  });

  it('pins result runTime to service_completed − service_started (seconds)', async () => {
    const hdf = JSON.parse(await convertConveyorToHdf(loadFixture('sample-results.json'))) as HDFResults;
    const clamav = hdf.baselines.find(b => b.title?.includes('Clamav'));
    const req = clamav!.requirements.find(
      r => r.id === '033ecf8f77772375c638c1874f881a2aa300aae7073c23280554edf007174602',
    );
    // .164 → .179 (trimmed-UTC millis) = 0.015s.
    expect(req!.results[0]!.runTime).toBeCloseTo(0.015, 9);
  });

  it('pins typed scanner tags from the result', async () => {
    const hdf = JSON.parse(await convertConveyorToHdf(loadFixture('sample-results.json'))) as HDFResults;
    const clamav = hdf.baselines.find(b => b.title?.includes('Clamav'));
    const req = clamav!.requirements.find(
      r => r.id === '033ecf8f77772375c638c1874f881a2aa300aae7073c23280554edf007174602',
    );
    // created/expiry_ts canonicalized to trimmed-UTC millis (per repo policy).
    expect(req!.tags?.['created']).toBe('2023-08-28T12:23:54.184Z');
    expect(req!.tags?.['classification']).toBe('TLP:C');
    expect(req!.tags?.['expiry_ts']).toBe('2023-08-31T12:23:54.184Z');
    expect(req!.tags?.['size']).toBe(351);
    expect(req!.tags?.['type']).toBe('document/stigma');
  });

  it('omits typed tags the source leaves null', async () => {
    const hdf = JSON.parse(await convertConveyorToHdf(loadFixture('sample-results.json'))) as HDFResults;
    const moldy = hdf.baselines.find(b => b.title?.includes('Moldy'));
    const req = moldy!.requirements.find(
      r => r.id === '60e5941e7c34e77decf4d079ae18b531d35326ae8bd26d1dbca7ce23de548634',
    );
    expect(req!.tags?.['created']).toBe('2023-08-28T12:38:41.769Z');
    expect(req!.tags).not.toHaveProperty('size');
    expect(req!.tags).not.toHaveProperty('type');
  });

  it('pins tool.version to the first sorted service_version', async () => {
    const hdf = JSON.parse(await convertConveyorToHdf(loadFixture('sample-results.json'))) as HDFResults;
    expect(hdf.tool?.version).toBe('4.3.0.0');
  });

  it('pins top-level timestamp to api_response.times.completed', async () => {
    const hdf = JSON.parse(await convertConveyorToHdf(loadFixture('sample-results.json'))) as HDFResults;
    // times.completed = 2023-08-28T12:25:24.834217Z → trimmed-UTC millis.
    expect(hdf.timestamp).toBe('2023-08-28T12:25:24.834Z');
  });

  it('falls back to the zero sentinel startTime and omits runTime when milestones are absent', async () => {
    const input = JSON.stringify({
      api_response: { results: { r1: { sha256: 'abc', response: { service_name: 'Moldy' }, result: { score: 0, sections: [] } } } },
    });
    const hdf = JSON.parse(await convertConveyorToHdf(input)) as HDFResults;
    const res = hdf.baselines[0]!.requirements[0]!.results[0]!;
    expect(res.startTime).toBe('0001-01-01T00:00:00Z');
    expect(res.runTime).toBeUndefined();
  });

  it('falls back to now() for the top-level timestamp when times.completed is absent', async () => {
    const input = JSON.stringify({
      api_response: { results: { r1: { sha256: 'abc', response: { service_name: 'Moldy' }, result: { score: 0, sections: [] } } } },
    });
    const hdf = JSON.parse(await convertConveyorToHdf(input)) as HDFResults;
    expect(new Date(hdf.timestamp!).getTime()).toBeGreaterThan(new Date('2020-01-01T00:00:00Z').getTime());
  });

  it('omits tool.version when no service_version is present', async () => {
    const input = JSON.stringify({
      api_response: { results: { r1: { sha256: 'abc', response: { service_name: 'Moldy' }, result: { score: 0, sections: [] } } } },
    });
    const hdf = JSON.parse(await convertConveyorToHdf(input)) as HDFResults;
    expect(hdf.tool?.version).toBeUndefined();
  });
});

describe('conveyor to HDF converter', async () => {
  describe('input validation', async () => {
    it('should throw when api_response is missing', async () => {
      await expect(convertConveyorToHdf('{"api_error_message": ""}')).rejects.toThrow();
    });
  });

  describe('multi-baseline output (grouped by scanner)', async () => {
    it('should produce multiple baselines (one per scanner type)', async () => {
      const hdf = JSON.parse(await convertConveyorToHdf(loadFixture('sample-results.json'))) as HDFResults;
      expectValidResults(hdf);
      // Fixture has 4 scanner types: Clamav, CodeQuality, Stigma, Moldy
      expect(hdf.baselines.length).toBeGreaterThanOrEqual(4);
    });

    it('should use "Conveyor Scan" as baseline name for all baselines', async () => {
      const hdf = JSON.parse(await convertConveyorToHdf(loadFixture('sample-results.json'))) as HDFResults;
      for (const baseline of hdf.baselines) {
        expect(baseline.name).toBe('Conveyor Scan');
      }
    });

    it('should include scanner name in baseline title', async () => {
      const hdf = JSON.parse(await convertConveyorToHdf(loadFixture('sample-results.json'))) as HDFResults;
      const titles = hdf.baselines.map(b => b.title ?? '');
      const hasClamav = titles.some(t => t.includes('Clamav'));
      const hasMoldy = titles.some(t => t.includes('Moldy'));
      expect(hasClamav).toBe(true);
      expect(hasMoldy).toBe(true);
    });
  });

  describe('checksum', async () => {
    it('should include sha256 checksum on each baseline', async () => {
      const hdf = JSON.parse(await convertConveyorToHdf(loadFixture('sample-results.json'))) as HDFResults;
      for (const baseline of hdf.baselines) {
        expect(baseline.resultsChecksum?.algorithm).toBe('sha256');
        expect(baseline.resultsChecksum?.value).toMatch(/^[a-f0-9]{64}$/);
      }
    });
  });

  describe('generator and tool', async () => {
    it('should set generator name and version', async () => {
      const hdf = JSON.parse(await convertConveyorToHdf(loadFixture('sample-results.json'))) as HDFResults;
      expect(hdf.generator?.name).toBe('conveyor-to-hdf');
      expect(hdf.generator?.version).toBe('1.0.0');
    });

    it('should set tool name to "Conveyor" with no format', async () => {
      const hdf = JSON.parse(await convertConveyorToHdf(loadFixture('sample-results.json'))) as HDFResults;
      expect(hdf.tool?.name).toBe('Conveyor');
      expect(hdf.tool?.format).toBeUndefined() // serialization structures are not formats (kpvj);
    });
  });

  describe('target', async () => {
    it('should set target type to Application', async () => {
      const hdf = JSON.parse(await convertConveyorToHdf(loadFixture('sample-results.json'))) as HDFResults;
      expect(hdf.components).toBeDefined();
      expect(hdf.components![0]!.type).toBe('application');
    });
  });

  describe('score to impact mapping', async () => {
    it('should map score=1000 to impact=1.0', async () => {
      const hdf = JSON.parse(await convertConveyorToHdf(loadFixture('sample-results.json'))) as HDFResults;
      // Moldy baseline has score=1000
      const moldy = hdf.baselines.find(b => b.title?.includes('Moldy'));
      expect(moldy).toBeDefined();
      const hasMax = moldy!.requirements.some(r => r.impact === 1.0);
      expect(hasMax).toBe(true);
    });

    it('should map score=0 to impact=0.0', async () => {
      const hdf = JSON.parse(await convertConveyorToHdf(loadFixture('sample-results.json'))) as HDFResults;
      const moldy = hdf.baselines.find(b => b.title?.includes('Moldy'));
      expect(moldy).toBeDefined();
      const hasZero = moldy!.requirements.some(r => r.impact === 0.0);
      expect(hasZero).toBe(true);
    });
  });

  describe('status mapping', async () => {
    it('should mark score=0 results as passed', async () => {
      const hdf = JSON.parse(await convertConveyorToHdf(loadFixture('sample-results.json'))) as HDFResults;
      const moldy = hdf.baselines.find(b => b.title?.includes('Moldy'));
      expect(moldy).toBeDefined();
      const hasPassed = moldy!.requirements.some(
        r => r.results.some(res => res.status === 'passed')
      );
      expect(hasPassed).toBe(true);
    });

    it('should mark score>0 results as failed', async () => {
      const hdf = JSON.parse(await convertConveyorToHdf(loadFixture('sample-results.json'))) as HDFResults;
      const moldy = hdf.baselines.find(b => b.title?.includes('Moldy'));
      expect(moldy).toBeDefined();
      const hasFailed = moldy!.requirements.some(
        r => r.results.some(res => res.status === 'failed')
      );
      expect(hasFailed).toBe(true);
    });
  });

  describe('requirement structure', async () => {
    it('should use sha256 hash as requirement ID', async () => {
      const hdf = JSON.parse(await convertConveyorToHdf(loadFixture('sample-results.json'))) as HDFResults;
      for (const baseline of hdf.baselines) {
        for (const req of baseline.requirements) {
          expect(req.id).toMatch(/^[a-f0-9]{64}$/);
        }
      }
    });

    it('should map file tree names to requirement titles', async () => {
      const hdf = JSON.parse(await convertConveyorToHdf(loadFixture('sample-results.json'))) as HDFResults;
      const hasTitle = hdf.baselines.some(b =>
        b.requirements.some(r => r.title && r.title.length > 0)
      );
      expect(hasTitle).toBe(true);
    });

    it('should include default description on every requirement', async () => {
      const hdf = JSON.parse(await convertConveyorToHdf(loadFixture('sample-results.json'))) as HDFResults;
      for (const baseline of hdf.baselines) {
        for (const req of baseline.requirements) {
          const hasDefault = req.descriptions?.some(d => d.label === 'default');
          expect(hasDefault).toBe(true);
        }
      }
    });

    it('should include NIST tags on every requirement', async () => {
      const hdf = JSON.parse(await convertConveyorToHdf(loadFixture('sample-results.json'))) as HDFResults;
      for (const baseline of hdf.baselines) {
        for (const req of baseline.requirements) {
          const nist = req.tags?.['nist'] as string[];
          expect(nist).toBeDefined();
          expect(nist.length).toBeGreaterThan(0);
        }
      }
    });
  });

  describe('result structure', async () => {
    it('should include code_desc on every result', async () => {
      const hdf = JSON.parse(await convertConveyorToHdf(loadFixture('sample-results.json'))) as HDFResults;
      for (const baseline of hdf.baselines) {
        for (const req of baseline.requirements) {
          for (const res of req.results) {
            expect(res.codeDesc).toBeTruthy();
          }
        }
      }
    });

    it('should include start_time on every result', async () => {
      const hdf = JSON.parse(await convertConveyorToHdf(loadFixture('sample-results.json'))) as HDFResults;
      for (const baseline of hdf.baselines) {
        for (const req of baseline.requirements) {
          for (const res of req.results) {
            expect(res.startTime).toBeTruthy();
          }
        }
      }
    });
  });

  describe('timestamp', async () => {
    it('should include a timestamp', async () => {
      const hdf = JSON.parse(await convertConveyorToHdf(loadFixture('sample-results.json'))) as HDFResults;
      expect(hdf.timestamp).toBeTruthy();
    });
  });

  describe('edge cases: missing optional fields', async () => {
    it('should handle result with no file_tree', async () => {
      const input = JSON.stringify({
        api_response: {
          results: {
            r1: {
              sha256: 'abc123',
              response: { service_name: 'Moldy' },
              result: { score: 0, sections: [] },
            },
          },
        },
      });
      const hdf = JSON.parse(await convertConveyorToHdf(input)) as HDFResults;
      expect(hdf.baselines).toHaveLength(1);
      const req = hdf.baselines[0]!.requirements[0]!;
      expect(req.title).toBe('');
      expect(req.results[0]!.status).toBe('passed');
    });

    it('should handle score at max (1000) → impact 1.0', async () => {
      const input = JSON.stringify({
        api_response: {
          results: {
            r1: {
              sha256: 'abc',
              response: { service_name: 'Moldy', milestones: {} },
              result: { score: 1000, sections: [{ title_text: 'test', heuristic: { heur_id: 'h1', score: 5, name: 'Test' } }] },
            },
          },
        },
      });
      const hdf = JSON.parse(await convertConveyorToHdf(input)) as HDFResults;
      expect(hdf.baselines[0]!.requirements[0]!.impact).toBe(1.0);
    });

    it('should handle sections with no title_text (desc fallback)', async () => {
      const input = JSON.stringify({
        api_response: {
          results: {
            r1: {
              sha256: 'abc',
              response: { service_name: 'Stigma' },
              result: { score: 100, sections: [{ body: 'body text', body_format: 'text', classification: 'mal', depth: 1 }] },
            },
          },
        },
      });
      const hdf = JSON.parse(await convertConveyorToHdf(input)) as HDFResults;
      const req = hdf.baselines[0]!.requirements[0]!;
      const desc = req.descriptions?.find(d => d.label === 'default');
      expect(desc!.data).toContain('abc');
    });

    it('should handle CodeQuality scanner type', async () => {
      const input = JSON.stringify({
        api_response: {
          results: {
            r1: {
              sha256: 'abc',
              response: { service_name: 'CodeQuality' },
              result: { score: 50, sections: [{ title_text: 'CQ test', body: null, body_format: 'json', classification: 'clean', depth: 0 }] },
            },
          },
        },
      });
      const hdf = JSON.parse(await convertConveyorToHdf(input)) as HDFResults;
      expect(hdf.baselines[0]!.requirements[0]!.results[0]!.codeDesc).toContain('CQ test');
    });

    it('should handle unknown scanner type (JSON fallback)', async () => {
      const input = JSON.stringify({
        api_response: {
          results: {
            r1: {
              sha256: 'abc',
              response: { service_name: 'UnknownScanner' },
              result: { score: 100, sections: [{ title_text: 'test' }] },
            },
          },
        },
      });
      const hdf = JSON.parse(await convertConveyorToHdf(input)) as HDFResults;
      expect(hdf.baselines[0]!.requirements[0]!.results[0]!.codeDesc).toContain('title_text');
    });

    it('should handle params.description for target name', async () => {
      const input = JSON.stringify({
        api_response: {
          results: {
            r1: {
              sha256: 'abc',
              response: { service_name: 'Moldy' },
              result: { score: 0, sections: [] },
            },
          },
          params: { description: 'Custom Target' },
        },
      });
      const hdf = JSON.parse(await convertConveyorToHdf(input)) as HDFResults;
      expect(hdf.components![0]!.name).toBe('Custom Target');
    });

    it('should use default target name when params has no description', async () => {
      const input = JSON.stringify({
        api_response: {
          results: {
            r1: {
              sha256: 'abc',
              response: { service_name: 'Moldy' },
              result: { score: 0, sections: [] },
            },
          },
          params: {},
        },
      });
      const hdf = JSON.parse(await convertConveyorToHdf(input)) as HDFResults;
      expect(hdf.components![0]!.name).toBe('Conveyor Scan');
    });

    it('should synthesize a passed placeholder when results is empty', async () => {
      const hdf = JSON.parse(await convertConveyorToHdf(loadFixture('empty.json'))) as HDFResults;
      expect(hdf.baselines).toHaveLength(1);
      const baseline = hdf.baselines[0]!;
      expect(baseline.requirements).toHaveLength(1);

      const req = baseline.requirements[0]!;
      expect(req.id).toBe('conveyor-no-findings');
      expect(req.results).toHaveLength(1);
      expect(req.results[0]!.status).toBe('passed');

      const codeDesc = req.results[0]!.codeDesc;
      expect(codeDesc).toContain('Conveyor');
      expect(codeDesc).toContain('Inspection of file: submissions/empty.zip');
    });

    it('should handle negative score → impact 0.0', async () => {
      const input = JSON.stringify({
        api_response: {
          results: {
            r1: {
              sha256: 'abc',
              response: { service_name: 'Moldy' },
              result: { score: -5, sections: [] },
            },
          },
        },
      });
      const hdf = JSON.parse(await convertConveyorToHdf(input)) as HDFResults;
      expect(hdf.baselines[0]!.requirements[0]!.impact).toBe(0.0);
    });
  });
});

describe('absent-score handling', () => {
  it('maps a scoreless result to notReviewed @ 0.0 and keeps genuine 0/positive verdicts', async () => {
    const input = JSON.stringify({
      api_error_message: '',
      api_response: {
        file_tree: {
          'sha-absent': { name: ['absent.bin'], sha256: 'sha-absent' },
          'sha-zero': { name: ['zero.bin'], sha256: 'sha-zero' },
          'sha-scored': { name: ['scored.bin'], sha256: 'sha-scored' },
        },
        results: {
          'sha-absent.SvcA.v1.k1': { sha256: 'sha-absent', response: { service_name: 'SvcA', milestones: {} }, result: { sections: [{ title_text: 't', body: null, body_format: 'TEXT', classification: 'TLP:C', depth: 0 }] } },
          'sha-zero.SvcA.v1.k2': { sha256: 'sha-zero', response: { service_name: 'SvcA', milestones: {} }, result: { score: 0, sections: [] } },
          'sha-scored.SvcA.v1.k3': { sha256: 'sha-scored', response: { service_name: 'SvcA', milestones: {} }, result: { score: 500, sections: [] } },
        },
        times: {},
      },
    });
    const hdf = JSON.parse(await convertConveyorToHdf(input)) as HDFResults;
    const all = hdf.baselines.flatMap((b) => b.requirements);
    const byId = (id: string) => all.find((r) => r.id === id);

    const absent = byId('sha-absent');
    expect(absent?.results[0].status).toBe('notReviewed');
    expect(absent?.impact).toBe(0);
    expect(absent?.results[0].message).toContain('no score');

    expect(byId('sha-zero')?.results[0].status).toBe('passed');
    expect(byId('sha-zero')?.impact).toBe(0);
    expect(byId('sha-scored')?.results[0].status).toBe('failed');
    expect(byId('sha-scored')?.impact).toBe(0.5);
  });
});
