import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { describe, it, expect } from 'vitest';
import { convertConveyorToHdf } from './converter.js';
import { runConverterContractTests } from '../../../shared/typescript/converter-contract.js';
import { expectValidResults } from '../../../test/helpers/expectValidHdf.js';
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

    it('should set tool name to "Conveyor" and format to "JSON"', async () => {
      const hdf = JSON.parse(await convertConveyorToHdf(loadFixture('sample-results.json'))) as HDFResults;
      expect(hdf.tool?.name).toBe('Conveyor');
      expect(hdf.tool?.format).toBe('JSON');
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
