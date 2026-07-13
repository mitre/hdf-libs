import { describe, it, expect } from 'vitest';
import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { convertSplunkToHdf } from './converter.js';
import { runConverterContractTests } from '../../../shared/typescript/converter-contract.js';
import { expectValidResults } from '../../../test/helpers/expectValidHdf.js';
import type { HDFResults } from '@mitre/hdf-schema';

const __dirname = dirname(fileURLToPath(import.meta.url));

runConverterContractTests({
  converterName: 'splunk-to-hdf',
  convertFn: convertSplunkToHdf,
  minimalFixture: 'splunk-events.json',
});

describe('timestamp parse fallback', () => {
  it('falls back to a valid startTime when result.start_time is unparseable', async () => {
    const input = loadFixture('splunk-events.json').replace(/2019-11-04T16:17:17-05:00/g, 'not-a-date');
    const hdf = JSON.parse(await convertSplunkToHdf(input)) as HDFResults;
    expectValidResults(hdf);
  });
});

function loadFixture(name: string): string {
  return readFileSync(join(__dirname, `../fixtures/input/${name}`), 'utf-8');
}

describe('Splunk to HDF Converter', () => {
  describe('convertSplunkToHdf - events fixture', () => {
    it('should convert Splunk events to HDF', async () => {
      const input = loadFixture('splunk-events.json');
      const result = await convertSplunkToHdf(input);
      expect(result).toBeTruthy();

      const hdf: HDFResults = JSON.parse(result);
      expectValidResults(hdf);
      expect(hdf.baselines).toBeInstanceOf(Array);
      expect(hdf.baselines.length).toBe(1);
      expect(hdf.generator?.name).toBe('splunk-to-hdf');
    });

    it('should produce the correct baseline name', async () => {
      const input = loadFixture('splunk-events.json');
      const hdf: HDFResults = JSON.parse(await convertSplunkToHdf(input));
      expect(hdf.baselines[0]!.name).toBe('disa_stig-el7');
    });

    it('should produce 6 requirements from 6 control events', async () => {
      const input = loadFixture('splunk-events.json');
      const hdf: HDFResults = JSON.parse(await convertSplunkToHdf(input));
      expect(hdf.baselines[0]!.requirements.length).toBe(6);
    });

    it('should preserve control IDs', async () => {
      const input = loadFixture('splunk-events.json');
      const hdf: HDFResults = JSON.parse(await convertSplunkToHdf(input));
      const ids = hdf.baselines[0]!.requirements.map(r => r.id).sort();
      expect(ids).toContain('V-78997');
      expect(ids).toContain('V-77825');
      expect(ids).toContain('V-77821');
    });
  });

  describe('convertSplunkToHdf - minimal fixture', () => {
    it('should convert minimal Splunk input', async () => {
      const input = loadFixture('splunk-minimal.json');
      const hdf: HDFResults = JSON.parse(await convertSplunkToHdf(input));

      expect(hdf.baselines.length).toBe(1);
      expect(hdf.baselines[0]!.requirements.length).toBe(1);
      expect(hdf.baselines[0]!.requirements[0]!.results.length).toBe(1);
    });

    it('should produce a passed result from minimal fixture', async () => {
      const input = loadFixture('splunk-minimal.json');
      const hdf: HDFResults = JSON.parse(await convertSplunkToHdf(input));
      expect(hdf.baselines[0]!.requirements[0]!.results[0]!.status).toBe('passed');
    });
  });

  describe('convertSplunkToHdf - descriptions', () => {
    it('should convert description objects to arrays', async () => {
      const input = loadFixture('splunk-events.json');
      const hdf: HDFResults = JSON.parse(await convertSplunkToHdf(input));

      for (const req of hdf.baselines[0]!.requirements) {
        expect(req.descriptions).toBeInstanceOf(Array);
        for (const desc of req.descriptions) {
          expect(desc).toHaveProperty('label');
          expect(desc).toHaveProperty('data');
        }
      }
    });

    it('should have default, check, and fix labels', async () => {
      const input = loadFixture('splunk-events.json');
      const hdf: HDFResults = JSON.parse(await convertSplunkToHdf(input));

      const firstReq = hdf.baselines[0]!.requirements[0]!;
      const labels = firstReq.descriptions.map((d: { label: string }) => d.label);
      expect(labels).toContain('default');
      expect(labels).toContain('check');
      expect(labels).toContain('fix');
    });
  });

  describe('convertSplunkToHdf - tags', () => {
    it('should preserve NIST tags from controls', async () => {
      const input = loadFixture('splunk-events.json');
      const hdf: HDFResults = JSON.parse(await convertSplunkToHdf(input));

      const firstReq = hdf.baselines[0]!.requirements[0]!;
      expect(firstReq.tags).toBeDefined();
      expect(firstReq.tags.nist).toBeDefined();
      expect(Array.isArray(firstReq.tags.nist)).toBe(true);
    });

    it('should preserve CCI tags from controls', async () => {
      const input = loadFixture('splunk-events.json');
      const hdf: HDFResults = JSON.parse(await convertSplunkToHdf(input));

      const firstReq = hdf.baselines[0]!.requirements[0]!;
      expect(firstReq.tags.cci).toBeDefined();
    });
  });

  describe('convertSplunkToHdf - result status mapping', () => {
    it('should have both passed and failed results', async () => {
      const input = loadFixture('splunk-events.json');
      const hdf: HDFResults = JSON.parse(await convertSplunkToHdf(input));

      const statuses = new Set<string>();
      for (const req of hdf.baselines[0]!.requirements) {
        for (const res of req.results) {
          statuses.add(res.status);
        }
      }
      expect(statuses.has('passed')).toBe(true);
      expect(statuses.has('failed')).toBe(true);
    });
  });

  describe('convertSplunkToHdf - target', () => {
    it('should set target from header platform', async () => {
      const input = loadFixture('splunk-events.json');
      const hdf: HDFResults = JSON.parse(await convertSplunkToHdf(input));

      expect(hdf.components.length).toBeGreaterThan(0);
      expect(hdf.components[0]!.name).toBe('centos');
    });
  });

  describe('convertSplunkToHdf - impact', () => {
    it('should preserve impact from control', async () => {
      const input = loadFixture('splunk-events.json');
      const hdf: HDFResults = JSON.parse(await convertSplunkToHdf(input));

      for (const req of hdf.baselines[0]!.requirements) {
        expect(req.impact).toBe(0.5);
      }
    });
  });

  describe('convertSplunkToHdf - source location', () => {
    it('should preserve source location from controls', async () => {
      const input = loadFixture('splunk-events.json');
      const hdf: HDFResults = JSON.parse(await convertSplunkToHdf(input));

      const withSrcLoc = hdf.baselines[0]!.requirements.filter(
        (r: { sourceLocation?: unknown }) => r.sourceLocation,
      );
      expect(withSrcLoc.length).toBeGreaterThan(0);
    });
  });

  describe('convertSplunkToHdf - generator', () => {
    it('should set generator name', async () => {
      const input = loadFixture('splunk-events.json');
      const hdf: HDFResults = JSON.parse(await convertSplunkToHdf(input));
      expect(hdf.generator?.name).toBe('splunk-to-hdf');
    });
  });

  describe('convertSplunkToHdf - checksum', () => {
    it('should set resultsChecksum on baseline', async () => {
      const input = loadFixture('splunk-events.json');
      const hdf: HDFResults = JSON.parse(await convertSplunkToHdf(input));

      const baseline = hdf.baselines[0]!;
      expect(baseline.resultsChecksum).toBeDefined();
      expect(baseline.resultsChecksum?.algorithm).toBe('sha256');
      expect(baseline.resultsChecksum?.value).toHaveLength(64);
    });
  });

  describe('convertSplunkToHdf - profile fields', () => {
    it('should set profile title and version', async () => {
      const input = loadFixture('splunk-events.json');
      const hdf: HDFResults = JSON.parse(await convertSplunkToHdf(input));

      const baseline = hdf.baselines[0]!;
      expect(baseline.title).toBe('DISA RedHat Enterprise Linux 7 STIG - v1r4');
      expect(baseline.version).toBe('0.2.0');
    });

    it('should include groups', async () => {
      const input = loadFixture('splunk-events.json');
      const hdf: HDFResults = JSON.parse(await convertSplunkToHdf(input));

      const baseline = hdf.baselines[0]!;
      expect(baseline.groups).toBeDefined();
      expect(baseline.groups!.length).toBeGreaterThan(0);
    });
  });

  describe('convertSplunkToHdf - error handling', () => {
    it('should throw on empty array', async () => {
      await expect(convertSplunkToHdf('[]')).rejects.toThrow('No Splunk events found');
    });

    it('should throw when no header event present', async () => {
      const noHeader = JSON.stringify([{
        meta: {
          guid: 'test', subtype: 'control', hdf_splunk_schema: '1.0',
          filetype: 'evaluation', filename: 'test.json', profile_sha256: 'abc',
        },
        id: 'V-12345', title: 'Test', desc: '', descriptions: {},
        impact: 0.5, code: '', tags: {}, results: [], refs: [],
      }]);
      await expect(convertSplunkToHdf(noHeader)).rejects.toThrow('Expected 1 header event');
    });
  });

  describe('convertSplunkToHdf - multiple results per control', () => {
    it('should handle controls with multiple results', async () => {
      const input = loadFixture('splunk-events.json');
      const hdf: HDFResults = JSON.parse(await convertSplunkToHdf(input));

      const multiResult = hdf.baselines[0]!.requirements.find(
        r => r.results.length > 1,
      );
      expect(multiResult).toBeDefined();
    });
  });

  describe('edge cases: status mapping and optional fields', () => {
    function makeEvents(opts: { status?: string; noResults?: boolean; noDescs?: boolean; noGroups?: boolean; noProfile?: boolean; noRelease?: boolean }): string {
      return JSON.stringify([
        {
          meta: { guid: 'g1', subtype: 'header' },
          platform: { name: 'host1', release: opts.noRelease ? '' : 'Ubuntu 22' },
          statistics: { duration: 10 },
          version: '1.0',
        },
        {
          meta: { guid: 'g1', subtype: 'profile' },
          name: 'TestProfile',
          sha256: 'sha1',
          title: opts.noProfile ? '' : 'Profile Title',
          version: opts.noProfile ? '' : '1.0',
          summary: opts.noProfile ? '' : 'Summary',
          groups: opts.noGroups ? undefined : [{ id: 'g1', controls: ['ctrl-1'] }],
        },
        {
          meta: { guid: 'g1', subtype: 'control', profile_sha256: 'sha1' },
          id: 'ctrl-1',
          title: 'Control 1',
          desc: '',
          descriptions: opts.noDescs ? undefined : { default: 'Default desc', check: 'Check desc' },
          impact: 0.5,
          code: '',
          tags: { nist: ['AC-1'] },
          results: opts.noResults ? [] : [{
            status: opts.status ?? 'passed',
            code_desc: 'Test code',
            start_time: '2025-01-01T00:00:00Z',
            run_time: 0.5,
            message: 'msg',
          }],
          source_location: { ref: 'test.rb', line: 1 },
        },
      ]);
    }

    it('should map skipped status to notReviewed', async () => {
      const hdf = JSON.parse(await convertSplunkToHdf(makeEvents({ status: 'skipped' }))) as HDFResults;
      expect(hdf.baselines[0]!.requirements[0]!.results[0]!.status).toBe('notReviewed');
    });

    it('should map error status to error', async () => {
      const hdf = JSON.parse(await convertSplunkToHdf(makeEvents({ status: 'error' }))) as HDFResults;
      expect(hdf.baselines[0]!.requirements[0]!.results[0]!.status).toBe('error');
    });

    it('should map unknown status to notReviewed', async () => {
      const hdf = JSON.parse(await convertSplunkToHdf(makeEvents({ status: 'unknown' }))) as HDFResults;
      expect(hdf.baselines[0]!.requirements[0]!.results[0]!.status).toBe('notReviewed');
    });

    it('should handle control with no results', async () => {
      const hdf = JSON.parse(await convertSplunkToHdf(makeEvents({ noResults: true }))) as HDFResults;
      expect(hdf.baselines[0]!.requirements[0]!.results).toHaveLength(0);
    });

    it('should fall back to a default description when the control has none', async () => {
      const hdf = JSON.parse(await convertSplunkToHdf(makeEvents({ noDescs: true }))) as HDFResults;
      expect(hdf.baselines[0]!.requirements[0]!.descriptions).toEqual([
        { label: 'default', data: '' },
      ]);
    });

    it('should handle profile with no groups/title/version/summary', async () => {
      const hdf = JSON.parse(await convertSplunkToHdf(makeEvents({ noGroups: true, noProfile: true }))) as HDFResults;
      expect(hdf.baselines).toHaveLength(1);
    });

    it('should handle empty release', async () => {
      const hdf = JSON.parse(await convertSplunkToHdf(makeEvents({ noRelease: true }))) as HDFResults;
      expect(hdf.components![0]!.osName).toBeUndefined();
    });

    it('should handle control with no source_location', async () => {
      const events = JSON.parse(makeEvents({}));
      delete events[2].source_location;
      const hdf = JSON.parse(await convertSplunkToHdf(JSON.stringify(events))) as HDFResults;
      expect(hdf.baselines[0]!.requirements[0]!.sourceLocation).toBeUndefined();
    });
  });
});
