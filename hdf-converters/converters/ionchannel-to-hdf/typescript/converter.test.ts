import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { describe, it, expect } from 'vitest';
import { convertIonchannelToHdf } from './converter.js';
import { runConverterContractTests } from '../../../shared/typescript/converter-contract.js';
import { DEFAULT_MAX_INPUT_SIZE } from '../../../shared/typescript/converterutil.js';
import { expectValidResults } from '../../../test/helpers/expectValidHdf.js';
import { assertRequirementCount } from '../../../shared/typescript/anchor.js';
import type { HDFResults } from '@mitre/hdf-schema';

const __dirname = dirname(fileURLToPath(import.meta.url));
const FIXTURES_DIR = join(__dirname, '..', 'fixtures');

function loadFixture(name: string): string {
  return readFileSync(join(FIXTURES_DIR, 'input', name), 'utf-8');
}

// Derive the ground-truth requirement count directly from the raw JSON,
// independent of the converter. The emission model is: one requirement per
// distinct org/name in the flattened "dependency" scan tree, PLUS one per
// non-dependency scan summary. A generic key count would over-count when a
// package appears in two subtrees, so the dedup is re-derived here rather than
// reusing the converter's traversal.
function countEmittedRequirements(input: string): number {
  const doc = JSON.parse(input) as {
    scan_summaries?: Array<{
      name?: string;
      results?: { data?: { dependencies?: unknown[] } };
    }>;
  };
  const seen = new Set<string>();
  const walk = (node: unknown): void => {
    if (node === null || typeof node !== 'object') return;
    const dep = node as { org?: unknown; name?: unknown; dependencies?: unknown[] };
    seen.add(`${String(dep.org)}/${String(dep.name)}`);
    for (const sub of dep.dependencies ?? []) walk(sub);
  };
  let nonDep = 0;
  for (const scan of doc.scan_summaries ?? []) {
    if (scan.name === 'dependency') {
      for (const dep of scan.results?.data?.dependencies ?? []) walk(dep);
    } else {
      nonDep++;
    }
  }
  return seen.size + nonDep;
}

runConverterContractTests({
  converterName: 'ionchannel-to-hdf',
  convertFn: convertIonchannelToHdf,
  minimalFixture: 'minimal.json',
});

// Ground-truth anchor: one requirement per distinct flattened dependency.
describe('ionchannel-to-hdf ground-truth anchor', () => {
  it.each(['minimal.json', 'edge-cases.json'])(
    'emits one requirement per distinct flattened dependency (%s)',
    async (name) => {
      const input = loadFixture(name);
      assertRequirementCount(
        await convertIonchannelToHdf(input),
        countEmittedRequirements(input),
        `${name}: one requirement per distinct flattened dependency plus one per non-dependency scan`,
      );
    },
  );
});

describe('ionchannel to HDF converter', async () => {
  describe('input validation', async () => {
    it('should throw on oversized input', async () => {
      const big = '{' + 'x'.repeat(DEFAULT_MAX_INPUT_SIZE + 1) + '}';
      await expect(convertIonchannelToHdf(big)).rejects.toThrow('exceeds maximum');
    });

    it('should throw when scan_summaries is not an array', async () => {
      // scan_summaries present but the wrong shape (object, not array).
      const input = JSON.stringify({ source: 'x', scan_summaries: { name: 'dependency' } });
      await expect(convertIonchannelToHdf(input)).rejects.toThrow(
        'scan_summaries invalid summary data',
      );
    });
  });

  describe('minimal fixture', async () => {
    it('should produce valid HDF from minimal fixture', async () => {
      const output = await convertIonchannelToHdf(loadFixture('minimal.json'));
      const hdf = JSON.parse(output) as HDFResults;
      expectValidResults(hdf);

      expect(hdf.timestamp).toBeTruthy();
      expect(hdf.generator?.name).toBe('ionchannel-to-hdf');
      expect(hdf.generator?.version).toBe('1.0.0');
      expect(hdf.baselines).toHaveLength(1);
    });

    it('should use "Ion Channel SBOM Analysis" as the baseline name', async () => {
      const hdf = JSON.parse(await convertIonchannelToHdf(loadFixture('minimal.json'))) as HDFResults;
      expect(hdf.baselines[0]!.name).toBe('Ion Channel SBOM Analysis');
    });

    it('should include baseline title with source', async () => {
      const hdf = JSON.parse(await convertIonchannelToHdf(loadFixture('minimal.json'))) as HDFResults;
      expect(hdf.baselines[0]!.title).toBe(
        'Ion Channel Analysis of https://github.com/example-org/example-project.git',
      );
    });

    it('should include data source info', async () => {
      const hdf = JSON.parse(await convertIonchannelToHdf(loadFixture('minimal.json'))) as HDFResults;
      expect(hdf.tool?.name).toBe('Ion Channel');
      expect(hdf.tool?.format).toBeUndefined() // serialization structures are not formats (kpvj);
    });

    it('should flatten 2 top-level + 1 sub-dependency into 3 requirements', async () => {
      const hdf = JSON.parse(await convertIonchannelToHdf(loadFixture('minimal.json'))) as HDFResults;
      expect(hdf.baselines[0]!.requirements).toHaveLength(3);
    });

    it('should produce correct requirement IDs', async () => {
      const hdf = JSON.parse(await convertIonchannelToHdf(loadFixture('minimal.json'))) as HDFResults;
      const ids = hdf.baselines[0]!.requirements.map((r) => r.id);
      expect(ids).toContain('dependency-expressjs/express');
      expect(ids).toContain('dependency-jshttp/accepts');
      expect(ids).toContain('dependency-lodash/lodash');
    });

    it('should build correct title for standard dependency', async () => {
      const hdf = JSON.parse(await convertIonchannelToHdf(loadFixture('minimal.json'))) as HDFResults;
      const req = hdf.baselines[0]!.requirements.find(
        (r) => r.id === 'dependency-expressjs/express',
      );
      expect(req?.title).toBe('Dependency express from expressjs @ 4.18.2 (Required ^4.18.0)');
    });

    it('should set impact to 0.0 for all dependencies', async () => {
      const hdf = JSON.parse(await convertIonchannelToHdf(loadFixture('minimal.json'))) as HDFResults;
      for (const req of hdf.baselines[0]!.requirements) {
        expect(req.impact).toBe(0.0);
      }
    });

    it('should include NIST CM-8 tags', async () => {
      const hdf = JSON.parse(await convertIonchannelToHdf(loadFixture('minimal.json'))) as HDFResults;
      const req = hdf.baselines[0]!.requirements.find(
        (r) => r.id === 'dependency-expressjs/express',
      );
      expect(req?.tags?.nist).toContain('CM-8');
    });

    it('should include tags with metadata', async () => {
      // CM-8 has no CCI mappings, so just verify tags exist with metadata
      const hdf = JSON.parse(await convertIonchannelToHdf(loadFixture('minimal.json'))) as HDFResults;
      const req = hdf.baselines[0]!.requirements.find(
        (r) => r.id === 'dependency-expressjs/express',
      );
      expect(req?.tags).toBeDefined();
      expect(req?.tags?.org).toBe('expressjs');
    });

    it('should surface package and outdated_version in tags', async () => {
      // heimdall2 spreads the whole dependency object into tags; these two
      // fields carry data in the fixture (package="npm", patch_behind=1).
      const hdf = JSON.parse(await convertIonchannelToHdf(loadFixture('minimal.json'))) as HDFResults;
      const express = hdf.baselines[0]!.requirements.find(
        (r) => r.id === 'dependency-expressjs/express',
      );
      expect(express?.tags?.package).toBe('npm');
      expect(express?.tags?.outdated_version).toEqual({
        major_behind: 0,
        minor_behind: 0,
        patch_behind: 1,
      });
    });

    it('should track sub-dependencies in tags', async () => {
      const hdf = JSON.parse(await convertIonchannelToHdf(loadFixture('minimal.json'))) as HDFResults;
      const express = hdf.baselines[0]!.requirements.find(
        (r) => r.id === 'dependency-expressjs/express',
      );
      expect(express?.tags?.dependencies).toContain('accepts');
    });

    it('should track parent dependencies in tags', async () => {
      const hdf = JSON.parse(await convertIonchannelToHdf(loadFixture('minimal.json'))) as HDFResults;
      const accepts = hdf.baselines[0]!.requirements.find(
        (r) => r.id === 'dependency-jshttp/accepts',
      );
      expect(accepts?.tags?.parentDependencies).toContain('expressjs/express');
    });

    it('should include dependency JSON in code field', async () => {
      const hdf = JSON.parse(await convertIonchannelToHdf(loadFixture('minimal.json'))) as HDFResults;
      const lodash = hdf.baselines[0]!.requirements.find(
        (r) => r.id === 'dependency-lodash/lodash',
      );
      expect(lodash?.code).toContain('"name": "lodash"');
      expect(lodash?.code).toContain('"version": "4.17.21"');
    });

    it('should have notReviewed results for all dependencies', async () => {
      const hdf = JSON.parse(await convertIonchannelToHdf(loadFixture('minimal.json'))) as HDFResults;
      for (const req of hdf.baselines[0]!.requirements) {
        expect(req.results).toHaveLength(1);
        expect(req.results[0]!.status).toBe('notReviewed');
      }
    });

    it('should omit controlType (static-fallback NIST resolves to undefined)', async () => {
      // CM-8 is a static-fallback bundle → deriveControlTypeFromTags returns
      // undefined, so no dependency requirement carries a controlType. Mirrors
      // the Go twin's TestConvertIonChannelToHDF_ControlType.
      const hdf = JSON.parse(await convertIonchannelToHdf(loadFixture('minimal.json'))) as HDFResults;
      for (const req of hdf.baselines[0]!.requirements) {
        expect(req.controlType).toBeUndefined();
      }
    });

    it('should include sha256 integrity', async () => {
      const hdf = JSON.parse(await convertIonchannelToHdf(loadFixture('minimal.json'))) as HDFResults;
      expect(hdf.baselines[0]!.integrity?.algorithm).toBe('sha256');
      expect(hdf.baselines[0]!.integrity?.checksum).toBeTruthy();
    });
  });

  describe('edge cases fixture', async () => {
    it('should handle Python editable install', async () => {
      const hdf = JSON.parse(await convertIonchannelToHdf(loadFixture('edge-cases.json'))) as HDFResults;
      const req = hdf.baselines[0]!.requirements.find(
        (r) => r.id === 'dependency-n/a/-e',
      );
      expect(req?.title).toBe('Python requirements file requirements.txt');
    });

    it('should omit n/a fields from title', async () => {
      const hdf = JSON.parse(await convertIonchannelToHdf(loadFixture('edge-cases.json'))) as HDFResults;
      const req = hdf.baselines[0]!.requirements.find(
        (r) => r.id === 'dependency-n/a/requests',
      );
      expect(req?.title).toBe('Dependency requests @ 2.31.0');
    });

    it('should omit n/a version from title', async () => {
      const hdf = JSON.parse(await convertIonchannelToHdf(loadFixture('edge-cases.json'))) as HDFResults;
      const req = hdf.baselines[0]!.requirements.find(
        (r) => r.id === 'dependency-example-corp/internal-lib',
      );
      expect(req?.title).toBe('Dependency internal-lib from example-corp (Required >=0.5.0)');
    });

    it('should keep the dependency baseline to its 3 deps', async () => {
      const hdf = JSON.parse(await convertIonchannelToHdf(loadFixture('edge-cases.json'))) as HDFResults;
      const dep = hdf.baselines.find((b) => b.name === 'Ion Channel SBOM Analysis');
      expect(dep?.requirements).toHaveLength(3);
    });

    it('should emit a baseline + requirement for the community scan', async () => {
      const hdf = JSON.parse(await convertIonchannelToHdf(loadFixture('edge-cases.json'))) as HDFResults;
      const community = hdf.baselines.find((b) => b.name === 'Ion Channel community Scan');
      expect(community?.requirements).toHaveLength(1);

      const req = community!.requirements[0]!;
      expect(req.id).toBe('scan-community');
      expect(req.title).toBe('Community analysis');
      expect(req.descriptions?.[0]?.data).toBe('Community scan completed');
      expect(req.tags?.name).toBe('community');
      expect(req.tags?.type).toBe('community');
      expect(req.results[0]!.status).toBe('notReviewed');
      // Serializable scan data is preserved in the code field.
      expect(req.code).toContain('"committers": 5');
      expect(req.code).toContain('"stars": 42');
    });

    it('should surface the analysis verdict on the primary baseline', async () => {
      const hdf = JSON.parse(await convertIonchannelToHdf(loadFixture('edge-cases.json'))) as HDFResults;
      const dep = hdf.baselines.find((b) => b.name === 'Ion Channel SBOM Analysis')!;
      expect(dep.description).toContain('FAILED');
      expect(dep.description).toContain('medium');
      expect(dep.description).toContain('strict');
      expect(dep.labels?.passed).toBe('false');
      expect(dep.labels?.risk).toBe('medium');
      expect(dep.labels?.ruleset_name).toBe('strict');
      expect(dep.labels?.ruleset_id).toBe('ruleset-002');
    });
  });

  // Fallback-default branches: scans and verdicts whose optional source fields
  // are absent. Exercises the `||`/`??`/`if` fallback sides the fixtures don't.
  describe('fallback defaults', async () => {
    it('falls back scan title/desc/type/code and empty dependency data', async () => {
      const input = JSON.stringify({
        source: 'https://example.com/repo.git',
        summary: '',
        passed: true,
        ruleset_name: 'foo', // present, but ruleset_id absent (verdictDescription inner branch)
        scan_summaries: [
          // dependency scan with no `dependencies` key → allDeps falls back to []
          { name: 'dependency', results: { type: 'dependency', data: {} } },
          // license scan with no description/summary and results lacking type/data
          { name: 'license', results: {} },
        ],
      });
      const hdf = JSON.parse(await convertIonchannelToHdf(input)) as HDFResults;

      const dep = hdf.baselines.find((b) => b.name === 'Ion Channel SBOM Analysis')!;
      expect(dep.requirements).toHaveLength(0);
      // verdictDescription: ruleset_name present, ruleset_id absent → no "(id)" suffix.
      expect(dep.description).toBe('Ion Channel analysis verdict: PASSED. Ruleset: foo.');

      const license = hdf.baselines.find((b) => b.name === 'Ion Channel license Scan')!;
      const req = license.requirements[0]!;
      expect(req.title).toBe('License scan');
      expect(req.descriptions?.[0]?.data).toBe('License scan summary');
      expect(req.tags?.type).toBe('');
      expect(req.code).toBe('{}');
    });
  });

  // The shared snapshot masks the top-level timestamp, so these pin the exact
  // source-derived values the golden cannot verify.
  describe('timestamp backfill', async () => {
    it('sets the top-level timestamp from analysis updated_at', async () => {
      // minimal.json analysis updated_at = 2024-01-15T10:35:00Z (scan completion).
      const hdf = JSON.parse(await convertIonchannelToHdf(loadFixture('minimal.json'))) as HDFResults;
      expect(hdf.timestamp).toBe('2024-01-15T10:35:00Z');
    });

    it('sets a scan-summary result startTime from the scan created_at', async () => {
      // edge-cases.json community scan created_at = 2024-02-20T14:00:00Z.
      const hdf = JSON.parse(await convertIonchannelToHdf(loadFixture('edge-cases.json'))) as HDFResults;
      const community = hdf.baselines.find((b) => b.name === 'Ion Channel community Scan')!;
      expect(community.requirements[0]!.results[0]!.startTime).toBe('2024-02-20T14:00:00Z');
    });

    it('falls back to analysis created_at when updated_at is absent', async () => {
      const input = JSON.stringify({
        source: 'https://example.com/repo.git',
        summary: '',
        passed: true,
        created_at: '2024-03-14T09:00:00Z',
        scan_summaries: [
          { name: 'dependency', summary: '', results: { type: 'dependency', data: { dependencies: [] } } },
        ],
      });
      const hdf = JSON.parse(await convertIonchannelToHdf(input)) as HDFResults;
      expect(hdf.timestamp).toBe('2024-03-14T09:00:00Z');
    });

    it('falls back to a valid now() when the analysis carries no time', async () => {
      const input = JSON.stringify({
        source: 'https://example.com/repo.git',
        summary: '',
        passed: true,
        scan_summaries: [
          { name: 'dependency', summary: '', results: { type: 'dependency', data: { dependencies: [] } } },
        ],
      });
      const hdf = JSON.parse(await convertIonchannelToHdf(input)) as HDFResults;
      expect(hdf.timestamp).toBeTruthy();
      expect(new Date(hdf.timestamp!).getTime()).toBeGreaterThan(0);
    });

    it('falls back scan startTime to updated_at then the sentinel', async () => {
      const input = JSON.stringify({
        source: 'https://example.com/repo.git',
        summary: '',
        passed: true,
        scan_summaries: [
          { name: 'dependency', summary: '', results: { type: 'dependency', data: { dependencies: [] } } },
          // created_at absent → updated_at wins.
          { name: 'community', summary: 's', updated_at: '2024-05-06T07:08:09Z', results: { type: 'community', data: {} } },
          // neither present → zero sentinel, mirroring Go's zero time.Time.
          { name: 'license', summary: 's', results: { type: 'license', data: {} } },
        ],
      });
      const hdf = JSON.parse(await convertIonchannelToHdf(input)) as HDFResults;
      const community = hdf.baselines.find((b) => b.name === 'Ion Channel community Scan')!;
      expect(community.requirements[0]!.results[0]!.startTime).toBe('2024-05-06T07:08:09Z');
      const license = hdf.baselines.find((b) => b.name === 'Ion Channel license Scan')!;
      expect(license.requirements[0]!.results[0]!.startTime).toBe('0001-01-01T00:00:00Z');
    });
  });

  describe('analysis-level verdict tags on requirements', async () => {
    it('should tag dependency requirements with the analysis verdict (passed=false)', async () => {
      const hdf = JSON.parse(await convertIonchannelToHdf(loadFixture('edge-cases.json'))) as HDFResults;
      const req = hdf.baselines[0]!.requirements.find((r) => r.id === 'dependency-n/a/requests')!;
      expect(req.tags?.passed).toBe(false);
      expect(req.tags?.risk).toBe('medium');
      expect(req.tags?.ruleset_name).toBe('strict');
      expect(req.tags?.ruleset_id).toBe('ruleset-002');
    });

    it('should tag non-dependency scan requirements with the analysis verdict', async () => {
      const hdf = JSON.parse(await convertIonchannelToHdf(loadFixture('edge-cases.json'))) as HDFResults;
      const community = hdf.baselines.find((b) => b.name === 'Ion Channel community Scan')!;
      const req = community.requirements[0]!;
      expect(req.tags?.passed).toBe(false);
      expect(req.tags?.risk).toBe('medium');
      expect(req.tags?.ruleset_name).toBe('strict');
      expect(req.tags?.ruleset_id).toBe('ruleset-002');
    });

    it('should carry passed=true as a native boolean', async () => {
      const hdf = JSON.parse(await convertIonchannelToHdf(loadFixture('minimal.json'))) as HDFResults;
      const req = hdf.baselines[0]!.requirements.find((r) => r.id === 'dependency-expressjs/express')!;
      expect(req.tags?.passed).toBe(true);
      expect(req.tags?.risk).toBe('low');
      expect(req.tags?.ruleset_name).toBe('default');
      expect(req.tags?.ruleset_id).toBe('ruleset-001');
    });

    it('should omit empty verdict fields while keeping passed', async () => {
      const input = JSON.stringify({
        source: 'https://example.com/repo.git',
        summary: '',
        risk: '',
        passed: true,
        ruleset_id: '',
        ruleset_name: '',
        scan_summaries: [
          {
            name: 'dependency',
            summary: '',
            results: {
              type: 'dependency',
              data: {
                dependencies: [
                  { org: 'acme', name: 'widget', type: 'npm', version: '1.0.0', dependencies: [] },
                ],
              },
            },
          },
        ],
      });
      const hdf = JSON.parse(await convertIonchannelToHdf(input)) as HDFResults;
      const req = hdf.baselines[0]!.requirements.find((r) => r.id === 'dependency-acme/widget')!;
      expect(req.tags?.passed).toBe(true);
      expect(req.tags && 'risk' in req.tags).toBe(false);
      expect(req.tags && 'ruleset_name' in req.tags).toBe(false);
      expect(req.tags && 'ruleset_id' in req.tags).toBe(false);
    });
  });

  describe('auxiliary tool metadata (extensions + namespaced tags)', async () => {
    it('surfaces run-scope metadata in baseline.extensions.ionchannel', async () => {
      // All fields below carry data in minimal.json; text is "" so it is omitted.
      const hdf = JSON.parse(await convertIonchannelToHdf(loadFixture('minimal.json'))) as HDFResults;
      const dep = hdf.baselines.find((b) => b.name === 'Ion Channel SBOM Analysis')!;
      const ion = dep.extensions?.ionchannel as Record<string, unknown>;
      expect(ion).toEqual({
        id: 'a1b2c3d4-e5f6-7890-abcd-ef1234567890',
        analysis_id: 'analysis-001-abcdef',
        team_id: 'team-001-ghijkl',
        project_id: 'project-001-mnopqr',
        name: 'example-project',
        type: 'git',
        branch: 'main',
        description: 'Example project for dependency analysis',
        status: 'finished',
        duration: 12345,
        public: false,
      });
    });

    it('emits run-scope metadata once, only on the primary baseline', async () => {
      const hdf = JSON.parse(await convertIonchannelToHdf(loadFixture('edge-cases.json'))) as HDFResults;
      const community = hdf.baselines.find((b) => b.name === 'Ion Channel community Scan')!;
      expect(community.extensions).toBeUndefined();
    });

    it('omits absent run-metadata fields and the extensions block entirely', async () => {
      // No homeless run metadata → extensions omitted.
      const input = JSON.stringify({
        source: 'https://example.com/repo.git',
        summary: '',
        passed: true,
        scan_summaries: [
          { name: 'dependency', summary: '', results: { type: 'dependency', data: { dependencies: [] } } },
        ],
      });
      const hdf = JSON.parse(await convertIonchannelToHdf(input)) as HDFResults;
      const dep = hdf.baselines.find((b) => b.name === 'Ion Channel SBOM Analysis')!;
      expect(dep.extensions).toBeUndefined();
    });

    it('emits public:false but omits absent sibling fields', async () => {
      const input = JSON.stringify({
        source: 'https://example.com/repo.git',
        summary: '',
        passed: true,
        name: 'proj',
        public: false,
        scan_summaries: [
          { name: 'dependency', summary: '', results: { type: 'dependency', data: { dependencies: [] } } },
        ],
      });
      const hdf = JSON.parse(await convertIonchannelToHdf(input)) as HDFResults;
      const dep = hdf.baselines.find((b) => b.name === 'Ion Channel SBOM Analysis')!;
      const ion = dep.extensions?.ionchannel as Record<string, unknown>;
      expect(ion).toEqual({ name: 'proj', public: false });
    });

    it('tags dependency requirements with namespaced trigger fields', async () => {
      const hdf = JSON.parse(await convertIonchannelToHdf(loadFixture('minimal.json'))) as HDFResults;
      const req = hdf.baselines[0]!.requirements.find((r) => r.id === 'dependency-expressjs/express')!;
      expect(req.tags?.['ionchannel/trigger_hash']).toBe('abc123def456');
      expect(req.tags?.['ionchannel/trigger_text']).toBe('feat: add new feature');
      expect(req.tags?.['ionchannel/trigger_author']).toBe('developer@example.com');
      expect(req.tags?.['ionchannel/trigger']).toBe('source_commit');
    });

    it('tags non-dependency scan requirements with namespaced trigger fields', async () => {
      const hdf = JSON.parse(await convertIonchannelToHdf(loadFixture('edge-cases.json'))) as HDFResults;
      const community = hdf.baselines.find((b) => b.name === 'Ion Channel community Scan')!;
      const req = community.requirements[0]!;
      expect(req.tags?.['ionchannel/trigger_hash']).toBe('def789ghi012');
      expect(req.tags?.['ionchannel/trigger_text']).toBe('fix: update deps');
      expect(req.tags?.['ionchannel/trigger_author']).toBe('admin@example.com');
      expect(req.tags?.['ionchannel/trigger']).toBe('source_commit');
    });

    it('omits namespaced trigger tags when the analysis carries no triggers', async () => {
      const input = JSON.stringify({
        source: 'https://example.com/repo.git',
        summary: '',
        passed: true,
        scan_summaries: [
          {
            name: 'dependency',
            summary: '',
            results: {
              type: 'dependency',
              data: { dependencies: [{ org: 'acme', name: 'widget', type: 'npm', version: '1.0.0', dependencies: [] }] },
            },
          },
        ],
      });
      const hdf = JSON.parse(await convertIonchannelToHdf(input)) as HDFResults;
      const req = hdf.baselines[0]!.requirements.find((r) => r.id === 'dependency-acme/widget')!;
      const triggerKeys = Object.keys(req.tags ?? {}).filter((k) => k.startsWith('ionchannel/'));
      expect(triggerKeys).toEqual([]);
    });
  });
});
