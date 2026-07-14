import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { describe, it, expect } from 'vitest';
import { convertTrufflehogToHdf } from './converter.js';
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
  converterName: 'trufflehog-to-hdf',
  convertFn: convertTrufflehogToHdf,
  minimalFixture: 'minimal.json',
});

// countDistinctTrufflehogGroups parses raw TruffleHog output generically — NOT
// via the converter's parser — and returns the number of distinct
// "DetectorName DecoderName" groups. TruffleHog's emission unit is that group
// (findings sharing a detector+decoder collapse into one requirement with many
// results), so a plain findings count would overshoot. Accepts the same three
// input shapes the converter does: JSON array, single JSON object, or NDJSON.
function countDistinctTrufflehogGroups(input: string): number {
  type Finding = { DetectorName?: string; DecoderName?: string };
  let findings: Finding[];
  try {
    const parsed = JSON.parse(input) as Finding | Finding[];
    findings = Array.isArray(parsed) ? parsed : [parsed];
  } catch {
    findings = input
      .trim()
      .split('\n')
      .filter((line) => line.trim().length > 0)
      .map((line) => JSON.parse(line) as Finding);
  }
  const distinct = new Set(findings.map((f) => `${f.DetectorName ?? ''} ${f.DecoderName ?? ''}`));
  return distinct.size;
}

// Ground-truth anchor (input-derived count; see shared/typescript/anchor.ts):
// one requirement per DISTINCT DetectorName+DecoderName group, counted
// independently of the converter's parser so a silent under-extraction fails
// even when Go/TS agree. multi-detector.json's 3 findings collapse to 2 groups.
describe('trufflehog-to-hdf ground-truth anchor', () => {
  it('emits one requirement per distinct DetectorName+DecoderName', async () => {
    const input = loadFixture('multi-detector.json');
    assertRequirementCount(
      await convertTrufflehogToHdf(input),
      countDistinctTrufflehogGroups(input),
      'multi-detector.json: one requirement per distinct DetectorName+DecoderName',
    );
  });
});

describe('trufflehog to HDF converter', async () => {
  describe('empty findings', async () => {
    it('should synthesize a passed placeholder requirement when input has no findings', async () => {
      const output = await convertTrufflehogToHdf(loadFixture('empty.json'));
      const hdf = JSON.parse(output) as HDFResults;

      expect(hdf.baselines).toHaveLength(1);
      expect(hdf.baselines[0]!.requirements).toHaveLength(1);

      const req = hdf.baselines[0]!.requirements[0]!;
      expect(req.id).toBe('trufflehog-no-findings');
      expect(req.results).toHaveLength(1);
      expect(req.results[0]!.status).toBe('passed');
      expect(req.results[0]!.codeDesc).toContain('TruffleHog');
      expect(req.results[0]!.codeDesc).toContain('scanned');
    });
  });

  describe('minimal fixture (single object)', async () => {
    it('should produce valid HDF from single-object fixture', async () => {
      const output = await convertTrufflehogToHdf(loadFixture('minimal.json'));
      const hdf = JSON.parse(output) as HDFResults;
      expectValidResults(hdf);

      expect(hdf.baselines).toHaveLength(1);
      // Single AWS finding → 1 requirement with 1 result
      expect(hdf.baselines[0]!.requirements).toHaveLength(1);
      expect(hdf.baselines[0]!.requirements[0]!.results).toHaveLength(1);
    });

    it('should use "TruffleHog Scan" as the baseline name', async () => {
      const hdf = JSON.parse(await convertTrufflehogToHdf(loadFixture('minimal.json'))) as HDFResults;
      expect(hdf.baselines[0]!.name).toBe('TruffleHog Scan');
    });

    it('should set impact to 0.5 for all findings', async () => {
      const hdf = JSON.parse(await convertTrufflehogToHdf(loadFixture('minimal.json'))) as HDFResults;
      expect(hdf.baselines[0]!.requirements[0]!.impact).toBe(0.5);
    });

    it('should set NIST tag to IA-5 (7)', async () => {
      const hdf = JSON.parse(await convertTrufflehogToHdf(loadFixture('minimal.json'))) as HDFResults;
      const tags = hdf.baselines[0]!.requirements[0]!.tags;
      expect(tags?.['nist']).toEqual(['IA-5 (7)']);
    });

    it('should set CCI tags', async () => {
      const hdf = JSON.parse(await convertTrufflehogToHdf(loadFixture('minimal.json'))) as HDFResults;
      const tags = hdf.baselines[0]!.requirements[0]!.tags;
      const cci = tags?.['cci'] as string[];
      expect(cci).toContain('CCI-000202');
      expect(cci).toContain('CCI-000203');
      expect(cci).toContain('CCI-002367');
    });

    it('should mark all results as failed', async () => {
      const hdf = JSON.parse(await convertTrufflehogToHdf(loadFixture('minimal.json'))) as HDFResults;
      for (const req of hdf.baselines[0]!.requirements) {
        for (const result of req.results) {
          expect(result.status).toBe('failed');
        }
      }
    });

    it('should include source info in CodeDesc', async () => {
      const hdf = JSON.parse(await convertTrufflehogToHdf(loadFixture('minimal.json'))) as HDFResults;
      const codeDesc = hdf.baselines[0]!.requirements[0]!.results[0]?.codeDesc ?? '';
      expect(codeDesc).toContain('new_key');
      expect(codeDesc).toContain('0416560b');
      expect(codeDesc).toContain('Git');
    });

    it('should include Verified and Redacted in Message', async () => {
      const hdf = JSON.parse(await convertTrufflehogToHdf(loadFixture('minimal.json'))) as HDFResults;
      const msg = hdf.baselines[0]!.requirements[0]!.results[0]?.message ?? '';
      expect(msg).toContain('Verified');
      expect(msg).toContain('Redacted');
    });

    it('should include a sha256 checksum', async () => {
      const hdf = JSON.parse(await convertTrufflehogToHdf(loadFixture('minimal.json'))) as HDFResults;
      const checksum = hdf.baselines[0]!.resultsChecksum;
      expect(checksum?.algorithm).toBe('sha256');
      expect(checksum?.value).toMatch(/^[a-f0-9]{64}$/);
    });

    it('should set generator name to "trufflehog-to-hdf"', async () => {
      const hdf = JSON.parse(await convertTrufflehogToHdf(loadFixture('minimal.json'))) as HDFResults;
      expect(hdf.generator?.name).toBe('trufflehog-to-hdf');
      expect(hdf.generator?.version).toBe('1.0.0');
    });

    it('should set tool to TruffleHog/JSON', async () => {
      const hdf = JSON.parse(await convertTrufflehogToHdf(loadFixture('minimal.json'))) as HDFResults;
      expect(hdf.tool?.name).toBe('TruffleHog');
      expect(hdf.tool?.format).toBe('JSON');
    });

    it('should set requirement ID to "AWS PLAIN"', async () => {
      const hdf = JSON.parse(await convertTrufflehogToHdf(loadFixture('minimal.json'))) as HDFResults;
      expect(hdf.baselines[0]!.requirements[0]!.id).toBe('AWS PLAIN');
    });

    it('should set requirement title', async () => {
      const hdf = JSON.parse(await convertTrufflehogToHdf(loadFixture('minimal.json'))) as HDFResults;
      expect(hdf.baselines[0]!.requirements[0]!.title).toBe('Found AWS secret using PLAIN decoder');
    });
  });

  describe('multi-detector fixture (JSON array)', async () => {
    it('should produce 2 requirements from 3 findings (2 AWS + 1 URI)', async () => {
      const hdf = JSON.parse(await convertTrufflehogToHdf(loadFixture('multi-detector.json'))) as HDFResults;
      expect(hdf.baselines).toHaveLength(1);
      expect(hdf.baselines[0]!.requirements).toHaveLength(2);
    });

    it('should group AWS PLAIN with 2 results and URI PLAIN with 1 result', async () => {
      const hdf = JSON.parse(await convertTrufflehogToHdf(loadFixture('multi-detector.json'))) as HDFResults;
      const reqs = hdf.baselines[0]!.requirements;
      const aws = reqs.find(r => r.id === 'AWS PLAIN');
      expect(aws).toBeDefined();
      expect(aws!.results).toHaveLength(2);

      const uri = reqs.find(r => r.id === 'URI PLAIN');
      expect(uri).toBeDefined();
      expect(uri!.results).toHaveLength(1);
    });

    it('should set target from Git repository URL', async () => {
      const hdf = JSON.parse(await convertTrufflehogToHdf(loadFixture('multi-detector.json'))) as HDFResults;
      expect(hdf.components).toBeDefined();
      expect(hdf.components![0]!.name).toBe('https://github.com/trufflesecurity/test_keys');
      expect(hdf.components![0]!.type).toBe('repository');
    });

    it('should include baseline title with source name', async () => {
      const hdf = JSON.parse(await convertTrufflehogToHdf(loadFixture('multi-detector.json'))) as HDFResults;
      expect(hdf.baselines[0]!.title).toContain('trufflehog');
    });
  });

  describe('NDJSON fixture', async () => {
    it('should produce 2 requirements from 3 NDJSON lines', async () => {
      const hdf = JSON.parse(await convertTrufflehogToHdf(loadFixture('ndjson-input.ndjson'))) as HDFResults;
      expect(hdf.baselines).toHaveLength(1);
      // 1 URI PLAIN + 2 Postgres PLAIN → 2 requirements
      expect(hdf.baselines[0]!.requirements).toHaveLength(2);
    });

    it('should include VerificationError in message', async () => {
      const hdf = JSON.parse(await convertTrufflehogToHdf(loadFixture('ndjson-input.ndjson'))) as HDFResults;
      for (const req of hdf.baselines[0]!.requirements) {
        for (const result of req.results) {
          expect(result.message).toContain('VerificationError');
        }
      }
    });

    it('should include DetectorDescription as default description', async () => {
      const hdf = JSON.parse(await convertTrufflehogToHdf(loadFixture('ndjson-input.ndjson'))) as HDFResults;
      const postgres = hdf.baselines[0]!.requirements.find(r => r.id === 'Postgres PLAIN');
      expect(postgres).toBeDefined();
      expect(postgres!.descriptions.length).toBeGreaterThan(0);
      expect(postgres!.descriptions[0]!.label).toBe('default');
      expect(postgres!.descriptions[0]!.data).toContain('Postgres');
    });

    it('should not produce a target for filesystem sources', async () => {
      const hdf = JSON.parse(await convertTrufflehogToHdf(loadFixture('ndjson-input.ndjson'))) as HDFResults;
      expect(hdf.components ?? []).toHaveLength(0);
    });
  });
});
