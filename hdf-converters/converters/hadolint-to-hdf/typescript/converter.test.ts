import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { DEFAULT_STATIC_ANALYSIS_NIST_TAGS } from '@mitre/hdf-mappings';
import { ResultStatus, TargetType, VerificationMethodEnum, type EvaluatedRequirement, type HDFResults } from '@mitre/hdf-schema';
import { parseJSON } from '@mitre/hdf-utilities';
import { expectValidResults } from '../../../test/helpers/expectValidHdf.js';
import { runConverterContractTests } from '../../../shared/typescript/converter-contract.js';
import { convertHadolintToHdf } from './converter.js';

const FIXTURES_DIR = join(dirname(fileURLToPath(import.meta.url)), '..', 'fixtures');

function loadFixture(name: string): string {
  return readFileSync(join(FIXTURES_DIR, 'input', name), 'utf-8');
}

async function convert(name: string): Promise<HDFResults> {
  return parseJSON<HDFResults>(await convertHadolintToHdf(loadFixture(name)));
}

function requirementById(result: HDFResults, id: string): EvaluatedRequirement {
  for (const baseline of result.baselines) {
    const req = baseline.requirements.find((r) => r.id === id);
    if (req) return req;
  }
  throw new Error(`no requirement with id ${id}`);
}

// Twin of go/converter_test.go.
runConverterContractTests({
  converterName: 'hadolint-to-hdf',
  convertFn: convertHadolintToHdf,
  minimalFixture: 'real.json',
});

describe('hadolint to HDF converter', () => {
  it('produces a valid document with a fixed baseline label and a component', async () => {
    const result = await convert('real.json');
    expectValidResults(result);

    expect(result.baselines).toHaveLength(1);
    expect(result.baselines[0]!.name).toBe('Hadolint Scan');
    expect(result.baselines[0]!.title).toBe('Hadolint Scan of Dockerfile');
    expect(result.generator?.name).toBe('hadolint-to-hdf');
    expect(result.tool?.name).toBe('hadolint');
    expect(result.tool?.version).toBeUndefined();
    expect(result.components).toEqual([{name: 'Dockerfile', type: TargetType.Repository}]);
  });

  it('groups by rule code and keeps every finding', async () => {
    const result = await convert('real.json');
    const reqs = result.baselines[0]!.requirements;
    expect(reqs.map((r) => r.id)).toEqual(['DL3002', 'DL3041', 'DL3059']);
    expect(reqs.reduce((n, r) => n + r.results.length, 0)).toBe(4);
    expect(requirementById(result, 'DL3041').results).toHaveLength(2);
  });

  it('carries the structured finding detail', async () => {
    const req = requirementById(await convert('real.json'), 'DL3002');
    expect(req.title).toBe('Last USER should not be root');
    expect(req.impact).toBe(0.5);
    expect(req.descriptions).toEqual([{label: 'default', data: 'Last USER should not be root'}]);
    expect(req.sourceLocation).toEqual({ref: 'Dockerfile', line: 11});
    expect(req.verificationMethod).toBe(VerificationMethodEnum.Automated);
    expect(JSON.parse(req.code!).code).toBe('DL3002');

    expect(req.results).toHaveLength(1);
    expect(req.results[0]!.status).toBe(ResultStatus.Failed);
    expect(req.results[0]!.codeDesc).toBe('File: Dockerfile | Line: 11 | Column: 1');
    expect(req.results[0]!.message).toBe('Last USER should not be root');
  });

  it('tags NIST and CCI from the mapping table', async () => {
    const result = await convert('real.json');
    expect(requirementById(result, 'DL3002').tags.nist).toEqual(['AC-6']);
    expect(requirementById(result, 'DL3002').tags.cci).toEqual(['CCI-000225']);
    expect(requirementById(result, 'DL3041').tags.nist).toEqual(['CM-2']);
    expect(requirementById(result, 'DL3059').tags.nist).toEqual(['CM-7']);
  });

  it('resolves a shellcheck rule from the same table', async () => {
    const req = requirementById(await convert('shellcheck.json'), 'SC2154');
    expect(req.tags.nist).toEqual(['SA-11']);
    expect(req.impact).toBe(0.5);
  });

  // An unmapped rule takes the shared static-analysis fallback rather than an
  // empty nist tag, which would drop it from every NIST-based view.
  it('falls back to the shared static-analysis controls for an unmapped rule', async () => {
    const input = '[{"code":"DL9999","column":1,"file":"Dockerfile","level":"error","line":3,"message":"A rule with no mapping"}]';
    const result = parseJSON<HDFResults>(await convertHadolintToHdf(input));
    const req = requirementById(result, 'DL9999');
    expect(req.tags.nist).toEqual([...DEFAULT_STATIC_ANALYSIS_NIST_TAGS]);
    expect(req.tags.cci).not.toHaveLength(0);
    expect(req.impact).toBe(0.7);
  });

  // DL1000 is hadolint's parse-error pseudo-rule, deliberately absent from the
  // table, and the one case where the column is not hardcoded to 1.
  it('handles the parse-error pseudo-rule', async () => {
    const input = '[{"code":"DL1000","column":7,"file":"Dockerfile","level":"error","line":1,"message":"unexpected \'F\'"}]';
    const req = requirementById(parseJSON<HDFResults>(await convertHadolintToHdf(input)), 'DL1000');
    expect(req.tags.nist).toEqual([...DEFAULT_STATIC_ANALYSIS_NIST_TAGS]);
    expect(req.results[0]!.codeDesc).toBe('File: Dockerfile | Line: 1 | Column: 7');
  });

  it('maps each level to its impact', async () => {
    for (const [level, want] of Object.entries({error: 0.7, warning: 0.5, info: 0.3, style: 0.1, '': 0.0, 'unheard-of': 0.0})) {
      const input = `[{"code":"DL3000","column":1,"file":"Dockerfile","level":"${level}","line":1,"message":"m"}]`;
      const result = parseJSON<HDFResults>(await convertHadolintToHdf(input));
      expect(requirementById(result, 'DL3000').impact, `level ${level}`).toBe(want);
    }
  });

  it('names one component per distinct file', async () => {
    const input = JSON.stringify([
      {code: 'DL3000', column: 1, file: 'a/Dockerfile', level: 'warning', line: 1, message: 'm'},
      {code: 'DL3001', column: 1, file: 'b/Dockerfile', level: 'warning', line: 2, message: 'n'},
      {code: 'DL3002', column: 1, file: 'a/Dockerfile', level: 'warning', line: 3, message: 'o'},
    ]);
    const result = parseJSON<HDFResults>(await convertHadolintToHdf(input));
    expect(result.components?.map((c) => c.name)).toEqual(['a/Dockerfile', 'b/Dockerfile']);
    expect(result.baselines[0]!.title).toBe('Hadolint Scan of 2 files');
  });

  it('synthesizes a passed placeholder for a clean report', async () => {
    const result = await convert('empty.json');
    expectValidResults(result);
    expect(result.baselines[0]!.requirements).toHaveLength(1);

    const req = result.baselines[0]!.requirements[0]!;
    expect(req.id).toBe('hadolint-no-findings');
    expect(req.title).toBe('No findings reported');
    expect(req.impact).toBe(0);
    expect(req.results[0]!.status).toBe(ResultStatus.Passed);
    expect(req.results[0]!.codeDesc).toBe('hadolint scanned the Dockerfile and reported zero findings.');
    expect(result.components).toBeUndefined();
  });

  // The same table the Go suite rejects, so neither implementation accepts an
  // input the other refuses. A null list is malformed rather than clean, and a
  // field present with the wrong type is rejected by Go's decoder.
  it('rejects malformed input', async () => {
    for (const input of [
      '',
      'not json',
      '{"code":"DL3000"}',
      '[{"code":42}]',
      'null',
      '[{"code":"DL3002","line":"nope"}]',
      '[{"code":"DL3002","column":true}]',
      '[{"code":"DL3002","level":3}]',
      '[{"code":"DL3002","message":["a"]}]',
      '[{"code":"DL3002","file":{}}]',
      '[{"code":"DL3002","line":1.5}]'
    ]) {
      await expect(convertHadolintToHdf(input)).rejects.toThrow();
    }
  });

  // Go decodes a missing field to its zero value rather than erroring, so a
  // sparse finding has to stay acceptable here too; rejecting it would only
  // invert the divergence.
  it('accepts a finding whose optional fields are absent', async () => {
    const out = JSON.parse(await convertHadolintToHdf('[{"code":"DL3002"}]'));
    expect(out.baselines[0].requirements).toHaveLength(1);
    expect(out.baselines[0].requirements[0].id).toBe('DL3002');
  });

  // Go decodes an explicit null to the zero value rather than erroring.
  it('accepts a finding whose fields are explicitly null', async () => {
    const out = JSON.parse(await convertHadolintToHdf('[{"code":"DL3002","line":null,"file":null}]'));
    expect(out.baselines[0].requirements).toHaveLength(1);
  });

  // hadolint can emit SARIF as well as JSON; a SARIF document routes to the
  // shared converter rather than failing to parse as a findings array.
  it('delegates SARIF input to the SARIF converter', async () => {
    const sarif = readFileSync(join(FIXTURES_DIR, '..', '..', 'sarif-to-hdf', 'fixtures', 'input', 'gosec.sarif'), 'utf-8');
    const result = parseJSON<HDFResults>(await convertHadolintToHdf(sarif));
    expect(result.baselines[0]!.name).not.toBe('Hadolint Scan');
  });
});
