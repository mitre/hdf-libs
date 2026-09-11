import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, it, expect } from 'vitest';
import { resultsCorpus } from '../../../shared/typescript/schema-corpus.js';
import { convertHdfToAsff } from './converter.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const VERSION = '0.1.0';

// AWS publishes no JSON Schema for ASFF, so the required-member lists come from
// its official service model instead of a hand-kept list in this file. See
// ../schemas/provenance.json for the source and how to re-derive them. The Go
// peer reads the same table.
const REQUIRED = (
  JSON.parse(readFileSync(join(__dirname, '..', 'schemas', 'asff-required-members.json'), 'utf-8')) as {
    required: Record<string, string[]>;
  }
).required;

function findings(input: string): Record<string, unknown>[] {
  const parsed = JSON.parse(convertHdfToAsff(input, VERSION)) as
    | { Findings?: Record<string, unknown>[] }
    | Record<string, unknown>[];
  return Array.isArray(parsed) ? parsed : (parsed.Findings ?? []);
}

const fixture = (name: string): string =>
  readFileSync(join(__dirname, '..', 'fixtures', 'input', name), 'utf-8');

describe('hdf-to-asff required members', () => {
  it('has a populated table', () => {
    expect(REQUIRED.AwsSecurityFinding?.length, 'an empty table would pass vacuously').toBeGreaterThan(0);
  });

  // A required member that is present but empty is not satisfied: AWS rejects an
  // empty GeneratorId, and the hand-rolled key-list check this replaces could not
  // tell "absent" from "".
  it.each(['compliance.json', 'cve.json'])('%s emits every required member, non-empty', (name) => {
    for (const [i, f] of findings(fixture(name)).entries()) {
      for (const k of REQUIRED.AwsSecurityFinding as string[]) {
        expect(f, `${name} finding ${i}: required member ${k}`).toHaveProperty(k);
        if (typeof f[k] === 'string') {
          expect(f[k], `${name} finding ${i}: required member ${k} is empty`).not.toBe('');
        }
      }
    }
  });

  it('never emits a Vulnerability without its required Id', () => {
    expect(REQUIRED.Vulnerability, 'the table must say Id is required or this asserts nothing').toContain('Id');
    const input =
      `{"baselines":[{"name":"b","requirements":[{"id":"SV-1","title":"t","impact":0.5,` +
      `"descriptions":[{"label":"default","data":"d"}],"cvss":[{"score":7.5}],` +
      `"results":[{"status":"failed","codeDesc":"c","startTime":"2020-01-01T00:00:00Z"}]}]}],` +
      `"generator":{"name":"x","version":"1"},"timestamp":"2020-01-01T00:00:00Z"}`;
    for (const f of findings(input)) {
      for (const v of (f.Vulnerabilities as Record<string, unknown>[] | undefined) ?? []) {
        expect(v).toHaveProperty('Id');
        expect(v.Id).not.toBe('');
      }
    }
  });

  it('never emits an empty GeneratorId', () => {
    const input =
      `{"baselines":[{"name":"b","requirements":[{"id":"","title":"t","impact":0.5,` +
      `"descriptions":[{"label":"default","data":"d"}],` +
      `"results":[{"status":"failed","codeDesc":"c","startTime":"2020-01-01T00:00:00Z"}]}]}],` +
      `"generator":{"name":"x","version":"1"},"timestamp":"2020-01-01T00:00:00Z"}`;
    const f = findings(input)[0];
    expect(f?.GeneratorId).toBeTruthy();
  });
});

// The Go peer generates fixtures/expected/corpus-outputs.json for every corpus
// input; this verifies TypeScript emits the same bytes. That is what makes the
// byte-identical claim an assertion rather than a manual observation, and it
// covers the id-less shapes the full fixtures do not.
//
// Go owns regeneration: go test ./converters/hdf-to-asff/go/ -update
describe('hdf-to-asff Go/TypeScript corpus output parity', () => {
  const golden = JSON.parse(
    readFileSync(join(__dirname, '..', 'fixtures', 'expected', 'corpus-outputs.json'), 'utf-8'),
  ) as Record<string, string>;

  it('covers every corpus case', () => {
    expect(Object.keys(golden).sort()).toEqual(resultsCorpus().map((c) => c.name).sort());
  });

  it.each(resultsCorpus().map((c) => [c.name, c] as const))(
    'emits what the Go peer emits for %s',
    (name, c) => {
      let actual: string;
      try {
        actual = convertHdfToAsff(c.input, VERSION);
      } catch {
        actual = 'REJECTED';
      }
      expect(actual, `TypeScript and Go diverged on corpus case ${name}`).toBe(golden[name]);
    },
  );
});

// Types describes what the finding carries, not what the input had. Mirrors the
// Go peer: a dropped CVSS entry must also drop the CVE taxonomy.
describe('hdf-to-asff Types reflects emitted Vulnerabilities', () => {
  it.each([
    ['cvss with a source keeps the CVE taxonomy', '[{"score":7.5,"source":"CVE-2024-1"}]',
      'Software and Configuration Checks/Vulnerabilities/CVE', true],
    ['cvss without a source drops to the compliance taxonomy', '[{"score":7.5}]',
      'Software and Configuration Checks', false],
    ['no cvss at all is a compliance finding', '[]', 'Software and Configuration Checks', false],
  ])('%s', (_label, cvss, wantType, wantVulns) => {
    const input =
      `{"baselines":[{"name":"b","requirements":[{"id":"SV-1","title":"t","impact":0.5,` +
      `"descriptions":[{"label":"default","data":"d"}],"cvss":${cvss as string},` +
      `"results":[{"status":"failed","codeDesc":"c","startTime":"2020-01-01T00:00:00Z"}]}]}],` +
      `"generator":{"name":"x","version":"1"},"timestamp":"2020-01-01T00:00:00Z"}`;
    const f = findings(input)[0];
    expect(f?.Types).toEqual([wantType]);
    expect('Vulnerabilities' in (f ?? {})).toBe(wantVulns);
  });
});
