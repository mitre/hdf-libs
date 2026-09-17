import { readFileSync, readdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, it, expect } from 'vitest';
import { results, amendments } from '@mitre/hdf-fixtures';
import { resultsCorpus, amendmentsCorpus, type CorpusCase } from '../../../shared/typescript/schema-corpus.js';
import { loadSchemaValidator } from '../../../shared/typescript/schema-validation.js';
import { convertHdfToOscalSar } from '../../hdf-to-oscal-sar/typescript/converter.js';
import { convertHdfToOscalPoam } from '../../hdf-to-oscal-poam/typescript/converter.js';
import { oscalToken } from './shared.js';
import type { Property } from './types.js';
import {
  absentFieldProp,
  consumedVocabularyProp,
  emptyFieldProp,
  findVocabularyProp,
  findVocabularyProps,
  normalizePropValue,
  pushVocabularyProp,
  vocabularyDefaultNamespace,
  vocabularyNamespace,
  vocabularyProp,
  vocabularyRows,
  validateVocabularyTable,
  type VocabularyRow,
} from './vocabulary.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const CONVERTERS = join(__dirname, '..', '..');

/** FedRAMP's registered extension namespace (ADR-0014 §1.3). */
const FEDRAMP_NAMESPACE = 'https://fedramp.gov/ns/oscal';

/** Exercises every prop the SAR exporter can emit. Mirrors the Go peer's input. */
const ALL_SAR_PROPS = `{
  "baselines": [{
    "name": "b", "version": "1.2.0",
    "requirements": [{
      "id": "SV-230221r858734_rule", "impact": 0.7, "title": "req",
      "tags": { "nist": ["AC-2"], "cci": ["CCI-000012"] },
      "descriptions": [
        { "label": "default", "data": "default desc" },
        { "label": "check", "data": "check text" },
        { "label": "fix", "data": "fix text" }
      ],
      "code": "control 'SV-1' do end",
      "controlType": "technical", "verificationMethod": "automated", "applicability": "required",
      "refs": [{ "ref": "Handbook 3\\nsection 2" }],
      "cwe": ["CWE-79"],
      "epss": { "date": "2026-01-01", "score": 0.97532, "percentile": 0.999 },
      "kev": { "inKev": true, "dateAdded": "2025-01-01", "dueDate": "2025-02-01" },
      "cvss": [{ "version": "3.1", "baseScore": 9.8, "baseVector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" }],
      "results": [{ "status": "failed", "codeDesc": "c", "startTime": "2026-01-01T00:00:00Z" }]
    }, {
      "id": "SV-2", "impact": 0.0, "tags": {},
      "descriptions": [{ "label": "default", "data": "d" }, { "label": "fix", "data": "impact-0 fix text" }],
      "results": [{ "status": "passed", "codeDesc": "c", "startTime": "2026-01-01T00:00:00Z" }]
    }]
  }]
}`;

/** Exercises every prop the POA&M exporter emits from the vocabulary. Mirrors the Go peer's input. */
const ALL_POAM_PROPS = `{
  "name": "a", "amendmentId": "8f2b7c1e-4d3a-4b6e-9a1f-2c3d4e5f6a7b",
  "labels": { "environment": "production" },
  "overrides": [{
    "requirementId": "AC-2", "type": "waiver", "status": "notApplicable",
    "reason": "accepted", "justification": "component_not_present",
    "impact": { "value": 0.3 },
    "baselineRef": "rhel-9-stig", "componentRef": "1b2c3d4e-5f6a-4b7c-8d9e-0f1a2b3c4d5e",
    "appliedAt": "2020-01-01T00:00:00Z", "expiresAt": "2099-12-31T00:00:00Z",
    "appliedBy": { "identifier": "analyst", "type": "username" },
    "milestones": [{
      "description": "patch", "status": "completed",
      "estimatedCompletion": "2099-12-31T00:00:00Z",
      "completedAt": "2020-02-01T00:00:00Z",
      "completedBy": { "identifier": "engineer", "type": "username" }
    }],
    "evidence": [{
      "type": "file", "data": "log", "mimeType": "text/plain",
      "capturedBy": { "identifier": "scanner", "type": "username" }
    }],
    "externalReferences": [{ "sourceName": "NVD", "externalId": "CVE-2021-44228", "href": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228" }]
  }]
}`;

interface EmittedProp {
  path: string;
  name: string;
  ns: string;
  class: string;
}

/** Walks decoded OSCAL JSON and returns every member of every props array. */
function collectProps(node: unknown, path: string, out: EmittedProp[]): void {
  if (Array.isArray(node)) {
    node.forEach((e, i) => collectProps(e, `${path}[${i}]`, out));
    return;
  }
  if (node === null || typeof node !== 'object') return;
  for (const [key, value] of Object.entries(node)) {
    if (key === 'props') {
      expect(Array.isArray(value), `${path}.props is not an array`).toBe(true);
      (value as Array<Record<string, unknown>>).forEach((p, i) => {
        out.push({
          path: `${path}.props[${i}]`,
          name: typeof p.name === 'string' ? p.name : '',
          ns: typeof p.ns === 'string' ? p.ns : '',
          class: typeof p.class === 'string' ? p.class : '',
        });
      });
      continue;
    }
    collectProps(value, `${path}.${key}`, out);
  }
}

/** One input an exporter is run on. mayReject names why the exporter may refuse it; an input without one must convert. */
interface ExporterInput {
  label: string;
  input: string;
  mayReject?: string;
}

/** Why the exporter may refuse a corpus case: the corpus marks MustReject cases as refused and lets MustNotCorrupt cases be refused. */
function corpusRejection(c: CorpusCase): string | undefined {
  return c.contract === 'MustConvert' ? undefined : `the adversarial corpus contract ${c.contract} allows rejection`;
}

/**
 * Mirrors the documented exemption in the SAR exporter's corpus test: OSCAL
 * cannot represent an assessment with no evaluated baselines.
 */
const SAR_REJECTIONS: Record<string, string> = {
  'corpus zero-baselines': 'OSCAL Assessment Results requires at least one result, so the SAR exporter rejects an assessment with no evaluated baselines',
};

/** Why a conversion error fails the guard, or undefined when the input may be rejected. */
function conversionErrorProblem(input: ExporterInput, err: unknown): string | undefined {
  if (input.mayReject) return undefined;
  return `${input.label}: expected to convert, but the exporter failed: ${err instanceof Error ? err.message : String(err)}`;
}

function sarInputs(): ExporterInput[] {
  return [
    { label: 'hdf-fixtures results minimal', input: results.minimal.read() },
    { label: 'hdf-fixtures results inspec-multilayered', input: results.inspecMultilayered.read() },
    { label: 'hdf-to-oscal-sar multiline', input: readFileSync(join(CONVERTERS, 'hdf-to-oscal-sar', 'fixtures', 'input', 'multiline.hdf.json'), 'utf-8') },
    { label: 'every SAR prop', input: ALL_SAR_PROPS },
    ...resultsCorpus().map((c) => ({ label: `corpus ${c.name}`, input: c.input, mayReject: SAR_REJECTIONS[`corpus ${c.name}`] ?? corpusRejection(c) })),
  ];
}

function poamInputs(): ExporterInput[] {
  return [
    { label: 'hdf-fixtures amendments uc-01-fixed', input: amendments.uc01Fixed.read() },
    { label: 'hdf-fixtures amendments multi-cve', input: amendments.multiCve.read() },
    { label: 'hdf-schema minimal-amendments', input: readFileSync(join(CONVERTERS, '..', '..', 'hdf-schema', 'test', 'fixtures', 'minimal-amendments.json'), 'utf-8') },
    { label: 'every POA&M prop', input: ALL_POAM_PROPS },
    ...amendmentsCorpus().map((c) => ({ label: `corpus ${c.name}`, input: c.input, mayReject: corpusRejection(c) })),
  ];
}

/** An absent ns is the NIST default namespace, as OSCAL defines. */
function canonicalNs(ns: string): string {
  return ns === '' ? vocabularyDefaultNamespace() : ns;
}

/** Marks the POA&M label props whose names come from HDF data. */
const AMENDMENT_LABEL_CLASS = 'amendment-label';

async function emittedPropNames(
  inputs: ExporterInput[],
  convert: (input: string) => Promise<string>,
): Promise<{ seen: Set<string>; labels: number }> {
  const rows = new Map(vocabularyRows().map((r) => [r.name, r] as const));
  const seen = new Set<string>();
  let labels = 0;
  let converted = 0;
  for (const exporterInput of inputs) {
    const { label, input } = exporterInput;
    let out: string;
    try {
      out = await convert(input);
    } catch (err) {
      const problem = conversionErrorProblem(exporterInput, err);
      expect(problem, problem).toBeUndefined();
      continue;
    }
    converted++;
    const props: EmittedProp[] = [];
    collectProps(JSON.parse(out), '$', props);
    for (const p of props) {
      // ADR-0014 §1.5 excludes data-named label props; §4.6 replaces them.
      if (p.class === AMENDMENT_LABEL_CLASS) {
        labels++;
        continue;
      }
      const row = rows.get(p.name);
      expect(row, `${label}: ${p.path} emits prop "${p.name}", which is not a vocabulary row`).toBeDefined();
      if (!row) continue;
      expect(canonicalNs(p.ns), `${label}: ${p.path} prop "${p.name}" carries the wrong namespace`).toBe(canonicalNs(row.ns));
      if (row.ns === vocabularyDefaultNamespace()) {
        expect(p.ns, `${label}: ${p.path} NIST prop "${p.name}" must keep the default namespace by omitting ns`).toBe('');
      }
      seen.add(p.name);
    }
  }
  expect(converted, 'no input converted — the run would prove nothing').toBeGreaterThan(0);
  return { seen, labels };
}

describe('vocabulary: emitted props are rows', () => {
  it('fails an input that must convert when its conversion errors', () => {
    expect(conversionErrorProblem({ label: 'fixture', input: '' }, new Error('boom'))).toBe('fixture: expected to convert, but the exporter failed: boom');
    expect(conversionErrorProblem({ label: 'corpus x', input: '', mayReject: 'allowed' }, new Error('boom'))).toBeUndefined();
    for (const c of amendmentsCorpus()) {
      expect(corpusRejection(c) === undefined, c.name).toBe(c.contract === 'MustConvert');
    }
  });

  it('the inline inputs are valid HDF', () => {
    const schemas = join(CONVERTERS, '..', '..', 'hdf-validators', 'go', 'schemas');
    const validateResults = loadSchemaValidator(join(schemas, 'hdf-results.schema.json'));
    expect(validateResults(JSON.parse(ALL_SAR_PROPS)), JSON.stringify(validateResults.errors)).toBe(true);
    const validateAmendments = loadSchemaValidator(join(schemas, 'hdf-amendments.schema.json'));
    expect(validateAmendments(JSON.parse(ALL_POAM_PROPS)), JSON.stringify(validateAmendments.errors)).toBe(true);
  });

  it('hdf-to-oscal-sar', async () => {
    const { seen } = await emittedPropNames(sarInputs(), convertHdfToOscalSar);
    for (const name of [
      'hdf-requirement-id', 'baseline-version', 'nist', 'cci', 'control-type', 'verification-method',
      'applicability', 'cwe', 'epss-score', 'epss-percentile', 'kev', 'kev-due-date', 'cvss-base-score',
      'cvss-base-vector', 'reference', 'description-label', 'type',
    ]) {
      expect(seen.has(name), `no input exercised the SAR prop "${name}", so the guard does not cover it`).toBe(true);
    }
  });

  it('hdf-to-oscal-poam', async () => {
    const { seen, labels } = await emittedPropNames(poamInputs(), convertHdfToOscalPoam);
    expect(labels, 'no input emitted an amendment label prop, so the label exclusion is not exercised').toBeGreaterThan(0);
    for (const name of [
      'amendment-id', 'override-type', 'impact-override', 'justification', 'baseline-ref', 'component-ref',
      'milestone-status', 'completed-at', 'completed-by', 'mime-type', 'captured-by', 'source-name',
      'external-id', 'impacted-control-id',
    ]) {
      expect(seen.has(name), `no input exercised the POA&M prop "${name}", so the guard does not cover it`).toBe(true);
    }
  });
});

/**
 * The ADR-0014 Context inventory: the 18 SAR and 13 POA&M names exporters emitted
 * without ns before the ADR, plus FedRAMP's impacted-control-id.
 */
const ADR_CONTEXT_INVENTORY = [
  'applicability', 'baseline-version', 'cci', 'check', 'control-type', 'cvss-base-score',
  'cvss-base-vector', 'cwe', 'epss-percentile', 'epss-score', 'fix', 'hdf-requirement-id', 'kev',
  'kev-due-date', 'nist', 'rationale', 'reference', 'verification-method',
  'amendment-id', 'baseline-ref', 'captured-by', 'completed-at', 'completed-by', 'component-ref',
  'external-id', 'impact-override', 'justification', 'milestone-status', 'mime-type',
  'override-type', 'source-name',
  'impacted-control-id',
];

describe('vocabulary: table', () => {
  it('has the §1.5 shape', () => {
    expect(vocabularyNamespace()).toBe('https://mitre.github.io/hdf-libs/ns/oscal');
    expect(vocabularyDefaultNamespace()).toBe('http://csrc.nist.gov/ns/oscal');
    const rows = vocabularyRows();
    expect(rows.length).toBeGreaterThan(0);
    const names = new Set<string>();
    for (const r of rows) {
      expect(names.has(r.name), `duplicate row ${r.name}`).toBe(false);
      names.add(r.name);
      expect(oscalToken(r.name), `row name ${r.name} is not an OSCAL token`).toBe(r.name);
      expect([vocabularyNamespace(), vocabularyDefaultNamespace(), FEDRAMP_NAMESPACE]).toContain(r.ns);
      expect(r.objects.length, r.name).toBeGreaterThan(0);
      expect(r.meaning, r.name).not.toBe('');
      expect(r.valueFormat, r.name).not.toBe('');
      expect(r.hdfField === null || r.hdfField !== '', r.name).toBe(true);
    }
    expect(ADR_CONTEXT_INVENTORY).toHaveLength(32);
    expect(new Set(rows.filter((r) => r.legacy).map((r) => r.name))).toEqual(new Set(ADR_CONTEXT_INVENTORY));

    const byName = new Map<string, VocabularyRow>(rows.map((r) => [r.name, r]));
    expect(byName.get('impacted-control-id')?.ns).toBe(FEDRAMP_NAMESPACE);
    for (const n of ['type', 'label', 'sort-id', 'version']) {
      expect(byName.get(n)?.ns, n).toBe(vocabularyDefaultNamespace());
      expect(byName.get(n)?.legacy, n).toBe(false);
    }
    for (const n of ['POAM-ID', 'CORE', 'assessment-type']) {
      expect(byName.get(n)?.ns, n).toBe(FEDRAMP_NAMESPACE);
      expect(byName.get(n)?.legacy, n).toBe(false);
    }
    for (const n of ['description-label', 'empty-field', 'absent-field']) {
      expect(byName.get(n)?.ns, n).toBe(vocabularyNamespace());
      expect(byName.get(n)?.legacy, n).toBe(false);
    }
  });

  it('returns a copy of the rows', () => {
    const rows = vocabularyRows();
    rows[0]!.name = 'mutated';
    rows[0]!.objects[0] = 'mutated';
    expect(vocabularyRows()[0]!.name).not.toBe('mutated');
    expect(vocabularyRows()[0]!.objects[0]).not.toBe('mutated');
  });
});

interface StringCases {
  ecmascriptWhitespace: string[];
  cases: Array<{ name: string; in: string; value: string | null; remarks: string | null }>;
}

const stringCases = JSON.parse(
  readFileSync(join(CONVERTERS, '..', 'shared', 'oscal-string-cases.json'), 'utf-8'),
) as StringCases;

/** OSCAL's StringDatatype pattern, read from the vendored schema and applied with ECMAScript semantics as ajv does. */
const STRING_DATATYPE = new RegExp(
  (JSON.parse(readFileSync(join(CONVERTERS, 'hdf-to-oscal-sar', 'schemas', 'oscal_assessment-results_schema-v1.2.3.json'), 'utf-8')) as {
    definitions: { StringDatatype: { pattern: string } };
  }).definitions.StringDatatype.pattern,
  'u',
);

describe('vocabulary: §1.7 shared string cases', () => {
  it('the shared table is populated', () => {
    expect(stringCases.cases.length).toBeGreaterThan(0);
  });

  it.each(stringCases.cases.map((c) => [c.name, c] as const))('%s', (_name, c) => {
    const prop = vocabularyProp('reference', c.in);
    const pushed: Property[] = [];
    pushVocabularyProp(pushed, 'reference', c.in);
    if (c.value === null) {
      expect(prop).toBeUndefined();
      expect(pushed).toEqual([]);
      return;
    }
    expect(prop).toBeDefined();
    expect(prop!.value).toBe(c.value);
    expect(normalizePropValue(c.in)).toBe(c.value);
    expect(STRING_DATATYPE.test(prop!.value), `${JSON.stringify(prop!.value)} is not an OSCAL StringDatatype`).toBe(true);
    expect(STRING_DATATYPE.test(c.in), 'the StringDatatype check must accept exactly the inputs normalization leaves unchanged').toBe(c.in === c.value);
    expect(prop!.remarks).toBe(c.remarks ?? undefined);
    expect(prop!.ns).toBe(vocabularyNamespace());
    expect(pushed).toEqual([prop]);
    expect(findVocabularyProp([prop!], 'reference')?.value, 'the read helper must return the exact HDF value').toBe(c.in);
  });

  it('trims exactly the code points the table lists, which are exactly ECMAScript \\s', () => {
    const listed = new Set(stringCases.ecmascriptWhitespace.map((cp) => parseInt(cp.slice(2), 16)));
    expect(listed.size).toBe(25);
    const mismatches: string[] = [];
    for (let cp = 0; cp <= 0x10ffff; cp++) {
      if (cp >= 0xd800 && cp <= 0xdfff) continue;
      const ch = String.fromCodePoint(cp);
      const isListed = listed.has(cp);
      if (/^\s$/u.test(ch) !== isListed || (normalizePropValue(`${ch}x`) === 'x') !== isListed) {
        mismatches.push(`U+${cp.toString(16).toUpperCase().padStart(4, '0')}`);
      }
    }
    expect(mismatches).toEqual([]);
  });
});

describe('vocabulary: emit helpers', () => {
  it('an unknown name is a programming error', () => {
    expect(() => vocabularyProp('not-a-row', 'x')).toThrow('oscal: "not-a-row" is not a row of the OSCAL vocabulary');
  });
  it('a NIST row omits ns', () => {
    expect(vocabularyProp('type', 'evidence')).toStrictEqual({ name: 'type', value: 'evidence' });
  });
  it("a FedRAMP row carries FedRAMP's namespace", () => {
    expect(vocabularyProp('impacted-control-id', 'ac-2')).toStrictEqual({ name: 'impacted-control-id', value: 'ac-2', ns: FEDRAMP_NAMESPACE });
  });
  it('a third-party prop never records remarks', () => {
    expect(vocabularyProp('impacted-control-id', ' ac-2\n')).toStrictEqual({ name: 'impacted-control-id', value: 'ac-2', ns: FEDRAMP_NAMESPACE });
  });
  it('push keeps existing props', () => {
    const props: Property[] = [{ name: 'x', value: 'y' }];
    pushVocabularyProp(props, 'kev', 'true');
    expect(props).toStrictEqual([{ name: 'x', value: 'y' }, { name: 'kev', value: 'true', ns: vocabularyNamespace() }]);
  });
  it('empty-field names the HDF field', () => {
    expect(emptyFieldProp('baselineRef')).toStrictEqual({ name: 'empty-field', value: 'baselineRef', ns: vocabularyNamespace() });
  });
  it('absent-field names the HDF field', () => {
    expect(absentFieldProp('systemRef')).toStrictEqual({ name: 'absent-field', value: 'systemRef', ns: vocabularyNamespace() });
  });
  it('normalizing an empty value leaves it empty', () => {
    expect(normalizePropValue('')).toBe('');
  });
  it('a field prop needs a field name', () => {
    expect(() => emptyFieldProp('')).toThrow('oscal: empty-field needs the name of an HDF field');
  });
});

describe('vocabulary: read helpers', () => {
  const hdfNs = vocabularyNamespace();

  it('matches name and namespace', () => {
    const props: Property[] = [
      { name: 'nist', ns: 'https://example.org/ns/oscal', value: 'foreign' },
      { name: 'cci', ns: hdfNs, value: 'CCI-1' },
      { name: 'nist', ns: hdfNs, value: 'AC-2' },
    ];
    expect(findVocabularyProp(props, 'nist')).toStrictEqual({ index: 2, value: 'AC-2', legacy: false });
  });
  it('a legacy row accepts a prop with no ns and reports it', () => {
    expect(findVocabularyProp([{ name: 'hdf-requirement-id', value: 'SV-1' }], 'hdf-requirement-id')).toStrictEqual({ index: 0, value: 'SV-1', legacy: true });
  });
  it('a non-legacy row rejects a prop with no ns', () => {
    expect(findVocabularyProp([{ name: 'description-label', value: 'check' }], 'description-label')).toBeUndefined();
  });
  it('a legacy row rejects a prop in another namespace', () => {
    expect(findVocabularyProp([{ name: 'nist', ns: 'https://example.org/ns/oscal', value: 'AC-2' }], 'nist')).toBeUndefined();
  });
  it("the FedRAMP row matches FedRAMP's namespace byte for byte", () => {
    const props: Property[] = [
      { name: 'impacted-control-id', ns: 'http://fedramp.gov/ns/oscal', value: 'ac-1' },
      { name: 'impacted-control-id', ns: FEDRAMP_NAMESPACE, value: 'ac-2' },
    ];
    expect(findVocabularyProp(props, 'impacted-control-id')).toStrictEqual({ index: 1, value: 'ac-2', legacy: false });
  });
  it('the legacy FedRAMP row accepts no ns', () => {
    expect(findVocabularyProp([{ name: 'impacted-control-id', value: 'ac-2' }], 'impacted-control-id')).toStrictEqual({ index: 0, value: 'ac-2', legacy: true });
  });
  it('an HDF prop prefers remarks', () => {
    expect(findVocabularyProp([{ name: 'reference', ns: hdfNs, value: 'a b', remarks: 'a\nb' }], 'reference')?.value).toBe('a\nb');
  });
  it('a legacy-matched HDF prop prefers remarks', () => {
    expect(findVocabularyProp([{ name: 'check', value: 'preview', remarks: 'full\ntext' }], 'check')?.value).toBe('full\ntext');
  });
  it('a third-party prop ignores remarks', () => {
    expect(findVocabularyProp([{ name: 'impacted-control-id', ns: FEDRAMP_NAMESPACE, value: 'ac-2', remarks: "owner's note" }], 'impacted-control-id')?.value).toBe('ac-2');
  });
  it('the NIST row matches an absent or explicit default namespace', () => {
    const props: Property[] = [
      { name: 'type', ns: hdfNs, value: 'ours' },
      { name: 'type', value: 'evidence' },
      { name: 'type', ns: vocabularyDefaultNamespace(), value: 'plan' },
    ];
    expect(findVocabularyProps(props, 'type')).toStrictEqual([
      { index: 1, value: 'evidence', legacy: false },
      { index: 2, value: 'plan', legacy: false },
    ]);
  });
  it('an unknown name matches nothing', () => {
    expect(findVocabularyProp([{ name: 'not-a-row', ns: hdfNs, value: 'x' }], 'not-a-row')).toBeUndefined();
    expect(findVocabularyProps([{ name: 'not-a-row', value: 'x' }], 'not-a-row')).toStrictEqual([]);
  });
  it('absent props match nothing', () => {
    expect(findVocabularyProp(undefined, 'nist')).toBeUndefined();
    expect(findVocabularyProps(undefined, 'nist')).toStrictEqual([]);
  });
  it('finds every match in order', () => {
    const props: Property[] = [
      { name: 'cci', ns: hdfNs, value: 'CCI-1' },
      { name: 'cci', value: 'CCI-2' },
      { name: 'cci', ns: 'https://example.org/ns/oscal', value: 'CCI-3' },
    ];
    expect(findVocabularyProps(props, 'cci')).toStrictEqual([
      { index: 0, value: 'CCI-1', legacy: false },
      { index: 1, value: 'CCI-2', legacy: true },
    ]);
  });
});

describe('vocabulary: consumed props', () => {
  const hdfNs = vocabularyNamespace();
  it.each([
    ['an HDF-namespaced row', { name: 'nist', ns: hdfNs, value: 'AC-2' }, true],
    ['an HDF-namespaced name that is not a row', { name: 'future-prop', ns: hdfNs, value: 'x' }, true],
    ['a legacy row with no ns', { name: 'check', value: 'x' }, true],
    ['the legacy FedRAMP row with no ns', { name: 'impacted-control-id', value: 'ac-2' }, true],
    ['a non-legacy row with no ns', { name: 'description-label', value: 'check' }, false],
    ['a legacy name in a foreign namespace', { name: 'nist', ns: 'https://example.org/ns/oscal', value: 'AC-2' }, false],
    ["a FedRAMP prop in FedRAMP's namespace", { name: 'impacted-control-id', ns: FEDRAMP_NAMESPACE, value: 'ac-2' }, false],
    ['a NIST prop', { name: 'type', value: 'evidence' }, false],
    ['an unknown name with no ns', { name: 'priority', value: 'high' }, false],
  ] as Array<[string, Property, boolean]>)('%s', (_name, prop, want) => {
    expect(consumedVocabularyProp(prop)).toBe(want);
  });
});

interface PropRead {
  line: number;
  name: string;
  literal: boolean;
  lookup: boolean;
}

const PROP_LOOKUP = /(\bfunction\s+)?\b(?:extractPropValue|extractAllPropValues|findVocabularyProps?)\(\s*[^,()]+,\s*([^,)]+)/g;
const NAME_COMPARISON = /\.name\s*(?:===|!==)\s*'([^']*)'/g;
const NON_PROP_COMPARISONS = new Set(['impact', 'risk', 'likelihood']); // risk characterization facet names, not props

/**
 * Finds, in TypeScript source, every prop-name argument of a prop lookup and
 * every string literal a name is compared with, across line breaks.
 */
function scanPropReads(source: string): PropRead[] {
  const lineOf = (offset: number): number => source.slice(0, offset).split('\n').length;
  const reads: PropRead[] = [];
  for (const m of source.matchAll(PROP_LOOKUP)) {
    if (m[1] !== undefined) continue; // the helper's own definition
    const raw = m[2]!;
    const arg = raw.trim();
    const line = lineOf(m.index + m[0].length - raw.length + raw.indexOf(arg));
    const literal = /^'([^']*)'$/.exec(arg);
    reads.push(literal ? { line, name: literal[1]!, literal: true, lookup: true } : { line, name: arg, literal: false, lookup: true });
  }
  for (const m of source.matchAll(NAME_COMPARISON)) {
    if (NON_PROP_COMPARISONS.has(m[1]!)) continue;
    reads.push({ line: lineOf(m.index + m[0].length - m[1]!.length - 1), name: m[1]!, literal: true, lookup: false });
  }
  return reads;
}

describe('vocabulary: importer prop reads', () => {
  it('the scanner finds names across line breaks and skips helper definitions', () => {
    const source = [
      'export function extractPropValue(',
      '  props: Property[] | undefined,',
      '  name: string,',
      '): string | undefined {',
      '  const v = extractPropValue(',
      '    ctrl.props,',
      "    'CORE',",
      '  );',
      "  const w = extractAllPropValues(p.props, name, '');",
      '  if (p.name ===',
      "    'sort-id' || f.name !== 'impact') return;",
      '}',
    ].join('\n');
    expect(scanPropReads(source)).toStrictEqual([
      { line: 7, name: 'CORE', literal: true, lookup: true },
      { line: 9, name: 'name', literal: false, lookup: true },
      { line: 11, name: 'sort-id', literal: true, lookup: false },
    ]);
  });

  it('every prop name the importer reads is a vocabulary row (ADR-0014 §1.5)', () => {
    const rows = new Set(vocabularyRows().map((r) => r.name));
    const read = new Set<string>();
    const problems: string[] = [];
    // vocabulary.ts is the helpers themselves, which forward a caller's name.
    const files = readdirSync(__dirname).filter((f) => f.endsWith('.ts') && !f.endsWith('.test.ts') && f !== 'vocabulary.ts');
    for (const f of files) {
      for (const r of scanPropReads(readFileSync(join(__dirname, f), 'utf-8'))) {
        if (!r.literal) {
          problems.push(`${f}:${r.line} reads a prop whose name is not a string literal (${r.name}), so the sweep cannot check it`);
        } else if (!rows.has(r.name)) {
          problems.push(r.lookup ? `${f}:${r.line} reads prop "${r.name}", which is not a vocabulary row` : `${f}:${r.line} compares a name with "${r.name}", which is not a vocabulary row`);
        }
        read.add(r.name);
      }
    }
    expect(problems).toEqual([]);
    for (const name of ['CORE', 'label', 'sort-id', 'version', 'assessment-type', 'POAM-ID', 'impacted-control-id', 'description-label']) {
      expect(read.has(name), `the sweep no longer finds the importer's read of "${name}"; it may have stopped matching`).toBe(true);
    }
  });
});

describe('vocabulary: table validation', () => {
  const row = { name: 'a', ns: 'n', objects: ['o'], meaning: 'm', valueFormat: 'v', hdfField: null, legacy: false };
  it.each([
    ['no namespace', { defaultNamespace: 'd', props: [row] }, 'oscal: the OSCAL vocabulary table has no namespace'],
    ['no default namespace', { namespace: 'n', props: [row] }, 'oscal: the OSCAL vocabulary table has no defaultNamespace'],
    ['no rows', { namespace: 'n', defaultNamespace: 'd', props: [] }, 'oscal: the OSCAL vocabulary table has no rows'],
    ['rows that are not an array', { namespace: 'n', defaultNamespace: 'd' }, 'oscal: the OSCAL vocabulary table has no rows'],
    ['duplicate row', { namespace: 'n', defaultNamespace: 'd', props: [row, row] }, 'oscal: the OSCAL vocabulary table defines "a" twice'],
  ] as Array<[string, unknown, string]>)('rejects a table with %s', (_name, table, message) => {
    expect(() => validateVocabularyTable(table)).toThrow(message);
  });

  it('indexes a valid table', () => {
    const { byName } = validateVocabularyTable({ namespace: 'n', defaultNamespace: 'd', props: [row, { ...row, name: 'b' }] });
    expect(byName.get('b')?.name).toBe('b');
  });
});
