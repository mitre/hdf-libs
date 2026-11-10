import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import Ajv2020 from 'ajv/dist/2020.js';
import addFormats from 'ajv-formats';
import { validateResults } from '@mitre/hdf-validators';
import { describe, expect, it, vi } from 'vitest';
import { setDefaultMaxInputSize } from '@mitre/hdf-utilities';
import { convertHdfToEcs, convertHdfToEcsBundle } from '../../converters/hdf-to-ecs/typescript/converter.js';
import { convertHdfToSplunk, convertHdfToSplunkBundle } from '../../converters/hdf-to-splunk/typescript/converter.js';
import { convertHdfToOcsf, convertHdfToOcsfBundle } from '../../converters/hdf-to-ocsf/typescript/converter.js';
import { buildExportBundle, resolveExportEvent, resolveExportSource } from './exportbundle.js';
import { loadSchemaValidator } from './schema-validation.js';
import { asMap, canonicalize, parseJSONPreservingNumbers, stringifyLine } from './exportmap.js';

const fixture = new URL('../../converters/hdf-to-ecs/fixtures/input/override.json', import.meta.url);
const resolverCases = JSON.parse(readFileSync(new URL('../bundle-fixtures/cases.json', import.meta.url), 'utf8')) as {
  name: string;
  edits: { document: 'manifest' | 'envelope'; path: string[]; value?: unknown; remove?: boolean }[];
  artifactMode?: string;
  error?: string;
}[];

describe('source-preserving export bundle', () => {
  it('uses Web Crypto for hashing in browser-compatible consumers', async () => {
    const digest = vi.spyOn(globalThis.crypto.subtle, 'digest');
    try {
      const input = readFileSync(fixture);
      const bundle = await convertHdfToEcsBundle(input);
      expect(JSON.parse(bundle.manifest).artifacts[0].checksum.value).toBe(createHash('sha512').update(input).digest('hex'));
      expect(digest).toHaveBeenCalledWith('SHA-512', expect.any(Uint8Array));
    } finally {
      digest.mockRestore();
    }
  });

  it('retains independent source bytes when a Buffer caller reuses its input', async () => {
    const input = readFileSync(fixture);
    const expected = Buffer.from(input);
    const pendingBundle = convertHdfToEcsBundle(input);
    input.fill(0);
    const bundle = await pendingBundle;
    expect(Buffer.from(bundle.source)).toEqual(expected);
    const artifact = Buffer.from(bundle.source);
    const pendingReadback = resolveExportEvent(bundle.events, bundle.manifest, [{ href: 'source.json', bytes: artifact }]);
    artifact.fill(0);
    const resolved = await pendingReadback;
    expect(Buffer.from(resolved.source)).toEqual(expected);
  });

  it('preserves large source strings below the configured input limit', async () => {
    for (const character of ['a', '\\']) {
      const document = JSON.parse(readFileSync(fixture, 'utf8'));
      document.baselines[0].extensions = { passthrough: { large: character.repeat(10 * 1024 * 1024) } };
      expect(validateResults(document).valid).toBe(true);
      const input = Buffer.from(JSON.stringify(document));
      const bundle = await convertHdfToEcsBundle(input);
      expect(Buffer.from(bundle.source).equals(input)).toBe(true);
      const resolved = await resolveExportEvent(bundle.events, bundle.manifest, [{ href: 'source.json', bytes: input }]);
      expect(JSON.parse(resolved.baseline).extensions).toEqual(document.baselines[0].extensions);
    }
  });

  it('retains an empty assessment artifact without fabricating a finding', async () => {
    const document = JSON.parse(readFileSync(fixture, 'utf8'));
    document.baselines = [];
    expect(validateResults(document).valid).toBe(true);
    const input = Buffer.from(JSON.stringify(document));
    for (const convert of [convertHdfToEcsBundle, convertHdfToSplunkBundle, convertHdfToOcsfBundle]) {
      const bundle = await convert(input);
      expect(bundle.events).toBe('');
      expect(Buffer.from(bundle.source)).toEqual(input);
      expect(JSON.parse(bundle.manifest).artifacts).toHaveLength(1);
    }
  });

  it('distinguishes occurrences of duplicate requirement IDs and resolves every one', async () => {
    const document = JSON.parse(readFileSync(fixture, 'utf8'));
    const baseline = document.baselines[0];
    baseline.requirements.push(structuredClone(baseline.requirements[0]));
    document.baselines.push(structuredClone(baseline));
    expect(validateResults(document).valid).toBe(true);
    const input = Buffer.from(JSON.stringify(document));
    const bundle = await convertHdfToEcsBundle(input);
    const records = bundle.events.trim().split('\n').map((line) => JSON.parse(line).hdf.source);
    expect(records.map((record) => record.pointer)).toEqual([
      '/baselines/0/requirements/0', '/baselines/0/requirements/1', '/baselines/1/requirements/0', '/baselines/1/requirements/1',
    ]);
    for (const record of records) {
      const resolved = await resolveExportSource(JSON.stringify(record), bundle.manifest, [{ href: 'source.json', bytes: input }]);
      expect(JSON.parse(resolved.requirement).id).toBe(record.requirement.id);
    }
  });

  it.each(['compliance.json', 'cve.json', 'override.json'])('validates complete OCSF bundle events: %s', async (name) => {
    const input = readFileSync(new URL(`../../converters/hdf-to-ocsf/fixtures/input/${name}`, import.meta.url));
    const bundle = await convertHdfToOcsfBundle(input);
    for (const line of bundle.events.trim().split('\n')) {
      const event = JSON.parse(line);
      const filename = event.class_uid === 2002 ? 'ocsf-vulnerability_finding-2002.schema.json' : 'ocsf-compliance_finding-2003.schema.json';
      const validate = loadSchemaValidator(fileURLToPath(new URL(`../../converters/hdf-to-ocsf/schemas/${filename}`, import.meta.url)));
      expect(validate(event), JSON.stringify(validate.errors)).toBe(true);
    }
  });

  it('keeps number spelling significant when comparing a carried requirement', async () => {
    const document = JSON.parse(readFileSync(fixture, 'utf8'));
    document.baselines[0].requirements[0].tags.sourceNumber = 'DECIMAL_TOKEN';
    const input = Buffer.from(JSON.stringify(document).replace('"DECIMAL_TOKEN"', '1.0'));
    expect(validateResults(JSON.parse(input.toString('utf8'))).valid).toBe(true);
    const bundle = await convertHdfToEcsBundle(input);
    const event = asMap(parseJSONPreservingNumbers(bundle.events))!;
    const record = asMap(asMap(event.hdf)!.source)!;
    const envelope = stringifyLine(canonicalize(record));
    const artifacts = [{ href: 'source.json', bytes: input }];
    expect((await resolveExportEvent(bundle.events, bundle.manifest, artifacts)).requirement).toContain('"sourceNumber":1.0');
    expect((await resolveExportSource(envelope, bundle.manifest, artifacts)).requirement).toContain('"sourceNumber":1.0');
    await expect(resolveExportSource(envelope.replace('"sourceNumber":1.0', '"sourceNumber":1'), bundle.manifest, artifacts)).rejects.toThrow(/record mismatch/);
  });

  it.each(['', 'null', '{"hdf":null}', '{"hdf":{}}\n{"hdf":{}}'])('rejects missing or malformed finding projections: %s', async (projection) => {
    await expect(buildExportBundle(readFileSync(fixture), projection, 'ecs')).rejects.toThrow();
  });

  it('rejects unknown targets and malformed source JSON', async () => {
    await expect(buildExportBundle(readFileSync(fixture), '', 'unknown')).rejects.toThrow(/target/);
    for (const input of ['', 'not-json', '{} {}', '\ufeff{}']) {
      await expect(convertHdfToEcsBundle(Buffer.from(input))).rejects.toThrow();
    }
    await expect(resolveExportSource('{}', '{}', [])).rejects.toThrow(/profile/);
    await expect(resolveExportSource('{', '{}', [])).rejects.toThrow();
  });

  it('matches executable Go bundle output byte-for-byte, including source-number spelling', async () => {
    const scratch = mkdtempSync(join(tmpdir(), 'hdf-bundle-parity-'));
    try {
      const program = join(scratch, 'main.go');
      writeFileSync(program, `package main
import (
 "encoding/json"
 "io"
 "os"
 ecs "github.com/mitre/hdf-libs/hdf-converters/v3/converters/hdf-to-ecs/go"
 splunk "github.com/mitre/hdf-libs/hdf-converters/v3/converters/hdf-to-splunk/go"
 ocsf "github.com/mitre/hdf-libs/hdf-converters/v3/converters/hdf-to-ocsf/go"
 "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go/exportmap"
)
func main() {
 input, err := io.ReadAll(os.Stdin); if err != nil { panic(err) }
 output := make([]*exportmap.ExportBundle, 0, 3)
 for _, convert := range []func([]byte, string) (*exportmap.ExportBundle, error){ecs.ConvertHDFToECSBundle, splunk.ConvertHDFToSplunkBundle, ocsf.ConvertHDFToOCSFBundle} {
  bundle, err := convert(input, "0.1.0"); if err != nil { panic(err) }; output = append(output, bundle)
 }
 if err := json.NewEncoder(os.Stdout).Encode(output); err != nil { panic(err) }
}`);
      const executable = join(scratch, process.platform === 'win32' ? 'bundles.exe' : 'bundles');
      execFileSync('go', ['build', '-o', executable, program], { cwd: fileURLToPath(new URL('../../../', import.meta.url)), timeout: 60_000 });
      const original = readFileSync(fixture);
      const boundary = JSON.parse(original.toString('utf8'));
      boundary.baselines[0].requirements[0].tags.future = JSON.parse('{"10":"ten","2":"two","__proto__":null,"nested":[null,{},[],false],"unicode":["😀","�","\\\\ud800"],"large":"RAW_LARGE_NUMBER","decimal":"RAW_DECIMAL_NUMBER","negativeZero":"RAW_NEGATIVE_ZERO"}');
      const variant = Buffer.from(JSON.stringify(boundary).replace('"RAW_LARGE_NUMBER"', '9007199254740993').replace('"RAW_DECIMAL_NUMBER"', '1.0').replace('"RAW_NEGATIVE_ZERO"', '-0'));
      expect(validateResults(JSON.parse(variant.toString('utf8'))).valid).toBe(true);
      for (const input of [original, variant]) {
        const peer = JSON.parse(execFileSync(executable, { input, encoding: 'utf8', timeout: 20_000 })) as { Events: string; Manifest: string; Source: string }[];
        for (const [index, convert] of [convertHdfToEcsBundle, convertHdfToSplunkBundle, convertHdfToOcsfBundle].entries()) {
          const bundle = await convert(input);
          expect.soft(Buffer.from(peer[index].Events, 'base64').toString('utf8')).toBe(bundle.events);
          expect.soft(Buffer.from(peer[index].Manifest, 'base64').toString('utf8')).toBe(bundle.manifest);
          expect(Buffer.from(peer[index].Source, 'base64')).toEqual(input);
        }
      }
    } finally {
      rmSync(scratch, { recursive: true, force: true });
    }
  });

  it('validates all emitted envelopes and manifests against the shared HDF-based schema', async () => {
    const input = readFileSync(fixture);
    expect(validateResults(JSON.parse(input.toString('utf8'))).valid).toBe(true);
    const common = JSON.parse(readFileSync(new URL('../../../hdf-schema/src/schemas/primitives/common.schema.json', import.meta.url), 'utf8'));
    const schema = JSON.parse(readFileSync(new URL('../export-bundle.schema.json', import.meta.url), 'utf8'));
    const ajv = new Ajv2020({ strict: false, allErrors: true });
    addFormats(ajv);
    ajv.addSchema(common);
    ajv.addSchema(schema);
    const manifestValid = ajv.compile({ $ref: `${schema.$id}#/$defs/Manifest` });
    const envelopeValid = ajv.compile({ $ref: `${schema.$id}#/$defs/SourceEnvelope` });
    for (const convert of [convertHdfToEcsBundle, convertHdfToSplunkBundle, convertHdfToOcsfBundle]) {
      const bundle = await convert(input);
      const event = JSON.parse(bundle.events);
      expect(manifestValid(JSON.parse(bundle.manifest)), JSON.stringify(manifestValid.errors)).toBe(true);
      expect(envelopeValid(event.hdf?.source ?? event.event?.hdf.source ?? event.unmapped.hdf_source), JSON.stringify(envelopeValid.errors)).toBe(true);
    }
  });

  it.each(resolverCases)('resolves retained source: $name', async ({ edits, artifactMode, error }) => {
    const input = readFileSync(fixture);
    const bundle = await convertHdfToEcsBundle(input);
    const documents = { envelope: JSON.parse(bundle.events).hdf.source, manifest: JSON.parse(bundle.manifest) };
    for (const edit of edits) {
      let parent = documents[edit.document];
      for (const key of edit.path.slice(0, -1)) parent = parent[key];
      if (edit.remove) delete parent[edit.path.at(-1)!];
      else parent[edit.path.at(-1)!] = edit.value;
    }
    let artifacts = [{ href: 'source.json', bytes: input }];
    if (artifactMode === 'missing') artifacts = [];
    if (artifactMode === 'duplicate') artifacts.push(artifacts[0]);
    if (artifactMode === 'tampered') artifacts[0].bytes = Buffer.concat([input, Buffer.from(' ')]);
    if (artifactMode === 'duplicate-reference') documents.manifest.artifacts.push(documents.manifest.artifacts[0]);
    const resolve = () => resolveExportSource(JSON.stringify(documents.envelope), JSON.stringify(documents.manifest), artifacts);
    if (error) {
      await expect(resolve()).rejects.toThrow(new RegExp(error));
    } else {
      const resolved = await resolve();
      const baseline = JSON.parse(input.toString('utf8')).baselines[0];
      expect(Buffer.from(resolved.source)).toEqual(input);
      expect(JSON.parse(resolved.baseline)).toEqual(baseline);
      expect(JSON.parse(resolved.requirement)).toEqual(baseline.requirements[0]);
    }
  });

  it.each([
    { target: 'ecs', convert: convertHdfToEcs, bundle: convertHdfToEcsBundle, path: ['hdf', 'source'] },
    { target: 'splunk', convert: convertHdfToSplunk, bundle: convertHdfToSplunkBundle, path: ['event', 'hdf', 'source'] },
    { target: 'ocsf', convert: convertHdfToOcsf, bundle: convertHdfToOcsfBundle, path: ['unmapped', 'hdf_source'] },
  ])('adds complete source data without changing $target projections', async ({ target, convert, bundle, path }) => {
    const input = readFileSync(fixture);
    const output = await bundle(input, '0.1.0');
    const event = JSON.parse(output.events);
    let parent = event;
    for (const key of path.slice(0, -1)) parent = parent[key];
    const key = path.at(-1)!;
    expect(parent[key].requirement).toEqual(JSON.parse(input.toString('utf8')).baselines[0].requirements[0]);
    delete parent[key];
    expect(event).toEqual(JSON.parse(convert(input.toString('utf8'), '0.1.0')));
    expect(Buffer.from(output.source)).toEqual(input);
    expect(JSON.parse(output.manifest).target).toBe(target);
    expect(JSON.parse((await resolveExportEvent(output.events, output.manifest, [{ href: 'source.json', bytes: input }])).requirement))
      .toEqual(JSON.parse(input.toString('utf8')).baselines[0].requirements[0]);
  });

  it('enforces the configured byte limit before decoding', async () => {
    setDefaultMaxInputSize(1);
    try {
      await expect(buildExportBundle(Buffer.from('not json'), '', 'ecs')).rejects.toThrow(/maximum allowed size/);
    } finally {
      setDefaultMaxInputSize(0);
    }
  });

  it('rejects malformed Unicode even in an overwritten duplicate member', async () => {
    const original = readFileSync(fixture, 'utf8');
    const source = Buffer.from(original.replace('"title": "Ensure SSH', '"title": "\\ud800", "title": "Ensure SSH'));
    await expect(buildExportBundle(source, convertHdfToEcs(original), 'ecs')).rejects.toThrow(/Unicode/);
  });

  it.each(['null', '[]', '{}', '{"baselines":null}', '{"baselines":{}}'])('rejects missing result collections: %s', async (input) => {
    await expect(buildExportBundle(Buffer.from(input), '', 'ecs')).rejects.toThrow(/baselines/);
  });

  it('rejects extra projections instead of silently discarding them', async () => {
    const input = readFileSync(fixture);
    const legacy = convertHdfToEcs(input.toString('utf8'));
    await expect(buildExportBundle(input, legacy + legacy, 'ecs')).rejects.toThrow(/count/);
  });

  it('rejects an existing source envelope instead of overwriting it', async () => {
    const input = readFileSync(fixture);
    const event = JSON.parse(convertHdfToEcs(input.toString('utf8')));
    event.hdf.source = null;
    await expect(buildExportBundle(input, JSON.stringify(event), 'ecs')).rejects.toThrow(/already/);
  });

  it.each(['\\ud800', '\\udfff'])('rejects unpaired surrogate %s before preserving records', async (escape) => {
    const original = readFileSync(fixture, 'utf8');
    const source = Buffer.from(original.replace('Ensure SSH root login is disabled', escape));
    await expect(buildExportBundle(source, convertHdfToEcs(original), 'ecs')).rejects.toThrow();
  });

  it('rejects invalid UTF-8 inside an otherwise valid source string', async () => {
    const input = readFileSync(fixture);
    const legacy = convertHdfToEcs(input.toString('utf8'));
    const index = input.indexOf('Ensure SSH');
    expect(index).toBeGreaterThan(0);
    input[index] = 0xff;
    await expect(buildExportBundle(input, legacy, 'ecs')).rejects.toThrow();
  });

  it('delivers a versioned manifest whose identity hashes the original artifact bytes', async () => {
    const input = readFileSync(fixture);
    const digest = createHash('sha512').update(input).digest('hex');
    const bundle = await buildExportBundle(input, convertHdfToEcs(input.toString('utf8')), 'ecs');
    const artifact = {
      sourceName: 'hdf-results', externalId: `sha512:${digest}`, mediaType: 'application/json',
      checksum: { algorithm: 'sha512', value: digest },
    };
    expect(JSON.parse(bundle.manifest)).toEqual({
      profileVersion: '1.0', outputProfile: 'legacy-additive/1', target: 'ecs',
      events: 'events.ndjson', artifacts: [{ ...artifact, href: 'source.json' }],
    });
    expect(JSON.parse(bundle.events.trim()).hdf.source).toMatchObject({
      profileVersion: '1.0', outputProfile: 'legacy-additive/1', artifact,
    });
  });

  it('retains original bytes and the complete requirement alongside the native projection', async () => {
    const input = readFileSync(fixture);
    const original = JSON.parse(input.toString('utf8'));
    const legacy = convertHdfToEcs(input.toString('utf8'));
    const bundle = await buildExportBundle(input, legacy, 'ecs');
    expect(Buffer.from(bundle.source)).toEqual(input);
    const event = JSON.parse(bundle.events.trim());
    expect(event.hdf.source.pointer).toBe('/baselines/0/requirements/0');
    expect(event.hdf.source.requirement).toEqual(original.baselines[0].requirements[0]);
    expect(event.event).toEqual(JSON.parse(legacy).event);
    expect(JSON.parse(Buffer.from(bundle.source).toString('utf8')).baselines[0].integrity).toEqual({
      algorithm: 'sha256', checksum: 'abc123',
    });
  });
});
