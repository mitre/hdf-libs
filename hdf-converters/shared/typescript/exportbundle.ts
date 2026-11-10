/// <reference lib="es2024.string" />
/// <reference lib="es2022.object" />
import { HashAlgorithm, type ExternalReference } from '@mitre/hdf-schema';
import { sha512, validateInputSize } from '@mitre/hdf-utilities';
import { createScanner } from 'jsonc-parser';
import { type Obj, asArr, asMap, canonicalize, parseJSONPreservingNumbers, stringifyLine } from './exportmap.js';

export interface ExportBundle {
  events: string;
  source: Uint8Array;
  manifest: string;
}

export interface BundleArtifact {
  href: string;
  bytes: Uint8Array;
}

export interface ResolvedExportSource {
  source: Uint8Array;
  baseline: string;
  requirement: string;
}

export async function resolveExportEvent(event: string, manifest: string, artifacts: readonly BundleArtifact[]): Promise<ResolvedExportSource> {
  const inventory = requireProfile(parseBundleJSON(manifest));
  const target = bundleTarget(inventory.target);
  const { parent, key } = envelopeParent(asMap(parseBundleJSON(event)), target);
  if (!parent || !asMap(parent[key])) throw new Error('Missing source envelope');
  return resolveExportSource(stringifyLine(canonicalize(parent[key])), manifest, artifacts);
}

export async function resolveExportSource(envelope: string, manifest: string, artifacts: readonly BundleArtifact[]): Promise<ResolvedExportSource> {
  const record = requireProfile(parseBundleJSON(envelope));
  const inventory = requireProfile(parseBundleJSON(manifest));
  if (record.profileVersion !== inventory.profileVersion || record.outputProfile !== inventory.outputProfile) {
    throw new Error('Manifest profile mismatch');
  }
  bundleTarget(inventory.target);
  if (inventory.events !== 'events.ndjson') throw new Error('Unsupported manifest events location');
  const digest = artifactDigest(record.artifact);
  const references = asArr(inventory.artifacts) ?? [];
  const matches = references.filter((reference) => artifactDigest(reference) === digest);
  if (matches.length !== 1) throw new Error('Missing or ambiguous manifest artifact');
  const href = asMap(matches[0])?.href;
  if (typeof href !== 'string' || href.length === 0) throw new Error('Missing artifact location');
  const supplied = artifacts.filter((artifact) => artifact.href === href);
  const suppliedArtifact = supplied[0];
  if (supplied.length !== 1 || !suppliedArtifact) throw new Error('Missing or ambiguous supplied artifact');
  validateInputSize(suppliedArtifact.bytes);
  const bytes = new Uint8Array(suppliedArtifact.bytes);
  if ((await sha512(bytes)) !== digest) throw new Error('Artifact checksum mismatch');
  const source = asMap(parseBundleJSON(new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes)));
  const pointer = typeof record.pointer === 'string'
    ? /^\/baselines\/(0|[1-9]\d*)\/requirements\/(0|[1-9]\d*)$/.exec(record.pointer) : null;
  if (!pointer) throw new Error('Invalid requirement pointer');
  const bi = Number(pointer[1]);
  const ri = Number(pointer[2]);
  if (!Number.isSafeInteger(bi) || !Number.isSafeInteger(ri)) throw new Error('Invalid requirement pointer');
  const baseline = asMap(asArr(source?.baselines)?.[bi]);
  const requirement = asMap(asArr(baseline?.requirements)?.[ri]);
  if (!baseline || !requirement) throw new Error('Requirement pointer does not resolve');
  const canonicalRecord = stringifyLine(canonicalize(requirement));
  if (!asMap(record.requirement) || canonicalRecord !== stringifyLine(canonicalize(record.requirement))) {
    throw new Error('Source record mismatch');
  }
  return { source: new Uint8Array(bytes), baseline: stringifyLine(canonicalize(baseline)) + '\n', requirement: canonicalRecord + '\n' };
}

function requireProfile(value: unknown): Obj {
  const object = asMap(value);
  if (!object || typeof object.profileVersion !== 'string' || !/^1\.(0|[1-9]\d*)$/.test(object.profileVersion)
      || object.outputProfile !== 'legacy-additive/1') throw new Error('Unsupported source profile');
  return object;
}

function bundleTarget(value: unknown): string {
  if (typeof value !== 'string' || !['ecs', 'splunk', 'ocsf'].includes(value)) {
    throw new Error('Unsupported bundle target');
  }
  return value;
}

function envelopeParent(event: Obj | undefined, target: string): { parent: Obj | undefined; key: string } {
  if (target === 'ocsf') return { parent: asMap(event?.unmapped), key: 'hdf_source' };
  const payload = target === 'splunk' ? asMap(event?.event) : event;
  return { parent: asMap(payload?.hdf), key: 'source' };
}

function artifactDigest(value: unknown): string {
  const artifact = asMap(value);
  const checksum = asMap(artifact?.checksum);
  if (artifact?.sourceName !== 'hdf-results' || artifact.mediaType !== 'application/json'
      || checksum?.algorithm !== 'sha512' || typeof checksum.value !== 'string'
      || !/^[a-f0-9]{128}$/.test(checksum.value) || artifact.externalId !== `sha512:${checksum.value}`) {
    throw new Error('Invalid artifact identity');
  }
  return checksum.value;
}

function parseBundleJSON(text: string): unknown {
  validateInputSize(text);
  if (!text.isWellFormed()) throw new Error('Unpaired Unicode surrogate in source');
  const value = parseJSONPreservingNumbers(text);
  // Inspect every string token: parsing an object hides overwritten duplicate members.
  const scanner = createScanner(text, true);
  while (scanner.getPosition() < text.length) {
    scanner.scan();
    if (!scanner.getTokenValue().isWellFormed()) {
      throw new Error('Unpaired Unicode surrogate in source');
    }
  }
  return value;
}

export async function projectExportBundle(input: Uint8Array, target: string, project: (text: string) => string): Promise<ExportBundle> {
  validateInputSize(input);
  const text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(input);
  return buildExportBundle(input, project(text), target);
}

export async function buildExportBundle(input: Uint8Array, events: string, target: string): Promise<ExportBundle> {
  validateInputSize(input);
  bundleTarget(target);
  const retained = new Uint8Array(input);
  const text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(retained);
  const source = parseBundleJSON(text);
  const digest = await sha512(retained);
  const artifact: ExternalReference = {
    sourceName: 'hdf-results', externalId: `sha512:${digest}`, mediaType: 'application/json',
    checksum: { algorithm: HashAlgorithm.Sha512, value: digest },
  };
  const profile = { profileVersion: '1.0', outputProfile: 'legacy-additive/1' };
  const document = asMap(source);
  const baselines = asArr(document?.baselines);
  if (!baselines) throw new Error('Source must contain a baselines array');
  const lines = events.trim() ? events.trimEnd().split('\n') : [];
  const output: string[] = [];
  for (const [bi, rawBaseline] of baselines.entries()) {
    const baseline = asMap(rawBaseline);
    for (const [ri, requirement] of (asArr(baseline?.requirements) ?? []).entries()) {
      if (!asMap(requirement)) continue;
      const event = asMap(parseJSONPreservingNumbers(lines[output.length] ?? 'null'));
      const { parent, key } = envelopeParent(event, target);
      if (!event || !parent) throw new Error(`Missing ${target} finding projection`);
      if (Object.hasOwn(parent, key)) throw new Error('Projection already contains a source envelope');
      parent[key] = { ...profile, artifact, pointer: `/baselines/${bi}/requirements/${ri}`, requirement };
      output.push(stringifyLine(canonicalize(event)));
    }
  }
  if (output.length !== lines.length) throw new Error('Finding projection count does not match source requirements');
  const manifest = { ...profile, target, events: 'events.ndjson', artifacts: [{ ...artifact, href: 'source.json' }] };
  return {
    events: output.length ? output.join('\n') + '\n' : '', source: retained,
    manifest: stringifyLine(canonicalize(manifest)) + '\n',
  };
}
