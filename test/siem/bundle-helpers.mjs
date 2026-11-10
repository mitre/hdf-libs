import assert from 'node:assert/strict';
import { readFile, writeFile, mkdir, stat, rename } from 'node:fs/promises';
import { join } from 'node:path';
import { command, repository } from './harness.mjs';

export const execution = { timeout: 600_000, maxBuffer: 32 * 1024 * 1024 };
export const lossless = (text) => JSON.parse(text, (_key, value, context) =>
  typeof value === 'number' ? JSON.rawJSON(context.source) : value);

export async function consumer(artifacts, fn, args, signal) {
  return command(process.execPath, ['--input-type=module', '-e', `await (${fn.toString()})(process.argv.slice(1))`, ...args],
    { ...execution, cwd: artifacts.consumer, signal });
}

export async function sourceCase(entry) {
  const bytes = await readFile(join(repository, entry.path));
  if (!entry.variant) return bytes;
  const source = lossless(bytes.toString('utf8'));
  if (entry.variant === 'empty') source.baselines = [];
  else if (entry.variant === 'duplicate-ids') {
    source.baselines[0].requirements.push(source.baselines[0].requirements[0]);
  } else {
    assert.equal(entry.variant, 'boundary');
    const schema = JSON.parse(await readFile(join(repository, 'hdf-schema/src/schemas/primitives/extensions.schema.json'), 'utf8'));
    source.integrity = schema.$defs.Integrity.examples[1];
    source.baselines[0].integrity = source.integrity;
    const future = {
      unicode: 'café 東京 😀 \\u0041', nullable: null, empty: '',
      integer: JSON.rawJSON('9007199254740993'), negativeZero: JSON.rawJSON('-0'),
      plain: 'x'.repeat(1024 * 1024 + 1), escaped: '\n'.repeat(512 * 1024 + 1),
    };
    source.extensions = { passthrough: { futureOptional: future } };
    source.baselines[0].extensions = { passthrough: { futureOptional: future } };
    source.baselines[0].requirements[0].tags.futureOptional = future;
  }
  return Buffer.from(JSON.stringify(source));
}

export async function makeBundle(artifacts, producer, input, folder, signal, target = 'ecs') {
  assert.ok(['ecs', 'splunk'].includes(target), 'unsupported integration target');
  const output = join(folder, 'export');
  const archive = join(folder, 'export.zip');
  const options = { ...execution, signal };
  if (producer === 'cli') {
    await command(artifacts.cli, ['convert', input, '--to', target, '--bundle', '-o', archive], options);
    await command('unzip', ['-q', archive, '-d', output], options);
  } else {
    await mkdir(output);
    await consumer(artifacts, async ([input, output, target]) => {
      const { convertHdfToEcsBundle, convertHdfToSplunkBundle } = await import('@mitre/hdf-converters');
      const { readFile, writeFile } = await import('node:fs/promises');
      const { join } = await import('node:path');
      const convert = target === 'ecs' ? convertHdfToEcsBundle : convertHdfToSplunkBundle;
      const bundle = await convert(await readFile(input));
      for (const [name, bytes] of Object.entries({ 'source.json': bundle.source, 'events.ndjson': bundle.events, 'manifest.json': bundle.manifest })) {
        await writeFile(join(output, name), bytes);
      }
    }, [input, output, target], signal);
    const pkg = join(output, 'evidence-package.json');
    await command(artifacts.cli, ['evidence', 'build', '--results', join(output, 'source.json'), '-o', pkg], options);
    await command(artifacts.cli, ['evidence', 'add-evidence', pkg,
      '--file', join(output, 'events.ndjson'), '--format', target === 'ecs' ? 'ecs' : 'x-splunk-export',
      '--file', join(output, 'manifest.json'), '--format', 'x-hdf-siem-export-profile'], options);
    await command(artifacts.cli, ['evidence', 'bundle', pkg, '-o', archive], options);
  }
  const sizes = {};
  for (const name of ['source.json', 'events.ndjson', 'manifest.json', 'evidence-package.json']) {
    sizes[name] = (await stat(join(output, name))).size;
  }
  sizes.totalUncompressed = Object.values(sizes).reduce((sum, size) => sum + size, 0);
  sizes.archive = (await stat(archive)).size;
  return { output, sizes };
}

// Runs in the installed consumer so every library import follows its public exports.
export async function verifyReadback([input, output, retained, name, target = 'ecs']) {
  const assert = (await import('node:assert/strict')).default;
  const { readFile, readdir } = await import('node:fs/promises');
  const { join } = await import('node:path');
  const { resolveExportEvent } = await import('@mitre/hdf-converters');
  const { parseEvidencePackage, parseExternalEvidence, verifyChecksums } = await import('@mitre/hdf-engine');
  const { computeEffectiveStatus, governingStatusOverride, impactToSeverity } = await import('@mitre/hdf-utilities');
  assert.ok(['ecs', 'splunk'].includes(target), 'unsupported integration target');
  const parse = (text) => JSON.parse(text, (_key, value, context) =>
    typeof value === 'number' ? JSON.rawJSON(context.source) : value);
  const original = await readFile(input);
  const expected = parse(original.toString('utf8'));
  if (name === 'boundary') {
    const future = expected.baselines[0].requirements[0].tags.futureOptional;
    assert.equal(future.integer.rawJSON, '9007199254740993');
    assert.equal(future.negativeZero.rawJSON, '-0');
    assert.equal(future.unicode, 'café 東京 😀 \\u0041');
    assert.equal(future.nullable, null);
    assert.equal(Object.hasOwn(future, 'missing'), false);
    assert.equal(future.plain.length, 1024 * 1024 + 1);
    assert.equal(future.escaped.length, 512 * 1024 + 1);
    assert.ok(expected.integrity.signature);
    assert.deepEqual(expected.baselines[0].integrity, expected.integrity);
  }
  if (name === 'duplicate-ids') {
    assert.equal(expected.baselines[0].requirements.length, 2);
    assert.equal(expected.baselines[0].requirements[0].id, expected.baselines[0].requirements[1].id);
  }
  if (name === 'empty') assert.deepEqual(expected.baselines, []);
  const pkg = await readFile(join(output, 'evidence-package.json'), 'utf8');
  const entries = [...parseEvidencePackage(pkg).contents, ...parseExternalEvidence(pkg)];
  assert.deepEqual(entries.map((e) => e.uri).sort(), ['events.ndjson', 'manifest.json', 'source.json']);
  assert.equal(entries.find((e) => e.uri === 'source.json').type, 'hdf-results');
  assert.equal(entries.find((e) => e.uri === 'events.ndjson').format, target === 'ecs' ? 'ecs' : 'x-splunk-export');
  assert.equal(entries.find((e) => e.uri === 'manifest.json').format, 'x-hdf-siem-export-profile');
  const snapshots = new Map();
  for (const entry of entries) {
    assert.equal(entry.checksumAlgorithm, 'sha512');
    snapshots.set(entry.uri, await readFile(join(output, entry.uri)));
  }
  const checked = await verifyChecksums(entries, (uri) => snapshots.get(uri));
  assert.deepEqual(checked.map((result) => result.status), ['match', 'match', 'match']);
  assert.deepEqual(snapshots.get('source.json'), original);
  const manifest = snapshots.get('manifest.json').toString('utf8');
  const inventory = JSON.parse(manifest);
  assert.equal(inventory.target, target);
  assert.equal(inventory.events, 'events.ndjson');
  assert.equal(inventory.artifacts.length, 1);
  assert.equal(inventory.artifacts[0].href, 'source.json');
  assert.equal(inventory.artifacts[0].checksum.value, entries.find((e) => e.uri === 'source.json').checksum);
  const sourceArtifacts = [{ href: 'source.json', bytes: snapshots.get('source.json') }];
  const occurrences = expected.baselines.flatMap((baseline, bi) => baseline.requirements.map((requirement, ri) =>
    ({ baseline, requirement, pointer: `/baselines/${bi}/requirements/${ri}` })));
  const files = (await readdir(retained)).sort((a, b) => Number(a.split('.')[0]) - Number(b.split('.')[0]));
  assert.equal(files.length, occurrences.length);
  const outcomes = { success: 0, failure: 0, unknown: 0 };
  const severities = {};
  const rawStatuses = {};
  const impacts = {};
  const effectiveImpacts = {};
  const scores = {};
  const effectiveStatuses = {};
  const dispositions = {};
  const suppression = {};
  let activeFindings = 0;
  const pointers = new Set();
  for (let i = 0; i < files.length; i++) {
    const raw = await readFile(join(retained, files[i]), 'utf8');
    const envelope = JSON.parse(raw);
    const event = target === 'splunk' ? envelope.event : envelope;
    const occurrence = occurrences[i];
    assert.equal(event.hdf.source.pointer, occurrence.pointer);
    pointers.add(event.hdf.source.pointer);
    const resolved = await resolveExportEvent(raw, manifest, sourceArtifacts);
    assert.deepEqual(Buffer.from(resolved.source), original);
    assert.deepEqual(parse(resolved.requirement), occurrence.requirement);
    assert.deepEqual(parse(resolved.baseline), occurrence.baseline);
    // Derive projection expectations from the source and canonical status API.
    const req = JSON.parse(JSON.stringify(occurrence.requirement));
    const status = computeEffectiveStatus({ impact: req.impact, resultStatuses: req.results.map((r) => r.status), overrides: req.statusOverrides });
    const rawStatus = computeEffectiveStatus({ impact: req.impact, resultStatuses: req.results.map((r) => r.status) });
    const outcome = status === 'passed' ? 'success' : status === 'failed' ? 'failure' : 'unknown';
    if (target === 'ecs') assert.equal(event.event.outcome, outcome);
    else {
      assert.equal(event.hdf_status, rawStatus);
      const suppressed = governingStatusOverride(req.statusOverrides ?? []) !== undefined
        && ['failed', 'error'].includes(rawStatus) && !['failed', 'error'].includes(status);
      assert.equal(event.suppressed, suppressed);
      suppression[suppressed] = (suppression[suppressed] ?? 0) + 1;
      const cve = (req.cvss ?? []).find((entry) => entry.source?.toUpperCase().startsWith('CVE-'))?.source;
      if (!suppressed && (['failed', 'error'].includes(rawStatus) || cve)) activeFindings++;
    }
    assert.equal(event.hdf.status, rawStatus);
    outcomes[outcome]++;
    rawStatuses[rawStatus] = (rawStatuses[rawStatus] ?? 0) + 1;
    // Native queries treat -0 as zero; preservation checks keep its source token.
    assert.ok(event.hdf.impact === req.impact);
    impacts[req.impact] = (impacts[req.impact] ?? 0) + 1;
    if (Object.hasOwn(req, 'effectiveImpact')) {
      assert.equal(event.hdf.effective_impact, req.effectiveImpact);
      effectiveImpacts[req.effectiveImpact] = (effectiveImpacts[req.effectiveImpact] ?? 0) + 1;
    }
    for (const [sourceKey, eventKey, counts] of [
      ['effectiveStatus', 'effective_status', effectiveStatuses],
      ['disposition', 'disposition', dispositions],
      ['effectiveImpact', 'effective_impact', effectiveImpacts],
    ]) {
      assert.equal(Object.hasOwn(event.hdf, eventKey), Object.hasOwn(req, sourceKey), `${eventKey} presence`);
      if (Object.hasOwn(req, sourceKey)) {
        assert.equal(event.hdf[eventKey], req[sourceKey], eventKey);
        if (sourceKey !== 'effectiveImpact') counts[req[sourceKey]] = (counts[req[sourceKey]] ?? 0) + 1;
      }
    }
    if (target === 'ecs') {
      const severity = req.cvss?.[0]?.baseSeverity ?? req.severity;
      if (req.cvss?.length && severity) {
        assert.equal(event.vulnerability.severity, severity);
        severities[severity] = (severities[severity] ?? 0) + 1;
      }
      if (req.cvss?.length && Object.hasOwn(req.cvss[0], 'baseScore')) {
        const score = req.cvss[0].baseScore;
        assert.ok(event.vulnerability.score.base === score);
        scores[score] = (scores[score] ?? 0) + 1;
      }
    } else {
      const severity = impactToSeverity(req.impact);
      assert.equal(event.severity, severity);
      severities[severity] = (severities[severity] ?? 0) + 1;
      const sourceScores = (req.cvss ?? []).filter((c) => typeof c.baseScore === 'number').map((c) => c.baseScore);
      if (sourceScores.length) {
        const score = Math.max(...sourceScores);
        assert.ok(event.cvss === score);
        scores[score] = (scores[score] ?? 0) + 1;
      } else assert.equal(Object.hasOwn(event, 'cvss'), false);
    }
  }
  assert.equal(pointers.size, occurrences.length, 'duplicate IDs must retain distinct occurrences');
  console.log(JSON.stringify({ events: files.length, outcomes, rawStatuses, severities, impacts, effectiveImpacts, scores,
    effectiveStatuses, dispositions, suppression, ...(target === 'splunk' ? { activeFindings } : {}), checksums: checked.length }));
}

export async function rejectArtifacts(artifacts, output, event, signal) {
  const pkg = join(output, 'evidence-package.json');
  const { target } = JSON.parse(await readFile(join(output, 'manifest.json'), 'utf8'));
  assert.ok(['ecs', 'splunk'].includes(target));
  const options = { ...execution, signal };
  const rejectCLI = async () => assert.rejects(
    command(artifacts.cli, ['evidence', 'resolve', pkg, '--event', event], options),
    (error) => typeof error.code === 'number' && error.code !== 0 && error.stdout === '' && error.stderr.length > 0);
  const checks = [];
  for (const name of ['source.json', 'events.ndjson', 'manifest.json']) {
    const path = join(output, name);
    const original = await readFile(path);
    for (const mode of ['missing', 'altered']) {
      try {
        if (mode === 'missing') await rename(path, `${path}.saved`);
        else await writeFile(path, Buffer.concat([original, Buffer.from(' ')]));
        await rejectCLI();
        await consumer(artifacts, async ([output, name, mode]) => {
          const assert = (await import('node:assert/strict')).default;
          const { readFileSync } = await import('node:fs');
          const { join } = await import('node:path');
          const { parseEvidencePackage, parseExternalEvidence, verifyChecksums } = await import('@mitre/hdf-engine');
          const pkg = readFileSync(join(output, 'evidence-package.json'), 'utf8');
          const entries = [...parseEvidencePackage(pkg).contents, ...parseExternalEvidence(pkg)];
          const checked = await verifyChecksums(entries, (uri) => readFileSync(join(output, uri)));
          assert.equal(checked.find((c) => c.uri === name).status, mode === 'missing' ? 'error' : 'mismatch');
        }, [output, name, mode], signal);
        checks.push(`${mode}-${name}`);
      } finally {
        if (mode === 'missing') await rename(`${path}.saved`, path);
        else await writeFile(path, original);
      }
    }
  }
  const original = await readFile(pkg);
  try {
    const duplicated = JSON.parse(original);
    duplicated.contents.push(duplicated.contents[0]);
    await writeFile(pkg, JSON.stringify(duplicated));
    await rejectCLI();
    checks.push('ambiguous-package-source');
  } finally { await writeFile(pkg, original); }
  await consumer(artifacts, async ([output, event]) => {
    const assert = (await import('node:assert/strict')).default;
    const { readFile } = await import('node:fs/promises');
    const { join } = await import('node:path');
    const { resolveExportEvent } = await import('@mitre/hdf-converters');
    const raw = await readFile(event, 'utf8');
    const manifest = await readFile(join(output, 'manifest.json'), 'utf8');
    const source = { href: 'source.json', bytes: await readFile(join(output, 'source.json')) };
    await assert.rejects(resolveExportEvent(raw, manifest, [source, source]), /ambiguous/);
    const duplicate = JSON.parse(manifest);
    duplicate.artifacts.push(duplicate.artifacts[0]);
    await assert.rejects(resolveExportEvent(raw, JSON.stringify(duplicate), [source]), /ambiguous/);
    const changed = JSON.parse(raw);
    const payload = JSON.parse(manifest).target === 'splunk' ? changed.event : changed;
    payload.hdf.source.requirement.title += ' changed';
    await assert.rejects(resolveExportEvent(JSON.stringify(changed), manifest, [source]), /record mismatch/);
  }, [output, event], signal);
  const raw = await readFile(event);
  try {
    const changed = lossless(raw.toString('utf8'));
    const payload = target === 'splunk' ? changed.event : changed;
    payload.hdf.source.requirement.title += ' changed';
    await writeFile(event, JSON.stringify(changed));
    await rejectCLI();
    checks.push('ambiguous-manifest', 'ambiguous-supplied-source', 'changed-record');
  } finally { await writeFile(event, raw); }
  return checks;
}
