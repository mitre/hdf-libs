import assert from 'node:assert/strict';
import { readFile, writeFile, mkdir, stat, rename } from 'node:fs/promises';
import { join, dirname } from 'node:path';
import { createHash } from 'node:crypto';
import { command, repository } from './harness.mjs';

const execution = { timeout: 600_000, maxBuffer: 32 * 1024 * 1024 };
const lossless = (text) => JSON.parse(text, (_key, value, context) =>
  typeof value === 'number' ? JSON.rawJSON(context.source) : value);

function assertBulkCreated(bulk, expected) {
  assert.equal(bulk.errors, false, JSON.stringify(bulk.items));
  assert.equal(bulk.items.length, expected);
  for (const item of bulk.items) assert.equal(item.create.status, 201);
}

async function consumer(artifacts, fn, args, signal) {
  return command(process.execPath, ['--input-type=module', '-e', `await (${fn.toString()})(process.argv.slice(1))`, ...args],
    { ...execution, cwd: artifacts.consumer, signal });
}

async function sourceCase(entry) {
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

async function makeBundle(artifacts, producer, input, folder, signal) {
  const output = join(folder, 'export');
  const archive = join(folder, 'export.zip');
  const options = { ...execution, signal };
  if (producer === 'cli') {
    await command(artifacts.cli, ['convert', input, '--to', 'ecs', '--bundle', '-o', archive], options);
    await command('unzip', ['-q', archive, '-d', output], options);
  } else {
    await mkdir(output);
    await consumer(artifacts, async ([input, output]) => {
      const { convertHdfToEcsBundle } = await import('@mitre/hdf-converters');
      const { readFile, writeFile } = await import('node:fs/promises');
      const { join } = await import('node:path');
      const bundle = await convertHdfToEcsBundle(await readFile(input));
      for (const [name, bytes] of Object.entries({ 'source.json': bundle.source, 'events.ndjson': bundle.events, 'manifest.json': bundle.manifest })) {
        await writeFile(join(output, name), bytes);
      }
    }, [input, output], signal);
    const pkg = join(output, 'evidence-package.json');
    await command(artifacts.cli, ['evidence', 'build', '--results', join(output, 'source.json'), '-o', pkg], options);
    await command(artifacts.cli, ['evidence', 'add-evidence', pkg,
      '--file', join(output, 'events.ndjson'), '--format', 'ecs',
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
export async function verifyReadback([input, output, retained, name]) {
  const assert = (await import('node:assert/strict')).default;
  const { readFile, readdir } = await import('node:fs/promises');
  const { join } = await import('node:path');
  const { resolveExportEvent } = await import('@mitre/hdf-converters');
  const { parseEvidencePackage, parseExternalEvidence, verifyChecksums } = await import('@mitre/hdf-engine');
  const { computeEffectiveStatus } = await import('@mitre/hdf-utilities');
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
  assert.equal(entries.find((e) => e.uri === 'events.ndjson').format, 'ecs');
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
  assert.equal(inventory.target, 'ecs');
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
  const pointers = new Set();
  for (let i = 0; i < files.length; i++) {
    const raw = await readFile(join(retained, files[i]), 'utf8');
    const event = JSON.parse(raw);
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
    assert.equal(event.event.outcome, outcome);
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
  }
  assert.equal(pointers.size, occurrences.length, 'duplicate IDs must retain distinct occurrences');
  console.log(JSON.stringify({ events: files.length, outcomes, rawStatuses, severities, impacts, effectiveImpacts, scores,
    effectiveStatuses, dispositions, checksums: checked.length }));
}

async function rejectArtifacts(artifacts, output, event, signal) {
  const pkg = join(output, 'evidence-package.json');
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
    changed.hdf.source.requirement.title += ' changed';
    await assert.rejects(resolveExportEvent(JSON.stringify(changed), manifest, [source]), /record mismatch/);
  }, [output, event], signal);
  const raw = await readFile(event);
  try {
    const changed = lossless(raw.toString('utf8'));
    changed.hdf.source.requirement.title += ' changed';
    await writeFile(event, JSON.stringify(changed));
    await rejectCLI();
    checks.push('ambiguous-manifest', 'ambiguous-supplied-source', 'changed-record');
  } finally { await writeFile(event, raw); }
  return checks;
}

export async function verify({ artifacts, environment, credentials, requestRaw, signal }) {
  const container = environment.getContainer('elasticsearch-1');
  const origin = `http://${container.getHost()}:${container.getMappedPort(9200)}`;
  const auth = { username: 'elastic', password: credentials.ES_PASSWORD, signal };
  const request = (path, options = {}) => requestRaw(`${origin}${path}`, { ...auth, ...options });
  const directory = join(dirname(artifacts.consumer), 'elasticsearch');
  await mkdir(directory);
  const mapping = await readFile(new URL('../../hdf-converters/shared/ecs-bundle-mapping.json', import.meta.url), 'utf8');
  const results = [];
  for (const entry of artifacts.cases) {
    const source = await sourceCase(entry);
    const caseDirectory = join(directory, entry.name);
    await mkdir(caseDirectory);
    const input = join(caseDirectory, 'input.json');
    await writeFile(input, source);
    await command(artifacts.cli, ['validate', input, '--json'], { ...execution, signal });
    for (const producer of ['cli', 'typescript']) {
      const folder = join(caseDirectory, producer);
      await mkdir(folder);
      const { output, sizes } = await makeBundle(artifacts, producer, input, folder, signal);
      const events = await readFile(join(output, 'events.ndjson'), 'utf8');
      const lines = events === '' ? [] : events.trimEnd().split('\n');
      const index = `hdf-${entry.name}-${producer}`;
      await request(`/${index}`, { method: 'PUT', body: mapping });
      // Keep each bulk request comfortably below the vendor's default 100 MB limit.
      let batch = '';
      let batchCount = 0;
      async function flush() {
        const bulk = JSON.parse(await request(`/${index}/_bulk`, { method: 'POST', body: batch, timeoutMs: 120_000 }));
        assertBulkCreated(bulk, batchCount);
        batch = ''; batchCount = 0;
      }
      for (let i = 0; i < lines.length; i++) {
        batch += `${JSON.stringify({ create: { _id: String(i) } })}\n${lines[i]}\n`;
        batchCount++;
        if (Buffer.byteLength(batch) >= 5 * 1024 * 1024) await flush();
      }
      if (batchCount) await flush();
      await request(`/${index}/_refresh`, { method: 'POST' });
      assert.equal(JSON.parse(await request(`/${index}/_count`)).count, lines.length);
      if (entry.name === 'override') {
        const mixed = JSON.parse(await request(`/${index}/_bulk`, { method: 'POST',
          body: `${JSON.stringify({ create: { _id: '0' } })}\n${lines[0]}\n${JSON.stringify({ create: { _id: 'probe' } })}\n${lines[0]}\n` }));
        assert.deepEqual(mixed.items.map((item) => item.create.status), [409, 201]);
        assert.throws(() => assertBulkCreated(mixed, 2), { code: 'ERR_ASSERTION' });
        await request(`/${index}/_doc/probe?refresh=true`, { method: 'DELETE' });
      }
      const retained = join(folder, 'retained');
      await mkdir(retained);
      for (let i = 0; i < lines.length; i++) {
        await writeFile(join(retained, `${i}.json`), await request(`/${index}/_source/${i}`));
      }
      const proof = JSON.parse((await consumer(artifacts, verifyReadback, [input, output, retained, entry.name], signal)).stdout);
      for (const [field, counts] of Object.entries({ 'event.outcome.keyword': proof.outcomes,
        'hdf.status.keyword': proof.rawStatuses, 'vulnerability.severity.keyword': proof.severities,
        'hdf.impact': proof.impacts, 'hdf.effective_impact': proof.effectiveImpacts, 'vulnerability.score.base': proof.scores,
        'hdf.effective_status.keyword': proof.effectiveStatuses, 'hdf.disposition.keyword': proof.dispositions })) {
        for (const [value, expected] of Object.entries(counts)) {
          const count = JSON.parse(await request(`/${index}/_count`, {
            method: 'POST', body: JSON.stringify({ query: { term: { [field]: value } } }),
          }));
          assert.equal(count.count, expected, `${entry.name}/${producer}: ${field}=${value}`);
        }
      }
      const fields = JSON.parse(await request(`/${index}/_field_caps?fields=hdf.source.*`));
      assert.deepEqual(Object.keys(fields.fields), [], 'preservation members must not become indexed fields');
      let negatives = [];
      if (lines.length) {
        const event = join(retained, '0.json');
        const recover = () => command(artifacts.cli, ['evidence', 'resolve', join(output, 'evidence-package.json'), '--event', event],
          { ...execution, signal, encoding: 'buffer' });
        assert.deepEqual((await recover()).stdout, source);
        if (entry.name === 'override') negatives = await rejectArtifacts(artifacts, output, event, signal);
        assert.deepEqual((await recover()).stdout, source);
      }
      results.push({ name: entry.name, producer, kind: entry.kind, sourceSha256: createHash('sha256').update(source).digest('hex'),
        ...proof, negatives, sizes });
      console.log(`Elasticsearch ${entry.name}/${producer}: ${proof.events} events verified`);
      await request(`/${index}`, { method: 'DELETE' });
    }
  }
  const nodes = JSON.parse(await request('/_nodes/settings?flat_settings=true'));
  return { cases: results, mapping: JSON.parse(mapping), limits: { bulkBatchBytes: 5 * 1024 * 1024, requestMaxResponseBytes: 128 * 1024 * 1024 },
    nodeSettings: Object.values(nodes.nodes).map((node) => ({ httpMaxContentLength: node.settings['http.max_content_length'] ?? '100mb (default)' })) };
}
