import assert from 'node:assert/strict';
import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { join, dirname } from 'node:path';
import { createHash } from 'node:crypto';
import { command } from './harness.mjs';
import { execution, consumer, sourceCase, makeBundle, verifyReadback, rejectArtifacts } from './bundle-helpers.mjs';

function assertBulkCreated(bulk, expected) {
  assert.equal(bulk.errors, false, JSON.stringify(bulk.items));
  assert.equal(bulk.items.length, expected);
  for (const item of bulk.items) assert.equal(item.create.status, 201);
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
