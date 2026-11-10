import assert from 'node:assert/strict';
import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { join, dirname } from 'node:path';
import { createHash } from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';
import { command, repository, assertSplunkLicense } from './harness.mjs';
import { execution, consumer, sourceCase, makeBundle, verifyReadback, rejectArtifacts } from './bundle-helpers.mjs';

export async function verify({ artifacts, environment, credentials, requestRaw, signal }) {
  const container = environment.getContainer('splunk-1');
  await container.copyDirectoriesToContainer([{
    source: join(repository, 'hdf-converters/converters/hdf-to-splunk/Splunk_TA_hdf'),
    target: '/opt/splunk/etc/apps/Splunk_TA_hdf',
  }]);
  await container.restart({ timeout: 30_000 });
  const origin = `http://${container.getHost()}:${container.getMappedPort(8089)}`;
  const hec = `http://${container.getHost()}:${container.getMappedPort(8088)}/services/collector/event`;
  const request = async (path, options = {}) => JSON.parse(await requestRaw(`${origin}/services${path}`, {
    username: 'admin', password: credentials.SPLUNK_PASSWORD, signal, ...options,
  }));
  const form = (values) => ({ method: 'POST', contentType: 'application/x-www-form-urlencoded',
    body: new URLSearchParams(values).toString() });
  const info = (await request('/server/info?output_mode=json')).entry[0].content;
  assertSplunkLicense(info);
  const props = (await request('/configs/conf-props/hdf%3Aresults?output_mode=json')).entry[0].content;
  assert.equal(props.KV_MODE, 'json');
  assert.equal(String(props.TRUNCATE), '0');
  const httpInput = (await request('/configs/conf-limits/http_input?output_mode=json')).entry[0].content;
  const inputs = (await request('/configs/conf-inputs/http?output_mode=json')).entry[0].content;
  const spath = (await request('/configs/conf-limits/spath?output_mode=json')).entry[0].content;
  const directory = join(dirname(artifacts.consumer), 'splunk');
  await mkdir(directory);

  async function search(query, kind = 'results') {
    const deadline = AbortSignal.timeout(120_000);
    const bounded = signal ? AbortSignal.any([signal, deadline]) : deadline;
    const job = await request('/search/jobs?output_mode=json', { ...form({ search: query,
      earliest_time: '0', latest_time: 'now', max_count: '10000' }), signal: bounded });
    assert.equal(typeof job.sid, 'string');
    const path = `/search/jobs/${encodeURIComponent(job.sid)}`;
    try {
      for (;;) {
        const state = (await request(`${path}?output_mode=json`, { signal: bounded })).entry[0].content;
        assert.notEqual(state.dispatchState, 'FAILED', 'Splunk search failed');
        assert.ok(!state.isFailed, 'Splunk search failed');
        if (state.isDone) break;
        await delay(500, undefined, { signal: bounded });
      }
      const rows = [];
      for (let offset = 0; ; offset += 100) {
        const page = await request(`/search/v2/jobs/${encodeURIComponent(job.sid)}/${kind}?output_mode=json&count=100&offset=${offset}`, { signal: bounded });
        assert.ok(Array.isArray(page.results));
        assert.equal((page.messages ?? []).some((message) => message.type === 'ERROR' || message.type === 'FATAL'), false);
        rows.push(...page.results);
        if (page.results.length < 100) return rows;
      }
    } finally { await request(`${path}?output_mode=json`, { method: 'DELETE' }); }
  }

  const results = [];
  const cases = [...artifacts.cases].sort((a, b) => Number(b.name === 'override') - Number(a.name === 'override'));
  for (const entry of cases) {
    const source = await sourceCase(entry);
    const caseDirectory = join(directory, entry.name);
    await mkdir(caseDirectory);
    const input = join(caseDirectory, 'input.json');
    await writeFile(input, source);
    await command(artifacts.cli, ['validate', input, '--json'], { ...execution, signal });
    for (const producer of ['cli', 'typescript']) {
      const folder = join(caseDirectory, producer);
      await mkdir(folder);
      const { output, sizes } = await makeBundle(artifacts, producer, input, folder, signal, 'splunk');
      const events = await readFile(join(output, 'events.ndjson'), 'utf8');
      const lines = events === '' ? [] : events.trimEnd().split('\n');
      const index = `hdf_${entry.name.replaceAll('-', '_')}_${producer}`;
      await request('/data/indexes?output_mode=json', form({ name: index, frozenTimePeriodInSecs: '3153600000' }));
      const indexSettings = (await request(`/data/indexes/${index}?output_mode=json`)).entry[0].content;
      assert.equal(Number(indexSettings.frozenTimePeriodInSecs), 3153600000);
      const expectedPointers = new Map();
      const indexedFields = new Map();
      let largestEventBytes = 0;
      let batch = '';
      async function flush() {
        const response = JSON.parse(await requestRaw(hec, { token: credentials.SPLUNK_HEC_TOKEN,
          method: 'POST', body: batch, signal, timeoutMs: 120_000 }));
        assert.equal(response.code, 0, 'HEC rejected a batch');
        batch = '';
      }
      for (let i = 0; i < lines.length; i++) {
        const envelope = JSON.parse(lines[i]);
        assert.equal(envelope.sourcetype, 'hdf:results');
        assert.ok(envelope.fields && typeof envelope.fields === 'object');
        assert.equal(Object.keys(envelope.fields).some((key) => key.startsWith('hdf.source') || key === 'hdf'), false,
          'preservation belongs inside event');
        for (const [key, value] of Object.entries(envelope.fields)) {
          assert.match(key, /^[a-z_]+$/);
          assert.equal(value, envelope.event[key]);
          indexedFields.set(key, (indexedFields.get(key) ?? 0) + 1);
        }
        expectedPointers.set(envelope.event.hdf.source.pointer, i);
        assert.ok(lines[i].startsWith('{'));
        assert.equal(Object.hasOwn(envelope, 'index'), false);
        // Add only routing metadata; leave every numeric token inside event untouched.
        const routed = `{"index":${JSON.stringify(index)},${lines[i].slice(1)}\n`;
        largestEventBytes = Math.max(largestEventBytes, Buffer.byteLength(routed));
        if (batch && Buffer.byteLength(batch) + Buffer.byteLength(routed) > 5 * 1024 * 1024) await flush();
        batch += routed;
      }
      if (batch) await flush();
      assert.equal(expectedPointers.size, lines.length);
      const query = `search index=${index} sourcetype="hdf:results"`;
      const visibleDeadline = Date.now() + 180_000;
      for (;;) {
        const rows = await search(`${query} | stats count`);
        assert.equal(rows.length, 1);
        const count = Number(rows[0].count);
        assert.ok(count <= lines.length, 'unexpected duplicate events');
        if (count === lines.length) break;
        assert.ok(Date.now() < visibleDeadline, `search visibility timeout: ${count}/${lines.length}`);
        await delay(1000, undefined, { signal });
      }
      const retained = join(folder, 'retained');
      await mkdir(retained);
      const rows = await search(query, 'events');
      assert.equal(rows.length, lines.length);
      const seen = new Set();
      for (const row of rows) {
        assert.equal(typeof row._raw, 'string');
        const pointer = JSON.parse(row._raw).hdf.source.pointer;
        assert.ok(expectedPointers.has(pointer), 'unexpected occurrence');
        assert.equal(seen.has(pointer), false, 'duplicate occurrence');
        seen.add(pointer);
        await writeFile(join(retained, `${expectedPointers.get(pointer)}.json`), `{"event":${row._raw}}`);
      }
      const proof = JSON.parse((await consumer(artifacts, verifyReadback,
        [input, output, retained, entry.name, 'splunk'], signal)).stdout);
      for (const [field, expected] of Object.entries({ hdf_status: proof.rawStatuses, suppressed: proof.suppression, severity: proof.severities })) {
        const counts = await search(`${query} | stats count by ${field}`);
        assert.deepEqual(Object.fromEntries(counts.map((row) => [row[field], Number(row.count)])), expected, field);
      }
      if (lines.length) {
        const expressions = [...indexedFields.keys()].flatMap((field) => [
          `sum(eval(if(isnull(${field}),0,1))) AS present_${field}`,
          `sum(eval(if(mvcount(${field})>1,1,0))) AS duplicate_${field}`,
        ]);
        const counts = await search(`${query} | stats ${expressions.join(' ')}`);
        assert.equal(counts.length, 1);
        for (const [field, expected] of indexedFields) {
          assert.equal(Number(counts[0][`present_${field}`]), expected, `${field} presence`);
          assert.equal(Number(counts[0][`duplicate_${field}`]), 0, `${field} must remain single-valued`);
        }
      }
      if (lines.length) {
        const values = await search(`${query} | eval occurrence=spath(_raw,"hdf.source.pointer") | table occurrence ${[...indexedFields.keys()].join(' ')}`);
        assert.equal(values.length, lines.length);
        const returned = new Set();
        for (const row of values) {
          assert.ok(expectedPointers.has(row.occurrence), 'unknown native-field occurrence');
          assert.equal(returned.has(row.occurrence), false, 'duplicate native-field occurrence');
          returned.add(row.occurrence);
          const expected = JSON.parse(lines[expectedPointers.get(row.occurrence)]).fields;
          for (const field of indexedFields.keys()) {
            if (Object.hasOwn(expected, field)) {
              assert.equal(row[field], String(expected[field]), `${field} must retain its exact exported value`);
            } else assert.equal(Object.hasOwn(row, field), false, `${field} must remain absent`);
          }
        }
      }
      for (const selector of ['eventtype=hdf_finding', 'tag=vulnerability tag=report']) {
        const counts = await search(`${query} ${selector} | stats count`);
        assert.equal(counts.length, 1);
        assert.equal(Number(counts[0].count), proof.activeFindings, selector);
      }
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
        ...proof, negatives, sizes, largestEventBytes });
      console.log(`Splunk ${entry.name}/${producer}: ${proof.events} events verified`);
    }
  }
  return { cases: results, licenseState: info.licenseState, version: info.version,
    configuration: { KV_MODE: props.KV_MODE, TRUNCATE: props.TRUNCATE,
      maxEventSize: inputs.maxEventSize ?? null, maxEventSizeDefault: '5MB (vendor default when unset)',
      maxContentLength: httpInput.max_content_length, extractionCutoff: spath.extraction_cutoff },
    limits: { batchBytes: 5 * 1024 * 1024, responseBytes: 128 * 1024 * 1024, searchPage: 100,
      testIndexRetentionSeconds: 3153600000 } };
}
