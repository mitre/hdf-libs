import assert from 'node:assert/strict';
import test from 'node:test';
import { readdir, mkdtemp, writeFile, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { runWithEnvironment, runSuite, main } from './run.mjs';

test('reports startup failure and releases only owned resources', async () => {
  const calls = [];
  const failure = new Error('Readiness timed out');
  await assert.rejects(runWithEnvironment({
    start: async () => { calls.push('start'); throw failure; },
    stop: async () => { calls.push('stop-owned'); },
    work: async () => { calls.push('work'); },
  }), (error) => error === failure);
  assert.deepEqual(calls, ['start', 'stop-owned']);
});

test('retains the original failure when cleanup also fails', async () => {
  const failure = new Error('Readiness timed out');
  const cleanup = new Error('Cleanup failed');
  await assert.rejects(runWithEnvironment({
    start: async () => { throw failure; },
    stop: async () => { throw cleanup; },
    work: async () => assert.fail('must not run'),
  }), (error) => error instanceof AggregateError
    && error.errors[0] === failure && error.errors[1] === cleanup);
});

test('cleans up a started environment before returning the work result', async () => {
  const calls = [];
  const environment = { name: 'owned' };
  const result = await runWithEnvironment({
    start: async () => environment,
    work: async (actual) => { assert.equal(actual, environment); calls.push('work'); return 42; },
    stop: async () => { calls.push('stop'); },
  });
  assert.equal(result, 42);
  assert.deepEqual(calls, ['work', 'stop']);
});

test('fails when successful work cannot clean up', async () => {
  const cleanup = new Error('Cleanup failed');
  await assert.rejects(runWithEnvironment({
    start: async () => ({}), work: async () => 42, stop: async () => { throw cleanup; },
  }), (error) => error === cleanup);
});

test('interruption during startup prevents work and cleans up', async () => {
  const controller = new AbortController();
  const interruption = new Error('Interrupted');
  let cleaned = false;
  await assert.rejects(runWithEnvironment({
    signal: controller.signal,
    start: async () => { controller.abort(interruption); return {}; },
    work: async () => assert.fail('must not run'),
    stop: async () => { cleaned = true; },
  }), (error) => error === interruption);
  assert.equal(cleaned, true);
});

test('environment-only probes every target and cleans up without building artifacts', async () => {
  const calls = [];
  const result = await runSuite({ targets: ['elasticsearch', 'splunk'], environmentOnly: true }, {
    start: async () => ({}), stop: async () => calls.push('stop'),
    probe: async (target) => { calls.push(target); return { version: 'qualified' }; },
    build: async () => assert.fail('environment-only cannot require CLI delivery'),
    executeTarget: async () => assert.fail('must not claim target ingestion'),
  });
  assert.deepEqual(calls, ['elasticsearch', 'splunk', 'stop']);
  assert.deepEqual(result, { mode: 'environment', targets: {
    elasticsearch: { version: 'qualified' }, splunk: { version: 'qualified' },
  } });
});

test('full runs build once and fail if any selected target fails', async () => {
  const calls = []; const failure = new Error('Splunk readback failed');
  await assert.rejects(runSuite({ targets: ['elasticsearch', 'splunk'], environmentOnly: false }, {
    start: async () => ({}), stop: async () => calls.push('stop'),
    probe: async () => ({}), build: async () => { calls.push('build'); return { cli: 'current' }; },
    executeTarget: async (target, artifacts) => {
      assert.equal(artifacts.cli, 'current'); calls.push(target);
      if (target === 'splunk') throw failure;
    },
  }), (error) => error === failure);
  assert.deepEqual(calls, ['build', 'elasticsearch', 'splunk', 'stop']);
});

test('full runs retain every target verification result', async () => {
  const result = await runSuite({ targets: ['elasticsearch'], environmentOnly: false }, {
    start: async () => ({}), stop: async () => {}, probe: async () => ({ ready: true }),
    build: async () => ({}), executeTarget: async () => ({ records: 2, preserved: true }),
  });
  assert.deepEqual(result, { mode: 'integration', targets: { elasticsearch: {
    ready: true, verification: { records: 2, preserved: true },
  } } });
});

test('pre-cancelled runs never start services', async () => {
  const controller = new AbortController(); controller.abort();
  await assert.rejects(runWithEnvironment({ signal: controller.signal,
    start: async () => assert.fail('must not start'), stop: async () => {}, work: async () => assert.fail('must not run'),
  }), /abort/i);
});

test('requested live services authenticate and clean up owned resources', {
  skip: !process.env.HDF_SIEM_TEST_SERVICES,
}, async (t) => {
  const output = t.mock.method(console, 'log', () => {});
  const target = process.env.HDF_SIEM_TEST_SERVICES;
  const report = await main(['--environment-only', '--target', target]);
  assert.equal(report.status, 'PASS');
  assert.equal(report.cleanup, 'PASS');
  assert.equal(report.mode, 'environment');
  assert.deepEqual(Object.keys(report.targets), target === 'all' ? ['elasticsearch', 'splunk'] : [target]);
  const folders = await readdir(new URL('./.runs/', import.meta.url));
  const folder = folders.find((name) => name.toLowerCase() === report.project);
  assert.ok(folder, 'the run must retain its report directory');
  assert.equal(output.mock.calls.at(-1).arguments[0], `SIEM PASS; report: ${folder}/report.json`);
});

test('full-mode entry point passes current artifacts to modules and cleans up a module failure', {
  skip: process.env.HDF_SIEM_TEST_WIRING !== 'yes',
}, async (t) => {
  const suites = await mkdtemp(join(tmpdir(), 'siem-wiring-'));
  t.after(() => rm(suites, { recursive: true, force: true }));
  const source = `import assert from 'node:assert/strict';
    import { stat } from 'node:fs/promises';
    export async function verify({ artifacts, environment, credentials, requestRaw, signal }) {
      assert.equal((await stat(artifacts.cli)).isFile(), true);
      assert.equal((await stat(artifacts.consumer)).isDirectory(), true);
      assert.equal(artifacts.cases.every(entry => entry.validated), true);
      const container = environment.getContainer('elasticsearch-1');
      const raw = await requestRaw('http://' + container.getHost() + ':' + container.getMappedPort(9200),
        { username: 'elastic', password: credentials.ES_PASSWORD, signal });
      assert.equal(typeof JSON.parse(raw).version.number, 'string');
      throw new Error('Selected verification failed after authenticated readback');
    }`;
  await writeFile(join(suites, 'elasticsearch.test.mjs'), source);
  const output = t.mock.method(console, 'log', () => {});
  await assert.rejects(main(['--target', 'elasticsearch'], { suiteDirectory: suites }),
    /Selected verification failed after authenticated readback/);
  const reportPath = output.mock.calls.at(-1).arguments[0].split('report: ')[1];
  const report = JSON.parse(await readFile(new URL(`./.runs/${reportPath}`, import.meta.url), 'utf8'));
  assert.equal(report.status, 'FAIL');
  assert.equal(report.cleanup, 'PASS');
  assert.match(report.error, /Selected verification failed after authenticated readback/);
});
