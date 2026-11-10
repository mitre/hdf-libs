import assert from 'node:assert/strict';
import test from 'node:test';
import { createServer } from 'node:http';
import { createServer as createSecureServer } from 'node:https';
import { once } from 'node:events';
import { mkdtemp, readFile, stat, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, basename } from 'node:path';
import { parseOptions, redact, requestRaw, requestWhenAvailable, createRun, qualifyRuntime, buildArtifacts, assertSplunkLicense } from './harness.mjs';
import { execFile } from 'node:child_process';
import { promisify, parseEnv } from 'node:util';
import { fileURLToPath } from 'node:url';

const qualifiedEnvironment = parseEnv(await readFile(new URL('./.env.example', import.meta.url), 'utf8'));

test('selects explicit targets and requires consent before Splunk can start', () => {
  assert.deepEqual(parseOptions(['--environment-only', '--target', 'elasticsearch'], {}), {
    targets: ['elasticsearch'], environmentOnly: true, acceptSplunk: false, allowEmulation: false,
  });
  assert.throws(() => parseOptions(['--target', 'all'], {}), /Splunk terms/);
  assert.deepEqual(parseOptions(['--target', 'all'], {
    HDF_SIEM_ACCEPT_SPLUNK_TERMS: 'yes', HDF_SIEM_ALLOW_AMD64_EMULATION: 'yes',
  }).targets, ['elasticsearch', 'splunk']);
  assert.equal(parseOptions(['--target', 'splunk'], { HDF_SIEM_ACCEPT_SPLUNK_TERMS: 'yes' }).allowEmulation, false);
  for (const args of [[], ['--target', 'unknown'], ['--target'], ['--mystery'], ['--target', 'elasticsearch', 'extra']]) {
    assert.throws(() => parseOptions(args, {}));
  }
});

test('redacts credentials and local paths without losing the failure reason', () => {
  assert.equal(redact('failed secret-token at /private/run/path', ['secret-token', '/private/run/path']),
    'failed [REDACTED] at [REDACTED]');
  assert.equal(redact(new Error('denied secret-token'), ['secret-token']), 'Error: denied [REDACTED]');
});

test('rejects expired or unconfirmed Splunk licenses before reporting readiness', () => {
  assert.doesNotThrow(() => assertSplunkLicense({ licenseState: 'OK' }));
  for (const info of [{ licenseState: 'Expired' }, { licenseState: 'unknown' }, {}, null, undefined]) {
    assert.throws(() => assertSplunkLicense(info), /Splunk license is not active/);
  }
});

async function server(t, handler) {
  const instance = createServer(handler);
  instance.listen(0, '127.0.0.1');
  await once(instance, 'listening');
  t.after(() => new Promise((resolve) => { instance.close(resolve); instance.closeAllConnections(); }));
  return `http://127.0.0.1:${instance.address().port}`;
}

test('retrieves exact JSON text and sends authentication without number normalization', async (t) => {
  const source = '{"n":9007199254740993,"z":-0,"s":"雪"}';
  const url = await server(t, (req, res) => {
    assert.equal(req.headers.authorization, `Basic ${Buffer.from('admin:private').toString('base64')}`);
    res.end(source);
  });
  assert.equal(await requestRaw(url, { username: 'admin', password: 'private' }), source);
});

test('rejects HTTP failures without exposing response secrets', async (t) => {
  const url = await server(t, (_req, res) => { res.writeHead(401); res.end('secret'); });
  await assert.rejects(requestRaw(url), (error) => error.message === 'HTTP 401');
});

test('bounds response size and request duration', async (t) => {
  const large = await server(t, (_req, res) => res.end('too large'));
  await assert.rejects(requestRaw(large, { maxBytes: 3 }), /response size/i);
  const stalled = await server(t, () => {});
  await assert.rejects(requestRaw(stalled, { timeoutMs: 30 }), /timeout/i);
});

test('rejects unsupported transports and honors cancellation', async () => {
  await assert.rejects(requestRaw('file:///tmp/data'), /protocol/i);
  const controller = new AbortController(); controller.abort();
  await assert.rejects(requestRaw('http://127.0.0.1:1', { signal: controller.signal }), /abort/i);
});

test('sends HEC token and raw request body without reserializing numbers', async (t) => {
  const body = '{"event":{"n":9007199254740993,"z":-0}}';
  const url = await server(t, async (req, res) => {
    assert.equal(req.method, 'POST');
    assert.equal(req.headers.authorization, 'Splunk private-token');
    const chunks = []; for await (const chunk of req) chunks.push(chunk);
    assert.equal(Buffer.concat(chunks).toString(), body);
    res.end('{"code":0}');
  });
  assert.equal(await requestRaw(url, { method: 'POST', token: 'private-token', body }), '{"code":0}');
});

test('trusts only the supplied test CA for HTTPS requests', async (t) => {
  const directory = await mkdtemp(join(tmpdir(), 'siem-tls-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  await promisify(execFile)('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '36500',
    '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1',
    '-keyout', join(directory, 'key.pem'), '-out', join(directory, 'cert.pem')]);
  const ca = await readFile(join(directory, 'cert.pem'));
  const instance = createSecureServer({ key: await readFile(join(directory, 'key.pem')), cert: ca }, (_req, res) => res.end('trusted'));
  instance.listen(0, '127.0.0.1'); await once(instance, 'listening');
  t.after(() => new Promise((resolve) => { instance.close(resolve); instance.closeAllConnections(); }));
  const url = `https://127.0.0.1:${instance.address().port}`;
  await assert.rejects(requestRaw(url), /self.signed certificate/i);
  assert.equal(await requestRaw(url, { ca }), 'trusted');
});

test('retries only documented transient readiness responses', async (t) => {
  let requests = 0;
  const url = await server(t, (_req, res) => {
    if (++requests === 1) { res.writeHead(404); res.end(); }
    else res.end('ready');
  });
  assert.equal(await requestWhenAvailable(url, { retryStatuses: [404], intervalMs: 1 }), 'ready');
  assert.equal(requests, 2);
  let deniedRequests = 0;
  const unauthorized = await server(t, (_req, res) => { deniedRequests++; res.writeHead(401); res.end(); });
  await assert.rejects(requestWhenAvailable(unauthorized, { retryStatuses: [404] }), /HTTP 401/);
  assert.equal(deniedRequests, 1);
});

test('readiness deadlines and cancellation fail instead of retrying forever', async (t) => {
  const url = await server(t, (_req, res) => { res.writeHead(404); res.end(); });
  await assert.rejects(requestWhenAvailable(url, { retryStatuses: [404], readinessTimeoutMs: 40, intervalMs: 5 }), /Readiness timeout/);
  const controller = new AbortController(); controller.abort();
  await assert.rejects(requestWhenAvailable(url, { signal: controller.signal }), /abort/i);
});

test('readiness bounds stalled requests and cancels an in-progress retry delay', async (t) => {
  const stalled = await server(t, () => {});
  await assert.rejects(requestWhenAvailable(stalled, { readinessTimeoutMs: 40 }), /Readiness timeout/);
  const controller = new AbortController();
  let requests = 0;
  const url = await server(t, (_req, res) => {
    requests++;
    res.writeHead(404); res.end();
    setTimeout(() => controller.abort(new Error('Owner cancelled readiness')), 20);
  });
  await assert.rejects(requestWhenAvailable(url, {
    retryStatuses: [404], intervalMs: 10_000, signal: controller.signal,
  }), /Owner cancelled readiness/);
  assert.equal(requests, 1);
});

test('readiness does not retry statuses without an explicit allowlist', async (t) => {
  let requests = 0;
  const url = await server(t, (_req, res) => { requests++; res.writeHead(404); res.end(); });
  await assert.rejects(requestWhenAvailable(url), /HTTP 404/);
  assert.equal(requests, 1);
});

test('creates private isolated credentials without accepting runtime terms implicitly', async (t) => {
  const parent = await mkdtemp(join(tmpdir(), 'siem-test-'));
  t.after(() => rm(parent, { recursive: true, force: true }));
  const first = await createRun(parent, { acceptSplunk: false });
  const second = await createRun(parent, { acceptSplunk: true });
  assert.notEqual(first.project, second.project);
  assert.match(first.project, /^hdf-siem-[a-f0-9]{32}$/);
  assert.equal(first.project, basename(first.directory), 'project identity must not fold distinct directory names together');
  assert.notEqual(first.credentials.ES_PASSWORD, second.credentials.ES_PASSWORD);
  assert.match(first.credentials.ES_PASSWORD, /^[a-f0-9]{48}$/);
  assert.equal((await stat(first.directory)).mode & 0o777, 0o700);
  assert.equal((await stat(first.envFile)).mode & 0o777, 0o600);
  assert.equal(first.credentials.SPLUNK_START_ARGS, '');
  assert.equal(second.credentials.SPLUNK_START_ARGS, '--accept-license');
  assert.equal(second.credentials.SPLUNK_GENERAL_TERMS, '--accept-sgt-current-at-splunk-com');
  const written = await readFile(first.envFile, 'utf8');
  assert.equal(written.includes(`ES_PASSWORD=${first.credentials.ES_PASSWORD}\n`), true);
});

test('requires explicit emulation consent and an enabled cleanup reaper', () => {
  const options = { targets: ['splunk'], allowEmulation: false };
  assert.throws(() => qualifyRuntime({ OSType: 'linux', Architecture: 'aarch64' }, options, {}), /emulation/i);
  assert.throws(() => qualifyRuntime({ OSType: 'windows', Architecture: 'amd64' }, options, {}), /Linux/);
  assert.throws(() => qualifyRuntime({ OSType: 'linux', Architecture: 'amd64' }, options, { TESTCONTAINERS_RYUK_DISABLED: 'true' }), /reaper/i);
  assert.doesNotThrow(() => qualifyRuntime({ OSType: 'linux', Architecture: 'amd64' }, options, qualifiedEnvironment));
  assert.doesNotThrow(() => qualifyRuntime({ OSType: 'linux', Architecture: 'arm64' }, { ...options, allowEmulation: true }, qualifiedEnvironment));
  assert.doesNotThrow(() => qualifyRuntime({ OSType: 'linux', Architecture: 'arm64' }, { targets: ['elasticsearch'] }, qualifiedEnvironment));
});

test('rejects missing or unqualified cleanup images before service startup', () => {
  const runtime = { OSType: 'linux', Architecture: 'amd64' };
  const options = { targets: ['elasticsearch'] };
  for (const environment of [{}, { RYUK_CONTAINER_IMAGE: 'testcontainers/ryuk:latest' },
    { RYUK_CONTAINER_IMAGE: 'unqualified/ryuk@sha256:' + '0'.repeat(64) }]) {
    assert.throws(() => qualifyRuntime(runtime, options, environment), /qualified cleanup image/);
  }
  assert.doesNotThrow(() => qualifyRuntime(runtime, options, qualifiedEnvironment));
});

test('builds a runnable current CLI and imports the installed packed converter', { skip: process.env.HDF_SIEM_TEST_BUILD !== 'yes' }, async (t) => {
  const directory = await mkdtemp(join(tmpdir(), 'siem-build-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const result = await buildArtifacts(directory);
  const { stdout } = await promisify(execFile)(result.cli, ['--help']);
  assert.match(stdout, /convert/);
  const path = fileURLToPath(new URL('../../hdf-converters/converters/hdf-to-ecs/fixtures/input/override.json', import.meta.url));
  const fixture = await readFile(path);
  const code = `import { readFile } from 'node:fs/promises';
    import { convertHdfToEcsBundle } from '@mitre/hdf-converters';
    const bundle = await convertHdfToEcsBundle(await readFile(process.argv[1]));
    console.log(JSON.stringify({ source: Buffer.from(bundle.source).toString('base64'), manifest: bundle.manifest }));`;
  const imported = await promisify(execFile)(process.execPath, ['--input-type=module', '-e', code, path], { cwd: result.consumer });
  const bundle = JSON.parse(imported.stdout);
  assert.deepEqual(Buffer.from(bundle.source, 'base64'), fixture);
  const manifest = JSON.parse(bundle.manifest);
  assert.equal(manifest.profileVersion, '1.0');
  assert.equal(result.tarballs.length, 7);
  assert.deepEqual(result.cases.map((entry) => entry.name), [
    'inspec-overlay', 'override', 'negative-zero', 'riskadjust', 'cve', 'boundary', 'duplicate-ids', 'empty',
  ]);
  assert.equal(result.cases.every((entry) => entry.validated && /^[a-f0-9]{64}$/.test(entry.sha256)), true);
});
