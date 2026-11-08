import { parseArgs, parseEnv, promisify } from 'node:util';
import { readFileSync } from 'node:fs';
import http from 'node:http';
import https from 'node:https';
import { mkdir, writeFile, readFile, readdir } from 'node:fs/promises';
import { randomBytes, createHash } from 'node:crypto';
import { join, basename, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFile } from 'node:child_process';
import { setTimeout as delay } from 'node:timers/promises';

export const repository = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
export const command = promisify(execFile);
const qualifiedEnvironment = parseEnv(readFileSync(new URL('./.env.example', import.meta.url), 'utf8'));

export function assertSplunkLicense(info) {
  if (info?.licenseState !== 'OK') throw new Error('Splunk license is not active');
}

export function parseOptions(args, environment) {
  const { values } = parseArgs({ args, allowPositionals: false, options: {
    target: { type: 'string' }, 'environment-only': { type: 'boolean', default: false },
  } });
  if (!['all', 'elasticsearch', 'splunk'].includes(values.target)) {
    throw new Error('Specify --target elasticsearch|splunk|all');
  }
  const targets = values.target === 'all' ? ['elasticsearch', 'splunk'] : [values.target];
  const acceptSplunk = environment.HDF_SIEM_ACCEPT_SPLUNK_TERMS === 'yes';
  if (targets.includes('splunk') && !acceptSplunk) {
    throw new Error('Splunk terms require explicit HDF_SIEM_ACCEPT_SPLUNK_TERMS=yes');
  }
  return { targets, environmentOnly: values['environment-only'], acceptSplunk,
    allowEmulation: environment.HDF_SIEM_ALLOW_AMD64_EMULATION === 'yes' };
}

export function redact(value, secrets) {
  let result = String(value);
  for (const secret of secrets.filter(Boolean).sort((a, b) => b.length - a.length)) {
    result = result.replaceAll(secret, '[REDACTED]');
  }
  return result;
}

export async function requestRaw(address, {
  username, password, token, ca, method = 'GET', body,
  timeoutMs = 15_000, maxBytes = 128 * 1024 * 1024, signal,
} = {}) {
  const url = new URL(address);
  if (!['http:', 'https:'].includes(url.protocol)) throw new Error('Unsupported request protocol');
  const headers = {};
  if (username) headers.authorization = `Basic ${Buffer.from(`${username}:${password}`).toString('base64')}`;
  if (token) headers.authorization = `Splunk ${token}`;
  if (body !== undefined) headers['content-type'] = 'application/json';
  return new Promise((resolve, reject) => {
    const transport = url.protocol === 'https:' ? https : http;
    const request = transport.request(url, { method, headers, ca, signal }, (response) => {
      if (response.statusCode < 200 || response.statusCode >= 300) {
        const error = new Error(`HTTP ${response.statusCode}`);
        error.statusCode = response.statusCode;
        response.resume(); reject(error); return;
      }
      let size = 0;
      const chunks = [];
      response.on('data', (chunk) => {
        size += chunk.length;
        if (size > maxBytes) {
          const error = new Error('Response size exceeds limit');
          reject(error);
          request.destroy(error);
        } else chunks.push(chunk);
      });
      response.on('error', reject);
      response.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    });
    const deadline = setTimeout(() => request.destroy(new Error('Request timeout')), timeoutMs);
    request.on('close', () => clearTimeout(deadline));
    request.on('error', reject);
    request.end(body);
  });
}

export async function requestWhenAvailable(address, {
  retryStatuses = [], intervalMs = 250, readinessTimeoutMs = 30_000, signal, ...options
} = {}) {
  const deadline = new AbortController();
  const timer = setTimeout(() => deadline.abort(new Error('Readiness timeout')), readinessTimeoutMs);
  const combined = signal ? AbortSignal.any([signal, deadline.signal]) : deadline.signal;
  try {
    for (;;) {
      combined.throwIfAborted();
      try {
        return await requestRaw(address, { ...options, signal: combined });
      } catch (error) {
        combined.throwIfAborted();
        if (!retryStatuses.includes(error.statusCode)) throw error;
      }
      await delay(intervalMs, undefined, { signal: combined });
    }
  } catch (error) {
    combined.throwIfAborted();
    throw error;
  } finally {
    clearTimeout(timer);
  }
}

export async function createRun(parent, { acceptSplunk }) {
  await mkdir(parent, { recursive: true, mode: 0o700 });
  const directory = join(parent, `hdf-siem-${randomBytes(16).toString('hex')}`);
  await mkdir(directory, { mode: 0o700 });
  const credentials = {
    ES_PASSWORD: randomBytes(24).toString('hex'),
    SPLUNK_PASSWORD: `Hdf-${randomBytes(24).toString('hex')}!`,
    SPLUNK_HEC_TOKEN: randomBytes(24).toString('hex'),
    SPLUNK_START_ARGS: acceptSplunk ? '--accept-license' : '',
    SPLUNK_GENERAL_TERMS: acceptSplunk ? '--accept-sgt-current-at-splunk-com' : '',
  };
  const envFile = join(directory, 'runtime.env');
  await writeFile(envFile, Object.entries(credentials).map(([k, v]) => `${k}=${v}\n`).join(''), { mode: 0o600 });
  return { directory, project: basename(directory), credentials, envFile };
}

export function qualifyRuntime(info, options, environment) {
  if (info.OSType !== 'linux') throw new Error('Linux containers are required');
  if (environment.TESTCONTAINERS_RYUK_DISABLED === 'true') throw new Error('The resource reaper must remain enabled');
  if (options.targets.includes('splunk') && !['amd64', 'x86_64'].includes(info.Architecture)
    && !options.allowEmulation) throw new Error('Splunk requires explicit AMD64 emulation consent');
  if (environment.RYUK_CONTAINER_IMAGE !== qualifiedEnvironment.RYUK_CONTAINER_IMAGE) {
    throw new Error('Use the qualified cleanup image: run Node with --env-file=test/siem/.env.example');
  }
}

export async function buildArtifacts(directory, signal) {
  const consumer = join(directory, 'consumer');
  const packed = join(directory, 'packages');
  await mkdir(consumer, { recursive: true });
  await mkdir(packed, { recursive: true });
  const packages = new Map();
  async function collect(name) {
    if (packages.has(name)) return;
    const folder = join(repository, name.replace('@mitre/', ''));
    const manifest = JSON.parse(await readFile(join(folder, 'package.json'), 'utf8'));
    packages.set(name, folder);
    for (const [dependency, version] of Object.entries(manifest.dependencies ?? {})) {
      if (version.startsWith('workspace:')) await collect(dependency);
    }
  }
  await collect('@mitre/hdf-converters');
  const options = { cwd: repository, signal, timeout: 600_000, maxBuffer: 16 * 1024 * 1024 };
  await command('pnpm', ['--filter', '@mitre/hdf-converters...', 'build'], options);
  const dependencies = {};
  for (const [name, folder] of packages) {
    const manifest = JSON.parse(await readFile(join(folder, 'package.json'), 'utf8'));
    await command('pnpm', ['pack', '--pack-destination', packed], { ...options, cwd: folder });
    dependencies[name] = `file:${join(packed, `${name.replace('@', '').replace('/', '-')}-${manifest.version}.tgz`)}`;
  }
  await writeFile(join(consumer, 'package.json'), JSON.stringify({ private: true, type: 'module', dependencies }));
  await command('npm', ['install', '--ignore-scripts', '--no-audit', '--no-fund'], { ...options, cwd: consumer });
  const cli = join(directory, 'hdf');
  await command('go', ['build', '-o', cli, './cmd/hdf'], { ...options, cwd: join(repository, 'hdf-cli') });
  const cases = JSON.parse(await readFile(new URL('./cases.json', import.meta.url), 'utf8'));
  for (const entry of cases) {
    const path = join(repository, entry.path);
    await command(cli, ['validate', path, '--json'], options);
    const bytes = await readFile(path);
    Object.assign(entry, { validated: true, bytes: bytes.length, sha256: createHash('sha256').update(bytes).digest('hex') });
  }
  return { consumer, cli, cases, tarballs: (await readdir(packed)).filter((name) => name.endsWith('.tgz')) };
}
