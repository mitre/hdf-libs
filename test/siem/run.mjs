import { DockerComposeEnvironment, Wait } from 'testcontainers';
import { access, readFile, writeFile, unlink } from 'node:fs/promises';
import { resolve, join, dirname, basename } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { parseOptions, createRun, qualifyRuntime, requestRaw, requestWhenAvailable, redact, command, repository, buildArtifacts, assertSplunkLicense } from './harness.mjs';

export async function runWithEnvironment({ start, stop, work, signal }) {
  let failure;
  try {
    signal?.throwIfAborted();
    const environment = await start();
    signal?.throwIfAborted();
    return await work(environment, signal);
  } catch (error) {
    failure = error;
    throw error;
  } finally {
    try {
      await stop();
    } catch (error) {
      if (failure) throw new AggregateError([failure, error], 'Run and cleanup failed');
      throw error;
    }
  }
}

export async function runSuite(options, { start, stop, probe, build, executeTarget, signal }) {
  return runWithEnvironment({ start, stop, signal, work: async (environment) => {
    const result = { mode: options.environmentOnly ? 'environment' : 'integration', targets: {} };
    for (const target of options.targets) result.targets[target] = await probe(target, environment, signal);
    if (!options.environmentOnly) {
      const artifacts = await build(signal);
      for (const target of options.targets) {
        result.targets[target].verification = await executeTarget(target, artifacts, environment, signal);
      }
    }
    return result;
  } });
}
export async function main(args = process.argv.slice(2), {
  suiteDirectory = dirname(fileURLToPath(import.meta.url)),
} = {}) {
  const options = parseOptions(args, process.env);
  const folder = dirname(fileURLToPath(import.meta.url));
  if (!options.environmentOnly) {
    for (const target of options.targets) await access(join(suiteDirectory, `${target}.test.mjs`));
  }
  const info = JSON.parse((await command('docker', ['info', '--format', '{{json .}}'], { timeout: 30_000 })).stdout);
  qualifyRuntime(info, options, process.env);
  const run = await createRun(join(folder, '.runs'), options);
  const secrets = [...Object.values(run.credentials), run.directory, repository];
  const controller = new AbortController();
  const interrupt = () => controller.abort(new Error('Run interrupted'));
  process.once('SIGINT', interrupt);
  process.once('SIGTERM', interrupt);
  let started;
  let cleanupFailed = false;
  const composeArgs = ['compose', '--project-name', run.project, '--env-file', run.envFile, '-f', join(folder, 'compose.yaml')];
  const execOptions = { cwd: repository, timeout: 120_000, maxBuffer: 8 * 1024 * 1024 };
  const report = { project: run.project, runtime: { os: info.OSType, architecture: info.Architecture, memory: info.MemTotal }, status: 'FAIL' };
  try {
    await command('docker', [...composeArgs, 'config', '--quiet'], execOptions);
    const config = JSON.parse((await command('docker', [...composeArgs, '--profile', '*', 'config', '--format', 'json'], execOptions)).stdout);
    report.images = Object.fromEntries(options.targets.map((target) => [target, config.services[target].image]));
    report.testcontainers = JSON.parse(await readFile(new URL('../../node_modules/testcontainers/package.json', import.meta.url), 'utf8')).version;
    const lifecycle = new DockerComposeEnvironment(folder, 'compose.yaml')
      .withProjectName(run.project).withEnvironmentFile(run.envFile)
      .withProfiles(...options.targets).withStartupTimeout(600_000);
    for (const target of options.targets) lifecycle.withWaitStrategy(`${target}-1`, Wait.forHealthCheck());
    const result = await runSuite(options, {
      signal: controller.signal,
      start: async () => { started = await lifecycle.up(options.targets); return started; },
      stop: async () => {
        try {
          if (started) await started.down({ timeout: 30_000, removeVolumes: true });
          else await command('docker', [...composeArgs, '--profile', '*', 'down', '--volumes', '--timeout', '30'], execOptions);
          for (const args of [['ps', '-aq'], ['network', 'ls', '-q'], ['volume', 'ls', '-q']]) {
            const remaining = await command('docker', [...args, '--filter', `label=com.docker.compose.project=${run.project}`], execOptions);
            if (remaining.stdout.trim()) throw new Error('Owned resources remain after cleanup');
          }
          report.cleanup = 'PASS';
        } catch (error) {
          cleanupFailed = true;
          report.cleanup = 'FAIL';
          throw error;
        }
      },
      probe: async (target, environment, signal) => {
        const container = environment.getContainer(`${target}-1`);
        const port = target === 'elasticsearch' ? 9200 : 8089;
        const origin = `http://${container.getHost()}:${container.getMappedPort(port)}`;
        const auth = target === 'elasticsearch'
          ? { username: 'elastic', password: run.credentials.ES_PASSWORD }
          : { username: 'admin', password: run.credentials.SPLUNK_PASSWORD };
        const endpoint = target === 'elasticsearch' ? '/' : '/services/server/info?output_mode=json';
        const response = JSON.parse(await requestRaw(`${origin}${endpoint}`, { ...auth, signal }));
        const version = target === 'elasticsearch' ? response.version?.number : response.entry?.[0]?.content?.version;
        if (!version) throw new Error(`${target} did not return its version`);
        if (target === 'elasticsearch') {
          const license = JSON.parse(await requestWhenAvailable(`${origin}/_license`, { ...auth, signal, retryStatuses: [404] }));
          if (license.license?.status !== 'active' || license.license?.type !== 'basic') throw new Error('Elasticsearch Basic license is not active');
        } else {
          assertSplunkLicense(response.entry?.[0]?.content);
          const hec = `http://${container.getHost()}:${container.getMappedPort(8088)}/services/collector/health`;
          const health = JSON.parse(await requestRaw(hec, { token: run.credentials.SPLUNK_HEC_TOKEN, signal }));
          if (health.code !== 17) throw new Error('Splunk HEC is not healthy');
        }
        return { version, authenticated: true, image: report.images[target] };
      },
      build: (signal) => buildArtifacts(run.directory, signal),
      executeTarget: async (target, artifacts, environment, signal) => {
        const suite = await import(pathToFileURL(join(suiteDirectory, `${target}.test.mjs`)).href);
        return suite.verify({ artifacts, environment, credentials: run.credentials, requestRaw, signal });
      },
    });
    Object.assign(report, result, { status: 'PASS', cleanup: 'PASS' });
  } catch (error) {
    report.error = redact(error instanceof AggregateError ? error.errors.join('; ') : error, secrets);
    throw new Error(report.error);
  } finally {
    process.removeListener('SIGINT', interrupt);
    process.removeListener('SIGTERM', interrupt);
    await writeFile(join(run.directory, 'report.json'), JSON.stringify(report, null, 2), { mode: 0o600 });
    if (!cleanupFailed) await unlink(run.envFile);
    console.log(`SIEM ${report.status}; report: ${basename(run.directory)}/report.json`);
  }
  return report;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((error) => { console.error(error.message); process.exitCode = 1; });
}
