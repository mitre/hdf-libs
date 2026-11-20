import assert from 'node:assert/strict';
import test from 'node:test';
import { validateReport } from './ci-report.mjs';
import cases from './cases.json' with { type: 'json' };
import { mkdtemp, mkdir, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

const commit = 'a'.repeat(40);
const digest = 'b'.repeat(64);
function completed() {
  return { mode: 'integration', status: 'PASS', cleanup: 'PASS',
    source: { commit, trackedDiffSha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', untracked: [] },
    targets: { splunk: { version: '10.6.1.1', authenticated: true, image: `splunk/splunk@sha256:${digest}`,
      verification: { cases: cases.flatMap(({ name, kind }) => ['cli', 'typescript'].map((producer) => ({
        name, kind, producer, sourceSha256: digest, events: name === 'empty' ? 0 : 1, checksums: 3,
        sizes: { 'source.json': 1, 'events.ndjson': name === 'empty' ? 0 : 1, 'manifest.json': 1, 'evidence-package.json': 1, archive: 1 },
        negatives: name === 'override' ? Array.from({ length: 10 }, (_, i) => `rejected-${i}`) : [],
      }))) } } } };
}

test('missing requested target cannot count as integration evidence', () => {
  assert.throws(() => validateReport({ status: 'PASS', mode: 'integration', targets: {} }, 'splunk'), /target/);
});

test('service readiness cannot count as integration evidence', () => {
  assert.throws(() => validateReport({ status: 'PASS', mode: 'environment', targets: { splunk: {} } }, 'splunk'), /integration/);
});

test('accepts a complete current-commit matrix, including the empty assessment', () => {
  assert.equal(validateReport(completed(), 'splunk', commit).length, cases.length * 2);
});

for (const [name, mutate] of [
  ['failed run', r => { r.status = 'FAIL'; }],
  ['failed cleanup', r => { r.cleanup = 'FAIL'; }],
  ['missing cleanup', r => { delete r.cleanup; }],
  ['wrong commit', r => { r.source.commit = 'c'.repeat(40); }],
  ['missing fingerprint', r => { delete r.source; }],
  ['dirty checkout', r => { r.source.trackedDiffSha256 = digest; }],
  ['untracked implementation', r => { r.source.untracked = [{ path: 'test/siem/extra.mjs', sha256: digest }]; }],
  ['missing version', r => { delete r.targets.splunk.version; }],
  ['missing digest', r => { r.targets.splunk.image = 'splunk/splunk:latest'; }],
  ['unauthenticated target', r => { r.targets.splunk.authenticated = false; }],
  ['missing verification', r => { delete r.targets.splunk.verification; }],
  ['empty matrix', r => { r.targets.splunk.verification.cases = []; }],
  ['missing producer', r => { r.targets.splunk.verification.cases.pop(); }],
  ['duplicate case', r => { const rows = r.targets.splunk.verification.cases; rows[1] = rows[0]; }],
  ['unknown case', r => { r.targets.splunk.verification.cases[0].name = 'unknown'; }],
  ['missing source hash', r => { delete r.targets.splunk.verification.cases[0].sourceSha256; }],
  ['producer input disagreement', r => { r.targets.splunk.verification.cases[0].sourceSha256 = 'd'.repeat(64); }],
  ['missing event result', r => { delete r.targets.splunk.verification.cases[0].events; }],
  ['negative event count', r => { r.targets.splunk.verification.cases[0].events = -1; }],
  ['missing integrity checks', r => { r.targets.splunk.verification.cases[0].checksums = 0; }],
  ['string integrity count', r => { r.targets.splunk.verification.cases[0].checksums = '3'; }],
  ['partial integrity count', r => { r.targets.splunk.verification.cases[0].checksums = 2; }],
  ['no events from a populated fixture', r => { r.targets.splunk.verification.cases[0].events = 0; }],
  ['events from an empty fixture', r => { r.targets.splunk.verification.cases.find(c => c.name === 'empty').events = 1; }],
  ['incorrect fixture provenance', r => { r.targets.splunk.verification.cases[0].kind = 'unknown'; }],
  ['missing archive', r => { delete r.targets.splunk.verification.cases[0].sizes.archive; }],
  ['missing negative cases', r => { r.targets.splunk.verification.cases.find(c => c.name === 'override').negatives = []; }],
]) {
  test(`rejects ${name}`, () => {
    const report = completed(); mutate(report);
    assert.throws(() => validateReport(report, 'splunk', commit));
  });
}

test('requires an explicit supported target and expected commit', () => {
  assert.throws(() => validateReport(completed(), 'all', commit));
  assert.throws(() => validateReport(completed(), 'splunk'));
});

for (const scenario of ['complete', 'missing', 'empty', 'malformed', 'duplicate', 'failed', 'readiness']) {
  test(`JUnit command preserves ${scenario} evidence verdict`, async (t) => {
    const directory = await mkdtemp(join(tmpdir(), 'siem-report-'));
    t.after(() => rm(directory, { recursive: true, force: true }));
    if (scenario !== 'missing') {
      await mkdir(join(directory, 'run'));
      const report = completed();
      if (scenario === 'failed') report.status = 'FAIL';
      if (scenario === 'readiness') report.mode = 'environment';
      await writeFile(join(directory, 'run', 'report.json'), scenario === 'empty' ? ''
        : scenario === 'malformed' ? 'secret-test-marker' : JSON.stringify(report));
      if (scenario === 'duplicate') {
        await mkdir(join(directory, 'run2'));
        await writeFile(join(directory, 'run2', 'report.json'), JSON.stringify(report));
      }
    }
    const env = { ...process.env, HDF_SIEM_REPORT_DIR: directory, HDF_SIEM_REPORT_TARGET: 'splunk', HDF_SIEM_REPORT_COMMIT: commit };
    delete env.NODE_TEST_CONTEXT;
    const result = spawnSync(process.execPath, ['--test', '--test-reporter=junit', fileURLToPath(new URL('./ci-report.mjs', import.meta.url))], {
      encoding: 'utf8', env,
    });
    assert.equal(result.status, scenario === 'complete' ? 0 : 1, result.stderr);
    assert.match(result.stdout, /<testcase name="splunk source-preserving integration"/);
    assert.equal(result.stdout.includes('<failure'), scenario !== 'complete');
    assert.equal(result.stdout.includes('secret-test-marker'), false, 'report contents cannot leak through parser diagnostics');
    assert.equal(result.stdout.includes(directory), false, 'local report paths must not leak');
  });
}
