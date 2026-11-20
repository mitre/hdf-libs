import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { parse as parseYaml } from 'yaml';
import {
  toolsInManifest,
  checksummedInLock,
  checkToolchainChecksums,
  checkGuardWiring,
} from '../check-toolchain-checksums.mjs';

const manifest = (body) => `[tools]\n${body}\n`;
const lockFor = (tool, platforms) =>
  `[[tools."${tool}"]]\nversion = "1.0.0"\n` +
  platforms.map((p) => `\n[tools."${tool}"."platforms.${p}"]\nchecksum = "sha256:abc"\n`).join('');

test('reads the tools the manifest installs, ignoring other sections', () => {
  const toml = `min_version = "2026.10.9"\n\n${manifest('node = "24"\nshellcheck = "0.11.0"')}\n[settings]\nexperimental = true\n`;
  assert.deepEqual(toolsInManifest(toml), ['node', 'shellcheck']);
});

test('a quoted backend tool name survives the read', () => {
  assert.deepEqual(toolsInManifest(manifest('"aqua:jdx/jactionlint" = "2.5.0"')), ['aqua:jdx/jactionlint']);
});

test('reads which platforms each locked tool records, and which of those carry a checksum', () => {
  const { locked, platforms, withChecksum } = checksummedInLock(lockFor('shellcheck', ['linux-x64', 'macos-arm64']));
  assert.deepEqual([...locked], ['shellcheck']);
  assert.deepEqual([...platforms.get('shellcheck')].sort(), ['linux-x64', 'macos-arm64']);
  assert.deepEqual([...withChecksum.get('shellcheck')].sort(), ['linux-x64', 'macos-arm64']);
});

test('a correctly checksummed toolchain reports nothing', () => {
  const offenders = checkToolchainChecksums({
    miseToml: manifest('shellcheck = "0.11.0"'),
    miseLock: lockFor('shellcheck', ['linux-x64']),
  });
  assert.deepEqual(offenders, []);
});

test('a binary tool with no checksum is reported', () => {
  const offenders = checkToolchainChecksums({
    miseToml: manifest('shellcheck = "0.11.0"'),
    miseLock: '[[tools."shellcheck"]]\nversion = "0.11.0"\n',
  });
  assert.equal(offenders.length, 1);
  assert.match(offenders[0].reason, /records no platform with a checksum/);
});

test('a platform the lock records without a checksum is reported, so one covered platform cannot stand in for all', () => {
  const miseLock =
    '[[tools."shellcheck"]]\nversion = "0.11.0"\n' +
    '\n[tools."shellcheck"."platforms.linux-x64"]\nchecksum = "sha256:abc"\n' +
    '\n[tools."shellcheck"."platforms.macos-arm64"]\nurl = "https://example.test/x.tar.gz"\n';
  const offenders = checkToolchainChecksums({ miseToml: manifest('shellcheck = "0.11.0"'), miseLock });
  assert.equal(offenders.length, 1);
  assert.match(offenders[0].reason, /macos-arm64 with no checksum/);
});

test('a manifest tool missing from the lock is reported', () => {
  const offenders = checkToolchainChecksums({
    miseToml: manifest('shellcheck = "0.11.0"'),
    miseLock: '',
  });
  assert.equal(offenders.length, 1);
  assert.match(offenders[0].reason, /absent from the lock/);
});

test('a tool-level checksum line is judged the same wherever it sits in the file', () => {
  const bare = '[[tools."shellcheck"]]\nversion = "0.11.0"\nchecksum = "sha256:abc"\n';
  const withPlatforms = lockFor('golangci-lint', ['macos-arm64']);
  const toml = manifest('shellcheck = "0.11.0"\n"golangci-lint" = "2.15.0"');
  const first = checkToolchainChecksums({ miseToml: toml, miseLock: `${bare}\n${withPlatforms}` });
  const second = checkToolchainChecksums({ miseToml: toml, miseLock: `${withPlatforms}\n${bare}` });
  assert.deepEqual(
    second.map((o) => o.reason),
    first.map((o) => o.reason),
    'the verdict must not depend on which tool block came first',
  );
  assert.ok(first.some((o) => /shellcheck records no platform/.test(o.reason)));
});

test('a source-built tool needs no checksum', () => {
  const offenders = checkToolchainChecksums({
    miseToml: manifest('"go:golang.org/x/vuln/cmd/govulncheck" = "1.9.0"'),
    miseLock: '[[tools."go:golang.org/x/vuln/cmd/govulncheck"]]\nversion = "1.9.0"\n',
  });
  assert.deepEqual(offenders, []);
});

test('a source-built tool that does carry a checksum is reported, so the exemption cannot widen silently', () => {
  const offenders = checkToolchainChecksums({
    miseToml: manifest('"go:golang.org/x/vuln/cmd/govulncheck" = "1.9.0"'),
    miseLock: lockFor('go:golang.org/x/vuln/cmd/govulncheck', ['linux-x64']),
  });
  assert.equal(offenders.length, 1);
  assert.match(offenders[0].reason, /re-check the exemption/);
});

test('this guard is wired into both the hook target and a CI job', () => {
  const packageJson = JSON.parse(readFileSync(new URL('../../package.json', import.meta.url), 'utf8'));
  const ci = parseYaml(readFileSync(new URL('../../.github/workflows/ci.yml', import.meta.url), 'utf8'));
  assert.deepEqual(checkGuardWiring({ packageJson, ci }), []);
});

test('a guard nothing invokes is reported, per side', () => {
  const ci = { jobs: { a: { steps: [{ run: 'echo hi' }] } } };
  const reasons = checkGuardWiring({ packageJson: { scripts: {} }, ci }).map((o) => o.reason);
  assert.equal(reasons.length, 3);
  assert.ok(reasons.some((r) => /no lint:toolchain-checksums script/.test(r)));
  assert.ok(reasons.some((r) => /check target does not run/.test(r)));
  assert.ok(reasons.some((r) => /no CI job runs/.test(r)));
});

test('the local lint and CI lint the workflows the same way: neither overrides the config', () => {
  const root = new URL('../../', import.meta.url);
  const pkg = JSON.parse(readFileSync(new URL('package.json', root), 'utf8'));
  const ciText = readFileSync(new URL('.github/workflows/ci.yml', root), 'utf8');
  // An allowlist, not a blocklist: the invocation must carry no arguments at all,
  // so neither caller can read a different rule set than the other. A list of
  // flags to forbid falls behind the tool; this cannot. Line continuations count,
  // so a flag on the next line is not a way past it.
  // Only where the name sits in command position: the availability loop in
  // lint:workflows mentions jactionlint as a word in a list, which is not a call.
  const invocations = (text) =>
    [...String(text).matchAll(/(?:^|[;&|]\s*|\n\s*)jactionlint((?:\s*\\\s*\n|[^\n|&;])*)/g)].map((m) =>
      m[1].trim(),
    );
  for (const args of invocations(pkg.scripts['lint:workflows'])) {
    assert.equal(args, '', `lint:workflows must invoke jactionlint with no arguments, got "${args}"`);
  }
  for (const args of invocations(ciText)) {
    assert.equal(args, '', `no workflow may pass jactionlint arguments, got "${args}"`);
  }
  const config = parseYaml(readFileSync(new URL('.github/jactionlint.yaml', root), 'utf8'));
  assert.equal(config.profile, 'default', 'the config selects the profile both callers then read');
  assert.equal(config.rules['template-injection'].pedantic, true);
});
