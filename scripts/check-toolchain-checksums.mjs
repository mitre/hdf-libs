#!/usr/bin/env node
// Every tool the pinned toolchain installs must carry platform checksums in
// mise.lock, so a release binary cannot be swapped under a version that already
// resolved. The two go: backend tools are the stated exception: neither
// publishes release binaries, mise builds them from source, and their integrity
// comes from the Go checksum database rather than an artifact hash there is no
// way to record here.
import { readFileSync, realpathSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

export const SOURCE_BUILT_PREFIX = 'go:';
const TARGET = 'lint:toolchain-checksums';

// mise.toml's [tools] entries, which is what a clone installs.
export function toolsInManifest(miseToml) {
  const lines = String(miseToml ?? '').split(/\r?\n/);
  const tools = [];
  let inTools = false;
  for (const line of lines) {
    const section = /^\s*\[([^\]]+)\]\s*$/.exec(line);
    if (section) {
      inTools = section[1].trim() === 'tools';
      continue;
    }
    if (!inTools) continue;
    const entry = /^\s*"?([A-Za-z0-9_:./@-]+?)"?\s*=\s*"/.exec(line);
    if (entry) tools.push(entry[1]);
  }
  return tools;
}

// Which tools mise.lock records a platform checksum for.
export function checksummedInLock(miseLock) {
  const text = String(miseLock ?? '');
  const locked = new Set();
  const platforms = new Map();
  const withChecksum = new Map();
  let current = '';
  let currentPlatform = '';
  for (const line of text.split(/\r?\n/)) {
    const block = /^\s*\[\[tools\.(?:"([^"]+)"|([^\]"]+))\]\]\s*$/.exec(line);
    if (block) {
      current = block[1] ?? block[2];
      // Reset the platform cursor, or a checksum line sitting directly under this
      // block would be credited to the previous tool's last platform, making the
      // verdict depend on where the entry sits in the file.
      currentPlatform = '';
      locked.add(current);
      continue;
    }
    const platform = /^\s*\[tools\.(?:"([^"]+)"|([^."]+))\."platforms\.([^"]+)"\]/.exec(line);
    if (platform) {
      current = platform[1] ?? platform[2];
      currentPlatform = platform[3];
      platforms.set(current, (platforms.get(current) ?? new Set()).add(currentPlatform));
      continue;
    }
    if (/^\s*checksum\s*=/.test(line) && current && currentPlatform) {
      withChecksum.set(current, (withChecksum.get(current) ?? new Set()).add(currentPlatform));
    }
  }
  return { locked, platforms, withChecksum };
}

export function checkToolchainChecksums({ miseToml, miseLock }) {
  const offenders = [];
  const { locked, platforms, withChecksum } = checksummedInLock(miseLock);
  for (const tool of toolsInManifest(miseToml)) {
    if (!locked.has(tool)) {
      offenders.push({ reason: `${tool} is pinned in the manifest but absent from the lock` });
      continue;
    }
    const sourceBuilt = tool.startsWith(SOURCE_BUILT_PREFIX);
    const recorded = platforms.get(tool) ?? new Set();
    const checksummed = withChecksum.get(tool) ?? new Set();
    const hasChecksum = checksummed.size > 0;
    if (!sourceBuilt && !hasChecksum) {
      offenders.push({ reason: `${tool} records no platform with a checksum in the lock` });
    }
    // Every platform the lock does record must carry one, or a clone on the
    // uncovered platform downloads a release nothing verified.
    const bare = [...recorded].filter((p) => !checksummed.has(p));
    if (!sourceBuilt && hasChecksum && bare.length > 0) {
      offenders.push({ reason: `${tool} records ${bare.join(', ')} with no checksum` });
    }
    // The exception must stay narrow: a source-built tool that suddenly does
    // carry artifact checksums means the backend changed, and the reason this
    // script exempts it no longer holds.
    if (sourceBuilt && hasChecksum) {
      offenders.push({
        reason: `${tool} is exempt as source-built, yet the lock records a checksum for it; re-check the exemption`,
      });
    }
  }
  return offenders;
}

// A guard nothing runs is not a guard.
export function checkGuardWiring({ packageJson, ci }) {
  const offenders = [];
  const scripts = packageJson?.scripts ?? {};
  if (!scripts[TARGET]) offenders.push({ reason: `package.json has no ${TARGET} script` });
  if (!String(scripts.check ?? '').includes(`pnpm run ${TARGET}`)) {
    offenders.push({ reason: `the check target does not run ${TARGET}, so the pre-commit hook skips it` });
  }
  const runsIt = Object.values(ci?.jobs ?? {}).some((job) =>
    (job?.steps ?? []).some((step) => String(step?.run ?? '').includes(TARGET)),
  );
  if (!runsIt) offenders.push({ reason: `no CI job runs ${TARGET}, so a pull request does not check it` });
  return offenders;
}

function main() {
  const root = join(dirname(fileURLToPath(import.meta.url)), '..');
  const read = (p) => readFileSync(join(root, p), 'utf8');
  const offenders = [
    ...checkToolchainChecksums({ miseToml: read('mise.toml'), miseLock: read('mise.lock') }),
  ];
  if (offenders.length === 0) {
    console.log('toolchain-checksums: ok — every tool the manifest pins is checksummed in the lock, bar the source-built ones');
    return;
  }
  for (const { reason } of offenders) console.error(`toolchain-checksums: ${reason}`);
  process.exit(1);
}

if (process.argv[1] && realpathSync(fileURLToPath(import.meta.url)) === realpathSync(process.argv[1])) main();
