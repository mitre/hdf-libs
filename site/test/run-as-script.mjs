import fs from 'fs';
import os from 'os';
import path from 'path';
import { execFileSync } from 'child_process';
import { fileURLToPath } from 'url';

const SITE_DIR = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const REPO_ROOT = path.resolve(SITE_DIR, '..');

/**
 * Runs a site generator as `pnpm generate` does, `node <script>`, from a copy of the repo
 * layout under a path with a space, which URL-encodes and so exposes a main-module guard
 * that compares import.meta.url to argv[1]. Hands the copy's site dir to `check`.
 */
export function runAsScriptUnderSpacedPath(script, inputs, check) {
  // Real path: macOS's tmpdir is behind a symlink, which would mask the case under test.
  const tmp = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'hdf-site-')));
  try {
    const root = path.join(tmp, 'dir with space');
    const site = path.join(root, 'site');
    fs.mkdirSync(site, { recursive: true });
    fs.copyFileSync(path.join(SITE_DIR, script), path.join(site, script));
    for (const rel of inputs) {
      fs.mkdirSync(path.dirname(path.join(root, rel)), { recursive: true });
      fs.copyFileSync(path.join(REPO_ROOT, rel), path.join(root, rel));
    }
    execFileSync(process.execPath, [path.join(site, script)], { stdio: 'pipe' });
    check(site);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
}
