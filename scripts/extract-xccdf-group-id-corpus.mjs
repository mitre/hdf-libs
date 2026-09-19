#!/usr/bin/env node
/**
 * Extract the XCCDF group-id collision corpus from the converter fixtures.
 *
 * hdf-to-xccdf must never encode two distinct STIG group ids to one XCCDF
 * Group/@id. That property is asserted over real gids, and this script is where
 * they come from: every distinct tags.gid in every converter fixture, with the
 * fixture (and so its provenance record) each one was found in.
 *
 * The output is COMMITTED and read by the Go and TypeScript tests. It is not
 * rebuilt at test time on purpose: scavenging the corpus from whatever fixtures
 * happen to exist made every converter's fixture size load-bearing for one
 * unrelated test, and a clean trim elsewhere failed it. Re-run this only to
 * grow the corpus deliberately, and commit the result with the fixtures it names.
 *
 *   node scripts/extract-xccdf-group-id-corpus.mjs
 */
import { readdirSync, readFileSync, writeFileSync, existsSync } from 'node:fs';
import { join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFileSync } from 'node:child_process';

const REPO_ROOT = fileURLToPath(new URL('..', import.meta.url));
const CONVERTERS = join(REPO_ROOT, 'hdf-converters', 'converters');
const OUT = join(REPO_ROOT, 'hdf-converters', 'shared', 'xccdf-group-id-corpus.json');

function walk(dir, out = []) {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const p = join(dir, entry.name);
    if (entry.isDirectory()) walk(p, out);
    else if (entry.name.endsWith('.json') && p.split('/').includes('fixtures')) out.push(p);
  }
  return out;
}

function visitTags(node, fn) {
  if (Array.isArray(node)) {
    for (const child of node) visitTags(child, fn);
  } else if (node && typeof node === 'object') {
    for (const [key, child] of Object.entries(node)) {
      if (key === 'tags' && child && typeof child === 'object' && !Array.isArray(child)) fn(child);
      visitTags(child, fn);
    }
  }
}

const gidSources = new Map();
for (const file of walk(CONVERTERS).sort()) {
  let doc;
  try {
    doc = JSON.parse(readFileSync(file, 'utf8'));
  } catch {
    continue; // deliberately malformed fixtures exercise error paths
  }
  const rel = relative(join(REPO_ROOT, 'hdf-converters'), file);
  visitTags(doc, (tags) => {
    if (typeof tags.gid !== 'string') return;
    if (!gidSources.has(tags.gid)) gidSources.set(tags.gid, new Set());
    gidSources.get(tags.gid).add(rel);
  });
}

const gids = [...gidSources.keys()].sort();
const perFixture = new Map();
for (const [, files] of gidSources) {
  for (const f of files) perFixture.set(f, (perFixture.get(f) ?? 0) + 1);
}
const sources = [...perFixture.entries()].sort().map(([fixture, count]) => {
  const dir = fixture.slice(0, fixture.indexOf('/fixtures/') + '/fixtures'.length);
  const provenance = ['provenance.txt', 'provenance.json']
    .map((n) => join(dir, n))
    .find((p) => existsSync(join(REPO_ROOT, 'hdf-converters', p)));
  return { fixture, provenance: provenance ?? null, gids: count };
});
const shapes = [...new Set(gids.map((g) => g.replace(/[0-9]+/g, 'N')))].sort();
const rev = execFileSync('git', ['rev-parse', '--short', 'HEAD'], { cwd: REPO_ROOT }).toString().trim();

const corpus = {
  $comment:
    'Real STIG/XCCDF group ids for the hdf-to-xccdf collision test, read by Go (groupid_test.go) and TypeScript (groupid.test.ts). ' +
    'Extracted by scripts/extract-xccdf-group-id-corpus.mjs from the converter fixtures listed in sources, each of which has its own provenance record; ' +
    'nothing here is invented. Committed on purpose and NOT rebuilt at test time, so trimming a fixture cannot change this test. ' +
    'sources and their gid counts describe the fixtures as they were at extractedAt; trimming one of them afterwards changes nothing here, which is the point. ' +
    'count and shapes are asserted by the tests: a truncated or hand-edited file fails.',
  extracted: new Date().toISOString().slice(0, 10),
  extractedAt: rev,
  sources,
  shapes,
  count: gids.length,
  gids,
};
writeFileSync(OUT, JSON.stringify(corpus, null, 2) + '\n');
console.log(`${gids.length} distinct gids, ${shapes.length} shapes, from ${sources.length} fixtures -> ${relative(REPO_ROOT, OUT)}`);
