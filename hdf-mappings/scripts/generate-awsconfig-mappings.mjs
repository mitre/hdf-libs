#!/usr/bin/env node
// Regenerates the AWS Config -> NIST 800-53 mapping (awsconfig-mappings.json) from
// authoritative AWS sources. This is the "repeatable refresh" for the mapping: run
// it, review the printed diff, commit. Output is written byte-identically to both
// the Go and TS copies. Deterministically sorted, so future diffs stay clean.
//
//   node scripts/generate-awsconfig-mappings.mjs [--check]
//
//     (no flag)  rewrite both mapping files and print the diff vs the committed data
//     --check    print the diff only; exit 1 if the files would change (CI drift gate)
//
// Provenance / tiers (a row's mapping comes from exactly one, in precedence order):
//   1. config-pack   — AWS Config "Operational Best Practices for NIST 800-53" docs
//   2. security-hub   — [STAGE 2] Security Hub NIST 800-53 standard control mappings
//   3. derived        — [STAGE 3] heuristic family-level alignment for the residual
// The authoritative tiers are regenerated from AWS; the derived tier is a small
// hand-curated input file. Provenance is tracked at the INPUT level, not as a
// runtime field, so the emitted shape is unchanged from what consumers already read.

import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO = join(__dirname, '..', '..');
const OUT_FILES = [
  join(REPO, 'hdf-mappings', 'go', 'awsconfig', 'awsconfig-mappings.json'),
  join(REPO, 'hdf-mappings', 'src', 'data', 'awsconfig-mappings.json'),
];

const CONFIG_DOCS = {
  5: 'https://docs.aws.amazon.com/config/latest/developerguide/operational-best-practices-for-nist-800-53_rev_5.html',
  4: 'https://docs.aws.amazon.com/config/latest/developerguide/operational-best-practices-for-nist-800-53_rev_4.html',
};

async function fetchText(url) {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`fetch ${url}: HTTP ${res.status}`);
  return res.text();
}

// --- normalizations (both are things AWS's raw docs need but our table already does) ---

// A collapsed sub-part token like "IA-5(1)(a)(d)(e)" is AWS shorthand for the sibling
// controls IA-5(1), IA-5(a), IA-5(d), IA-5(e) — not a valid single reference. Expand it.
function expandCollapsed(control) {
  const m = control.match(/^([A-Z]{2,}-\d+)((?:\([^)]*\)){2,})$/);
  if (!m) return [control];
  return [...m[2].matchAll(/\([^)]*\)/g)].map((g) => m[1] + g[0]);
}

// AWS sometimes writes a statement part without parens ("AC-5c"); canonicalize to
// standard NIST notation ("AC-5(c)").
function canonicalizeControl(control) {
  return control.replace(/^([A-Z]{2,}-\d+)([a-z])$/, '$1($2)');
}

// --- tier 1: AWS Config docs ---

// Parse the single control->rule table into ruleName -> Set(control), normalized.
function parseConfigDocs(html) {
  const map = new Map();
  for (const [, row] of html.matchAll(/<tr>(.*?)<\/tr>/gs)) {
    const cells = [...row.matchAll(/<td[^>]*>(.*?)<\/td>/gs)].map((c) => c[1]);
    if (cells.length < 3) continue;
    const control = cells[0].replace(/<[^>]+>/g, '').trim();
    const ruleMatch = cells[2].match(/developerguide\/([a-z0-9-]+)\.html/);
    if (!ruleMatch || !/^[A-Z]{2,}-\d/.test(control)) continue;
    const rule = ruleMatch[1];
    if (!map.has(rule)) map.set(rule, new Set());
    for (const raw of expandCollapsed(control)) map.get(rule).add(canonicalizeControl(raw));
  }
  return map;
}

// AWS managed rules follow rule-name -> SOURCE_IDENTIFIER as upper-snake. Prefer the
// source identifier already in the committed table (authoritative) when present.
function sourceIdFor(ruleName, existing) {
  return existing.get(ruleName) ?? ruleName.toUpperCase().replace(/-/g, '_');
}

async function main() {
  const check = process.argv.includes('--check');

  const committed = JSON.parse(readFileSync(OUT_FILES[0], 'utf-8'));
  const knownSourceId = new Map(committed.map((r) => [r.AwsConfigRuleName, r.AwsConfigRuleSourceIdentifier]));

  const rows = [];
  for (const rev of [5, 4]) {
    const byRule = parseConfigDocs(await fetchText(CONFIG_DOCS[rev]));
    for (const [rule, controls] of byRule) {
      // Lexical (code-unit) sort — matches Go sort.Strings byte order for the ASCII
      // control IDs, so the two mapping copies and both converters stay in lockstep.
      const nist = [...controls].sort();
      rows.push({
        AwsConfigRuleSourceIdentifier: sourceIdFor(rule, knownSourceId),
        AwsConfigRuleName: rule,
        'NIST-ID': nist.join('|'),
        Rev: rev,
      });
    }
    // TODO Stage 2: merge Security Hub NIST-standard rows for this rev.
  }
  // TODO Stage 3: merge the hand-curated heuristic tier (awsconfig-heuristic.json).

  rows.sort((a, b) => a.Rev - b.Rev || (a.AwsConfigRuleName < b.AwsConfigRuleName ? -1 : a.AwsConfigRuleName > b.AwsConfigRuleName ? 1 : 0));
  const json = JSON.stringify(rows, null, 2) + '\n';

  const before = readFileSync(OUT_FILES[0], 'utf-8');
  if (before === json) {
    console.log('awsconfig-mappings.json is up to date.');
    return;
  }
  const b = JSON.parse(before);
  const oldNames = new Set(b.map((r) => `${r.Rev}:${r.AwsConfigRuleName}`));
  const newNames = new Set(rows.map((r) => `${r.Rev}:${r.AwsConfigRuleName}`));
  const added = [...newNames].filter((n) => !oldNames.has(n));
  const removed = [...oldNames].filter((n) => !newNames.has(n));
  console.log(`rows: ${b.length} -> ${rows.length}`);
  if (added.length) console.log(`  added rules:   ${added.join(', ')}`);
  if (removed.length) console.log(`  removed rules: ${removed.join(', ')}`);

  if (check) {
    console.error('drift: mapping files are out of date — run without --check to regenerate.');
    process.exit(1);
  }
  for (const f of OUT_FILES) writeFileSync(f, json);
  console.log(`wrote ${OUT_FILES.length} files.`);
}

main().catch((e) => {
  console.error(e.message);
  process.exit(1);
});
