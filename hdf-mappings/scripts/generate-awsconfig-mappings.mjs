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
//   2. security-hub   — Security Hub NIST 800-53 r5 standard control pages (Rev 5 only)
//   3. derived        — [STAGE 3] heuristic family-level alignment for the residual
// The authoritative tiers are regenerated from AWS; the derived tier is a small
// hand-curated input file. Provenance is tracked at the INPUT level, not as a
// runtime field, so the emitted shape is unchanged from what consumers already read.
// No cross-source unioning: config-pack wins where both cover a rule, so every row's
// control set is one AWS publication verbatim (never a combination neither source ships).

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

// Security Hub publishes its NIST 800-53 r5 standard as per-service control pages
// (<service>-controls.html), each control listing its backing managed Config rule
// and "Related requirements" (the NIST controls). This is Rev 5 only.
const SECURITY_HUB_BASE = 'https://docs.aws.amazon.com/securityhub/latest/userguide/';
const SECURITY_HUB_TOC = SECURITY_HUB_BASE + 'toc-contents.json';

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

// --- tier 2: Security Hub NIST 800-53 r5 standard ---

// Parse one <service>-controls.html page into ruleName -> Set(control). Each control
// is an <h2 id="service-N"> section carrying an "AWS Config rule" link and a
// "Related requirements" list; keep only the NIST.800-53.r5 tokens (pages mix in
// PCI/CIS). A section may have a rule but no NIST reqs (skip) or vice versa.
function parseSecurityHubDocs(html) {
  const map = new Map();
  const sections = html.split(/<h2[^>]*id="([^"]+)"/);
  for (let i = 1; i < sections.length; i += 2) {
    const id = sections[i];
    const body = sections[i + 1];
    if (id.endsWith('-remediation')) continue;
    const ruleMatch = body.match(/AWS Config rule:<\/b>[\s\S]*?\/config\/latest\/developerguide\/([a-z0-9-]+)\.html/);
    const reqsMatch = body.match(/Related requirements:<\/b>([\s\S]*?)<\/p>/);
    if (!ruleMatch || !reqsMatch) continue;
    const rule = ruleMatch[1];
    for (const [, control] of reqsMatch[1].matchAll(/NIST\.800-53\.r5\s+([A-Z]{2,}-\d+(?:\([^)]*\))?)/g)) {
      for (const raw of expandCollapsed(control)) {
        if (!map.has(rule)) map.set(rule, new Set());
        map.get(rule).add(canonicalizeControl(raw));
      }
    }
  }
  return map;
}

// Fetch every Security Hub control page (enumerated from the docs TOC) and merge into
// ruleName -> Set(control). Within Security Hub a rule may back several controls; unioning
// their NIST sets is still single-source. Warns (does not fail) on any unreachable page.
async function fetchSecurityHubRules() {
  const toc = JSON.parse(await fetchText(SECURITY_HUB_TOC));
  const pages = new Set();
  (function walk(node) {
    if (Array.isArray(node)) node.forEach(walk);
    else if (node && typeof node === 'object') {
      if (typeof node.href === 'string' && /-controls\.html$/.test(node.href)) pages.add(node.href);
      Object.values(node).forEach(walk);
    }
  })(toc);

  const merged = new Map();
  let failed = 0;
  const list = [...pages];
  const CONCURRENCY = 12;
  for (let i = 0; i < list.length; i += CONCURRENCY) {
    const batch = await Promise.all(
      list.slice(i, i + CONCURRENCY).map((p) =>
        fetchText(SECURITY_HUB_BASE + p)
          .then(parseSecurityHubDocs)
          .catch(() => { failed += 1; return new Map(); })
      )
    );
    for (const m of batch) {
      for (const [rule, controls] of m) {
        if (!merged.has(rule)) merged.set(rule, new Set());
        for (const c of controls) merged.get(rule).add(c);
      }
    }
  }
  if (failed) console.warn(`  warning: ${failed}/${list.length} Security Hub pages were unreachable — coverage may be incomplete.`);
  return { rules: merged, pageCount: list.length };
}

async function main() {
  const check = process.argv.includes('--check');

  const committed = JSON.parse(readFileSync(OUT_FILES[0], 'utf-8'));
  const knownSourceId = new Map(committed.map((r) => [r.AwsConfigRuleName, r.AwsConfigRuleSourceIdentifier]));

  // Lexical (code-unit) sort — matches Go sort.Strings byte order for the ASCII
  // control IDs, so the two mapping copies and both converters stay in lockstep.
  const rowFor = (rule, controls, rev) => ({
    AwsConfigRuleSourceIdentifier: sourceIdFor(rule, knownSourceId),
    AwsConfigRuleName: rule,
    'NIST-ID': [...controls].sort().join('|'),
    Rev: rev,
  });

  const rows = [];
  const seen = new Set(); // `${rev}:${rule}` already emitted
  for (const rev of [5, 4]) {
    const byRule = parseConfigDocs(await fetchText(CONFIG_DOCS[rev]));
    for (const [rule, controls] of byRule) {
      rows.push(rowFor(rule, controls, rev));
      seen.add(`${rev}:${rule}`);
    }
  }

  // tier 2: Security Hub NIST 800-53 r5 standard. Config-pack takes precedence — only
  // rules absent at Rev 5 are added, each keeping its Security Hub control set verbatim.
  // No cross-source unioning: every row's controls come from exactly one AWS publication.
  const { rules: shRules, pageCount } = await fetchSecurityHubRules();
  let shAdded = 0;
  for (const [rule, controls] of shRules) {
    if (seen.has(`5:${rule}`)) continue;
    rows.push(rowFor(rule, controls, 5));
    seen.add(`5:${rule}`);
    shAdded += 1;
  }
  console.log(`  security hub: ${pageCount} pages, ${shRules.size} rules mapped, ${shAdded} new (rest already covered by config-pack).`);
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
