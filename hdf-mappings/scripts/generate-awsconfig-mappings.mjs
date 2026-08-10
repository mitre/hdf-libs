#!/usr/bin/env node
// Regenerates the AWS Config -> NIST 800-53 mapping (awsconfig-mappings.json) from
// authoritative AWS sources. This is the "repeatable refresh" for the mapping: run
// it, review the printed summary plus `git diff`, commit. Output is written
// byte-identically to both the Go and TS copies. Deterministically sorted, so
// future diffs stay clean.
//
//   node scripts/generate-awsconfig-mappings.mjs [--check]
//
//     (no flag)  rewrite both mapping files and print a row-count + added/removed summary
//     --check    report drift only; exit 1 if regenerating would change EITHER copy (CI gate)
//
// Provenance / tiers (a row's mapping comes from exactly one, in precedence order;
// each row records its tier in the Source field):
//   1. config-pack   — AWS Config "Operational Best Practices for NIST 800-53" docs
//   2. security-hub   — Security Hub NIST 800-53 r5 standard control pages (Rev 5 only)
//   3. derived-theme  — strong-theme heuristic for the residual: a rule's name matches a
//                       theme (encryption/TLS/logging/public-access) and inherits that
//                       theme's NIST core, computed from how AWS mapped same-theme rules
//   4. crosswalk      — per-rev completeness: a rule mapped at exactly one revision gets
//                       a row at the other by translating its controls through NIST's own
//                       r4<->r5 crosswalk (nist-revision-crosswalk.json). When nothing
//                       translates, an explicit empty-NIST-ID marker row is emitted.
// Tiers 1-2 are authoritative; tier 3 never invents controls — it reuses the core AWS
// already assigned to same-theme rules, at a >=75% confidence bar. Tier 4 inherits the
// confidence of the native row it was translated from. Rules matching no strong theme
// stay unmapped (the aws-config-to-hdf converter floors them to CM-6).
// Config-pack/security-hub take precedence over derived; no cross-source unioning within
// the authoritative tiers, so every authoritative row is one AWS publication verbatim.

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

// The full managed-rule catalog (from the Config docs "List of Managed Rules") drives
// the derived tier: a rule the two authoritative tiers miss but whose name matches a
// strong theme inherits that theme's NIST core. Rev 5 only.
const CONFIG_TOC = 'https://docs.aws.amazon.com/config/latest/developerguide/toc-contents.json';

// tier 3 strong themes: [name, include pattern, exclude pattern] over the rule name.
// Kept intentionally narrow — only themes where authoritatively-mapped rules share a
// stable NIST core. The exclude keeps at-rest encryption distinct from in-transit
// (an "encrypted-in-transit" rule is transmission protection, not at-rest). A control
// joins a theme's core when >= DERIVE_THRESHOLD of the theme's Rev5-mapped rules carry it.
const DERIVED_THEMES = [
  ['encryption/at-rest', /encrypt|kms|cmk/, /transit|ssl|tls|https|traffic|protocol-encrypted/],
  ['in-transit/TLS', /ssl|tls|https|in-transit/, null],
  ['logging/audit', /logging|logs|audit|cloudtrail|flow-log/, null],
  ['public-access', /public|publicly|internet/, null],
];
const DERIVE_THRESHOLD = 0.75;
// Rules naming a non-security config attribute never take a security theme: a tag check
// (`*-tagged`) or a certificate-transparency-log check asserts nothing about the theme's
// controls, so they fall through to the CM-6 floor instead of inheriting an encryption/
// audit core. Applied to both the derivation basis and residual matching.
const THEME_GLOBAL_EXCLUDE = /tag(?:ged)?$|transparent-logging/;
const themeMatches = (rule, include, exclude) =>
  !THEME_GLOBAL_EXCLUDE.test(rule) && include.test(rule) && !(exclude && exclude.test(rule));

async function fetchText(url) {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`fetch ${url}: HTTP ${res.status}`);
  return res.text();
}

// --- tier 4 support: NIST r4<->r5 crosswalk translation ---

const CROSSWALK_FILE = join(REPO, 'hdf-mappings', 'src', 'data', 'nist-revision-crosswalk.json');
// A trailing single-letter statement part, e.g. "AC-2(j)".
const STATEMENT_LETTER = /^(.*)\(([a-z])\)$/;

// Same resolution as the published Translate APIs (identity via rosters, edges
// for redirects, statement letters preserved on identity), plus one generator
// pragmatism: a token already valid at the destination revision passes through
// even when NIST doesn't list it at the source revision — AWS occasionally
// cites an old-rev control ID inside a newer-rev pack (e.g. SA-13 in a Rev 5
// mapping), and dropping it would lose a valid destination-rev tag.
function crosswalkTranslator() {
  const xw = JSON.parse(readFileSync(CROSSWALK_FILE, 'utf-8'));
  const rosters = new Map(Object.entries(xw.rosters).map(([rev, ids]) => [Number(rev), new Set(ids)]));
  const edges = new Map(xw.edges.map((e) => [`${e.from}:${e.control}`, e]));
  return (control, from, to) => {
    const edge = edges.get(`${from}:${control}`);
    if (edge) return edge.targets;
    if (rosters.get(from).has(control) && rosters.get(to).has(control)) return [control];
    const base = STATEMENT_LETTER.exec(control)?.[1];
    if (base) {
      const baseEdge = edges.get(`${from}:${base}`);
      if (baseEdge) return baseEdge.targets;
      if (rosters.get(from).has(base) && rosters.get(to).has(base)) return [control];
    }
    if (rosters.get(to).has(control) || (base && rosters.get(to).has(base))) return [control];
    return [];
  };
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

// --- tier 3: derived (strong-theme heuristic) ---

// Enumerate the managed-rule catalog from the Config docs "List of Managed Rules" subtree.
async function fetchManagedRuleCatalog() {
  const toc = JSON.parse(await fetchText(CONFIG_TOC));
  let section;
  (function find(node) {
    if (Array.isArray(node)) node.forEach(find);
    else if (node && typeof node === 'object') {
      if (node.title === 'List of Managed Rules') section = node;
      Object.values(node).forEach(find);
    }
  })(toc);
  const rules = new Set();
  (function collect(node) {
    if (Array.isArray(node)) node.forEach(collect);
    else if (node && typeof node === 'object') {
      if (typeof node.href === 'string' && /^[a-z0-9-]+\.html$/.test(node.href)) rules.add(node.href.replace(/\.html$/, ''));
      Object.values(node).forEach(collect);
    }
  })(section ?? {});
  return rules;
}

// Derive each strong theme's NIST core empirically: the controls carried by at least
// DERIVE_THRESHOLD of the Rev5 authoritatively-mapped rules whose name matches the theme.
// The core is thus never invented — it is exactly what AWS assigned to same-theme rules.
function deriveThemeCores(authoritativeRows) {
  const rev5 = new Map();
  for (const r of authoritativeRows) {
    if (r.Rev === 5) rev5.set(r.AwsConfigRuleName, r['NIST-ID'].split('|'));
  }
  const cores = new Map();
  for (const [theme, include, exclude] of DERIVED_THEMES) {
    const themeRules = [...rev5].filter(([name]) => themeMatches(name, include, exclude));
    const counts = new Map();
    for (const [, controls] of themeRules) for (const c of controls) counts.set(c, (counts.get(c) ?? 0) + 1);
    const core = new Set([...counts].filter(([, k]) => k >= DERIVE_THRESHOLD * themeRules.length).map(([c]) => c));
    cores.set(theme, core);
  }
  return cores;
}

async function main() {
  const check = process.argv.includes('--check');

  const committed = JSON.parse(readFileSync(OUT_FILES[0], 'utf-8'));
  const knownSourceId = new Map(committed.map((r) => [r.AwsConfigRuleName, r.AwsConfigRuleSourceIdentifier]));

  // Lexical (code-unit) sort — matches Go sort.Strings byte order for the ASCII
  // control IDs, so the two mapping copies and both converters stay in lockstep.
  const rowFor = (rule, controls, rev, source) => ({
    AwsConfigRuleSourceIdentifier: sourceIdFor(rule, knownSourceId),
    AwsConfigRuleName: rule,
    'NIST-ID': [...controls].sort().join('|'),
    Rev: rev,
    Source: source,
  });

  const rows = [];
  const seen = new Set(); // `${rev}:${rule}` already emitted
  for (const rev of [5, 4]) {
    const byRule = parseConfigDocs(await fetchText(CONFIG_DOCS[rev]));
    for (const [rule, controls] of byRule) {
      rows.push(rowFor(rule, controls, rev, 'config-pack'));
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
    rows.push(rowFor(rule, controls, 5, 'security-hub'));
    seen.add(`5:${rule}`);
    shAdded += 1;
  }
  console.log(`  security hub: ${pageCount} pages, ${shRules.size} rules mapped, ${shAdded} new (rest already covered by config-pack).`);

  // tier 3: derived. A managed rule the authoritative tiers miss but whose name matches a
  // strong theme inherits that theme's empirically-derived NIST core (union across matched
  // themes). Rules matching no strong theme stay unmapped — the aws-config-to-hdf converter
  // applies the CM-6 configuration-settings floor to those at conversion time.
  const catalog = await fetchManagedRuleCatalog();
  const cores = deriveThemeCores(rows);
  let derivedAdded = 0;
  for (const rule of [...catalog].sort()) {
    if (seen.has(`5:${rule}`)) continue;
    const controls = new Set();
    for (const [theme, include, exclude] of DERIVED_THEMES) {
      if (themeMatches(rule, include, exclude)) for (const c of cores.get(theme)) controls.add(c);
    }
    if (controls.size === 0) continue;
    rows.push(rowFor(rule, controls, 5, 'derived-theme'));
    seen.add(`5:${rule}`);
    derivedAdded += 1;
  }
  console.log(`  derived: catalog ${catalog.size} rules, ${derivedAdded} residual rules matched a strong theme (rest fall to the CM-6 converter floor).`);

  // tier 4: crosswalk. A rule mapped at exactly one revision gets a row at the other
  // revision by translating its controls through NIST's own r4<->r5 crosswalk (see
  // generate-nist-crosswalk.mjs). Native rows are never touched — this tier only fills
  // (rule, rev) holes. When nothing translates (the whole control set is new at the
  // native revision), an explicit empty-NIST-ID marker row is emitted: "no mapping
  // exists at this revision" is an answer, not an omission.
  const translate = crosswalkTranslator();
  const nativeRevs = new Map(); // rule -> Map(rev -> controls[])
  for (const r of rows) {
    if (!nativeRevs.has(r.AwsConfigRuleName)) nativeRevs.set(r.AwsConfigRuleName, new Map());
    nativeRevs.get(r.AwsConfigRuleName).set(r.Rev, r['NIST-ID'].split('|').filter(Boolean));
  }
  const backfilled = { 4: 0, 5: 0 };
  let markers = 0;
  for (const [rule, revs] of nativeRevs) {
    for (const [native, other] of [
      [5, 4],
      [4, 5],
    ]) {
      if (!revs.has(native) || revs.has(other) || seen.has(`${other}:${rule}`)) continue;
      const controls = new Set(revs.get(native).flatMap((c) => translate(c, native, other)));
      rows.push(rowFor(rule, controls, other, 'crosswalk'));
      seen.add(`${other}:${rule}`);
      if (controls.size === 0) markers += 1;
      else backfilled[other] += 1;
    }
  }
  console.log(`  crosswalk: backfilled ${backfilled[4]} Rev4 + ${backfilled[5]} Rev5 rows, ${markers} explicit unmapped marker row(s).`);

  rows.sort((a, b) => a.Rev - b.Rev || (a.AwsConfigRuleName < b.AwsConfigRuleName ? -1 : a.AwsConfigRuleName > b.AwsConfigRuleName ? 1 : 0));
  const json = JSON.stringify(rows, null, 2) + '\n';

  // Compare EVERY output copy, not just the first — a drifted or hand-edited TS copy
  // must still be caught (and rewritten) even when the Go copy already matches.
  const current = OUT_FILES.map((f) => readFileSync(f, 'utf-8'));
  if (current.every((c) => c === json)) {
    console.log(`awsconfig-mappings.json is up to date (${OUT_FILES.length} copies).`);
    return;
  }
  const b = JSON.parse(current[0]);
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
