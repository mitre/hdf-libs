#!/usr/bin/env node
// Regenerates the NIST 800-53 Rev 4 <-> Rev 5 control crosswalk
// (nist-revision-crosswalk.json) from NIST's own comparison workbooks. Run it,
// review the printed summary plus `git diff`, commit. Output is written
// byte-identically to both the Go and TS copies, deterministically sorted.
//
//   node scripts/generate-nist-crosswalk.mjs [--check]
//
//     (no flag)  rewrite both crosswalk files and print a summary
//     --check    report drift only; exit 1 if regenerating would change EITHER copy
//
// Sources (both NIST-published, machine-readable, from the SP 800-53 Rev 5 final page):
//   1. sp800-53r4-to-r5-comparison-workbook.xlsx, sheet "Rev4 Rev5 Compared" — one row
//      per Rev 5-era control ID with a change notation. Derivation:
//        "New base control"/"New control enhancement"  -> exists at Rev 5 only
//        "Withdrawn"                                    -> exists at Rev 4 only; the
//          detail column names the successor ("Moved to X" / "Incorporated into X")
//        detail "Previously withdrawn in Rev4; ..."     -> valid at NEITHER revision;
//          redirect edges are emitted from both directions so stale tags still resolve
//        anything else                                  -> same ID at both revisions
//   2. sp800-53r4-appj-to-r5-comparison.xlsx — Rev 4 Appendix J privacy controls
//      (AP/AR/DI/DM/IP/SE/TR/UL) with Rev 5 successor pointers. NIST labels these
//      pointers, not equivalences, so their relation is "pointer".
//
// Identity is implicit: a control present in both rosters translates to itself.
// Edges exist only for non-identity cases. Family-level incorporation ("SR family")
// stays a marker and is never expanded into member controls — expansion would invent
// specificity NIST didn't publish.

import { readFileSync, writeFileSync } from 'node:fs';
import { inflateRawSync } from 'node:zlib';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO = join(__dirname, '..', '..');
const OUT_FILES = [
  join(REPO, 'hdf-mappings', 'go', 'nist', 'nist-revision-crosswalk.json'),
  join(REPO, 'hdf-mappings', 'src', 'data', 'nist-revision-crosswalk.json'),
];

const SOURCES = {
  comparison:
    'https://csrc.nist.gov/files/pubs/sp/800/53/r5/upd1/final/docs/sp800-53r4-to-r5-comparison-workbook.xlsx',
  appendixJ:
    'https://csrc.nist.gov/files/pubs/sp/800/53/r5/upd1/final/docs/sp800-53r4-appj-to-r5-comparison.xlsx',
};

const CONTROL_ID = /^[A-Z]{2}-\d+(?:\(\d+\))?$/;
// A control reference in prose; optional trailing statement letter ("AC-2k").
const CONTROL_REF = /([A-Z]{2}-\d+(?:\(\d+\))?)([a-z])?(?![\w(])/g;

async function fetchBuffer(url) {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`fetch ${url}: HTTP ${res.status}`);
  return Buffer.from(await res.arrayBuffer());
}

// --- minimal xlsx (zip + worksheet XML) reader; no dependencies ---

function zipEntries(buf) {
  // End-of-central-directory record: scan backward for its signature.
  let eocd = -1;
  for (let i = buf.length - 22; i >= 0; i--) {
    if (buf.readUInt32LE(i) === 0x06054b50) {
      eocd = i;
      break;
    }
  }
  if (eocd < 0) throw new Error('not a zip: EOCD signature not found');
  const count = buf.readUInt16LE(eocd + 10);
  let off = buf.readUInt32LE(eocd + 16);
  const entries = new Map();
  for (let i = 0; i < count; i++) {
    if (buf.readUInt32LE(off) !== 0x02014b50) throw new Error('bad central directory entry');
    const method = buf.readUInt16LE(off + 10);
    const csize = buf.readUInt32LE(off + 20);
    const nameLen = buf.readUInt16LE(off + 28);
    const extraLen = buf.readUInt16LE(off + 30);
    const commentLen = buf.readUInt16LE(off + 32);
    const localOff = buf.readUInt32LE(off + 42);
    const name = buf.toString('utf8', off + 46, off + 46 + nameLen);
    // Local header repeats name/extra lengths; data starts after them.
    const lNameLen = buf.readUInt16LE(localOff + 26);
    const lExtraLen = buf.readUInt16LE(localOff + 28);
    const dataStart = localOff + 30 + lNameLen + lExtraLen;
    const raw = buf.subarray(dataStart, dataStart + csize);
    entries.set(name, { method, raw });
    off += 46 + nameLen + extraLen + commentLen;
  }
  return entries;
}

function zipRead(entries, name) {
  const e = entries.get(name);
  if (!e) throw new Error(`zip entry not found: ${name}`);
  return (e.method === 8 ? inflateRawSync(e.raw) : Buffer.from(e.raw)).toString('utf8');
}

function decodeEntities(s) {
  return s
    .replace(/&#x([0-9a-fA-F]+);/g, (_, h) => String.fromCodePoint(parseInt(h, 16)))
    .replace(/&#(\d+);/g, (_, d) => String.fromCodePoint(Number(d)))
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'")
    .replace(/&amp;/g, '&');
}

function textRuns(xml) {
  let out = '';
  for (const m of xml.matchAll(/<t(?:\s[^>]*)?>([\s\S]*?)<\/t>/g)) out += decodeEntities(m[1]);
  return out;
}

function sheetByName(entries, wanted) {
  const wb = zipRead(entries, 'xl/workbook.xml');
  const rels = zipRead(entries, 'xl/_rels/workbook.xml.rels');
  const relTarget = new Map();
  for (const m of rels.matchAll(/<Relationship\s[^>]*Id="([^"]+)"[^>]*Target="([^"]+)"/g)) {
    relTarget.set(m[1], m[2].replace(/^\//, ''));
  }
  for (const m of wb.matchAll(/<sheet\s[^>]*name="([^"]+)"[^>]*r:id="([^"]+)"/g)) {
    if (decodeEntities(m[1]) === wanted) {
      const target = relTarget.get(m[2]);
      return zipRead(entries, target.startsWith('xl/') ? target : `xl/${target}`);
    }
  }
  throw new Error(`sheet not found: ${wanted}`);
}

// Returns rows as maps of column letter -> cell text.
function parseRows(sheetXml, shared) {
  const rows = [];
  for (const rowMatch of sheetXml.matchAll(/<row\b[^>]*>([\s\S]*?)<\/row>/g)) {
    const cells = {};
    for (const c of rowMatch[1].matchAll(/<c\b([^>]*?)(?:\/>|>([\s\S]*?)<\/c>)/g)) {
      const attrs = c[1];
      const body = c[2] ?? '';
      const ref = /r="([A-Z]+)\d+"/.exec(attrs)?.[1];
      if (!ref) continue;
      const type = /t="([^"]+)"/.exec(attrs)?.[1];
      let value = '';
      if (type === 'inlineStr') {
        value = textRuns(body);
      } else {
        const v = /<v>([\s\S]*?)<\/v>/.exec(body)?.[1] ?? '';
        value = type === 's' ? shared[Number(v)] : decodeEntities(v);
      }
      cells[ref] = value;
    }
    rows.push(cells);
  }
  return rows;
}

function readWorkbookSheet(buf, sheetName) {
  const entries = zipEntries(buf);
  const shared = [];
  if (entries.has('xl/sharedStrings.xml')) {
    const ss = zipRead(entries, 'xl/sharedStrings.xml');
    for (const si of ss.matchAll(/<si(?:\s[^>]*)?>([\s\S]*?)<\/si>/g)) shared.push(textRuns(si[1]));
  }
  return parseRows(sheetByName(entries, sheetName), shared);
}

// --- derivation ---

const norm = (s) => (s ?? '').replace(/\s+/g, ' ').trim();

// "AC-02-10"-style key: family, padded control number, padded enhancement.
function sortKey(id) {
  const m = /^([A-Z]{2})-(\d+)(?:\((\d+)\))?$/.exec(id);
  if (!m) return id;
  return `${m[1]}-${m[2].padStart(3, '0')}-${(m[3] ?? '0').padStart(3, '0')}`;
}
const byControl = (a, b) => (sortKey(a) < sortKey(b) ? -1 : sortKey(a) > sortKey(b) ? 1 : 0);

// Extract successor control IDs from NIST prose; statement-letter references
// ("AC-2k") normalize to the base control. Returns sorted unique IDs.
function refsIn(text) {
  const ids = new Set();
  for (const m of text.matchAll(CONTROL_REF)) ids.add(m[1]);
  return [...ids].sort(byControl);
}

function relationOf(detail) {
  if (/moved to/i.test(detail)) return 'moved';
  if (/incorporated into/i.test(detail)) return 'incorporated';
  return 'none';
}

function deriveComparison(rows) {
  const carried = [];
  const newR5 = [];
  const edges = [];
  const bothRevRedirects = new Set();
  for (const cells of rows) {
    const id = norm(cells.A);
    if (!CONTROL_ID.test(id)) continue;
    const notation = norm(cells.H);
    const detail = norm(cells.I);
    if (/^Previously withdrawn in Rev4/i.test(detail)) {
      // Valid at neither revision; redirect from both directions.
      bothRevRedirects.add(id);
      const targets = refsIn(detail.replace(/^Previously withdrawn in Rev4;?/i, ''));
      for (const from of [4, 5]) {
        edges.push({ from, control: id, targets, relation: relationOf(detail), detail });
      }
    } else if (/\bWithdrawn\b/.test(notation)) {
      const famMatch = /incorporated into ([A-Z]{2}) family/i.exec(detail);
      if (famMatch) {
        edges.push({ from: 4, control: id, targets: [], relation: 'family', family: famMatch[1], detail });
      } else {
        const targets = refsIn(detail);
        edges.push({ from: 4, control: id, targets, relation: targets.length ? relationOf(detail) : 'none', detail });
      }
    } else if (/New base control|New control enhancement/.test(notation)) {
      newR5.push(id);
    } else {
      carried.push(id);
    }
  }
  return { carried, newR5, edges, bothRevRedirects };
}

function deriveAppendixJ(rows) {
  const r4Controls = [];
  const edges = [];
  for (const cells of rows) {
    const idMatch = /^([A-Z]{2}-\d+(?:\(\d+\))?):/.exec(norm(cells.A));
    if (!idMatch) continue;
    const id = idMatch[1];
    r4Controls.push(id);
    const targets = [];
    for (const line of (cells.B ?? '').split('\n')) {
      const t = /^([A-Z]{2}-\d+(?:\(\d+\))?):/.exec(line.trim());
      if (t) targets.push(t[1]);
    }
    targets.sort(byControl);
    edges.push({
      from: 4,
      control: id,
      targets,
      relation: targets.length ? 'pointer' : 'none',
      detail: norm(cells.B),
    });
  }
  return { r4Controls, edges };
}

async function generate() {
  const [cmpBuf, appjBuf] = await Promise.all([
    fetchBuffer(SOURCES.comparison),
    fetchBuffer(SOURCES.appendixJ),
  ]);
  const cmp = deriveComparison(readWorkbookSheet(cmpBuf, 'Rev4 Rev5 Compared'));
  const appj = deriveAppendixJ(readWorkbookSheet(appjBuf, 'SP 800-53 Rev 4 App J to Rev 5'));

  const withdrawnR4 = cmp.edges
    .filter((e) => e.from === 4 && !cmp.bothRevRedirects.has(e.control))
    .map((e) => e.control);
  const roster4 = [...new Set([...cmp.carried, ...withdrawnR4, ...appj.r4Controls])].sort(byControl);
  const roster5 = [...new Set([...cmp.carried, ...cmp.newR5])].sort(byControl);
  const in4 = new Set(roster4);
  const in5 = new Set(roster5);

  // Rev5->Rev4 origins: invert redirect edges whose target is new in Rev 5.
  // Both-rev redirects ("previously withdrawn") only ever target carried controls
  // and are excluded from inversion (their targets are valid at Rev 4 already).
  const origins = new Map();
  for (const e of [...cmp.edges, ...appj.edges]) {
    if (e.from !== 4 || cmp.bothRevRedirects.has(e.control)) continue;
    for (const t of e.targets) {
      if (in4.has(t)) continue;
      if (!origins.has(t)) origins.set(t, { controls: [], relations: new Set() });
      const o = origins.get(t);
      o.controls.push(e.control);
      o.relations.add(e.relation);
    }
  }
  const rev5Edges = cmp.newR5.map((id) => {
    const o = origins.get(id);
    if (!o) return { from: 5, control: id, targets: [], relation: 'none', detail: 'New in Rev 5' };
    const rels = o.relations;
    const relation = rels.size === 1 ? [...rels][0] : 'incorporated';
    return { from: 5, control: id, targets: o.controls.sort(byControl), relation, detail: 'New in Rev 5' };
  });

  // One Rev 4 withdrawal ("PL-5 -> App J control AR-2") targets an Appendix J
  // control that itself exists only at Rev 4: resolve such targets one step
  // through the Appendix J pointer so the Rev 5 direction lands on real
  // Rev 5 controls.
  const appjTargets = new Map(appj.edges.map((e) => [e.control, e.targets]));
  for (const e of cmp.edges) {
    if (e.from !== 4) continue;
    if (e.targets.some((t) => !in5.has(t) && appjTargets.has(t))) {
      e.targets = [
        ...new Set(e.targets.flatMap((t) => (!in5.has(t) && appjTargets.has(t) ? appjTargets.get(t) : [t]))),
      ].sort(byControl);
    }
  }

  const edges = [...cmp.edges, ...appj.edges, ...rev5Edges].sort(
    (a, b) => a.from - b.from || byControl(a.control, b.control)
  );

  // Validation: every redirect target must be a valid control at the destination
  // revision; wrong targets here would silently fabricate NIST mappings downstream.
  const problems = [];
  for (const e of edges) {
    const dest = e.from === 4 ? in5 : in4;
    for (const t of e.targets) {
      if (!dest.has(t)) problems.push(`${e.control} (from rev ${e.from}) -> ${t}: target not in destination roster`);
    }
  }
  if (roster5.length < 1000) problems.push(`rev 5 roster suspiciously small: ${roster5.length}`);
  if (roster4.length < 850) problems.push(`rev 4 roster suspiciously small: ${roster4.length}`);
  if (problems.length) {
    throw new Error(`crosswalk validation failed:\n  ${problems.join('\n  ')}`);
  }

  return {
    $comment:
      'Generated by hdf-mappings/scripts/generate-nist-crosswalk.mjs from NIST SP 800-53 comparison workbooks. Do not hand-edit; rerun the script. Identity is implicit: controls present in both rosters translate to themselves; edges cover only non-identity cases.',
    sources: [SOURCES.comparison, SOURCES.appendixJ],
    rosters: { 4: roster4, 5: roster5 },
    edges,
  };
}

const data = await generate();
const json = `${JSON.stringify(data, null, 2)}\n`;

const checkOnly = process.argv.includes('--check');
let drift = false;
for (const file of OUT_FILES) {
  let current = null;
  try {
    current = readFileSync(file, 'utf8');
  } catch {
    // missing counts as drift
  }
  if (current !== json) {
    drift = true;
    if (!checkOnly) writeFileSync(file, json);
    console.log(`${checkOnly ? 'DRIFT' : 'wrote'}: ${file}`);
  }
}

const e4 = data.edges.filter((e) => e.from === 4).length;
const e5 = data.edges.filter((e) => e.from === 5).length;
console.log(
  `rosters: rev4=${data.rosters[4].length} rev5=${data.rosters[5].length}; edges: rev4->5=${e4} rev5->4=${e5}`
);
if (checkOnly) {
  if (drift) {
    console.error('crosswalk drift detected; run: node scripts/generate-nist-crosswalk.mjs');
    process.exit(1);
  }
  console.log('crosswalk up to date');
}
