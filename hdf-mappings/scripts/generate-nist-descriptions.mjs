// Regenerates the NIST SP 800-53 Rev 5 control descriptions
// (src/data/nist-descriptions-rev5.json) from NIST's own machine-readable OSCAL
// catalog. Run it, review the diff, commit the JSON.
//
//   node scripts/generate-nist-descriptions.mjs          # regenerate
//   node scripts/generate-nist-descriptions.mjs --check  # fail on drift (CI)
//
// Source (NIST-published, machine-readable):
//   usnistgov/oscal-content — SP 800-53 Rev 5 catalog JSON.
//
// Output format matches the existing Rev 4 file (nist-descriptions.json): a flat
// map of HDF-style key -> text.
//   - Keys: base controls ("AC-02"), enhancements ("AC-02 01"), and statement
//     items ("AC-02 a", "AC-02 07 a", "AC-02 h 01"). Numbers are zero-padded to
//     two digits; guidance and assessment objectives are excluded (Rev 4 parity).
//   - A control/enhancement whose statement has lettered items keys the TITLE and
//     emits the items separately; one whose statement is a single prose block
//     keys that PROSE (this is the Rev 4 convention — enhancements without items,
//     e.g. "AC-02 01", carry their statement text directly).
//   - Titles are the Rev 5 form as published (title case — Rev 5 renamed many
//     "... POLICY AND PROCEDURES" controls to "Policy and Procedures").
//   - OSCAL parameter placeholders are resolved to the canonical
//     "[Assignment: ...]" / "[Selection: ...]" bracket form.
//   - Controls NIST withdrew in Rev 5 (title-only "withdrawn" stubs) are excluded.

import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO = join(__dirname, '..', '..');
const OUT_FILE = join(REPO, 'hdf-mappings', 'src', 'data', 'nist-descriptions-rev5.json');
const SOURCE =
  'https://raw.githubusercontent.com/usnistgov/oscal-content/main/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json';

// OSCAL base-control id "ac-2" -> HDF "AC-02". Non-base ids (enhancements like
// "ac-2.1", or odd ids) return null.
function hdfBaseId(oscalId) {
  const m = /^([a-z]{2})-(\d+)$/.exec(oscalId);
  return m ? `${m[1].toUpperCase()}-${m[2].padStart(2, '0')}` : null;
}

// Enhancement key: ("AC-02", "ac-2.1") -> "AC-02 01".
function hdfEnhancementKey(baseHdf, enhOscalId) {
  const n = enhOscalId.split('.').pop();
  return `${baseHdf} ${n.padStart(2, '0')}`;
}

// Statement-item id -> HDF suffix relative to its owner control/enhancement:
// ("ac-2_smt.a", "ac-2") -> "a"; ("ac-2.7_smt.a", "ac-2.7") -> "a";
// ("ac-2_smt.h.1", "ac-2") -> "h 01". Letters kept, numbers zero-padded.
function statementSuffix(itemId, ownerOscalId) {
  const prefix = `${ownerOscalId}_smt.`;
  if (!itemId.startsWith(prefix)) return null;
  return itemId
    .slice(prefix.length)
    .split('.')
    .map((seg) => (/^\d+$/.test(seg) ? seg.padStart(2, '0') : seg))
    .join(' ');
}

function renderParam(param) {
  if (!param) return '[Assignment]';
  if (param.select) {
    const hm = param.select['how-many'];
    const q = hm === 'one-or-more' ? ' (one or more)' : hm === 'one' ? ' (one)' : '';
    return `[Selection${q}: ${(param.select.choice || []).join('; ')}]`;
  }
  return param.label ? `[Assignment: ${param.label}]` : '[Assignment]';
}

function renderProse(prose, paramById) {
  if (!prose) return '';
  return prose
    .replace(/\{\{\s*insert:\s*param,\s*([\w.-]+)\s*\}\}/g, (_, id) => renderParam(paramById.get(id)))
    .replace(/\s+/g, ' ')
    .trim();
}

// A withdrawn control is a title-only OSCAL stub; it is not a Rev 5 control.
function isWithdrawn(control) {
  return (control.props || []).some((p) => p.name === 'status' && p.value === 'withdrawn');
}

function collectItems(item, ownerOscalId, hdfKey, paramById, out) {
  const suffix = statementSuffix(item.id || '', ownerOscalId);
  const text = renderProse(item.prose, paramById);
  if (suffix && text) out[`${hdfKey} ${suffix}`] = text;
  for (const sub of item.parts || []) {
    collectItems(sub, ownerOscalId, hdfKey, paramById, out);
  }
}

// Emit one control or enhancement under hdfKey, then recurse into enhancements.
function emit(control, hdfKey, out) {
  const paramById = new Map((control.params || []).map((p) => [p.id, p]));
  const statement = (control.parts || []).find((p) => p.name === 'statement');
  const items = statement?.parts || [];

  if (items.length > 0) {
    out[hdfKey] = control.title; // title at the key; items carry the prose
    for (const item of items) collectItems(item, control.id, hdfKey, paramById, out);
  } else if (statement && statement.prose) {
    out[hdfKey] = renderProse(statement.prose, paramById); // single-statement prose
  } else {
    out[hdfKey] = control.title; // title-only
  }

  for (const enh of control.controls || []) {
    if (!isWithdrawn(enh)) emit(enh, hdfEnhancementKey(hdfKey, enh.id), out);
  }
}

function extract(catalog) {
  const out = {};
  for (const group of catalog.groups || []) {
    for (const control of group.controls || []) {
      const base = hdfBaseId(control.id);
      if (base && !isWithdrawn(control)) emit(control, base, out);
    }
  }
  return out;
}

async function main() {
  const res = await fetch(SOURCE);
  if (!res.ok) throw new Error(`fetch ${SOURCE}: HTTP ${res.status}`);
  const { catalog } = await res.json();

  const data = extract(catalog);
  const sorted = {};
  for (const k of Object.keys(data).sort()) sorted[k] = data[k];
  const json = JSON.stringify(sorted, null, 2) + '\n';

  const checkOnly = process.argv.includes('--check');
  let current = null;
  try {
    current = readFileSync(OUT_FILE, 'utf8');
  } catch {
    /* missing counts as drift */
  }
  const drift = current !== json;
  if (drift && !checkOnly) writeFileSync(OUT_FILE, json);

  const controls = Object.keys(sorted).filter((k) => !k.includes(' ')).length;
  const families = new Set(Object.keys(sorted).map((k) => k.slice(0, 2))).size;
  console.log(
    `${drift ? (checkOnly ? 'DRIFT' : 'wrote') : 'clean'}: ${OUT_FILE}\n` +
      `entries=${Object.keys(sorted).length} controls+enhancements=${controls} families=${families}`
  );
  if (checkOnly && drift) {
    console.error('descriptions drift detected; run: node scripts/generate-nist-descriptions.mjs');
    process.exit(1);
  }
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
