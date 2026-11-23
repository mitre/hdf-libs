#!/usr/bin/env node
// Regenerates cci-mappings.json from DISA's CCI list (U_CCI_List.zip, unzipped):
//
//   node scripts/generate-cci-mappings.mjs <path/to/U_CCI_List.xml> [--check]
//
// --check exits 1 if regenerating from that file would change the table. Each item
// keeps its definition and DISA's Rev 4 and Rev 5 references exactly as published,
// or its Rev 3 references when DISA gives neither, so a referenced item is not left
// without one; 800-53A is dropped, deprecated items kept, and a reference that is not
// an 800-53 control identifier is printed and rejected, never repaired (a Rev 3 one
// keeps its leading control). Provenance: hdf-mappings/README.md.

import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const OUT = join(__dirname, '..', 'go', 'datasets', 'mappings', 'cci-mappings.json');

const REVISIONS = ['3', '4', '5'];

// Family-number, an optional enhancement, then statement parts ("a", "1",
// "(a)"), space-separated as DISA writes them. Mirrored by the dataset tests.
const CONTROL_IDENTIFIER = /^[A-Z]{2}-\d+(?: \(\d+\))?(?: (?:[a-z]{1,2}|\d+|\([a-z0-9]+\)))*$/;

// The control or enhancement a reference starts with, followed by a space.
const REV3_LEAD = /^[A-Z]{2}-\d+(?: \(\d+\))?(?= )/;

const ENTITIES = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'" };

function decode(s) {
  return s.replace(/&(?:#(\d+)|#x([0-9a-fA-F]+)|(amp|lt|gt|quot|apos));/g, (_, dec, hex, name) =>
    name ? ENTITIES[name] : String.fromCodePoint(Number.parseInt(dec ?? hex, dec ? 10 : 16)),
  );
}

function attrs(tag) {
  const out = {};
  for (const m of tag.matchAll(/(\w+)="([^"]*)"/g)) out[m[1]] = decode(m[2]);
  return out;
}

// One child element's text; the list's children are flat text elements.
function child(body, name, id) {
  const all = [...body.matchAll(new RegExp(`<${name}>([^<]*)</${name}>|<${name}\\s*/>`, 'g'))];
  if (all.length > 1) throw new Error(`${id}: ${all.length} <${name}> elements`);
  return all.length ? decode(all[0][1] ?? '') : undefined;
}

export function parseCciList(xml) {
  const version = child(xml.slice(0, xml.indexOf('<cci_items>')), 'version', 'metadata');
  const items = [...xml.matchAll(/<cci_item id="([^"]+)">([\s\S]*?)<\/cci_item>/g)];
  const opened = (xml.match(/<cci_item[\s>]/g) ?? []).length;
  if (items.length !== opened) throw new Error(`parsed ${items.length} cci_item elements of ${opened}`);

  const table = {};
  const rejected = [];
  const reduced = [];
  const statuses = {};
  for (const [, id, body] of items) {
    if (id in table) throw new Error(`${id}: duplicate cci_item`);
    const status = child(body, 'status', id) ?? '';
    statuses[status] = (statuses[status] ?? 0) + 1;
    const nist = {};
    for (const m of body.matchAll(/<reference\s[^>]*\/>/g)) {
      const ref = attrs(m[0]);
      if (ref.creator !== 'NIST' || !REVISIONS.includes(ref.version) || ref.title?.endsWith('53A')) continue;
      let index = ref.index;
      if (!CONTROL_IDENTIFIER.test(index)) {
        // A Rev 3 reference is read as its control or enhancement only, so one
        // with malformed statement parts keeps that leading identifier.
        const lead = ref.version === '3' ? REV3_LEAD.exec(index)?.[0] : undefined;
        if (!lead) {
          rejected.push(`${id} Rev ${ref.version}: ${JSON.stringify(ref.index)}`);
          continue;
        }
        reduced.push(`${id} Rev 3: ${JSON.stringify(ref.index)} kept as ${JSON.stringify(lead)}`);
        index = lead;
      }
      const list = (nist[ref.version] ??= []);
      if (!list.includes(index)) list.push(index);
    }
    // Rev 3 is the fallback only: an item with a later reference does not carry it.
    if (nist['4'] || nist['5']) delete nist['3'];
    table[id] = { def: child(body, 'definition', id) ?? '', nist };
  }
  return { version, table, rejected, reduced, statuses };
}

function serialize(table) {
  const sorted = Object.fromEntries(Object.keys(table).sort().map((k) => [k, table[k]]));
  return `${JSON.stringify(sorted, null, 2)}\n`;
}

function main() {
  const args = process.argv.slice(2);
  const check = args.includes('--check');
  const input = args.find((a) => !a.startsWith('--'));
  if (!input) {
    console.error('usage: generate-cci-mappings.mjs <path/to/U_CCI_List.xml> [--check]');
    process.exit(2);
  }
  const bytes = readFileSync(input);
  const { version, table, rejected, reduced, statuses } = parseCciList(bytes.toString('utf8').replace(/^\uFEFF/, ''));
  const out = serialize(table);

  const ids = Object.keys(table);
  const at = (rev) => ids.filter((id) => table[id].nist[rev]).length;
  console.log(`CCI list version ${version}, sha256 ${createHash('sha256').update(bytes).digest('hex')}`);
  console.log(`${ids.length} items; statuses ${JSON.stringify(statuses)}`);
  console.log(`with Rev 5 references: ${at('5')}; with Rev 4: ${at('4')}; Rev 3 only: ${at('3')}; with none: ${ids.filter((id) => !Object.keys(table[id].nist).length).length}`);
  for (const r of rejected) console.log(`rejected (not an 800-53 control identifier): ${r}`);
  for (const r of reduced) console.log(`malformed statement parts: ${r}`);

  if (check) {
    const current = readFileSync(OUT, 'utf8');
    if (current !== out) {
      console.error('cci-mappings.json is out of date; rerun without --check');
      process.exit(1);
    }
    console.log('cci-mappings.json is current');
    return;
  }
  writeFileSync(OUT, out);
  console.log(`wrote ${OUT}`);
}

if (process.argv[1] === fileURLToPath(import.meta.url)) main();
