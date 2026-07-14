#!/usr/bin/env node
/**
 * Timestamp-handling guard for Go converters and shared converter code.
 *
 * A `*-to-hdf` converter must parse tool-supplied timestamps via
 * `hdfutil.ParseTimestamp` (which normalizes to UTC), NOT a bare
 * `time.Parse(time.RFC3339...)`. A bare RFC3339 parse preserves the source
 * offset and diverges from the (UTC) TypeScript converter; ParseTimestamp also
 * covers more formats. Custom-layout `time.Parse("<layout>", ...)` calls are
 * allowed — they handle formats ParseTimestamp does not.
 *
 * Scans each converter's Go dir AND hdf-converters/shared/go (recursively):
 * shared Go code (converterutil, exportmap, bom, checklist, vex) parses
 * timestamps on behalf of the converters and is equally exposed to the footgun.
 * Mirrors the TypeScript `no-restricted-syntax` guard in
 * hdf-converters/eslint.config.js, which covers converters/ and shared/. See
 * site/docs/contributing/developer-guide.md (Timestamp Handling).
 */
import { readdirSync, readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const convertersDir = join(root, 'hdf-converters', 'converters');
const sharedGoDir = join(root, 'hdf-converters', 'shared', 'go');

// Bare RFC3339 / RFC3339Nano parse — should be hdfutil.ParseTimestamp.
// `g` flag + whole-file scan so a call wrapped across lines
// (e.g. `time.Parse(\n  time.RFC3339, ...)`) is still detected — \s* spans newlines.
// Matches both time.Parse(...) and time.ParseInLocation(...) on an RFC3339 layout.
// `(Nano)?` is spelled out for readers only — the layout constant is matched
// unanchored, and RFC3339 is a prefix of RFC3339Nano, so RFC3339Nano is caught
// with or without it.
const FORBIDDEN = /time\.Parse(InLocation)?\(\s*time\.RFC3339(Nano)?/g;

// Recursively collect non-test .go files under a directory (missing dir -> none).
function goFilesUnder(dir) {
  const out = [];
  let entries;
  try {
    entries = readdirSync(dir, { withFileTypes: true });
  } catch {
    return out; // no such dir (e.g. converter has no Go implementation)
  }
  for (const e of entries) {
    const p = join(dir, e.name);
    if (e.isDirectory()) out.push(...goFilesUnder(p));
    else if (e.name.endsWith('.go') && !e.name.endsWith('_test.go')) out.push(p);
  }
  return out;
}

const files = [];
for (const conv of readdirSync(convertersDir, { withFileTypes: true })) {
  if (conv.isDirectory()) files.push(...goFilesUnder(join(convertersDir, conv.name, 'go')));
}
files.push(...goFilesUnder(sharedGoDir));

const offenders = [];
for (const path of files) {
  const content = readFileSync(path, 'utf8');
  for (const match of content.matchAll(FORBIDDEN)) {
    const line = content.slice(0, match.index).split('\n').length;
    const snippet = content.slice(match.index, match.index + 60).replace(/\s+/g, ' ').trim();
    offenders.push(`${path}:${line}: ${snippet}`);
  }
}

if (offenders.length > 0) {
  console.error(
    '\nTimestamp guard FAILED: Go converters must use hdfutil.ParseTimestamp,\n' +
      'not a bare time.Parse(time.RFC3339...). ParseTimestamp normalizes to UTC\n' +
      'so output matches the TypeScript converters and is host-independent.\n' +
      'See site/docs/contributing/developer-guide.md (Timestamp Handling).\n',
  );
  for (const o of offenders) console.error('  ' + o);
  process.exit(1);
}

console.log('Timestamp guard: no bare time.Parse(time.RFC3339) in Go converters or shared/go. OK');
