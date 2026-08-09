#!/usr/bin/env node
/**
 * Timestamp-handling guard for the HDF Go code that parses tool timestamps.
 *
 * Go code must parse tool-supplied timestamps via `hdfutil.ParseTimestamp`
 * (which normalizes to UTC), NOT a bare `time.Parse(time.RFC3339...)`. A bare
 * RFC3339 parse preserves the source offset and diverges from the (UTC)
 * TypeScript peer; ParseTimestamp also covers more formats. Custom-layout
 * `time.Parse("<layout>", ...)` calls are allowed — they handle formats
 * ParseTimestamp does not. A genuine non-footgun use (e.g. a format-only check
 * that discards the parse result) opts out with a `timestamp-guard:allow`
 * marker on the offending line or the line directly above it.
 *
 * Scans (recursively) the converters' Go dirs, hdf-converters/shared/go, and
 * the other Go modules that parse timestamps: hdf-diff/go, hdf-cli, and
 * hdf-utilities/go. Mirrors the TypeScript `no-restricted-syntax` guard shared
 * via scripts/eslint-timestamp-guard.mjs. See
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
    if (e.name === 'node_modules' || e.name === 'dist' || e.name === '.git') continue;
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
// The same footgun exists wherever HDF Go code parses timestamps: the diff
// engine, the CLI, and hdf-utilities (which also carries the Go peers of the
// shared parse helpers). Scan them too so the class cannot regrow.
files.push(...goFilesUnder(join(root, 'hdf-diff', 'go')));
files.push(...goFilesUnder(join(root, 'hdf-cli')));
files.push(...goFilesUnder(join(root, 'hdf-utilities', 'go')));

// A justified exception carries a `timestamp-guard:allow` marker (with a reason)
// on the offending line or the line directly above it — for genuine non-footgun
// uses such as a format-validation check that DISCARDS the parse result rather
// than parsing a tool timestamp for use. This is a reason-bearing, guard-
// specific opt-out, not a blanket nolint.
const ALLOW_MARKER = 'timestamp-guard:allow';

const offenders = [];
for (const path of files) {
  const content = readFileSync(path, 'utf8');
  const lines = content.split('\n');
  for (const match of content.matchAll(FORBIDDEN)) {
    const lineNo = content.slice(0, match.index).split('\n').length; // 1-indexed
    const thisLine = lines[lineNo - 1] ?? '';
    const prevLine = lines[lineNo - 2] ?? '';
    if (thisLine.includes(ALLOW_MARKER) || prevLine.includes(ALLOW_MARKER)) continue;
    const snippet = content.slice(match.index, match.index + 60).replace(/\s+/g, ' ').trim();
    offenders.push(`${path}:${lineNo}: ${snippet}`);
  }
}

if (offenders.length > 0) {
  console.error(
    '\nTimestamp guard FAILED: HDF Go code must use hdfutil.ParseTimestamp,\n' +
      'not a bare time.Parse(time.RFC3339...). ParseTimestamp normalizes to UTC\n' +
      'so output matches the TypeScript peer and is host-independent. A genuine\n' +
      'non-footgun use can opt out with a timestamp-guard:allow marker.\n' +
      'See site/docs/contributing/developer-guide.md (Timestamp Handling).\n',
  );
  for (const o of offenders) console.error('  ' + o);
  process.exit(1);
}

console.log('Timestamp guard: no bare time.Parse(time.RFC3339) in the scanned HDF Go modules. OK');
