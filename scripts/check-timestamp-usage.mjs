#!/usr/bin/env node
/**
 * Timestamp-handling guard for Go converters.
 *
 * A `*-to-hdf` converter must parse tool-supplied timestamps via
 * `hdfutil.ParseTimestamp` (which normalizes to UTC), NOT a bare
 * `time.Parse(time.RFC3339...)`. A bare RFC3339 parse preserves the source
 * offset and diverges from the (UTC) TypeScript converter; ParseTimestamp also
 * covers more formats. Custom-layout `time.Parse("<layout>", ...)` calls are
 * allowed — they handle formats ParseTimestamp does not.
 *
 * The TypeScript side is guarded by the `no-restricted-syntax` rule in
 * hdf-converters/eslint.config.js. See
 * site/docs/contributing/developer-guide.md (Timestamp Handling).
 */
import { readdirSync, readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const convertersDir = join(root, 'hdf-converters', 'converters');

// Bare RFC3339 / RFC3339Nano parse — should be hdfutil.ParseTimestamp.
// `g` flag + whole-file scan so a call wrapped across lines
// (e.g. `time.Parse(\n  time.RFC3339, ...)`) is still detected — \s* spans newlines.
// Matches both time.Parse(...) and time.ParseInLocation(...) on an RFC3339 layout.
const FORBIDDEN = /time\.Parse(InLocation)?\(\s*time\.RFC3339/g;

const offenders = [];
for (const conv of readdirSync(convertersDir, { withFileTypes: true })) {
  if (!conv.isDirectory()) continue;
  const goDir = join(convertersDir, conv.name, 'go');
  let entries;
  try {
    entries = readdirSync(goDir);
  } catch {
    continue; // converter has no Go implementation
  }
  for (const file of entries) {
    if (!file.endsWith('.go') || file.endsWith('_test.go')) continue;
    const path = join(goDir, file);
    const content = readFileSync(path, 'utf8');
    for (const match of content.matchAll(FORBIDDEN)) {
      const line = content.slice(0, match.index).split('\n').length;
      const snippet = content.slice(match.index, match.index + 60).replace(/\s+/g, ' ').trim();
      offenders.push(`${path}:${line}: ${snippet}`);
    }
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

console.log('Timestamp guard: no bare time.Parse(time.RFC3339) in Go converters. OK');
