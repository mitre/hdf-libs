#!/usr/bin/env node
//
// Guards the `overrides:` block in pnpm-workspace.yaml against the two ways a
// transitive-advisory pin rots.
//
// An EXACT target is the one that has actually bitten this repo: `fast-uri@<3.1.6`
// pinned the tree to 3.1.6, two advisories then named 3.1.6 itself, and because
// the pre-commit hook runs `pnpm audit`, every commit in the repo was blocked at
// once. `brace-expansion` pinned to 5.0.9 went the same way. A range target does
// not prevent that outright — pnpm reuses the lockfile's resolution, so the held
// version only moves on a re-resolve — but it makes the remedy `pnpm update`
// rather than an edit here, and it stops the pin itself naming the floor.
//
// An UNDOCUMENTED entry is the slower failure. Nobody can tell whether it is
// still load-bearing, so it survives every audit by default and the block grows.
//
// This guard FAILS CLOSED. Any line inside the block it cannot parse is an
// offender, because a line-based reader that silently skips what it does not
// recognise would report a file full of exact pins as clean.
//
// Inertness — a pin that protects nothing — is NOT checked here. The decisive
// test is whether removing the entry introduces an advisory, which needs a
// network re-resolve and would rewrite the lockfile; it belongs to the
// dependabot-cycle review the block's own comment prescribes.

import { readFile } from 'node:fs/promises';
import { realpathSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';

const RANGE_LEAD = /^[\^~><=*xX]/;

// A mapping line: optional quotes on either side, any indent, optional trailing
// comment. Deliberately permissive so that a spelling we do not expect is read
// and judged rather than skipped.
const MAPPING = /^(\s+)(?:"([^"]+)"|'([^']+)'|([^\s:#][^:#]*?))\s*:\s*(?:"([^"]*)"|'([^']*)'|([^\s#]+))\s*(?:#.*)?$/;

/**
 * Extracts the overrides entries, each with the comment block directly above
 * it, plus any line in the block that could not be read as an entry.
 */
export function parseOverrides(yamlText) {
  const lines = yamlText.split('\n');
  const start = lines.findIndex((l) => /^overrides:\s*$/.test(l));
  if (start === -1) return { entries: [], unparsed: [] };

  const entries = [];
  const unparsed = [];
  let pending = [];

  for (let i = start + 1; i < lines.length; i += 1) {
    const line = lines[i];
    if (line.trim() === '') {
      pending = [];
      continue;
    }
    // A non-indented line ends the block (the next top-level key).
    if (!/^\s/.test(line)) break;

    const comment = line.match(/^\s*#\s?(.*)$/);
    if (comment) {
      pending.push(comment[1].trim());
      continue;
    }

    const m = line.match(MAPPING);
    if (!m) {
      unparsed.push({ line: i + 1, text: line.trim() });
      pending = [];
      continue;
    }
    const key = m[2] ?? m[3] ?? m[4];
    const target = m[5] ?? m[6] ?? m[7];
    // Scoped names carry a leading @, so the separator is the LAST one.
    const at = key.lastIndexOf('@');
    if (at <= 0) {
      unparsed.push({ line: i + 1, text: line.trim() });
      pending = [];
      continue;
    }
    entries.push({
      pkg: key.slice(0, at),
      range: key.slice(at + 1),
      target,
      comment: pending.join(' ').trim(),
      line: i + 1,
    });
    pending = [];
  }
  return { entries, unparsed };
}

/** Applies both rules, plus the fail-closed rule for unreadable lines. */
export function checkOverrides({ entries, unparsed }) {
  const offenders = [];
  for (const entry of entries) {
    const reasons = [];
    if (!RANGE_LEAD.test(entry.target)) {
      reasons.push(
        `target "${entry.target}" is an exact version; use a range (e.g. "^${entry.target}") so a later patch in that major is reachable without an edit here`,
      );
    }
    if (entry.comment === '') {
      reasons.push('no comment above it saying what it holds back and what would let it go');
    }
    if (reasons.length > 0) {
      offenders.push({ ...entry, reason: reasons.join('; and ') });
    }
  }
  for (const line of unparsed) {
    offenders.push({
      pkg: '(unreadable)',
      range: '',
      target: '',
      line: line.line,
      reason: `cannot be read as an override entry: ${line.text} — the guard fails closed rather than skip a line it cannot judge`,
    });
  }
  return { offenders, checked: entries.length };
}

const WORKSPACE = join(fileURLToPath(new URL('../', import.meta.url)), 'pnpm-workspace.yaml');

// Compare resolved real paths, not the raw strings: a symlinked invocation path
// (os.tmpdir() reporting /var while the module resolves to /private/var, say)
// makes a string comparison silently false, and this script would then exit 0
// having checked nothing — a fail-open in the gate itself.
const invokedDirectly = (() => {
  if (!process.argv[1]) return false;
  try {
    return realpathSync(fileURLToPath(import.meta.url)) === realpathSync(process.argv[1]);
  } catch {
    return false;
  }
})();

if (invokedDirectly) {
  const parsed = parseOverrides(await readFile(WORKSPACE, 'utf8'));
  const { offenders, checked } = checkOverrides(parsed);
  if (offenders.length > 0) {
    console.error(`pnpm-workspace.yaml: ${offenders.length} override line(s) need attention\n`);
    for (const o of offenders) {
      console.error(`  pnpm-workspace.yaml:${o.line}  ${o.pkg}${o.range ? `@${o.range}` : ''}`);
      console.error(`    ${o.reason}\n`);
    }
    console.error('Procedure: site/docs/contributing/developer-guide.md -> Dependency Audit Overrides');
    process.exit(1);
  }
  console.log(`pnpm-workspace.yaml: ${checked} overrides, all range-targeted and documented`);
}
