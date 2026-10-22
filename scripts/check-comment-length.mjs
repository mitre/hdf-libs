#!/usr/bin/env node
//
// Fails when a comment block or a comment line grows past the thresholds in
// scripts/comment-length.config.json, measured against a recorded baseline so
// existing comments are frozen rather than rewritten all at once.
//
// One config, two checkers. The doc comments in this repo come in matched Go and
// TypeScript pairs, so two rules with independently drifting semantics would
// diverge exactly where parity matters; scripts/comment-length/testdata/cases.json
// makes the two agree or fails a test.

import { readFile, writeFile, mkdtemp, readdir } from 'node:fs/promises';
import ts from 'typescript';
import { readFileSync, realpathSync } from 'node:fs';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';
import { join, relative, isAbsolute } from 'node:path';
import { tmpdir } from 'node:os';

const run = promisify(execFile);
const ROOT = fileURLToPath(new URL('../', import.meta.url));
const CONFIG = join(ROOT, 'scripts', 'comment-length.config.json');
const GO_CHECKER = join(ROOT, 'scripts', 'comment-length', 'main.go');

let configCache;
async function config() {
  configCache ??= JSON.parse(await readFile(CONFIG, 'utf8'));
  return configCache;
}

/** The three caps, from the shared config. Neither checker hard-codes them. */
export function thresholds() {
  const c = JSON.parse(readFileSync(CONFIG, 'utf8'));
  return { doc: c.doc, inline: c.inline, line: c.line };
}

// The TypeScript analogue of go/ast's Doc fields: the node kinds whose leading
// comment documents a declaration rather than annotating a statement.
const DECL_KINDS = new Set([
  ts.SyntaxKind.FunctionDeclaration, ts.SyntaxKind.ClassDeclaration,
  ts.SyntaxKind.InterfaceDeclaration, ts.SyntaxKind.TypeAliasDeclaration,
  ts.SyntaxKind.EnumDeclaration, ts.SyntaxKind.EnumMember,
  ts.SyntaxKind.ModuleDeclaration, ts.SyntaxKind.VariableStatement,
  ts.SyntaxKind.ImportDeclaration, ts.SyntaxKind.ImportEqualsDeclaration,
  ts.SyntaxKind.ExportDeclaration, ts.SyntaxKind.ExportAssignment,
  ts.SyntaxKind.MethodDeclaration, ts.SyntaxKind.MethodSignature,
  ts.SyntaxKind.PropertyDeclaration, ts.SyntaxKind.PropertySignature,
  ts.SyntaxKind.GetAccessor, ts.SyntaxKind.SetAccessor,
  ts.SyntaxKind.Constructor, ts.SyntaxKind.IndexSignature,
]);

/**
 * Comment groups in one TypeScript source, read through the parser — a raw
 * scanner reports a `//` inside a regex literal or a template substitution as a
 * comment, and this does not. A comment after code on the same line IS one.
 *
 * Grouping and doc-attachment follow go/ast: consecutive comments merge across
 * at most one newline, and a group is a declaration's doc only when it ends on
 * the line directly above it — not on the same line.
 */
export function commentGroups(source, fileName = 't.ts') {
  const sf = ts.createSourceFile(fileName, source, ts.ScriptTarget.Latest, true);

  // Comment ranges, collected per token so the parser decides what is trivia.
  const seen = new Map();
  const addRanges = (ranges) => {
    for (const r of ranges ?? []) {
      if (!seen.has(r.pos)) seen.set(r.pos, { start: r.pos, end: r.end, text: source.slice(r.pos, r.end) });
    }
  };
  const isJSDoc = (k) => k >= ts.SyntaxKind.FirstJSDocNode && k <= ts.SyntaxKind.LastJSDocNode;
  let firstCodeStart = source.length;
  const walkTokens = (node) => {
    if (isJSDoc(node.kind)) return;
    const kids = node.getChildren(sf);
    if (kids.length === 0) {
      const absent = node.pos === node.end;
      if (node.kind !== ts.SyntaxKind.EndOfFileToken && !absent) {
        firstCodeStart = Math.min(firstCodeStart, node.getStart(sf));
      }
      // JsxText's full start lies inside its own content, so trivia there is text.
      if (node.kind !== ts.SyntaxKind.JsxText) {
        addRanges(ts.getLeadingCommentRanges(source, node.getFullStart()));
        addRanges(ts.getTrailingCommentRanges(source, node.getEnd()));
      }
      return;
    }
    for (const k of kids) walkTokens(k);
  };
  walkTokens(sf);
  // A file of only comments has no token to hang them on.
  addRanges(ts.getLeadingCommentRanges(source, 0));

  const comments = [...seen.values()].sort((a, b) => a.start - b.start);

  const groups = [];
  for (const c of comments) {
    const prev = groups.at(-1);
    const gap = prev ? source.slice(prev.end, c.start) : null;
    if (prev && /^\s*$/.test(gap) && (gap.match(/\n/g) ?? []).length <= 1) {
      prev.comments.push(c);
      prev.end = c.end;
      continue;
    }
    groups.push({ comments: [c], start: c.start, end: c.end });
  }

  // Doc attachment, with go/ast's adjacency requirement: the group must end just
  // above the declaration. A blank line detaches it, and a detached run annotates
  // rather than documents.
  // Exactly one newline: the group must end on the line ABOVE. Zero would mean the
  // same line, which go/ast does not treat as a doc comment either.
  const adjacent = (from, to) => {
    const gap = source.slice(from, to);
    return /^\s*$/.test(gap) && (gap.match(/\n/g) ?? []).length === 1;
  };
  const docGroups = new Set();
  const visit = (node) => {
    if (DECL_KINDS.has(node.kind)) {
      const nodeStart = node.getStart(sf);
      for (const g of groups) {
        if (g.end <= nodeStart && adjacent(g.end, nodeStart)) docGroups.add(g);
      }
    }
    ts.forEachChild(node, visit);
  };
  ts.forEachChild(sf, visit);

  return groups.map((g) => {
    const lineOf = (pos) => sf.getLineAndCharacterOfPosition(pos).line + 1;
    // A shebang is trivia, not code, so a header below it is still a header.
    const isHeader = g.end <= firstCodeStart;
    const isDoc = isHeader || docGroups.has(g);
    const lines = g.comments.reduce((n, c) => n + (c.text.match(/\n/g) ?? []).length + 1, 0);
    return { start: lineOf(g.start), lines, isHeader, isDoc, comments: g.comments, lineOf };
  });
}

/** Violations in the named TypeScript files. */
export async function scanTypeScript(files) {
  const { doc, inline, line } = await config();
  const out = [];
  for (const file of files) {
    const source = await readFile(file, 'utf8');
    for (const g of commentGroups(source, file)) {
      const kind = g.isDoc ? 'doc' : 'inline';
      if (g.lines > (g.isDoc ? doc : inline)) out.push({ file, line: g.start, kind, count: g.lines });
      for (const c of g.comments) {
        // Measured from the comment's own first character, as go/ast reports it,
        // so an indented comment is not charged for its indentation.
        c.text.replace(/\r/g, '').split('\n').forEach((l, n) => {
          if ([...l].length > line) {
            out.push({ file, line: g.lineOf(c.start) + n, kind: 'line', count: [...l].length });
          }
        });
      }
    }
  }
  return out;
}

let goBinary;
async function buildGoChecker() {
  if (goBinary) return goBinary;
  const dir = await mkdtemp(join(realpathSync(tmpdir()), 'comment-length-'));
  goBinary = join(dir, 'comment-length');
  await run('go', ['build', '-o', goBinary, GO_CHECKER], { cwd: ROOT });
  return goBinary;
}

/** Violations in the named Go files, via go/ast — see main.go for why. */
export async function scanGo(files) {
  if (files.length === 0) return [];
  await config();
  const bin = await buildGoChecker();
  // One source for the numbers: the Go side reads the same file.
  const caps = ['-config', CONFIG];
  const out = [];
  // Chunked: the whole repo's paths do not fit on one command line.
  for (let i = 0; i < files.length; i += 300) {
    const { stdout } = await run(bin, [...caps, ...files.slice(i, i + 300)], {
      cwd: ROOT,
      maxBuffer: 64 * 1024 * 1024,
    });
    out.push(...JSON.parse(stdout));
  }
  return out;
}

// A generator's own marker. Hand-editing such a file is pointless, so its comment
// volume is not this check's business.
const GENERATED = /\b(?:DO NOT EDIT|Code generated by|@generated|autogenerated)\b/i;

/** Whether a source announces itself as generated, judged on its first lines. */
export function isGenerated(source) {
  return GENERATED.test(source.split('\n', 12).join('\n'));
}

const SKIP_DIR = new Set([
  'node_modules', 'dist', '.git', 'coverage', 'testdata', 'vendor',
  '.pnpm-store', '.beads', '.beads.backup-pre-recovery', '.agents', '.scratch',
  // Vendored rule corpora, deliberately full of unparseable snippets.
  '.semgrep-rules',
  '.husky', '.github', '.claude', '.vscode', '.idea',
]);

/** Every source the check judges: repo-relative, generated files already dropped. */
export async function sourceFiles(root = ROOT) {
  const out = [];
  async function walk(dir) {
    for (const e of await readdir(dir, { withFileTypes: true })) {
      if (e.isDirectory()) {
        if (SKIP_DIR.has(e.name)) continue;
        await walk(join(dir, e.name));
        continue;
      }
      const name = e.name;
      if (name.endsWith('.d.ts')) continue;
      if (!/\.(?:go|ts|tsx|mts|mjs)$/.test(name)) continue;
      const full = join(dir, name);
      if (isGenerated(await readFile(full, 'utf8'))) continue;
      out.push(relative(root, full));
    }
  }
  await walk(root);
  return out.sort();
}

/**
 * The ratchet. A file may carry the violations the baseline records and no more;
 * one the baseline does not mention may carry none.
 *
 * An allowlist entry drops a file out of the comparison and must say why — an
 * exemption nobody can justify is how the whole check stops meaning anything.
 */
export function judge(violations, baseline, allowlist, scanned) {
  const problems = [];
  const exempt = new Set();
  for (const entry of allowlist ?? []) {
    if (!entry?.reason || !String(entry.reason).trim()) {
      problems.push({ file: entry?.file ?? '(unnamed)', message: `allowlist entry for ${entry?.file ?? '(unnamed)'} has no reason; say why it is exempt or remove it` });
      continue;
    }
    if (scanned && !scanned.includes(entry.file)) {
      problems.push({ file: entry.file, message: `allowlist entry for ${entry.file} matches no scanned file; fix the path or remove it` });
      continue;
    }
    exempt.add(entry.file);
  }

  const counts = new Map();
  for (const v of violations) {
    if (exempt.has(v.file)) continue;
    counts.set(v.file, (counts.get(v.file) ?? 0) + 1);
  }

  const tightened = [];
  for (const [file, now] of [...counts].sort()) {
    const was = baseline?.[file];
    if (was === undefined) {
      problems.push({ file, message: `${file} is not in the baseline and has ${now} comment-length violation(s); shorten them` });
    } else if (now > was) {
      problems.push({ file, message: `${file} has ${now} comment-length violation(s), above its baseline of ${was}` });
    }
  }
  for (const [file, was] of Object.entries(baseline ?? {})) {
    if (exempt.has(file)) continue;
    const now = counts.get(file) ?? 0;
    if (now < was) tightened.push({ file, was, now });
  }
  return { problems, tightened: tightened.sort((a, b) => a.file.localeCompare(b.file)) };
}

const BASELINE = join(ROOT, 'scripts', 'comment-length-baseline.json');

/** A path as the baseline records it: relative to the repo root, forward slashes. */
export function repoRelative(file) {
  return relative(ROOT, isAbsolute(file) ? file : join(ROOT, file)).split('\\').join('/');
}

/** Scans every source and returns the violations, both languages. */
export async function scanAll() {
  const files = await sourceFiles();
  const abs = (f) => join(ROOT, f);
  const go = files.filter((f) => f.endsWith('.go')).map(abs);
  const ts = files.filter((f) => !f.endsWith('.go')).map(abs);
  const found = [...(await scanGo(go)), ...(await scanTypeScript(ts))];
  // Keyed repo-relative, so the baseline is portable between checkouts and carries
  // nobody's home directory. Both scanners are handed absolute paths.
  return found.map((v) => ({ ...v, file: repoRelative(v.file) }));
}

async function main(argv) {
  const update = argv.includes('--update-baseline');
  const violations = await scanAll();
  const counts = {};
  for (const v of violations) counts[v.file] = (counts[v.file] ?? 0) + 1;

  if (update) {
    const ordered = Object.fromEntries(Object.entries(counts).sort(([a], [b]) => a.localeCompare(b)));
    await writeFile(BASELINE, `${JSON.stringify(ordered, null, 2)}\n`);
    const total = Object.values(ordered).reduce((a, b) => a + b, 0);
    process.stdout.write(`comment-length: baseline recorded — ${Object.keys(ordered).length} files, ${total} violations\n`);
    return 0;
  }

  const { allowlist } = await config();
  const baseline = JSON.parse(await readFile(BASELINE, 'utf8'));
  const { problems, tightened } = judge(violations, baseline, allowlist, await sourceFiles());

  for (const p of problems) process.stderr.write(`comment-length: ${p.message}\n`);
  if (tightened.length > 0) {
    process.stdout.write(`comment-length: ${tightened.length} file(s) now below baseline — run \`pnpm lint:comments --update-baseline\` to tighten\n`);
  }
  if (problems.length > 0) {
    const { doc, inline, line } = thresholds();
    process.stderr.write(`comment-length: ${problems.length} problem(s). Caps: doc ${doc} lines, other comments ${inline}, any comment line ${line} chars.\n`);
    return 1;
  }
  process.stdout.write(`comment-length: ok — ${Object.keys(counts).length} file(s) at or below baseline\n`);
  return 0;
}

const invokedDirectly =
  process.argv[1] && realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url));
if (invokedDirectly) {
  process.exit(await main(process.argv.slice(2)));
}
