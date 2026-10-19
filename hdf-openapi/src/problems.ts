import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parse as parseYaml } from 'yaml';

const HERE = dirname(fileURLToPath(import.meta.url));

/** Who owns the condition: the mcperr taxonomy, ADR-0008 §3's conventions, or the service. */
export type ProblemOwner = 'taxonomy' | 'convention' | 'service';

export interface ProblemDoc {
  /** The mcperr code this type maps, where one does (ADR-0010 §6). */
  code?: string;
  title: string;
  status: number;
  owner: ProblemOwner;
  cause: string;
  remedy: string;
}

const OWNERS = new Set<string>(['taxonomy', 'convention', 'service']);

/**
 * The site generator turns each key into a path segment, so a key that is not a bare
 * kebab-case name would write outside the pages directory. Also the shape RFC 9457 type
 * URIs are built from.
 */
const TYPE_NAME = /^[a-z][a-z0-9]*(-[a-z0-9]+)*$/;

/** Loads the problem-type documentation, refusing a malformed or incomplete entry. */
export function loadProblemDocs(file = join(HERE, 'problems.yaml')): Record<string, ProblemDoc> {
  const parsed = parseYaml(readFileSync(file, 'utf-8')) as Record<string, unknown> | null;
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error('problems.yaml did not parse to a mapping');
  }
  const out: Record<string, ProblemDoc> = {};
  for (const [type, value] of Object.entries(parsed)) {
    if (value === null || typeof value !== 'object' || Array.isArray(value)) {
      throw new Error(`problems.yaml: ${type} is not a mapping`);
    }
    if (!TYPE_NAME.test(type)) {
      throw new Error(`problems.yaml: ${JSON.stringify(type)} is not a problem type name`);
    }
    const entry = value as Record<string, unknown>;
    const required = ['cause', 'owner', 'remedy', 'status', 'title'];
    const keys = Object.keys(entry).sort();
    const unexpected = keys.filter((key) => !required.includes(key) && key !== 'code');
    const missing = required.filter((key) => !keys.includes(key));
    if (unexpected.length > 0 || missing.length > 0) {
      throw new Error(
        `problems.yaml: ${type} declares ${keys.join(',')}, expected ${required.join(',')} and an optional code`,
      );
    }
    if (entry.code !== undefined && (typeof entry.code !== 'string' || !/^[A-Z][A-Z_]*$/.test(entry.code))) {
      throw new Error(`problems.yaml: ${type} has code ${String(entry.code)}, which is not an mcperr code`);
    }
    if (typeof entry.status !== 'number' || entry.status < 400 || entry.status > 599) {
      throw new Error(`problems.yaml: ${type} has status ${String(entry.status)}, not a 4xx or 5xx`);
    }
    if (typeof entry.owner !== 'string' || !OWNERS.has(entry.owner)) {
      throw new Error(`problems.yaml: ${type} has owner ${String(entry.owner)}`);
    }
    for (const prose of ['cause', 'remedy', 'title'] as const) {
      if (typeof entry[prose] !== 'string' || (entry[prose] as string).trim() === '') {
        throw new Error(`problems.yaml: ${type} has no ${prose}`);
      }
    }
    out[type] = entry as unknown as ProblemDoc;
  }
  return out;
}

/** Where the hosted problem-type pages live, which every `type` value dereferences to. */
export const PROBLEM_BASE = 'https://mitre.github.io/hdf-libs/problems';

/**
 * ADR-0010 §6's code-to-status-and-type mapping, derived from problems.yaml rather than
 * restated beside it — §6 says the mapping exists exactly once, and that file is where.
 */
export function problemTypes(docs = loadProblemDocs()): Record<string, { status: number; type: string }> {
  const mapped: Record<string, { status: number; type: string }> = {};
  for (const [type, entry] of Object.entries(docs)) {
    if (entry.code !== undefined) mapped[entry.code] = { status: entry.status, type };
  }
  return mapped;
}

/**
 * The codes ADR-0010 §6 marks `never`. Recorded rather than silently dropped: each is a
 * `file`-adapter concern with no HTTP surface, and TRUNCATED is dead in the MCP too.
 */
export const UNMAPPED_CODES = [
  'CACHE_MISS',
  'OUTPUT_EXISTS',
  'PATH_DENIED',
  'WRITE_FAILED',
  'TRUNCATED',
];
