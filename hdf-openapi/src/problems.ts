import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parse as parseYaml } from 'yaml';

const HERE = dirname(fileURLToPath(import.meta.url));

/** Who owns the condition: the mcperr taxonomy, ADR-0008 §3's conventions, or the service. */
export type ProblemOwner = 'taxonomy' | 'convention' | 'service';

export interface ProblemDoc {
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
    const keys = Object.keys(entry).sort().join(',');
    if (keys !== 'cause,owner,remedy,status') {
      throw new Error(`problems.yaml: ${type} declares ${keys}, expected cause,owner,remedy,status`);
    }
    if (typeof entry.status !== 'number' || entry.status < 400 || entry.status > 599) {
      throw new Error(`problems.yaml: ${type} has status ${String(entry.status)}, not a 4xx or 5xx`);
    }
    if (typeof entry.owner !== 'string' || !OWNERS.has(entry.owner)) {
      throw new Error(`problems.yaml: ${type} has owner ${String(entry.owner)}`);
    }
    for (const prose of ['cause', 'remedy'] as const) {
      if (typeof entry[prose] !== 'string' || (entry[prose] as string).trim() === '') {
        throw new Error(`problems.yaml: ${type} has no ${prose}`);
      }
    }
    out[type] = entry as unknown as ProblemDoc;
  }
  return out;
}
