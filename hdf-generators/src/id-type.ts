import type { BaselineRequirement } from '@mitre/hdf-schema';

/**
 * Identifiers a control can be keyed on: the rule id the baseline carries, the
 * STIG group id (tags.gid) or the STIG id (tags.stig_id).
 */
const ID_TYPES = ['rule', 'group', 'version'] as const;

const ID_TYPE_TAG: Record<string, string> = { group: 'tags.gid', version: 'tags.stig_id' };

function tagString(req: BaselineRequirement, key: string): string {
  const v = req.tags?.[key];
  return typeof v === 'string' ? v.trim() : '';
}

function idOf(req: BaselineRequirement, idType: string): string {
  if (idType === 'group') return tagString(req, 'gid');
  if (idType === 'version') return tagString(req, 'stig_id');
  return req.id;
}

/**
 * The per-control file for id, with path separators and traversal removed so
 * no id can write outside controls/. Mirrors the Go controlFilename.
 */
export function controlFilename(id: string): string {
  const safe = id.replace(/\.\./g, '').replace(/[/\\]/g, '');
  return `controls/${safe || 'unknown'}.rb`;
}

/** Groups by key in first-seen order; describes each group of two or more. */
function duplicates(
  reqs: BaselineRequirement[],
  keyed: BaselineRequirement[],
  key: (r: BaselineRequirement) => string,
  describe: (k: string, members: BaselineRequirement[]) => string,
): string[] {
  const groups = new Map<string, BaselineRequirement[]>();
  keyed.forEach((r, i) => {
    const k = key(r);
    groups.set(k, [...(groups.get(k) ?? []), reqs[i]!]);
  });
  return [...groups].filter(([, m]) => m.length > 1).map(([k, m]) => describe(k, m));
}

/** Other id types under which every member is present and distinct, or the remedy. */
function separatingTypes(members: BaselineRequirement[], current: string): string {
  const ok = ID_TYPES.filter((t) => {
    if (t === current) return false;
    const ids = members.map((m) => idOf(m, t));
    return ids.every((id) => id !== '') && new Set(ids).size === ids.length;
  });
  if (ok.length === 0) {
    return 'no id type tells them apart: convert to an HDF baseline, give one requirement a distinct id, and generate from that file';
  }
  return `id type ${ok.join(' or ')} tells them apart`;
}

/**
 * Returns the requirements with each id replaced by the chosen identifier.
 * Throws when a requirement lacks it, or when two requirements would share a
 * control id or, with perFile, a control file. Mirrors the Go keyRequirements.
 */
export function keyRequirements(
  reqs: BaselineRequirement[],
  idType: string | undefined,
  perFile: boolean,
): BaselineRequirement[] {
  const type = idType || 'rule';
  if (!(ID_TYPES as readonly string[]).includes(type)) {
    throw new Error(`unknown id type ${JSON.stringify(type)}; use rule, group or version`);
  }

  const keyed = reqs.map((r) => ({ ...r, id: idOf(r, type) }));
  const missing = reqs.filter((_, i) => keyed[i]!.id === '').map((r) => r.id);
  if (missing.length > 0) {
    throw new Error(
      `id type ${type}: ${missing.length} requirements have no ${type} id (${ID_TYPE_TAG[type]}): ${missing.join(', ')}`,
    );
  }

  let problems = duplicates(reqs, keyed, (r) => r.id, (k, members) => {
    const described = members.map((m) => `${m.id} (group ${idOf(m, 'group')}, version ${idOf(m, 'version')})`);
    return `${members.length} requirements resolve to control id ${k}: ${described.join(', ')}; ${separatingTypes(members, type)}`;
  });
  if (perFile && problems.length === 0) {
    problems = duplicates(reqs, keyed, (r) => controlFilename(r.id), (k, members) =>
      `${members.length} requirements resolve to file ${k}: ${members.map((m) => idOf(m, type)).join(', ')}`,
    );
  }
  if (problems.length > 0) {
    throw new Error(`id type ${type}: ${problems.join('\n')}`);
  }
  return keyed;
}
