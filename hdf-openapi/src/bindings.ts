// The binding table's grammar, and the checks that keep it a MAPPING rather than an API.
//
// ADR-0008 §2 gives the table a closed grammar and a mechanical no-fragment rule. Both
// live here, in one place, so the generator and the tests cannot drift apart about what a
// legal table is.

import { parse as parseYaml } from 'yaml';

/**
 * Every key the table may use. ADR-0008 §2 defines the grammar; anything outside this set
 * is a fault, which is what stops the table growing an API by accretion.
 *
 * `class` is deliberately absent for real tools — it derives from the tool's
 * `readOnlyHint` — and legal only inside `synthetic`, where no hint exists.
 */
export const CLOSED_KEYS = new Set([
  'tools',
  'resources',
  'synthetic',
  'absent',
  'method',
  'path',
  'placement',
  'bodyRef',
  'drop',
  'enumFrom',
  'items',
  'fullResponse',
  'fields',
  'name',
  'reason',
  'tool',
  'resource',
  'field',
  'class',
  'scopes',
]);

/** Keys that would make the table carry a schema instead of naming one. */
const SCHEMA_KEYS = ['type', 'properties', '$ref', 'oneOf', 'allOf'];

/**
 * Input names the MCP exposes because it reads a filesystem. None may reach HTTP: the
 * document is addressed by id and the service owns where bytes live. ADR-0008 §2 requires
 * the generator to hard-fail on each unless the table drops it with a reason.
 */
export const FILESYSTEM_FIELDS = new Set([
  'path',
  'output',
  'outputDir',
  'overwrite',
  'directory',
  'pattern',
  'failFast',
  'sources',
  'dryRun',
]);

export interface ToolBinding {
  method?: string;
  path?: string;
  fields?: Record<string, { placement?: string; enumFrom?: string }>;
  drop?: { name: string; reason: string }[];
  bodyRef?: string;
  items?: string;
  fullResponse?: string | string[];
  class?: string;
}

export interface BindingTable {
  tools?: Record<string, ToolBinding>;
  resources?: Record<string, { method?: string; path?: string }>;
  synthetic?: Record<string, ToolBinding & { scopes?: string[] }>;
  absent?: { tool?: string; resource?: string; field?: string; reason: string }[];
}

export function loadBindings(yamlText: string): BindingTable {
  const parsed = parseYaml(yamlText) as BindingTable | null;
  // An array is typeof 'object', so it has to be excluded explicitly: a table that parsed
  // to a list would otherwise sail through here and read as empty everywhere downstream.
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error('bindings.yaml did not parse to a mapping');
  }
  return parsed;
}

/**
 * Every place the table carries a schema rather than naming one. `items` is legal as the
 * scalar naming an output field and illegal as a schema, so it is judged by its value.
 */
export function schemaFragments(raw: unknown, path = ''): string[] {
  const found: string[] = [];
  if (Array.isArray(raw)) {
    raw.forEach((v, i) => found.push(...schemaFragments(v, `${path}/${i}`)));
    return found;
  }
  if (raw === null || typeof raw !== 'object') return found;
  for (const [key, value] of Object.entries(raw)) {
    if (SCHEMA_KEYS.includes(key)) found.push(`${path}/${key}`);
    if (key === 'items' && typeof value !== 'string') found.push(`${path}/items is not a scalar`);
    found.push(...schemaFragments(value, `${path}/${key}`));
  }
  return found;
}

/** Keys used outside the closed set. Names under `tools`/`resources`/`synthetic`/`fields` are data. */
export function unknownKeys(raw: unknown, path = '', parentIsNameMap = false): string[] {
  const found: string[] = [];
  if (Array.isArray(raw)) {
    raw.forEach((v, i) => found.push(...unknownKeys(v, `${path}/${i}`, false)));
    return found;
  }
  if (raw === null || typeof raw !== 'object') return found;
  for (const [key, value] of Object.entries(raw)) {
    if (!parentIsNameMap && !CLOSED_KEYS.has(key)) found.push(`${path}/${key}`);
    const isNameMap = ['tools', 'resources', 'synthetic', 'fields'].includes(key);
    found.push(...unknownKeys(value, `${path}/${key}`, isNameMap));
  }
  return found;
}

interface Surface {
  toolsList: { tools: { name: string; inputSchema?: { properties?: Record<string, unknown> } }[] };
  contract: Record<string, unknown>;
}

/**
 * Resource and template names from the contract. Both live one level down — the golden
 * wraps each list with its cache policy (`ttlMs`, `cacheScope`) — so the nesting is read
 * here rather than assumed by every caller.
 */
export function resourceNames(contract: Record<string, unknown>): string[] {
  const list = (holder: unknown, key: string): { name?: string }[] =>
    ((holder as Record<string, unknown> | undefined)?.[key] as { name?: string }[]) ?? [];
  return [
    ...list(contract.resources, 'resources'),
    ...list(contract.resourceTemplates, 'resourceTemplates'),
  ]
    .map((r) => r.name)
    .filter((n): n is string => typeof n === 'string');
}

/**
 * Every way the table fails to map the live surface, as one flat list so a caller can
 * report all of them rather than the first. Each fault is prefixed with the tool it
 * belongs to, so a per-tool test can filter.
 */
export function bindingFaults(table: BindingTable, surface: Surface): string[] {
  const faults: string[] = [];
  const absent = table.absent ?? [];
  const absentTools = new Set(absent.filter((a) => a.tool && !a.field).map((a) => a.tool));
  const absentFields = new Set(absent.filter((a) => a.field).map((a) => `${a.tool}.${a.field}`));

  for (const entry of absent) {
    if (!entry.reason) faults.push(`absent entry ${JSON.stringify(entry)} carries no reason`);
  }

  const fullShapes = new Set(Object.keys((surface.contract.fullShapes as object) ?? {}));

  for (const tool of surface.toolsList.tools) {
    const binding = table.tools?.[tool.name];
    if (!binding) {
      if (!absentTools.has(tool.name)) faults.push(`${tool.name}: not bound and not recorded absent`);
      continue;
    }
    if (binding.class !== undefined) {
      faults.push(`${tool.name}: declares class, which must derive from readOnlyHint`);
    }
    for (const named of [binding.fullResponse ?? []].flat()) {
      if (!fullShapes.has(named)) {
        faults.push(`${tool.name}: fullResponse names ${named}, absent from the contract`);
      }
    }
    const dropped = new Set((binding.drop ?? []).map((d) => d.name));
    for (const drop of binding.drop ?? []) {
      if (!drop.reason) faults.push(`${tool.name}: drops ${drop.name} with no reason`);
    }
    for (const field of Object.keys(tool.inputSchema?.properties ?? {})) {
      const placed = binding.fields?.[field]?.placement !== undefined;
      const accounted = placed || dropped.has(field) || absentFields.has(`${tool.name}.${field}`);
      if (!accounted) faults.push(`${tool.name}.${field}: neither placed, dropped, nor absent`);
      if (FILESYSTEM_FIELDS.has(field) && !dropped.has(field)) {
        faults.push(`${tool.name}.${field}: filesystem-shaped and must be dropped, not exposed`);
      }
    }
  }

  const absentResources = new Set(absent.filter((a) => a.resource).map((a) => a.resource));
  for (const name of resourceNames(surface.contract)) {
    if (table.resources?.[name] === undefined && !absentResources.has(name)) {
      faults.push(`${name}: resource not bound and not recorded absent`);
    }
  }
  return faults;
}
