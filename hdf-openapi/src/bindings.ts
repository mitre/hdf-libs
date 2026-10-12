// The binding table's grammar, and the checks that keep it a MAPPING rather than an API.
//
// ADR-0008 §2 gives the table a closed grammar and a mechanical no-fragment rule. Both
// live here, in one place, so the generator and the tests cannot drift apart about what a
// legal table is.

import { parse as parseYaml } from 'yaml';
import { scopesFor } from './generate-api.js';

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
  'summaryRef',
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
  'success',
  'problems',
  'etag',
]);

/** Keys that would make the table carry a schema instead of naming one. */
const SCHEMA_KEYS = ['type', 'properties', '$ref', 'oneOf', 'allOf'];

/**
 * Input names that are filesystem-shaped whatever their schema says: the service owns
 * where bytes live, so none may reach HTTP. ADR-0008 §2 requires a hard-fail on each
 * unless the table drops it with a reason.
 */
export const FILESYSTEM_FIELDS = new Set([
  'path',
  'output',
  'outputDir',
  'overwrite',
  'directory',
  'pattern',
  'failFast',
  'dryRun',
]);

/**
 * `sources` is deliberately NOT gated, and that is a correction to ADR-0008 §2.
 *
 * Its hard-fail list names `sources`, but every `source`/`sources` input on every tool has
 * the same properties — `{handle, path}` — so the name carries no filesystem meaning of its
 * own. Only the descriptions differ (hdf_convert calls it a batch of tool-output files; the
 * others call it a set of documents), and prose is not a contract. The filesystem half is
 * `path`, which the fixed `handle` -> `id` rewrite drops by taking the id instead.
 *
 * The ADR's own Context list of filesystem-shaped inputs omits `sources`, which is the
 * clue that the hard-fail list over-reached. Gating it by name would drop cross-document
 * query, compliance and aggregate for a rule that is really about the traversal inputs
 * above — directory, pattern, failFast and outputDir — which stay gated.
 */
export interface ToolBinding {
  method?: string;
  path?: string;
  fields?: Record<string, { placement?: string; enumFrom?: string }>;
  drop?: { name: string; reason: string }[];
  bodyRef?: string;
  /** A fullShapes key whose shape becomes the envelope's `summary` member. */
  summaryRef?: string;
  items?: string;
  fullResponse?: string | string[];
  class?: string;
  /** Success status, where it is not 200. Synthetic operations only. */
  success?: number;
  /** Problem statuses this operation declares, each naming its problem types. */
  problems?: Record<string, string[]>;
  /** Whether the success response issues the document's ETag. */
  etag?: boolean;
  /** Hand-set scopes, which §2 allows only on a synthetic operation. */
  scopes?: string[];
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
    const isNameMap = ['tools', 'resources', 'synthetic', 'fields', 'problems'].includes(key);
    found.push(...unknownKeys(value, `${path}/${key}`, isNameMap));
  }
  return found;
}

interface Surface {
  toolsList: { tools: { name: string; inputSchema?: { properties?: Record<string, unknown> } }[] };
  contract: Record<string, unknown>;
  /** Conventions component names, the one hand-authored shape input §2 admits. */
  conventions?: string[];
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
  // Reflected shapes plus the conventions components. `bodyRef` may name either; a
  // `fullResponse` or `summaryRef` must be a reflected shape, since both describe a
  // response the MCP produces.
  const shapeNames = new Set([...fullShapes, ...(surface.conventions ?? [])]);

  for (const [name, binding] of Object.entries(table.synthetic ?? {})) {
    // The hand-set scopes reach the document, so a value disagreeing with what its class
    // means would silently widen or narrow the operation. Checked against the derivation
    // rather than trusted or recomputed.
    if (binding.class !== undefined && binding.scopes !== undefined) {
      const derived = scopesFor(binding.class);
      const declared = [...binding.scopes].sort().join(', ');
      if (declared !== [...derived].sort().join(', ')) {
        faults.push(
          `synthetic ${name}: scopes [${declared}] disagree with class ${binding.class}, ` +
            `which means [${[...derived].sort().join(', ')}]`,
        );
      }
    }
    if (binding.success !== undefined && !(binding.success >= 200 && binding.success < 400)) {
      faults.push(`${name}: success ${binding.success} is not a success status`);
    }
    for (const status of Object.keys(binding.problems ?? {})) {
      if (!/^[45]\d\d$/.test(status)) {
        faults.push(`${name}: problems declares ${status}, which is not a 4xx or 5xx status`);
      }
      if ((binding.problems![status] ?? []).length === 0) {
        faults.push(`${name}: problems declares ${status} with no problem type`);
      }
    }
  }

  for (const tool of surface.toolsList.tools) {
    const binding = table.tools?.[tool.name];
    if (!binding) {
      if (!absentTools.has(tool.name)) faults.push(`${tool.name}: not bound and not recorded absent`);
      continue;
    }
    if (binding.class !== undefined) {
      faults.push(`${tool.name}: declares class, which must derive from readOnlyHint`);
    }
    // §2 hand-sets a status surface only where nothing derives one. On a real tool the
    // per-tool error codes do, so a declaration here would be a waiver, not a source.
    for (const key of ['success', 'problems'] as const) {
      if (binding[key] !== undefined) {
        faults.push(`${tool.name}: declares ${key}, which only a synthetic operation may do`);
      }
    }
    for (const named of [binding.fullResponse ?? []].flat()) {
      if (!fullShapes.has(named)) {
        faults.push(`${tool.name}: fullResponse names ${named}, absent from the contract`);
      }
    }
    // The other two keys that name a shape. §2 gives `bodyRef` the form
    // `<components key | fullShapes key>`, so it is checked against the wider set; no real
    // tool uses it today — all three uses are synthetic — so that half is a forward guard,
    // reached only by a planted fault.
    if (binding.summaryRef !== undefined && !fullShapes.has(binding.summaryRef)) {
      faults.push(`${tool.name}: summaryRef names ${binding.summaryRef}, absent from the contract`);
    }
    if (binding.bodyRef !== undefined && !shapeNames.has(binding.bodyRef)) {
      faults.push(`${tool.name}: bodyRef names ${binding.bodyRef}, which is neither a reflected shape nor a conventions component`);
    }
    // A summaryRef only reaches the document through the paged envelope, which okResponse
    // builds only when the table also names the row array and its shape. Without them the
    // key emits nothing — and the failure surfaces as a test dereferencing `content` on a
    // response that has none, which names the symptom rather than the cause. This faults
    // where the cause is.
    if (binding.summaryRef !== undefined && (binding.items === undefined || binding.fullResponse === undefined)) {
      faults.push(`${tool.name}: summaryRef needs items and fullResponse, or it reaches no response`);
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

  // Synthetic operations are not in the golden, so nothing above reaches them. Their
  // shapes must still resolve: ADR-0008 §2 allows a conventions component or a reflected
  // type, and nothing else — an unresolvable name here is the API being authored by typo.
  for (const [name, op] of Object.entries(table.synthetic ?? {})) {
    if (op.class === undefined) faults.push(`synthetic ${name}: no class, which is hand-set here`);
    if (op.scopes === undefined) faults.push(`synthetic ${name}: no scopes, which are hand-set here`);
    for (const named of [op.bodyRef ?? [], op.fullResponse ?? []].flat()) {
      if (!shapeNames.has(named)) {
        faults.push(`synthetic ${name}: names ${named}, which is neither a reflected shape nor a conventions component`);
      }
    }
  }

  const absentResources = new Set(absent.filter((a) => a.resource).map((a) => a.resource));
  const boundResources = Object.keys(table.resources ?? {});
  // A concrete resource is covered by a bound TEMPLATE it is an instance of: the contract
  // lists hdf-enum-Result_Status and 23 siblings, all served by the hdf-enum template.
  // Binding each one would be a 24-entry hand-kept list that rots the moment an enum is
  // added, which is the failure the derived-coverage checks exist to prevent.
  const coveredByTemplate = (name: string): boolean =>
    boundResources.some((bound) => bound !== name && name.startsWith(`${bound}-`));
  for (const name of resourceNames(surface.contract)) {
    const covered =
      table.resources?.[name] !== undefined || absentResources.has(name) || coveredByTemplate(name);
    if (!covered) faults.push(`${name}: resource not bound and not recorded absent`);
  }
  return faults;
}
