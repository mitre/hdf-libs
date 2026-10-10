// MCP/HTTP parity: the drift gate ADR-0008's risk table names.
//
// The generator already refuses to emit an unbound tool, so parity is not a second
// coverage check. It answers the question the build cannot: once the document exists, does
// it still describe the MCP surface the golden records — after the fixed rewrite map, which
// is why this is a projection and never an equality.
//
// Every check here reports rather than throws. A caller decides whether drift is a build
// failure or a report, and a test can plant one drift and read back exactly which kind
// fired.

import { FILESYSTEM_FIELDS, type BindingTable, type ToolBinding } from './bindings.js';
import { PROBLEM_TYPES, STRIPPED_OUTPUT_FIELDS, UNMAPPED_CODES } from './generate-api.js';

export type ParityKind =
  | 'unbound-tool'
  | 'stale-binding'
  | 'parameter'
  | 'enum'
  | 'resource'
  | 'error-code'
  | 'full-shape-field'
  | 'read-only-hint';

export interface ParityFinding {
  kind: ParityKind;
  /** The tool, field, resource, code or shape that drifted. */
  subject: string;
  detail: string;
}

interface McpTool {
  name: string;
  description?: string;
  inputSchema: { properties?: Record<string, unknown> };
  annotations?: { readOnlyHint?: boolean };
}

interface NamedResource {
  name: string;
  uri?: string;
  uriTemplate?: string;
  mimeType?: string;
  description?: string;
}

export interface ParityInput {
  toolsList: { tools: McpTool[] };
  contract: {
    errorCodes: string[];
    fullShapes: Record<string, unknown>;
    resources: { resources: NamedResource[] };
    resourceTemplates: { resourceTemplates: NamedResource[] };
  };
  table: BindingTable;
  doc: {
    paths: Record<string, Record<string, { parameters?: unknown[]; requestBody?: unknown }>>;
    components: { schemas: Record<string, unknown> };
  };
}

/** The rewrite map's parameter rename, as the generator applies it. */
const parameterName = (field: string, placement: string): string =>
  placement === 'path' ? 'id' : field === 'page' ? 'next' : field;

const propertiesOf = (shape: unknown): Record<string, unknown> =>
  (shape as { properties?: Record<string, unknown> } | undefined)?.properties ?? {};

/** Parameter names the document declares for an operation. */
function parametersOf(input: ParityInput, binding: ToolBinding): Set<string> {
  const op = input.doc.paths[binding.path ?? '']?.[binding.method ?? ''];
  const declared = (op?.parameters ?? []) as { name?: string }[];
  return new Set(declared.map((p) => p.name).filter((n): n is string => n !== undefined));
}

/** Property names the document declares in an operation's request body. */
function bodyPropertiesOf(input: ParityInput, binding: ToolBinding): Set<string> {
  const op = input.doc.paths[binding.path ?? '']?.[binding.method ?? ''];
  const content = (op?.requestBody as { content?: Record<string, { schema?: unknown }> })?.content;
  const names = new Set<string>();
  for (const media of Object.values(content ?? {})) {
    for (const name of Object.keys(propertiesOf(media.schema))) names.add(name);
  }
  return names;
}

export function parityFindings(input: ParityInput): ParityFinding[] {
  const found: ParityFinding[] = [];
  const report = (kind: ParityKind, subject: string, detail: string): void => {
    found.push({ kind, subject, detail });
  };

  const tools = new Map(input.toolsList.tools.map((t) => [t.name, t]));
  const bound = input.table.tools ?? {};
  const absentTools = new Set(
    (input.table.absent ?? []).map((a) => a.tool).filter((t): t is string => t !== undefined),
  );
  const absentResources = new Set(
    (input.table.absent ?? []).map((a) => a.resource).filter((r): r is string => r !== undefined),
  );

  // 1. A tool the MCP serves that the table neither binds nor records as absent.
  for (const name of tools.keys()) {
    if (bound[name] === undefined && !absentTools.has(name)) {
      report('unbound-tool', name, `the MCP serves ${name} and the table neither binds nor excludes it`);
    }
  }

  // 2. A binding for a tool the MCP no longer serves. The table outliving its subject is
  //    the drift that leaves a path in the document answering for nothing.
  for (const name of Object.keys(bound)) {
    if (!tools.has(name)) {
      report('stale-binding', name, `the table binds ${name}, which the MCP no longer serves`);
    }
  }

  for (const [name, binding] of Object.entries(bound)) {
    const tool = tools.get(name);
    if (tool === undefined) continue;
    const fields = binding.fields ?? {};
    const dropped = new Set((binding.drop ?? []).map((d) => d.name));
    const declaredParameters = parametersOf(input, binding);
    const declaredBody = bodyPropertiesOf(input, binding);

    for (const [field, schema] of Object.entries(tool.inputSchema.properties ?? {})) {
      const spec = fields[field];
      const placement = spec?.placement;

      // 3. An input the table neither placed nor dropped — the shape a newly added MCP
      //    field takes. Silence here would mean the HTTP surface quietly lost it.
      if (placement === undefined) {
        if (!dropped.has(field)) {
          report(
            'parameter',
            `${name}.${field}`,
            `the MCP declares ${field} and the table neither places nor drops it`,
          );
        }
        continue;
      }
      if (dropped.has(field)) {
        report('parameter', `${name}.${field}`, `${field} is both placed in ${placement} and dropped`);
        continue;
      }
      if (FILESYSTEM_FIELDS.has(field)) continue;

      if (placement === 'body') {
        const expected = field === 'handle' ? 'id' : field;
        if (!declaredBody.has(expected)) {
          report(
            'parameter',
            `${name}.${field}`,
            `placed in the body and absent from the emitted body of ${binding.method} ${binding.path}`,
          );
        }
        continue;
      }

      const expected = parameterName(field, placement);
      if (!declaredParameters.has(expected)) {
        report(
          'parameter',
          `${name}.${field}`,
          `placed in ${placement} as ${expected} and absent from ${binding.method} ${binding.path}`,
        );
        continue;
      }

      // 4. A vocabulary that moved. The document advertises the accepted values, so an
      //    enum that drifts upstream makes the document wrong rather than merely stale.
      //
      //    A repeatable field carries its vocabulary on `items`, so both sides are read
      //    the same way: comparing only the scalar position would have made this check
      //    silently skip every multi-valued filter, which is most of them.
      const enumOf = (node: unknown): unknown[] | undefined => {
        const n = node as { enum?: unknown[]; items?: { enum?: unknown[] } } | undefined;
        return n?.enum ?? n?.items?.enum;
      };
      const upstream = enumOf(schema);
      if (spec?.enumFrom === 'schema enum' && Array.isArray(upstream)) {
        const op = input.doc.paths[binding.path ?? '']?.[binding.method ?? ''];
        const parameter = ((op?.parameters ?? []) as { name?: string; schema?: unknown }[]).find(
          (p) => p.name === expected,
        );
        const carried = enumOf(parameter?.schema);
        if (JSON.stringify(carried) !== JSON.stringify(upstream)) {
          report(
            'enum',
            `${name}.${field}`,
            `the MCP enum and the emitted enum differ: ${JSON.stringify(upstream)} vs ${JSON.stringify(carried)}`,
          );
        }
      }
    }

    // 8. The hint decides the SCOPE, not the method. §2 derives `class` from
    //    `readOnlyHint` and §3 gives a read-class operation `hdf:read` and a write-class
    //    operation `hdf:write` as well. The method is deliberately not the test: a
    //    read-only tool whose input is a whole document still has to POST it, which is
    //    exactly what hdf_validate does.
    const readOnly = tool.annotations?.readOnlyHint === true;
    const op = input.doc.paths[binding.path ?? '']?.[binding.method ?? ''];
    const scopes = ((op as { security?: Record<string, string[]>[] } | undefined)?.security ?? [])
      .flatMap((requirement) => Object.values(requirement))
      .flat();
    const writes = scopes.includes('hdf:write') || scopes.includes('hdf:admin');
    if (readOnly === writes) {
      report(
        'read-only-hint',
        name,
        `readOnlyHint is ${readOnly} and the emitted scopes are ${JSON.stringify(scopes)}; a read-only tool carries hdf:read alone`,
      );
    }
  }

  // 5. A resource the MCP serves that nothing binds. The 24 hdf-enum-* instances are
  //    covered by their template's binding, which is why this is a prefix test and not a
  //    list of 24 that rots when the schema gains an enum.
  const boundResources = new Set(Object.keys(input.table.resources ?? {}));
  const coveredByTemplate = (name: string): boolean =>
    [...boundResources].some((b) => b !== name && name.startsWith(`${b}-`));
  const serves = [
    ...input.contract.resources.resources,
    ...input.contract.resourceTemplates.resourceTemplates,
  ];
  for (const resource of serves) {
    if (boundResources.has(resource.name)) continue;
    if (absentResources.has(resource.name)) continue;
    if (coveredByTemplate(resource.name)) continue;
    report('resource', resource.name, `the MCP serves ${resource.name} and nothing binds or excludes it`);
  }
  const servedNames = new Set(serves.map((r) => r.name));
  for (const name of boundResources) {
    if (!servedNames.has(name)) {
      report('stale-binding', name, `the table binds resource ${name}, which the MCP no longer serves`);
    }
  }

  // 6. A code the MCP can emit with nowhere to land. ADR-0010 §6 either gives a code an
  //    HTTP status or marks it `never`; a third state means a client meets an error the
  //    document does not describe.
  const unmapped = new Set(UNMAPPED_CODES);
  //
  //    Scoped to the mapping's EXISTENCE. Whether every mapped type is reachable in the
  //    emitted document is a different property, and the document currently declares no
  //    412 and no 422 at all — tracked separately rather than folded in here, so this
  //    check passing is not read as the error surface being complete.
  for (const code of input.contract.errorCodes) {
    if (PROBLEM_TYPES[code] === undefined && !unmapped.has(code)) {
      report('error-code', code, `the MCP can emit ${code} and ADR-0010 §6 gives it neither a status nor never`);
    }
  }

  // 7. A reflected shape that lost a member. The rewrite map strips a known set; anything
  //    else missing is the response silently narrowing under the document's own nose.
  for (const [shape, declared] of Object.entries(input.contract.fullShapes)) {
    const component = input.doc.components.schemas[shape];
    if (component === undefined) {
      report('full-shape-field', shape, `the contract declares shape ${shape} and the document has no component for it`);
      continue;
    }
    const emitted = new Set(Object.keys(propertiesOf(component)));
    for (const field of Object.keys(propertiesOf(declared))) {
      if (STRIPPED_OUTPUT_FIELDS.has(field)) continue;
      if (!emitted.has(field)) {
        report('full-shape-field', `${shape}.${field}`, `declared on ${shape} upstream and absent from the emitted component`);
      }
    }
  }

  return found;
}
