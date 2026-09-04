// Pure rendering helpers for the schema-docs generator (generate-schema-docs.mjs),
// extracted so they can be unit-tested without executing the generator's
// top-level file I/O.

// anchorId produces a deterministic, VitePress-independent heading id for a
// named schema type. The generator emits `### Name {#<anchorId(Name)>}` on the
// definition and links `$ref` cells to `#<anchorId(Name)>`, so both sides always
// agree regardless of VitePress's internal slugify (which we deliberately do not
// depend on).
export function anchorId(name) {
  return String(name)
    .toLowerCase()
    .replace(/[\s_]+/g, '-')
    .replace(/[^a-z0-9-]/g, '')
    .replace(/-+/g, '-')
    .replace(/^-|-$/g, '');
}

// renderEnumValues appends an "allowed values" block for a named enum def. Named
// enum defs carry no object properties, so without this they render as just a
// heading + description — hiding that they are enums and which values are legal.
export function renderEnumValues(defn, lines) {
  if (!defn || !Array.isArray(defn.enum)) return;
  const base = defn.type ? `\`${defn.type}\`` : '`string`';
  lines.push(`**Enum** (${base}) — allowed values:`);
  lines.push('');
  for (const value of defn.enum) {
    lines.push(`- \`"${value}"\``);
  }
  lines.push('');
}

// refTypeName extracts the target type name from a $ref, local (`#/$defs/X`) or
// embedded-primitive (`https://…#/$defs/Y`).
function refTypeName(ref) {
  if (ref.startsWith('#/$defs/')) return ref.replace('#/$defs/', '');
  const parts = ref.split('/');
  return parts[parts.length - 1];
}

// resolveTypeName renders a property's type for a doc table cell. When the type
// is a $ref to a type rendered on the same page (its name is in knownTypes), it
// becomes a clickable intra-page anchor link; otherwise it degrades to plain
// code — never a broken link. Array/oneOf/anyOf recurse, so wrapped refs are
// linked too. knownTypes is a Set of the type names that have a heading on the
// current page.
export function resolveTypeName(prop, knownTypes = new Set()) {
  if (!prop) return 'any';
  if (prop.$ref) {
    const name = refTypeName(prop.$ref);
    if (knownTypes.has(name)) return `[\`${name}\`](#${anchorId(name)})`;
    return `\`${name}\``;
  }
  if (prop.const) return `\`"${prop.const}"\``;
  if (prop.enum) return prop.enum.map((v) => `\`"${v}"\``).join(' \\| ');
  if (prop.type === 'array') {
    const itemType = prop.items ? resolveTypeName(prop.items, knownTypes) : 'any';
    return `${itemType}[]`;
  }
  if (prop.type === 'object' && prop.additionalProperties) {
    const valType = resolveTypeName(prop.additionalProperties, knownTypes);
    return `Map<string, ${valType}>`;
  }
  if (prop.oneOf) return prop.oneOf.map((p) => resolveTypeName(p, knownTypes)).join(' \\| ');
  if (prop.anyOf) return prop.anyOf.map((p) => resolveTypeName(p, knownTypes)).join(' \\| ');
  if (prop.type) return `\`${prop.type}\`${prop.format ? ` (${prop.format})` : ''}`;
  return 'any';
}

// mdCell renders a description into a markdown table cell. Backslashes are
// escaped first so the backslashes introduced by the later escapes aren't
// themselves re-escaped.
export function mdCell(s) {
  // Table cells cannot hold block paragraphs; render source-authored
  // paragraph breaks as explicit line breaks and flatten the rest.
  const flattened = (s || '')
    .replace(/\\/g, '\\\\')
    .replace(/\n\n+/g, '<br><br>')
    .replace(/\n/g, ' ')
    .replace(/\|/g, '\\|');

  // Descriptions carry data (CPE wildcards, cron expressions, glob patterns),
  // so anything outside a code span renders literally rather than as markdown.
  // Code spans are passed through whole: a backslash escape inside one renders
  // as a literal backslash, which would corrupt the span's contents.
  return flattened.replace(/(`+)[\s\S]*?\1|[*_[\]]/g, (match) =>
    match.startsWith('`') ? match : `\\${match}`,
  );
}
