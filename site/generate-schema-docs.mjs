/**
 * Generate VitePress markdown pages from HDF JSON Schema files.
 *
 * Reads bundled schemas from hdf-schema/dist/schemas/ and produces:
 * - schemas/index.md — overview with links to all document types
 * - schemas/<name>.md — per-schema reference page with types, properties, examples
 * - public/schemas/ — raw .schema.json files served as static assets
 *
 * Run: node generate-schema-docs.mjs
 */

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SCHEMAS_DIR = path.resolve(__dirname, '../hdf-schema/dist/schemas');
const OUTPUT_DIR = path.resolve(__dirname, 'schemas');
const PUBLIC_DIR = path.resolve(__dirname, 'public/schemas');

// Ensure output dirs exist
fs.mkdirSync(OUTPUT_DIR, { recursive: true });
fs.mkdirSync(PUBLIC_DIR, { recursive: true });

// Document type display names and descriptions
const SCHEMA_META = {
  'hdf-results': {
    title: 'HDF Results',
    description: 'Assessment results from running security checks against a target system.',
    icon: '📊',
  },
  'hdf-baseline': {
    title: 'HDF Baseline',
    description: 'Security requirement definitions without results — the "what to check" document.',
    icon: '📋',
  },
  'hdf-system': {
    title: 'HDF System',
    description: 'System authorization boundary, components, data flows, and control designations.',
    icon: '🏗️',
  },
  'hdf-plan': {
    title: 'HDF Plan',
    description: 'Assessment plan defining what baselines to run against which components.',
    icon: '📅',
  },
  'hdf-amendments': {
    title: 'HDF Amendments',
    description: 'Waivers, attestations, POA&Ms, and other status overrides applied to findings.',
    icon: '📝',
  },
  'hdf-evidence-package': {
    title: 'HDF Evidence Package',
    description: 'Bundle of references to all HDF documents for a complete assessment record.',
    icon: '📦',
  },
  'hdf-comparison': {
    title: 'HDF Comparison',
    description: 'Differential analysis of two or more assessment results.',
    icon: '🔀',
  },
};

// Read all bundled schemas
const schemaFiles = fs.readdirSync(SCHEMAS_DIR)
  .filter(f => f.endsWith('.schema.json'))
  .sort();

const schemas = schemaFiles.map(f => {
  const raw = fs.readFileSync(path.join(SCHEMAS_DIR, f), 'utf-8');
  const schema = JSON.parse(raw);
  const name = f.replace('.schema.json', '');
  // Copy to public dir for direct download
  fs.copyFileSync(path.join(SCHEMAS_DIR, f), path.join(PUBLIC_DIR, f));
  // Also create versioned path
  const version = schema.$id.split('/').pop();
  const versionDir = path.join(PUBLIC_DIR, name, version);
  fs.mkdirSync(versionDir, { recursive: true });
  fs.writeFileSync(path.join(versionDir, 'index.json'), raw);
  return { name, schema, filename: f };
});

// --- Generate index page ---

const indexLines = [
  '---',
  'outline: deep',
  '---',
  '',
  '# HDF Schema Reference',
  '',
  'The Heimdall Data Format (HDF) defines 7 JSON document types for security assessment data.',
  'Each schema is self-contained — all referenced types are embedded, no external fetches needed.',
  '',
  '## Document Types',
  '',
];

for (const { name, schema } of schemas) {
  const meta = SCHEMA_META[name] || { title: name, description: schema.description || '', icon: '📄' };
  const version = schema.$id.split('/').pop();
  indexLines.push(`### ${meta.icon} [${meta.title}](/schemas/${name})`);
  indexLines.push('');
  indexLines.push(meta.description);
  indexLines.push('');
  indexLines.push(`- **Version**: \`${version}\``);
  indexLines.push(`- **Schema**: [\`${name}.schema.json\`](/schemas/${name}.schema.json)`);
  indexLines.push(`- **\`$id\`**: \`${schema.$id}\``);
  indexLines.push('');
}

indexLines.push('## Downloads');
indexLines.push('');
indexLines.push('| Schema | Version | Download |');
indexLines.push('|--------|---------|----------|');
for (const { name, schema } of schemas) {
  const version = schema.$id.split('/').pop();
  const meta = SCHEMA_META[name] || { title: name };
  indexLines.push(`| ${meta.title} | ${version} | [${name}.schema.json](/schemas/${name}.schema.json) |`);
}

fs.writeFileSync(path.join(OUTPUT_DIR, 'index.md'), indexLines.join('\n'));

// --- Generate per-schema pages ---

for (const { name, schema } of schemas) {
  const meta = SCHEMA_META[name] || { title: name, description: '', icon: '📄' };
  const version = schema.$id.split('/').pop();
  const lines = [
    '---',
    'outline: deep',
    '---',
    '',
    `# ${meta.title}`,
    '',
    schema.description || meta.description,
    '',
    `| | |`,
    `|---|---|`,
    `| **Version** | \`${version}\` |`,
    `| **\`$id\`** | \`${schema.$id}\` |`,
    `| **Download** | [${name}.schema.json](/schemas/${name}.schema.json) |`,
    '',
  ];

  // Root-level properties
  if (schema.properties) {
    lines.push('## Properties');
    lines.push('');
    lines.push('| Field | Type | Required | Description |');
    lines.push('|-------|------|----------|-------------|');

    const required = new Set(schema.required || []);
    for (const [field, prop] of Object.entries(schema.properties)) {
      const type = resolveTypeName(prop);
      const req = required.has(field) ? '**yes**' : 'no';
      const desc = (prop.description || '').replace(/\n/g, ' ').replace(/\|/g, '\\|');
      lines.push(`| \`${field}\` | ${type} | ${req} | ${desc} |`);
    }
    lines.push('');
  }

  // Root-level examples
  if (schema.examples && schema.examples.length > 0) {
    lines.push('## Example');
    lines.push('');
    lines.push('```json');
    lines.push(JSON.stringify(schema.examples[0], null, 2));
    lines.push('```');
    lines.push('');
  }

  // $defs — type definitions
  const defs = schema.$defs || {};
  const localDefs = {};
  const embeddedDefs = {};

  for (const [key, defn] of Object.entries(defs)) {
    if (key.startsWith('https://')) {
      embeddedDefs[key] = defn;
    } else {
      localDefs[key] = defn;
    }
  }

  // Local definitions (types defined in this schema)
  if (Object.keys(localDefs).length > 0) {
    lines.push('## Types');
    lines.push('');

    for (const [typeName, defn] of Object.entries(localDefs)) {
      lines.push(`### ${typeName.replace(/_/g, '\\_')}`);
      lines.push('');
      if (defn.description) {
        lines.push(defn.description);
        lines.push('');
      }

      // Properties from the type itself or from allOf composition
      const props = collectProperties(defn);
      if (Object.keys(props).length > 0) {
        const req = collectRequired(defn);
        lines.push('| Field | Type | Required | Description |');
        lines.push('|-------|------|----------|-------------|');
        for (const [field, prop] of Object.entries(props)) {
          const type = resolveTypeName(prop);
          const isReq = req.has(field) ? '**yes**' : 'no';
          const desc = (prop.description || '').replace(/\n/g, ' ').replace(/\|/g, '\\|');
          lines.push(`| \`${field}\` | ${type} | ${isReq} | ${desc} |`);
        }
        lines.push('');
      }

      // Examples for this type
      if (defn.examples && defn.examples.length > 0) {
        lines.push('::: details Example');
        lines.push('```json');
        lines.push(JSON.stringify(defn.examples[0], null, 2));
        lines.push('```');
        lines.push(':::');
        lines.push('');
      }
    }
  }

  // Embedded primitive schemas (collapsed by default)
  const embeddedKeys = Object.keys(embeddedDefs);
  if (embeddedKeys.length > 0) {
    lines.push('## Embedded Primitives');
    lines.push('');
    lines.push('These types are embedded from shared primitive schemas.');
    lines.push('');

    for (const embeddedId of embeddedKeys.sort()) {
      const embedded = embeddedDefs[embeddedId];
      const shortId = embeddedId.replace('https://mitre.github.io/hdf-libs/schemas/primitives/', '');
      lines.push(`### ${shortId}`);
      lines.push('');

      const innerDefs = embedded.$defs || {};
      if (Object.keys(innerDefs).length > 0) {
        for (const [typeName, defn] of Object.entries(innerDefs)) {
          lines.push(`#### ${typeName.replace(/_/g, '\\_')}`);
          lines.push('');
          if (defn.description) {
            lines.push(defn.description);
            lines.push('');
          }

          const props = collectProperties(defn);
          if (Object.keys(props).length > 0) {
            const req = collectRequired(defn);
            lines.push('| Field | Type | Required | Description |');
            lines.push('|-------|------|----------|-------------|');
            for (const [field, prop] of Object.entries(props)) {
              const type = resolveTypeName(prop);
              const isReq = req.has(field) ? '**yes**' : 'no';
              const desc = (prop.description || '').replace(/\n/g, ' ').replace(/\|/g, '\\|');
              lines.push(`| \`${field}\` | ${type} | ${isReq} | ${desc} |`);
            }
            lines.push('');
          }

          if (defn.examples && defn.examples.length > 0) {
            lines.push('::: details Example');
            lines.push('```json');
            lines.push(JSON.stringify(defn.examples[0], null, 2));
            lines.push('```');
            lines.push(':::');
            lines.push('');
          }
        }
      }
    }
  }

  fs.writeFileSync(path.join(OUTPUT_DIR, `${name}.md`), lines.join('\n'));
}

console.log(`Generated ${schemas.length} schema pages + index in ${OUTPUT_DIR}`);

// --- Helpers ---

function resolveTypeName(prop) {
  if (!prop) return 'any';
  if (prop.$ref) {
    const ref = prop.$ref;
    if (ref.startsWith('#/$defs/')) return `\`${ref.replace('#/$defs/', '')}\``;
    // External ref — extract type name from end
    const parts = ref.split('/');
    const typePart = parts[parts.length - 1];
    const schemaPart = parts[parts.length - 3] || '';
    return `\`${typePart}\``;
  }
  if (prop.const) return `\`"${prop.const}"\``;
  if (prop.enum) return prop.enum.map(v => `\`"${v}"\``).join(' \\| ');
  if (prop.type === 'array') {
    const itemType = prop.items ? resolveTypeName(prop.items) : 'any';
    return `${itemType}[]`;
  }
  if (prop.type === 'object' && prop.additionalProperties) {
    const valType = resolveTypeName(prop.additionalProperties);
    return `Map<string, ${valType}>`;
  }
  if (prop.oneOf) return prop.oneOf.map(resolveTypeName).join(' \\| ');
  if (prop.anyOf) return prop.anyOf.map(resolveTypeName).join(' \\| ');
  if (prop.type) return `\`${prop.type}\`${prop.format ? ` (${prop.format})` : ''}`;
  return 'any';
}

function collectProperties(defn) {
  const props = { ...(defn.properties || {}) };
  // Collect from allOf
  if (defn.allOf) {
    for (const sub of defn.allOf) {
      if (sub.properties) {
        Object.assign(props, sub.properties);
      }
    }
  }
  return props;
}

function collectRequired(defn) {
  const req = new Set(defn.required || []);
  if (defn.allOf) {
    for (const sub of defn.allOf) {
      if (sub.required) {
        for (const r of sub.required) req.add(r);
      }
    }
  }
  return req;
}
