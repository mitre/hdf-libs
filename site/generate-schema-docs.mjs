// Generate VitePress markdown pages from HDF JSON Schema files.
//
// Reads bundled schemas from hdf-schema/dist/schemas/ (current version)
// AND the per-version archive at site/public/schemas/<name>/v<X.Y.Z>/
// index.json (historical versions), then produces:
//
// - schemas/index.md — overview for the current version
// - schemas/<name>.md — current-version per-schema reference pages
// - v<X.Y.Z>/schemas/index.md — overview for each historical version
// - v<X.Y.Z>/schemas/<name>.md — historical per-schema pages
// - public/schemas/ — current-version raw .schema.json (top-level)
// - public/schemas/<name>/<version>/index.json — written for the current
//   version. Historical entries are seeded by site/seed-archive.mjs and
//   are NOT touched here (existing files preserved).
// - .vitepress/versions.json — manifest listing versions found, with the
//   current version marked. Consumed by config.mjs to build the nav
//   dropdown and per-version sidebars.
//
// Run: node generate-schema-docs.mjs

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SCHEMAS_DIR = path.resolve(__dirname, '../hdf-schema/dist/schemas');
const OUTPUT_DIR = path.resolve(__dirname, 'schemas');
const PUBLIC_DIR = path.resolve(__dirname, 'public/schemas');
const VITEPRESS_DIR = path.resolve(__dirname, '.vitepress');
const SITE_DIR = __dirname;

// Document type display names and descriptions
const SCHEMA_META = {
  'hdf-results': {
    title: 'HDF Results',
    description: 'Assessment results from running security checks against a target system.',
  },
  'hdf-baseline': {
    title: 'HDF Baseline',
    description: 'Security requirement definitions without results — the "what to check" document.',
  },
  'hdf-system': {
    title: 'HDF System',
    description: 'System authorization boundary, components, data flows, and control designations.',
  },
  'hdf-plan': {
    title: 'HDF Plan',
    description: 'Assessment plan defining what baselines to run against which components.',
  },
  'hdf-amendments': {
    title: 'HDF Amendments',
    description: 'Waivers, attestations, POA&Ms, and other status overrides applied to findings.',
  },
  'hdf-evidence-package': {
    title: 'HDF Evidence Package',
    description: 'Bundle of references to all HDF documents for a complete assessment record.',
  },
  'hdf-comparison': {
    title: 'HDF Comparison',
    description: 'Differential analysis of two or more assessment results.',
  },
  'hdf-requirement-change-event': {
    title: 'HDF Requirement Change Event',
    description: 'A single continuous-monitoring wire event: one requirement\'s effective posture changed on one system component.',
  },
};

const MAIN_SCHEMAS = Object.keys(SCHEMA_META);

// --- 1. Read current schemas from dist/ -----------------------------------

fs.mkdirSync(OUTPUT_DIR, { recursive: true });
fs.mkdirSync(PUBLIC_DIR, { recursive: true });

const currentSchemas = [];
for (const name of MAIN_SCHEMAS) {
  const file = `${name}.schema.json`;
  const filePath = path.join(SCHEMAS_DIR, file);
  if (!fs.existsSync(filePath)) {
    console.warn(`Warning: ${file} missing from ${SCHEMAS_DIR} — skipping`);
    continue;
  }
  const raw = fs.readFileSync(filePath, 'utf-8');
  const schema = JSON.parse(raw);
  const version = idVersion(schema.$id);

  // Top-level public copy (current version only) — preserves existing
  // /schemas/<name>.schema.json URL pattern.
  fs.copyFileSync(filePath, path.join(PUBLIC_DIR, file));

  // Per-version archive write for the current version. (Historical
  // versions are written by site/seed-archive.mjs; we don't touch them.)
  // Trailing newline matches the seed-archive.mjs write pattern so the
  // archive byte-format is consistent regardless of which writer produced it.
  const archiveDir = path.join(PUBLIC_DIR, name, version);
  fs.mkdirSync(archiveDir, { recursive: true });
  const archiveJson = raw.endsWith('\n') ? raw : raw + '\n';
  fs.writeFileSync(path.join(archiveDir, 'index.json'), archiveJson);

  currentSchemas.push({ name, schema, version });
}

const currentVersion = currentSchemas[0]?.version;
if (!currentVersion) {
  throw new Error(`No current schemas read from ${SCHEMAS_DIR}; run 'cd hdf-schema && pnpm build:schemas' first`);
}

// --- 2. Discover historical archive versions ------------------------------

// Walk public/schemas/<name>/v*/ and gather every (name, version) pair.
// The CURRENT version's archive entry was just written above; we skip it
// when collecting historical ones.
const archiveBySchema = {};
for (const name of MAIN_SCHEMAS) {
  const dir = path.join(PUBLIC_DIR, name);
  if (!fs.existsSync(dir)) continue;
  const versions = fs.readdirSync(dir)
    .filter((f) => f.startsWith('v') && fs.existsSync(path.join(dir, f, 'index.json')));
  archiveBySchema[name] = versions;
}

// Build the cross-schema set of historical versions. A version counts as
// "historical" if it isn't the current version AND at least one main
// schema has an archive entry for it.
const historicalVersions = new Set();
for (const versions of Object.values(archiveBySchema)) {
  for (const v of versions) {
    if (v !== currentVersion) historicalVersions.add(v);
  }
}

const historicalVersionList = Array.from(historicalVersions).sort(semverCompareDesc);

// --- 3. Render current-version pages --------------------------------------

writeIndexPage(OUTPUT_DIR, currentSchemas, /* urlPrefix= */ '');
for (const entry of currentSchemas) {
  const md = renderSchemaPage(entry.schema, entry.name, '');
  fs.writeFileSync(path.join(OUTPUT_DIR, `${entry.name}.md`), md);
}

// --- 4. Render historical-version pages -----------------------------------

for (const version of historicalVersionList) {
  const versionedSchemas = [];
  for (const name of MAIN_SCHEMAS) {
    const versions = archiveBySchema[name] || [];
    if (!versions.includes(version)) continue;
    const archivePath = path.join(PUBLIC_DIR, name, version, 'index.json');
    const schema = JSON.parse(fs.readFileSync(archivePath, 'utf-8'));
    versionedSchemas.push({ name, schema, version });
  }
  if (versionedSchemas.length === 0) continue;

  const versionDir = path.join(SITE_DIR, version, 'schemas');
  fs.mkdirSync(versionDir, { recursive: true });

  const urlPrefix = `/${version}`;
  writeIndexPage(versionDir, versionedSchemas, urlPrefix);
  for (const entry of versionedSchemas) {
    const md = renderSchemaPage(entry.schema, entry.name, urlPrefix);
    fs.writeFileSync(path.join(versionDir, `${entry.name}.md`), md);
  }
}

// --- 5. Emit the versions manifest for config.mjs --------------------------

fs.mkdirSync(VITEPRESS_DIR, { recursive: true });
const manifest = {
  current: currentVersion,
  versions: [currentVersion, ...historicalVersionList],
};
fs.writeFileSync(
  path.join(VITEPRESS_DIR, 'versions.json'),
  JSON.stringify(manifest, null, 2) + '\n',
);

console.log(
  `Generated ${currentSchemas.length} current pages (${currentVersion}) + ${historicalVersionList.length} historical version sets`,
);

// === Page rendering helpers ================================================

function writeIndexPage(outputDir, schemas, urlPrefix) {
  const isHistorical = urlPrefix !== '';
  const lines = [
    '---',
    'outline: deep',
    '---',
    '',
    isHistorical
      ? `# HDF Schema Reference — ${schemas[0]?.version}`
      : '# HDF Schema Reference',
    '',
    isHistorical
      ? `Historical snapshot of HDF documents as of release ${schemas[0]?.version}. For the current version see [/schemas/](/schemas/).`
      : 'The Heimdall Data Format (HDF) defines 7 JSON document types for security assessment data. Each schema is self-contained — all referenced types are embedded, no external fetches needed.',
    '',
    '## Document Types',
    '',
  ];

  for (const { name, schema } of schemas) {
    const meta = SCHEMA_META[name] || { title: name, description: schema.description || '' };
    lines.push(`### [${meta.title}](${urlPrefix}/schemas/${name})`);
    lines.push('');
    lines.push(meta.description);
    lines.push('');
    lines.push(`- **Version**: \`${idVersion(schema.$id)}\``);
    lines.push(`- **\`$id\`**: \`${schema.$id}\``);
    lines.push('');
  }

  lines.push('## Downloads');
  lines.push('');
  lines.push('| Schema | Version | Download |');
  lines.push('|--------|---------|----------|');
  for (const { name, schema } of schemas) {
    const meta = SCHEMA_META[name] || { title: name };
    const version = idVersion(schema.$id);
    const downloadUrl = isHistorical
      ? `/schemas/${name}/${version}/index.json`
      : `/schemas/${name}.schema.json`;
    lines.push(`| ${meta.title} | ${version} | [\`${name}.schema.json\`](${downloadUrl}) |`);
  }

  fs.writeFileSync(path.join(outputDir, 'index.md'), lines.join('\n'));
}

function renderSchemaPage(schema, name, urlPrefix) {
  const isHistorical = urlPrefix !== '';
  const meta = SCHEMA_META[name] || { title: name, description: '' };
  const version = idVersion(schema.$id);
  const downloadUrl = isHistorical
    ? `/schemas/${name}/${version}/index.json`
    : `/schemas/${name}.schema.json`;

  const lines = [
    '---',
    'outline: deep',
    '---',
    '',
    `# ${meta.title}${isHistorical ? ` — ${version}` : ''}`,
    '',
    schema.description || meta.description,
    '',
    `| | |`,
    `|---|---|`,
    `| **Version** | \`${version}\` |`,
    `| **\`$id\`** | \`${schema.$id}\` |`,
    `| **Download** | [${name}.schema.json](${downloadUrl}) |`,
    '',
  ];

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

  const embeddedKeys = Object.keys(embeddedDefs);
  if (embeddedKeys.length > 0) {
    lines.push('## Embedded Primitives');
    lines.push('');
    lines.push('These types are embedded from shared primitive schemas.');
    lines.push('');
    for (const embeddedId of embeddedKeys.sort()) {
      const embedded = embeddedDefs[embeddedId];
      // Drop both the URL prefix AND the trailing /vX.Y.Z so the rendered
      // heading (and its derived anchor + right-rail TOC entry) stays stable
      // across releases.
      const shortId = embeddedId
        .replace('https://mitre.github.io/hdf-libs/schemas/primitives/', '')
        .replace(/\/v\d+\.\d+\.\d+$/, '');
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

  return lines.join('\n');
}

// === Misc helpers ==========================================================

function idVersion(schemaId) {
  if (!schemaId) return 'unknown';
  const match = schemaId.match(/\/v\d+\.\d+\.\d+$/);
  return match ? match[0].slice(1) : 'unknown';
}

function semverCompareDesc(a, b) {
  const [maja, mina, pata] = a.replace(/^v/, '').split('.').map(Number);
  const [majb, minb, patb] = b.replace(/^v/, '').split('.').map(Number);
  if (maja !== majb) return majb - maja;
  if (mina !== minb) return minb - mina;
  return patb - pata;
}

function resolveTypeName(prop) {
  if (!prop) return 'any';
  if (prop.$ref) {
    const ref = prop.$ref;
    if (ref.startsWith('#/$defs/')) return `\`${ref.replace('#/$defs/', '')}\``;
    const parts = ref.split('/');
    const typePart = parts[parts.length - 1];
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
  if (defn.allOf) {
    for (const sub of defn.allOf) {
      if (sub.properties) Object.assign(props, sub.properties);
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
