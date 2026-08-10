import { mkdirSync, existsSync, writeFileSync, readFileSync, readdirSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath, pathToFileURL } from 'url';
import {
  quicktype,
  InputData,
  JSONSchemaInput,
  FetchingJSONSchemaStore,
} from 'quicktype-core';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const DIST_SCHEMAS_DIR = join(__dirname, '..', 'dist', 'schemas');
const DIST_DIR = join(__dirname, '..', 'dist');

// Schemas to generate types for.
// Names use HDF (uppercase acronym) matching schema title fields ("HDF Results", etc.).
// This ensures combined quicktype output produces correct root type names.
const SCHEMAS = [
  { file: 'hdf-results.schema.json', name: 'HDFResults' },
  { file: 'hdf-baseline.schema.json', name: 'HDFBaseline' },
  { file: 'hdf-comparison.schema.json', name: 'HDFComparison' },
  { file: 'hdf-system.schema.json', name: 'HDFSystem' },
  { file: 'hdf-plan.schema.json', name: 'HDFPlan' },
  { file: 'hdf-amendments.schema.json', name: 'HDFAmendments' },
  { file: 'hdf-evidence-package.schema.json', name: 'HDFEvidencePackage' },
  { file: 'hdf-requirement-change-event.schema.json', name: 'HDFRequirementChangeEvent' },
];

const LANGUAGES = [
  { name: 'typescript', dir: 'ts', options: { 'just-types': 'true' } },
  { name: 'go', dir: 'go', options: { 'package': 'hdf', 'omit-empty': 'true' } },
];

/**
 * Preprocess a JSON Schema to work around quicktype-core 23.x bugs:
 * 1. Replace bare primitive types in oneOf with a wrapper object so quicktype
 *    can generate a name for the variant (avoids codePointAt crash).
 * 2. Remove `const: true` boolean properties (quicktype can't handle const).
 */
function preprocessSchemaForQuicktype(schemaJson: string): string {
  const schema = JSON.parse(schemaJson);

  function walk(node: unknown): unknown {
    if (node === null || typeof node !== 'object') return node;
    if (Array.isArray(node)) return node.map(walk);

    const obj = node as Record<string, unknown>;

    if (obj['type'] === 'boolean' && 'const' in obj) {
      const { const: _, ...rest } = obj;
      void _;
      return walk(rest);
    }

    if (Array.isArray(obj['oneOf'])) {
      const items = obj['oneOf'] as Array<Record<string, unknown>>;
      const hasBare = items.some(
        (i) => typeof i['type'] === 'string' && !i['$ref']
      );
      const hasRef = items.some((i) => '$ref' in i);
      if (hasBare && hasRef) {
        const { oneOf: __, ...rest } = obj;
        void __;
        return walk({ ...rest, description: obj['description'] });
      }
    }

    const result: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(obj)) {
      result[key] = walk(value);
    }
    return result;
  }

  return JSON.stringify(walk(schema));
}

/**
 * Normalize quicktype's shared-type doc comments.
 *
 * quicktype set-unions every `$ref`-sibling `description` onto the referenced
 * type's doc comment (DescriptionTypeAttributeKind.combine), so a shared type
 * like Checksum ends up with a grab-bag of unrelated per-use sentences. Per JSON
 * Schema 2020-12 a `$ref`-sibling description annotates the referencing FIELD,
 * not the referenced type — and every other generator (go-jsonschema,
 * oapi-codegen, json-schema-to-typescript, datamodel-code-generator) treats it
 * that way. quicktype has no flag to disable the union, so we correct its output:
 * force each generated type's doc comment to equal its own `$def` description.
 * The per-field docs quicktype already emits correctly are left untouched.
 */

/** Collapse a title / generated type name to a casing- and separator-insensitive
 * key, so "External Evidence Reference", "ExternalEvidenceReference", and
 * "SBOMCoverage" all match their `$def`. */
function normKey(s: string): string {
  return s.replace(/[^a-zA-Z0-9]/g, '').toLowerCase();
}

/** normKey(title) -> the `$def`'s own description, for every source `$def` that
 * carries both a title and a description. A title that collides on two different
 * descriptions is dropped (ambiguous — leave those types alone). */
function canonicalTypeDescriptions(): Map<string, string> {
  const byKey = new Map<string, string>();
  const dropped = new Set<string>();
  const walkDir = (dir: string): string[] => {
    const out: string[] = [];
    for (const e of readdirSync(dir, { withFileTypes: true })) {
      const p = join(dir, e.name);
      if (e.isDirectory()) out.push(...walkDir(p));
      else if (e.name.endsWith('.schema.json')) out.push(p);
    }
    return out;
  };
  const add = (title?: string, description?: string): void => {
    if (!title || !description) return;
    const key = normKey(title);
    const desc = description.replace(/\s+/g, ' ').trim();
    if (byKey.has(key) && byKey.get(key) !== desc) dropped.add(key);
    else byKey.set(key, desc);
  };
  for (const file of walkDir(join(__dirname, 'schemas'))) {
    const schema = JSON.parse(readFileSync(file, 'utf-8')) as {
      title?: string;
      description?: string;
      $defs?: Record<string, { title?: string; description?: string }>;
    };
    // Root document type (e.g. HDF Baseline) — quicktype can union an allOf-extended
    // base type's description onto it, same grab-bag symptom.
    add(schema.title, schema.description);
    for (const def of Object.values(schema.$defs ?? {})) {
      if (def && typeof def === 'object') add(def.title, def.description);
    }
  }
  for (const k of dropped) byKey.delete(k);
  return byKey;
}

/** Wrap a description as `// ` comment lines at ~100 cols (quicktype's width). */
function wrapComment(text: string, linePrefix: string): string[] {
  const lines: string[] = [];
  let cur = linePrefix;
  for (const w of text.split(' ')) {
    if (cur !== linePrefix && (cur + ' ' + w).length > 100) {
      lines.push(cur);
      cur = linePrefix;
    }
    cur += (cur === linePrefix ? ' ' : ' ') + w;
  }
  lines.push(cur);
  return lines;
}

/** Replace each generated type's doc comment with its own `$def` description,
 * dropping quicktype's cross-reference description union. Exported for testing. */
export function normalizeSharedTypeDocs(source: string, lang: 'go' | 'typescript'): string {
  const byKey = canonicalTypeDescriptions();
  if (lang === 'go') {
    return source.replace(
      /(?:^\/\/[^\n]*\n)+(type (\w+) )/gm,
      (m, decl: string, name: string) => {
        const canon = byKey.get(normKey(name));
        return canon ? wrapComment(canon, '//').join('\n') + '\n' + decl : m;
      },
    );
  }
  // Anchor to a column-0 JSDoc block immediately before a column-0 export — a
  // type doc. Field JSDocs are indented, so `^/**` never matches them (and an
  // unanchored match would let `[\s\S]*?` swallow the interface body).
  return source.replace(
    /^\/\*\*\n(?: \*[^\n]*\n)* \*\/\n(export (?:interface|type|enum) (\w+))/gm,
    (m, decl: string, name: string) => {
      const canon = byKey.get(normKey(name));
      return canon ? '/**\n' + wrapComment(canon, ' *').join('\n') + '\n */\n' + decl : m;
    },
  );
}

/** A plain-string identity property lifted from Host_Component. */
export interface IdentityField {
  name: string;
  description: string;
}

/**
 * Collect the plain-string properties Host_Component declares — the identity
 * fields (`hostname`, `fqdn`, `domain`, …) the reconciler guarantees on the
 * generated `Component` interface. Exported for unit testing.
 */
export function hostIdentityStringFields(compSchema: unknown): IdentityField[] {
  const host = (compSchema as Record<string, Record<string, unknown>>)?.$defs?.Host_Component as
    | { allOf?: Array<Record<string, unknown>> }
    | undefined;
  const branch = (host?.allOf ?? []).find(
    (b) => b && typeof b === 'object' && 'properties' in b
  );
  const props = (branch?.properties ?? {}) as Record<string, Record<string, unknown>>;
  return Object.entries(props)
    .filter(([, def]) => def?.type === 'string')
    .map(([name, def]) => ({ name, description: String(def.description ?? '').replace(/\s+/g, ' ').trim() }));
}

/**
 * Insert any missing `fields` into the generated `Component` interface as
 * optional properties. Idempotent — a field already present is left untouched;
 * returns `tsSource` unchanged if there is no `Component` interface or nothing
 * to add. Exported for unit testing.
 */
export function insertComponentFields(tsSource: string, fields: IdentityField[]): string {
  const header = 'export interface Component {';
  const start = tsSource.indexOf(header);
  if (start === -1) return tsSource;
  const bodyStart = start + header.length;
  const close = tsSource.indexOf('\n}', bodyStart);
  if (close === -1) return tsSource;
  const block = tsSource.slice(bodyStart, close);

  const additions = fields
    .filter((f) => !new RegExp(`\\n\\s*${f.name}\\?:`).test(block))
    .map((f) => {
      const doc = f.description ? `    /**\n     * ${f.description}\n     */\n` : '';
      return `${doc}    ${f.name}?: string;`;
    });
  if (additions.length === 0) return tsSource;

  return tsSource.slice(0, close) + '\n' + additions.join('\n') + tsSource.slice(close);
}

/**
 * Reinstate Host_Component identity fields the TypeScript renderer drops.
 *
 * quicktype builds an independent type graph per language, and its TS renderer
 * unifies same-named properties across unrelated types — so Host_Component's
 * `hostname` (collides with Runner.hostname) and `domain` (collides with
 * Signature.domain) get attributed to those types and vanish from the flattened
 * `Component` interface, while `fqdn` (no such collision) survives. The Go
 * renderer keeps all three. This reconciles the TS output back to the schema.
 */
function reinstateComponentIdentityFields(tsSource: string): string {
  const compSchemaPath = join(
    __dirname, 'schemas', 'primitives', 'component.schema.json'
  );
  const compSchema = JSON.parse(readFileSync(compSchemaPath, 'utf-8'));
  return insertComponentFields(tsSource, hostIdentityStringFields(compSchema));
}

/**
 * Generate go.mod file for the Go types package.
 */
function generateGoMod(outputDir: string): void {
  const goModContent = `// Code generated by hdf-schema build. DO NOT EDIT.
module github.com/mitre/hdf-libs/hdf-schema/dist/go/v3

go 1.26
`;
  writeFileSync(join(outputDir, 'go.mod'), goModContent);
}

/**
 * Generate types for all schemas in all languages (combined output).
 */
export async function generateTypes(): Promise<void> {
  if (!existsSync(DIST_SCHEMAS_DIR)) {
    throw new Error(
      'Bundled schemas not found. Run `pnpm build:schemas` first.'
    );
  }

  // Collect schemas once — same set for all languages
  const schemasToGenerate: Array<{ path: string; name: string }> = [];
  for (const schema of SCHEMAS) {
    const schemaPath = join(DIST_SCHEMAS_DIR, schema.file);
    if (!existsSync(schemaPath)) {
      console.warn(`  Skipping ${schema.file} (not found)`);
      continue;
    }
    schemasToGenerate.push({ path: schemaPath, name: schema.name });
  }

  if (schemasToGenerate.length === 0) {
    throw new Error('No schemas found in dist/schemas/');
  }

  // Preprocess each schema once (output is deterministic), then build a fresh
  // JSONSchemaInput per language inside Promise.all — quicktype mutates its
  // input's internal state, so the two languages cannot share one input.
  const preprocessed = schemasToGenerate.map((schema) => ({
    name: schema.name,
    schema: preprocessSchemaForQuicktype(readFileSync(schema.path, 'utf-8')),
  }));

  await Promise.all(LANGUAGES.map(async (lang) => {
    const outputDir = join(DIST_DIR, lang.dir);
    if (!existsSync(outputDir)) {
      mkdirSync(outputDir, { recursive: true });
    }

    console.log(`Generating ${lang.name} types...`);

    const langSchemaInput = new JSONSchemaInput(new FetchingJSONSchemaStore());
    for (const entry of preprocessed) {
      await langSchemaInput.addSource(entry);
    }

    const inputData = new InputData();
    inputData.addInput(langSchemaInput);

    const result = await quicktype({
      inputData,
      lang: lang.name as 'typescript' | 'go',
      rendererOptions: lang.options,
    });

    const ext = lang.name === 'go' ? 'go' : 'ts';
    const outputPath = join(outputDir, `hdf.${ext}`);
    let output = result.lines.join('\n');
    output = normalizeSharedTypeDocs(output, lang.name as 'go' | 'typescript');
    if (lang.name === 'typescript') {
      output = reinstateComponentIdentityFields(output);
    }
    writeFileSync(outputPath, output);
    console.log(`  → ${outputPath}`);

    if (lang.name === 'go') {
      generateGoMod(outputDir);
    }
  }));

  console.log('Done.');
}

// Run if called directly
/* c8 ignore start */
if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  generateTypes().catch((err) => {
    console.error('Type generation failed:', err);
    process.exit(1);
  });
}
/* c8 ignore stop */
