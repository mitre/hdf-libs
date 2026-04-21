import { mkdirSync, existsSync, writeFileSync, readFileSync } from 'fs';
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

// Schemas to generate types for
const SCHEMAS = [
  { file: 'hdf-results.schema.json', name: 'HdfResults' },
  { file: 'hdf-baseline.schema.json', name: 'HdfBaseline' },
  { file: 'hdf-comparison.schema.json', name: 'HdfComparison' },
  { file: 'hdf-system.schema.json', name: 'HdfSystem' },
  { file: 'hdf-plan.schema.json', name: 'HdfPlan' },
  { file: 'hdf-amendments.schema.json', name: 'HdfAmendments' },
  { file: 'hdf-evidence-package.schema.json', name: 'HdfEvidencePackage' },
];

// Language configurations
const LANGUAGES = [
  { name: 'typescript', dir: 'ts', ext: 'ts', options: { 'just-types': true } },
  { name: 'go', dir: 'go', ext: 'go', options: { package: 'hdf' } },
];

/**
 * Convert a schema filename to output filename for a given language.
 */
export function toOutputFilename(schemaFile: string, ext: string): string {
  // hdf-results.schema.json -> hdf-results.ts or hdf_results.go
  const base = schemaFile.replace('.schema.json', '');
  if (ext === 'go') {
    return base.replace(/-/g, '_') + '.' + ext;
  }
  return base + '.' + ext;
}

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

    // Remove const from boolean properties (quicktype chokes on const: true)
    if (obj['type'] === 'boolean' && 'const' in obj) {
      const { const: _, ...rest } = obj;
      void _;
      return walk(rest);
    }

    // Simplify oneOf containing a bare primitive alongside $ref objects:
    // Replace the entire oneOf with a permissive type so quicktype can proceed.
    if (Array.isArray(obj['oneOf'])) {
      const items = obj['oneOf'] as Array<Record<string, unknown>>;
      const hasBare = items.some(
        (i) => typeof i['type'] === 'string' && !i['$ref']
      );
      const hasRef = items.some((i) => '$ref' in i);
      if (hasBare && hasRef) {
        // Collapse to a permissive union — quicktype will generate an "any" variant
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
 * Generate types for a single schema in a single language.
 */
async function generateForLanguage(
  schemaPath: string,
  typeName: string,
  language: string,
  options: Record<string, unknown>
): Promise<string> {
  const schemaContent = preprocessSchemaForQuicktype(readFileSync(schemaPath, 'utf-8'));

  const schemaInput = new JSONSchemaInput(new FetchingJSONSchemaStore());
  await schemaInput.addSource({ name: typeName, schema: schemaContent });

  const inputData = new InputData();
  inputData.addInput(schemaInput);

  const result = await quicktype({
    inputData,
    lang: language as 'typescript' | 'go',
    rendererOptions: options as Record<string, string>,
  });

  return result.lines.join('\n');
}

/**
 * Generate types for multiple schemas combined into a single file.
 * Used for Go to avoid duplicate type declarations.
 */
async function generateCombinedForLanguage(
  schemas: Array<{ path: string; name: string }>,
  language: string,
  options: Record<string, unknown>
): Promise<string> {
  const schemaInput = new JSONSchemaInput(new FetchingJSONSchemaStore());

  for (const schema of schemas) {
    const schemaContent = preprocessSchemaForQuicktype(readFileSync(schema.path, 'utf-8'));
    await schemaInput.addSource({ name: schema.name, schema: schemaContent });
  }

  const inputData = new InputData();
  inputData.addInput(schemaInput);

  const result = await quicktype({
    inputData,
    lang: language as 'typescript' | 'go',
    rendererOptions: options as Record<string, string>,
  });

  return result.lines.join('\n');
}

/**
 * Add backward-compatible aliases for Go enum constants whose names changed
 * when quicktype regenerated with a different schema set.
 * These aliases let existing converter code compile without changes.
 */
function addGoEnumAliases(code: string): string {
  const aliases: Array<{ constant: string; alias: string; type: string }> = [];

  // Check which constants exist and add aliases for the old names
  const aliasMap: Record<string, { old: string; type: string }> = {
    'Application': { old: 'CopyrightApplication', type: 'Copyright' },
  };

  for (const [newName, { old, type }] of Object.entries(aliasMap)) {
    // Only add alias if the new name exists and the old name doesn't
    const constRegex = new RegExp(`\\b${newName}\\s+${type}\\s*=`);
    const oldRegex = new RegExp(`\\b${old}\\s+${type}\\s*=`);
    if (constRegex.test(code) && !oldRegex.test(code)) {
      aliases.push({ constant: newName, alias: old, type });
    }
  }

  if (aliases.length === 0) return code;

  const block = aliases
    .map((a) => `\t${a.alias} = ${a.constant}`)
    .join('\n');

  return code + `\n// Backward-compatible aliases for renamed constants.\nconst (\n${block}\n)\n`;
}

/**
 * Add omitempty tags to optional pointer fields in generated Go code.
 * This ensures that nil/null fields are omitted from JSON output, matching
 * the discriminated union semantics of the schema.
 */
function addOmitemptyToGoCode(code: string): string {
  // Pattern matches Go struct fields with pointer types or interface{} and json tags
  // Example: FQDN *string `json:"fqdn"` or Sbom interface{} `json:"sbom"`
  // Captures: field name, type, json tag name
  const fieldPattern = /(\w+)\s+(\*\w+(?:<[^>]+>)?|\*time\.Time|interface\{\})\s+`json:"([^"]+)"`/g;

  return code.replace(fieldPattern, (match, fieldName, fieldType, jsonTag) => {
    // Only add omitempty if not already present
    if (jsonTag.includes('omitempty')) {
      return match;
    }

    // Add omitempty to the json tag
    const newJsonTag = `${jsonTag},omitempty`;
    return `${fieldName} ${fieldType} \`json:"${newJsonTag}"\``;
  });
}

/**
 * Generate go.mod file for the Go types package.
 */
function generateGoMod(outputDir: string): void {
  const goModContent = `// Code generated by hdf-schema build. DO NOT EDIT.
module github.com/mitre/hdf-schema

go 1.23
`;
  const goModPath = join(outputDir, 'go.mod');
  writeFileSync(goModPath, goModContent);
  console.log(`  → ${goModPath}`);
}

/**
 * Generate types for all schemas in all languages.
 */
export async function generateTypes(): Promise<void> {
  // Ensure bundled schemas exist
  if (!existsSync(DIST_SCHEMAS_DIR)) {
    throw new Error(
      'Bundled schemas not found. Run `pnpm build:schemas` first.'
    );
  }

  for (const lang of LANGUAGES) {
    const outputDir = join(DIST_DIR, lang.dir);

    // Create output directory
    if (!existsSync(outputDir)) {
      mkdirSync(outputDir, { recursive: true });
    }

    console.log(`Generating ${lang.name} types...`);

    // For Go, combine all schemas into a single file to avoid duplicate types
    if (lang.name === 'go') {
      const schemasToGenerate: Array<{ path: string; name: string }> = [];

      for (const schema of SCHEMAS) {
        const schemaPath = join(DIST_SCHEMAS_DIR, schema.file);
        if (!existsSync(schemaPath)) {
          console.warn(`  Skipping ${schema.file} (not found)`);
          continue;
        }
        schemasToGenerate.push({ path: schemaPath, name: schema.name });
      }

      if (schemasToGenerate.length > 0) {
        try {
          let code = await generateCombinedForLanguage(
            schemasToGenerate,
            lang.name,
            lang.options
          );

          // Add omitempty tags to optional fields for discriminated union support
          code = addOmitemptyToGoCode(code);
          // Add backward-compatible aliases for renamed enum constants
          code = addGoEnumAliases(code);

          const outputPath = join(outputDir, 'hdf.go');
          writeFileSync(outputPath, code);
          console.log(`  → ${outputPath}`);
        } catch (err) {
          console.warn(`  Combined Go generation failed: ${(err as Error).message}`);
          console.warn('  Retrying with individually-validated schemas...');

          // Probe each schema individually to find which ones quicktype can handle
          const validSchemas: Array<{ path: string; name: string }> = [];
          for (const schema of schemasToGenerate) {
            try {
              await generateForLanguage(schema.path, schema.name, lang.name, lang.options);
              validSchemas.push(schema);
            } catch (probeErr) {
              console.warn(`  Excluding ${schema.name} (quicktype error: ${(probeErr as Error).message})`);
            }
          }

          // Re-combine only the schemas that passed probing
          if (validSchemas.length > 0) {
            let code = await generateCombinedForLanguage(
              validSchemas,
              lang.name,
              lang.options
            );

            code = addOmitemptyToGoCode(code);
            code = addGoEnumAliases(code);

            const outputPath = join(outputDir, 'hdf.go');
            writeFileSync(outputPath, code);
            console.log(`  → ${outputPath} (${validSchemas.length}/${schemasToGenerate.length} schemas)`);
          }
        }
      }

      generateGoMod(outputDir);
      continue;
    }

    // For other languages, generate separate files per schema
    for (const schema of SCHEMAS) {
      const schemaPath = join(DIST_SCHEMAS_DIR, schema.file);
      const outputFile = toOutputFilename(schema.file, lang.ext);
      const outputPath = join(outputDir, outputFile);

      if (!existsSync(schemaPath)) {
        console.warn(`  Skipping ${schema.file} (not found)`);
        continue;
      }

      try {
        const code = await generateForLanguage(
          schemaPath,
          schema.name,
          lang.name,
          lang.options
        );

        writeFileSync(outputPath, code);
        console.log(`  → ${outputPath}`);
      } catch (err) {
        console.warn(`  Skipping ${schema.file} (quicktype error: ${(err as Error).message})`);
      }
    }
  }

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
