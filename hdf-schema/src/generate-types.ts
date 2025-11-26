import { mkdirSync, existsSync, writeFileSync, readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
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
];

// Language configurations
const LANGUAGES = [
  { name: 'typescript', dir: 'ts', ext: 'ts', options: { 'just-types': true } },
  { name: 'go', dir: 'go', ext: 'go', options: { package: 'hdf' } },
  { name: 'python', dir: 'python', ext: 'py', options: { 'python-version': '3.7' } },
];

/**
 * Convert a schema filename to output filename for a given language.
 */
function toOutputFilename(schemaFile: string, ext: string): string {
  // hdf-results.schema.json -> hdf-results.ts or hdf_results.go
  const base = schemaFile.replace('.schema.json', '');
  if (ext === 'go' || ext === 'py') {
    return base.replace(/-/g, '_') + '.' + ext;
  }
  return base + '.' + ext;
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
  const schemaContent = readFileSync(schemaPath, 'utf-8');

  const schemaInput = new JSONSchemaInput(new FetchingJSONSchemaStore());
  await schemaInput.addSource({ name: typeName, schema: schemaContent });

  const inputData = new InputData();
  inputData.addInput(schemaInput);

  const result = await quicktype({
    inputData,
    lang: language,
    rendererOptions: options as Record<string, string>,
  });

  return result.lines.join('\n');
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

    for (const schema of SCHEMAS) {
      const schemaPath = join(DIST_SCHEMAS_DIR, schema.file);
      const outputFile = toOutputFilename(schema.file, lang.ext);
      const outputPath = join(outputDir, outputFile);

      if (!existsSync(schemaPath)) {
        console.warn(`  Skipping ${schema.file} (not found)`);
        continue;
      }

      const code = await generateForLanguage(
        schemaPath,
        schema.name,
        lang.name,
        lang.options
      );

      writeFileSync(outputPath, code);
      console.log(`  → ${outputPath}`);
    }
  }

  console.log('Done.');
}

// Run if called directly
if (import.meta.url === `file://${process.argv[1]}`) {
  generateTypes().catch((err) => {
    console.error('Type generation failed:', err);
    process.exit(1);
  });
}
