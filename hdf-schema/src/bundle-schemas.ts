import { registerSchema } from '@hyperjump/json-schema/draft-2020-12';
import { bundle } from '@hyperjump/json-schema/bundle';
import { readFileSync, writeFileSync, mkdirSync, existsSync, readdirSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const SCHEMAS_DIR = join(__dirname, 'schemas');
const PRIMITIVES_DIR = join(SCHEMAS_DIR, 'primitives');
const DIST_DIR = join(__dirname, '..', 'dist', 'schemas');

// Main schemas to bundle (these have $ref to primitives)
const MAIN_SCHEMAS = ['hdf-results.schema.json', 'hdf-baseline.schema.json', 'hdf-comparison.schema.json'];

/**
 * Load and register all schemas with @hyperjump/json-schema.
 * This allows the bundler to resolve $refs by $id.
 */
function registerAllSchemas(): void {
  // Load and register all primitive schemas
  const primitiveFiles = readdirSync(PRIMITIVES_DIR).filter((f) => f.endsWith('.schema.json'));
  for (const file of primitiveFiles) {
    const filePath = join(PRIMITIVES_DIR, file);
    const content = JSON.parse(readFileSync(filePath, 'utf-8'));
    const id = content.$id as string;
    if (id) {
      registerSchema(content, id);
    }
  }

  // Load and register main schemas
  for (const schemaFile of MAIN_SCHEMAS) {
    const filePath = join(SCHEMAS_DIR, schemaFile);
    const content = JSON.parse(readFileSync(filePath, 'utf-8'));
    const id = content.$id as string;
    if (id) {
      registerSchema(content, id);
    }
  }
}

/**
 * Bundle a schema using @hyperjump/json-schema.
 * This follows the official JSON Schema 2020-12 bundling specification.
 */
async function bundleSchema(schemaId: string): Promise<object> {
  const bundled = await bundle(schemaId, {
    // Use URI-based naming for embedded schemas
    definitionNamingStrategy: 'uri',
    // Always include dialect for clarity
    alwaysIncludeDialect: true,
  });

  return bundled;
}

/**
 * Bundle all main schemas and write to dist directory.
 */
export async function bundleSchemas(): Promise<void> {
  // Register all schemas first so the bundler can resolve $refs
  registerAllSchemas();

  // Create dist directory
  if (!existsSync(DIST_DIR)) {
    mkdirSync(DIST_DIR, { recursive: true });
  }

  for (const schemaFile of MAIN_SCHEMAS) {
    const inputPath = join(SCHEMAS_DIR, schemaFile);
    const outputPath = join(DIST_DIR, schemaFile);

    // Read the schema to get its $id
    const content = JSON.parse(readFileSync(inputPath, 'utf-8'));
    const schemaId = content.$id as string;

    console.log(`Bundling ${schemaFile}...`);

    const bundled = await bundleSchema(schemaId);

    writeFileSync(outputPath, JSON.stringify(bundled, null, 2));

    console.log(`  → ${outputPath}`);
  }

  console.log('Done.');
}

// Run if called directly
/* c8 ignore start */
if (import.meta.url === `file://${process.argv[1]}`) {
  bundleSchemas().catch((err) => {
    console.error('Bundle failed:', err);
    process.exit(1);
  });
}
/* c8 ignore stop */
