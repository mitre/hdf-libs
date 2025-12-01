import $RefParser from '@apidevtools/json-schema-ref-parser';
import { readFileSync, writeFileSync, mkdirSync, existsSync, readdirSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const SCHEMAS_DIR = join(__dirname, 'schemas');
const PRIMITIVES_DIR = join(SCHEMAS_DIR, 'primitives');
const DIST_DIR = join(__dirname, '..', 'dist', 'schemas');

// Main schemas to bundle (these have $ref to primitives)
const MAIN_SCHEMAS = ['hdf-results.schema.json', 'hdf-baseline.schema.json'];

/**
 * Load all primitive schemas and create a resolver that maps
 * our custom URIs to local file contents.
 */
function createResolver() {
  const primitiveSchemas = new Map<string, object>();

  // Load all primitive schemas
  const primitiveFiles = readdirSync(PRIMITIVES_DIR).filter((f) => f.endsWith('.schema.json'));
  for (const file of primitiveFiles) {
    const content = JSON.parse(readFileSync(join(PRIMITIVES_DIR, file), 'utf-8'));
    const id = content.$id as string;
    if (id) {
      primitiveSchemas.set(id, content);
    }
  }

  return {
    order: 1,
    canRead: /^https:\/\/hdf\.aesirsystems\.com\/schemas\//,
    read: (file: { url: string }) => {
      // Extract the base URL (without fragment)
      const url = file.url.split('#')[0] ?? file.url;

      // Find matching schema by $id
      const schema = primitiveSchemas.get(url);
      if (!schema) {
        throw new Error(`Could not resolve schema: ${url}`);
      }
      return JSON.stringify(schema);
    },
  };
}

/**
 * Bundle a schema by resolving all $ref and inlining definitions.
 */
async function bundleSchema(schemaPath: string): Promise<object> {
  const parser = new $RefParser();

  const bundled = await parser.bundle(schemaPath, {
    resolve: {
      aesir: createResolver(),
    },
  });

  return bundled;
}

/**
 * Bundle all main schemas and write to dist directory.
 */
export async function bundleSchemas(): Promise<void> {
  // Create dist directory
  if (!existsSync(DIST_DIR)) {
    mkdirSync(DIST_DIR, { recursive: true });
  }

  for (const schemaFile of MAIN_SCHEMAS) {
    const inputPath = join(SCHEMAS_DIR, schemaFile);
    const outputPath = join(DIST_DIR, schemaFile);

    console.log(`Bundling ${schemaFile}...`);

    const bundled = await bundleSchema(inputPath);

    writeFileSync(outputPath, JSON.stringify(bundled, null, 2));

    console.log(`  → ${outputPath}`);
  }

  console.log('Done.');
}

// Run if called directly
if (import.meta.url === `file://${process.argv[1]}`) {
  bundleSchemas().catch((err) => {
    console.error('Bundle failed:', err);
    process.exit(1);
  });
}
