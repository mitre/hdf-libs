/**
 * Script to create index.js and index.d.ts files after type generation.
 *
 * Also inlines all 21 source schemas (7 main + 14 primitives) as named
 * JS exports, so downstream consumers (notably @mitre/hdf-validators) can
 * do `import { hdfResultsSchema, commonSchema, ... } from '@mitre/hdf-schema'`
 * and pick them up as plain JS objects — no JSON imports, no
 * bundler-specific configuration, no duplication across consuming
 * packages.
 */
import { writeFileSync, copyFileSync, existsSync, rmSync, readdirSync, readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath, pathToFileURL } from 'url';
import { execSync } from 'child_process';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const ROOT_DIR = join(__dirname, '..');

/** Convert kebab-case filename stem to camelCase identifier. */
function toCamel(stem: string): string {
  return stem.replace(/-([a-z])/g, (_, c: string) => c.toUpperCase());
}

/**
 * Compute the exported identifier for a schema filename.
 * Kebab-case stems like `hdf-results` become `hdfResults`, then get the
 * literal `Schema` suffix appended: `hdfResultsSchema`. Primitives work
 * the same way: `data-flow` -> `dataFlowSchema`.
 */
function schemaExportName(filename: string): string {
  const stem = filename.replace(/\.schema\.json$/, '');
  return `${toCamel(stem)}Schema`;
}

/**
 * Read every source schema JSON and emit it as a named JS export. Returns
 * matched `.js` and `.d.ts` fragments ready to be spliced into the
 * generated index files. Exports are source-format (with $refs intact) to
 * preserve the validator contract: consumers register each schema
 * independently with AJV, which resolves the refs at runtime.
 */
function generateSchemaExports(rootDir: string): { js: string; dts: string } {
  const schemasDir = join(rootDir, 'src/schemas');
  const primitivesDir = join(schemasDir, 'primitives');

  const mainFiles = readdirSync(schemasDir)
    .filter((f) => f.endsWith('.schema.json'))
    .sort();
  const primitiveFiles = readdirSync(primitivesDir)
    .filter((f) => f.endsWith('.schema.json'))
    .sort();

  const jsLines: string[] = [];
  const dtsLines: string[] = [];

  const entries: { exportName: string; path: string }[] = [
    ...mainFiles.map((file) => ({
      exportName: schemaExportName(file),
      path: join(schemasDir, file),
    })),
    ...primitiveFiles.map((file) => ({
      exportName: schemaExportName(file),
      path: join(primitivesDir, file),
    })),
  ];

  for (const { exportName, path } of entries) {
    const json = JSON.parse(readFileSync(path, 'utf-8')) as Record<string, unknown>;
    jsLines.push(`export const ${exportName} = ${JSON.stringify(json)};`);
    dtsLines.push(`export declare const ${exportName}: Readonly<Record<string, unknown>>;`);
  }

  return { js: jsLines.join('\n'), dts: dtsLines.join('\n') };
}

export interface CreateIndexOptions {
  /** Override the compile step (for testing) */
  compile?: (cwd: string) => void;
}

export function createIndex(options: CreateIndexOptions = {}): void {
  // Check if TypeScript files exist before compiling
  const tsDir = join(ROOT_DIR, 'dist/ts');
  const combinedTs = join(tsDir, 'hdf.ts');

  if (!existsSync(combinedTs)) {
    // eslint-disable-next-line no-console
    console.warn('Skipping index creation: dist/ts/hdf.ts not found');
    return;
  }

  // Clean compiled output so tsc doesn't refuse to overwrite its own input
  for (const ext of ['.d.ts', '.js']) {
    const file = join(tsDir, `hdf${ext}`);
    if (existsSync(file)) {
      rmSync(file);
    }
  }

  // Compile TypeScript files in dist/ts to JavaScript
  // This creates .js and .d.ts files from the generated .ts files
  // Note: uses explicit file listing instead of glob (dist/ts/*.ts) because
  // Windows PowerShell does not expand shell globs in execSync commands.
  const compile = options.compile ?? ((cwd: string) => {
    const tsFiles = readdirSync(tsDir)
      .filter(f => f.endsWith('.ts') && !f.endsWith('.d.ts'))
      .map(f => join('dist/ts', f));
    // Write a temporary tsconfig to avoid TS6's TS5112 error when passing
    // files on the command line alongside an existing tsconfig.json.
    const tmpConfig = join(cwd, 'tsconfig.dist-types.json');
    writeFileSync(tmpConfig, JSON.stringify({
      compilerOptions: {
        declaration: true,
        module: 'ESNext',
        target: 'ES2020',
        moduleResolution: 'bundler',
        skipLibCheck: true,
      },
      files: tsFiles,
    }));
    try {
      execSync(`tsc --project ${tmpConfig}`, { cwd, stdio: 'inherit' });
    } finally {
      rmSync(tmpConfig, { force: true });
    }
  });

  try {
    compile(ROOT_DIR);
  } catch (error) {
    // eslint-disable-next-line no-console
    console.warn('Failed to compile TypeScript files:', error);
    return;
  }

  // Copy helpers to dist
  const helpersJs = join(ROOT_DIR, 'src/helpers.js');
  const helpersDts = join(ROOT_DIR, 'src/helpers.d.ts');

  copyFileSync(helpersJs, join(ROOT_DIR, 'dist/helpers.js'));
  copyFileSync(helpersDts, join(ROOT_DIR, 'dist/helpers.d.ts'));

  const schemaExports = generateSchemaExports(ROOT_DIR);

  const primarySource = './ts/hdf.js';

  const indexDtsContent = `/**
 * Main entry point for @mitre/hdf-schema
 * Re-exports all types from generated TypeScript definitions, plus the
 * 21 source schemas as named JS-object exports.
 */

// Inlined source schemas (with $refs intact — consumers register them
// individually with their JSON Schema validator to resolve cross-refs).
${schemaExports.dts}

// When combined hdf.ts is available, ALL types from all 7 schemas are in
// that single file. No per-file re-exports — mixing module paths causes
// TypeScript nominal type incompatibility (same interface from different
// .d.ts files are not assignable to each other).
export * from '${primarySource}';

// Re-export helper functions
export * from './helpers.js';

// ── Deprecated aliases for backward compatibility ──
// These will be removed in the next major version.
// Consumers should migrate to HDF* naming (matching schema titles).
/** @deprecated Use HDFResults */
export type HdfResults = HDFResults;
/** @deprecated Use HDFBaseline */
export type HdfBaseline = HDFBaseline;
/** @deprecated Use HDFComparison */
export type HdfComparison = HDFComparison;
/** @deprecated Use HDFSystem */
export type HdfSystem = HDFSystem;
/** @deprecated Use HDFPlan */
export type HdfPlan = HDFPlan;
/** @deprecated Use HDFAmendments */
export type HdfAmendments = HDFAmendments;
/** @deprecated Use HDFEvidencePackage */
export type HdfEvidencePackage = HDFEvidencePackage;
`;



  const indexJsContent = `/**
 * Main entry point for @mitre/hdf-schema
 * Re-exports all types from generated TypeScript definitions, plus the
 * 21 source schemas as named JS-object exports.
 */

// Inlined source schemas (with $refs intact — consumers register them
// individually with their JSON Schema validator to resolve cross-refs).
${schemaExports.js}

// Combined file has ALL enums and types from all 7 schemas — no per-file
// re-exports needed. Mixing module paths causes TypeScript nominal type
// incompatibility (structurally identical types from different .d.ts are not assignable).
export * from '${primarySource}';

// Re-export helper functions
export * from './helpers.js';
`;

  // Write both .js and .d.ts files to dist directory
  const distDir = join(ROOT_DIR, 'dist');
  if (existsSync(distDir)) {
    writeFileSync(join(distDir, 'index.js'), indexJsContent);
    writeFileSync(join(distDir, 'index.d.ts'), indexDtsContent);

    // eslint-disable-next-line no-console
    console.log('Created dist/index.js and dist/index.d.ts');
  }
}

// Run if called directly
/* v8 ignore next 3 -- CLI entry point, not testable in vitest */
if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  createIndex();
}
