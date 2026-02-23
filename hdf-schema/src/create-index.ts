/**
 * Script to create index.js and index.d.ts files after type generation
 */
import { writeFileSync, copyFileSync, existsSync, rmSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { execSync } from 'child_process';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const ROOT_DIR = join(__dirname, '..');

export interface CreateIndexOptions {
  /** Override the compile step (for testing) */
  compile?: (cwd: string) => void;
}

export function createIndex(options: CreateIndexOptions = {}): void {
  // Check if TypeScript files exist before compiling
  const tsDir = join(ROOT_DIR, 'dist/ts');
  const resultsTs = join(tsDir, 'hdf-results.ts');
  const baselineTs = join(tsDir, 'hdf-baseline.ts');

  if (!existsSync(resultsTs) || !existsSync(baselineTs)) {
    // eslint-disable-next-line no-console
    console.warn('Skipping index creation: TypeScript files not found');
    return;
  }

  // Clean stale .d.ts and .js output so tsc doesn't refuse to overwrite its own input
  for (const name of ['hdf-results', 'hdf-baseline']) {
    for (const ext of ['.d.ts', '.js']) {
      const file = join(tsDir, `${name}${ext}`);
      if (existsSync(file)) {
        rmSync(file);
      }
    }
  }

  // Compile TypeScript files in dist/ts to JavaScript
  // This creates .js and .d.ts files from the generated .ts files
  const compile = options.compile ?? ((cwd: string) => {
    execSync('tsc dist/ts/*.ts --declaration --module esnext --target es2020 --moduleResolution bundler --skipLibCheck', {
      cwd,
      stdio: 'inherit',
    });
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

  if (existsSync(helpersJs)) {
    copyFileSync(helpersJs, join(ROOT_DIR, 'dist/helpers.js'));
  }
  if (existsSync(helpersDts)) {
    copyFileSync(helpersDts, join(ROOT_DIR, 'dist/helpers.d.ts'));
  }

  // index.d.ts uses named type exports (valid in declaration files)
  const indexDtsContent = `/**
 * Main entry point for @mitre/hdf-schema
 * Re-exports all types from generated TypeScript definitions
 */

// Re-export all types from hdf-results (includes most common types)
export * from './ts/hdf-results.js';

// Re-export baseline-only types (interfaces not in hdf-results).
// No export * from hdf-baseline — its enums (HashAlgorithm, Severity) duplicate
// hdf-results and cause ambiguous-export collisions.
export type { HdfBaseline, BaselineRequirement } from './ts/hdf-baseline.js';

// Re-export helper functions
export * from './helpers.js';
`;

  // index.js uses only export * (named exports of type-only symbols crash Node ESM).
  // hdf-baseline.js only contains enums (HashAlgorithm, Severity) that are already
  // exported by hdf-results.js, so we skip it to avoid ESM ambiguous-export collisions.
  const indexJsContent = `/**
 * Main entry point for @mitre/hdf-schema
 * Re-exports all types from generated TypeScript definitions
 */

// Re-export all values from hdf-results (enums like ResultStatus, HashAlgorithm, Severity)
export * from './ts/hdf-results.js';

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
if (import.meta.url === `file://${process.argv[1]}`) {
  createIndex();
}
