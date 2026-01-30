/**
 * Script to create index.js and index.d.ts files after type generation
 */
import { writeFileSync, copyFileSync, existsSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { execSync } from 'child_process';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const ROOT_DIR = join(__dirname, '..');

export function createIndex(): void {
  // Check if TypeScript files exist before compiling
  const tsDir = join(ROOT_DIR, 'dist/ts');
  const resultsTs = join(tsDir, 'hdf-results.ts');
  const baselineTs = join(tsDir, 'hdf-baseline.ts');

  if (!existsSync(resultsTs) || !existsSync(baselineTs)) {
    // eslint-disable-next-line no-console
    console.warn('Skipping index creation: TypeScript files not found');
    return;
  }

  // Compile TypeScript files in dist/ts to JavaScript
  // This creates .js and .d.ts files from the generated .ts files
  try {
    execSync('tsc dist/ts/*.ts --declaration --module esnext --target es2020 --moduleResolution bundler --skipLibCheck', {
      cwd: ROOT_DIR,
      stdio: 'inherit',
    });
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

  const indexContent = `/**
 * Main entry point for @mitre/hdf-schema
 * Re-exports all types from generated TypeScript definitions
 */

// Re-export all types from hdf-results (includes most common types)
export * from './ts/hdf-results.js';

// Re-export HdfBaseline specifically from hdf-baseline
export { HdfBaseline, BaselineRequirement } from './ts/hdf-baseline.js';

// Re-export helper functions
export * from './helpers.js';
`;

  // Write both .js and .d.ts files to dist directory
  const distDir = join(ROOT_DIR, 'dist');
  if (existsSync(distDir)) {
    writeFileSync(join(distDir, 'index.js'), indexContent);
    writeFileSync(join(distDir, 'index.d.ts'), indexContent);

    // eslint-disable-next-line no-console
    console.log('Created dist/index.js and dist/index.d.ts');
  }
}

// Run if called directly
if (import.meta.url === `file://${process.argv[1]}`) {
  createIndex();
}
