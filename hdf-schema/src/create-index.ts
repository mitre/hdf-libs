/**
 * Script to create index.js and index.d.ts files after type generation
 */
import { writeFileSync, copyFileSync, existsSync, rmSync, readdirSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath, pathToFileURL } from 'url';
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
  const comparisonTs = join(tsDir, 'hdf-comparison.ts');

  if (!existsSync(resultsTs) || !existsSync(baselineTs)) {
    // eslint-disable-next-line no-console
    console.warn('Skipping index creation: TypeScript files not found');
    return;
  }

  // Clean stale .d.ts and .js output so tsc doesn't refuse to overwrite its own input
  for (const name of ['hdf-results', 'hdf-baseline', 'hdf-comparison', 'hdf-system', 'hdf-plan', 'hdf-amendments', 'hdf-evidence-package']) {
    for (const ext of ['.d.ts', '.js']) {
      const file = join(tsDir, `${name}${ext}`);
      if (existsSync(file)) {
        rmSync(file);
      }
    }
  }

  // Compile TypeScript files in dist/ts to JavaScript
  // This creates .js and .d.ts files from the generated .ts files
  // Note: uses explicit file listing instead of glob (dist/ts/*.ts) because
  // Windows PowerShell does not expand shell globs in execSync commands.
  const compile = options.compile ?? ((cwd: string) => {
    const tsFiles = readdirSync(tsDir)
      .filter(f => f.endsWith('.ts') && !f.endsWith('.d.ts'))
      .map(f => join('dist/ts', f))
      .join(' ');
    if (!tsFiles) {
      throw new Error('No .ts files found in dist/ts/');
    }
    execSync(`tsc ${tsFiles} --declaration --module esnext --target es2020 --moduleResolution bundler --skipLibCheck`, {
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

  // Determine if comparison types are available
  const hasComparison = existsSync(comparisonTs);

  // index.d.ts uses named type exports (valid in declaration files)
  // No export * from hdf-comparison — its shared types (Checksum, Target, Severity, etc.)
  // duplicate hdf-results and cause ambiguous-export collisions.
  // Only export comparison-unique types.
  const comparisonDtsExport = hasComparison
    ? `
// Re-export comparison-specific types (interfaces and enums not in hdf-results).
// No export * from hdf-comparison — shared types duplicate hdf-results.
export type {
  HdfComparison, RequirementDiff, ComparisonSummary, Source,
  Annotation, BaselineDiff, BaselineRef, ComponentDiff, FieldChange, MatchingConfig,
  PackageDiff, ScannerConflict, SeverityBreakdown, StateCounts, PerSourceSummary,
  Value,
} from './ts/hdf-comparison.js';
export {
  AnnotationCategory, BaselineDiffState, ChangeReason, ComparisonMode,
  ConflictResolution, FormatVersion, MatchStrategy, Op, OriginalFormat,
  PackageDiffState, RequirementState, SourceRole, Type,
} from './ts/hdf-comparison.js';
`
    : '';

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
${comparisonDtsExport}
// Re-export system types
// No Component re-export — it's already exported by hdf-results.js via export *
export type {
  HdfSystem, InputOverride, ControlDesignation, DataFlow,
} from './ts/hdf-system.js';
export {
  AuthorizationStatus, BoundaryDescription, CategorizationLevel, Designation, Direction,
} from './ts/hdf-system.js';

// Re-export plan types
export type {
  HdfPlan, Assessment, Schedule, RunnerConfig,
} from './ts/hdf-plan.js';
export {
  PlanType,
} from './ts/hdf-plan.js';

// Re-export amendments types
// No OverrideType enum — already exported by hdf-results via export *.
export type {
  HdfAmendments, StandaloneOverride,
} from './ts/hdf-amendments.js';

// Re-export evidence-package types
export type {
  HdfEvidencePackage, ContentReference, CompletenessCheck, SBOMCoverage,
} from './ts/hdf-evidence-package.js';
export {
  ContentType,
} from './ts/hdf-evidence-package.js';

// Re-export helper functions
export * from './helpers.js';
`;

  // index.js uses only export * (named exports of type-only symbols crash Node ESM).
  // hdf-baseline.js only contains enums (HashAlgorithm, Severity) that are already
  // exported by hdf-results.js, so we skip it to avoid ESM ambiguous-export collisions.
  // hdf-comparison.js has overlapping enums too, so we use named exports for unique enums only.
  const comparisonJsExport = hasComparison
    ? `
// Re-export comparison-specific enums (runtime values not in hdf-results)
export {
  AnnotationCategory, BaselineDiffState, ChangeReason, ComparisonMode,
  ConflictResolution, FormatVersion, MatchStrategy, Op, OriginalFormat,
  PackageDiffState, RequirementState, SourceRole, Type,
} from './ts/hdf-comparison.js';
`
    : '';

  const indexJsContent = `/**
 * Main entry point for @mitre/hdf-schema
 * Re-exports all types from generated TypeScript definitions
 */

// Re-export all values from hdf-results (enums like ResultStatus, HashAlgorithm, Severity)
export * from './ts/hdf-results.js';
${comparisonJsExport}
// Re-export system enums (runtime values)
export {
  AuthorizationStatus, BoundaryDescription, CategorizationLevel, Designation, Direction,
} from './ts/hdf-system.js';

// Re-export plan enums (runtime values)
export {
  PlanType,
} from './ts/hdf-plan.js';

// No amendments enum re-export — OverrideType already from hdf-results via export *.

// Re-export evidence-package enums (runtime values)
export {
  ContentType,
} from './ts/hdf-evidence-package.js';

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
