#!/usr/bin/env node
/**
 * Compare TypeScript and Go converter outputs.
 *
 * Runs after both test suites have executed and generated outputs.
 * Compares test-output/differential/typescript/ vs test-output/differential/go/
 */

import { readdirSync, existsSync } from 'fs';
import { join, dirname } from 'path';
import { execSync } from 'child_process';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const rootDir = join(__dirname, '../..');
const outputDir = join(rootDir, 'test-output/differential');
const tsOutputDir = join(outputDir, 'typescript');
const goOutputDir = join(outputDir, 'go');

let failures = 0;
let successes = 0;

function compareConverter(converterName) {
  console.log(`\n📊 Comparing ${converterName}...`);

  const tsDir = join(tsOutputDir, converterName);
  const goDir = join(goOutputDir, converterName);

  if (!existsSync(tsDir)) {
    console.error(`  ❌ TypeScript output not found: ${tsDir}`);
    failures++;
    return;
  }

  if (!existsSync(goDir)) {
    console.error(`  ❌ Go output not found: ${goDir}`);
    failures++;
    return;
  }

  const tsFiles = readdirSync(tsDir).filter(f => f.endsWith('.json'));
  const goFiles = readdirSync(goDir).filter(f => f.endsWith('.json'));

  if (tsFiles.length !== goFiles.length) {
    console.error(`  ❌ File count mismatch: TS=${tsFiles.length}, Go=${goFiles.length}`);
    failures++;
    return;
  }

  for (const file of tsFiles) {
    const tsFile = join(tsDir, file);
    const goFile = join(goDir, file);

    if (!existsSync(goFile)) {
      console.error(`  ❌ Go output missing: ${file}`);
      failures++;
      continue;
    }

    try {
      // Use compare.ts for deep comparison
      execSync(
        `npx tsx ${join(__dirname, 'compare.ts')} "${tsFile}" "${goFile}"`,
        { stdio: 'inherit' }
      );
      console.log(`  ✅ ${file}`);
      successes++;
    } catch (error) {
      console.error(`  ❌ ${file}`);
      failures++;
    }
  }
}

// Main execution
console.log('🔍 Differential Testing - Comparing TypeScript vs Go Outputs');
console.log('===========================================================');

if (!existsSync(tsOutputDir)) {
  console.error('❌ TypeScript outputs not found. Run: pnpm test:differential');
  process.exit(2);
}

if (!existsSync(goOutputDir)) {
  console.error('❌ Go outputs not found. Run: cd hdf-converters && go test ./converters/...');
  process.exit(2);
}

// Get list of converters from TypeScript output
const converters = readdirSync(tsOutputDir).filter(f => {
  const path = join(tsOutputDir, f);
  return existsSync(path) && readdirSync(path).length > 0;
});

if (converters.length === 0) {
  console.error('❌ No converter outputs found');
  process.exit(2);
}

// Compare each converter
for (const converter of converters) {
  compareConverter(converter);
}

// Summary
console.log('\n' + '='.repeat(60));
console.log(`✅ Passed: ${successes}`);
console.log(`❌ Failed: ${failures}`);
console.log('='.repeat(60));

process.exit(failures > 0 ? 1 : 0);
