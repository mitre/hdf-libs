#!/usr/bin/env tsx
/**
 * Deep JSON comparison utility for differential testing.
 *
 * Compares two JSON files and reports differences.
 * Exit code 0 = identical, 1 = different, 2 = error
 */

/* eslint-disable no-console -- CLI tool requires console output */

import { readFileSync } from 'fs';
import { deepStrictEqual } from 'assert';

interface CompareOptions {
  ignoreFields?: string[];  // Fields to ignore (e.g., timestamps)
  ignoreArrayOrder?: boolean;
}

interface AssertionErrorLike extends Error {
  actual?: unknown;
  expected?: unknown;
}

function compareJSON(
  file1: string,
  file2: string,
  options: CompareOptions = {}
): boolean {
  try {
    const data1: unknown = JSON.parse(readFileSync(file1, 'utf-8'));
    const data2: unknown = JSON.parse(readFileSync(file2, 'utf-8'));

    // Normalize if needed
    const normalized1 = normalizeData(data1, options);
    const normalized2 = normalizeData(data2, options);

    // Deep comparison
    deepStrictEqual(normalized1, normalized2);

    return true;
  } catch (error) {
    if (error instanceof Error && error.name === 'AssertionError') {
      console.error('Files differ:');
      console.error(`   Left:  ${file1}`);
      console.error(`   Right: ${file2}`);
      console.error();
      console.error('Difference:', error.message);

      // Show detailed diff
      showDetailedDiff(error as AssertionErrorLike);

      return false;
    }
    throw error;
  }
}

function normalizeData(data: unknown, options: CompareOptions): unknown {
  if (typeof data !== 'object' || data === null) {
    return data;
  }

  if (Array.isArray(data)) {
    const normalized = data.map(item => normalizeData(item, options));
    return options.ignoreArrayOrder ? normalized.sort() : normalized;
  }

  const result: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(data as Record<string, unknown>)) {
    // Skip ignored fields
    if (options.ignoreFields?.includes(key)) {
      continue;
    }
    result[key] = normalizeData(value, options);
  }

  return result;
}

function showDetailedDiff(error: AssertionErrorLike): void {
  if (error.actual && error.expected) {
    console.error('\nExpected:');
    console.error(JSON.stringify(error.expected, null, 2).split('\n').slice(0, 20).join('\n'));
    console.error('\nActual:');
    console.error(JSON.stringify(error.actual, null, 2).split('\n').slice(0, 20).join('\n'));
  }
}

// CLI Usage
if (import.meta.url === `file://${process.argv[1]}`) {
  const [,, file1, file2, ...optionArgs] = process.argv;

  if (!file1 || !file2) {
    console.error('Usage: compare.ts <file1> <file2> [--ignore-fields=field1,field2]');
    process.exit(2);
  }

  const options: CompareOptions = {};
  for (const arg of optionArgs) {
    if (arg.startsWith('--ignore-fields=')) {
      options.ignoreFields = arg.split('=')[1]?.split(',');
    }
  }

  try {
    const identical = compareJSON(file1, file2, options);
    if (identical) {
      console.log('Files are identical');
      process.exit(0);
    } else {
      process.exit(1);
    }
  } catch (error) {
    console.error('Error comparing files:', error);
    process.exit(2);
  }
}

export { compareJSON, type CompareOptions };
