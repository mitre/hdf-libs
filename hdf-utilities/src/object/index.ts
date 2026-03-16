/**
 * Generic object query utilities for traversing parsed data structures.
 *
 * These functions work on any plain JS objects — parsed XML, JSON, or CSV rows
 * are all objects by the time converters work with them.
 */

/**
 * Recursively find all values for a given key anywhere in a nested object tree.
 *
 * Walks the entire tree depth-first. When a property matching `key` is found,
 * its value is collected. Recurse continues into all child values (objects and
 * arrays) regardless of whether the current level matched.
 *
 * @param obj - Object tree to search (parsed XML, JSON, etc.)
 * @param key - Property name to search for
 * @param maxDepth - Maximum recursion depth (default 100). Nodes beyond this depth are silently skipped.
 * @returns Flat array of all matched values
 */
export function findValuesByKey(
  obj: unknown,
  key: string,
  maxDepth = 100,
): unknown[] {
  const results: unknown[] = [];
  walk(obj, key, results, 0, maxDepth);
  return results;
}

function walk(
  node: unknown,
  key: string,
  results: unknown[],
  depth: number,
  maxDepth: number,
): void {
  if (depth > maxDepth) {
    return;
  }

  if (node === null || node === undefined || typeof node !== 'object') {
    return;
  }

  if (Array.isArray(node)) {
    for (const item of node) {
      walk(item, key, results, depth + 1, maxDepth);
    }
    return;
  }

  const record = node as Record<string, unknown>;
  if (key in record) {
    results.push(record[key]);
  }
  for (const value of Object.values(record)) {
    walk(value, key, results, depth + 1, maxDepth);
  }
}

/**
 * Extract all values for a named field from an array of objects.
 *
 * Rows where the column is `undefined` are skipped.
 *
 * @param rows - Array of objects (e.g. parsed CSV rows)
 * @param column - Property name to extract
 * @returns Array of values for that column
 */
export function extractColumn(
  rows: Record<string, unknown>[],
  column: string,
): unknown[] {
  return rows.map((r) => r[column]).filter((v) => v !== undefined);
}

/**
 * Filter an array of objects to rows where a column matches a value.
 *
 * Uses strict equality (`===`).
 *
 * @param rows - Array of objects to filter
 * @param column - Property name to check
 * @param value - Value to match against
 * @returns Filtered array of matching rows
 */
export function findRows(
  rows: Record<string, unknown>[],
  column: string,
  value: unknown,
): Record<string, unknown>[] {
  return rows.filter((r) => r[column] === value);
}
