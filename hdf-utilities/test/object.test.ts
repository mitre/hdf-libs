import { describe, it, expect } from 'vitest';
import {
  findValuesByKey,
  extractColumn,
  findRows,
} from '../src/object/index.js';
import { findXmlValues } from '../src/xml/index.js';
import { findJsonValues } from '../src/json/index.js';
import { extractCsvColumn, findCsvRows } from '../src/csv/index.js';

describe('findValuesByKey', () => {
  it('should find a top-level key', () => {
    const obj = { name: 'Alice', age: 30 };
    expect(findValuesByKey(obj, 'name')).toEqual(['Alice']);
  });

  it('should find a deeply nested key', () => {
    const obj = { a: { b: { c: { target: 'found' } } } };
    expect(findValuesByKey(obj, 'target')).toEqual(['found']);
  });

  it('should find a key inside arrays of objects', () => {
    const obj = {
      items: [
        { id: 1, label: 'first' },
        { id: 2, label: 'second' },
      ],
    };
    expect(findValuesByKey(obj, 'label')).toEqual(['first', 'second']);
  });

  it('should return multiple matches across the tree', () => {
    const obj = {
      title: 'root',
      children: [
        { title: 'child1' },
        { nested: { title: 'child2' } },
      ],
    };
    expect(findValuesByKey(obj, 'title')).toEqual([
      'root',
      'child1',
      'child2',
    ]);
  });

  it('should return empty array when key not found', () => {
    const obj = { a: 1, b: { c: 2 } };
    expect(findValuesByKey(obj, 'missing')).toEqual([]);
  });

  it('should handle null without throwing', () => {
    expect(findValuesByKey(null, 'key')).toEqual([]);
  });

  it('should handle undefined without throwing', () => {
    expect(findValuesByKey(undefined, 'key')).toEqual([]);
  });

  it('should handle primitives without throwing', () => {
    expect(findValuesByKey(42, 'key')).toEqual([]);
    expect(findValuesByKey('string', 'key')).toEqual([]);
    expect(findValuesByKey(true, 'key')).toEqual([]);
  });

  it('should work on a realistic parsed XML structure', () => {
    // Simulates Benchmark → Group → Rule → title from parsed XCCDF XML
    const parsed = {
      Benchmark: {
        Group: [
          {
            Rule: {
              title: 'Ensure SSH is configured',
              description: 'SSH must use strong ciphers',
            },
          },
          {
            Rule: {
              title: 'Disable root login',
              description: 'Root login must be disabled',
            },
          },
        ],
      },
    };
    expect(findValuesByKey(parsed, 'title')).toEqual([
      'Ensure SSH is configured',
      'Disable root login',
    ]);
  });

  it('should work on a parsed JSON structure', () => {
    const parsed = {
      results: {
        findings: [
          { severity: 'HIGH', message: 'Open port' },
          { severity: 'LOW', message: 'Info leak' },
        ],
      },
    };
    expect(findValuesByKey(parsed, 'severity')).toEqual(['HIGH', 'LOW']);
  });

  it('should return the value of the key, not the key itself', () => {
    const obj = { data: { key: 'value' } };
    const results = findValuesByKey(obj, 'key');
    expect(results).toEqual(['value']);
    expect(results).not.toContain('key');
  });
});

describe('extractColumn', () => {
  it('should extract a named column from an array of objects', () => {
    const rows = [
      { name: 'Alice', age: 30 },
      { name: 'Bob', age: 25 },
      { name: 'Charlie', age: 35 },
    ];
    expect(extractColumn(rows, 'name')).toEqual(['Alice', 'Bob', 'Charlie']);
  });

  it('should skip rows where column is undefined', () => {
    const rows = [
      { name: 'Alice', age: 30 },
      { age: 25 },
      { name: 'Charlie', age: 35 },
    ];
    expect(extractColumn(rows, 'name')).toEqual(['Alice', 'Charlie']);
  });

  it('should return empty array for empty input', () => {
    expect(extractColumn([], 'name')).toEqual([]);
  });

  it('should return empty array when column does not exist in any row', () => {
    const rows = [
      { name: 'Alice' },
      { name: 'Bob' },
    ];
    expect(extractColumn(rows, 'missing')).toEqual([]);
  });
});

describe('findRows', () => {
  it('should filter rows matching a column value', () => {
    const rows = [
      { status: 'pass', name: 'A' },
      { status: 'fail', name: 'B' },
      { status: 'pass', name: 'C' },
    ];
    expect(findRows(rows, 'status', 'pass')).toEqual([
      { status: 'pass', name: 'A' },
      { status: 'pass', name: 'C' },
    ]);
  });

  it('should return empty array when no matches', () => {
    const rows = [
      { status: 'pass', name: 'A' },
      { status: 'pass', name: 'B' },
    ];
    expect(findRows(rows, 'status', 'fail')).toEqual([]);
  });

  it('should use strict equality', () => {
    const rows = [
      { value: 1 },
      { value: '1' },
      { value: true },
    ];
    expect(findRows(rows, 'value', 1)).toEqual([{ value: 1 }]);
    expect(findRows(rows, 'value', '1')).toEqual([{ value: '1' }]);
  });

  it('should return empty array for empty input', () => {
    expect(findRows([], 'col', 'val')).toEqual([]);
  });
});

describe('format-specific aliases', () => {
  it('findXmlValues should be the same function as findValuesByKey', () => {
    expect(findXmlValues).toBe(findValuesByKey);
  });

  it('findJsonValues should be the same function as findValuesByKey', () => {
    expect(findJsonValues).toBe(findValuesByKey);
  });

  it('extractCsvColumn should be the same function as extractColumn', () => {
    expect(extractCsvColumn).toBe(extractColumn);
  });

  it('findCsvRows should be the same function as findRows', () => {
    expect(findCsvRows).toBe(findRows);
  });
});
