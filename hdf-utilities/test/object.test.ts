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

  describe('depth limiting', () => {
    it('should find values within default depth limit', () => {
      // Build a chain of 10 levels — well within the 100 default
      let obj: Record<string, unknown> = { target: 'found' };
      for (let i = 0; i < 10; i++) {
        obj = { nested: obj };
      }
      expect(findValuesByKey(obj, 'target')).toEqual(['found']);
    });

    it('should not find values beyond custom maxDepth', () => {
      // Build a chain of 5 levels, set maxDepth to 3
      let obj: Record<string, unknown> = { target: 'deep' };
      for (let i = 0; i < 5; i++) {
        obj = { nested: obj };
      }
      // With maxDepth=3, we should NOT reach the target at depth 6
      expect(findValuesByKey(obj, 'target', 3)).toEqual([]);
    });

    it('should find values exactly at maxDepth boundary', () => {
      // Build a chain where target is exactly at depth N
      let obj: Record<string, unknown> = { target: 'boundary' };
      for (let i = 0; i < 3; i++) {
        obj = { nested: obj };
      }
      // walk starts at depth 0 for the outermost object.
      // Each Object.values recursion increments depth by 1.
      // The { target: 'boundary' } object is reached at depth 3.
      // maxDepth=3 allows depth 3 (guard is depth > maxDepth), so it finds the value.
      // maxDepth=2 stops at depth 3 (3 > 2), so it does not find the value.
      expect(findValuesByKey(obj, 'target', 3)).toEqual(['boundary']);
      expect(findValuesByKey(obj, 'target', 2)).toEqual([]);
    });

    it('should handle arrays within depth counting', () => {
      const obj = {
        items: [
          { nested: { target: 'in-array' } },
        ],
      };
      // Array traversal counts as depth
      expect(findValuesByKey(obj, 'target')).toEqual(['in-array']);
      expect(findValuesByKey(obj, 'target', 1)).toEqual([]);
    });

    it('should not throw when depth limit exceeded', () => {
      let obj: Record<string, unknown> = { target: 'deep' };
      for (let i = 0; i < 100; i++) {
        obj = { nested: obj };
      }
      // Should silently truncate, not throw
      expect(() => findValuesByKey(obj, 'target', 5)).not.toThrow();
    });
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
