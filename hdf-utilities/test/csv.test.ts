import { describe, it, expect } from 'vitest';
import {
  parseCsv,
  parseCsvArray,
  buildCsv,
  buildCsvArray,
  isValidCsv,
} from '../src/csv';

describe('CSV Utilities', () => {
  describe('parseCsv', () => {
    it('should parse simple CSV with headers', () => {
      const csv = `name,age,city
John,30,NYC
Jane,25,LA`;

      const result = parseCsv(csv);

      expect(result).toHaveLength(2);
      expect(result[0]).toEqual({ name: 'John', age: '30', city: 'NYC' });
      expect(result[1]).toEqual({ name: 'Jane', age: '25', city: 'LA' });
    });

    it('should handle CSV with quoted values', () => {
      const csv = `name,description
"Product A","A great, useful product"
"Product B","Another ""amazing"" product"`;

      const result = parseCsv(csv);

      expect(result).toHaveLength(2);
      expect(result[0]).toEqual({
        name: 'Product A',
        description: 'A great, useful product',
      });
      expect(result[1]).toEqual({
        name: 'Product B',
        description: 'Another "amazing" product',
      });
    });

    it('should handle empty fields', () => {
      const csv = `name,age,city
John,,NYC
,25,LA`;

      const result = parseCsv(csv);

      expect(result).toHaveLength(2);
      expect(result[0]).toEqual({ name: 'John', age: '', city: 'NYC' });
      expect(result[1]).toEqual({ name: '', age: '25', city: 'LA' });
    });

    it('should skip empty lines by default', () => {
      const csv = `name,age
John,30

Jane,25`;

      const result = parseCsv(csv);

      expect(result).toHaveLength(2);
      expect(result[0]).toEqual({ name: 'John', age: '30' });
      expect(result[1]).toEqual({ name: 'Jane', age: '25' });
    });

    it('should allow custom options', () => {
      const csv = `name,age,city
John,30,NYC`;

      const result = parseCsv(csv, {
        transformHeader: (header) => header.toUpperCase(),
      });

      expect(result[0]).toEqual({ NAME: 'John', AGE: '30', CITY: 'NYC' });
    });

    it('should enable dynamic typing when specified', () => {
      const csv = `name,age,active
John,30,true`;

      const result = parseCsv(csv, { dynamicTyping: true });

      expect(result[0]).toEqual({ name: 'John', age: 30, active: true });
      expect(typeof result[0].age).toBe('number');
      expect(typeof result[0].active).toBe('boolean');
    });

    it('should throw error for malformed CSV', () => {
      const csv = `name,age
John,30,"unclosed quote`;

      expect(() => parseCsv(csv)).toThrow('CSV parsing failed');
    });

    it('should handle single row CSV', () => {
      const csv = `name,age
John,30`;

      const result = parseCsv(csv);

      expect(result).toHaveLength(1);
      expect(result[0]).toEqual({ name: 'John', age: '30' });
    });

    it('should handle CSV with headers only', () => {
      const csv = `name,age,city`;

      const result = parseCsv(csv);

      expect(result).toHaveLength(0);
    });
  });

  describe('parseCsvArray', () => {
    it('should parse CSV into array of arrays', () => {
      const csv = `name,age,city
John,30,NYC
Jane,25,LA`;

      const result = parseCsvArray(csv);

      expect(result).toHaveLength(3);
      expect(result[0]).toEqual(['name', 'age', 'city']);
      expect(result[1]).toEqual(['John', '30', 'NYC']);
      expect(result[2]).toEqual(['Jane', '25', 'LA']);
    });

    it('should handle quoted values', () => {
      const csv = `"Product A","A great, useful product"
"Product B","Another product"`;

      const result = parseCsvArray(csv);

      expect(result).toHaveLength(2);
      expect(result[0]).toEqual(['Product A', 'A great, useful product']);
      expect(result[1]).toEqual(['Product B', 'Another product']);
    });

    it('should skip empty lines by default', () => {
      const csv = `John,30

Jane,25`;

      const result = parseCsvArray(csv);

      expect(result).toHaveLength(2);
      expect(result[0]).toEqual(['John', '30']);
      expect(result[1]).toEqual(['Jane', '25']);
    });

    it('should throw error for malformed CSV', () => {
      const csv = `John,30,"unclosed quote`;

      expect(() => parseCsvArray(csv)).toThrow('CSV parsing failed');
    });
  });

  describe('buildCsv', () => {
    it('should build CSV from array of objects', () => {
      const data = [
        { name: 'John', age: 30, city: 'NYC' },
        { name: 'Jane', age: 25, city: 'LA' },
      ];

      const result = buildCsv(data);

      expect(result).toBe(`name,age,city\nJohn,30,NYC\nJane,25,LA`);
    });

    it('should quote fields with commas', () => {
      const data = [
        { name: 'Product A', description: 'A great, useful product' },
      ];

      const result = buildCsv(data);

      expect(result).toBe(
        `name,description\nProduct A,"A great, useful product"`
      );
    });

    it('should handle empty fields', () => {
      const data = [
        { name: 'John', age: '', city: 'NYC' },
        { name: '', age: 25, city: 'LA' },
      ];

      const result = buildCsv(data);

      expect(result).toBe(`name,age,city\nJohn,,NYC\n,25,LA`);
    });

    it('should allow custom delimiter', () => {
      const data = [{ name: 'John', age: 30 }];

      const result = buildCsv(data, { delimiter: ';' });

      expect(result).toBe(`name;age\nJohn;30`);
    });

    it('should allow custom newline', () => {
      const data = [
        { name: 'John', age: 30 },
        { name: 'Jane', age: 25 },
      ];

      const result = buildCsv(data, { newline: '\r\n' });

      expect(result).toBe(`name,age\r\nJohn,30\r\nJane,25`);
    });

    it('should build CSV without headers when specified', () => {
      const data = [
        { name: 'John', age: 30 },
        { name: 'Jane', age: 25 },
      ];

      const result = buildCsv(data, { header: false });

      expect(result).toBe(`John,30\nJane,25`);
    });

    it('should handle empty array', () => {
      const data: Record<string, unknown>[] = [];

      const result = buildCsv(data);

      expect(result).toBe('');
    });
  });

  describe('buildCsvArray', () => {
    it('should build CSV from array of arrays', () => {
      const data = [
        ['name', 'age', 'city'],
        ['John', '30', 'NYC'],
        ['Jane', '25', 'LA'],
      ];

      const result = buildCsvArray(data);

      expect(result).toBe(`name,age,city\nJohn,30,NYC\nJane,25,LA`);
    });

    it('should quote fields with commas', () => {
      const data = [['Product A', 'A great, useful product']];

      const result = buildCsvArray(data);

      expect(result).toBe(`Product A,"A great, useful product"`);
    });

    it('should allow custom delimiter', () => {
      const data = [['John', '30']];

      const result = buildCsvArray(data, { delimiter: '\t' });

      expect(result).toBe(`John\t30`);
    });

    it('should handle empty array', () => {
      const data: string[][] = [];

      const result = buildCsvArray(data);

      expect(result).toBe('');
    });
  });

  describe('isValidCsv', () => {
    it('should return true for valid CSV', () => {
      const csv = `name,age
John,30
Jane,25`;

      expect(isValidCsv(csv)).toBe(true);
    });

    it('should return true for CSV with quoted values', () => {
      const csv = `"Product A","A great, useful product"`;

      expect(isValidCsv(csv)).toBe(true);
    });

    it('should return false for empty string', () => {
      expect(isValidCsv('')).toBe(false);
    });

    it('should return false for whitespace only', () => {
      expect(isValidCsv('   ')).toBe(false);
    });

    it('should return false for malformed CSV', () => {
      const csv = `John,30,"unclosed quote`;

      expect(isValidCsv(csv)).toBe(false);
    });

    it('should return false for single value without delimiters', () => {
      // Single value without CSV structure returns no rows after skipEmptyLines
      expect(isValidCsv('value')).toBe(false);
    });

    it('should return true for single row', () => {
      expect(isValidCsv('name,age,city')).toBe(true);
    });
  });

  describe('Real-world scenarios', () => {
    it('should parse security tool CSV export', () => {
      const csv = `PluginID,Severity,Name,Description
12345,High,"SSL Certificate Issue","Certificate has expired"
67890,Medium,"Missing Header","Security header not found"`;

      const result = parseCsv(csv);

      expect(result).toHaveLength(2);
      expect(result[0]).toEqual({
        PluginID: '12345',
        Severity: 'High',
        Name: 'SSL Certificate Issue',
        Description: 'Certificate has expired',
      });
    });

    it('should handle CSV with special characters', () => {
      const csv = `title,description
"Test with ""quotes""","Contains, commas and ""quotes"""
"Line
break","Has newline"`;

      const result = parseCsv(csv);

      expect(result).toHaveLength(2);
      expect(result[0].title).toBe('Test with "quotes"');
      expect(result[0].description).toBe('Contains, commas and "quotes"');
      expect(result[1].title).toBe('Line\nbreak');
    });

    it('should round-trip data correctly', () => {
      const original = [
        { name: 'John Doe', age: 30, city: 'New York, NY' },
        { name: 'Jane Smith', age: 25, city: 'Los Angeles, CA' },
      ];

      const csv = buildCsv(original);
      const parsed = parseCsv(csv);

      expect(parsed).toHaveLength(2);
      expect(parsed[0]).toEqual({
        name: 'John Doe',
        age: '30',
        city: 'New York, NY',
      });
      expect(parsed[1]).toEqual({
        name: 'Jane Smith',
        age: '25',
        city: 'Los Angeles, CA',
      });
    });
  });
});
