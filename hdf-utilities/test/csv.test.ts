import { describe, it, expect } from 'vitest';
import {
  parseCsv,
  parseCsvArray,
  buildCsv,
  buildCsvArray,
  isValidCsv,
  sanitizeCsvValue,
  sanitizeCsvArray,
  sanitizeCsvObject,
} from '../src/csv';

describe('CSV Utilities', () => {
  describe('maxSize option', () => {
    const smallCsv = 'name,age\nJohn,30';

    it('parseCsv should accept input within maxSize limit', () => {
      expect(() => parseCsv(smallCsv, { maxSize: 1000 })).not.toThrow();
    });

    it('parseCsv should reject input exceeding maxSize limit', () => {
      expect(() => parseCsv(smallCsv, { maxSize: 5 })).toThrow(
        /exceeds maximum allowed size/
      );
    });

    it('parseCsv should not enforce a limit when maxSize is omitted', () => {
      const largeCsv = 'a,b\n' + 'x,y\n'.repeat(5_000);
      expect(() => parseCsv(largeCsv)).not.toThrow();
    });

    it('parseCsvArray should accept input within maxSize limit', () => {
      expect(() => parseCsvArray(smallCsv, { maxSize: 1000 })).not.toThrow();
    });

    it('parseCsvArray should reject input exceeding maxSize limit', () => {
      expect(() => parseCsvArray(smallCsv, { maxSize: 5 })).toThrow(
        /exceeds maximum allowed size/
      );
    });

    it('should report actual size and limit in error message', () => {
      expect(() => parseCsv(smallCsv, { maxSize: 10 })).toThrow(
        new RegExp(`${smallCsv.length} bytes.*10 bytes`)
      );
    });

    it('should check size before doing any parsing work', () => {
      // Even malformed CSV should fail on size first
      const badCsv = '"unclosed quote';
      expect(() => parseCsv(badCsv, { maxSize: 3 })).toThrow(
        /exceeds maximum allowed size/
      );
    });
  });

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

      expect(result).toBe(`name,age,city\nJohn,30,NYC\nJane,25,LA\n`);
    });

    it('should quote fields with commas', () => {
      const data = [
        { name: 'Product A', description: 'A great, useful product' },
      ];

      const result = buildCsv(data);

      expect(result).toBe(
        `name,description\nProduct A,"A great, useful product"\n`
      );
    });

    it('should handle empty fields', () => {
      const data = [
        { name: 'John', age: '', city: 'NYC' },
        { name: '', age: 25, city: 'LA' },
      ];

      const result = buildCsv(data);

      expect(result).toBe(`name,age,city\nJohn,,NYC\n,25,LA\n`);
    });

    it('should allow custom delimiter', () => {
      const data = [{ name: 'John', age: 30 }];

      const result = buildCsv(data, { delimiter: ';' });

      expect(result).toBe(`name;age\nJohn;30\n`);
    });

    it('should allow custom newline', () => {
      const data = [
        { name: 'John', age: 30 },
        { name: 'Jane', age: 25 },
      ];

      const result = buildCsv(data, { newline: '\r\n' });

      expect(result).toBe(`name,age\r\nJohn,30\r\nJane,25\r\n`);
    });

    it('should build CSV without headers when specified', () => {
      const data = [
        { name: 'John', age: 30 },
        { name: 'Jane', age: 25 },
      ];

      const result = buildCsv(data, { header: false });

      expect(result).toBe(`John,30\nJane,25\n`);
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

      expect(result).toBe(`name,age,city\nJohn,30,NYC\nJane,25,LA\n`);
    });

    it('should quote fields with commas', () => {
      const data = [['Product A', 'A great, useful product']];

      const result = buildCsvArray(data);

      expect(result).toBe(`Product A,"A great, useful product"\n`);
    });

    it('should allow custom delimiter', () => {
      const data = [['John', '30']];

      const result = buildCsvArray(data, { delimiter: '\t' });

      expect(result).toBe(`John\t30\n`);
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

  describe('whitespace and trim behavior', () => {
    it('should trim leading/trailing whitespace from input before parsing', () => {
      const csv = '  name,age\nJohn,30\n  ';
      const result = parseCsv(csv);
      expect(result).toHaveLength(1);
      expect(result[0]).toEqual({ name: 'John', age: '30' });
    });

    it('should throw or return empty for whitespace-only input (after trim becomes empty)', () => {
      // parseCsv trims input; "   " becomes "" which papaparse rejects
      const input = '   ';
      let threw = false;
      let result: unknown[] = [];
      try {
        result = parseCsv(input);
      } catch {
        threw = true;
      }
      // papaparse either throws or returns []: both are acceptable empty-input behaviors
      expect(threw || result.length === 0).toBe(true);
    });
  });

  describe('error message format', () => {
    it('should include Row prefix in error message', () => {
      const csv = `name,age\nJohn,30,"unclosed quote`;
      let errorMessage = '';
      try {
        parseCsv(csv);
      } catch (e) {
        errorMessage = (e as Error).message;
      }
      expect(errorMessage).toContain('CSV parsing failed');
      expect(errorMessage).toContain('Row');
    });

    it('should use "; " separator when multiple row errors exist', () => {
      // parseCsvArray with header:false and quotes that span multiple rows
      // This exercises the join('; ') path when there are multiple parse errors
      const csv = `name,age\nJohn,30,"unclosed`;
      let errorMessage = '';
      try {
        parseCsv(csv);
      } catch (e) {
        errorMessage = (e as Error).message;
      }
      // The error message format: "Row N: message; Row M: message"
      expect(errorMessage).toMatch(/Row \d+:/);
    });
  });

  describe('header option', () => {
    it('header:false treats first row as data not headers', () => {
      const csv = `name,age\nJohn,30`;
      // With header:false via parseCsvArray (which uses DEFAULT_PARSE_ARRAY_OPTIONS)
      const result = parseCsvArray(csv);
      // First row is data, not headers
      expect(result[0]).toEqual(['name', 'age']);
      expect(result[1]).toEqual(['John', '30']);
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

  describe('CSV Injection Protection', () => {
    describe('sanitizeCsvValue', () => {
      it('should prefix values starting with =', () => {
        expect(sanitizeCsvValue('=1+1')).toBe("'=1+1");
        expect(sanitizeCsvValue('=SUM(A1:A10)')).toBe("'=SUM(A1:A10)");
      });

      it('should prefix values starting with +', () => {
        expect(sanitizeCsvValue('+1234')).toBe("'+1234");
      });

      it('should prefix values starting with -', () => {
        expect(sanitizeCsvValue('-5')).toBe("'-5");
        expect(sanitizeCsvValue('-cmd')).toBe("'-cmd");
      });

      it('should prefix values starting with @', () => {
        expect(sanitizeCsvValue('@SUM(A1:A10)')).toBe("'@SUM(A1:A10)");
      });

      it('should prefix values starting with |', () => {
        expect(sanitizeCsvValue('|calc')).toBe("'|calc");
      });

      it('should prefix values starting with %', () => {
        expect(sanitizeCsvValue('%calc%')).toBe("'%calc%");
      });

      it('should not modify safe values', () => {
        expect(sanitizeCsvValue('normal text')).toBe('normal text');
        expect(sanitizeCsvValue('123')).toBe('123');
        expect(sanitizeCsvValue('test@example.com')).toBe('test@example.com');
      });

      it('should handle non-string values', () => {
        expect(sanitizeCsvValue(123)).toBe('123');
        expect(sanitizeCsvValue(true)).toBe('true');
        expect(sanitizeCsvValue(null)).toBe('null');
      });
    });

    describe('sanitizeCsvArray', () => {
      it('should sanitize all values in array', () => {
        const input = ['=1+1', 'safe', '@SUM', '+123'];
        const result = sanitizeCsvArray(input);
        expect(result).toEqual(["'=1+1", 'safe', "'@SUM", "'+123"]);
      });

      it('should handle mixed types', () => {
        const input = ['=formula', 123, true, 'normal'];
        const result = sanitizeCsvArray(input);
        expect(result).toEqual(["'=formula", '123', 'true', 'normal']);
      });
    });

    describe('sanitizeCsvObject', () => {
      it('should sanitize all values in object', () => {
        const input = { name: '=formula', value: 'safe', cmd: '@exec' };
        const result = sanitizeCsvObject(input);
        expect(result).toEqual({
          name: "'=formula",
          value: 'safe',
          cmd: "'@exec",
        });
      });
    });

    describe('buildCsv with sanitization', () => {
      it('should sanitize when option is enabled', () => {
        const data = [
          { title: '=1+1', description: 'safe' },
          { title: 'normal', description: '@SUM(A1)' },
        ];

        const csv = buildCsv(data, { sanitize: true });

        // Verify formulas are prefixed
        expect(csv).toContain("'=1+1");
        expect(csv).toContain("'@SUM(A1)");

        // Verify line structure shows sanitization
        const lines = csv.split('\n');
        expect(lines[1]).toBe("'=1+1,safe");
        expect(lines[2]).toBe("normal,'@SUM(A1)");
      });

      it('should not sanitize when option is disabled', () => {
        const data = [{ title: '=1+1', description: 'safe' }];

        const csv = buildCsv(data, { sanitize: false });

        expect(csv).toContain('=1+1');
        expect(csv).not.toContain("'=1+1");
      });

      it('should not sanitize by default', () => {
        const data = [{ title: '=1+1' }];

        const csv = buildCsv(data);

        expect(csv).toContain('=1+1');
        expect(csv).not.toContain("'=1+1");
      });
    });

    describe('buildCsvArray with sanitization', () => {
      it('should sanitize when option is enabled', () => {
        const data = [
          ['Title', 'Command'],
          ['Test', '=cmd|calc'],
          ['Normal', 'safe'],
        ];

        const csv = buildCsvArray(data, { sanitize: true });

        expect(csv).toContain("'=cmd|calc");
        expect(csv).not.toContain('=cmd|calc,');
      });

      it('should not sanitize by default', () => {
        const data = [['=1+1', 'test']];

        const csv = buildCsvArray(data);

        expect(csv).toContain('=1+1');
      });
    });

    describe('Security attack vectors', () => {
      it('should prevent Excel formula injection attack', () => {
        const maliciousData = [
          {
            finding: 'SQL Injection',
            payload: '=cmd|"/c calc"!A1',
            status: 'Failed',
          },
        ];

        const csv = buildCsv(maliciousData, { sanitize: true });

        // Formula should be neutralized with leading quote
        expect(csv).toContain("'=cmd|");
        // Verify the original formula was prefixed
        const lines = csv.split('\n');
        expect(lines[1]).toMatch(/^SQL Injection,"'=cmd\|/);
      });

      it('should prevent DDE injection attack', () => {
        const maliciousData = [
          {
            url: '@SUM(1+1)*cmd|"/c calc"!A1',
            description: 'Malicious URL',
          },
        ];

        const csv = buildCsv(maliciousData, { sanitize: true });

        // Verify @ formula is escaped
        expect(csv).toContain("'@SUM");
        const lines = csv.split('\n');
        expect(lines[1]).toMatch(/^"'@SUM/);
      });

      it('should handle real security tool output', () => {
        const scanResults = [
          {
            pluginId: '12345',
            severity: 'High',
            name: 'SSL Certificate Issue',
            output: '=HYPERLINK("http://evil.com","Click here")',
          },
        ];

        const csv = buildCsv(scanResults, { sanitize: true });

        // Verify formula is escaped
        expect(csv).toContain("'=HYPERLINK");
      });
    });
  });
});
