import { describe, it, expect, vi } from 'vitest';
import { parseJSON, stringifyJSON, isValidJSON } from '../src/json/index.js';

describe('parseJSON', () => {
  it('should parse valid JSON string', () => {
    const input = '{"name": "test", "value": 123}';
    const result = parseJSON(input);
    expect(result).toEqual({ name: 'test', value: 123 });
  });

  it('should parse JSON array', () => {
    const input = '[1, 2, 3]';
    const result = parseJSON(input);
    expect(result).toEqual([1, 2, 3]);
  });

  it('should throw error for invalid JSON', () => {
    const input = '{invalid json}';
    expect(() => parseJSON(input)).toThrow();
  });

  it('should throw error for empty string', () => {
    expect(() => parseJSON('')).toThrow('Input cannot be empty');
  });

  it('should throw error with message for invalid JSON', () => {
    expect(() => parseJSON('{bad}')).toThrow('Invalid JSON');
  });

  it('should throw error for non-string input', () => {
    expect(() => parseJSON(123 as any)).toThrow('Input must be a string');
  });

  it('should handle nested objects', () => {
    const input = '{"outer": {"inner": {"deep": "value"}}}';
    const result = parseJSON(input);
    expect(result).toEqual({ outer: { inner: { deep: 'value' } } });
  });

  it('should handle null value', () => {
    const input = 'null';
    const result = parseJSON(input);
    expect(result).toBeNull();
  });

  it('should handle boolean values', () => {
    expect(parseJSON('true')).toBe(true);
    expect(parseJSON('false')).toBe(false);
  });

  it('should handle numbers', () => {
    expect(parseJSON('42')).toBe(42);
    expect(parseJSON('3.14')).toBe(3.14);
  });

  it('should handle non-Error exceptions', () => {
    const spy = vi.spyOn(JSON, 'parse').mockImplementation(() => {
      throw 'string error';
    });
    expect(() => parseJSON('test')).toThrow('Invalid JSON: string error');
    spy.mockRestore();
  });

  it('should parse input with leading/trailing whitespace', () => {
    // parseJSON does not explicitly trim but JSON.parse handles surrounding whitespace
    const input = '  {"name": "test"}  ';
    // The trim() check on input.trim() === '' passes non-empty trimmed, then JSON.parse handles whitespace
    const result = parseJSON<{ name: string }>(input);
    expect(result.name).toBe('test');
  });

  it('should throw for whitespace-only input (empty after trim)', () => {
    expect(() => parseJSON('   ')).toThrow('Input cannot be empty');
  });
});

describe('stringifyJSON', () => {
  it('should stringify object', () => {
    const input = { name: 'test', value: 123 };
    const result = stringifyJSON(input);
    expect(result).toBe('{"name":"test","value":123}');
  });

  it('should stringify with pretty printing', () => {
    const input = { name: 'test', value: 123 };
    const result = stringifyJSON(input, { pretty: true });
    expect(result).toContain('\n');
    expect(result).toContain('  ');
  });

  it('should stringify array', () => {
    const input = [1, 2, 3];
    const result = stringifyJSON(input);
    expect(result).toBe('[1,2,3]');
  });

  it('should stringify null', () => {
    const result = stringifyJSON(null);
    expect(result).toBe('null');
  });

  it('should stringify boolean', () => {
    expect(stringifyJSON(true)).toBe('true');
    expect(stringifyJSON(false)).toBe('false');
  });

  it('should stringify number', () => {
    expect(stringifyJSON(42)).toBe('42');
  });

  it('should stringify string', () => {
    expect(stringifyJSON('hello')).toBe('"hello"');
  });

  it('should handle nested objects', () => {
    const input = { outer: { inner: { deep: 'value' } } };
    const result = stringifyJSON(input);
    expect(result).toBe('{"outer":{"inner":{"deep":"value"}}}');
  });

  it('should throw on circular references', () => {
    const obj: any = { name: 'test' };
    obj.self = obj;
    expect(() => stringifyJSON(obj)).toThrow();
  });

  it('should handle non-Error exceptions', () => {
    const spy = vi.spyOn(JSON, 'stringify').mockImplementation(() => {
      throw 'string error';
    });
    expect(() => stringifyJSON({ test: 'value' })).toThrow('Failed to stringify JSON: string error');
    spy.mockRestore();
  });
});

describe('isValidJSON', () => {
  it('should return true for valid JSON string', () => {
    expect(isValidJSON('{"name": "test"}')).toBe(true);
  });

  it('should return true for valid JSON array', () => {
    expect(isValidJSON('[1, 2, 3]')).toBe(true);
  });

  it('should return true for valid primitives', () => {
    expect(isValidJSON('null')).toBe(true);
    expect(isValidJSON('true')).toBe(true);
    expect(isValidJSON('false')).toBe(true);
    expect(isValidJSON('42')).toBe(true);
    expect(isValidJSON('"string"')).toBe(true);
  });

  it('should return false for invalid JSON', () => {
    expect(isValidJSON('{invalid}')).toBe(false);
  });

  it('should return false for empty string', () => {
    expect(isValidJSON('')).toBe(false);
  });

  it('should return false for undefined', () => {
    expect(isValidJSON('undefined')).toBe(false);
  });

  it('should return false for non-string input', () => {
    expect(isValidJSON(123 as any)).toBe(false);
    expect(isValidJSON({} as any)).toBe(false);
    expect(isValidJSON([] as any)).toBe(false);
  });
});
