import { describe, it, expect } from 'vitest';
import { parseCpe } from '../src/cpe/index.js';

describe('parseCpe', () => {
  describe('well-formed input', () => {
    it('should parse a standard well-formed CPE 2.3 URI', () => {
      const result = parseCpe('cpe:2.3:a:openssl:openssl:1.1.1k:*:*:*:*:*:*:*');
      expect(result).not.toBeNull();
      expect(result!.raw).toBe('cpe:2.3:a:openssl:openssl:1.1.1k:*:*:*:*:*:*:*');
      expect(result!.part).toBe('a');
      expect(result!.vendor).toBe('openssl');
      expect(result!.product).toBe('openssl');
      expect(result!.version).toBe('1.1.1k');
      expect(result!.update).toBe('*');
      expect(result!.edition).toBe('*');
      expect(result!.language).toBe('*');
      expect(result!.swEdition).toBe('*');
      expect(result!.targetSw).toBe('*');
      expect(result!.targetHw).toBe('*');
      expect(result!.other).toBe('*');
      expect(result!.warnings).toEqual([]);
    });

    it('should parse a real grype-style CPE (ca-certificates)', () => {
      const result = parseCpe(
        'cpe:2.3:a:ca-certificates:ca-certificates:2023.2.64-1.amzn2.0.1:*:*:*:*:*:*:*',
      );
      expect(result).not.toBeNull();
      expect(result!.part).toBe('a');
      expect(result!.vendor).toBe('ca-certificates');
      expect(result!.product).toBe('ca-certificates');
      expect(result!.version).toBe('2023.2.64-1.amzn2.0.1');
      expect(result!.warnings).toEqual([]);
    });

    it('should parse operating system part (o)', () => {
      const result = parseCpe(
        'cpe:2.3:o:microsoft:windows_10:1909:*:*:*:*:*:*:*',
      );
      expect(result).not.toBeNull();
      expect(result!.part).toBe('o');
      expect(result!.vendor).toBe('microsoft');
      expect(result!.product).toBe('windows_10');
      expect(result!.warnings).toEqual([]);
    });

    it('should parse hardware part (h)', () => {
      const result = parseCpe('cpe:2.3:h:cisco:asr_1000:*:*:*:*:*:*:*:*');
      expect(result).not.toBeNull();
      expect(result!.part).toBe('h');
      expect(result!.warnings).toEqual([]);
    });

    it('should parse any-part wildcard (*)', () => {
      const result = parseCpe('cpe:2.3:*:vendor:product:1.0:*:*:*:*:*:*:*');
      expect(result).not.toBeNull();
      expect(result!.part).toBe('*');
      expect(result!.warnings).toEqual([]);
    });

    it('should populate all twelve product fields when present', () => {
      const result = parseCpe(
        'cpe:2.3:a:vend:prod:1.0:beta:pro:en-us:enterprise:linux:x86_64:custom',
      );
      expect(result).not.toBeNull();
      expect(result!.part).toBe('a');
      expect(result!.vendor).toBe('vend');
      expect(result!.product).toBe('prod');
      expect(result!.version).toBe('1.0');
      expect(result!.update).toBe('beta');
      expect(result!.edition).toBe('pro');
      expect(result!.language).toBe('en-us');
      expect(result!.swEdition).toBe('enterprise');
      expect(result!.targetSw).toBe('linux');
      expect(result!.targetHw).toBe('x86_64');
      expect(result!.other).toBe('custom');
      expect(result!.warnings).toEqual([]);
    });
  });

  describe('missing prefix returns null', () => {
    it('should return null for input without cpe:2.3: prefix', () => {
      expect(parseCpe('openssl:1.1.1k')).toBeNull();
    });

    it('should return null for empty string', () => {
      expect(parseCpe('')).toBeNull();
    });

    it('should return null for unrelated string', () => {
      expect(parseCpe('not a cpe at all')).toBeNull();
    });

    it('should return null for CPE 2.2 URI binding', () => {
      // Old URI-binding form starts with cpe:/ — not 2.3 formatted
      expect(parseCpe('cpe:/a:openssl:openssl:1.1.1k')).toBeNull();
    });

    it('should return null for incorrect prefix version', () => {
      expect(parseCpe('cpe:2.4:a:openssl:openssl:1.1.1k')).toBeNull();
    });
  });

  describe('truncated input is padded with warning', () => {
    it('should pad truncated 5-field CPE with * defaults', () => {
      const result = parseCpe('cpe:2.3:a:openssl:openssl:1.1.1k');
      expect(result).not.toBeNull();
      expect(result!.part).toBe('a');
      expect(result!.vendor).toBe('openssl');
      expect(result!.product).toBe('openssl');
      expect(result!.version).toBe('1.1.1k');
      expect(result!.update).toBe('*');
      expect(result!.edition).toBe('*');
      expect(result!.language).toBe('*');
      expect(result!.swEdition).toBe('*');
      expect(result!.targetSw).toBe('*');
      expect(result!.targetHw).toBe('*');
      expect(result!.other).toBe('*');
      expect(result!.warnings).toHaveLength(1);
      expect(result!.warnings[0]).toMatch(
        /truncated: expected 13 colon-separated fields, got \d+/,
      );
    });

    it('should warn when only the prefix is present (cpe:2.3:)', () => {
      const result = parseCpe('cpe:2.3:');
      expect(result).not.toBeNull();
      // All twelve product fields should be empty strings
      expect(result!.part).toBe('');
      expect(result!.vendor).toBe('');
      expect(result!.product).toBe('');
      expect(result!.version).toBe('');
      expect(result!.update).toBe('');
      expect(result!.edition).toBe('');
      expect(result!.language).toBe('');
      expect(result!.swEdition).toBe('');
      expect(result!.targetSw).toBe('');
      expect(result!.targetHw).toBe('');
      expect(result!.other).toBe('');
      // Truncated (1 colon-segment) plus unknown part are both reported
      const allWarnings = result!.warnings.join(' | ');
      expect(allWarnings).toMatch(/truncated/);
    });

    it('should pad a 2-field truncated CPE', () => {
      const result = parseCpe('cpe:2.3:a:openssl');
      expect(result).not.toBeNull();
      expect(result!.part).toBe('a');
      expect(result!.vendor).toBe('openssl');
      expect(result!.product).toBe('*');
      expect(result!.warnings.some((w) => /truncated/.test(w))).toBe(true);
    });
  });

  describe('extra fields are ignored with warning', () => {
    it('should keep 12 fields and warn when extras are present', () => {
      const result = parseCpe(
        'cpe:2.3:a:vend:prod:1.0:*:*:*:*:*:*:*:extra1:extra2',
      );
      expect(result).not.toBeNull();
      expect(result!.part).toBe('a');
      expect(result!.vendor).toBe('vend');
      expect(result!.product).toBe('prod');
      expect(result!.other).toBe('*');
      expect(result!.warnings).toContain('extra fields ignored');
    });
  });

  describe('invalid part values are accepted with warning', () => {
    it('should warn on unknown part letter', () => {
      const result = parseCpe('cpe:2.3:x:vendor:product:1.0:*:*:*:*:*:*:*');
      expect(result).not.toBeNull();
      expect(result!.part).toBe('x');
      expect(result!.warnings).toContain('unknown part: x');
    });

    it('should warn on multi-character part', () => {
      const result = parseCpe(
        'cpe:2.3:app:vendor:product:1.0:*:*:*:*:*:*:*',
      );
      expect(result).not.toBeNull();
      expect(result!.part).toBe('app');
      expect(result!.warnings).toContain('unknown part: app');
    });

    it('should warn on empty part field', () => {
      const result = parseCpe('cpe:2.3::vendor:product:1.0:*:*:*:*:*:*:*');
      expect(result).not.toBeNull();
      expect(result!.part).toBe('');
      expect(result!.warnings).toContain('unknown part: ');
    });
  });

  describe('escape handling', () => {
    it('should unescape \\: in a field value', () => {
      const result = parseCpe(
        'cpe:2.3:a:my\\:vendor:product:1.0:*:*:*:*:*:*:*',
      );
      expect(result).not.toBeNull();
      expect(result!.vendor).toBe('my:vendor');
      expect(result!.product).toBe('product');
      expect(result!.version).toBe('1.0');
    });

    it('should unescape \\\\ in a field value', () => {
      const result = parseCpe(
        'cpe:2.3:a:my\\\\vendor:product:1.0:*:*:*:*:*:*:*',
      );
      expect(result).not.toBeNull();
      expect(result!.vendor).toBe('my\\vendor');
    });

    it('should not split on an escaped colon spanning fields', () => {
      const result = parseCpe(
        'cpe:2.3:a:foo\\:bar\\:baz:product:1.0:*:*:*:*:*:*:*',
      );
      expect(result).not.toBeNull();
      expect(result!.vendor).toBe('foo:bar:baz');
      expect(result!.product).toBe('product');
    });

    it('should preserve unknown backslash escapes verbatim', () => {
      // \n is not a known CPE escape — keep backslash literal in the field.
      const result = parseCpe(
        'cpe:2.3:a:foo\\nbar:product:1.0:*:*:*:*:*:*:*',
      );
      expect(result).not.toBeNull();
      expect(result!.vendor).toBe('foo\\nbar');
    });

    it('should keep a trailing lone backslash verbatim', () => {
      // Backslash at the very end of input has nothing to escape — keep it.
      const result = parseCpe('cpe:2.3:a:vendor\\');
      expect(result).not.toBeNull();
      expect(result!.vendor).toBe('vendor\\');
    });

    it('should unescape mixed escapes', () => {
      // backslash-backslash then escaped colon
      const result = parseCpe(
        'cpe:2.3:a:a\\\\b\\:c:product:1.0:*:*:*:*:*:*:*',
      );
      expect(result).not.toBeNull();
      expect(result!.vendor).toBe('a\\b:c');
    });
  });

  describe('preserves raw input', () => {
    it('raw should always echo back the original input', () => {
      const inputs = [
        'cpe:2.3:a:openssl:openssl:1.1.1k:*:*:*:*:*:*:*',
        'cpe:2.3:a:openssl:openssl:1.1.1k',
        'cpe:2.3:',
        'cpe:2.3:a:vend:prod:1.0:*:*:*:*:*:*:*:extra',
      ];
      for (const input of inputs) {
        const result = parseCpe(input);
        expect(result).not.toBeNull();
        expect(result!.raw).toBe(input);
      }
    });
  });
});
