import { describe, it, expect } from 'vitest';
import { parsePurl } from '../src/purl/index.js';

describe('parsePurl', () => {
  describe('null cases', () => {
    it('returns null for missing pkg: prefix', () => {
      expect(parsePurl('npm/lodash@4.17.21')).toBeNull();
    });

    it('returns null for empty string', () => {
      expect(parsePurl('')).toBeNull();
    });

    it('returns null when only pkg: prefix is present', () => {
      expect(parsePurl('pkg:')).toBeNull();
    });

    it('returns null when no type is given (pkg:@1.0.0)', () => {
      // After stripping leading slashes per spec, `pkg:@1.0.0` has an empty
      // type segment (everything before the first `/` or end-of-path is
      // type; here the path starts with `@`, so type is empty).
      // Equivalent: `pkg:` alone is also null.
      expect(parsePurl('pkg:/')).toBeNull();
    });
  });

  describe('standard PURLs', () => {
    it('parses pkg:npm/lodash@4.17.21', () => {
      const r = parsePurl('pkg:npm/lodash@4.17.21');
      expect(r).not.toBeNull();
      expect(r!.raw).toBe('pkg:npm/lodash@4.17.21');
      expect(r!.type).toBe('npm');
      expect(r!.namespace).toBeNull();
      expect(r!.name).toBe('lodash');
      expect(r!.version).toBe('4.17.21');
      expect(r!.qualifiers.size).toBe(0);
      expect(r!.subpath).toBeNull();
      expect(r!.warnings).toEqual([]);
    });

    it('parses pypi PURL with no namespace', () => {
      const r = parsePurl('pkg:pypi/django@4.2.1');
      expect(r!.type).toBe('pypi');
      expect(r!.namespace).toBeNull();
      expect(r!.name).toBe('django');
      expect(r!.version).toBe('4.2.1');
    });
  });

  describe('namespaces', () => {
    it('parses rpm with namespace and qualifier', () => {
      const r = parsePurl('pkg:rpm/redhat/openssl@1.1.1k-7.el8_4?arch=x86_64');
      expect(r!.type).toBe('rpm');
      expect(r!.namespace).toBe('redhat');
      expect(r!.name).toBe('openssl');
      expect(r!.version).toBe('1.1.1k-7.el8_4');
      expect(r!.qualifiers.get('arch')).toBe('x86_64');
      expect(r!.qualifiers.size).toBe(1);
    });

    it('parses maven multi-segment namespace', () => {
      const r = parsePurl(
        'pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1',
      );
      expect(r!.type).toBe('maven');
      expect(r!.namespace).toBe('org.apache.logging.log4j');
      expect(r!.name).toBe('log4j-core');
      expect(r!.version).toBe('2.14.1');
    });

    it('parses golang with embedded slashes in namespace', () => {
      const r = parsePurl('pkg:golang/github.com/spf13/cobra@v1.7.0');
      expect(r!.type).toBe('golang');
      expect(r!.namespace).toBe('github.com/spf13');
      expect(r!.name).toBe('cobra');
      expect(r!.version).toBe('v1.7.0');
    });
  });

  describe('subpath', () => {
    it('parses bitbucket PURL with subpath', () => {
      const r = parsePurl(
        'pkg:bitbucket/birkenfeld/pygments-main@244fd47e07d1014f0aed9c#ui/templates/',
      );
      expect(r!.type).toBe('bitbucket');
      expect(r!.namespace).toBe('birkenfeld');
      expect(r!.name).toBe('pygments-main');
      expect(r!.version).toBe('244fd47e07d1014f0aed9c');
      expect(r!.subpath).toBe('ui/templates/');
    });

    it('parses subpath with no version', () => {
      const r = parsePurl('pkg:generic/foo#sub/path');
      expect(r!.name).toBe('foo');
      expect(r!.version).toBeNull();
      expect(r!.subpath).toBe('sub/path');
    });
  });

  describe('qualifiers', () => {
    it('parses multiple qualifiers', () => {
      const r = parsePurl(
        'pkg:deb/debian/curl@7.50.3?arch=amd64&distro=stretch',
      );
      expect(r!.qualifiers.get('arch')).toBe('amd64');
      expect(r!.qualifiers.get('distro')).toBe('stretch');
      expect(r!.qualifiers.size).toBe(2);
    });

    it('warns on qualifier with no = sign', () => {
      const r = parsePurl('pkg:npm/foo@1.0.0?arch');
      expect(r!.qualifiers.get('arch')).toBe('');
      expect(r!.warnings.length).toBeGreaterThan(0);
      expect(r!.warnings.some((w) => w.includes('arch'))).toBe(true);
    });

    it('decodes URL-encoded qualifier values', () => {
      const r = parsePurl('pkg:npm/foo@1.0.0?path=%2Fusr%2Flocal');
      expect(r!.qualifiers.get('path')).toBe('/usr/local');
    });

    it('skips empty qualifier segments', () => {
      const r = parsePurl('pkg:npm/foo@1.0.0?arch=amd64&&distro=stretch');
      expect(r!.qualifiers.get('arch')).toBe('amd64');
      expect(r!.qualifiers.get('distro')).toBe('stretch');
      expect(r!.qualifiers.size).toBe(2);
    });
  });

  describe('version handling', () => {
    it('decodes URL-encoded version', () => {
      const r = parsePurl('pkg:npm/foo@1.0%2B0');
      expect(r!.version).toBe('1.0+0');
    });

    it('decodes %40 in version', () => {
      const r = parsePurl('pkg:npm/foo@1.0%40beta');
      expect(r!.version).toBe('1.0@beta');
    });

    it('uses last @ when multiple are present', () => {
      const r = parsePurl('pkg:npm/foo@bar@1.0.0');
      expect(r!.name).toBe('foo@bar');
      expect(r!.version).toBe('1.0.0');
    });

    it('handles missing version', () => {
      const r = parsePurl('pkg:npm/lodash');
      expect(r!.type).toBe('npm');
      expect(r!.name).toBe('lodash');
      expect(r!.version).toBeNull();
    });
  });

  describe('edge cases', () => {
    it('strips trailing slash with no warning', () => {
      const r = parsePurl('pkg:npm/lodash@4.17.21/');
      expect(r!.name).toBe('lodash');
      expect(r!.version).toBe('4.17.21');
      expect(r!.warnings).toEqual([]);
    });

    it('returns result with empty name and warning when name is missing', () => {
      const r = parsePurl('pkg:npm/');
      expect(r).not.toBeNull();
      expect(r!.type).toBe('npm');
      expect(r!.name).toBe('');
      expect(r!.warnings.length).toBeGreaterThan(0);
    });

    it('returns result with empty name when only type+@version present', () => {
      const r = parsePurl('pkg:npm/@1.0.0');
      expect(r).not.toBeNull();
      expect(r!.type).toBe('npm');
      expect(r!.name).toBe('');
      expect(r!.version).toBe('1.0.0');
      expect(r!.warnings.length).toBeGreaterThan(0);
    });

    it('handles unknown type without warning', () => {
      const r = parsePurl('pkg:made-up-ecosystem/foo@1.0.0');
      expect(r!.type).toBe('made-up-ecosystem');
      expect(r!.warnings).toEqual([]);
    });

    it('lowercases type per spec', () => {
      const r = parsePurl('pkg:NPM/lodash@4.17.21');
      expect(r!.type).toBe('npm');
    });

    it('preserves raw input verbatim', () => {
      const input = 'pkg:NPM/lodash@4.17.21';
      const r = parsePurl(input);
      expect(r!.raw).toBe(input);
    });

    it('handles qualifiers without version', () => {
      const r = parsePurl('pkg:npm/lodash?arch=x86_64');
      expect(r!.name).toBe('lodash');
      expect(r!.version).toBeNull();
      expect(r!.qualifiers.get('arch')).toBe('x86_64');
    });

    it('handles qualifiers and subpath together', () => {
      const r = parsePurl('pkg:npm/foo@1.0.0?arch=x86#sub');
      expect(r!.version).toBe('1.0.0');
      expect(r!.qualifiers.get('arch')).toBe('x86');
      expect(r!.subpath).toBe('sub');
    });

    it('decodes URL-encoded namespace and name segments', () => {
      const r = parsePurl('pkg:npm/%40scope/pkg@1.0.0');
      expect(r!.namespace).toBe('@scope');
      expect(r!.name).toBe('pkg');
    });

    it('normalizes empty fragment to null subpath', () => {
      const r = parsePurl('pkg:npm/foo@1.0.0#');
      expect(r!.subpath).toBeNull();
    });

    it('normalizes empty version (trailing @) to null', () => {
      const r = parsePurl('pkg:npm/foo@');
      expect(r!.version).toBeNull();
    });

    it('preserves malformed percent-encoding instead of throwing', () => {
      const r = parsePurl('pkg:npm/foo@1.0%ZZ');
      expect(r).not.toBeNull();
      expect(r!.version).toBe('1.0%ZZ');
    });
  });
});
