import { describe, it, expect } from 'vitest';
import {
  generateHash,
  sha256,
  sha512,
  hashObject,
  verifyHash,
} from '../src/hash/index.js';

describe('Hash Utilities', () => {
  describe('generateHash', () => {
    it('should generate SHA-256 hash by default', () => {
      const hash = generateHash('hello world');
      expect(hash).toBe(
        'b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9'
      );
    });

    it('should generate SHA-512 hash when specified', () => {
      const hash = generateHash('hello world', { algorithm: 'sha512' });
      expect(hash).toBe(
        '309ecc489c12d6eb4cc40f50c902f2b4d0ed77ee511a7c7a9bcd3ca86d4cd86f989dd35bc5ff499670da34255b45b0cfd830e81f605dcf7dc5542e93ae9cd76f'
      );
    });

    it('should support different encodings', () => {
      const hexHash = generateHash('hello world', { encoding: 'hex' });
      const base64Hash = generateHash('hello world', { encoding: 'base64' });

      expect(hexHash).toBe(
        'b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9'
      );
      expect(base64Hash).toBe('uU0nuZNNPgilLlLX2n2r+sSE7+N6U4DukIj3rOLvzek=');
    });

    it('should generate consistent hashes for same input', () => {
      const hash1 = generateHash('test data');
      const hash2 = generateHash('test data');
      expect(hash1).toBe(hash2);
    });

    it('should generate different hashes for different inputs', () => {
      const hash1 = generateHash('test data 1');
      const hash2 = generateHash('test data 2');
      expect(hash1).not.toBe(hash2);
    });

    it('should handle empty strings', () => {
      const hash = generateHash('');
      expect(hash).toBe(
        'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
      );
    });

    it('should handle unicode characters', () => {
      const hash = generateHash('Hello 世界 🌍');
      expect(hash).toHaveLength(64); // SHA-256 produces 64 hex characters
      expect(typeof hash).toBe('string');
    });

    it('should handle special characters', () => {
      const hash = generateHash('!@#$%^&*()_+-=[]{}|;:,.<>?');
      expect(hash).toHaveLength(64);
      expect(typeof hash).toBe('string');
    });
  });

  describe('sha256', () => {
    it('should generate SHA-256 hash', () => {
      const hash = sha256('hello world');
      expect(hash).toBe(
        'b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9'
      );
    });

    it('should be equivalent to generateHash with sha256 algorithm', () => {
      const data = 'test data';
      expect(sha256(data)).toBe(generateHash(data, { algorithm: 'sha256' }));
    });

    it('should handle long strings', () => {
      const longString = 'a'.repeat(10000);
      const hash = sha256(longString);
      expect(hash).toHaveLength(64);
    });
  });

  describe('sha512', () => {
    it('should generate SHA-512 hash', () => {
      const hash = sha512('hello world');
      expect(hash).toBe(
        '309ecc489c12d6eb4cc40f50c902f2b4d0ed77ee511a7c7a9bcd3ca86d4cd86f989dd35bc5ff499670da34255b45b0cfd830e81f605dcf7dc5542e93ae9cd76f'
      );
    });

    it('should be equivalent to generateHash with sha512 algorithm', () => {
      const data = 'test data';
      expect(sha512(data)).toBe(generateHash(data, { algorithm: 'sha512' }));
    });

    it('should produce 128 character hex string', () => {
      const hash = sha512('test');
      expect(hash).toHaveLength(128);
    });
  });

  describe('hashObject', () => {
    it('should hash an object by stringifying it', () => {
      const obj = { id: 'V-12345', title: 'Test Control' };
      const hash = hashObject(obj);
      expect(hash).toHaveLength(64); // SHA-256 default
      expect(typeof hash).toBe('string');
    });

    it('should generate consistent hashes for same object', () => {
      const obj = { a: 1, b: 2, c: 3 };
      const hash1 = hashObject(obj);
      const hash2 = hashObject(obj);
      expect(hash1).toBe(hash2);
    });

    it('should generate different hashes for different objects', () => {
      const obj1 = { a: 1, b: 2 };
      const obj2 = { a: 1, b: 3 };
      const hash1 = hashObject(obj1);
      const hash2 = hashObject(obj2);
      expect(hash1).not.toBe(hash2);
    });

    it('should handle nested objects', () => {
      const obj = {
        control: {
          id: 'V-12345',
          results: [
            { status: 'passed', message: 'OK' },
            { status: 'failed', message: 'Error' },
          ],
        },
      };
      const hash = hashObject(obj);
      expect(hash).toHaveLength(64);
    });

    it('should handle arrays', () => {
      const arr = [1, 2, 3, 4, 5];
      const hash = hashObject(arr);
      expect(hash).toHaveLength(64);
    });

    it('should handle null and undefined', () => {
      const hashNull = hashObject(null);
      const hashUndef = hashObject(undefined);
      expect(hashNull).toHaveLength(64);
      expect(hashUndef).toHaveLength(64);
      expect(hashNull).not.toBe(hashUndef);
    });

    it('should support different algorithms', () => {
      const obj = { test: 'data' };
      const sha256Hash = hashObject(obj, { algorithm: 'sha256' });
      const sha512Hash = hashObject(obj, { algorithm: 'sha512' });
      expect(sha256Hash).toHaveLength(64);
      expect(sha512Hash).toHaveLength(128);
    });

    it('should be sensitive to property order', () => {
      // JSON.stringify is sensitive to property order
      const obj1 = { a: 1, b: 2 };
      const obj2 = { b: 2, a: 1 };
      const hash1 = hashObject(obj1);
      const hash2 = hashObject(obj2);
      // These will be different because JSON.stringify preserves insertion order
      expect(hash1).not.toBe(hash2);
    });
  });

  describe('verifyHash', () => {
    it('should verify correct hash', () => {
      const data = 'hello world';
      const hash = sha256(data);
      expect(verifyHash(data, hash)).toBe(true);
    });

    it('should reject incorrect hash', () => {
      const data = 'hello world';
      const wrongHash = sha256('different data');
      expect(verifyHash(data, wrongHash)).toBe(false);
    });

    it('should work with different algorithms', () => {
      const data = 'test data';
      const sha256Hash = sha256(data);
      expect(verifyHash(data, sha256Hash, { algorithm: 'sha256' })).toBe(true);

      const sha512Hash = sha512(data);
      expect(verifyHash(data, sha512Hash, { algorithm: 'sha512' })).toBe(true);
    });

    it('should be case-sensitive for hash value', () => {
      const data = 'test';
      const hash = sha256(data).toUpperCase();
      // Crypto hashes are lowercase hex by default
      expect(verifyHash(data, hash)).toBe(false);
    });

    it('should handle empty data', () => {
      const data = '';
      const hash = sha256(data);
      expect(verifyHash(data, hash)).toBe(true);
    });

    it('should fail for partial hash', () => {
      const data = 'test';
      const fullHash = sha256(data);
      const partialHash = fullHash.substring(0, 32);
      expect(verifyHash(data, partialHash)).toBe(false);
    });
  });

  describe('explicit algorithm option', () => {
    it('explicit sha256 algorithm matches default', () => {
      const data = 'test data for algorithm option';
      const defaultHash = generateHash(data);
      const explicitHash = generateHash(data, { algorithm: 'sha256' });
      expect(explicitHash).toBe(defaultHash);
    });
  });

  describe('hashObject undefined handling', () => {
    it('undefined value is serialized as string "undefined"', () => {
      // hashObject serializes undefined as the string 'undefined', not JSON.stringify(undefined) = undefined
      const hashUndef = hashObject(undefined);
      const hashStrUndef = generateHash('undefined');
      expect(hashUndef).toBe(hashStrUndef);
    });

    it('null is distinct from undefined', () => {
      const hashNull = hashObject(null);
      const hashUndef = hashObject(undefined);
      expect(hashNull).not.toBe(hashUndef);
    });
  });

  describe('Real-world HDF use cases', () => {
    it('should hash HDF control object consistently', () => {
      const control = {
        id: 'V-67373',
        title: 'The Ubuntu operating system must display the Standard Mandatory DoD Notice',
        desc: 'Display of a standardized and approved use notification...',
        impact: 0.5,
        tags: {
          severity: 'medium',
          gtitle: 'SRG-OS-000023-GPOS-00006',
          gid: 'V-67373',
          rid: 'SV-81863r2_rule',
          stig_id: 'UBTU-16-010010',
          fix_id: 'F-73487r1_fix',
          cci: ['CCI-000048'],
          nist: ['AC-8 a', 'Rev_4'],
        },
        results: [
          {
            status: 'passed',
            code_desc: 'File /etc/issue should be file',
            run_time: 0.002912,
            start_time: '2023-10-24T10:15:30-05:00',
          },
        ],
      };

      const hash1 = hashObject(control);
      const hash2 = hashObject(control);
      expect(hash1).toBe(hash2);
      expect(hash1).toHaveLength(64);
    });

    it('should generate different hashes for controls with different results', () => {
      const baseControl = {
        id: 'V-67373',
        title: 'Test Control',
        impact: 0.5,
      };

      const control1 = {
        ...baseControl,
        results: [{ status: 'passed' }],
      };

      const control2 = {
        ...baseControl,
        results: [{ status: 'failed' }],
      };

      const hash1 = hashObject(control1);
      const hash2 = hashObject(control2);
      expect(hash1).not.toBe(hash2);
    });

    it('should hash profile metadata', () => {
      const profile = {
        name: 'canonical-ubuntu-16.04-lts-stig-baseline',
        version: '1.0.0',
        title: 'Canonical Ubuntu 16.04 LTS Security Technical Implementation Guide',
        maintainer: 'MITRE SAF Team',
        summary: 'Canonical Ubuntu 16.04 LTS STIG Baseline',
        license: 'Apache-2.0',
        copyright: 'MITRE',
      };

      const hash = hashObject(profile);
      expect(hash).toHaveLength(64);
      expect(typeof hash).toBe('string');
    });
  });
});
