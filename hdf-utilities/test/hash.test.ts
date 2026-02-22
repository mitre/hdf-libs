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
    it('should generate SHA-256 hash by default', async () => {
      const hash = await generateHash('hello world');
      expect(hash).toBe(
        'b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9'
      );
    });

    it('should generate SHA-512 hash when specified', async () => {
      const hash = await generateHash('hello world', { algorithm: 'sha512' });
      expect(hash).toBe(
        '309ecc489c12d6eb4cc40f50c902f2b4d0ed77ee511a7c7a9bcd3ca86d4cd86f989dd35bc5ff499670da34255b45b0cfd830e81f605dcf7dc5542e93ae9cd76f'
      );
    });

    it('should support different encodings', async () => {
      const hexHash = await generateHash('hello world', { encoding: 'hex' });
      const base64Hash = await generateHash('hello world', { encoding: 'base64' });

      expect(hexHash).toBe(
        'b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9'
      );
      expect(base64Hash).toBe('uU0nuZNNPgilLlLX2n2r+sSE7+N6U4DukIj3rOLvzek=');
    });

    it('should generate consistent hashes for same input', async () => {
      const hash1 = await generateHash('test data');
      const hash2 = await generateHash('test data');
      expect(hash1).toBe(hash2);
    });

    it('should generate different hashes for different inputs', async () => {
      const hash1 = await generateHash('test data 1');
      const hash2 = await generateHash('test data 2');
      expect(hash1).not.toBe(hash2);
    });

    it('should handle empty strings', async () => {
      const hash = await generateHash('');
      expect(hash).toBe(
        'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
      );
    });

    it('should handle unicode characters', async () => {
      const hash = await generateHash('Hello 世界 🌍');
      expect(hash).toHaveLength(64); // SHA-256 produces 64 hex characters
      expect(typeof hash).toBe('string');
    });

    it('should handle special characters', async () => {
      const hash = await generateHash('!@#$%^&*()_+-=[]{}|;:,.<>?');
      expect(hash).toHaveLength(64);
      expect(typeof hash).toBe('string');
    });
  });

  describe('sha256', () => {
    it('should generate SHA-256 hash', async () => {
      const hash = await sha256('hello world');
      expect(hash).toBe(
        'b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9'
      );
    });

    it('should be equivalent to generateHash with sha256 algorithm', async () => {
      const data = 'test data';
      expect(await sha256(data)).toBe(await generateHash(data, { algorithm: 'sha256' }));
    });

    it('should handle long strings', async () => {
      const longString = 'a'.repeat(10000);
      const hash = await sha256(longString);
      expect(hash).toHaveLength(64);
    });
  });

  describe('sha512', () => {
    it('should generate SHA-512 hash', async () => {
      const hash = await sha512('hello world');
      expect(hash).toBe(
        '309ecc489c12d6eb4cc40f50c902f2b4d0ed77ee511a7c7a9bcd3ca86d4cd86f989dd35bc5ff499670da34255b45b0cfd830e81f605dcf7dc5542e93ae9cd76f'
      );
    });

    it('should be equivalent to generateHash with sha512 algorithm', async () => {
      const data = 'test data';
      expect(await sha512(data)).toBe(await generateHash(data, { algorithm: 'sha512' }));
    });

    it('should produce 128 character hex string', async () => {
      const hash = await sha512('test');
      expect(hash).toHaveLength(128);
    });
  });

  describe('hashObject', () => {
    it('should hash an object by stringifying it', async () => {
      const obj = { id: 'V-12345', title: 'Test Control' };
      const hash = await hashObject(obj);
      expect(hash).toHaveLength(64); // SHA-256 default
      expect(typeof hash).toBe('string');
    });

    it('should generate consistent hashes for same object', async () => {
      const obj = { a: 1, b: 2, c: 3 };
      const hash1 = await hashObject(obj);
      const hash2 = await hashObject(obj);
      expect(hash1).toBe(hash2);
    });

    it('should generate different hashes for different objects', async () => {
      const obj1 = { a: 1, b: 2 };
      const obj2 = { a: 1, b: 3 };
      const hash1 = await hashObject(obj1);
      const hash2 = await hashObject(obj2);
      expect(hash1).not.toBe(hash2);
    });

    it('should handle nested objects', async () => {
      const obj = {
        control: {
          id: 'V-12345',
          results: [
            { status: 'passed', message: 'OK' },
            { status: 'failed', message: 'Error' },
          ],
        },
      };
      const hash = await hashObject(obj);
      expect(hash).toHaveLength(64);
    });

    it('should handle arrays', async () => {
      const arr = [1, 2, 3, 4, 5];
      const hash = await hashObject(arr);
      expect(hash).toHaveLength(64);
    });

    it('should handle null and undefined', async () => {
      const hashNull = await hashObject(null);
      const hashUndef = await hashObject(undefined);
      expect(hashNull).toHaveLength(64);
      expect(hashUndef).toHaveLength(64);
      expect(hashNull).not.toBe(hashUndef);
    });

    it('should support different algorithms', async () => {
      const obj = { test: 'data' };
      const sha256Hash = await hashObject(obj, { algorithm: 'sha256' });
      const sha512Hash = await hashObject(obj, { algorithm: 'sha512' });
      expect(sha256Hash).toHaveLength(64);
      expect(sha512Hash).toHaveLength(128);
    });

    it('should be sensitive to property order', async () => {
      // JSON.stringify is sensitive to property order
      const obj1 = { a: 1, b: 2 };
      const obj2 = { b: 2, a: 1 };
      const hash1 = await hashObject(obj1);
      const hash2 = await hashObject(obj2);
      // These will be different because JSON.stringify preserves insertion order
      expect(hash1).not.toBe(hash2);
    });
  });

  describe('verifyHash', () => {
    it('should verify correct hash', async () => {
      const data = 'hello world';
      const hash = await sha256(data);
      expect(await verifyHash(data, hash)).toBe(true);
    });

    it('should reject incorrect hash', async () => {
      const data = 'hello world';
      const wrongHash = await sha256('different data');
      expect(await verifyHash(data, wrongHash)).toBe(false);
    });

    it('should work with different algorithms', async () => {
      const data = 'test data';
      const sha256Hash = await sha256(data);
      expect(await verifyHash(data, sha256Hash, { algorithm: 'sha256' })).toBe(true);

      const sha512Hash = await sha512(data);
      expect(await verifyHash(data, sha512Hash, { algorithm: 'sha512' })).toBe(true);
    });

    it('should be case-sensitive for hash value', async () => {
      const data = 'test';
      const hash = (await sha256(data)).toUpperCase();
      // Crypto hashes are lowercase hex by default
      expect(await verifyHash(data, hash)).toBe(false);
    });

    it('should handle empty data', async () => {
      const data = '';
      const hash = await sha256(data);
      expect(await verifyHash(data, hash)).toBe(true);
    });

    it('should fail for partial hash', async () => {
      const data = 'test';
      const fullHash = await sha256(data);
      const partialHash = fullHash.substring(0, 32);
      expect(await verifyHash(data, partialHash)).toBe(false);
    });
  });

  describe('explicit algorithm option', () => {
    it('explicit sha256 algorithm matches default', async () => {
      const data = 'test data for algorithm option';
      const defaultHash = await generateHash(data);
      const explicitHash = await generateHash(data, { algorithm: 'sha256' });
      expect(explicitHash).toBe(defaultHash);
    });
  });

  describe('hashObject undefined handling', () => {
    it('undefined value is serialized as string "undefined"', async () => {
      // hashObject serializes undefined as the string 'undefined', not JSON.stringify(undefined) = undefined
      const hashUndef = await hashObject(undefined);
      const hashStrUndef = await generateHash('undefined');
      expect(hashUndef).toBe(hashStrUndef);
    });

    it('null is distinct from undefined', async () => {
      const hashNull = await hashObject(null);
      const hashUndef = await hashObject(undefined);
      expect(hashNull).not.toBe(hashUndef);
    });
  });

  describe('Real-world HDF use cases', () => {
    it('should hash HDF control object consistently', async () => {
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

      const hash1 = await hashObject(control);
      const hash2 = await hashObject(control);
      expect(hash1).toBe(hash2);
      expect(hash1).toHaveLength(64);
    });

    it('should generate different hashes for controls with different results', async () => {
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

      const hash1 = await hashObject(control1);
      const hash2 = await hashObject(control2);
      expect(hash1).not.toBe(hash2);
    });

    it('should hash profile metadata', async () => {
      const profile = {
        name: 'canonical-ubuntu-16.04-lts-stig-baseline',
        version: '1.0.0',
        title: 'Canonical Ubuntu 16.04 LTS Security Technical Implementation Guide',
        maintainer: 'MITRE SAF Team',
        summary: 'Canonical Ubuntu 16.04 LTS STIG Baseline',
        license: 'Apache-2.0',
        copyright: 'MITRE',
      };

      const hash = await hashObject(profile);
      expect(hash).toHaveLength(64);
      expect(typeof hash).toBe('string');
    });
  });
});
