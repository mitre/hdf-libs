/**
 * Hash utilities for HDF content
 * Provides cryptographic hashing functions for content identification and integrity verification
 */

import { createHash } from 'node:crypto';
import type { BinaryToTextEncoding } from 'node:crypto';

/**
 * Supported hash algorithms
 */
export type HashAlgorithm = 'sha256' | 'sha512';

/**
 * Supported output encodings
 */
export type HashEncoding = BinaryToTextEncoding;

/**
 * Options for hash generation
 */
export interface HashOptions {
  /** Hash algorithm (default: 'sha256') */
  algorithm?: HashAlgorithm;
  /** Output encoding (default: 'hex') */
  encoding?: HashEncoding;
}

/**
 * Generate a hash of the given data
 *
 * @param data - String data to hash
 * @param options - Hash generation options
 * @returns Hex-encoded hash string
 *
 * @example
 * ```typescript
 * const hash = generateHash('hello world');
 * // Returns: 'b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9'
 * ```
 */
export function generateHash(data: string, options: HashOptions = {}): string {
  const { algorithm = 'sha256', encoding = 'hex' } = options;
  const hash = createHash(algorithm);
  return hash.update(data).digest(encoding);
}

/**
 * Generate a SHA-256 hash (recommended for most use cases)
 *
 * @param data - String data to hash
 * @returns Hex-encoded SHA-256 hash
 *
 * @example
 * ```typescript
 * const hash = sha256('hello world');
 * // Returns: 'b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9'
 * ```
 */
export function sha256(data: string): string {
  return generateHash(data, { algorithm: 'sha256' });
}

/**
 * Generate a SHA-512 hash (enhanced security for sensitive data)
 *
 * @param data - String data to hash
 * @returns Hex-encoded SHA-512 hash
 *
 * @example
 * ```typescript
 * const hash = sha512('hello world');
 * // Returns: '309ecc489c12d6eb4cc40f50c902f2b4d0ed77ee511a7c7a9bcd3ca86d4cd86f989dd35bc5ff499670da34255b45b0cfd830e81f605dcf7dc5542e93ae9cd76f'
 * ```
 */
export function sha512(data: string): string {
  return generateHash(data, { algorithm: 'sha512' });
}

/**
 * Generate a hash of an object by stringifying it first
 * Useful for hashing HDF control objects or other structured data
 *
 * @param obj - Object to hash
 * @param options - Hash generation options
 * @returns Hex-encoded hash string
 *
 * @example
 * ```typescript
 * const control = { id: 'V-12345', title: 'Test Control' };
 * const hash = hashObject(control);
 * // Returns hash of the JSON-stringified object
 * ```
 */
export function hashObject(obj: unknown, options: HashOptions = {}): string {
  // JSON.stringify returns undefined for undefined, so handle it explicitly
  const stringified = obj === undefined ? 'undefined' : JSON.stringify(obj);
  return generateHash(stringified, options);
}

/**
 * Verify that data matches a given hash
 *
 * @param data - String data to verify
 * @param expectedHash - Expected hash value
 * @param options - Hash generation options (must match hash generation)
 * @returns True if data matches the hash
 *
 * @example
 * ```typescript
 * const data = 'hello world';
 * const hash = sha256(data);
 * const isValid = verifyHash(data, hash); // true
 * ```
 */
export function verifyHash(
  data: string,
  expectedHash: string,
  options: HashOptions = {}
): boolean {
  const actualHash = generateHash(data, options);
  return actualHash === expectedHash;
}
