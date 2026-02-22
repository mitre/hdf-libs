/**
 * Hash utilities for HDF content
 * Provides cryptographic hashing functions for content identification and integrity verification
 * Uses the Web Crypto API (globalThis.crypto.subtle) for browser and Node.js compatibility
 */

/**
 * Supported hash algorithms
 */
export type HashAlgorithm = 'sha256' | 'sha512';

/**
 * Supported output encodings
 */
export type HashEncoding = 'hex' | 'base64';

/**
 * Options for hash generation
 */
export interface HashOptions {
  /** Hash algorithm (default: 'sha256') */
  algorithm?: HashAlgorithm;
  /** Output encoding (default: 'hex') */
  encoding?: HashEncoding;
}

/** Map our algorithm names to Web Crypto algorithm identifiers */
const ALGORITHM_MAP: Record<HashAlgorithm, string> = {
  sha256: 'SHA-256',
  sha512: 'SHA-512',
};

/** Convert an ArrayBuffer to a hex string */
function bufferToHex(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let hex = '';
  for (const b of bytes) {
    hex += b.toString(16).padStart(2, '0');
  }
  return hex;
}

/** Convert an ArrayBuffer to a base64 string */
function bufferToBase64(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (const b of bytes) {
    binary += String.fromCharCode(b);
  }
  return btoa(binary);
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
 * const hash = await generateHash('hello world');
 * // Returns: 'b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9'
 * ```
 */
export async function generateHash(data: string, options: HashOptions = {}): Promise<string> {
  const { algorithm = 'sha256', encoding = 'hex' } = options;
  const webAlgorithm = ALGORITHM_MAP[algorithm];
  const encoded = new TextEncoder().encode(data);
  const hashBuffer = await globalThis.crypto.subtle.digest(webAlgorithm, encoded);
  return encoding === 'base64' ? bufferToBase64(hashBuffer) : bufferToHex(hashBuffer);
}

/**
 * Generate a SHA-256 hash (recommended for most use cases)
 *
 * @param data - String data to hash
 * @returns Hex-encoded SHA-256 hash
 *
 * @example
 * ```typescript
 * const hash = await sha256('hello world');
 * // Returns: 'b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9'
 * ```
 */
export async function sha256(data: string): Promise<string> {
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
 * const hash = await sha512('hello world');
 * // Returns: '309ecc489c12d6eb4cc40f50c902f2b4d0ed77ee511a7c7a9bcd3ca86d4cd86f989dd35bc5ff499670da34255b45b0cfd830e81f605dcf7dc5542e93ae9cd76f'
 * ```
 */
export async function sha512(data: string): Promise<string> {
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
 * const hash = await hashObject(control);
 * // Returns hash of the JSON-stringified object
 * ```
 */
export async function hashObject(obj: unknown, options: HashOptions = {}): Promise<string> {
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
 * const hash = await sha256(data);
 * const isValid = await verifyHash(data, hash); // true
 * ```
 */
export async function verifyHash(
  data: string,
  expectedHash: string,
  options: HashOptions = {}
): Promise<boolean> {
  const actualHash = await generateHash(data, options);
  return actualHash === expectedHash;
}
