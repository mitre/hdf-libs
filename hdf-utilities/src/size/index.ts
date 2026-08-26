// Schema-free input-size guard — the TS peer of hdf-utilities/go/size.go, kept
// at behavioural parity. The engine loader runs it as its FIRST operation,
// before any parse, to defend against memory exhaustion on untrusted input.

/** Default maximum input size (50 MB), matching the Go DefaultMaxInputSize. */
export const DEFAULT_MAX_INPUT_SIZE = 50 * 1024 * 1024;

/**
 * validateInputSize throws if input exceeds maxSize bytes (maxSize <= 0 uses
 * DEFAULT_MAX_INPUT_SIZE). Byte length is measured on the UTF-8 encoding for a
 * string input, so it matches the Go []byte length for the same document.
 */
export function validateInputSize(input: string | Uint8Array, maxSize = 0): void {
  const limit = maxSize > 0 ? maxSize : DEFAULT_MAX_INPUT_SIZE;
  const len = typeof input === 'string' ? new TextEncoder().encode(input).length : input.length;
  if (len > limit) {
    throw new Error(`input exceeds maximum allowed size of ${limit} bytes (${len} bytes provided)`);
  }
}
