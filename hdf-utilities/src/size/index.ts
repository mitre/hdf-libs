// Schema-free input-size guard — the TS peer of hdf-utilities/go/size.go, kept
// at behavioural parity. The engine loader runs it as its FIRST operation,
// before any parse, to defend against memory exhaustion on untrusted input.

/** Default maximum input size (50 MB), matching the Go DefaultMaxInputSize. */
export const DEFAULT_MAX_INPUT_SIZE = 50 * 1024 * 1024;

// configuredMaxInputSize, when > 0, overrides DEFAULT_MAX_INPUT_SIZE for callers
// that pass maxSize <= 0 ("use the default"). A host sets it once from its own
// configuration so a raised ceiling reaches every converter's size guard — which
// passes 0 — without threading a value through every call site. The Go peer is
// hdfutil.configuredMaxInputSize / SetDefaultMaxInputSize.
let configuredMaxInputSize = 0;

/**
 * setDefaultMaxInputSize sets the process-wide fallback used when a caller passes
 * maxSize <= 0. A value <= 0 restores the built-in DEFAULT_MAX_INPUT_SIZE.
 */
export function setDefaultMaxInputSize(maxSize: number): void {
  configuredMaxInputSize = maxSize > 0 ? maxSize : 0;
}

/**
 * resolveMaxInputSize returns the effective byte limit for a caller-supplied
 * maxSize: the explicit value when > 0, else the configured process default, else
 * DEFAULT_MAX_INPUT_SIZE. An explicit limit always wins.
 */
export function resolveMaxInputSize(maxSize = 0): number {
  if (maxSize > 0) return maxSize;
  if (configuredMaxInputSize > 0) return configuredMaxInputSize;
  return DEFAULT_MAX_INPUT_SIZE;
}

/**
 * validateInputSize throws if input exceeds the effective limit for maxSize (see
 * resolveMaxInputSize; maxSize <= 0 uses the configured default or
 * DEFAULT_MAX_INPUT_SIZE). Byte length is measured on the UTF-8 encoding for a
 * string input, so it matches the Go []byte length for the same document.
 */
export function validateInputSize(input: string | Uint8Array, maxSize = 0): void {
  const limit = resolveMaxInputSize(maxSize);
  if (typeof input !== 'string') {
    if (input.length > limit) throw tooLarge(limit, input.length);
    return;
  }
  // UTF-8 never uses fewer than one byte per code unit nor more than three, so
  // the cheap bound settles most inputs before anything reads the string.
  if (input.length * 3 <= limit) return;
  const len = utf8ByteLength(input);
  if (len > limit) throw tooLarge(limit, len);
}

function tooLarge(limit: number, len: number): Error {
  return new Error(`input exceeds maximum allowed size of ${limit} bytes (${len} bytes provided)`);
}

/**
 * UTF-8 byte length, counted rather than encoded: a TextEncoder pass would
 * allocate a full copy of the very input this guard exists to reject.
 * An unpaired surrogate counts as the three-byte replacement character, which
 * is what TextEncoder emits for one.
 */
function utf8ByteLength(s: string): number {
  let bytes = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c < 0x80) {
      bytes += 1;
    } else if (c < 0x800) {
      bytes += 2;
    } else if (c >= 0xd800 && c <= 0xdbff && (s.charCodeAt(i + 1) & 0xfc00) === 0xdc00) {
      bytes += 4;
      i++;
    } else {
      bytes += 3;
    }
  }
  return bytes;
}
