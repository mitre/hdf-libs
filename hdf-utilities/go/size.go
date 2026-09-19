package hdfutil

import "fmt"

// DefaultMaxInputSize is the default maximum input size (256 MB) for loading HDF
// documents — matching the converters' DefaultMaxJSONSize and the CLI's file
// limit. Callers pass an explicit limit; <= 0 falls back to this default. Sized
// so large scanner-to-HDF conversions (output runs ~2x its input) stay readable
// by downstream commands at the default; the value is a memory-safety ceiling,
// not a correctness limit — raise it per-invocation with the CLI's --max-size.
const DefaultMaxInputSize = 256 * 1024 * 1024

// configuredMaxInputSize, when > 0, overrides DefaultMaxInputSize for callers
// that pass maxSize <= 0 ("use the default"). The host sets it once from its own
// configuration (the CLI from --max-size, an embedder from its config) so a
// raised ceiling reaches every converter's size guard — which passes a literal 0
// — without threading a value through ~50 call sites. Set once before any
// conversion; it is not meant to change under concurrent reads, mirroring the
// package-global converter version the registry already relies on.
var configuredMaxInputSize int

// SetDefaultMaxInputSize sets the process-wide fallback used when a caller passes
// maxSize <= 0. A value <= 0 restores the built-in DefaultMaxInputSize.
func SetDefaultMaxInputSize(maxSize int) {
	if maxSize < 0 {
		maxSize = 0
	}
	configuredMaxInputSize = maxSize
}

// ResolveMaxInputSize returns the effective byte limit for a caller-supplied
// maxSize: the explicit value when > 0, else the configured process default,
// else the built-in DefaultMaxInputSize. An explicit limit always wins, so a
// caller can still cap below the configured default.
func ResolveMaxInputSize(maxSize int) int {
	if maxSize > 0 {
		return maxSize
	}
	if configuredMaxInputSize > 0 {
		return configuredMaxInputSize
	}
	return DefaultMaxInputSize
}

// ValidateInputSize returns an error if input exceeds the effective limit for
// maxSize (see ResolveMaxInputSize; maxSize <= 0 uses the configured default or
// DefaultMaxInputSize). It is the schema-free size guard the engine loader and
// every converter run as their FIRST operation, before any parse — defense
// against memory exhaustion when loading untrusted documents.
func ValidateInputSize(input []byte, maxSize int) error {
	limit := ResolveMaxInputSize(maxSize)
	if len(input) > limit {
		return fmt.Errorf("input exceeds maximum allowed size of %d bytes (%d bytes provided)", limit, len(input))
	}
	return nil
}
