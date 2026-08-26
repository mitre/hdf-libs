package hdfutil

import "fmt"

// DefaultMaxInputSize is the default maximum input size (50 MB) for loading HDF
// documents — matching the converters' DefaultMaxJSONSize and the CLI's file
// limit. Callers pass an explicit limit; <= 0 falls back to this default.
const DefaultMaxInputSize = 50 * 1024 * 1024

// ValidateInputSize returns an error if input exceeds maxSize bytes (maxSize
// <= 0 uses DefaultMaxInputSize). It is the schema-free size guard the engine
// loader runs as its FIRST operation, before any parse — defense against
// memory exhaustion when loading untrusted documents.
func ValidateInputSize(input []byte, maxSize int) error {
	if maxSize <= 0 {
		maxSize = DefaultMaxInputSize
	}
	if len(input) > maxSize {
		return fmt.Errorf("input exceeds maximum allowed size of %d bytes (%d bytes provided)", maxSize, len(input))
	}
	return nil
}
