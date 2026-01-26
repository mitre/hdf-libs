package cmd

import (
	"errors"
	"fmt"
	"strings"
)

// ErrConverterNotFound is returned when no converter exists for the requested format pair.
var ErrConverterNotFound = errors.New("converter not found")

// Converter defines the interface for format converters.
type Converter interface {
	// Convert transforms input bytes to output bytes.
	Convert(input []byte) ([]byte, error)

	// Name returns a human-readable name for this converter (used in help text).
	Name() string
}

// FormatPair represents a source-to-destination format conversion.
type FormatPair struct {
	Source string
	Dest   string
}

// String returns a human-readable representation of the format pair.
func (fp FormatPair) String() string {
	return fmt.Sprintf("%s -> %s", fp.Source, fp.Dest)
}

// converterRegistry holds all registered converters.
var converterRegistry = make(map[FormatPair]Converter)

// RegisterConverter adds a converter to the registry.
// Format names are normalized (lowercase, trimmed) before registration.
func RegisterConverter(source, dest string, converter Converter) {
	pair := FormatPair{
		Source: normalizeFormat(source),
		Dest:   normalizeFormat(dest),
	}
	converterRegistry[pair] = converter
}

// GetConverter retrieves a converter for the given format pair.
// Format names are normalized (lowercase, trimmed) before lookup.
// Returns ErrConverterNotFound if no converter is registered for the pair.
func GetConverter(source, dest string) (Converter, error) {
	pair := FormatPair{
		Source: normalizeFormat(source),
		Dest:   normalizeFormat(dest),
	}
	if conv, ok := converterRegistry[pair]; ok {
		return conv, nil
	}
	return nil, fmt.Errorf("%w: %s to %s", ErrConverterNotFound, source, dest)
}

// ListConverters returns all registered format pairs.
func ListConverters() []FormatPair {
	pairs := make([]FormatPair, 0, len(converterRegistry))
	for pair := range converterRegistry {
		pairs = append(pairs, pair)
	}
	return pairs
}

// normalizeFormat canonicalizes format names (lowercase, trimmed).
func normalizeFormat(f string) string {
	return strings.ToLower(strings.TrimSpace(f))
}
