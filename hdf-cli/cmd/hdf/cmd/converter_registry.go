package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	hdf "github.com/mitre/hdf-schema"
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

// HDFResultsConvertFn is the standard signature for converters that produce HDF Results.
// Most converters in the monorepo share this signature.
type HDFResultsConvertFn func(input []byte, converterVersion string) (*hdf.HDFResults, error)

// hdfResultsConverter wraps a standard HDFResultsConvertFn, handling JSON
// serialization and error wrapping. This eliminates ~30 lines of boilerplate
// per converter that previously required a dedicated struct and file.
type hdfResultsConverter struct {
	displayName string
	errPrefix   string
	convertFn   HDFResultsConvertFn
}

func (c *hdfResultsConverter) Name() string {
	return c.displayName
}

func (c *hdfResultsConverter) Convert(input []byte) ([]byte, error) {
	result, err := c.convertFn(input, version)
	if err != nil {
		return nil, fmt.Errorf("%s conversion failed: %w", c.errPrefix, err)
	}

	output, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to serialize HDF output: %w", err)
	}

	return output, nil
}

// registerHDFConverter registers a standard HDF Results converter under one
// source format name. The dest is always "hdf". Use registerHDFConverterMulti
// for converters that accept multiple source format names (e.g., xccdf + arf).
func registerHDFConverter(source, displayName, errPrefix string, fn HDFResultsConvertFn) {
	RegisterConverter(source, "hdf", &hdfResultsConverter{
		displayName: displayName,
		errPrefix:   errPrefix,
		convertFn:   fn,
	})
}

// registerHDFConverterMulti registers a standard HDF Results converter under
// multiple source format names, sharing a single converter instance.
// The dest is always "hdf".
func registerHDFConverterMulti(sources []string, displayName, errPrefix string, fn HDFResultsConvertFn) {
	c := &hdfResultsConverter{
		displayName: displayName,
		errPrefix:   errPrefix,
		convertFn:   fn,
	}
	for _, src := range sources {
		RegisterConverter(src, "hdf", c)
	}
}
