package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
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

// VersionedConverter is an optional interface for converters that support
// multiple input format versions (e.g. SARIF 2.0 vs 2.1). Single-version
// converters need not implement this — they are unaffected.
type VersionedConverter interface {
	Converter
	// SetInputVersion sets the version of the input format to use for conversion.
	// An empty string means "use the latest supported version" (default behavior).
	SetInputVersion(version string)
	// SupportedVersions returns the list of supported input versions, latest first.
	SupportedVersions() []string
}

// OutputVersionSetter is an optional interface for converters that support
// setting the output schema version. Used by the HDF version converter
// when --to hdf@N specifies a version.
type OutputVersionSetter interface {
	SetOutputVersion(version string)
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

// HDFBaselineConvertFn is the signature for converters that produce HDF Baseline.
type HDFBaselineConvertFn func(input []byte, converterVersion string) (*hdf.HDFBaseline, error)

// hdfBaselineConverter wraps a HDFBaselineConvertFn, handling JSON
// serialization and error wrapping.
type hdfBaselineConverter struct {
	displayName string
	errPrefix   string
	convertFn   HDFBaselineConvertFn
}

func (c *hdfBaselineConverter) Name() string {
	return c.displayName
}

func (c *hdfBaselineConverter) Convert(input []byte) ([]byte, error) {
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

// registerHDFBaselineConverter registers an HDF Baseline converter under one
// source format name. The dest is always "hdf".
func registerHDFBaselineConverter(source, displayName, errPrefix string, fn HDFBaselineConvertFn) {
	RegisterConverter(source, "hdf", &hdfBaselineConverter{
		displayName: displayName,
		errPrefix:   errPrefix,
		convertFn:   fn,
	})
}

// RawConvertFn is the signature for converters that handle their own JSON
// serialization (e.g., auto-detect converters where the output type varies).
type RawConvertFn func(input []byte, converterVersion string) ([]byte, error)

// rawConverter wraps a RawConvertFn, handling error wrapping.
type rawConverter struct {
	displayName string
	errPrefix   string
	convertFn   RawConvertFn
}

func (c *rawConverter) Name() string {
	return c.displayName
}

func (c *rawConverter) Convert(input []byte) ([]byte, error) {
	result, err := c.convertFn(input, version)
	if err != nil {
		return nil, fmt.Errorf("%s conversion failed: %w", c.errPrefix, err)
	}
	return result, nil
}

// registerRawConverter registers a raw converter (handles its own JSON
// serialization) under one source format name. The dest is always "hdf".
func registerRawConverter(source, displayName, errPrefix string, fn RawConvertFn) {
	RegisterConverter(source, "hdf", &rawConverter{
		displayName: displayName,
		errPrefix:   errPrefix,
		convertFn:   fn,
	})
}

// HDFPlanConvertFn is the signature for converters that produce HDF Plan.
type HDFPlanConvertFn func(input []byte, converterVersion string) (*hdf.HDFPlan, error)

// hdfPlanConverter wraps a HDFPlanConvertFn, handling JSON serialization
// and error wrapping.
type hdfPlanConverter struct {
	displayName string
	errPrefix   string
	convertFn   HDFPlanConvertFn
}

func (c *hdfPlanConverter) Name() string {
	return c.displayName
}

func (c *hdfPlanConverter) Convert(input []byte) ([]byte, error) {
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

// registerHDFPlanConverter registers an HDF Plan converter under one source
// format name. The dest is always "hdf".
func registerHDFPlanConverter(source, displayName, errPrefix string, fn HDFPlanConvertFn) {
	RegisterConverter(source, "hdf", &hdfPlanConverter{
		displayName: displayName,
		errPrefix:   errPrefix,
		convertFn:   fn,
	})
}

// HDFAmendmentsConvertFn is the signature for converters that produce HDF Amendments.
type HDFAmendmentsConvertFn func(input []byte, converterVersion string) (*hdf.HDFAmendments, error)

// hdfAmendmentsConverter wraps a HDFAmendmentsConvertFn, handling JSON
// serialization and error wrapping.
type hdfAmendmentsConverter struct {
	displayName string
	errPrefix   string
	convertFn   HDFAmendmentsConvertFn
}

func (c *hdfAmendmentsConverter) Name() string {
	return c.displayName
}

func (c *hdfAmendmentsConverter) Convert(input []byte) ([]byte, error) {
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

// registerHDFAmendmentsConverter registers an HDF Amendments converter under
// one source format name. The dest is always "hdf".
func registerHDFAmendmentsConverter(source, displayName, errPrefix string, fn HDFAmendmentsConvertFn) {
	RegisterConverter(source, "hdf", &hdfAmendmentsConverter{
		displayName: displayName,
		errPrefix:   errPrefix,
		convertFn:   fn,
	})
}
