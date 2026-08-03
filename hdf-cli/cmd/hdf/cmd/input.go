// Package cmd implements the CLI commands for the hdf tool.
package cmd

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	hdfparsers "github.com/mitre/hdf-libs/hdf-parsers/go/v3"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
)

const (
	// DefaultMaxSizeMB is the default maximum file size in megabytes.
	DefaultMaxSizeMB = 50
)

// utf8BOM is the UTF-8 byte-order-mark sequence that some Windows tools prepend.
// Go/JS JSON parsers and CSV header matching choke on it, so it is stripped at
// the input boundary before any downstream consumer sees the bytes.
var utf8BOM = []byte{0xEF, 0xBB, 0xBF}

// getMaxFileSize returns the maximum allowed file size in bytes.
// Uses the --max-size flag if set, otherwise defaults to 50MB.
func getMaxFileSize() int64 {
	if maxSizeMB > 0 {
		return int64(maxSizeMB) * 1024 * 1024
	}
	return DefaultMaxSizeMB * 1024 * 1024
}

// readInputFile reads from a file path or stdin with security validations.
// It enforces size limits, validates the input is a regular file, and rejects
// empty input. Use readInputFileAllowEmpty on paths (e.g. convert) that must
// decide the empty-input policy themselves after resolving the target format.
func readInputFile(path string) ([]byte, error) {
	return readInput(path, false)
}

// readInputFileAllowEmpty is readInputFile without the empty-input rejection:
// it returns empty (zero-length) data instead of erroring. Callers are then
// responsible for the empty-input policy. Used by convert, where some formats
// (exit-code-first scanners) treat empty input as a valid zero-findings signal.
// All other size/type/symlink validations still apply.
func readInputFileAllowEmpty(path string) ([]byte, error) {
	return readInput(path, true)
}

// readInput reads from a file path or stdin with security validations. When
// allowEmpty is false, empty input is rejected with "no input provided"; when
// true, empty data is returned to the caller.
func readInput(path string, allowEmpty bool) ([]byte, error) {
	// Handle stdin
	var data []byte
	var err error
	if path == "" || path == "-" {
		data, err = readFromStdin(allowEmpty)
	} else {
		data, err = readFromFile(path, allowEmpty)
	}
	if err != nil {
		return nil, err
	}

	// Strip a leading UTF-8 BOM so every downstream consumer — auto-detect,
	// converters, schema validation — sees clean bytes regardless of whether
	// the file was produced on Windows.
	data = bytes.TrimPrefix(data, utf8BOM)
	if len(data) == 0 && !allowEmpty {
		// A file/stdin containing only a BOM passes the upstream non-empty
		// checks but has no real content; report it clearly instead of letting
		// downstream parsing emit a confusing "could not auto-detect" error.
		return nil, fmt.Errorf("no input provided")
	}
	return data, nil
}

// readFromStdin reads from stdin with a size limit. When allowEmpty is false,
// empty stdin is rejected.
func readFromStdin(allowEmpty bool) ([]byte, error) {
	maxSize := getMaxFileSize()
	limited := io.LimitReader(os.Stdin, maxSize+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("failed to read stdin: %w", err)
	}

	if int64(len(data)) > maxSize {
		return nil, fmt.Errorf("input too large: exceeds %d MB limit (use --max-size to increase)", maxSizeMB)
	}

	if len(data) == 0 && !allowEmpty {
		return nil, fmt.Errorf("no input provided")
	}

	return data, nil
}

// readFromFile reads a file with security validations. When allowEmpty is false,
// a zero-byte file is rejected.
func readFromFile(path string, allowEmpty bool) ([]byte, error) {
	// Check for symlinks if --no-follow-symlinks is set
	if noFollowSymlinks {
		linkInfo, err := os.Lstat(path)
		if err != nil {
			if os.IsNotExist(err) {
				return nil, fmt.Errorf("file not found: %s", path)
			}
			return nil, fmt.Errorf("cannot stat file: %w", err)
		}
		if linkInfo.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("refusing to follow symlink: %s (use without --no-follow-symlinks to allow)", path)
		}
	}

	// Open file first to get handle
	f, err := os.Open(path) // #nosec G304 -- CLI intentionally reads user-provided paths
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("file not found: %s", path)
		}
		if os.IsPermission(err) {
			return nil, fmt.Errorf("permission denied: %s", path)
		}
		return nil, fmt.Errorf("cannot open file: %w", err)
	}
	defer func() { _ = f.Close() }()

	// Validate file type and size
	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("cannot stat file: %w", err)
	}

	if info.IsDir() {
		return nil, fmt.Errorf("%s is a directory, not a file", path)
	}

	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}

	if info.Size() == 0 && !allowEmpty {
		return nil, fmt.Errorf("file is empty: %s", path)
	}

	maxSize := getMaxFileSize()
	if info.Size() > maxSize {
		return nil, fmt.Errorf("file too large: %d bytes (max %d MB, use --max-size to increase)",
			info.Size(), maxSizeMB)
	}

	// Read with limit as defense-in-depth
	data, err := io.ReadAll(io.LimitReader(f, maxSize))
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	return data, nil
}

// safePath joins baseDir and relPath, then verifies the result stays within
// baseDir. Returns an error if the resolved path escapes the base directory
// (e.g., via "../" traversal). This prevents JSON-controlled file paths from
// reading or writing arbitrary files on the filesystem.
func safePath(baseDir, relPath string) (string, error) {
	if relPath == "" {
		return "", fmt.Errorf("empty path")
	}
	resolved := filepath.Clean(filepath.Join(baseDir, relPath))
	base := filepath.Clean(baseDir) + string(os.PathSeparator)
	if !strings.HasPrefix(resolved, base) && resolved != filepath.Clean(baseDir) {
		return "", fmt.Errorf("path traversal detected: %q resolves outside base directory", relPath)
	}
	return resolved, nil
}

// parseHDFResults validates and parses JSON data into HdfResults via
// hdf-parsers (the canonical HDF parse path). Schema validation runs first
// as a gatekeeper, then JSON decode, then trailing-garbage check — all
// inside hdfparsers.ParseResults. hdf-parsers also normalizes bare InSpec
// timestamps before schema validation, so the CLI accepts real-world InSpec
// output that previously failed.
func parseHDFResults(data []byte) (hdf.HDFResults, error) {
	r := hdfparsers.ParseResults(data)
	if !r.Success {
		return hdf.HDFResults{}, errors.New(translateParserError(r.Error))
	}
	return *r.Data, nil
}

// parseHDFBaseline is the baseline counterpart to parseHDFResults.
//
//nolint:unparam // result is used in validate.go, linter can't see across files
func parseHDFBaseline(data []byte) (hdf.HDFBaseline, error) {
	r := hdfparsers.ParseBaseline(data)
	if !r.Success {
		return hdf.HDFBaseline{}, errors.New(translateParserError(r.Error))
	}
	return *r.Data, nil
}

// parseHDFSystem validates and parses JSON data into HDFSystem via hdf-parsers.
// Mirrors parseHDFResults / parseHDFBaseline; provided for CLI sites that
// want typed-struct access. Sites that operate on the doc as a generic map
// can call loadAndValidateHDFDoc instead. Kept for parity with the
// Go and TS hdf-parsers Parse* exports per project policy
// (memory: feedback_ts_go_library_parity).
//
//nolint:unused // CLI-internal helper; published as TS/Go API parity surface
func parseHDFSystem(data []byte) (hdf.HDFSystem, error) {
	r := hdfparsers.ParseSystem(data)
	if !r.Success {
		return hdf.HDFSystem{}, errors.New(translateParserError(r.Error))
	}
	return *r.Data, nil
}

// parseHDFPlan validates and parses JSON data into HDFPlan via hdf-parsers.
//
//nolint:unused // see parseHDFSystem
func parseHDFPlan(data []byte) (hdf.HDFPlan, error) {
	r := hdfparsers.ParsePlan(data)
	if !r.Success {
		return hdf.HDFPlan{}, errors.New(translateParserError(r.Error))
	}
	return *r.Data, nil
}

// parseHDFEvidencePackage validates and parses JSON data into HDFEvidencePackage via hdf-parsers.
//
//nolint:unused // see parseHDFSystem
func parseHDFEvidencePackage(data []byte) (hdf.HDFEvidencePackage, error) {
	r := hdfparsers.ParseEvidencePackage(data)
	if !r.Success {
		return hdf.HDFEvidencePackage{}, errors.New(translateParserError(r.Error))
	}
	return *r.Data, nil
}

// parseHDFComparison validates and parses JSON data into HDFComparison via hdf-parsers.
//
//nolint:unused // see parseHDFSystem
func parseHDFComparison(data []byte) (hdf.HDFComparison, error) {
	r := hdfparsers.ParseComparison(data)
	if !r.Success {
		return hdf.HDFComparison{}, errors.New(translateParserError(r.Error))
	}
	return *r.Data, nil
}

// loadAndValidateHDFDoc reads + schema-validates + unmarshals to a generic
// map[string]any. Used by consumer sites that perform load → map mutate →
// re-marshal flows (system.go, doc_set.go, evidence_build.go's System read)
// where typed-struct access is not the goal but the load-side schema gate IS.
//
// `expected` is the doc type the caller expects ("system", "plan",
// "evidencePackage", "comparison", "results", "baseline", or "amendments").
// The function errors when:
//   - the input's top-level shape doesn't match any known HDF doc type
//     (detectHDFDocType returns ("", false)) — would otherwise silently
//     pass validateHDFOutput's "not HDF-shaped" fallthrough
//   - the detected doc type doesn't match `expected`
//   - the schema validator rejects the input
//
// Pass `expected = ""` only when the caller genuinely accepts any HDF doc
// type (rare).
func loadAndValidateHDFDoc(data []byte, expected string) (map[string]any, error) {
	docType, ok := detectHDFDocType(data)
	if !ok {
		return nil, fmt.Errorf("input is not a recognized HDF document (no top-level discriminator key matched)")
	}
	if expected != "" && docType != expected {
		return nil, fmt.Errorf("input is HDF %s, expected HDF %s", docType, expected)
	}
	if err := validateHDFOutput(data); err != nil {
		return nil, fmt.Errorf("input failed schema validation: %w", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parse JSON: %w", err)
	}
	return doc, nil
}

// translateParserError rewrites hdf-parsers' error strings into the CLI's
// existing lowercase phrasing so user-facing messages stay consistent
// across every CLI command and existing test assertions keep working.
func translateParserError(parserErr string) string {
	if rest, ok := strings.CutPrefix(parserErr, "Schema validation failed: "); ok {
		return "schema validation failed: " + rest
	}
	if rest, ok := strings.CutPrefix(parserErr, "Invalid JSON: "); ok {
		// hdf-parsers' "unexpected trailing data after end of object" still
		// contains the CLI's historical "data after end of object" substring,
		// so existing trailing-garbage assertions pass. Other JSON errors
		// fall through here as "failed to parse JSON: <go-json-error>".
		if strings.Contains(rest, "unexpected trailing data after end of object") {
			return "invalid JSON: unexpected data after end of object"
		}
		return fmt.Sprintf("failed to parse JSON: %s", rest)
	}
	return parserErr
}
