// Package cmd implements the CLI commands for the hdf tool.
package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	validators "github.com/mitre/hdf-libs/hdf-validators/go/v3"
)

const (
	// DefaultMaxSizeMB is the default maximum file size in megabytes.
	DefaultMaxSizeMB = 50
)

// getMaxFileSize returns the maximum allowed file size in bytes.
// Uses the --max-size flag if set, otherwise defaults to 50MB.
func getMaxFileSize() int64 {
	if maxSizeMB > 0 {
		return int64(maxSizeMB) * 1024 * 1024
	}
	return DefaultMaxSizeMB * 1024 * 1024
}

// readInputFile reads from a file path or stdin with security validations.
// It enforces size limits and validates the input is a regular file.
func readInputFile(path string) ([]byte, error) {
	// Handle stdin
	if path == "" || path == "-" {
		return readFromStdin()
	}

	return readFromFile(path)
}

// readFromStdin reads from stdin with a size limit.
func readFromStdin() ([]byte, error) {
	maxSize := getMaxFileSize()
	limited := io.LimitReader(os.Stdin, maxSize+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("failed to read stdin: %w", err)
	}

	if int64(len(data)) > maxSize {
		return nil, fmt.Errorf("input too large: exceeds %d MB limit (use --max-size to increase)", maxSizeMB)
	}

	if len(data) == 0 {
		return nil, fmt.Errorf("no input provided")
	}

	return data, nil
}

// readFromFile reads a file with security validations.
func readFromFile(path string) ([]byte, error) {
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

	if info.Size() == 0 {
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

// parseHDFResults validates and parses JSON data into HdfResults.
// This acts as a gatekeeper - invalid data never reaches processing logic.
func parseHDFResults(data []byte) (hdf.HDFResults, error) {
	var results hdf.HDFResults

	// Step 1: Validate against JSON Schema (gatekeeper)
	validationResult := validators.ValidateResults(data)
	if !validationResult.Valid {
		return results, fmt.Errorf("schema validation failed: %s", validationResult.Error())
	}

	// Step 2: Parse into typed struct (only reached if schema valid)
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(&results); err != nil {
		return results, fmt.Errorf("failed to parse JSON: %w", err)
	}

	// Step 3: Check for trailing garbage
	if decoder.More() {
		return results, fmt.Errorf("invalid JSON: unexpected data after end of object")
	}

	return results, nil
}

// parseHDFBaseline validates and parses JSON data into HdfBaseline.
// This acts as a gatekeeper - invalid data never reaches processing logic.
//
//nolint:unparam // result is used in validate.go, linter can't see across files
func parseHDFBaseline(data []byte) (hdf.HDFBaseline, error) {
	var baseline hdf.HDFBaseline

	// Step 1: Validate against JSON Schema (gatekeeper)
	validationResult := validators.ValidateBaseline(data)
	if !validationResult.Valid {
		return baseline, fmt.Errorf("schema validation failed: %s", validationResult.Error())
	}

	// Step 2: Parse into typed struct (only reached if schema valid)
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(&baseline); err != nil {
		return baseline, fmt.Errorf("failed to parse JSON: %w", err)
	}

	// Step 3: Check for trailing garbage
	if decoder.More() {
		return baseline, fmt.Errorf("invalid JSON: unexpected data after end of object")
	}

	return baseline, nil
}
