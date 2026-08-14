// Package tools implements the HDF MCP read/analysis/authoring tools. This file
// provides source resolution shared by every document-taking tool: it turns a
// {path} or {handle} source into confined bytes plus a loaded document and a
// fresh handle, applying HDF_MCP_ROOT path confinement, the byte-bounded loader
// (parse/detect/degraded-read), and handle staleness verification.
package tools

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strconv"

	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/mcp/handle"
	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/mcp/loader"
	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/mcp/mcperr"
	hdfengine "github.com/mitre/hdf-libs/hdf-engine/go/v3"
	hdfutil "github.com/mitre/hdf-libs/hdf-utilities/go/v3"
)

// Resolved is the outcome of resolving a source: the confined bytes, the loader
// result (parsed doc + degraded-read errors), and a fresh self-encoding handle.
type Resolved struct {
	Content []byte
	Load    *loader.Result
	Handle  handle.Handle
}

// mcpRoot returns the confinement root all tool paths are resolved against:
// HDF_MCP_ROOT if set, else the process working directory. Paths outside it are
// rejected with PATH_DENIED.
func mcpRoot() string {
	if r := os.Getenv("HDF_MCP_ROOT"); r != "" {
		return r
	}
	wd, err := os.Getwd()
	if err != nil {
		return "."
	}
	return wd
}

// mcpMaxInputSize is the per-document read ceiling in bytes: HDF_MCP_MAX_SIZE if
// set to a positive integer, else hdfutil.DefaultMaxInputSize (50 MB). It gates a
// file BEFORE it is read into memory and is the same ceiling the loader applies
// after the read (register.go builds the loader with it), so the two never
// diverge.
func mcpMaxInputSize() int64 {
	if v := os.Getenv("HDF_MCP_MAX_SIZE"); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > 0 {
			return n
		}
	}
	return int64(hdfutil.DefaultMaxInputSize)
}

// redactFileErr builds a filesystem taxonomy error whose CLIENT payload names
// only the caller-relative path — never the absolute confined path or errno a
// *PathError's Error() would expose (which would reveal the deployer's
// HDF_MCP_ROOT layout). The raw cause is logged to stderr for the operator
// (stdout stays JSON-RPC only), matching the relative-path discipline the
// PATH_DENIED branches already follow.
func redactFileErr(code mcperr.Code, message, relPath string, cause error) *mcperr.Error {
	slog.Error(message, "path", relPath, "cause", cause)
	return mcperr.New(code, message, map[string]any{"path": relPath})
}

// guardFileSize rejects a file larger than maxSize before it is read into
// memory, so an over-large document returns TOO_LARGE without the allocation
// spike. The loader's post-read size guard remains the backstop. relPath is the
// caller-supplied path used in the (redacted) client-facing error.
func guardFileSize(confined, relPath string, maxSize int64) *mcperr.Error {
	fi, err := os.Stat(confined)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return mcperr.New(mcperr.DocumentNotFound, "no document at the given path", map[string]any{"path": relPath})
		}
		return redactFileErr(mcperr.DocumentNotFound, "could not read the document", relPath, err)
	}
	if fi.Size() > maxSize {
		return mcperr.New(mcperr.TooLarge, fmt.Sprintf("document is %d bytes, over the %d-byte limit", fi.Size(), maxSize), map[string]any{"path": relPath})
	}
	return nil
}

// resolveSource turns a {path} | {handle} source into confined bytes, a loaded
// document, and a fresh handle. On a handle source it re-reads the handle's path
// and enforces the content-hash staleness check (HANDLE_STALE). On a path source
// it confines the path to HDF_MCP_ROOT (PATH_DENIED) before reading. All errors
// are taxonomy errors — a schema-invalid document is NOT an error here: it comes
// back through Load with valid:false (degraded read).
func resolveSource(src handle.Source, ldr *loader.Loader) (*Resolved, *mcperr.Error) {
	switch {
	case src.Handle != "" && src.Path != "":
		return nil, mcperr.Arg("source sets both path and handle", "pass exactly one of source.path or source.handle")
	case src.Handle != "":
		return resolveHandle(src.Handle, ldr)
	case src.Path != "":
		return resolvePath(src.Path, ldr)
	default:
		return nil, mcperr.Arg("source sets neither path nor handle", "pass source.path (or source.handle from a prior hdf_open)")
	}
}

func resolvePath(path string, ldr *loader.Loader) (*Resolved, *mcperr.Error) {
	confined, err := hdfutil.SafePath(mcpRoot(), path)
	if err != nil {
		return nil, mcperr.New(mcperr.PathDenied, "path resolves outside HDF_MCP_ROOT", map[string]any{"path": path})
	}
	content, rerr := readFile(confined, path)
	if rerr != nil {
		return nil, rerr
	}
	res, lerr := ldr.Load(content)
	if lerr != nil {
		return nil, sizeOrLoadError(lerr)
	}
	return &Resolved{
		Content: content,
		Load:    res,
		Handle:  handle.Compute(path, content, res.DocType, hdfengine.Version()),
	}, nil
}

func resolveHandle(encoded string, ldr *loader.Loader) (*Resolved, *mcperr.Error) {
	h, err := handle.Decode(encoded)
	if err != nil {
		return nil, mcperr.Arg("source.handle is not a valid hdf_open handle",
			"pass a handle from a prior hdf_open response, or use source.path")
	}
	confined, serr := hdfutil.SafePath(mcpRoot(), h.Path)
	if serr != nil {
		return nil, mcperr.New(mcperr.PathDenied, "handle path resolves outside HDF_MCP_ROOT", map[string]any{"path": h.Path})
	}
	content, rerr := readFile(confined, h.Path)
	if rerr != nil {
		return nil, rerr
	}
	if verr := handle.Verify(h, content); verr != nil {
		return nil, mcperr.New(mcperr.HandleStale, "the file changed since the handle was minted", map[string]any{"path": h.Path})
	}
	res, lerr := ldr.Load(content)
	if lerr != nil {
		return nil, sizeOrLoadError(lerr)
	}
	return &Resolved{Content: content, Load: res, Handle: h}, nil
}

// readFile reads a confined path, mapping filesystem errors to taxonomy codes.
// relPath is the caller-supplied path surfaced in the (redacted) client error;
// the absolute confined path never reaches the client.
func readFile(confined, relPath string) ([]byte, *mcperr.Error) {
	if terr := guardFileSize(confined, relPath, mcpMaxInputSize()); terr != nil {
		return nil, terr
	}
	content, err := os.ReadFile(confined) //nolint:gosec // confined to HDF_MCP_ROOT by SafePath
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, mcperr.New(mcperr.DocumentNotFound, "no document at the given path", map[string]any{"path": relPath})
		}
		return nil, redactFileErr(mcperr.DocumentNotFound, "could not read the document", relPath, err)
	}
	return content, nil
}

// sizeOrLoadError maps a loader hard error (only the size guard today) to a
// taxonomy code.
func sizeOrLoadError(err error) *mcperr.Error {
	return mcperr.New(mcperr.TooLarge, err.Error(), nil)
}
