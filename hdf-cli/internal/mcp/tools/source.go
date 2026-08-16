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
func guardFileSize(confined, relPath, slot string, maxSize int64) *mcperr.Error {
	fi, err := os.Stat(confined)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return mcperr.New(mcperr.DocumentNotFound, "no document at the given path", map[string]any{"path": relPath}).WithNextCall(notFoundNextCall(slot))
		}
		return redactFileErr(mcperr.DocumentNotFound, "could not read the document", relPath, err).WithNextCall(notFoundNextCall(slot))
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
func resolveSource(src handle.Source, ldr *loader.Loader, slot string) (*Resolved, *mcperr.Error) {
	switch {
	case src.Handle != "" && src.Path != "":
		return nil, mcperr.Arg(fmt.Sprintf("%s sets both path and handle", slot),
			fmt.Sprintf("pass exactly one of %s.path or %s.handle", slot, slot))
	case src.Handle != "":
		return resolveHandle(src.Handle, ldr, slot)
	case src.Path != "":
		return resolvePath(src.Path, ldr, slot)
	default:
		return nil, mcperr.Arg(fmt.Sprintf("%s sets neither path nor handle", slot),
			fmt.Sprintf("pass %s.path (or %s.handle from a prior hdf_open)", slot, slot))
	}
}

func resolvePath(path string, ldr *loader.Loader, slot string) (*Resolved, *mcperr.Error) {
	confined, err := hdfutil.SafePath(mcpRoot(), path)
	if err != nil {
		return nil, mcperr.New(mcperr.PathDenied, "path resolves outside HDF_MCP_ROOT", map[string]any{"path": path})
	}
	content, rerr := readFile(confined, path, slot)
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

func resolveHandle(encoded string, ldr *loader.Loader, slot string) (*Resolved, *mcperr.Error) {
	h, err := handle.Decode(encoded)
	if err != nil {
		return nil, mcperr.Arg(fmt.Sprintf("%s.handle is not a valid hdf_open handle", slot),
			fmt.Sprintf("pass a handle from a prior hdf_open response, or use %s.path", slot))
	}
	// An empty path marks a handle for a document that was authored/derived but
	// never written to disk (the default writes-disabled posture). It resolves
	// from the in-memory content cache by contentSha256, so author→apply→
	// compliance composes with zero writes (jobi.1 / D1). A miss is a clear
	// cache-miss, never a path error (this also dissolves the D2 empty-path
	// PATH_DENIED misdiagnosis).
	if h.Path == "" {
		return resolveCachedHandle(h, ldr)
	}
	confined, serr := hdfutil.SafePath(mcpRoot(), h.Path)
	if serr != nil {
		return nil, mcperr.New(mcperr.PathDenied, "handle path resolves outside HDF_MCP_ROOT", map[string]any{"path": h.Path})
	}
	content, rerr := readFile(confined, h.Path, slot)
	if rerr != nil {
		return nil, rerr
	}
	if verr := handle.Verify(h, content); verr != nil {
		return nil, mcperr.New(mcperr.HandleStale, "the file changed since the handle was minted", map[string]any{"path": h.Path}).
			WithNextCall(fmt.Sprintf("the content changed — re-open the `%s` with hdf_open to mint a fresh handle", slot))
	}
	res, lerr := ldr.Load(content)
	if lerr != nil {
		return nil, sizeOrLoadError(lerr)
	}
	return &Resolved{Content: content, Load: res, Handle: h}, nil
}

// resolveCachedHandle resolves a content-addressed (empty-path) handle from the
// loader's in-memory cache. A cache-backed handle is valid only for the entry's
// bounded lifetime (until LRU eviction), so a miss returns CACHE_MISS with
// re-author/persist guidance — not a path error. The content is re-verified
// against the handle's contentSha256 on resolve (never resolve stale bytes).
func resolveCachedHandle(h handle.Handle, ldr *loader.Loader) (*Resolved, *mcperr.Error) {
	data, res, ok := ldr.LoadByHash(h.ContentSHA256)
	if !ok {
		return nil, mcperr.New(mcperr.CacheMiss, "the authored document is no longer in the in-memory cache",
			map[string]any{"contentSha256": h.ContentSHA256})
	}
	if verr := handle.Verify(h, data); verr != nil {
		return nil, mcperr.New(mcperr.CacheMiss, "the cached document does not match the handle",
			map[string]any{"contentSha256": h.ContentSHA256})
	}
	return &Resolved{Content: data, Load: res, Handle: h}, nil
}

// readFile reads a confined path, mapping filesystem errors to taxonomy codes.
// relPath is the caller-supplied path surfaced in the (redacted) client error;
// the absolute confined path never reaches the client. slot is the input field
// the caller passed (source / results / amendments / from / to), so the recovery
// hint names a parameter the emitting tool actually has (jobi.4 / D3).
func readFile(confined, relPath, slot string) ([]byte, *mcperr.Error) {
	if terr := guardFileSize(confined, relPath, slot, mcpMaxInputSize()); terr != nil {
		return nil, terr
	}
	content, err := os.ReadFile(confined) //nolint:gosec // confined to HDF_MCP_ROOT by SafePath
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, mcperr.New(mcperr.DocumentNotFound, "no document at the given path", map[string]any{"path": relPath}).WithNextCall(notFoundNextCall(slot))
		}
		return nil, redactFileErr(mcperr.DocumentNotFound, "could not read the document", relPath, err).WithNextCall(notFoundNextCall(slot))
	}
	return content, nil
}

// notFoundNextCall is the DOCUMENT_NOT_FOUND recovery hint, naming the input slot
// the caller actually passed (source / results / amendments / from / to) so the
// advice never references a parameter the emitting tool lacks (jobi.4 / D3).
func notFoundNextCall(slot string) string {
	return fmt.Sprintf("verify the path exists, then retry with a valid `%s` (or call hdf_open)", slot)
}

// sizeOrLoadError maps a loader hard error (only the size guard today) to a
// taxonomy code.
func sizeOrLoadError(err error) *mcperr.Error {
	return mcperr.New(mcperr.TooLarge, err.Error(), nil)
}
