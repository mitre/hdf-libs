// Package handle implements the self-encoding source handle every
// document-taking MCP tool depends on. A handle is base64 of
// {path, size, contentSha256, docType, engineSchemaVersion} — self-describing, not a
// cache key — so it survives process death, serializes into pipeline state, and
// doubles as a staleness check: a content-hash mismatch returns ErrHandleStale
// rather than silently re-reading changed content.
//
// It also provides the source union: a tool resolves either a {path} or a
// {handle} to the same document identity.
package handle

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
)

// ErrHandleStale is returned when a handle's contentSha256 no longer matches the
// current content. The MCP error taxonomy surfaces this as the HANDLE_STALE code.
var ErrHandleStale = errors.New("HANDLE_STALE")

// Handle is the self-describing document identity carried by a source handle.
type Handle struct {
	Path          string `json:"path"`
	Size          int64  `json:"size"`
	ContentSHA256 string `json:"contentSha256"`
	DocType       string `json:"docType"`
	// EngineSchemaVersion is the schema version the validating HDF engine bundles
	// and interprets the document under — NOT a version the document declares
	// (HDF documents carry no top-level schema-version field). It is sourced from
	// hdfengine.Version() (the engine and schema versions move in lockstep), so
	// it records "which schema version this handle was minted under", not the
	// document's own claim. Named to say so, rather than the misleading bare
	// "schemaVersion" it replaced.
	EngineSchemaVersion string `json:"engineSchemaVersion"`
}

// Compute builds a Handle from a document's path and content, computing size and
// the content SHA-256; docType and engineSchemaVersion are supplied by the caller
// (which has already detected them).
func Compute(path string, content []byte, docType, engineSchemaVersion string) Handle {
	return Handle{
		Path:                path,
		Size:                int64(len(content)),
		ContentSHA256:       sha256Hex(content),
		DocType:             docType,
		EngineSchemaVersion: engineSchemaVersion,
	}
}

// Encode serializes a Handle to its base64 handle string.
func Encode(h Handle) (string, error) {
	b, err := json.Marshal(h)
	if err != nil {
		return "", fmt.Errorf("encoding handle: %w", err)
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

// Decode parses a base64 handle string back into a Handle, with no server-side
// state — a handle is fully self-describing.
func Decode(s string) (Handle, error) {
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return Handle{}, fmt.Errorf("invalid handle encoding: %w", err)
	}
	var h Handle
	if err := json.Unmarshal(raw, &h); err != nil {
		return Handle{}, fmt.Errorf("invalid handle payload: %w", err)
	}
	return h, nil
}

// Verify reports whether the current content still matches the handle. A
// mismatch returns ErrHandleStale; a match returns nil.
func Verify(h Handle, content []byte) error {
	if sha256Hex(content) != h.ContentSHA256 {
		return fmt.Errorf("%w: content hash does not match the handle for %q", ErrHandleStale, h.Path)
	}
	return nil
}

// Source is the {path} | {handle} union a document-taking tool accepts. Exactly
// one field must be set.
type Source struct {
	Path   string `json:"path,omitempty"`
	Handle string `json:"handle,omitempty"`
}

func sha256Hex(content []byte) string {
	sum := sha256.Sum256(content)
	return hex.EncodeToString(sum[:])
}
