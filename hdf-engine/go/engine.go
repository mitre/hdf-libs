// Package hdfengine is the shared, schema-typed read-side engine library for
// HDF documents (detect, query, compliance, and future read-side engines). It
// sits above hdf-schema and hdf-utilities and is consumed as a library by both
// the CLI (package cmd) and the MCP server (hdf-cli/internal/mcp) — neither
// owns the engines. It is a sibling to hdf-diff; see ADR-0007.
//
// This file is the scaffold placeholder; the engines land via later cards.
package hdfengine

// Version reports the library version, kept on the workspace lockstep.
func Version() string {
	return "3.5.0"
}
