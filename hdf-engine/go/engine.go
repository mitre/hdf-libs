// Package hdfengine is the shared, schema-typed read-side engine library for
// HDF documents (detect, query, compliance, and future read-side engines). It
// sits above hdf-schema and hdf-utilities and is consumed as a library by both
// the CLI (package cmd) and the MCP server (hdf-cli/internal/mcp) — neither
// owns the engines. It is a sibling to hdf-diff; see ADR-0007.
//
// This file is the scaffold placeholder; the engines land via later cards.
package hdfengine

// Version reports the library version. The monorepo bumps every package in
// lockstep, so this must match hdf-engine/package.json — the single source of
// truth. It cannot be an ldflags stamp: the engine is consumed as a library
// (handle EngineSchemaVersion, converter generator provenance) where no linker
// flags are set. TestVersion enforces the match against package.json, so a
// workspace bump that forgets this constant fails CI instead of drifting.
func Version() string {
	return "3.5.0"
}
