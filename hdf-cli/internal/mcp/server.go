// Package mcp is the HDF MCP server: an stdio JSON-RPC server built on the
// modelcontextprotocol go-sdk. This file is the scaffold — it stands up the
// server with an empty tool set, structured stderr logging, and tool-annotation
// helpers. Tools and resources land in later phases.
//
// Nothing on the reachable path writes to stdout: on the stdio transport the
// go-sdk owns stdout for JSON-RPC framing, and a stray print would corrupt it.
// All diagnostics go to stderr via the slog logger.
package mcp

import (
	"context"
	"log/slog"
	"os"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// ServerName and ServerTitle identify this implementation to clients.
const (
	ServerName  = "hdf-mcp"
	ServerTitle = "HDF MCP Server"
)

// NewServer builds the HDF MCP server with an empty tool set and a stderr
// logger. version is the CLI version, surfaced as serverInfo.version. The
// returned server supports the spec revisions the go-sdk advertises (currently
// 2026-07-28 and 2025-11-25, negotiated per connection).
func NewServer(version string, logger *slog.Logger) *mcp.Server {
	if logger == nil {
		logger = NewStderrLogger(os.Getenv("HDF_MCP_LOG_LEVEL"))
	}
	// Route the process default logger to the same stderr logger so tool-side
	// diagnostics (e.g. redacted filesystem-error causes) never reach stdout,
	// which carries the JSON-RPC stream.
	slog.SetDefault(logger)
	return mcp.NewServer(&mcp.Implementation{
		Name:    ServerName,
		Title:   ServerTitle,
		Version: version,
	}, &mcp.ServerOptions{
		Logger:       logger,
		Instructions: "HDF MCP server: read, analyze, and author Heimdall Data Format documents.",
	})
}

// Run connects the server to the stdio transport and serves until the context
// is cancelled or the peer disconnects. This is the production entry the cobra
// command calls; it uses os.Stdin/os.Stdout via the go-sdk StdioTransport.
//
// register, if non-nil, installs the tool set onto the server before it serves.
// It is injected (rather than imported) so this package never depends on the
// tools package — keeping the dependency edge one-way (tools → mcp, never back).
func Run(ctx context.Context, version string, register func(*mcp.Server)) error {
	s := NewServer(version, nil)
	if register != nil {
		register(s)
	}
	return s.Run(ctx, &mcp.StdioTransport{})
}

// NewStderrLogger builds a structured slog logger writing to stderr at the given
// level ("debug"|"info"|"warn"|"error", default "info"). It writes ONLY to
// stderr — never stdout — so it is safe on the stdio transport.
func NewStderrLogger(level string) *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: parseLevel(level),
	}))
}

func parseLevel(level string) slog.Level {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// --- tool-annotation helpers ---
//
// The go-sdk ToolAnnotations booleans use a mix of value and pointer fields
// (a nil pointer means "unset / use the spec default"); these helpers set them
// explicitly so a tool's intent is unambiguous. Clients use readOnlyHint for
// parallel dispatch, so a read tool must set it true.

// ReadOnly returns annotations for a read-only, closed-world tool (the shape of
// every analysis tool): readOnlyHint=true, openWorldHint=false. A read-only tool
// is non-destructive and idempotent by definition.
func ReadOnly() *mcp.ToolAnnotations {
	return &mcp.ToolAnnotations{
		ReadOnlyHint:    true,
		DestructiveHint: boolPtr(false),
		IdempotentHint:  true,
		OpenWorldHint:   boolPtr(false),
	}
}

// Writing returns annotations for a write tool: readOnlyHint=false with explicit
// destructive and idempotent hints, closed-world. hdf_create_amendment and
// hdf_apply_amendment are additive (destructive=false); a tool that overwrites
// would set destructive=true.
func Writing(destructive, idempotent bool) *mcp.ToolAnnotations {
	return &mcp.ToolAnnotations{
		ReadOnlyHint:    false,
		DestructiveHint: boolPtr(destructive),
		IdempotentHint:  idempotent,
		OpenWorldHint:   boolPtr(false),
	}
}

func boolPtr(b bool) *bool { return &b }
