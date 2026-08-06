// Package mcperr is the closed, next-call-naming error taxonomy every MCP tool
// returns from. Each taxonomy error carries a fixed code, a message, and the
// concrete next call the agent should make — an error that does not name a
// recovery causes a retry loop. Taxonomy errors map to tool results with
// isError:true; malformed calls (a separate concern owned by the SDK layer)
// surface as JSON-RPC protocol errors instead.
//
// WRITES_DISABLED is deliberately NOT a taxonomy error: a write attempted in a
// writes-disabled deployment returns a successful preview (see WritesDisabled),
// because the agent cannot enable writes and an isError would only invite a
// retry loop.
package mcperr

import "fmt"

// Code is a member of the closed MCP error taxonomy. Adding a member is an
// ADR-level decision, not an in-code convenience — the set is intentionally
// fixed (see Codes).
type Code string

const (
	DocumentNotFound Code = "DOCUMENT_NOT_FOUND"
	PathDenied       Code = "PATH_DENIED"
	TooLarge         Code = "TOO_LARGE"
	WrongDocType     Code = "WRONG_DOC_TYPE"
	SchemaInvalid    Code = "SCHEMA_INVALID"
	HandleStale      Code = "HANDLE_STALE"
	NoConverter      Code = "NO_CONVERTER"
	Truncated        Code = "TRUNCATED"
	AmbiguousFormat  Code = "AMBIGUOUS_FORMAT"
)

// Codes is the exhaustive, closed taxonomy. Every member appears here exactly
// once; nothing outside this slice is a valid taxonomy code.
var Codes = []Code{
	DocumentNotFound,
	PathDenied,
	TooLarge,
	WrongDocType,
	SchemaInvalid,
	HandleStale,
	NoConverter,
	Truncated,
	AmbiguousFormat,
}

// defaultNextCall maps each code to the concrete recovery it recommends by
// default. Every code has an entry; a code without guidance is a defect the
// tests catch.
var defaultNextCall = map[Code]string{
	DocumentNotFound: "verify the path exists, then retry with a valid `source` (or call hdf_open)",
	PathDenied:       "use a path inside the configured HDF_MCP_ROOT",
	TooLarge:         "reduce the input size, or ask the deployer to raise the size limit",
	WrongDocType:     "call hdf_inspect for this document type (hdf_query is results/baseline only)",
	SchemaInvalid:    "call hdf_validate to see the specific line-numbered schema errors",
	HandleStale:      "the content changed — re-open the source with hdf_open to mint a fresh handle",
	NoConverter:      "check the hdf://catalog/converters resource for a supported `from` format",
	Truncated:        "narrow the result with filters, or fetch the next page with `page`",
	AmbiguousFormat:  "specify `from` explicitly to disambiguate the source format",
}

// Error is a taxonomy error. It implements the error interface and is recoverable
// via errors.As.
type Error struct {
	Code     Code
	Message  string
	NextCall string
	Details  map[string]any
}

// Error implements the error interface.
func (e *Error) Error() string {
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// New builds a taxonomy error, defaulting NextCall to the code's recommended
// recovery. Use WithNextCall to override with a more specific instruction.
func New(code Code, message string, details map[string]any) *Error {
	return &Error{
		Code:     code,
		Message:  message,
		NextCall: defaultNextCall[code],
		Details:  details,
	}
}

// WithNextCall overrides the recovery instruction and returns the error for
// chaining.
func (e *Error) WithNextCall(nextCall string) *Error {
	e.NextCall = nextCall
	return e
}

// ToolResult is the SDK-agnostic MCP tool-result shape a taxonomy error maps to.
// The MCP scaffold adapts it to the go-sdk result type; keeping it here means
// this package carries no SDK dependency.
type ToolResult struct {
	IsError  bool           `json:"isError"`
	Code     Code           `json:"code,omitempty"`
	Message  string         `json:"message,omitempty"`
	NextCall string         `json:"nextCall,omitempty"`
	Details  map[string]any `json:"details,omitempty"`
}

// AsToolResult renders a taxonomy error as an isError tool result — a recoverable
// result the model should retry differently, never a JSON-RPC protocol error.
func (e *Error) AsToolResult() ToolResult {
	return ToolResult{
		IsError:  true,
		Code:     e.Code,
		Message:  e.Message,
		NextCall: e.NextCall,
		Details:  e.Details,
	}
}

// WritesDisabledResult is the SUCCESSFUL (non-isError) response returned when a
// write is attempted in a writes-disabled deployment: the would-write preview
// plus a writesDisabled notice. It is deliberately not a taxonomy error.
type WritesDisabledResult struct {
	IsError        bool   `json:"isError"`        // always false
	WritesDisabled bool   `json:"writesDisabled"` // always true
	Preview        any    `json:"preview"`
	Notice         string `json:"notice"`
}

// WritesDisabled builds the successful writes-disabled preview response.
func WritesDisabled(preview any) WritesDisabledResult {
	return WritesDisabledResult{
		IsError:        false,
		WritesDisabled: true,
		Preview:        preview,
		Notice:         "writes are disabled in this deployment; this is the artifact that would be written",
	}
}
