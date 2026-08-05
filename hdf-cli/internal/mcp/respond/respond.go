// Package respond is the shared, token-bounded response serializer every
// collection-returning MCP tool uses to stay inside a token budget. Caps are
// enforced on serialized SIZE (not row count): rows are dropped to fit the
// verbosity tier's budget, and a truncated response always states what was
// dropped and names the narrowing parameter to use next — silent truncation is
// a defect. Encoding is JSON (default) or opt-in TOON; both sort object keys, so
// output is byte-deterministic across calls.
package respond

import (
	"encoding/json"
	"fmt"

	toon "github.com/toon-format/toon-go"
)

// Verbosity selects the token budget tier.
type Verbosity string

const (
	// Concise is the low-token tier (id/status-level fields).
	Concise Verbosity = "concise"
	// Full is the high-token tier (raw content, descriptions).
	Full Verbosity = "full"
)

// Encoding selects the wire format. JSON is the default and the return-trip
// format; TOON is opt-in per call for model-facing reads.
type Encoding string

const (
	// JSON is the default encoding (automation consumer, machine-typed).
	JSON Encoding = "json"
	// TOON is the opt-in token-efficient encoding for uniform arrays.
	TOON Encoding = "toon"
)

// Token budgets per verbosity tier, measured on the serialized output.
const (
	ConciseTokenBudget = 2000
	FullTokenBudget    = 10000
)

// Options configures a Serialize call.
type Options struct {
	Verbosity   Verbosity // default Concise
	Encoding    Encoding  // default JSON
	Total       int       // total rows available across all pages
	Page        int       // current 0-based page
	NarrowParam string    // narrowing parameter(s) the truncation notice recommends
}

// Result is the outcome of serialization: the encoded payload plus the bounding
// metadata the tool surfaces to the agent.
type Result struct {
	Payload   string
	Encoding  Encoding
	Total     int
	Returned  int
	Truncated bool
	NextPage  int    // set only when Truncated
	Notice    string // set only when Truncated; names the remedy
}

// EstimateTokens approximates the token count of a serialized string. Real
// tokenization is model-specific; this uses the standard ~4-bytes-per-token
// heuristic. The eval harness measures the true delta on fixtures later; the
// budget only needs a stable, conservative proxy to bound responses.
func EstimateTokens(s string) int {
	return (len(s) + 3) / 4
}

// Serialize renders rows into a token-bounded envelope, dropping rows to fit the
// verbosity budget in the chosen encoding. The envelope carries total, returned,
// truncated, and — when truncated — nextPage and a remedy-naming notice, plus the
// kept rows under collectionKey. It returns an error only for an encoding
// failure, never for an over-budget input (which truncates).
func Serialize(collectionKey string, rows []any, opts Options) (Result, error) {
	if opts.Verbosity == "" {
		opts.Verbosity = Concise
	}
	if opts.Encoding == "" {
		opts.Encoding = JSON
	}
	budget := ConciseTokenBudget
	if opts.Verbosity == Full {
		budget = FullTokenBudget
	}
	return serializeWithBudget(collectionKey, rows, opts, budget)
}

// serializeWithBudget is the budget-parameterized core, split out so the
// budget-boundary and pathological (even-zero-rows-over-budget) paths are
// testable without exposing the tier constants through the public API.
func serializeWithBudget(collectionKey string, rows []any, opts Options, budget int) (Result, error) {
	total := opts.Total
	if total < len(rows) {
		total = len(rows)
	}

	// Try keeping everything first.
	fullTruncated := len(rows) < total // more pages exist even before budget dropping
	payload, err := encode(collectionKey, rows, opts, total, len(rows), fullTruncated)
	if err != nil {
		return Result{}, err
	}
	if EstimateTokens(payload) <= budget {
		return buildResult(payload, opts, total, len(rows), fullTruncated), nil
	}

	// Over budget: find the largest prefix of rows that fits (with the notice
	// present, since any dropping means truncated=true). Binary search — envelope
	// size is monotonic in the kept-row count.
	lo, hi, best := 0, len(rows), 0
	var bestPayload string
	for lo <= hi {
		mid := (lo + hi) / 2
		p, encErr := encode(collectionKey, rows[:mid], opts, total, mid, true)
		if encErr != nil {
			return Result{}, encErr
		}
		if EstimateTokens(p) <= budget {
			best, bestPayload = mid, p
			lo = mid + 1
		} else {
			hi = mid - 1
		}
	}
	if bestPayload == "" {
		// Even zero rows exceed the budget (pathological). Emit the empty envelope.
		bestPayload, err = encode(collectionKey, rows[:0], opts, total, 0, true)
		if err != nil {
			return Result{}, err
		}
	}
	return buildResult(bestPayload, opts, total, best, true), nil
}

// buildResult assembles the Result metadata from a chosen payload.
func buildResult(payload string, opts Options, total, returned int, truncated bool) Result {
	r := Result{
		Payload:   payload,
		Encoding:  opts.Encoding,
		Total:     total,
		Returned:  returned,
		Truncated: truncated,
	}
	if truncated {
		r.NextPage = opts.Page + 1
		r.Notice = truncationNotice(opts.Verbosity, returned, total, r.NextPage, opts.NarrowParam)
	}
	return r
}

// truncationNotice states what was dropped and names the remedy: the
// narrowing parameter and the next page. Never silent.
func truncationNotice(v Verbosity, returned, total, nextPage int, narrowParam string) string {
	remedy := narrowParam
	if remedy == "" {
		remedy = "a narrowing filter or a smaller limit"
	}
	return fmt.Sprintf(
		"Response truncated to stay within the %s token budget: showing %d of %d rows. Narrow the result with %s, or fetch more with page=%d.",
		v, returned, total, remedy, nextPage,
	)
}

// encode builds the envelope map and serializes it in the requested encoding.
// A map[string]any is used deliberately: both encoding/json and toon-go sort
// object keys, so the output is byte-deterministic without a hand-ordered struct.
func encode(collectionKey string, keep []any, opts Options, total, returned int, truncated bool) (string, error) {
	env := map[string]any{
		"total":       total,
		"returned":    returned,
		"truncated":   truncated,
		collectionKey: keep,
	}
	if truncated {
		env["nextPage"] = opts.Page + 1
		env["notice"] = truncationNotice(opts.Verbosity, returned, total, opts.Page+1, opts.NarrowParam)
	}

	switch opts.Encoding {
	case TOON:
		s, err := toon.MarshalString(env)
		if err != nil {
			return "", fmt.Errorf("toon encode: %w", err)
		}
		return s, nil
	default:
		b, err := json.Marshal(env)
		if err != nil {
			return "", fmt.Errorf("json encode: %w", err)
		}
		return string(b), nil
	}
}
