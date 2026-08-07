// Package evalharness replays recorded MCP tool-call transcripts and asserts on
// both the final answer and a per-transcript token budget, and measures the
// tools/list surface against the ADR's token ceilings. A transcript whose
// response token count grows past its budget fails, so token regressions surface
// in test rather than silently consuming context headroom.
//
// Tokenizer pin: the token budget is meaningless without a fixed tokenizer, so
// this harness pins ONE — tiktoken o200k_base (the encoding for current OpenAI
// GPT-4o / o-series models) via github.com/tiktoken-go/tokenizer, which embeds
// its vocab and needs no network. Changing the tokenizer is a deliberate,
// reviewed change: update PinnedEncoding and re-baseline every budget.
package evalharness

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	"github.com/tiktoken-go/tokenizer"
)

// PinnedEncoding records the pinned tokenizer encoding (name + library version)
// the budgets are measured against — o200k_base, the encoding for current OpenAI
// GPT-4o / o-series models. See the package doc for why the pin matters.
const PinnedEncoding = "o200k_base (github.com/tiktoken-go/tokenizer v0.8.1)"

// tools/list token ceilings from the ADR Verification Strategy, measured on the
// marshalled ListToolsResult with the pinned tokenizer.
const (
	// ToolsListTotalBudget is the target total for the whole tools/list.
	ToolsListTotalBudget = 4500
	// ToolsListPerToolBudget is the ceiling for any single tool's schema.
	ToolsListPerToolBudget = 600
	// ToolsListHardFail is the absolute ceiling; exceeding it is always a failure.
	ToolsListHardFail = 6500
)

var (
	codecOnce sync.Once
	codec     tokenizer.Codec
	errCodec  error
)

func getCodec() (tokenizer.Codec, error) {
	codecOnce.Do(func() {
		codec, errCodec = tokenizer.Get(tokenizer.O200kBase)
	})
	return codec, errCodec
}

// compactForWire strips insignificant JSON whitespace so the ceiling is measured
// against the compact form the model actually receives over the JSON-RPC wire,
// not the indentation the golden file carries for human readability. Non-JSON
// input is returned unchanged (the synthetic ceiling fixtures are already
// compact), so counting still proceeds.
func compactForWire(s string) string {
	var buf bytes.Buffer
	if err := json.Compact(&buf, []byte(s)); err != nil {
		return s
	}
	return buf.String()
}

// CountTokens returns the number of tokens in s under the pinned tokenizer. It
// delegates through tokenCount, a seam tests swap to exercise the error
// propagation in Replay/MeasureToolsList (the embedded tokenizer itself cannot
// fail in practice).
func CountTokens(s string) (int, error) { return tokenCount(s) }

// tokenCount is the swappable token-counting seam; defaults to the real encoder.
var tokenCount = defaultTokenCount

func defaultTokenCount(s string) (int, error) {
	c, err := getCodec()
	if err != nil {
		return 0, fmt.Errorf("loading pinned tokenizer: %w", err)
	}
	ids, _, err := c.Encode(s)
	if err != nil {
		return 0, fmt.Errorf("tokenizing: %w", err)
	}
	return len(ids), nil
}

// Transcript is a recorded tool-call sequence: the request frames a client
// sent, the responses the real server returned, a per-transcript token budget
// measured over the responses, and an assertion on the final answer.
type Transcript struct {
	Name        string
	Requests    []string
	Responses   []string
	TokenBudget int
	// Assert validates the final answer of the transcript (the recorded
	// responses). It returns an error describing any mismatch.
	Assert func(responses []string) error
}

// Result is the outcome of replaying a transcript.
type Result struct {
	Name        string
	TotalTokens int
	Budget      int
	OverBudget  bool
	Overage     int
	AnswerErr   error
	Pass        bool
}

// Replay measures the transcript's recorded responses against its token budget
// and runs its final-answer assertion. It does not itself drive a server — the
// responses ARE the recording of a real run. The tools/list golden test
// re-drives the live server to keep the recorded surface honest.
func Replay(tr Transcript) (Result, error) {
	total, err := CountTokens(strings.Join(tr.Responses, "\n"))
	if err != nil {
		return Result{}, err
	}
	res := Result{
		Name:        tr.Name,
		TotalTokens: total,
		Budget:      tr.TokenBudget,
		OverBudget:  total > tr.TokenBudget,
	}
	if res.OverBudget {
		res.Overage = total - tr.TokenBudget
	}
	if tr.Assert != nil {
		res.AnswerErr = tr.Assert(tr.Responses)
	}
	res.Pass = !res.OverBudget && res.AnswerErr == nil
	return res, nil
}

// ToolTokens is a single tool's measured token cost within tools/list.
type ToolTokens struct {
	Name   string
	Tokens int
}

// ToolsListMeasurement is the token accounting for a tools/list result.
type ToolsListMeasurement struct {
	TotalTokens int
	PerTool     []ToolTokens
	// Violations lists every ceiling breach in human-readable form; empty means
	// the surface is within budget.
	Violations []string
}

// MeasureToolsList tokenizes a marshalled ListToolsResult and checks it against
// the ADR ceilings: total ≤ ToolsListTotalBudget, each tool ≤
// ToolsListPerToolBudget, and a hard failure past ToolsListHardFail. Per-tool
// attribution tokenizes each tool's own JSON object from the marshalled array.
func MeasureToolsList(resultJSON string, perToolJSON map[string]string) (ToolsListMeasurement, error) {
	total, err := CountTokens(compactForWire(resultJSON))
	if err != nil {
		return ToolsListMeasurement{}, err
	}
	m := ToolsListMeasurement{TotalTokens: total}

	for name, toolJSON := range perToolJSON {
		tk, err := CountTokens(compactForWire(toolJSON))
		if err != nil {
			return ToolsListMeasurement{}, err
		}
		m.PerTool = append(m.PerTool, ToolTokens{Name: name, Tokens: tk})
		if tk > ToolsListPerToolBudget {
			m.Violations = append(m.Violations,
				fmt.Sprintf("tool %q is %d tokens, over the per-tool ceiling of %d", name, tk, ToolsListPerToolBudget))
		}
	}

	if total > ToolsListHardFail {
		m.Violations = append(m.Violations,
			fmt.Sprintf("tools/list is %d tokens, past the HARD-FAIL ceiling of %d", total, ToolsListHardFail))
	} else if total > ToolsListTotalBudget {
		m.Violations = append(m.Violations,
			fmt.Sprintf("tools/list is %d tokens, over the total budget of %d", total, ToolsListTotalBudget))
	}
	return m, nil
}
