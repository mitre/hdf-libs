package respond

import (
	"encoding/json"
	"strings"
	"testing"

	toon "github.com/toon-format/toon-go"
)

// bigRow returns a row whose serialized size is large, to drive size-based
// (not count-based) truncation.
func bigRow(id int, descLen int) map[string]any {
	return map[string]any{
		"id":          id,
		"description": strings.Repeat("x", descLen),
	}
}

func smallRow(id int) map[string]any {
	return map[string]any{"id": id}
}

func make2(n int, mk func(int) map[string]any) []any {
	out := make([]any, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, mk(i))
	}
	return out
}

// The card's designated first-failing test.
func TestSerialize_TruncatesAndNamesRemedy(t *testing.T) {
	// 50 large rows blow past the concise budget.
	rows := make2(50, func(i int) map[string]any { return bigRow(i, 400) })
	res, err := Serialize("requirements", rows, Options{
		Verbosity:   Concise,
		Encoding:    JSON,
		Total:       len(rows),
		Page:        0,
		NarrowParam: "status[], severity[], or a smaller limit",
	})
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
	if !res.Truncated {
		t.Fatal("expected truncation for an over-budget collection")
	}
	if res.Returned >= len(rows) {
		t.Errorf("expected rows dropped, returned=%d of %d", res.Returned, len(rows))
	}
	if res.NextPage != 1 {
		t.Errorf("nextPage = %d, want 1", res.NextPage)
	}
	if res.Notice == "" {
		t.Fatal("silent truncation is a defect: notice must be set")
	}
	// The notice must state what was dropped AND name the narrowing parameter.
	if !strings.Contains(res.Notice, "status[]") {
		t.Errorf("notice must name the narrowing parameter, got %q", res.Notice)
	}
	if !strings.Contains(res.Notice, "page=1") {
		t.Errorf("notice should point at the next page, got %q", res.Notice)
	}
	// And the serialized payload must be within budget.
	if got := EstimateTokens(res.Payload); got > ConciseTokenBudget {
		t.Errorf("payload %d tokens exceeds concise budget %d", got, ConciseTokenBudget)
	}
}

func TestSerialize_CapOnSizeNotRowCount(t *testing.T) {
	// Same row COUNT, different row SIZE: large rows truncate, small rows don't.
	const n = 40
	large := make2(n, func(i int) map[string]any { return bigRow(i, 300) })
	small := make2(n, smallRow)

	lr, err := Serialize("items", large, Options{Verbosity: Concise, Encoding: JSON, Total: n, NarrowParam: "limit"})
	if err != nil {
		t.Fatal(err)
	}
	sr, err := Serialize("items", small, Options{Verbosity: Concise, Encoding: JSON, Total: n, NarrowParam: "limit"})
	if err != nil {
		t.Fatal(err)
	}
	if !lr.Truncated {
		t.Error("large-row payload should truncate at this row count")
	}
	if sr.Truncated {
		t.Error("small-row payload should NOT truncate at the same row count (cap is size, not count)")
	}
	if sr.Returned != n {
		t.Errorf("small payload returned %d, want all %d", sr.Returned, n)
	}
}

func TestSerialize_VerbosityBudgets(t *testing.T) {
	rows := make2(200, func(i int) map[string]any { return bigRow(i, 200) })
	concise, _ := Serialize("items", rows, Options{Verbosity: Concise, Encoding: JSON, Total: len(rows), NarrowParam: "limit"})
	full, _ := Serialize("items", rows, Options{Verbosity: Full, Encoding: JSON, Total: len(rows), NarrowParam: "limit"})

	if EstimateTokens(concise.Payload) > ConciseTokenBudget {
		t.Errorf("concise payload %d > %d", EstimateTokens(concise.Payload), ConciseTokenBudget)
	}
	if EstimateTokens(full.Payload) > FullTokenBudget {
		t.Errorf("full payload %d > %d", EstimateTokens(full.Payload), FullTokenBudget)
	}
	// full holds strictly more than concise.
	if full.Returned <= concise.Returned {
		t.Errorf("full (%d) should return more rows than concise (%d)", full.Returned, concise.Returned)
	}
}

func TestSerialize_NotTruncatedWhenUnderBudget(t *testing.T) {
	rows := make2(3, smallRow)
	res, err := Serialize("items", rows, Options{Verbosity: Concise, Encoding: JSON, Total: 3, NarrowParam: "limit"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Truncated {
		t.Error("small collection under budget must not be truncated")
	}
	if res.Notice != "" || res.NextPage != 0 {
		t.Errorf("untruncated response must not carry notice/nextPage: %+v", res)
	}
	if res.Returned != 3 || res.Total != 3 {
		t.Errorf("returned/total = %d/%d, want 3/3", res.Returned, res.Total)
	}
}

func TestSerialize_Deterministic_BothEncodings(t *testing.T) {
	rows := make2(10, func(i int) map[string]any { return bigRow(i, 50) })
	for _, enc := range []Encoding{JSON, TOON} {
		opts := Options{Verbosity: Concise, Encoding: enc, Total: len(rows), NarrowParam: "limit"}
		a, err := Serialize("items", rows, opts)
		if err != nil {
			t.Fatalf("%s: %v", enc, err)
		}
		b, _ := Serialize("items", rows, opts)
		if a.Payload != b.Payload {
			t.Errorf("%s encoding is not byte-deterministic across calls", enc)
		}
	}
}

func TestSerialize_TOONRoundTripsLosslessly(t *testing.T) {
	rows := make2(5, func(i int) map[string]any { return bigRow(i, 20) })
	res, err := Serialize("items", rows, Options{Verbosity: Full, Encoding: TOON, Total: len(rows), NarrowParam: "limit"})
	if err != nil {
		t.Fatalf("serialize toon: %v", err)
	}
	// Decode the TOON payload back to the JSON data model.
	decoded, err := toon.DecodeString(res.Payload)
	if err != nil {
		t.Fatalf("toon decode: %v", err)
	}
	// Re-encoding the decoded model as JSON must equal a direct JSON serialization
	// of the same logical envelope (both encoders sort keys).
	jsonRes, err := Serialize("items", rows, Options{Verbosity: Full, Encoding: JSON, Total: len(rows), NarrowParam: "limit"})
	if err != nil {
		t.Fatal(err)
	}
	roundTripped, err := json.Marshal(decoded)
	if err != nil {
		t.Fatal(err)
	}
	if string(roundTripped) != jsonRes.Payload {
		t.Errorf("TOON did not round-trip to the same JSON data model:\n toon->json: %s\n json:       %s", roundTripped, jsonRes.Payload)
	}
}

func TestSerialize_DefaultRemedyWhenNoNarrowParam(t *testing.T) {
	rows := make2(50, func(i int) map[string]any { return bigRow(i, 400) })
	res, err := Serialize("items", rows, Options{Verbosity: Concise, Encoding: JSON, Total: len(rows)})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Truncated {
		t.Fatal("expected truncation")
	}
	if !strings.Contains(res.Notice, "a narrowing filter or a smaller limit") {
		t.Errorf("empty NarrowParam should fall back to a generic remedy, got %q", res.Notice)
	}
}

func TestSerialize_EncodeErrorPropagates(t *testing.T) {
	// A value the encoders cannot represent (a func) surfaces as an error, not a
	// panic or a silently-dropped field.
	bad := []any{map[string]any{"id": 1, "fn": func() {}}}
	if _, err := Serialize("items", bad, Options{Encoding: JSON, Total: 1, NarrowParam: "limit"}); err == nil {
		t.Error("expected a JSON encode error for an unmarshalable value")
	}
	if _, err := Serialize("items", bad, Options{Encoding: TOON, Total: 1, NarrowParam: "limit"}); err == nil {
		t.Error("expected a TOON encode error for an unmarshalable value")
	}
}

func TestSerializeWithBudget_ZeroRowsPathological(t *testing.T) {
	// A budget so small that even the empty envelope exceeds it: the serializer
	// must still return the empty (truncated) envelope, not error or loop.
	rows := make2(5, func(i int) map[string]any { return bigRow(i, 100) })
	res, err := serializeWithBudget("items", rows, Options{Verbosity: Concise, Encoding: JSON, Total: len(rows), NarrowParam: "limit"}, 1)
	if err != nil {
		t.Fatalf("pathological budget should not error: %v", err)
	}
	if res.Returned != 0 || !res.Truncated {
		t.Errorf("expected 0 returned + truncated under a 1-token budget, got returned=%d truncated=%v", res.Returned, res.Truncated)
	}
	if res.Notice == "" {
		t.Error("pathological truncation must still carry a notice")
	}
}

func TestSerialize_DefaultsToJSON(t *testing.T) {
	res, err := Serialize("items", make2(2, smallRow), Options{Total: 2, NarrowParam: "limit"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Encoding != JSON {
		t.Errorf("default encoding = %q, want json", res.Encoding)
	}
	if !json.Valid([]byte(res.Payload)) {
		t.Error("default payload must be valid JSON")
	}
}

func TestPaginate_GreedyBudgetPacking(t *testing.T) {
	rows := make([]map[string]any, 10)
	for i := range rows {
		rows[i] = map[string]any{"i": i}
	}
	// Constant 100 tokens/row, budget 250 → 2 rows per page → 5 pages.
	pages := Paginate(rows, 250, func(p []map[string]any) int { return len(p) * 100 })
	if len(pages) != 5 {
		t.Fatalf("want 5 pages, got %d", len(pages))
	}
	seen := 0
	for _, p := range pages {
		if len(p) != 2 {
			t.Errorf("want 2 rows/page, got %d", len(p))
		}
		for _, r := range p {
			if r["i"] != seen {
				t.Errorf("row order not preserved: got %v at position %d", r["i"], seen)
			}
			seen++
		}
	}
	if seen != 10 {
		t.Errorf("all rows must be paginated, got %d of 10", seen)
	}
}

func TestPaginate_OversizeRowGetsOwnPage(t *testing.T) {
	rows := []map[string]any{{"i": 0}, {"i": 1}, {"i": 2}}
	// Each row alone is 1000 tokens, over the 500 budget — but paging must still
	// advance one row at a time rather than loop forever.
	pages := Paginate(rows, 500, func(p []map[string]any) int { return len(p) * 1000 })
	if len(pages) != 3 {
		t.Fatalf("each oversize row must get its own page, got %d pages", len(pages))
	}
	for _, p := range pages {
		if len(p) != 1 {
			t.Errorf("oversize page must hold exactly its one row, got %d", len(p))
		}
	}
}

func TestPaginate_EmptyInputYieldsOneEmptyPage(t *testing.T) {
	pages := Paginate(nil, 100, func([]map[string]any) int { return 0 })
	if len(pages) != 1 || len(pages[0]) != 0 {
		t.Fatalf("empty input must yield exactly one empty page, got %v", pages)
	}
}
