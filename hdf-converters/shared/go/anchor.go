package shared

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"errors"
	"io"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// Ground-truth anchors complement TS/Go golden parity. Parity proves the two
// implementations AGREE; it cannot prove either is CORRECT — when both misread a
// format the same way, their goldens match and the defect is invisible. An
// anchor asserts the converter reproduces an item count derived INDEPENDENTLY
// from the source document, so a silent under-extraction fails even when Go and
// TS agree. The count helpers below deliberately do NOT use any converter's
// typed structs or traversal: reusing the converter's parser would let the same
// bug corrupt the ground-truth count. Keep in lockstep with anchor.ts.

// CountXMLElements counts start-elements with the given local name in raw XML,
// via a generic token walk independent of any converter's structs. The local
// name ignores namespace prefixes, so it matches both <Rule> and <xccdf:Rule>.
func CountXMLElements(t *testing.T, input []byte, localName string) int {
	t.Helper()
	dec := xml.NewDecoder(bytes.NewReader(input))
	dec.Strict = false
	// Pass bytes through unchanged for non-UTF-8 encoding declarations (e.g.
	// ISO-8859-1, as in veracode.xml). Go's decoder otherwise errors on the
	// declaration; we only count element names (ASCII), never decode text.
	dec.CharsetReader = func(_ string, r io.Reader) (io.Reader, error) { return r, nil }
	n := 0
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		require.NoError(t, err, "count %q: XML token error", localName)
		if se, ok := tok.(xml.StartElement); ok && se.Name.Local == localName {
			n++
		}
	}
	return n
}

// CountJSONItemsUnderKey counts, across the whole document at any depth, the
// array entries held under the given object key (e.g. every "controls" array's
// elements — including nested ones). Generic walk, independent of converter
// structs. Use for JSON formats whose emission unit is "one requirement per
// element of some array".
func CountJSONItemsUnderKey(t *testing.T, input []byte, key string) int {
	t.Helper()
	var doc interface{}
	require.NoError(t, json.Unmarshal(input, &doc), "count %q: invalid JSON", key)
	return countUnderKey(doc, key)
}

func countUnderKey(v interface{}, key string) int {
	n := 0
	switch val := v.(type) {
	case map[string]interface{}:
		for k, child := range val {
			if k == key {
				if arr, ok := child.([]interface{}); ok {
					n += len(arr)
				}
			}
			n += countUnderKey(child, key)
		}
	case []interface{}:
		for _, item := range val {
			n += countUnderKey(item, key)
		}
	}
	return n
}

// TotalRequirements counts the requirements a converter emitted, across both
// output shapes: HDFResults carries them under baselines[].requirements, while
// HDFBaseline (e.g. a benchmark-only XCCDF) carries them at the top level. A
// document has one shape or the other, so summing both is safe. Serializes
// through JSON so it works on the typed result without importing the schema.
func TotalRequirements(t *testing.T, result interface{}) int {
	t.Helper()
	data, err := json.Marshal(result)
	require.NoError(t, err, "marshal HDF result for anchor count")
	var doc struct {
		Requirements []json.RawMessage `json:"requirements"`
		Baselines    []struct {
			Requirements []json.RawMessage `json:"requirements"`
		} `json:"baselines"`
	}
	require.NoError(t, json.Unmarshal(data, &doc), "unmarshal HDF result for anchor count")
	n := len(doc.Requirements)
	for i := range doc.Baselines {
		n += len(doc.Baselines[i].Requirements)
	}
	return n
}

// AssertRequirementCount asserts the converter emitted exactly want requirements
// — the ground-truth anchor. want must come from a source-derived count (the
// Count* helpers), never from converter output. msg states the source-derived
// relationship being asserted.
func AssertRequirementCount(t *testing.T, result interface{}, want int, msg string) {
	t.Helper()
	require.NotZero(t, want, "anchor proves nothing with want=0 — use a fixture with >=1 source unit: %s", msg)
	require.Equal(t, want, TotalRequirements(t, result), msg)
}

// CountHDFResultRequirements counts the requirements in a raw HDF Results
// document — the sum of baselines[].requirements lengths. This is the export-side
// ground truth (one output record per baseline requirement); unlike
// CountJSONItemsUnderKey it does NOT double-count the "requirements" key where it
// recurs at other depths (e.g. groups). Independent of any converter's parser.
func CountHDFResultRequirements(t *testing.T, input []byte) int {
	t.Helper()
	var doc struct {
		Baselines []struct {
			Requirements []json.RawMessage `json:"requirements"`
		} `json:"baselines"`
	}
	require.NoError(t, json.Unmarshal(input, &doc), "unmarshal HDF results for anchor count")
	n := 0
	for i := range doc.Baselines {
		n += len(doc.Baselines[i].Requirements)
	}
	return n
}

// CountNDJSONRecords counts the non-empty newline-delimited JSON records in
// exporter output (one event/finding per line). Counts the emitted records
// generically — no converter parser involved.
func CountNDJSONRecords(t *testing.T, output []byte) int {
	t.Helper()
	n := 0
	for _, line := range strings.Split(strings.TrimSpace(string(output)), "\n") {
		if strings.TrimSpace(line) != "" {
			n++
		}
	}
	return n
}

// CountHDFOverrides counts the overrides in a raw HDF Amendments document
// (top-level overrides[]). The export-side ground truth for amendment exporters.
func CountHDFOverrides(t *testing.T, input []byte) int {
	t.Helper()
	var doc struct {
		Overrides []json.RawMessage `json:"overrides"`
	}
	require.NoError(t, json.Unmarshal(input, &doc), "unmarshal HDF amendments for anchor count")
	return len(doc.Overrides)
}

// cveShaped matches the CVE-id shape the VEX exporters key on (mirrors their
// ^CVE-\d{4}-\d{4,}$ pattern, defined here independently of any converter).
var cveShaped = regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`)

// CountDistinctCVEOverrides counts the distinct CVE-shaped requirementIds among a
// raw HDF Amendments document's overrides — the export-side ground truth for the
// VEX exporters, which drop non-CVE overrides and emit one record per CVE.
// Independent of any converter's parser.
func CountDistinctCVEOverrides(t *testing.T, input []byte) int {
	t.Helper()
	var doc struct {
		Overrides []struct {
			RequirementID string `json:"requirementId"`
		} `json:"overrides"`
	}
	require.NoError(t, json.Unmarshal(input, &doc), "unmarshal HDF amendments for anchor count")
	seen := map[string]bool{}
	for _, o := range doc.Overrides {
		if cveShaped.MatchString(o.RequirementID) {
			seen[o.RequirementID] = true
		}
	}
	return len(seen)
}

// TotalOverrides counts the amendment overrides a VEX importer emitted (top-level
// overrides[]). VEX importers produce HDF Amendments, not requirements.
func TotalOverrides(t *testing.T, result interface{}) int {
	t.Helper()
	data, err := json.Marshal(result)
	require.NoError(t, err, "marshal amendments for anchor count")
	var doc struct {
		Overrides []json.RawMessage `json:"overrides"`
	}
	require.NoError(t, json.Unmarshal(data, &doc), "unmarshal amendments for anchor count")
	return len(doc.Overrides)
}

// AssertOverrideCount is the amendment-output analogue of AssertRequirementCount
// for VEX importers: assert overrides[] length equals a source-derived count.
func AssertOverrideCount(t *testing.T, result interface{}, want int, msg string) {
	t.Helper()
	require.NotZero(t, want, "anchor proves nothing with want=0 — use a fixture with >=1 source unit: %s", msg)
	require.Equal(t, want, TotalOverrides(t, result), msg)
}
