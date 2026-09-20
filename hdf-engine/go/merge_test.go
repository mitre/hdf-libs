package hdfengine

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	validators "github.com/mitre/hdf-libs/hdf-validators/go/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// loadMergeFixture reads one of the shared merge fixtures — committed copies of
// real converter expected output (gosec real, ZAP webgoat, grype tensorflow).
// test/merge.test.ts reads the SAME files and asserts the SAME expectations, so
// the two Merge implementations are held to one cross-language contract.
func loadMergeFixture(t *testing.T, name string) hdf.HDFResults {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "testdata", name))
	require.NoError(t, err)
	var results hdf.HDFResults
	require.NoError(t, json.Unmarshal(data, &results))
	return results
}

func threeScanners(t *testing.T) []MergeSource {
	t.Helper()
	return []MergeSource{
		{Name: "gosec.hdf.json", Doc: loadMergeFixture(t, "merge-gosec.json")},
		{Name: "zap.hdf.json", Doc: loadMergeFixture(t, "merge-zap.json")},
		{Name: "grype.hdf.json", Doc: loadMergeFixture(t, "merge-grype.json")},
	}
}

func baselineNames(r hdf.HDFResults) []string {
	out := make([]string, 0, len(r.Baselines))
	for _, b := range r.Baselines {
		out = append(out, b.Name)
	}
	return out
}

// TestMerge_OneBaselinePerInputPrefixedByTool is js1nv.3's first failing test:
// merging gosec + ZAP + grype yields one baseline per input baseline (1 + 4 + 1),
// each renamed `<tool>/<original>` per ADR-0016 §2, with every requirement
// carried and the output valid against hdf-results.
func TestMerge_OneBaselinePerInputPrefixedByTool(t *testing.T) {
	merged, warnings, err := Merge(threeScanners(t))
	require.NoError(t, err)
	assert.Empty(t, warnings, "distinct tools and names produce no warnings")

	assert.Equal(t, []string{
		"gosec/gosec Scan",
		"owasp zap/OWASP ZAP Scan: ciscobinary.openh264.org",
		"owasp zap/OWASP ZAP Scan: code.jquery.com",
		"owasp zap/OWASP ZAP Scan: detectportal.firefox.com",
		"owasp zap/OWASP ZAP Scan: mymac.com",
		"grype/tensorflow/tensorflow:latest",
	}, baselineNames(merged))

	total := 0
	for _, b := range merged.Baselines {
		total += len(b.Requirements)
	}
	assert.Equal(t, 57, total, "3 + 28 + 26 requirements, none dropped or deduplicated")

	data, err := json.Marshal(merged)
	require.NoError(t, err)
	res := validators.ValidateResults(data)
	assert.True(t, res.Valid, "merged document must validate as hdf-results: %+v", res.Errors)
}

// TestMerge_ProvenanceLabels (ADR-0016 §3): every merged baseline carries
// tool / toolVersion / sourceDocument; labels the source already had survive.
func TestMerge_ProvenanceLabels(t *testing.T) {
	merged, _, err := Merge(threeScanners(t))
	require.NoError(t, err)

	gosec := merged.Baselines[0]
	assert.Equal(t, map[string]string{"tool": "gosec", "toolVersion": "dev", "sourceDocument": "gosec.hdf.json"}, gosec.Labels)
	// The gosec baseline's own extensions ride along untouched.
	assert.Contains(t, gosec.Extensions, "gosec")

	zap := merged.Baselines[1]
	assert.Equal(t, map[string]string{
		"component": "ciscobinary.openh264.org", // pre-existing label, preserved
		"tool":      "owasp zap", "toolVersion": "2.7.0", "sourceDocument": "zap.hdf.json",
	}, zap.Labels)

	grype := merged.Baselines[5]
	assert.Equal(t, map[string]string{"tool": "grype", "toolVersion": "0.79.3", "sourceDocument": "grype.hdf.json"}, grype.Labels)
}

// TestMerge_Root (ADR-0016 §4): generator names the merger at the engine
// version; tool is omitted; timestamp is the latest input; components are the
// union (none of these fixtures carries a componentId, so all five are kept);
// each input's root provenance is preserved verbatim under extensions.
func TestMerge_Root(t *testing.T) {
	merged, _, err := Merge(threeScanners(t))
	require.NoError(t, err)

	require.NotNil(t, merged.Generator)
	assert.Equal(t, hdf.Generator{Name: "hdf-merge", Version: Version()}, *merged.Generator)
	assert.Nil(t, merged.Tool)
	require.NotNil(t, merged.Timestamp)
	assert.Equal(t, "2026-07-12T22:56:36.173673Z", merged.Timestamp.UTC().Format("2006-01-02T15:04:05.999999999Z07:00"), "gosec's timestamp is the latest of the three")
	assert.Len(t, merged.Components, 5, "4 ZAP sites + 1 grype image, no componentIds → all kept")

	ext, ok := merged.Extensions["hdf-merge"].(map[string]any)
	require.True(t, ok, "extensions[hdf-merge] must be present: %v", merged.Extensions)
	assert.Equal(t, Version(), ext["version"])
	sources, ok := ext["sources"].([]any)
	require.True(t, ok)
	require.Len(t, sources, 3)
	first, ok := sources[0].(map[string]any)
	require.True(t, ok)
	assert.EqualValues(t, 0, first["index"])
	assert.Equal(t, "gosec.hdf.json", first["name"])
	assert.Equal(t, map[string]any{"name": "gosec", "version": "dev"}, first["tool"])
	assert.Equal(t, map[string]any{"name": "gosec-to-hdf", "version": "1.0.0"}, first["generator"])
	assert.Equal(t, "2026-07-12T22:56:36.173673Z", first["timestamp"])
	_, hasRunner := first["runner"]
	assert.False(t, hasRunner, "an absent input field is absent, never synthesized")
}

// TestMerge_Deterministic (ADR-0016 §4): the same inputs in the same order
// serialize to byte-identical JSON on every run.
func TestMerge_Deterministic(t *testing.T) {
	a, _, err := Merge(threeScanners(t))
	require.NoError(t, err)
	b, _, err := Merge(threeScanners(t))
	require.NoError(t, err)
	ja, err := json.Marshal(a)
	require.NoError(t, err)
	jb, err := json.Marshal(b)
	require.NoError(t, err)
	assert.Equal(t, string(ja), string(jb))
}

// TestMerge_WarnsOnCollisionsAndOverwrites (ADR-0016 §2, §3): two inputs from
// the same tool with the same baseline name still collide after prefixing —
// both are kept and a warning names both positions. Merging an already-merged
// document overwrites its provenance labels, with a warning per label, and its
// prefix falls back to generator.name because a merged root carries no tool.
func TestMerge_WarnsOnCollisionsAndOverwrites(t *testing.T) {
	g := loadMergeFixture(t, "merge-gosec.json")
	merged, warnings, err := Merge([]MergeSource{{Name: "a.json", Doc: g}, {Name: "b.json", Doc: g}})
	require.NoError(t, err)
	assert.Equal(t, []string{"gosec/gosec Scan", "gosec/gosec Scan"}, baselineNames(merged), "collisions are kept, never dropped or renamed further")
	require.Len(t, warnings, 1)
	assert.Equal(t, MergeWarning{Kind: WarnDuplicateBaselineName, Name: "gosec/gosec Scan", Indices: []int{0, 1}}, warnings[0])

	again, warnings, err := Merge([]MergeSource{{Name: "merged.json", Doc: merged}})
	require.NoError(t, err)
	assert.Equal(t, []string{"hdf-merge/gosec/gosec Scan", "hdf-merge/gosec/gosec Scan"}, baselineNames(again))
	kinds := map[MergeWarningKind]int{}
	for _, w := range warnings {
		kinds[w.Kind]++
	}
	assert.Equal(t, 1, kinds[WarnDuplicateBaselineName], "the collision is reported again, exactly once")
	assert.Equal(t, 6, kinds[WarnLabelOverwritten], "tool, toolVersion and sourceDocument overwritten on each of the two baselines")
	assert.Equal(t, "hdf-merge", again.Baselines[0].Labels["tool"])
	assert.Equal(t, "merged.json", again.Baselines[0].Labels["sourceDocument"])
}

// TestMerge_Errors: no sources is an error, not an empty document.
func TestMerge_Errors(t *testing.T) {
	_, _, err := Merge(nil)
	require.Error(t, err)
	_, _, err = Merge([]MergeSource{})
	require.Error(t, err)
}

// TestMerge_WritesForLiveVerification is the Gate-18 hook: when
// HDF_MERGE_LIVE_OUT names a path, it writes the three-scanner merge there so
// the shipped `hdf` binary can be run against real merged output (validate,
// query, list). Skipped otherwise — it asserts nothing the tests above do not.
func TestMerge_WritesForLiveVerification(t *testing.T) {
	out := os.Getenv("HDF_MERGE_LIVE_OUT")
	if out == "" {
		t.Skip("set HDF_MERGE_LIVE_OUT=<path> to write the merged document for live verification")
	}
	merged, _, err := Merge(threeScanners(t))
	require.NoError(t, err)
	data, err := json.MarshalIndent(merged, "", "  ")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(out, data, 0o600))
}

// The tests below pin the ADR-0016 rules the three-scanner happy path cannot
// distinguish (its latest timestamp is also its first input, its fixtures carry
// no componentIds, and every input names a tool). Where a rule needs a document
// shape no committed real fixture has, the input is DERIVED from a real fixture
// in-test — a field cleared or an id assigned — never a fabricated document.

// TestMerge_LatestTimestampIsNotFirst: with grype (2024) first and gosec (2026)
// second, the root timestamp is still gosec's, so "latest" is not "first".
func TestMerge_LatestTimestampIsNotFirst(t *testing.T) {
	merged, _, err := Merge([]MergeSource{
		{Name: "grype.hdf.json", Doc: loadMergeFixture(t, "merge-grype.json")},
		{Name: "gosec.hdf.json", Doc: loadMergeFixture(t, "merge-gosec.json")},
		{Name: "zap.hdf.json", Doc: loadMergeFixture(t, "merge-zap.json")},
	})
	require.NoError(t, err)
	require.NotNil(t, merged.Timestamp)
	assert.Equal(t, "2026-07-12T22:56:36.173673Z", merged.Timestamp.UTC().Format(time.RFC3339Nano))
	assert.Equal(t, "grype/tensorflow/tensorflow:latest", merged.Baselines[0].Name, "input order is preserved")
	assert.Equal(t, "gosec/gosec Scan", merged.Baselines[1].Name)
}

// TestMerge_NoTimestampOnAnyInput: the root timestamp is omitted, not invented.
func TestMerge_NoTimestampOnAnyInput(t *testing.T) {
	g := loadMergeFixture(t, "merge-gosec.json")
	g.Timestamp = nil
	merged, _, err := Merge([]MergeSource{{Name: "g.json", Doc: g}})
	require.NoError(t, err)
	assert.Nil(t, merged.Timestamp)
	src := merged.Extensions["hdf-merge"].(map[string]any)["sources"].([]any)[0].(map[string]any)
	_, has := src["timestamp"]
	assert.False(t, has, "provenance carries no timestamp when the input had none")
}

// TestMerge_PrefixFallbacks: tool.name is trimmed and lower-cased; with no tool
// the generator name is used; with neither the prefix is doc<N>, 0-based, and no
// toolVersion label is written.
func TestMerge_PrefixFallbacks(t *testing.T) {
	spaced := loadMergeFixture(t, "merge-gosec.json")
	name := "  GoSec "
	spaced.Tool.Name = &name

	noTool := loadMergeFixture(t, "merge-gosec.json")
	noTool.Tool = nil // generator gosec-to-hdf remains

	bare := loadMergeFixture(t, "merge-gosec.json")
	bare.Tool = nil
	bare.Generator = nil

	merged, warnings, err := Merge([]MergeSource{
		{Name: "spaced.json", Doc: spaced},
		{Name: "notool.json", Doc: noTool},
		{Name: "bare.json", Doc: bare},
	})
	require.NoError(t, err)
	assert.Equal(t, []string{"gosec/gosec Scan", "gosec-to-hdf/gosec Scan", "doc2/gosec Scan"}, baselineNames(merged))
	assert.Equal(t, "gosec", merged.Baselines[0].Labels["tool"])
	assert.Equal(t, "gosec-to-hdf", merged.Baselines[1].Labels["tool"])
	assert.Equal(t, map[string]string{"tool": "doc2", "sourceDocument": "bare.json"}, merged.Baselines[2].Labels, "no tool → no toolVersion label")
	assert.Empty(t, warnings)
}

// TestMerge_ComponentUnionByID: components sharing a componentId are kept once;
// components without one are all kept. Derived from real documents: the grype
// image component is given a fixed UUID and merged with itself.
func TestMerge_ComponentUnionByID(t *testing.T) {
	id := "11111111-1111-4111-8111-111111111111"
	a := loadMergeFixture(t, "merge-grype.json")
	a.Components[0].ComponentID = &id
	b := loadMergeFixture(t, "merge-grype.json")
	b.Components[0].ComponentID = &id
	zap := loadMergeFixture(t, "merge-zap.json") // four components, no ids

	merged, _, err := Merge([]MergeSource{{Name: "a.json", Doc: a}, {Name: "b.json", Doc: b}, {Name: "zap.json", Doc: zap}})
	require.NoError(t, err)
	require.Len(t, merged.Components, 5, "1 (shared id, kept once) + 4 (no id, all kept)")
	assert.Equal(t, id, *merged.Components[0].ComponentID)
	assert.Nil(t, merged.Components[1].ComponentID)
	data, err := json.Marshal(merged)
	require.NoError(t, err)
	assert.True(t, validators.ValidateResults(data).Valid)
}

// TestMerge_RemergeReplacesProvenance: merging an already-merged document
// replaces tool and sourceDocument, REMOVES the stale toolVersion (the merged
// root has no tool, so a kept version would describe the wrong tool), and
// reports each of the three per baseline with the label named.
func TestMerge_RemergeReplacesProvenance(t *testing.T) {
	first, _, err := Merge([]MergeSource{{Name: "zap.hdf.json", Doc: loadMergeFixture(t, "merge-zap.json")}})
	require.NoError(t, err)
	assert.Equal(t, "2.7.0", first.Baselines[0].Labels["toolVersion"])

	again, warnings, err := Merge([]MergeSource{{Name: "merged.json", Doc: first}})
	require.NoError(t, err)
	for i, b := range again.Baselines {
		_, has := b.Labels["toolVersion"]
		assert.False(t, has, "baseline %d must not keep a stale toolVersion", i)
		assert.Equal(t, "hdf-merge", b.Labels["tool"])
		assert.Equal(t, "merged.json", b.Labels["sourceDocument"])
		assert.Contains(t, b.Labels, "component", "the ZAP site label is preserved through a re-merge")
	}
	got := map[string][]int{}
	for _, w := range warnings {
		require.Equal(t, WarnLabelOverwritten, w.Kind)
		got[w.Label] = append(got[w.Label], w.Indices[0])
	}
	assert.Equal(t, map[string][]int{"tool": {0, 1, 2, 3}, "toolVersion": {0, 1, 2, 3}, "sourceDocument": {0, 1, 2, 3}}, got)
}

// TestMerge_SingleDocumentIsIdentity: apart from the renamed baselines, their
// labels, and the merged root, one input comes out unchanged — requirements,
// baseline metadata, extensions and components are the same values.
func TestMerge_SingleDocumentIsIdentity(t *testing.T) {
	in := loadMergeFixture(t, "merge-zap.json")
	merged, warnings, err := Merge([]MergeSource{{Name: "zap.hdf.json", Doc: in}})
	require.NoError(t, err)
	assert.Empty(t, warnings)
	require.Len(t, merged.Baselines, len(in.Baselines))
	for i := range in.Baselines {
		want := in.Baselines[i]
		got := merged.Baselines[i]
		want.Name, got.Name = "", ""
		want.Labels, got.Labels = nil, nil
		assert.Equal(t, want, got, "baseline %d differs beyond name/labels", i)
	}
	assert.Equal(t, in.Components, merged.Components)
	// The input itself was not mutated.
	assert.Equal(t, "OWASP ZAP Scan: ciscobinary.openh264.org", in.Baselines[0].Name)
	assert.Equal(t, map[string]string{"component": "ciscobinary.openh264.org"}, in.Baselines[0].Labels)
}
