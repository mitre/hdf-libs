package hdftosplunk

import (
	"encoding/json"
	"testing"

	fixtures "github.com/mitre/hdf-libs/hdf-fixtures"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---- helpers ----

// parse loads the converter output as the typed top-level shape.
func parse(t *testing.T, out []byte) SplunkData {
	t.Helper()
	var d SplunkData
	require.NoError(t, json.Unmarshal(out, &d))
	return d
}

// ---- happy-path shape ----

func TestConvert_Minimal_ProducesOneReportOneProfileOneControl(t *testing.T) {
	out, err := ConvertHDFToSplunk(fixtures.Results.Minimal)
	require.NoError(t, err)
	d := parse(t, out)

	require.Len(t, d.Reports, 1, "exactly one report per HDF doc")
	require.Len(t, d.Profiles, 1, "one profile per baseline")
	require.Len(t, d.Controls, 1, "one control per requirement (minimal has 1)")

	assert.Equal(t, "header", d.Reports[0].Meta.Subtype)
	assert.Equal(t, "profile", d.Profiles[0].Meta.Subtype)
	assert.Equal(t, "control", d.Controls[0].Meta.Subtype)
}

func TestConvert_MetaGUIDIsConsistentAcrossRecords(t *testing.T) {
	out, err := ConvertHDFToSplunk(fixtures.Results.Minimal)
	require.NoError(t, err)
	d := parse(t, out)

	guid := d.Reports[0].Meta.GUID
	require.NotEmpty(t, guid)
	for i, p := range d.Profiles {
		assert.Equal(t, guid, p.Meta.GUID, "profile[%d] guid", i)
	}
	for i, c := range d.Controls {
		assert.Equal(t, guid, c.Meta.GUID, "control[%d] guid", i)
	}
}

func TestConvert_MetaGUIDDiffersBetweenCalls(t *testing.T) {
	out1, err := ConvertHDFToSplunk(fixtures.Results.Minimal)
	require.NoError(t, err)
	out2, err := ConvertHDFToSplunk(fixtures.Results.Minimal)
	require.NoError(t, err)
	d1 := parse(t, out1)
	d2 := parse(t, out2)
	assert.NotEqual(t, d1.Reports[0].Meta.GUID, d2.Reports[0].Meta.GUID,
		"each call generates a fresh GUID")
}

func TestConvert_HDFSplunkSchemaIs11(t *testing.T) {
	out, err := ConvertHDFToSplunk(fixtures.Results.Minimal)
	require.NoError(t, err)
	d := parse(t, out)
	assert.Equal(t, "1.1", d.Reports[0].Meta.HDFSplunkSchema)
	for _, p := range d.Profiles {
		assert.Equal(t, "1.1", p.Meta.HDFSplunkSchema)
	}
	for _, c := range d.Controls {
		assert.Equal(t, "1.1", c.Meta.HDFSplunkSchema)
	}
}

func TestConvert_FiletypeEvaluation(t *testing.T) {
	out, err := ConvertHDFToSplunk(fixtures.Results.Minimal)
	require.NoError(t, err)
	d := parse(t, out)
	assert.Equal(t, "evaluation", d.Reports[0].Meta.Filetype)
	for _, p := range d.Profiles {
		assert.Equal(t, "evaluation", p.Meta.Filetype)
	}
	for _, c := range d.Controls {
		assert.Equal(t, "evaluation", c.Meta.Filetype)
	}
}

func TestConvert_FilenameDefaultPlaceholder(t *testing.T) {
	out, err := ConvertHDFToSplunk(fixtures.Results.Minimal)
	require.NoError(t, err)
	d := parse(t, out)
	// Documented placeholder; fetcher rewrites at upload time when the
	// real filename is known.
	assert.Equal(t, "hdf-results.json", d.Reports[0].Meta.Filename)
}

// ---- profile fields ----

func TestConvert_ProfileFieldsFromBaseline(t *testing.T) {
	out, err := ConvertHDFToSplunk(fixtures.Results.Minimal)
	require.NoError(t, err)
	d := parse(t, out)

	require.Len(t, d.Profiles, 1)
	p := d.Profiles[0]
	assert.Equal(t, "Minimal Baseline", p.Name)
	assert.Equal(t, "1.0.0", p.Version)
	assert.True(t, p.Meta.IsBaseline, "no parentBaseline → is_baseline=true")
}

func TestConvert_ProfileSHA256FromResultsChecksum(t *testing.T) {
	out, err := ConvertHDFToSplunk(fixtures.Results.Minimal)
	require.NoError(t, err)
	d := parse(t, out)

	// Minimal fixture uses resultsChecksum.value="abc123".
	assert.Equal(t, "abc123", d.Profiles[0].SHA256)
	assert.Equal(t, "abc123", d.Profiles[0].Meta.ProfileSHA256)
}

// ---- control fields ----

func TestConvert_ControlFieldsFromRequirement(t *testing.T) {
	out, err := ConvertHDFToSplunk(fixtures.Results.Minimal)
	require.NoError(t, err)
	d := parse(t, out)

	require.Len(t, d.Controls, 1)
	c := d.Controls[0]
	assert.Equal(t, "REQ-001", c.ID)
	assert.Equal(t, "Test Requirement", c.Title)
	assert.InDelta(t, 0.7, c.Impact, 0.001)
}

func TestConvert_ControlProfileSHA256MatchesParent(t *testing.T) {
	out, err := ConvertHDFToSplunk(fixtures.Results.Minimal)
	require.NoError(t, err)
	d := parse(t, out)
	// Every control points at its parent baseline's sha256.
	require.Len(t, d.Profiles, 1)
	require.Len(t, d.Controls, 1)
	assert.Equal(t, d.Profiles[0].SHA256, d.Controls[0].Meta.ProfileSHA256)
}

func TestConvert_DescriptionsFlattened(t *testing.T) {
	// Build a synthetic HDF doc with multiple labeled descriptions.
	input := []byte(`{
		"baselines": [{
			"name": "Test",
			"requirements": [{
				"id": "R1",
				"title": "t",
				"impact": 0.0,
				"tags": {},
				"descriptions": [
					{"label": "default", "data": "primary"},
					{"label": "fix", "data": "remediation steps"},
					{"label": "check", "data": "how to verify"}
				],
				"results": [{"status": "passed", "codeDesc": "ok", "startTime": "2026-01-01T00:00:00Z"}]
			}]
		}]
	}`)
	out, err := ConvertHDFToSplunk(input)
	require.NoError(t, err)
	d := parse(t, out)
	require.Len(t, d.Controls, 1)

	descs := d.Controls[0].Descriptions
	require.NotNil(t, descs)
	assert.Equal(t, "primary", descs["default"])
	assert.Equal(t, "remediation steps", descs["fix"])
	assert.Equal(t, "how to verify", descs["check"])
	assert.Equal(t, "primary", d.Controls[0].Desc, "desc field uses default label")
}

func TestConvert_DescEmptyWhenNoDefaultLabel(t *testing.T) {
	input := []byte(`{
		"baselines": [{
			"name": "Test",
			"requirements": [{
				"id": "R1",
				"impact": 0.0,
				"tags": {},
				"descriptions": [{"label": "fix", "data": "only fix"}],
				"results": [{"status": "passed", "codeDesc": "ok", "startTime": "2026-01-01T00:00:00Z"}]
			}]
		}]
	}`)
	out, err := ConvertHDFToSplunk(input)
	require.NoError(t, err)
	d := parse(t, out)
	assert.Empty(t, d.Controls[0].Desc, "no default-labeled description → empty desc")
}

// ---- status fold ----

func TestConvert_StatusWorstWins(t *testing.T) {
	cases := []struct {
		name     string
		statuses []string
		want     string
	}{
		{"all passed", []string{"passed", "passed"}, "passed"},
		{"passed and failed", []string{"passed", "failed"}, "failed"},
		{"error trumps failed", []string{"failed", "error"}, "error"},
		{"failed trumps notReviewed", []string{"notReviewed", "failed"}, "failed"},
		{"only notApplicable", []string{"notApplicable", "notApplicable"}, "notApplicable"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			results := []map[string]any{}
			for _, s := range tc.statuses {
				results = append(results, map[string]any{
					"status":    s,
					"codeDesc":  "x",
					"startTime": "2026-01-01T00:00:00Z",
				})
			}
			doc := map[string]any{
				"baselines": []any{
					map[string]any{
						"name": "T",
						"requirements": []any{
							map[string]any{
								"id":     "R",
								"impact": 0.0,
								"tags":   map[string]any{},
								"descriptions": []any{
									map[string]any{"label": "default", "data": "d"},
								},
								"results": results,
							},
						},
					},
				},
			}
			input, _ := json.Marshal(doc)
			out, err := ConvertHDFToSplunk(input)
			require.NoError(t, err)
			d := parse(t, out)
			assert.Equal(t, tc.want, d.Controls[0].Meta.Status)
		})
	}
}

// ---- is_waived ----

func TestConvert_IsWaivedFromDisposition(t *testing.T) {
	input := []byte(`{
		"baselines": [{
			"name": "T",
			"requirements": [{
				"id": "R",
				"impact": 0.0,
				"tags": {},
				"descriptions": [{"label": "default", "data": "d"}],
				"results": [{"status": "passed", "codeDesc": "ok", "startTime": "2026-01-01T00:00:00Z"}],
				"disposition": "waiver"
			}]
		}]
	}`)
	out, err := ConvertHDFToSplunk(input)
	require.NoError(t, err)
	d := parse(t, out)
	assert.True(t, d.Controls[0].Meta.IsWaived)
}

func TestConvert_IsWaivedFalseWhenNoDispositionWaiver(t *testing.T) {
	out, err := ConvertHDFToSplunk(fixtures.Results.Minimal)
	require.NoError(t, err)
	d := parse(t, out)
	assert.False(t, d.Controls[0].Meta.IsWaived)
}

// ---- platform ----

func TestConvert_PlatformFromTool(t *testing.T) {
	input := []byte(`{
		"baselines": [{
			"name": "T",
			"requirements": [{
				"id": "R", "impact": 0, "tags": {},
				"descriptions": [{"label": "default", "data": "d"}],
				"results": [{"status": "passed", "codeDesc": "ok", "startTime": "2026-01-01T00:00:00Z"}]
			}]
		}],
		"tool": {"name": "Nessus", "version": "10.2"}
	}`)
	out, err := ConvertHDFToSplunk(input)
	require.NoError(t, err)
	d := parse(t, out)
	assert.Equal(t, "Nessus", d.Reports[0].Platform.Name)
	assert.Equal(t, "10.2", d.Reports[0].Platform.Release)
}

// ---- multi-baseline ----

func TestConvert_MultiBaseline_ProducesProfilePerBaseline(t *testing.T) {
	out, err := ConvertHDFToSplunk(fixtures.Results.InspecMultilayered)
	require.NoError(t, err)
	d := parse(t, out)
	require.GreaterOrEqual(t, len(d.Profiles), 2, "multilayered fixture has multiple baselines")
	require.NotEmpty(t, d.Controls)

	// Each control's profile_sha256 points to one of the emitted profiles.
	profileChecksums := map[string]bool{}
	for _, p := range d.Profiles {
		profileChecksums[p.SHA256] = true
	}
	for _, c := range d.Controls {
		assert.True(t, profileChecksums[c.Meta.ProfileSHA256],
			"control %q profile_sha256 %q not found among profiles", c.ID, c.Meta.ProfileSHA256)
	}
}

// ---- error paths ----

func TestConvert_InvalidJSON(t *testing.T) {
	_, err := ConvertHDFToSplunk([]byte("not json"))
	require.Error(t, err)
}

func TestConvert_EmptyInput(t *testing.T) {
	_, err := ConvertHDFToSplunk([]byte(""))
	require.Error(t, err)
}

func TestConvert_NoBaselines(t *testing.T) {
	_, err := ConvertHDFToSplunk([]byte(`{"baselines": []}`))
	require.Error(t, err, "HDF schema requires baselines.minItems=1; empty input is malformed")
}

// ---- direct helper tests (close coverage gaps on defensive arms) ----

func TestProfileSHA_PrefersResultsChecksum(t *testing.T) {
	v := "abc"
	b := &parsedBaseline{
		ResultsChecksum: &parsedChecksum{Value: &v},
	}
	assert.Equal(t, "abc", profileSHA(b))
}

func TestProfileSHA_FallsBackToIntegrity(t *testing.T) {
	v := "def"
	b := &parsedBaseline{
		Integrity: &parsedChecksum{Checksum: &v},
	}
	assert.Equal(t, "def", profileSHA(b))
}

func TestProfileSHA_EmptyWhenNoChecksum(t *testing.T) {
	b := &parsedBaseline{}
	assert.Empty(t, profileSHA(b))
}

func TestParsedChecksum_HashNil(t *testing.T) {
	var c *parsedChecksum
	assert.Empty(t, c.hash())
}

func TestFoldStatus_EmptyResults(t *testing.T) {
	assert.Equal(t, "notReviewed", foldStatus(nil))
}

func TestNormalizeTags_NilReturnsEmptyMap(t *testing.T) {
	got := normalizeTags(nil)
	require.NotNil(t, got)
	assert.Empty(t, got)
}

func TestRawToAny_EmptyReturnsNil(t *testing.T) {
	assert.Nil(t, rawToAny(nil))
}

func TestRawToAny_InvalidReturnsNil(t *testing.T) {
	assert.Nil(t, rawToAny(json.RawMessage("not json")))
}

func TestFindBaseline_NotFound(t *testing.T) {
	doc := &parsedDoc{Baselines: []parsedBaseline{{Name: "a"}}}
	assert.Nil(t, findBaseline(doc, "missing"))
}

func TestOverlayDepth_CycleBreaks(t *testing.T) {
	a := "B"
	b := "A"
	doc := &parsedDoc{Baselines: []parsedBaseline{
		{Name: "A", ParentBaseline: &a},
		{Name: "B", ParentBaseline: &b},
	}}
	// A -> B -> A would loop; visited-set must break it.
	assert.Equal(t, 2, overlayDepth(&doc.Baselines[0], doc))
}

func TestOverlayDepth_ParentNotPresent(t *testing.T) {
	miss := "not-in-doc"
	doc := &parsedDoc{Baselines: []parsedBaseline{
		{Name: "A", ParentBaseline: &miss},
	}}
	// Parent reference unresolved → stop at depth 1.
	assert.Equal(t, 1, overlayDepth(&doc.Baselines[0], doc))
}

func TestBuildReport_StatisticsPassthrough(t *testing.T) {
	input := []byte(`{
		"baselines": [{
			"name": "T",
			"requirements": [{
				"id": "R", "impact": 0, "tags": {},
				"descriptions": [{"label": "default", "data": "d"}],
				"results": [{"status": "passed", "codeDesc": "ok", "startTime": "2026-01-01T00:00:00Z"}]
			}]
		}],
		"statistics": {"duration": 3.5},
		"extensions": {"customKey": "customValue"}
	}`)
	out, err := ConvertHDFToSplunk(input)
	require.NoError(t, err)
	d := parse(t, out)

	require.NotNil(t, d.Reports[0].Statistics)
	require.NotNil(t, d.Reports[0].Passthrough)
	assert.Equal(t, "customValue", d.Reports[0].Passthrough["customKey"])
}
