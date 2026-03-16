package hdfparsers

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	hdf "github.com/mitre/hdf-schema"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ── Helpers ──────────────────────────────────────────────────

func ptr(s string) *string { return &s }

func makeReq(id string, opts ...func(*hdf.EvaluatedRequirement)) hdf.EvaluatedRequirement {
	r := hdf.EvaluatedRequirement{
		ID:           id,
		Impact:       0.5,
		Tags:         map[string]interface{}{},
		Results:      []hdf.RequirementResult{},
		Descriptions: []hdf.Description{{Label: "default", Data: "Requirement " + id}},
	}
	for _, opt := range opts {
		opt(&r)
	}
	return r
}

func makeBaseline(name string, reqs []hdf.EvaluatedRequirement, opts ...func(*hdf.EvaluatedBaseline)) hdf.EvaluatedBaseline {
	b := hdf.EvaluatedBaseline{
		Name:         name,
		Requirements: reqs,
	}
	for _, opt := range opts {
		opt(&b)
	}
	return b
}

func makeResults(baselines []hdf.EvaluatedBaseline) hdf.HDFResults {
	return hdf.HDFResults{Baselines: baselines}
}

func withParent(parent string) func(*hdf.EvaluatedBaseline) {
	return func(b *hdf.EvaluatedBaseline) { b.ParentBaseline = ptr(parent) }
}

func withCode(code string) func(*hdf.EvaluatedRequirement) {
	return func(r *hdf.EvaluatedRequirement) { r.Code = ptr(code) }
}

func withImpact(impact float64) func(*hdf.EvaluatedRequirement) {
	return func(r *hdf.EvaluatedRequirement) { r.Impact = impact }
}

func withResults(results ...hdf.RequirementResult) func(*hdf.EvaluatedRequirement) {
	return func(r *hdf.EvaluatedRequirement) { r.Results = results }
}

func withTags(tags map[string]interface{}) func(*hdf.EvaluatedRequirement) {
	return func(r *hdf.EvaluatedRequirement) { r.Tags = tags }
}

func withDescriptions(descs ...hdf.Description) func(*hdf.EvaluatedRequirement) {
	return func(r *hdf.EvaluatedRequirement) { r.Descriptions = descs }
}

func withSeverity(s *hdf.Severity) func(*hdf.EvaluatedRequirement) {
	return func(r *hdf.EvaluatedRequirement) { r.Severity = s }
}

func withEffectiveStatus(s *hdf.ResultStatus) func(*hdf.EvaluatedRequirement) {
	return func(r *hdf.EvaluatedRequirement) { r.EffectiveStatus = s }
}

func result(status string) hdf.RequirementResult {
	return hdf.RequirementResult{Status: hdf.ResultStatus(status), CodeDesc: "test"}
}

func findReq(reqs []hdf.EvaluatedRequirement, id string) *hdf.EvaluatedRequirement {
	for i := range reqs {
		if reqs[i].ID == id {
			return &reqs[i]
		}
	}
	return nil
}

func reqIDs(reqs []hdf.EvaluatedRequirement) []string {
	ids := make([]string, len(reqs))
	for i, r := range reqs {
		ids[i] = r.ID
	}
	return ids
}

// ── Passthrough ─────────────────────────────────────────────

func TestFlattenOverlays_Passthrough(t *testing.T) {
	t.Run("single baseline unchanged", func(t *testing.T) {
		results := makeResults([]hdf.EvaluatedBaseline{
			makeBaseline("single", []hdf.EvaluatedRequirement{makeReq("V-1"), makeReq("V-2")}),
		})
		flat := FlattenOverlays(results)
		assert.Len(t, flat.Results.Baselines, 1)
		assert.Equal(t, "single", flat.Results.Baselines[0].Name)
		assert.Len(t, flat.Results.Baselines[0].Requirements, 2)
		assert.Empty(t, flat.Metadata.Merges)
		assert.Equal(t, 1, flat.Metadata.OriginalBaselineCount)
		assert.Equal(t, 1, flat.Metadata.FlattenedBaselineCount)
	})

	t.Run("multiple independent baselines unchanged", func(t *testing.T) {
		results := makeResults([]hdf.EvaluatedBaseline{
			makeBaseline("alpha", []hdf.EvaluatedRequirement{makeReq("A-1")}),
			makeBaseline("beta", []hdf.EvaluatedRequirement{makeReq("B-1")}),
		})
		flat := FlattenOverlays(results)
		assert.Len(t, flat.Results.Baselines, 2)
		assert.Empty(t, flat.Metadata.Merges)
	})

	t.Run("metadata shows 0 merges no warnings", func(t *testing.T) {
		results := makeResults([]hdf.EvaluatedBaseline{
			makeBaseline("only", []hdf.EvaluatedRequirement{makeReq("V-1")}),
		})
		flat := FlattenOverlays(results)
		assert.Equal(t, 1, flat.Metadata.OriginalBaselineCount)
		assert.Equal(t, 1, flat.Metadata.FlattenedBaselineCount)
		assert.Empty(t, flat.Metadata.Merges)
		assert.Empty(t, flat.Metadata.Warnings)
	})
}

// ── Deep nesting (overlay chain) ──────────────────────────

func makeTwoLayer() hdf.HDFResults {
	return makeResults([]hdf.EvaluatedBaseline{
		makeBaseline("my-overlay", []hdf.EvaluatedRequirement{
			makeReq("V-1", withCode("overlay code V1"), withTags(map[string]interface{}{"cci": []string{"CCI-001"}})),
			makeReq("V-2", withCode(""), withTags(map[string]interface{}{"cci": []string{"CCI-002"}})),
		}),
		makeBaseline("my-base", []hdf.EvaluatedRequirement{
			makeReq("V-1", withCode("base code V1"), withResults(result("passed")), withTags(map[string]interface{}{"cci": []string{"CCI-001"}})),
			makeReq("V-2", withCode("base code V2"), withResults(result("failed")), withTags(map[string]interface{}{"cci": []string{"CCI-002"}})),
			makeReq("V-3", withCode("base only"), withResults(result("passed"))),
		}, withParent("my-overlay")),
	})
}

func TestFlattenOverlays_DeepTwoLayer(t *testing.T) {
	t.Run("deduplicates to one baseline named after root", func(t *testing.T) {
		flat := FlattenOverlays(makeTwoLayer())
		assert.Len(t, flat.Results.Baselines, 1)
		assert.Equal(t, "my-overlay", flat.Results.Baselines[0].Name)
	})

	t.Run("preserves base results on merged controls", func(t *testing.T) {
		flat := FlattenOverlays(makeTwoLayer())
		reqs := flat.Results.Baselines[0].Requirements
		v1 := findReq(reqs, "V-1")
		v2 := findReq(reqs, "V-2")
		require.NotNil(t, v1)
		require.NotNil(t, v2)
		assert.Equal(t, hdf.ResultStatus("passed"), v1.Results[0].Status)
		assert.Equal(t, hdf.ResultStatus("failed"), v2.Results[0].Status)
	})

	t.Run("takes overlay code when non-empty", func(t *testing.T) {
		flat := FlattenOverlays(makeTwoLayer())
		v1 := findReq(flat.Results.Baselines[0].Requirements, "V-1")
		require.NotNil(t, v1)
		assert.Equal(t, "overlay code V1", *v1.Code)
	})

	t.Run("keeps base code when overlay code is empty", func(t *testing.T) {
		flat := FlattenOverlays(makeTwoLayer())
		v2 := findReq(flat.Results.Baselines[0].Requirements, "V-2")
		require.NotNil(t, v2)
		assert.Equal(t, "base code V2", *v2.Code)
	})

	t.Run("preserves controls only in base", func(t *testing.T) {
		flat := FlattenOverlays(makeTwoLayer())
		v3 := findReq(flat.Results.Baselines[0].Requirements, "V-3")
		require.NotNil(t, v3)
		assert.Equal(t, "base only", *v3.Code)
		assert.Len(t, v3.Results, 1)
	})

	t.Run("adds controls only in overlay", func(t *testing.T) {
		results := makeResults([]hdf.EvaluatedBaseline{
			makeBaseline("overlay", []hdf.EvaluatedRequirement{makeReq("V-1"), makeReq("NEW-1", withCode("new"))}),
			makeBaseline("base", []hdf.EvaluatedRequirement{
				makeReq("V-1", withResults(result("passed"))),
			}, withParent("overlay")),
		})
		flat := FlattenOverlays(results)
		ids := reqIDs(flat.Results.Baselines[0].Requirements)
		assert.Contains(t, ids, "V-1")
		assert.Contains(t, ids, "NEW-1")
	})

	t.Run("metadata shows 1 merge with pattern deep", func(t *testing.T) {
		flat := FlattenOverlays(makeTwoLayer())
		assert.Equal(t, 2, flat.Metadata.OriginalBaselineCount)
		assert.Equal(t, 1, flat.Metadata.FlattenedBaselineCount)
		require.Len(t, flat.Metadata.Merges, 1)
		m := flat.Metadata.Merges[0]
		assert.Equal(t, "my-overlay", m.RootBaseline)
		assert.Contains(t, m.AbsorbedBaselines, "my-base")
		assert.Equal(t, 5, m.ControlsBefore)
		assert.Equal(t, 3, m.ControlsAfter)
		assert.Equal(t, PatternDeep, m.Pattern)
	})

	t.Run("clears parentBaseline and depends on flattened baseline", func(t *testing.T) {
		flat := FlattenOverlays(makeTwoLayer())
		assert.Nil(t, flat.Results.Baselines[0].ParentBaseline)
		assert.Nil(t, flat.Results.Baselines[0].Depends)
	})
}

// ── Deep nesting — three-layer ────────────────────────────

func makeThreeLayer() hdf.HDFResults {
	return makeResults([]hdf.EvaluatedBaseline{
		makeBaseline("top", []hdf.EvaluatedRequirement{
			makeReq("V-1", withCode("top override")),
			makeReq("V-2", withCode("")),
		}),
		makeBaseline("mid", []hdf.EvaluatedRequirement{
			makeReq("V-1", withCode("")),
			makeReq("V-2", withCode("mid override")),
		}, withParent("top")),
		makeBaseline("base", []hdf.EvaluatedRequirement{
			makeReq("V-1", withCode("base code"), withResults(result("passed"))),
			makeReq("V-2", withCode("base code"), withResults(result("failed"))),
		}, withParent("mid")),
	})
}

func TestFlattenOverlays_DeepThreeLayer(t *testing.T) {
	t.Run("deduplicates to one baseline", func(t *testing.T) {
		flat := FlattenOverlays(makeThreeLayer())
		assert.Len(t, flat.Results.Baselines, 1)
		assert.Len(t, flat.Results.Baselines[0].Requirements, 2)
	})

	t.Run("topmost non-empty code wins", func(t *testing.T) {
		flat := FlattenOverlays(makeThreeLayer())
		reqs := flat.Results.Baselines[0].Requirements
		assert.Equal(t, "top override", *findReq(reqs, "V-1").Code)
		assert.Equal(t, "mid override", *findReq(reqs, "V-2").Code)
	})

	t.Run("base results survive through all layers", func(t *testing.T) {
		flat := FlattenOverlays(makeThreeLayer())
		reqs := flat.Results.Baselines[0].Requirements
		assert.Len(t, findReq(reqs, "V-1").Results, 1)
		assert.Len(t, findReq(reqs, "V-2").Results, 1)
	})

	t.Run("metadata lists absorbed baselines in bottom-up order", func(t *testing.T) {
		flat := FlattenOverlays(makeThreeLayer())
		require.Len(t, flat.Metadata.Merges, 1)
		assert.Equal(t, []string{"base", "mid"}, flat.Metadata.Merges[0].AbsorbedBaselines)
	})
}

// ── Wide nesting (wrapper) ────────────────────────────────

func makeWide() hdf.HDFResults {
	return makeResults([]hdf.EvaluatedBaseline{
		makeBaseline("wrapper", []hdf.EvaluatedRequirement{
			makeReq("K-1", withCode("wrapper k1")),
			makeReq("R-1", withCode("wrapper r1")),
			makeReq("W-1", withCode("own"), withResults(result("passed"))),
		}),
		makeBaseline("k8s", []hdf.EvaluatedRequirement{
			makeReq("K-1", withCode("k8s code"), withResults(result("passed"))),
		}, withParent("wrapper")),
		makeBaseline("rhel", []hdf.EvaluatedRequirement{
			makeReq("R-1", withCode("rhel code"), withResults(result("failed"))),
		}, withParent("wrapper")),
	})
}

func TestFlattenOverlays_Wide(t *testing.T) {
	t.Run("produces single baseline with all control IDs", func(t *testing.T) {
		flat := FlattenOverlays(makeWide())
		assert.Len(t, flat.Results.Baselines, 1)
		ids := reqIDs(flat.Results.Baselines[0].Requirements)
		assert.Contains(t, ids, "K-1")
		assert.Contains(t, ids, "R-1")
		assert.Contains(t, ids, "W-1")
	})

	t.Run("child results merged into wrapper controls", func(t *testing.T) {
		flat := FlattenOverlays(makeWide())
		reqs := flat.Results.Baselines[0].Requirements
		assert.Equal(t, hdf.ResultStatus("passed"), findReq(reqs, "K-1").Results[0].Status)
		assert.Equal(t, hdf.ResultStatus("failed"), findReq(reqs, "R-1").Results[0].Status)
	})

	t.Run("wrapper own controls preserved", func(t *testing.T) {
		flat := FlattenOverlays(makeWide())
		w1 := findReq(flat.Results.Baselines[0].Requirements, "W-1")
		require.NotNil(t, w1)
		assert.Len(t, w1.Results, 1)
	})

	t.Run("metadata shows pattern wide", func(t *testing.T) {
		flat := FlattenOverlays(makeWide())
		require.Len(t, flat.Metadata.Merges, 1)
		assert.Equal(t, PatternWide, flat.Metadata.Merges[0].Pattern)
	})
}

// ── Hybrid (deep + wide) ─────────────────────────────────

func TestFlattenOverlays_Hybrid(t *testing.T) {
	t.Run("wrapper with overlay chain child", func(t *testing.T) {
		results := makeResults([]hdf.EvaluatedBaseline{
			makeBaseline("wrapper", []hdf.EvaluatedRequirement{makeReq("V-1"), makeReq("K-1")}),
			makeBaseline("overlay", []hdf.EvaluatedRequirement{
				makeReq("V-1", withCode("overlay code")),
			}, withParent("wrapper")),
			makeBaseline("base", []hdf.EvaluatedRequirement{
				makeReq("V-1", withCode("base code"), withResults(result("passed"))),
			}, withParent("overlay")),
			makeBaseline("k8s", []hdf.EvaluatedRequirement{
				makeReq("K-1", withResults(result("failed"))),
			}, withParent("wrapper")),
		})
		flat := FlattenOverlays(results)
		assert.Len(t, flat.Results.Baselines, 1)

		reqs := flat.Results.Baselines[0].Requirements
		v1 := findReq(reqs, "V-1")
		require.NotNil(t, v1)
		assert.Len(t, v1.Results, 1)
		assert.Equal(t, "overlay code", *v1.Code)
		assert.Equal(t, hdf.ResultStatus("failed"), findReq(reqs, "K-1").Results[0].Status)
	})
}

// ── Merge semantics ───────────────────────────────────────

func TestFlattenOverlays_MergeSemantics(t *testing.T) {
	t.Run("base results preserved when overlay has empty results", func(t *testing.T) {
		results := makeResults([]hdf.EvaluatedBaseline{
			makeBaseline("overlay", []hdf.EvaluatedRequirement{makeReq("V-1")}),
			makeBaseline("base", []hdf.EvaluatedRequirement{
				makeReq("V-1", withResults(result("passed"))),
			}, withParent("overlay")),
		})
		flat := FlattenOverlays(results)
		assert.Len(t, flat.Results.Baselines[0].Requirements[0].Results, 1)
	})

	t.Run("tags shallow-merged incoming keys override", func(t *testing.T) {
		results := makeResults([]hdf.EvaluatedBaseline{
			makeBaseline("overlay", []hdf.EvaluatedRequirement{
				makeReq("V-1", withTags(map[string]interface{}{"severity": "high", "custom": "new"})),
			}),
			makeBaseline("base", []hdf.EvaluatedRequirement{
				makeReq("V-1", withTags(map[string]interface{}{"severity": "low", "nist": []string{"AC-2"}})),
			}, withParent("overlay")),
		})
		flat := FlattenOverlays(results)
		tags := flat.Results.Baselines[0].Requirements[0].Tags
		assert.Equal(t, "high", tags["severity"])
		assert.Equal(t, []string{"AC-2"}, tags["nist"])
		assert.Equal(t, "new", tags["custom"])
	})

	t.Run("descriptions merged by label", func(t *testing.T) {
		results := makeResults([]hdf.EvaluatedBaseline{
			makeBaseline("overlay", []hdf.EvaluatedRequirement{
				makeReq("V-1", withDescriptions(
					hdf.Description{Label: "default", Data: "overlay default"},
					hdf.Description{Label: "rationale", Data: "overlay rationale"},
				)),
			}),
			makeBaseline("base", []hdf.EvaluatedRequirement{
				makeReq("V-1", withDescriptions(
					hdf.Description{Label: "default", Data: "base default"},
					hdf.Description{Label: "check", Data: "base check"},
				)),
			}, withParent("overlay")),
		})
		flat := FlattenOverlays(results)
		descs := flat.Results.Baselines[0].Requirements[0].Descriptions
		descMap := make(map[string]string)
		for _, d := range descs {
			descMap[d.Label] = d.Data
		}
		assert.Equal(t, "overlay default", descMap["default"])
		assert.Equal(t, "base check", descMap["check"])
		assert.Equal(t, "overlay rationale", descMap["rationale"])
	})

	t.Run("impact from overlay wins", func(t *testing.T) {
		results := makeResults([]hdf.EvaluatedBaseline{
			makeBaseline("overlay", []hdf.EvaluatedRequirement{makeReq("V-1", withImpact(0.0))}),
			makeBaseline("base", []hdf.EvaluatedRequirement{
				makeReq("V-1", withImpact(0.7)),
			}, withParent("overlay")),
		})
		flat := FlattenOverlays(results)
		assert.Equal(t, 0.0, flat.Results.Baselines[0].Requirements[0].Impact)
	})

	t.Run("severity from overlay wins over base", func(t *testing.T) {
		medium := hdf.Medium
		high := hdf.SeverityHigh
		results := makeResults([]hdf.EvaluatedBaseline{
			makeBaseline("overlay", []hdf.EvaluatedRequirement{
				makeReq("V-1", withImpact(0.0), withSeverity(&medium)),
			}),
			makeBaseline("base", []hdf.EvaluatedRequirement{
				makeReq("V-1", withImpact(0.7), withSeverity(&high), withResults(result("passed"))),
			}, withParent("overlay")),
		})
		flat := FlattenOverlays(results)
		req := flat.Results.Baselines[0].Requirements[0]
		require.NotNil(t, req.Severity)
		assert.Equal(t, hdf.Medium, *req.Severity)
	})

	t.Run("base severity preserved when overlay has none", func(t *testing.T) {
		high := hdf.SeverityHigh
		results := makeResults([]hdf.EvaluatedBaseline{
			makeBaseline("overlay", []hdf.EvaluatedRequirement{
				makeReq("V-1", withImpact(0.0)),
			}),
			makeBaseline("base", []hdf.EvaluatedRequirement{
				makeReq("V-1", withImpact(0.7), withSeverity(&high), withResults(result("passed"))),
			}, withParent("overlay")),
		})
		flat := FlattenOverlays(results)
		req := flat.Results.Baselines[0].Requirements[0]
		require.NotNil(t, req.Severity)
		assert.Equal(t, hdf.SeverityHigh, *req.Severity)
	})

	t.Run("severity survives three-layer merge", func(t *testing.T) {
		medium := hdf.Medium
		high := hdf.SeverityHigh
		results := makeResults([]hdf.EvaluatedBaseline{
			makeBaseline("top", []hdf.EvaluatedRequirement{
				makeReq("V-1", withImpact(0.0), withSeverity(&medium)),
			}),
			makeBaseline("mid", []hdf.EvaluatedRequirement{
				makeReq("V-1", withImpact(0.0)),
			}, withParent("top")),
			makeBaseline("base", []hdf.EvaluatedRequirement{
				makeReq("V-1", withImpact(0.7), withSeverity(&high), withResults(result("passed"))),
			}, withParent("mid")),
		})
		flat := FlattenOverlays(results)
		req := flat.Results.Baselines[0].Requirements[0]
		require.NotNil(t, req.Severity)
		assert.Equal(t, hdf.Medium, *req.Severity)
	})

	t.Run("effectiveStatus from overlay wins when overlay has results", func(t *testing.T) {
		na := hdf.NotApplicable
		passed := hdf.Passed
		naResult := hdf.RequirementResult{Status: hdf.NotApplicable, CodeDesc: "NA check"}
		results := makeResults([]hdf.EvaluatedBaseline{
			makeBaseline("overlay", []hdf.EvaluatedRequirement{
				makeReq("V-1", withImpact(0.0), withEffectiveStatus(&na), withResults(naResult)),
			}),
			makeBaseline("base", []hdf.EvaluatedRequirement{
				makeReq("V-1", withImpact(0.7), withEffectiveStatus(&passed), withResults(result("passed"))),
			}, withParent("overlay")),
		})
		flat := FlattenOverlays(results)
		req := flat.Results.Baselines[0].Requirements[0]
		require.NotNil(t, req.EffectiveStatus)
		assert.Equal(t, hdf.NotApplicable, *req.EffectiveStatus)
	})

	t.Run("base effectiveStatus preserved when overlay has no results", func(t *testing.T) {
		nr := hdf.NotReviewed
		passed := hdf.Passed
		results := makeResults([]hdf.EvaluatedBaseline{
			makeBaseline("overlay", []hdf.EvaluatedRequirement{
				makeReq("V-1", withImpact(0.0), withEffectiveStatus(&nr)),
			}),
			makeBaseline("base", []hdf.EvaluatedRequirement{
				makeReq("V-1", withImpact(0.7), withEffectiveStatus(&passed), withResults(result("passed"))),
			}, withParent("overlay")),
		})
		flat := FlattenOverlays(results)
		req := flat.Results.Baselines[0].Requirements[0]
		require.NotNil(t, req.EffectiveStatus)
		assert.Equal(t, hdf.Passed, *req.EffectiveStatus)
	})
}

// ── Edge cases ────────────────────────────────────────────

func TestFlattenOverlays_EdgeCases(t *testing.T) {
	t.Run("orphan child treated as root with warning", func(t *testing.T) {
		results := makeResults([]hdf.EvaluatedBaseline{
			makeBaseline("orphan", []hdf.EvaluatedRequirement{makeReq("V-1")}, withParent("nonexistent")),
		})
		flat := FlattenOverlays(results)
		assert.Len(t, flat.Results.Baselines, 1)
		assert.NotEmpty(t, flat.Metadata.Warnings)
		assert.Contains(t, flat.Metadata.Warnings[0], "nonexistent")
	})

	t.Run("circular parentBaseline detected with warning", func(t *testing.T) {
		results := makeResults([]hdf.EvaluatedBaseline{
			makeBaseline("A", []hdf.EvaluatedRequirement{makeReq("V-1")}, withParent("B")),
			makeBaseline("B", []hdf.EvaluatedRequirement{makeReq("V-1")}, withParent("A")),
		})
		flat := FlattenOverlays(results)
		assert.GreaterOrEqual(t, len(flat.Results.Baselines), 1)
		assert.NotEmpty(t, flat.Metadata.Warnings)
	})

	t.Run("empty requirements array produces empty merge", func(t *testing.T) {
		results := makeResults([]hdf.EvaluatedBaseline{
			makeBaseline("overlay", []hdf.EvaluatedRequirement{}),
			makeBaseline("base", []hdf.EvaluatedRequirement{}, withParent("overlay")),
		})
		flat := FlattenOverlays(results)
		assert.Len(t, flat.Results.Baselines, 1)
		assert.Empty(t, flat.Results.Baselines[0].Requirements)
	})

	t.Run("resource pack handled cleanly", func(t *testing.T) {
		results := makeResults([]hdf.EvaluatedBaseline{
			makeBaseline("wrapper", []hdf.EvaluatedRequirement{makeReq("K-1")}),
			makeBaseline("k8s", []hdf.EvaluatedRequirement{
				makeReq("K-1", withResults(result("passed"))),
			}, withParent("wrapper")),
			makeBaseline("k8s-resources", []hdf.EvaluatedRequirement{}, withParent("k8s")),
		})
		flat := FlattenOverlays(results)
		assert.Len(t, flat.Results.Baselines, 1)
		assert.Len(t, flat.Results.Baselines[0].Requirements, 1)
	})

	t.Run("preserves non-baseline fields on HDFResults", func(t *testing.T) {
		results := makeResults([]hdf.EvaluatedBaseline{
			makeBaseline("single", []hdf.EvaluatedRequirement{makeReq("V-1")}),
		})
		dur := 42.0
		results.Statistics = &hdf.Statistics{Duration: &dur}
		flat := FlattenOverlays(results)
		require.NotNil(t, flat.Results.Statistics)
		assert.Equal(t, 42.0, *flat.Results.Statistics.Duration)
	})
}

// ── Integration: real fixtures ────────────────────────────

// loadV1FixtureAsHDFResults reads an InSpec v1 exec-json fixture and converts
// it to HDF v2 baselines for testing flattenOverlays with real data.
func loadV1FixtureAsHDFResults(t *testing.T, path string) hdf.HDFResults {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)

	var raw struct {
		Profiles []struct {
			Name          string `json:"name"`
			ParentProfile string `json:"parent_profile"`
			Controls      []struct {
				ID           string                 `json:"id"`
				Impact       float64                `json:"impact"`
				Tags         map[string]interface{} `json:"tags"`
				Results      []json.RawMessage      `json:"results"`
				Descriptions []hdf.Description      `json:"descriptions"`
				Code         string                 `json:"code"`
				Title        string                 `json:"title"`
			} `json:"controls"`
			Depends []struct {
				Name string `json:"name"`
			} `json:"depends"`
		} `json:"profiles"`
	}
	require.NoError(t, json.Unmarshal(data, &raw))

	baselines := make([]hdf.EvaluatedBaseline, len(raw.Profiles))
	for i, p := range raw.Profiles {
		reqs := make([]hdf.EvaluatedRequirement, len(p.Controls))
		for j, c := range p.Controls {
			var results []hdf.RequirementResult
			for _, r := range c.Results {
				var rr struct {
					Status   string  `json:"status"`
					CodeDesc string  `json:"code_desc"`
					Message  *string `json:"message"`
				}
				require.NoError(t, json.Unmarshal(r, &rr))
				results = append(results, hdf.RequirementResult{
					Status:   hdf.ResultStatus(rr.Status),
					CodeDesc: rr.CodeDesc,
					Message:  rr.Message,
				})
			}
			code := c.Code
			title := c.Title
			reqs[j] = hdf.EvaluatedRequirement{
				ID:           c.ID,
				Impact:       c.Impact,
				Tags:         c.Tags,
				Results:      results,
				Descriptions: c.Descriptions,
				Code:         &code,
				Title:        &title,
			}
		}
		b := hdf.EvaluatedBaseline{
			Name:         p.Name,
			Requirements: reqs,
		}
		if p.ParentProfile != "" {
			b.ParentBaseline = ptr(p.ParentProfile)
		}
		deps := make([]hdf.Dependency, len(p.Depends))
		for k, d := range p.Depends {
			deps[k] = hdf.Dependency{Name: ptr(d.Name)}
		}
		if len(deps) > 0 {
			b.Depends = deps
		}
		baselines[i] = b
	}
	return hdf.HDFResults{Baselines: baselines}
}

func TestFlattenOverlays_Integration(t *testing.T) {
	fixturesDir := filepath.Join("..", "..", "hdf-schema", "test", "fixtures")

	t.Run("Three_Layer_RHEL7 3 profiles to 1 baseline 247 controls", func(t *testing.T) {
		results := loadV1FixtureAsHDFResults(t, filepath.Join(fixturesDir, "Three_Layer_RHEL7_Overlay_Example.json"))
		flat := FlattenOverlays(results)

		assert.Len(t, flat.Results.Baselines, 1)
		assert.Len(t, flat.Results.Baselines[0].Requirements, 247)
		assert.Equal(t, 3, flat.Metadata.OriginalBaselineCount)
		assert.Equal(t, 1, flat.Metadata.FlattenedBaselineCount)

		withResults := 0
		for _, r := range flat.Results.Baselines[0].Requirements {
			if len(r.Results) > 0 {
				withResults++
			}
		}
		assert.Equal(t, 247, withResults)
	})

	t.Run("wrapper.json 4 profiles to 1 baseline 534 controls", func(t *testing.T) {
		results := loadV1FixtureAsHDFResults(t, filepath.Join(fixturesDir, "wrapper.json"))
		flat := FlattenOverlays(results)

		assert.Len(t, flat.Results.Baselines, 1)
		assert.Len(t, flat.Results.Baselines[0].Requirements, 534)
		assert.Equal(t, 4, flat.Metadata.OriginalBaselineCount)
		assert.Equal(t, 1, flat.Metadata.FlattenedBaselineCount)
	})
}
