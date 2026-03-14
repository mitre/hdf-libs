package normalize

import (
	"encoding/json"
	"testing"

	hdf "github.com/mitre/hdf-cli/pkg/hdf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// v1SingleResultDoc builds a minimal v1 document with one control and one result.
// The result map is merged with the provided overrides on top of a default "passed" status.
func v1SingleResultDoc(resultFields map[string]interface{}) []byte {
	result := map[string]interface{}{
		"status": "passed",
	}
	for k, v := range resultFields {
		result[k] = v
	}
	v1 := map[string]interface{}{
		"profiles": []interface{}{
			map[string]interface{}{
				"name": "test",
				"controls": []interface{}{
					map[string]interface{}{
						"id":      "V-001",
						"impact":  0.7,
						"tags":    map[string]interface{}{},
						"results": []interface{}{result},
					},
				},
			},
		},
	}
	data, _ := json.Marshal(v1) //nolint:errcheck // test helper
	return data
}

// v1SingleControlDoc builds a minimal v1 document with one control (no results).
func v1SingleControlDoc(controlFields map[string]interface{}) []byte {
	control := map[string]interface{}{
		"id":     "V-001",
		"impact": 0.7,
		"tags":   map[string]interface{}{},
	}
	for k, v := range controlFields {
		control[k] = v
	}
	v1 := map[string]interface{}{
		"profiles": []interface{}{
			map[string]interface{}{
				"name":     "test",
				"controls": []interface{}{control},
			},
		},
	}
	data, _ := json.Marshal(v1) //nolint:errcheck // test helper
	return data
}

// firstResult extracts the first requirement result from an HdfResults.
func firstResult(t *testing.T, result hdf.HdfResults) hdf.RequirementResult {
	t.Helper()
	require.NotEmpty(t, result.Baselines)
	require.NotEmpty(t, result.Baselines[0].Requirements)
	require.NotEmpty(t, result.Baselines[0].Requirements[0].Results)
	return result.Baselines[0].Requirements[0].Results[0]
}

// firstReq extracts the first requirement from an HdfResults.
func firstReq(t *testing.T, result hdf.HdfResults) hdf.EvaluatedRequirement {
	t.Helper()
	require.NotEmpty(t, result.Baselines)
	require.NotEmpty(t, result.Baselines[0].Requirements)
	return result.Baselines[0].Requirements[0]
}

// ---------------------------------------------------------------------------
// IsV1Format tests
// ---------------------------------------------------------------------------

func TestIsV1Format_TrueForV1WithProfiles(t *testing.T) {
	data := map[string]interface{}{
		"profiles":   []interface{}{},
		"platform":   map[string]interface{}{},
		"statistics": map[string]interface{}{},
	}
	assert.True(t, IsV1Format(data))
}

func TestIsV1Format_FalseForV2WithBaselines(t *testing.T) {
	data := map[string]interface{}{
		"baselines": []interface{}{},
	}
	assert.False(t, IsV1Format(data))
}

func TestIsV1Format_FalseWhenBothProfilesAndBaselines(t *testing.T) {
	data := map[string]interface{}{
		"profiles":  []interface{}{},
		"baselines": []interface{}{},
	}
	assert.False(t, IsV1Format(data))
}

func TestIsV1Format_FalseForEmptyDocument(t *testing.T) {
	data := map[string]interface{}{}
	assert.False(t, IsV1Format(data))
}

// ---------------------------------------------------------------------------
// ToV2 tests
// ---------------------------------------------------------------------------

func TestToV2_PassthroughV2(t *testing.T) {
	v2JSON := `{"baselines":[{"name":"test","requirements":[]}],"statistics":{"duration":1.0}}`
	result, err := ToV2([]byte(v2JSON))
	require.NoError(t, err)
	assert.Equal(t, 1, len(result.Baselines))
	assert.Equal(t, "test", result.Baselines[0].Name)
}

func TestToV2_ConvertsProfilesToBaselines(t *testing.T) {
	v1 := map[string]interface{}{
		"profiles": []interface{}{
			map[string]interface{}{
				"name":       "nginx-baseline",
				"title":      "NGINX Baseline",
				"version":    "2.0.0",
				"sha256":     "abc123",
				"controls":   []interface{}{},
				"groups":     []interface{}{},
				"supports":   []interface{}{},
				"attributes": []interface{}{},
			},
		},
		"statistics": map[string]interface{}{"duration": 1.5},
	}
	data, err := json.Marshal(v1)
	require.NoError(t, err)

	result, err := ToV2(data)
	require.NoError(t, err)

	require.Len(t, result.Baselines, 1)
	assert.Equal(t, "nginx-baseline", result.Baselines[0].Name)
	title := "NGINX Baseline"
	assert.Equal(t, &title, result.Baselines[0].Title)
	version := "2.0.0"
	assert.Equal(t, &version, result.Baselines[0].Version)
}

func TestToV2_ConvertsControlsToRequirements(t *testing.T) {
	v1 := map[string]interface{}{
		"profiles": []interface{}{
			map[string]interface{}{
				"name": "test",
				"controls": []interface{}{
					map[string]interface{}{
						"id":     "V-13613",
						"title":  "Test Control",
						"desc":   "A test description",
						"impact": 0.5,
						"tags":   map[string]interface{}{"cci": []interface{}{"CCI-000366"}},
						"refs":   []interface{}{},
						"source_location": map[string]interface{}{
							"ref":  "controls/test.rb",
							"line": float64(1),
						},
						"results": []interface{}{
							map[string]interface{}{
								"status":     "passed",
								"code_desc":  "File /etc/nginx should exist",
								"run_time":   0.05,
								"start_time": "2024-01-01T00:00:00Z",
							},
						},
					},
				},
				"groups":   []interface{}{},
				"supports": []interface{}{},
			},
		},
		"statistics": map[string]interface{}{"duration": 0.05},
	}
	data, err := json.Marshal(v1)
	require.NoError(t, err)

	result, err := ToV2(data)
	require.NoError(t, err)

	require.Len(t, result.Baselines, 1)
	reqs := result.Baselines[0].Requirements
	require.Len(t, reqs, 1)

	req := reqs[0]
	assert.Equal(t, "V-13613", req.ID)
	title := "Test Control"
	assert.Equal(t, &title, req.Title)
	assert.InDelta(t, 0.5, req.Impact, 0.001)

	// Descriptions converted from desc string.
	require.Len(t, req.Descriptions, 1)
	assert.Equal(t, "default", req.Descriptions[0].Label)
	assert.Equal(t, "A test description", req.Descriptions[0].Data)

	// Results with camelCase.
	require.Len(t, req.Results, 1)
	assert.Equal(t, "File /etc/nginx should exist", req.Results[0].CodeDesc)
	require.NotNil(t, req.Results[0].RunTime)
	assert.InDelta(t, 0.05, *req.Results[0].RunTime, 0.001)
	assert.Equal(t, "2024-01-01T00:00:00Z", req.Results[0].StartTime.Format("2006-01-02T15:04:05Z"))

	// Source location.
	require.NotNil(t, req.SourceLocation.Ref)
	assert.Equal(t, "controls/test.rb", *req.SourceLocation.Ref)
	require.NotNil(t, req.SourceLocation.Line)
	assert.InDelta(t, 1.0, *req.SourceLocation.Line, 0.001)
}

func TestToV2_HandlesControlsWithNoResults(t *testing.T) {
	data := v1SingleControlDoc(nil)

	result, err := ToV2(data)
	require.NoError(t, err)

	req := firstReq(t, result)
	assert.Len(t, req.Results, 0)
}

func TestToV2_HandlesControlsWithNoDesc(t *testing.T) {
	data := v1SingleControlDoc(map[string]interface{}{
		"results": []interface{}{},
	})

	result, err := ToV2(data)
	require.NoError(t, err)

	req := firstReq(t, result)
	assert.Len(t, req.Descriptions, 0)
}

func TestToV2_PreservesTimestamp(t *testing.T) {
	v1 := map[string]interface{}{
		"profiles": []interface{}{
			map[string]interface{}{
				"name":     "test",
				"controls": []interface{}{},
			},
		},
		"timestamp": "2024-01-01T00:00:00Z",
	}
	data, err := json.Marshal(v1)
	require.NoError(t, err)

	result, err := ToV2(data)
	require.NoError(t, err)

	require.NotNil(t, result.Timestamp)
	assert.Equal(t, "2024-01-01T00:00:00Z", result.Timestamp.Format("2006-01-02T15:04:05Z"))
}

func TestToV2_HandlesProfileWithoutSHA256(t *testing.T) {
	v1 := map[string]interface{}{
		"profiles": []interface{}{
			map[string]interface{}{
				"name":     "no-hash",
				"controls": []interface{}{},
			},
		},
	}
	data, err := json.Marshal(v1)
	require.NoError(t, err)

	result, err := ToV2(data)
	require.NoError(t, err)

	baseline := result.Baselines[0]
	assert.Empty(t, baseline.Checksum.Value)
}

func TestToV2_HandlesProfileWithNoControls(t *testing.T) {
	v1 := map[string]interface{}{
		"profiles": []interface{}{
			map[string]interface{}{
				"name": "empty-profile",
			},
		},
	}
	data, err := json.Marshal(v1)
	require.NoError(t, err)

	result, err := ToV2(data)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements
	assert.Len(t, reqs, 0)
}

func TestToV2_HandlesControlsWithNoTagsOrRefs(t *testing.T) {
	data := v1SingleResultDoc(map[string]interface{}{
		"code_desc":  "test",
		"start_time": "2024-01-01T00:00:00Z",
	})

	result, err := ToV2(data)
	require.NoError(t, err)

	req := firstReq(t, result)
	assert.NotNil(t, req.Tags)
	assert.Len(t, req.Tags, 0)
	assert.NotNil(t, req.Refs)
	assert.Len(t, req.Refs, 0)
}

func TestToV2_HandlesCamelCaseResultFieldsInV1(t *testing.T) {
	data := v1SingleResultDoc(map[string]interface{}{
		"status":    "failed",
		"codeDesc":  "already camelCase",
		"runTime":   0.1,
		"startTime": "2024-01-01T00:00:00Z",
	})

	result, err := ToV2(data)
	require.NoError(t, err)

	r := firstResult(t, result)
	assert.Equal(t, "already camelCase", r.CodeDesc)
	require.NotNil(t, r.RunTime)
	assert.InDelta(t, 0.1, *r.RunTime, 0.001)
	assert.Equal(t, "2024-01-01T00:00:00Z", r.StartTime.Format("2006-01-02T15:04:05Z"))
}

func TestToV2_HandlesCamelCaseSourceLocationInV1(t *testing.T) {
	data := v1SingleControlDoc(map[string]interface{}{
		"sourceLocation": map[string]interface{}{
			"ref":  "controls/test.rb",
			"line": float64(5),
		},
		"results": []interface{}{},
	})

	result, err := ToV2(data)
	require.NoError(t, err)

	req := firstReq(t, result)
	require.NotNil(t, req.SourceLocation.Ref)
	assert.Equal(t, "controls/test.rb", *req.SourceLocation.Ref)
	require.NotNil(t, req.SourceLocation.Line)
	assert.InDelta(t, 5.0, *req.SourceLocation.Line, 0.001)
}

func TestToV2_MapsSkippedToNotReviewed(t *testing.T) {
	data := v1SingleResultDoc(map[string]interface{}{
		"status":     "skipped",
		"code_desc":  "skipped test",
		"start_time": "2024-01-01T00:00:00Z",
	})

	result, err := ToV2(data)
	require.NoError(t, err)

	r := firstResult(t, result)
	require.NotNil(t, r.Status)
	assert.Equal(t, "notReviewed", string(*r.Status))
}

func TestToV2_NormalizesNonISOTimestamp(t *testing.T) {
	data := v1SingleResultDoc(map[string]interface{}{
		"code_desc":  "test",
		"start_time": "2017-09-22 14:12:15 -0400",
	})

	result, err := ToV2(data)
	require.NoError(t, err)

	r := firstResult(t, result)
	formatted := r.StartTime.Format("2006-01-02T15:04:05Z07:00")
	assert.Contains(t, formatted, "T")
	assert.Equal(t, 2017, r.StartTime.Year())
	assert.Equal(t, 9, int(r.StartTime.Month()))
	assert.Equal(t, 22, r.StartTime.Day())
}

func TestToV2_PreservesValidISOTimestamp(t *testing.T) {
	data := v1SingleResultDoc(map[string]interface{}{
		"code_desc":  "test",
		"start_time": "2024-01-01T00:00:00Z",
	})

	result, err := ToV2(data)
	require.NoError(t, err)

	r := firstResult(t, result)
	assert.Equal(t, "2024-01-01T00:00:00Z", r.StartTime.Format("2006-01-02T15:04:05Z"))
}

func TestToV2_UnparseableTimestampBecomesZero(t *testing.T) {
	// Go requires time.Time, so unparseable timestamps become zero value.
	data := v1SingleResultDoc(map[string]interface{}{
		"code_desc":  "test",
		"start_time": "not-a-date",
	})

	result, err := ToV2(data)
	require.NoError(t, err)

	r := firstResult(t, result)
	assert.True(t, r.StartTime.IsZero())
}

func TestToV2_HandlesCamelCaseStartTimeOnly(t *testing.T) {
	data := v1SingleResultDoc(map[string]interface{}{
		"codeDesc":  "already camelCase desc",
		"startTime": "2024-06-01T00:00:00Z",
	})

	result, err := ToV2(data)
	require.NoError(t, err)

	r := firstResult(t, result)
	assert.Equal(t, "2024-06-01T00:00:00Z", r.StartTime.Format("2006-01-02T15:04:05Z"))
	assert.Equal(t, "already camelCase desc", r.CodeDesc)
}

func TestToV2_EmptyStartTimeBecomesZero(t *testing.T) {
	data := v1SingleResultDoc(map[string]interface{}{
		"code_desc":  "test",
		"start_time": "",
	})

	result, err := ToV2(data)
	require.NoError(t, err)

	r := firstResult(t, result)
	assert.True(t, r.StartTime.IsZero())
}

func TestToV2_MissingStartTimeBecomesZero(t *testing.T) {
	data := v1SingleResultDoc(map[string]interface{}{
		"code_desc": "test",
	})

	result, err := ToV2(data)
	require.NoError(t, err)

	r := firstResult(t, result)
	assert.True(t, r.StartTime.IsZero())
}

func TestToV2_MissingCodeDescDefaultsToEmpty(t *testing.T) {
	data := v1SingleResultDoc(map[string]interface{}{
		"start_time": "2024-01-01T00:00:00Z",
	})

	result, err := ToV2(data)
	require.NoError(t, err)

	r := firstResult(t, result)
	assert.Equal(t, "", r.CodeDesc)
}

func TestToV2_OmitsOptionalFieldsWhenUndefined(t *testing.T) {
	data := v1SingleResultDoc(map[string]interface{}{
		"code_desc":  "test",
		"start_time": "2024-01-01T00:00:00Z",
	})

	result, err := ToV2(data)
	require.NoError(t, err)

	r := firstResult(t, result)
	assert.Nil(t, r.RunTime)
	assert.Nil(t, r.Message)
}
