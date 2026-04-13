package normalize

import (
	"encoding/json"
	"testing"

	hdf "github.com/mitre/hdf-cli/pkg/hdf"
	hdfutil "github.com/mitre/hdf-libs/hdf-utilities/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// v1SingleResultDoc builds a minimal v1 document with one control and one result.
// The result map is merged with the provided overrides on top of a default "passed" status.
func v1SingleResultDoc(resultFields map[string]any) []byte {
	result := map[string]any{
		"status": "passed",
	}
	for k, v := range resultFields {
		result[k] = v
	}
	v1 := map[string]any{
		"profiles": []any{
			map[string]any{
				"name": "test",
				"controls": []any{
					map[string]any{
						"id":      "V-001",
						"impact":  0.7,
						"tags":    map[string]any{},
						"results": []any{result},
					},
				},
			},
		},
	}
	data, _ := json.Marshal(v1) //nolint:errcheck // test helper
	return data
}

// v1SingleControlDoc builds a minimal v1 document with one control (no results).
func v1SingleControlDoc(controlFields map[string]any) []byte {
	control := map[string]any{
		"id":     "V-001",
		"impact": 0.7,
		"tags":   map[string]any{},
	}
	for k, v := range controlFields {
		control[k] = v
	}
	v1 := map[string]any{
		"profiles": []any{
			map[string]any{
				"name":     "test",
				"controls": []any{control},
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
	data := map[string]any{
		"profiles":   []any{},
		"platform":   map[string]any{},
		"statistics": map[string]any{},
	}
	assert.True(t, IsV1Format(data))
}

func TestIsV1Format_FalseForV2WithBaselines(t *testing.T) {
	data := map[string]any{
		"baselines": []any{},
	}
	assert.False(t, IsV1Format(data))
}

func TestIsV1Format_FalseWhenBothProfilesAndBaselines(t *testing.T) {
	data := map[string]any{
		"profiles":  []any{},
		"baselines": []any{},
	}
	assert.False(t, IsV1Format(data))
}

func TestIsV1Format_FalseForEmptyDocument(t *testing.T) {
	data := map[string]any{}
	assert.False(t, IsV1Format(data))
}

// ---------------------------------------------------------------------------
// ToV2 tests
// ---------------------------------------------------------------------------

func TestToV2_PassthroughV2(t *testing.T) {
	v2JSON := `{"baselines":[{"name":"test","requirements":[]}],"statistics":{"duration":1.0}}`
	result, _, err := ToV2([]byte(v2JSON))
	require.NoError(t, err)
	assert.Equal(t, 1, len(result.Baselines))
	assert.Equal(t, "test", result.Baselines[0].Name)
}

func TestToV2_ConvertsProfilesToBaselines(t *testing.T) {
	v1 := map[string]any{
		"profiles": []any{
			map[string]any{
				"name":       "nginx-baseline",
				"title":      "NGINX Baseline",
				"version":    "2.0.0",
				"sha256":     "abc123",
				"controls":   []any{},
				"groups":     []any{},
				"supports":   []any{},
				"attributes": []any{},
			},
		},
		"statistics": map[string]any{"duration": 1.5},
	}
	data, err := json.Marshal(v1)
	require.NoError(t, err)

	result, _, err := ToV2(data)
	require.NoError(t, err)

	require.Len(t, result.Baselines, 1)
	assert.Equal(t, "nginx-baseline", result.Baselines[0].Name)
	title := "NGINX Baseline"
	assert.Equal(t, &title, result.Baselines[0].Title)
	version := "2.0.0"
	assert.Equal(t, &version, result.Baselines[0].Version)
}

func TestToV2_ConvertsControlsToRequirements(t *testing.T) {
	v1 := map[string]any{
		"profiles": []any{
			map[string]any{
				"name": "test",
				"controls": []any{
					map[string]any{
						"id":     "V-13613",
						"title":  "Test Control",
						"desc":   "A test description",
						"impact": 0.5,
						"tags":   map[string]any{"cci": []any{"CCI-000366"}},
						"refs":   []any{},
						"source_location": map[string]any{
							"ref":  "controls/test.rb",
							"line": float64(1),
						},
						"results": []any{
							map[string]any{
								"status":     "passed",
								"code_desc":  "File /etc/nginx should exist",
								"run_time":   0.05,
								"start_time": "2024-01-01T00:00:00Z",
							},
						},
					},
				},
				"groups":   []any{},
				"supports": []any{},
			},
		},
		"statistics": map[string]any{"duration": 0.05},
	}
	data, err := json.Marshal(v1)
	require.NoError(t, err)

	result, _, err := ToV2(data)
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

	result, _, err := ToV2(data)
	require.NoError(t, err)

	req := firstReq(t, result)
	assert.Len(t, req.Results, 0)
}

func TestToV2_HandlesControlsWithNoDesc(t *testing.T) {
	data := v1SingleControlDoc(map[string]any{
		"results": []any{},
	})

	result, _, err := ToV2(data)
	require.NoError(t, err)

	req := firstReq(t, result)
	assert.Len(t, req.Descriptions, 0)
}

func TestToV2_PreservesTimestamp(t *testing.T) {
	v1 := map[string]any{
		"profiles": []any{
			map[string]any{
				"name":     "test",
				"controls": []any{},
			},
		},
		"timestamp": "2024-01-01T00:00:00Z",
	}
	data, err := json.Marshal(v1)
	require.NoError(t, err)

	result, _, err := ToV2(data)
	require.NoError(t, err)

	require.NotNil(t, result.Timestamp)
	assert.Equal(t, "2024-01-01T00:00:00Z", result.Timestamp.Format("2006-01-02T15:04:05Z"))
}

func TestToV2_HandlesProfileWithoutSHA256(t *testing.T) {
	v1 := map[string]any{
		"profiles": []any{
			map[string]any{
				"name":     "no-hash",
				"controls": []any{},
			},
		},
	}
	data, err := json.Marshal(v1)
	require.NoError(t, err)

	result, _, err := ToV2(data)
	require.NoError(t, err)

	baseline := result.Baselines[0]
	assert.Empty(t, baseline.Checksum.Value)
}

func TestToV2_HandlesProfileWithNoControls(t *testing.T) {
	v1 := map[string]any{
		"profiles": []any{
			map[string]any{
				"name": "empty-profile",
			},
		},
	}
	data, err := json.Marshal(v1)
	require.NoError(t, err)

	result, _, err := ToV2(data)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements
	assert.Len(t, reqs, 0)
}

func TestToV2_HandlesControlsWithNoTagsOrRefs(t *testing.T) {
	data := v1SingleResultDoc(map[string]any{
		"code_desc":  "test",
		"start_time": "2024-01-01T00:00:00Z",
	})

	result, _, err := ToV2(data)
	require.NoError(t, err)

	req := firstReq(t, result)
	assert.NotNil(t, req.Tags)
	assert.Len(t, req.Tags, 0)
	assert.NotNil(t, req.Refs)
	assert.Len(t, req.Refs, 0)
}

func TestToV2_HandlesCamelCaseResultFieldsInV1(t *testing.T) {
	data := v1SingleResultDoc(map[string]any{
		"status":    "failed",
		"codeDesc":  "already camelCase",
		"runTime":   0.1,
		"startTime": "2024-01-01T00:00:00Z",
	})

	result, _, err := ToV2(data)
	require.NoError(t, err)

	r := firstResult(t, result)
	assert.Equal(t, "already camelCase", r.CodeDesc)
	require.NotNil(t, r.RunTime)
	assert.InDelta(t, 0.1, *r.RunTime, 0.001)
	assert.Equal(t, "2024-01-01T00:00:00Z", r.StartTime.Format("2006-01-02T15:04:05Z"))
}

func TestToV2_HandlesCamelCaseSourceLocationInV1(t *testing.T) {
	data := v1SingleControlDoc(map[string]any{
		"sourceLocation": map[string]any{
			"ref":  "controls/test.rb",
			"line": float64(5),
		},
		"results": []any{},
	})

	result, _, err := ToV2(data)
	require.NoError(t, err)

	req := firstReq(t, result)
	require.NotNil(t, req.SourceLocation.Ref)
	assert.Equal(t, "controls/test.rb", *req.SourceLocation.Ref)
	require.NotNil(t, req.SourceLocation.Line)
	assert.InDelta(t, 5.0, *req.SourceLocation.Line, 0.001)
}

func TestToV2_MapsSkippedToNotReviewed(t *testing.T) {
	data := v1SingleResultDoc(map[string]any{
		"status":     "skipped",
		"code_desc":  "skipped test",
		"start_time": "2024-01-01T00:00:00Z",
	})

	result, _, err := ToV2(data)
	require.NoError(t, err)

	r := firstResult(t, result)
	require.NotNil(t, r.Status)
	assert.Equal(t, "notReviewed", string(*r.Status))
}

func TestToV2_NormalizesNonISOTimestamp(t *testing.T) {
	data := v1SingleResultDoc(map[string]any{
		"code_desc":  "test",
		"start_time": "2017-09-22 14:12:15 -0400",
	})

	result, _, err := ToV2(data)
	require.NoError(t, err)

	r := firstResult(t, result)
	formatted := r.StartTime.Format("2006-01-02T15:04:05Z07:00")
	assert.Contains(t, formatted, "T")
	assert.Equal(t, 2017, r.StartTime.Year())
	assert.Equal(t, 9, int(r.StartTime.Month()))
	assert.Equal(t, 22, r.StartTime.Day())
}

func TestToV2_PreservesValidISOTimestamp(t *testing.T) {
	data := v1SingleResultDoc(map[string]any{
		"code_desc":  "test",
		"start_time": "2024-01-01T00:00:00Z",
	})

	result, _, err := ToV2(data)
	require.NoError(t, err)

	r := firstResult(t, result)
	assert.Equal(t, "2024-01-01T00:00:00Z", r.StartTime.Format("2006-01-02T15:04:05Z"))
}

func TestToV2_UnparseableTimestampBecomesZero(t *testing.T) {
	// Go requires time.Time, so unparseable timestamps become zero value.
	data := v1SingleResultDoc(map[string]any{
		"code_desc":  "test",
		"start_time": "not-a-date",
	})

	result, _, err := ToV2(data)
	require.NoError(t, err)

	r := firstResult(t, result)
	assert.True(t, r.StartTime.IsZero())
}

func TestToV2_HandlesCamelCaseStartTimeOnly(t *testing.T) {
	data := v1SingleResultDoc(map[string]any{
		"codeDesc":  "already camelCase desc",
		"startTime": "2024-06-01T00:00:00Z",
	})

	result, _, err := ToV2(data)
	require.NoError(t, err)

	r := firstResult(t, result)
	assert.Equal(t, "2024-06-01T00:00:00Z", r.StartTime.Format("2006-01-02T15:04:05Z"))
	assert.Equal(t, "already camelCase desc", r.CodeDesc)
}

func TestToV2_EmptyStartTimeBecomesZero(t *testing.T) {
	data := v1SingleResultDoc(map[string]any{
		"code_desc":  "test",
		"start_time": "",
	})

	result, _, err := ToV2(data)
	require.NoError(t, err)

	r := firstResult(t, result)
	assert.True(t, r.StartTime.IsZero())
}

func TestToV2_MissingStartTimeBecomesZero(t *testing.T) {
	data := v1SingleResultDoc(map[string]any{
		"code_desc": "test",
	})

	result, _, err := ToV2(data)
	require.NoError(t, err)

	r := firstResult(t, result)
	assert.True(t, r.StartTime.IsZero())
}

func TestToV2_MissingCodeDescDefaultsToEmpty(t *testing.T) {
	data := v1SingleResultDoc(map[string]any{
		"start_time": "2024-01-01T00:00:00Z",
	})

	result, _, err := ToV2(data)
	require.NoError(t, err)

	r := firstResult(t, result)
	assert.Equal(t, "", r.CodeDesc)
}

func TestToV2_OmitsOptionalFieldsWhenUndefined(t *testing.T) {
	data := v1SingleResultDoc(map[string]any{
		"code_desc":  "test",
		"start_time": "2024-01-01T00:00:00Z",
	})

	result, _, err := ToV2(data)
	require.NoError(t, err)

	r := firstResult(t, result)
	assert.Nil(t, r.RunTime)
	assert.Nil(t, r.Message)
}

// ---------------------------------------------------------------------------
// Coverage: parseTimestamp — all format branches
// ---------------------------------------------------------------------------

func TestParseTimestamp_TableDriven(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantZero  bool
		wantYear  int
		wantMonth int
		wantDay   int
	}{
		{"empty string", "", true, 0, 0, 0},
		{"RFC3339", "2024-06-15T10:30:00Z", false, 2024, 6, 15},
		{"RFC3339Nano", "2024-06-15T10:30:00.123456789Z", false, 2024, 6, 15},
		{"InSpec format with timezone", "2017-09-22 14:12:15 -0400", false, 2017, 9, 22},
		{"date-time without timezone", "2023-03-01 09:00:00", false, 2023, 3, 1},
		{"unparseable", "not-a-date-at-all", true, 0, 0, 0},
		{"T-containing but invalid RFC3339", "2024-13-99T00:00:00Z", true, 0, 0, 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := hdfutil.ParseTimestamp(tc.input)
			if tc.wantZero {
				assert.True(t, result.IsZero(), "expected zero time for %q", tc.input)
			} else {
				assert.False(t, result.IsZero(), "expected non-zero time for %q", tc.input)
				assert.Equal(t, tc.wantYear, result.Year())
				assert.Equal(t, tc.wantMonth, int(result.Month()))
				assert.Equal(t, tc.wantDay, result.Day())
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Coverage: normalizeGroups — with valid groups and non-map entries
// ---------------------------------------------------------------------------

func TestNormalizeGroups_WithValidGroups(t *testing.T) {
	title := "Group Title"
	profile := map[string]any{
		"groups": []any{
			map[string]any{"id": "G-001", "title": title},
			map[string]any{"id": "G-002"},
		},
	}
	groups := normalizeGroups(profile)
	require.Len(t, groups, 2)
	assert.Equal(t, "G-001", groups[0].ID)
	assert.NotNil(t, groups[0].Title)
	assert.Equal(t, "Group Title", *groups[0].Title)
	assert.Equal(t, "G-002", groups[1].ID)
	assert.Nil(t, groups[1].Title)
}

func TestNormalizeGroups_NoGroupsKey(t *testing.T) {
	profile := map[string]any{}
	groups := normalizeGroups(profile)
	assert.Len(t, groups, 0)
}

func TestNormalizeGroups_GroupsNotArray(t *testing.T) {
	profile := map[string]any{"groups": "not-an-array"}
	groups := normalizeGroups(profile)
	assert.Len(t, groups, 0)
}

func TestNormalizeGroups_NonMapEntry(t *testing.T) {
	profile := map[string]any{
		"groups": []any{
			"not-a-map",
			map[string]any{"id": "G-001"},
		},
	}
	groups := normalizeGroups(profile)
	assert.Len(t, groups, 1)
	assert.Equal(t, "G-001", groups[0].ID)
}

// ---------------------------------------------------------------------------
// Coverage: normalizeSupports — with valid entries, non-map items, empty
// ---------------------------------------------------------------------------

func TestNormalizeSupports_WithValidSupports(t *testing.T) {
	profile := map[string]any{
		"supports": []any{
			map[string]any{"platform": "linux", "platformName": "ubuntu"},
			map[string]any{"platform": "windows"},
		},
	}
	supports := normalizeSupports(profile)
	require.Len(t, supports, 2)
	assert.NotNil(t, supports[0].Platform)
	assert.Equal(t, "linux", *supports[0].Platform)
	assert.NotNil(t, supports[0].PlatformName)
	assert.Equal(t, "ubuntu", *supports[0].PlatformName)
	assert.NotNil(t, supports[1].Platform)
	assert.Equal(t, "windows", *supports[1].Platform)
	assert.Nil(t, supports[1].PlatformName)
}

func TestNormalizeSupports_NoSupportsKey(t *testing.T) {
	profile := map[string]any{}
	supports := normalizeSupports(profile)
	assert.Len(t, supports, 0)
}

func TestNormalizeSupports_SupportsNotArray(t *testing.T) {
	profile := map[string]any{"supports": 42}
	supports := normalizeSupports(profile)
	assert.Len(t, supports, 0)
}

func TestNormalizeSupports_NonMapEntry(t *testing.T) {
	profile := map[string]any{
		"supports": []any{
			123,
			map[string]any{"platform": "centos"},
		},
	}
	supports := normalizeSupports(profile)
	assert.Len(t, supports, 1)
}

// ---------------------------------------------------------------------------
// Coverage: normalizeInputs — with valid attrs, non-map items
// ---------------------------------------------------------------------------

func TestNormalizeInputs_WithValidAttrs(t *testing.T) {
	profile := map[string]any{
		"attributes": []any{
			map[string]any{"name": "attr1", "options": map[string]any{"type": "string"}},
			map[string]any{"name": "attr2"},
		},
	}
	attrs := normalizeInputs(profile)
	require.Len(t, attrs, 2)
	assert.Equal(t, "attr1", attrs[0]["name"])
	assert.Equal(t, "attr2", attrs[1]["name"])
}

func TestNormalizeInputs_NoAttrsKey(t *testing.T) {
	profile := map[string]any{}
	attrs := normalizeInputs(profile)
	assert.Len(t, attrs, 0)
}

func TestNormalizeInputs_AttrsNotArray(t *testing.T) {
	profile := map[string]any{"attributes": "nope"}
	attrs := normalizeInputs(profile)
	assert.Len(t, attrs, 0)
}

func TestNormalizeInputs_NonMapEntry(t *testing.T) {
	profile := map[string]any{
		"attributes": []any{
			"not-a-map",
			map[string]any{"name": "real-attr"},
		},
	}
	attrs := normalizeInputs(profile)
	assert.Len(t, attrs, 1)
}

// ---------------------------------------------------------------------------
// Coverage: getString / getFloat — missing key and wrong type
// ---------------------------------------------------------------------------

func TestGetString_MissingKey(t *testing.T) {
	m := map[string]any{}
	assert.Equal(t, "", getString(m, "missing"))
}

func TestGetString_WrongType(t *testing.T) {
	m := map[string]any{"key": 42}
	assert.Equal(t, "", getString(m, "key"))
}

func TestGetString_ValidString(t *testing.T) {
	m := map[string]any{"key": "value"}
	assert.Equal(t, "value", getString(m, "key"))
}

func TestGetFloat_MissingKey(t *testing.T) {
	m := map[string]any{}
	assert.Equal(t, 0.0, getFloat(m, "missing"))
}

func TestGetFloat_WrongType(t *testing.T) {
	m := map[string]any{"key": "not-a-float"}
	assert.Equal(t, 0.0, getFloat(m, "key"))
}

func TestGetFloat_ValidFloat(t *testing.T) {
	m := map[string]any{"key": 3.14}
	assert.InDelta(t, 3.14, getFloat(m, "key"), 0.001)
}

// ---------------------------------------------------------------------------
// Coverage: getFloatOptional
// ---------------------------------------------------------------------------

func TestGetFloatOptional_Present(t *testing.T) {
	m := map[string]any{"rt": 0.05}
	v, ok := getFloatOptional(m, "rt")
	assert.True(t, ok)
	assert.InDelta(t, 0.05, v, 0.001)
}

func TestGetFloatOptional_Missing(t *testing.T) {
	m := map[string]any{}
	_, ok := getFloatOptional(m, "rt")
	assert.False(t, ok)
}

func TestGetFloatOptional_WrongType(t *testing.T) {
	m := map[string]any{"rt": "string"}
	_, ok := getFloatOptional(m, "rt")
	assert.False(t, ok)
}

// ---------------------------------------------------------------------------
// Coverage: getStringFallback
// ---------------------------------------------------------------------------

func TestGetStringFallback_SnakeCasePresent(t *testing.T) {
	m := map[string]any{"code_desc": "snake"}
	assert.Equal(t, "snake", getStringFallback(m, "code_desc", "codeDesc"))
}

func TestGetStringFallback_CamelCasePresent(t *testing.T) {
	m := map[string]any{"codeDesc": "camel"}
	assert.Equal(t, "camel", getStringFallback(m, "code_desc", "codeDesc"))
}

func TestGetStringFallback_NeitherPresent(t *testing.T) {
	m := map[string]any{}
	assert.Equal(t, "", getStringFallback(m, "code_desc", "codeDesc"))
}

// ---------------------------------------------------------------------------
// Coverage: normalizeControl — code field, no tags, no desc
// ---------------------------------------------------------------------------

func TestNormalizeControl_WithCodeField(t *testing.T) {
	data := v1SingleControlDoc(map[string]any{
		"code":    "describe file('/etc/ssh') do\n  it { should exist }\nend",
		"results": []any{},
	})

	result, _, err := ToV2(data)
	require.NoError(t, err)

	req := firstReq(t, result)
	require.NotNil(t, req.Code)
	assert.Contains(t, *req.Code, "describe file")
}

func TestNormalizeControl_WithTags(t *testing.T) {
	data := v1SingleControlDoc(map[string]any{
		"tags":    map[string]any{"cci": []any{"CCI-000366"}, "nist": []any{"AC-1"}},
		"results": []any{},
	})

	result, _, err := ToV2(data)
	require.NoError(t, err)

	req := firstReq(t, result)
	assert.NotNil(t, req.Tags)
	assert.Contains(t, req.Tags, "cci")
	assert.Contains(t, req.Tags, "nist")
}

func TestNormalizeControl_WithTitle(t *testing.T) {
	data := v1SingleControlDoc(map[string]any{
		"title":   "My Control Title",
		"results": []any{},
	})

	result, _, err := ToV2(data)
	require.NoError(t, err)

	req := firstReq(t, result)
	require.NotNil(t, req.Title)
	assert.Equal(t, "My Control Title", *req.Title)
}

func TestNormalizeControl_WithMessage(t *testing.T) {
	data := v1SingleResultDoc(map[string]any{
		"status":     "failed",
		"code_desc":  "test",
		"start_time": "2024-01-01T00:00:00Z",
		"message":    "expected file to exist but it was missing",
	})

	result, _, err := ToV2(data)
	require.NoError(t, err)

	r := firstResult(t, result)
	require.NotNil(t, r.Message)
	assert.Equal(t, "expected file to exist but it was missing", *r.Message)
}

// ---------------------------------------------------------------------------
// Coverage: IsV1Format — profiles is not an array
// ---------------------------------------------------------------------------

func TestIsV1Format_ProfilesNotArray(t *testing.T) {
	data := map[string]any{
		"profiles": "not-an-array",
	}
	assert.False(t, IsV1Format(data))
}

// ---------------------------------------------------------------------------
// Coverage: ToV2 — invalid JSON
// ---------------------------------------------------------------------------

func TestToV2_InvalidJSON(t *testing.T) {
	_, _, err := ToV2([]byte("{invalid"))
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// Coverage: ToV2 — v1 with non-map profile entry (skipped)
// ---------------------------------------------------------------------------

func TestToV2_NonMapProfileEntrySkipped(t *testing.T) {
	v1 := map[string]any{
		"profiles": []any{
			"not-a-map",
			map[string]any{
				"name":     "valid",
				"controls": []any{},
			},
		},
	}
	data, err := json.Marshal(v1)
	require.NoError(t, err)

	result, warnings, err := ToV2(data)
	require.NoError(t, err)

	// Only the valid profile should be present
	assert.Len(t, result.Baselines, 1)
	assert.Equal(t, "valid", result.Baselines[0].Name)

	// Should have a warning about the skipped profile
	assert.Len(t, warnings, 1)
	assert.Contains(t, warnings[0], "skipped profile at index 0")
}

// ---------------------------------------------------------------------------
// Coverage: normalizeControl — non-map control entry skipped, non-map result skipped
// ---------------------------------------------------------------------------

func TestToV2_NonMapControlEntrySkipped(t *testing.T) {
	v1 := map[string]any{
		"profiles": []any{
			map[string]any{
				"name": "test",
				"controls": []any{
					"not-a-map",
					map[string]any{
						"id":     "V-001",
						"impact": 0.7,
						"tags":   map[string]any{},
					},
				},
			},
		},
	}
	data, err := json.Marshal(v1)
	require.NoError(t, err)

	result, warnings, err := ToV2(data)
	require.NoError(t, err)

	assert.Len(t, result.Baselines[0].Requirements, 1)
	assert.Equal(t, "V-001", result.Baselines[0].Requirements[0].ID)

	// Should have a warning about the skipped control
	assert.Len(t, warnings, 1)
	assert.Contains(t, warnings[0], "skipped control at index 0")
}

func TestToV2_NonMapResultEntrySkipped(t *testing.T) {
	v1 := map[string]any{
		"profiles": []any{
			map[string]any{
				"name": "test",
				"controls": []any{
					map[string]any{
						"id":     "V-001",
						"impact": 0.7,
						"tags":   map[string]any{},
						"results": []any{
							"not-a-map",
							map[string]any{
								"status":     "passed",
								"code_desc":  "test",
								"start_time": "2024-01-01T00:00:00Z",
							},
						},
					},
				},
			},
		},
	}
	data, err := json.Marshal(v1)
	require.NoError(t, err)

	result, _, err := ToV2(data)
	require.NoError(t, err)

	assert.Len(t, result.Baselines[0].Requirements[0].Results, 1)
}

// ---------------------------------------------------------------------------
// Coverage: normalizeResultStatus — non-skipped status pass-through
// ---------------------------------------------------------------------------

func TestNormalizeResultStatus_Passed(t *testing.T) {
	assert.Equal(t, "passed", normalizeResultStatus("passed"))
}

func TestNormalizeResultStatus_Failed(t *testing.T) {
	assert.Equal(t, "failed", normalizeResultStatus("failed"))
}

// ---------------------------------------------------------------------------
// Coverage: normalizeRefs — with actual refs
// ---------------------------------------------------------------------------

func TestToV2_WithRefs_MapFormat(t *testing.T) {
	data := v1SingleControlDoc(map[string]any{
		"refs":    []any{map[string]any{"ref": "some-ref"}},
		"results": []any{},
	})

	result, _, err := ToV2(data)
	require.NoError(t, err)

	req := firstReq(t, result)
	assert.Len(t, req.Refs, 1)
	// The ref value should be preserved from the v1 {"ref": "some-ref"} format
	require.NotNil(t, req.Refs[0].Ref)
	require.NotNil(t, req.Refs[0].Ref.String)
	assert.Equal(t, "some-ref", *req.Refs[0].Ref.String)
}

func TestToV2_WithRefs_StringFormat(t *testing.T) {
	data := v1SingleControlDoc(map[string]any{
		"refs":    []any{"plain-string-ref"},
		"results": []any{},
	})

	result, _, err := ToV2(data)
	require.NoError(t, err)

	req := firstReq(t, result)
	assert.Len(t, req.Refs, 1)
	// Plain string refs should be preserved
	require.NotNil(t, req.Refs[0].Ref)
	require.NotNil(t, req.Refs[0].Ref.String)
	assert.Equal(t, "plain-string-ref", *req.Refs[0].Ref.String)
}

func TestToV2_WithRefs_URLFormat(t *testing.T) {
	data := v1SingleControlDoc(map[string]any{
		"refs":    []any{map[string]any{"url": "https://example.com"}},
		"results": []any{},
	})

	result, _, err := ToV2(data)
	require.NoError(t, err)

	req := firstReq(t, result)
	assert.Len(t, req.Refs, 1)
	require.NotNil(t, req.Refs[0].URL)
	assert.Equal(t, "https://example.com", *req.Refs[0].URL)
}

// ---------------------------------------------------------------------------
// Coverage: normalizeSourceLocation — no source_location at all
// ---------------------------------------------------------------------------

func TestNormalizeSourceLocation_NoKey(t *testing.T) {
	control := map[string]any{}
	sl := normalizeSourceLocation(control)
	assert.Nil(t, sl.Ref)
	assert.Nil(t, sl.Line)
}

// ---------------------------------------------------------------------------
// Coverage: ToV2 — timestamp that is unparseable (empty after parse)
// ---------------------------------------------------------------------------

func TestToV2_EmptyTimestamp(t *testing.T) {
	v1 := map[string]any{
		"profiles": []any{
			map[string]any{
				"name":     "test",
				"controls": []any{},
			},
		},
		"timestamp": "",
	}
	data, err := json.Marshal(v1)
	require.NoError(t, err)

	result, _, err := ToV2(data)
	require.NoError(t, err)

	// Empty timestamp should leave Timestamp as nil
	assert.Nil(t, result.Timestamp)
}

// ---------------------------------------------------------------------------
// Coverage: ToV2 — v1 with statistics but no duration
// ---------------------------------------------------------------------------

func TestToV2_StatisticsNoDuration(t *testing.T) {
	v1 := map[string]any{
		"profiles": []any{
			map[string]any{
				"name":     "test",
				"controls": []any{},
			},
		},
		"statistics": map[string]any{},
	}
	data, err := json.Marshal(v1)
	require.NoError(t, err)

	result, _, err := ToV2(data)
	require.NoError(t, err)
	assert.Nil(t, result.Statistics.Duration)
}

// ---------------------------------------------------------------------------
// Coverage: ToV2 — runTime via camelCase fallback
// ---------------------------------------------------------------------------

func TestToV2_RunTimeCamelCaseFallback(t *testing.T) {
	data := v1SingleResultDoc(map[string]any{
		"status":     "passed",
		"code_desc":  "test",
		"start_time": "2024-01-01T00:00:00Z",
		"runTime":    0.25,
	})

	result, _, err := ToV2(data)
	require.NoError(t, err)

	r := firstResult(t, result)
	require.NotNil(t, r.RunTime)
	assert.InDelta(t, 0.25, *r.RunTime, 0.001)
}
