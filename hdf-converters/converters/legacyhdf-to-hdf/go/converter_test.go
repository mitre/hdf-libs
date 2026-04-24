package legacyhdf

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// getFixturesDir returns the path to the fixtures directory
func getFixturesDir() string {
	_, filename, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(filename), "..", "fixtures")
}

// getOutputDir returns the path to the test output directory
func getOutputDir() string {
	_, filename, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(filename), "..", "..", "..", "test-output", "differential", "go", "legacyhdf")
}

func TestConvertV1ToV2_Minimal(t *testing.T) {
	inputPath := filepath.Join(getFixturesDir(), "input", "minimal.json")

	// Load input
	inputData, err := os.ReadFile(inputPath)
	require.NoError(t, err, "Failed to read input file")

	var v1 HDFV1Results
	err = json.Unmarshal(inputData, &v1)
	require.NoError(t, err, "Failed to unmarshal input")

	// Convert
	v2 := ConvertV1ToV2(&v1)

	// Write output for differential testing
	outputDir := getOutputDir()
	err = os.MkdirAll(outputDir, 0755)
	require.NoError(t, err, "Failed to create output directory")

	outputData, err := json.MarshalIndent(v2, "", "  ")
	require.NoError(t, err, "Failed to marshal output")

	err = os.WriteFile(filepath.Join(outputDir, "minimal.json"), outputData, 0644)
	require.NoError(t, err, "Failed to write output file")

	// Basic structural checks
	require.NotNil(t, v2.Baselines)
	require.NotNil(t, v2.Components)
	assert.Len(t, v2.Components, 1)
	assert.Equal(t, hdf.Host, v2.Components[0].Type)
}

func TestConvertV1ToV2_Tool(t *testing.T) {
	inputPath := filepath.Join(getFixturesDir(), "input", "minimal.json")
	inputData, err := os.ReadFile(inputPath)
	require.NoError(t, err)

	var v1 HDFV1Results
	err = json.Unmarshal(inputData, &v1)
	require.NoError(t, err)

	v2 := ConvertV1ToV2(&v1)

	require.NotNil(t, v2.Tool)
	require.NotNil(t, v2.Tool.Name)
	assert.Equal(t, "Heimdall Data Format v1", *v2.Tool.Name)
	assert.Nil(t, v2.Tool.Version)
	assert.Nil(t, v2.Tool.Format)
}

func TestConvertV1ToV2_ContainerScan(t *testing.T) {
	inputPath := filepath.Join(getFixturesDir(), "input", "container-scan.json")

	// Load input
	inputData, err := os.ReadFile(inputPath)
	require.NoError(t, err, "Failed to read input file")

	var v1 HDFV1Results
	err = json.Unmarshal(inputData, &v1)
	require.NoError(t, err, "Failed to unmarshal input")

	// Convert
	v2 := ConvertV1ToV2(&v1)

	// Write output for differential testing
	outputDir := getOutputDir()
	err = os.MkdirAll(outputDir, 0755)
	require.NoError(t, err, "Failed to create output directory")

	outputData, err := json.MarshalIndent(v2, "", "  ")
	require.NoError(t, err, "Failed to marshal output")

	err = os.WriteFile(filepath.Join(outputDir, "container-scan.json"), outputData, 0644)
	require.NoError(t, err, "Failed to write output file")

	// Basic structural checks
	require.NotNil(t, v2.Baselines)
	require.NotNil(t, v2.Components)
}

func TestConvertV1ToV2_Wrapper(t *testing.T) {
	inputPath := filepath.Join(getFixturesDir(), "input", "wrapper.json")

	// Load input
	inputData, err := os.ReadFile(inputPath)
	require.NoError(t, err, "Failed to read input file")

	var v1 HDFV1Results
	err = json.Unmarshal(inputData, &v1)
	require.NoError(t, err, "Failed to unmarshal input")

	// Convert
	v2 := ConvertV1ToV2(&v1)

	// Write output for differential testing
	outputDir := getOutputDir()
	err = os.MkdirAll(outputDir, 0755)
	require.NoError(t, err, "Failed to create output directory")

	outputData, err := json.MarshalIndent(v2, "", "  ")
	require.NoError(t, err, "Failed to marshal output")

	err = os.WriteFile(filepath.Join(outputDir, "wrapper.json"), outputData, 0644)
	require.NoError(t, err, "Failed to write output file")

	// Basic structural checks
	require.NotNil(t, v2.Baselines)
	require.NotNil(t, v2.Components)
}

func TestIsHDFV1(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{
			name:     "valid v1.0",
			input:    `{"version": "1.0.0", "profiles": [], "platform": {"name": "test"}}`,
			expected: true,
		},
		{
			name:     "missing version",
			input:    `{"profiles": [], "platform": {"name": "test"}}`,
			expected: false,
		},
		{
			name:     "missing profiles",
			input:    `{"version": "1.0.0", "platform": {"name": "test"}}`,
			expected: false,
		},
		{
			name:     "missing platform",
			input:    `{"version": "1.0.0", "profiles": []}`,
			expected: false,
		},
		{
			name:     "version not string",
			input:    `{"version": 1, "profiles": [], "platform": {"name": "test"}}`,
			expected: false,
		},
		{
			name:     "profiles not array",
			input:    `{"version": "1.0.0", "profiles": {}, "platform": {"name": "test"}}`,
			expected: false,
		},
		{
			name:     "platform not object",
			input:    `{"version": "1.0.0", "profiles": [], "platform": "test"}`,
			expected: false,
		},
		{
			name:     "invalid json",
			input:    `not json`,
			expected: false,
		},
		{
			name:     "v2.0 format (has baselines instead of profiles)",
			input:    `{"baselines": [], "statistics": {}}`,
			expected: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := IsHDFV1([]byte(tc.input))
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestNormalizeStatus(t *testing.T) {
	tests := []struct {
		input    string
		expected hdf.ResultStatus
	}{
		{"passed", hdf.Passed},
		{"failed", hdf.Failed},
		{"error", hdf.Error},
		{"not_applicable", hdf.NotApplicable},
		{"not_reviewed", hdf.NotReviewed},
		{"skipped", hdf.NotReviewed},
		{"unknown_status", hdf.NotReviewed}, // unmapped statuses default to notReviewed
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			result := normalizeStatus(tc.input)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestIsHDFV1FromMap(t *testing.T) {
	tests := []struct {
		name     string
		input    map[string]interface{}
		expected bool
	}{
		{
			name: "valid v1.0",
			input: map[string]interface{}{
				"version":  "1.0.0",
				"profiles": []interface{}{},
				"platform": map[string]interface{}{"name": "test"},
			},
			expected: true,
		},
		{
			name: "missing version",
			input: map[string]interface{}{
				"profiles": []interface{}{},
				"platform": map[string]interface{}{"name": "test"},
			},
			expected: false,
		},
		{
			name: "missing profiles",
			input: map[string]interface{}{
				"version":  "1.0.0",
				"platform": map[string]interface{}{"name": "test"},
			},
			expected: false,
		},
		{
			name: "missing platform",
			input: map[string]interface{}{
				"version":  "1.0.0",
				"profiles": []interface{}{},
			},
			expected: false,
		},
		{
			name: "version not string",
			input: map[string]interface{}{
				"version":  1,
				"profiles": []interface{}{},
				"platform": map[string]interface{}{"name": "test"},
			},
			expected: false,
		},
		{
			name: "profiles not array",
			input: map[string]interface{}{
				"version":  "1.0.0",
				"profiles": map[string]interface{}{},
				"platform": map[string]interface{}{"name": "test"},
			},
			expected: false,
		},
		{
			name: "platform not object",
			input: map[string]interface{}{
				"version":  "1.0.0",
				"profiles": []interface{}{},
				"platform": "test",
			},
			expected: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := IsHDFV1FromMap(tc.input)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestConvertV1ToV2_WithNilProfiles(t *testing.T) {
	v1 := &HDFV1Results{
		Version: "1.0.0",
		Platform: V1Platform{
			Name: "test-system",
		},
		Profiles:   nil,
		Statistics: V1Statistics{},
	}

	v2 := ConvertV1ToV2(v1)

	// Should handle nil profiles
	require.NotNil(t, v2.Baselines)
	assert.Len(t, v2.Baselines, 0)

	// Should have targets
	require.Len(t, v2.Components, 1)
	assert.Equal(t, hdf.Host, v2.Components[0].Type)
	assert.Equal(t, "test-system", v2.Components[0].Name)
}

func TestConvertResult_AllOptionalFields(t *testing.T) {
	codeDesc := "Test code description"
	runTime := 1.5
	startTime := "2024-01-01T00:00:00Z"
	message := "Test message"
	exception := "Test exception"
	backtrace := []string{"line1", "line2"}
	resourceClass := "File"
	resourceID := "res-123"

	v1 := V1Result{
		Status:        "passed",
		CodeDesc:      &codeDesc,
		RunTime:       &runTime,
		StartTime:     &startTime,
		Message:       &message,
		Exception:     &exception,
		Backtrace:     backtrace,
		ResourceClass: &resourceClass,
		ResourceID:    &resourceID,
	}

	v2 := convertResult(v1)

	assert.Equal(t, hdf.Passed, v2.Status)
	assert.Equal(t, codeDesc, v2.CodeDesc)
	require.NotNil(t, v2.RunTime)
	assert.Equal(t, runTime, *v2.RunTime)
	require.NotNil(t, v2.Message)
	assert.Equal(t, message, *v2.Message)
	require.NotNil(t, v2.Exception)
	assert.Equal(t, exception, *v2.Exception)
	assert.NotNil(t, v2.Backtrace)
	require.NotNil(t, v2.Resource)
	assert.Equal(t, resourceClass, *v2.Resource)
	require.NotNil(t, v2.ResourceID)
	assert.Equal(t, resourceID, *v2.ResourceID)
}

func TestConvertDependency_AllFields(t *testing.T) {
	name := "dep-name"
	url := "https://example.com"
	path := "/path/to/dep"
	git := "git@github.com:example/repo.git"
	branch := "main"
	supermarket := "supermarket-id"
	compliance := "compliance-id"
	status := "loaded"

	v1 := V1Dependency{
		Name:        &name,
		URL:         &url,
		Path:        &path,
		Git:         &git,
		Branch:      &branch,
		Supermarket: &supermarket,
		Compliance:  &compliance,
		Status:      &status,
	}

	v2 := convertDependency(v1)

	require.NotNil(t, v2.Name)
	assert.Equal(t, name, *v2.Name)
	require.NotNil(t, v2.URL)
	assert.Equal(t, url, *v2.URL)
	require.NotNil(t, v2.Path)
	assert.Equal(t, path, *v2.Path)
	require.NotNil(t, v2.Git)
	assert.Equal(t, git, *v2.Git)
	require.NotNil(t, v2.Branch)
	assert.Equal(t, branch, *v2.Branch)
	require.NotNil(t, v2.Supermarket)
	assert.Equal(t, supermarket, *v2.Supermarket)
	require.NotNil(t, v2.Compliance)
	assert.Equal(t, compliance, *v2.Compliance)
	require.NotNil(t, v2.Status)
	assert.Equal(t, status, *v2.Status)
}

func TestConvertGroup_WithTitle(t *testing.T) {
	title := "Test Group Title"
	v1 := V1Group{
		ID:       "group-1",
		Title:    &title,
		Controls: []string{"ctrl-1", "ctrl-2"},
	}

	v2 := convertGroup(v1)

	assert.Equal(t, "group-1", v2.ID)
	require.NotNil(t, v2.Title)
	assert.Equal(t, title, *v2.Title)
	assert.Equal(t, []string{"ctrl-1", "ctrl-2"}, v2.Requirements)
}

func TestConvertProfile_AllOptionalFields(t *testing.T) {
	version := "1.0.0"
	title := "Test Profile"
	maintainer := "Test Author"
	summary := "Test summary"
	license := "Apache-2.0"
	copyright := "2024"
	copyrightEmail := "test@example.com"
	sha256 := "abc123def456"
	parentProfile := "parent-profile"
	status := "loaded"
	statusMessage := "Loaded successfully"
	groupTitle := "Group Title"

	v1 := V1Profile{
		Name:           "test-profile",
		Version:        &version,
		Title:          &title,
		Maintainer:     &maintainer,
		Summary:        &summary,
		License:        &license,
		Copyright:      &copyright,
		CopyrightEmail: &copyrightEmail,
		Groups: []V1Group{
			{ID: "group-1", Title: &groupTitle, Controls: []string{"ctrl-1"}},
		},
		Controls: []V1Control{
			{ID: "ctrl-1", Impact: 0.5},
		},
		SHA256:        &sha256,
		Depends:       []V1Dependency{{Name: &maintainer}},
		ParentProfile: &parentProfile,
		Status:        &status,
		StatusMessage: &statusMessage,
	}

	v2 := convertProfile(v1)

	assert.Equal(t, "test-profile", v2.Name)
	require.NotNil(t, v2.Version)
	assert.Equal(t, version, *v2.Version)
	require.NotNil(t, v2.Title)
	assert.Equal(t, title, *v2.Title)
	require.NotNil(t, v2.Maintainer)
	assert.Equal(t, maintainer, *v2.Maintainer)
	require.NotNil(t, v2.Summary)
	assert.Equal(t, summary, *v2.Summary)
	require.NotNil(t, v2.License)
	assert.Equal(t, license, *v2.License)
	require.NotNil(t, v2.Copyright)
	assert.Equal(t, copyright, *v2.Copyright)
	require.NotNil(t, v2.CopyrightEmail)
	assert.Equal(t, copyrightEmail, *v2.CopyrightEmail)
	assert.Equal(t, hdf.Sha256, *v2.Integrity.Algorithm)
	assert.Equal(t, sha256, *v2.Integrity.Checksum)
	require.NotNil(t, v2.ParentBaseline)
	assert.Equal(t, parentProfile, *v2.ParentBaseline)
	require.NotNil(t, v2.Status)
	assert.Equal(t, status, *v2.Status)
	require.NotNil(t, v2.StatusMessage)
	assert.Equal(t, statusMessage, *v2.StatusMessage)
	require.Len(t, v2.Groups, 1)
	require.Len(t, v2.Requirements, 1)
	require.Len(t, v2.Depends, 1)
}

// ── Overlay flattening integration tests ──────────────────

func TestConvertV1ToV2_DeepOverlayFlatten(t *testing.T) {
	inputPath := filepath.Join(getFixturesDir(), "input", "three-layer-overlay.json")
	inputData, err := os.ReadFile(inputPath)
	require.NoError(t, err)

	var v1 HDFV1Results
	require.NoError(t, json.Unmarshal(inputData, &v1))
	require.Len(t, v1.Profiles, 3, "fixture should have 3 profiles before conversion")

	v2 := ConvertV1ToV2(&v1)

	t.Run("flattens 3 profiles into 1 baseline", func(t *testing.T) {
		assert.Len(t, v2.Baselines, 1)
	})

	t.Run("produces 247 deduplicated requirements", func(t *testing.T) {
		assert.Len(t, v2.Baselines[0].Requirements, 247)
	})

	t.Run("every requirement has results from base profile", func(t *testing.T) {
		withResults := 0
		for _, r := range v2.Baselines[0].Requirements {
			if len(r.Results) > 0 {
				withResults++
			}
		}
		assert.Equal(t, 247, withResults)
	})

	t.Run("parentBaseline cleared on output", func(t *testing.T) {
		assert.Nil(t, v2.Baselines[0].ParentBaseline)
	})

	t.Run("uses top overlay name as baseline name", func(t *testing.T) {
		assert.Contains(t, v2.Baselines[0].Name, "second-layer")
	})
}

func TestConvertV1ToV2_WideWrapperFlatten(t *testing.T) {
	inputPath := filepath.Join(getFixturesDir(), "input", "wrapper.json")
	inputData, err := os.ReadFile(inputPath)
	require.NoError(t, err)

	var v1 HDFV1Results
	require.NoError(t, json.Unmarshal(inputData, &v1))
	require.Len(t, v1.Profiles, 4, "fixture should have 4 profiles before conversion")

	v2 := ConvertV1ToV2(&v1)

	t.Run("flattens 4 profiles into 1 baseline", func(t *testing.T) {
		assert.Len(t, v2.Baselines, 1)
	})

	t.Run("produces 534 aggregated requirements", func(t *testing.T) {
		assert.Len(t, v2.Baselines[0].Requirements, 534)
	})

	t.Run("uses wrapper name as baseline name", func(t *testing.T) {
		assert.Equal(t, "wrapper", v2.Baselines[0].Name)
	})
}

func TestConvertV1ToV2_PassthroughNoOverlays(t *testing.T) {
	v1 := &HDFV1Results{
		Version:  "1.0.0",
		Platform: V1Platform{Name: "test"},
		Profiles: []V1Profile{{
			Name: "simple-profile",
			Controls: []V1Control{{
				ID:      "V-1",
				Impact:  0.5,
				Results: []V1Result{{Status: "passed"}},
			}},
		}},
	}

	v2 := ConvertV1ToV2(v1)

	t.Run("single profile passes through as single baseline", func(t *testing.T) {
		assert.Len(t, v2.Baselines, 1)
		assert.Equal(t, "simple-profile", v2.Baselines[0].Name)
		assert.Len(t, v2.Baselines[0].Requirements, 1)
	})
}

func TestConvertV1ToV2_ImpactZeroNotApplicable(t *testing.T) {
	t.Run("sets effectiveStatus to notApplicable when impact is 0 and no explicit status", func(t *testing.T) {
		v1 := &HDFV1Results{
			Version:  "1.0.0",
			Platform: V1Platform{Name: "test"},
			Profiles: []V1Profile{{
				Name: "test",
				Controls: []V1Control{
					{ID: "V-1", Impact: 0, Results: []V1Result{{Status: "skipped"}}},
					{ID: "V-2", Impact: 0.7, Results: []V1Result{{Status: "passed"}}},
				},
			}},
		}
		v2 := ConvertV1ToV2(v1)
		reqs := v2.Baselines[0].Requirements

		require.NotNil(t, reqs[0].EffectiveStatus)
		assert.Equal(t, hdf.NotApplicable, *reqs[0].EffectiveStatus)
		require.NotNil(t, reqs[1].EffectiveStatus)
		assert.Equal(t, hdf.Passed, *reqs[1].EffectiveStatus) // derived from results
	})

	t.Run("does not override explicit effectiveStatus even if impact is 0", func(t *testing.T) {
		passed := "passed"
		v1 := &HDFV1Results{
			Version:  "1.0.0",
			Platform: V1Platform{Name: "test"},
			Profiles: []V1Profile{{
				Name: "test",
				Controls: []V1Control{
					{ID: "V-1", Impact: 0, Status: &passed, Results: []V1Result{{Status: "passed"}}},
				},
			}},
		}
		v2 := ConvertV1ToV2(v1)
		require.NotNil(t, v2.Baselines[0].Requirements[0].EffectiveStatus)
		assert.Equal(t, hdf.Passed, *v2.Baselines[0].Requirements[0].EffectiveStatus)
	})

	t.Run("classifies 27 impact-0 controls as notApplicable in Three_Layer fixture", func(t *testing.T) {
		inputPath := filepath.Join(getFixturesDir(), "input", "three-layer-overlay.json")
		inputData, err := os.ReadFile(inputPath)
		require.NoError(t, err)

		var v1 HDFV1Results
		require.NoError(t, json.Unmarshal(inputData, &v1))

		v2 := ConvertV1ToV2(&v1)
		reqs := v2.Baselines[0].Requirements

		notApplicable := 0
		for _, r := range reqs {
			if r.EffectiveStatus != nil && *r.EffectiveStatus == hdf.NotApplicable {
				assert.Equal(t, 0.0, r.Impact)
				notApplicable++
			}
		}
		assert.Equal(t, 27, notApplicable)
	})
}

func TestConvertV1ToV2_AlwaysComputeEffectiveStatus(t *testing.T) {
	t.Run("passed when all results passed", func(t *testing.T) {
		v1 := &HDFV1Results{
			Version:  "1.0.0",
			Platform: V1Platform{Name: "test"},
			Profiles: []V1Profile{{
				Name:     "test",
				Controls: []V1Control{{ID: "V-1", Impact: 0.7, Results: []V1Result{{Status: "passed"}}}},
			}},
		}
		v2 := ConvertV1ToV2(v1)
		require.NotNil(t, v2.Baselines[0].Requirements[0].EffectiveStatus)
		assert.Equal(t, hdf.Passed, *v2.Baselines[0].Requirements[0].EffectiveStatus)
	})

	t.Run("failed when any result failed", func(t *testing.T) {
		v1 := &HDFV1Results{
			Version:  "1.0.0",
			Platform: V1Platform{Name: "test"},
			Profiles: []V1Profile{{
				Name:     "test",
				Controls: []V1Control{{ID: "V-1", Impact: 0.7, Results: []V1Result{{Status: "passed"}, {Status: "failed"}}}},
			}},
		}
		v2 := ConvertV1ToV2(v1)
		require.NotNil(t, v2.Baselines[0].Requirements[0].EffectiveStatus)
		assert.Equal(t, hdf.Failed, *v2.Baselines[0].Requirements[0].EffectiveStatus)
	})

	t.Run("passed when mixed passed and skipped", func(t *testing.T) {
		v1 := &HDFV1Results{
			Version:  "1.0.0",
			Platform: V1Platform{Name: "test"},
			Profiles: []V1Profile{{
				Name:     "test",
				Controls: []V1Control{{ID: "V-1", Impact: 0.7, Results: []V1Result{{Status: "skipped"}, {Status: "passed"}}}},
			}},
		}
		v2 := ConvertV1ToV2(v1)
		require.NotNil(t, v2.Baselines[0].Requirements[0].EffectiveStatus)
		assert.Equal(t, hdf.Passed, *v2.Baselines[0].Requirements[0].EffectiveStatus)
	})

	t.Run("notReviewed when all results skipped", func(t *testing.T) {
		v1 := &HDFV1Results{
			Version:  "1.0.0",
			Platform: V1Platform{Name: "test"},
			Profiles: []V1Profile{{
				Name:     "test",
				Controls: []V1Control{{ID: "V-1", Impact: 0.5, Results: []V1Result{{Status: "skipped"}}}},
			}},
		}
		v2 := ConvertV1ToV2(v1)
		require.NotNil(t, v2.Baselines[0].Requirements[0].EffectiveStatus)
		assert.Equal(t, hdf.NotReviewed, *v2.Baselines[0].Requirements[0].EffectiveStatus)
	})

	t.Run("notReviewed when no results", func(t *testing.T) {
		v1 := &HDFV1Results{
			Version:  "1.0.0",
			Platform: V1Platform{Name: "test"},
			Profiles: []V1Profile{{
				Name:     "test",
				Controls: []V1Control{{ID: "V-1", Impact: 0.5, Results: []V1Result{}}},
			}},
		}
		v2 := ConvertV1ToV2(v1)
		require.NotNil(t, v2.Baselines[0].Requirements[0].EffectiveStatus)
		assert.Equal(t, hdf.NotReviewed, *v2.Baselines[0].Requirements[0].EffectiveStatus)
	})

	t.Run("every control has effectiveStatus in Three_Layer fixture", func(t *testing.T) {
		inputPath := filepath.Join(getFixturesDir(), "input", "three-layer-overlay.json")
		inputData, err := os.ReadFile(inputPath)
		require.NoError(t, err)
		var v1 HDFV1Results
		require.NoError(t, json.Unmarshal(inputData, &v1))
		v2 := ConvertV1ToV2(&v1)

		for _, r := range v2.Baselines[0].Requirements {
			assert.NotNilf(t, r.EffectiveStatus, "control %s missing effectiveStatus", r.ID)
		}
	})

	t.Run("Three_Layer counts: 73 passed, 138 failed, 27 NA, 9 NR", func(t *testing.T) {
		inputPath := filepath.Join(getFixturesDir(), "input", "three-layer-overlay.json")
		inputData, err := os.ReadFile(inputPath)
		require.NoError(t, err)
		var v1 HDFV1Results
		require.NoError(t, json.Unmarshal(inputData, &v1))
		v2 := ConvertV1ToV2(&v1)

		counts := map[hdf.ResultStatus]int{}
		for _, r := range v2.Baselines[0].Requirements {
			if r.EffectiveStatus != nil {
				counts[*r.EffectiveStatus]++
			}
		}
		assert.Equal(t, 73, counts[hdf.Passed])
		assert.Equal(t, 138, counts[hdf.Failed])
		assert.Equal(t, 27, counts[hdf.NotApplicable])
		assert.Equal(t, 9, counts[hdf.NotReviewed])
		assert.Equal(t, 0, counts[hdf.Error])
	})
}

// ── Severity from tags.severity ──────────────────

func TestSeverityFromTagsSeverity(t *testing.T) {
	t.Run("populates severity from tags.severity for NA controls (impact=0)", func(t *testing.T) {
		v1 := &HDFV1Results{
			Version:  "1.0.0",
			Platform: V1Platform{Name: "test"},
			Profiles: []V1Profile{{
				Name: "test",
				Controls: []V1Control{{
					ID:      "V-1",
					Impact:  0,
					Tags:    map[string]interface{}{"severity": "medium", "nist": []string{"AC-1"}},
					Results: []V1Result{{Status: "skipped"}},
				}},
			}},
		}
		v2 := ConvertV1ToV2(v1)
		req := v2.Baselines[0].Requirements[0]
		require.NotNil(t, req.Severity, "severity should be set")
		assert.Equal(t, hdf.Medium, *req.Severity)
		require.NotNil(t, req.EffectiveStatus)
		assert.Equal(t, hdf.NotApplicable, *req.EffectiveStatus)
	})

	t.Run("populates severity from tags.severity for non-NA controls", func(t *testing.T) {
		v1 := &HDFV1Results{
			Version:  "1.0.0",
			Platform: V1Platform{Name: "test"},
			Profiles: []V1Profile{{
				Name: "test",
				Controls: []V1Control{{
					ID:      "V-1",
					Impact:  0.7,
					Tags:    map[string]interface{}{"severity": "high"},
					Results: []V1Result{{Status: "passed"}},
				}},
			}},
		}
		v2 := ConvertV1ToV2(v1)
		require.NotNil(t, v2.Baselines[0].Requirements[0].Severity)
		assert.Equal(t, hdf.SeverityHigh, *v2.Baselines[0].Requirements[0].Severity)
	})

	t.Run("falls back to impact-derived severity when tags.severity missing", func(t *testing.T) {
		v1 := &HDFV1Results{
			Version:  "1.0.0",
			Platform: V1Platform{Name: "test"},
			Profiles: []V1Profile{{
				Name: "test",
				Controls: []V1Control{{
					ID:      "V-1",
					Impact:  0.7,
					Results: []V1Result{{Status: "passed"}},
				}},
			}},
		}
		v2 := ConvertV1ToV2(v1)
		require.NotNil(t, v2.Baselines[0].Requirements[0].Severity)
		assert.Equal(t, hdf.SeverityHigh, *v2.Baselines[0].Requirements[0].Severity)
	})

	t.Run("maps impact values to correct severity levels", func(t *testing.T) {
		cases := []struct {
			impact   float64
			expected hdf.Severity
		}{
			{0.9, hdf.Critical},
			{0.7, hdf.SeverityHigh},
			{0.5, hdf.Medium},
			{0.3, hdf.SeverityLow},
		}
		for _, tc := range cases {
			v1 := &HDFV1Results{
				Version:  "1.0.0",
				Platform: V1Platform{Name: "test"},
				Profiles: []V1Profile{{
					Name:     "test",
					Controls: []V1Control{{ID: "V-1", Impact: tc.impact, Results: []V1Result{}}},
				}},
			}
			v2 := ConvertV1ToV2(v1)
			require.NotNilf(t, v2.Baselines[0].Requirements[0].Severity, "impact=%.1f should have severity", tc.impact)
			assert.Equalf(t, tc.expected, *v2.Baselines[0].Requirements[0].Severity, "impact=%.1f", tc.impact)
		}
	})

	t.Run("ignores invalid tags.severity and falls back to impact", func(t *testing.T) {
		v1 := &HDFV1Results{
			Version:  "1.0.0",
			Platform: V1Platform{Name: "test"},
			Profiles: []V1Profile{{
				Name: "test",
				Controls: []V1Control{{
					ID:      "V-1",
					Impact:  0.7,
					Tags:    map[string]interface{}{"severity": "bogus"},
					Results: []V1Result{{Status: "passed"}},
				}},
			}},
		}
		v2 := ConvertV1ToV2(v1)
		require.NotNil(t, v2.Baselines[0].Requirements[0].Severity)
		assert.Equal(t, hdf.SeverityHigh, *v2.Baselines[0].Requirements[0].Severity)
	})

	t.Run("ubi9 fixture: NA controls have severity from tags not none", func(t *testing.T) {
		inputPath := filepath.Join(getFixturesDir(), "input", "ubi9-scan.json")
		inputData, err := os.ReadFile(inputPath)
		require.NoError(t, err)

		var v1 HDFV1Results
		require.NoError(t, json.Unmarshal(inputData, &v1))

		v2 := ConvertV1ToV2(&v1)
		reqs := v2.Baselines[0].Requirements

		// Find SV-257779: impact=0, tags.severity=medium
		var sv257779 *hdf.EvaluatedRequirement
		for i := range reqs {
			if reqs[i].ID == "SV-257779" {
				sv257779 = &reqs[i]
				break
			}
		}
		require.NotNil(t, sv257779, "SV-257779 should exist")
		require.NotNil(t, sv257779.EffectiveStatus)
		assert.Equal(t, hdf.NotApplicable, *sv257779.EffectiveStatus)
		require.NotNil(t, sv257779.Severity)
		assert.Equal(t, hdf.Medium, *sv257779.Severity)
	})
}

func TestParseTime(t *testing.T) {
	// Valid RFC3339
	ts := parseTime("2024-01-01T00:00:00Z")
	assert.False(t, ts.IsZero())
	assert.Equal(t, 2024, ts.Year())

	// Valid RFC3339Nano
	ts2 := parseTime("2024-01-01T00:00:00.123456789Z")
	assert.False(t, ts2.IsZero())

	// Invalid format returns zero time
	ts3 := parseTime("not a timestamp")
	assert.True(t, ts3.IsZero())
}
