package legacyhdf

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	hdf "github.com/mitre/hdf-schema"
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
	require.NotNil(t, v2.Targets)
	assert.Len(t, v2.Targets, 1)
	assert.Equal(t, hdf.Host, v2.Targets[0].Type)
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
	require.NotNil(t, v2.Targets)
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
	require.NotNil(t, v2.Targets)
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
	require.Len(t, v2.Targets, 1)
	assert.Equal(t, hdf.Host, v2.Targets[0].Type)
	assert.Equal(t, "test-system", v2.Targets[0].Name)
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
	assert.Equal(t, hdf.Sha256, v2.Checksum.Algorithm)
	assert.Equal(t, sha256, v2.Checksum.Value)
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
