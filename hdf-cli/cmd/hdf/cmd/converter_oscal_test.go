//nolint:dupl
package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	hdf "github.com/mitre/hdf-schema"
)

const (
	oscalFixtureDir = "../../../../hdf-converters/converters/oscal-to-hdf/fixtures/input"
)

func TestConvertOSCALCatalog(t *testing.T) {
	inputPath := filepath.Join(oscalFixtureDir, "catalog-moderate-resolved.json")
	if _, err := os.Stat(inputPath); err != nil {
		t.Skip("OSCAL fixture not available")
	}

	output := filepath.Join(t.TempDir(), "out.json")
	cmd := NewRootCmd()
	cmd.SetArgs([]string{"convert", "oscal-catalog", "to", "hdf", inputPath, output})

	err := cmd.Execute()
	require.NoError(t, err)

	data, err := os.ReadFile(output)
	require.NoError(t, err)

	var baseline hdf.HDFBaseline
	err = json.Unmarshal(data, &baseline)
	require.NoError(t, err)

	assert.Equal(t, 287, len(baseline.Requirements))
	assert.NotEmpty(t, baseline.Name)
	assert.NotNil(t, baseline.Generator)
}

func TestConvertOSCALProfile(t *testing.T) {
	profilePath := filepath.Join(oscalFixtureDir, "profile-moderate.json")
	catalogPath := filepath.Join(oscalFixtureDir, "catalog-800-53-rev5.json")
	if _, err := os.Stat(profilePath); err != nil {
		t.Skip("OSCAL profile fixture not available")
	}
	if _, err := os.Stat(catalogPath); err != nil {
		t.Skip("OSCAL catalog fixture not available")
	}

	output := filepath.Join(t.TempDir(), "out.json")

	// Reset flag for test isolation
	oscalCatalogFlag = ""

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"convert", "oscal-profile", "to", "hdf", profilePath, output,
		"--catalog", catalogPath})

	err := cmd.Execute()
	require.NoError(t, err)

	data, err := os.ReadFile(output)
	require.NoError(t, err)

	var baseline hdf.HDFBaseline
	err = json.Unmarshal(data, &baseline)
	require.NoError(t, err)

	assert.Equal(t, 287, len(baseline.Requirements))
	assert.NotNil(t, baseline.Title)
	assert.Contains(t, *baseline.Title, "MODERATE")
}

func TestConvertOSCALProfile_NoCatalogFlag(t *testing.T) {
	profilePath := filepath.Join(oscalFixtureDir, "profile-moderate.json")
	if _, err := os.Stat(profilePath); err != nil {
		t.Skip("OSCAL profile fixture not available")
	}

	output := filepath.Join(t.TempDir(), "out.json")

	// Reset flag for test isolation
	oscalCatalogFlag = ""

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"convert", "oscal-profile", "to", "hdf", profilePath, output})

	err := cmd.Execute()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "--catalog flag is required")
}

func TestConvertOSCALProfile_BadCatalogPath(t *testing.T) {
	profilePath := filepath.Join(oscalFixtureDir, "profile-moderate.json")
	if _, err := os.Stat(profilePath); err != nil {
		t.Skip("OSCAL profile fixture not available")
	}

	output := filepath.Join(t.TempDir(), "out.json")
	oscalCatalogFlag = ""

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"convert", "oscal-profile", "to", "hdf", profilePath, output,
		"--catalog", "/nonexistent/catalog.json"})

	err := cmd.Execute()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to read catalog")
}
