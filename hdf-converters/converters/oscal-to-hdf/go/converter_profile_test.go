package oscal

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
)

func loadFixture(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	return data
}

func TestConvertProfileToHDF_ModerateBaseline(t *testing.T) {
	profile := loadFixture(t, "../fixtures/input/profile-moderate.json")
	catalog := loadFixture(t, "../fixtures/input/catalog-800-53-rev5.json")

	baseline, err := ConvertProfileToHDF(profile, catalog, "1.0.0-test")
	require.NoError(t, err)

	// Profile selects 287 control IDs
	assert.Equal(t, 287, len(baseline.Requirements))

	// Metadata should come from the profile, not the catalog
	assert.NotNil(t, baseline.Title)
	assert.Contains(t, *baseline.Title, "MODERATE")
	assert.NotNil(t, baseline.Version)
	assert.Equal(t, "5.2.0", *baseline.Version)

	// Generator
	assert.NotNil(t, baseline.Generator)
	assert.Equal(t, "oscal-catalog-to-hdf", baseline.Generator.Name)

	// Integrity based on profile input (not catalog)
	assert.NotNil(t, baseline.Integrity)
	assert.Equal(t, hdf.Sha256, *baseline.Integrity.Algorithm)
}

func TestConvertProfileToHDF_MatchesResolvedCatalog(t *testing.T) {
	profile := loadFixture(t, "../fixtures/input/profile-moderate.json")
	catalog := loadFixture(t, "../fixtures/input/catalog-800-53-rev5.json")

	baseline, err := ConvertProfileToHDF(profile, catalog, "1.0.0-test")
	require.NoError(t, err)

	// Also convert the pre-resolved catalog directly
	resolvedCatalog := loadFixture(t, "../fixtures/input/catalog-moderate-resolved.json")
	directBaseline, err := ConvertCatalogToHDF(resolvedCatalog, "1.0.0-test")
	require.NoError(t, err)

	// Both should produce the same number of requirements
	assert.Equal(t, len(directBaseline.Requirements), len(baseline.Requirements),
		"profile resolver and pre-resolved catalog should produce same control count")

	// Build requirement ID sets and compare
	profileIDs := make(map[string]bool)
	for _, r := range baseline.Requirements {
		profileIDs[r.ID] = true
	}
	directIDs := make(map[string]bool)
	for _, r := range directBaseline.Requirements {
		directIDs[r.ID] = true
	}

	// Every ID in the pre-resolved catalog should be in our resolved output
	for id := range directIDs {
		assert.True(t, profileIDs[id], "pre-resolved catalog has %s but profile resolver doesn't", id)
	}
	for id := range profileIDs {
		assert.True(t, directIDs[id], "profile resolver has %s but pre-resolved catalog doesn't", id)
	}
}

func TestConvertProfileToHDF_ControlContent(t *testing.T) {
	profile := loadFixture(t, "../fixtures/input/profile-moderate.json")
	catalog := loadFixture(t, "../fixtures/input/catalog-800-53-rev5.json")

	baseline, err := ConvertProfileToHDF(profile, catalog, "1.0.0-test")
	require.NoError(t, err)

	// Find AC-1
	var ac1 *hdf.BaselineRequirement
	for i := range baseline.Requirements {
		if baseline.Requirements[i].ID == "AC-1" {
			ac1 = &baseline.Requirements[i]
			break
		}
	}
	require.NotNil(t, ac1, "AC-1 should be in moderate baseline")

	// Title should be preserved from catalog
	assert.Equal(t, "Policy and Procedures", *ac1.Title)

	// Should have descriptions
	assert.GreaterOrEqual(t, len(ac1.Descriptions), 1)
	assert.Equal(t, "default", ac1.Descriptions[0].Label)

	// Tags should include NIST tag
	nist, ok := ac1.Tags["nist"]
	assert.True(t, ok)
	assert.Equal(t, []string{"AC-1"}, nist)
}

func TestConvertProfileToHDF_FilteringWorks(t *testing.T) {
	profile := loadFixture(t, "../fixtures/input/profile-moderate.json")
	catalog := loadFixture(t, "../fixtures/input/catalog-800-53-rev5.json")

	baseline, err := ConvertProfileToHDF(profile, catalog, "1.0.0-test")
	require.NoError(t, err)

	// The full catalog has 1196 controls; moderate should have 287
	catalogBaseline, err := ConvertCatalogToHDF(catalog, "1.0.0-test")
	require.NoError(t, err)

	assert.Greater(t, len(catalogBaseline.Requirements), len(baseline.Requirements),
		"profile should filter down from full catalog")
}

func TestConvertProfileToHDF_GroupsFilteredCorrectly(t *testing.T) {
	profile := loadFixture(t, "../fixtures/input/profile-moderate.json")
	catalog := loadFixture(t, "../fixtures/input/catalog-800-53-rev5.json")

	baseline, err := ConvertProfileToHDF(profile, catalog, "1.0.0-test")
	require.NoError(t, err)

	// All groups should reference existing requirements
	reqIDs := make(map[string]bool)
	for _, r := range baseline.Requirements {
		reqIDs[r.ID] = true
	}
	for _, g := range baseline.Groups {
		for _, rid := range g.Requirements {
			assert.True(t, reqIDs[rid], "group %s references non-existent requirement %s", g.ID, rid)
		}
	}
}

func TestConvertProfileToHDF_EmptyProfileInput(t *testing.T) {
	catalog := loadFixture(t, "../fixtures/input/catalog-800-53-rev5.json")
	_, err := ConvertProfileToHDF(nil, catalog, "1.0.0")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "empty input")
}

func TestConvertProfileToHDF_EmptyCatalogInput(t *testing.T) {
	profile := loadFixture(t, "../fixtures/input/profile-moderate.json")
	_, err := ConvertProfileToHDF(profile, nil, "1.0.0")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "empty input")
}

func TestConvertProfileToHDF_NotProfile(t *testing.T) {
	catalog := loadFixture(t, "../fixtures/input/catalog-800-53-rev5.json")
	_, err := ConvertProfileToHDF(catalog, catalog, "1.0.0")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "expected profile document")
}

func TestConvertProfileToHDF_CatalogNotCatalog(t *testing.T) {
	profile := loadFixture(t, "../fixtures/input/profile-moderate.json")
	_, err := ConvertProfileToHDF(profile, profile, "1.0.0")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "expected catalog document")
}

func TestConvertProfileToHDF_InvalidJSON(t *testing.T) {
	catalog := loadFixture(t, "../fixtures/input/catalog-800-53-rev5.json")
	_, err := ConvertProfileToHDF([]byte("not json"), catalog, "1.0.0")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse JSON")
}

func TestConvertProfileToHDF_RoundTrip(t *testing.T) {
	profile := loadFixture(t, "../fixtures/input/profile-moderate.json")
	catalog := loadFixture(t, "../fixtures/input/catalog-800-53-rev5.json")

	baseline, err := ConvertProfileToHDF(profile, catalog, "1.0.0-test")
	require.NoError(t, err)

	out, err := json.Marshal(baseline)
	require.NoError(t, err)

	var roundtrip hdf.HDFBaseline
	err = json.Unmarshal(out, &roundtrip)
	require.NoError(t, err)
	assert.Equal(t, baseline.Name, roundtrip.Name)
	assert.Equal(t, len(baseline.Requirements), len(roundtrip.Requirements))
}

// --- Unit tests for internal helpers ---

func TestCollectIncludedIDs(t *testing.T) {
	imp := Import{
		IncludeControls: []IncludeControl{
			{WithIDs: []string{"ac-1", "ac-2", "ac-3"}},
			{WithIDs: []string{"si-1"}},
		},
	}
	ids := collectIncludedIDs(imp)
	assert.Len(t, ids, 4)
	assert.True(t, ids["ac-1"])
	assert.True(t, ids["si-1"])
}

func TestCollectIncludedIDs_NoIncludes(t *testing.T) {
	imp := Import{Href: "#something"}
	ids := collectIncludedIDs(imp)
	assert.Nil(t, ids) // nil means include all
}

func TestCollectExcludedIDs(t *testing.T) {
	imp := Import{
		ExcludeControls: []ExcludeControl{
			{WithIDs: []string{"ac-15"}},
		},
	}
	ids := collectExcludedIDs(imp)
	assert.Len(t, ids, 1)
	assert.True(t, ids["ac-15"])
}

func TestShouldIncludeControl(t *testing.T) {
	include := map[string]bool{"ac-1": true, "ac-2": true}
	exclude := map[string]bool{"ac-2": true}

	// Included and not excluded
	assert.True(t, shouldIncludeControl("ac-1", include, exclude, false))
	// Included but excluded
	assert.False(t, shouldIncludeControl("ac-2", include, exclude, false))
	// Not included
	assert.False(t, shouldIncludeControl("ac-3", include, exclude, false))
	// Include all, not excluded
	assert.True(t, shouldIncludeControl("ac-3", nil, exclude, true))
	// Include all, excluded
	assert.False(t, shouldIncludeControl("ac-2", nil, exclude, true))
}

func TestSubstituteParams(t *testing.T) {
	overrides := map[string][]string{
		"ac-1_prm_1": {"annually"},
		"ac-1_prm_2": {"quarterly", "as needed"},
	}

	text := "Review {{ insert: param, ac-1_prm_1 }} and update {{ insert: param, ac-1_prm_2 }}."
	result := substituteParams(text, overrides)
	assert.Equal(t, "Review annually and update quarterly, as needed.", result)
}

func TestSubstituteParams_NoMatch(t *testing.T) {
	text := "No parameters here."
	result := substituteParams(text, map[string][]string{"x": {"y"}})
	assert.Equal(t, "No parameters here.", result)
}

// ---- Red Hat OSCAL profile fixture (real organizational profile) ----

func TestConvertProfileToHDF_RedHatFedRAMPHigh(t *testing.T) {
	// Red Hat FedRAMP High profile uses 97 alter directives to add
	// FedRAMP-specific requirements and guidance to controls.
	profile := loadFixture(t, "../fixtures/input/profile-redhat-fedramp-high.json")
	catalog := loadFixture(t, "../fixtures/input/catalog-800-53-rev5.json")
	baseline, err := ConvertProfileToHDF(profile, catalog, "1.0.0")
	require.NoError(t, err, "Profile with alters should now convert successfully")
	assert.NotEmpty(t, baseline.Requirements, "Should have requirements")
}

// ---- Alter directive unit tests ----

func TestApplyAlters_AddEnding(t *testing.T) {
	catalog := &Catalog{
		Groups: []Group{{
			ID: "ac",
			Controls: []Control{{
				ID:    "ac-1",
				Title: "Access Control Policy",
				Parts: []Part{{
					ID:    "ac-1_smt",
					Name:  "statement",
					Prose: "Original statement.",
				}},
			}},
		}},
	}

	alters := []Alter{{
		ControlID: "ac-1",
		Adds: []Addition{{
			Position: "ending",
			ByID:     "ac-1_smt",
			Parts: []Part{{
				ID:    "ac-1_fr",
				Name:  "item",
				Prose: "FedRAMP additional requirement.",
			}},
		}},
	}}

	applyAlters(catalog, alters)

	ctrl := catalog.Groups[0].Controls[0]
	// The original statement part should now have a child part added
	smt := findPartByID(ctrl.Parts, "ac-1_smt")
	require.NotNil(t, smt, "Statement part should exist")
	assert.Len(t, smt.Parts, 1, "Should have 1 child part added")
	assert.Equal(t, "ac-1_fr", smt.Parts[0].ID)
	assert.Equal(t, "FedRAMP additional requirement.", smt.Parts[0].Prose)
}

func TestApplyAlters_AddStarting(t *testing.T) {
	catalog := &Catalog{
		Controls: []Control{{
			ID: "ac-1",
			Parts: []Part{{
				ID:    "ac-1_smt",
				Name:  "statement",
				Parts: []Part{{ID: "existing", Prose: "Existing child."}},
			}},
		}},
	}

	alters := []Alter{{
		ControlID: "ac-1",
		Adds: []Addition{{
			Position: "starting",
			ByID:     "ac-1_smt",
			Parts: []Part{{
				ID:    "prepended",
				Prose: "Prepended part.",
			}},
		}},
	}}

	applyAlters(catalog, alters)
	smt := findPartByID(catalog.Controls[0].Parts, "ac-1_smt")
	require.NotNil(t, smt)
	require.Len(t, smt.Parts, 2)
	assert.Equal(t, "prepended", smt.Parts[0].ID)
	assert.Equal(t, "existing", smt.Parts[1].ID)
}

func TestApplyAlters_AddProps(t *testing.T) {
	catalog := &Catalog{
		Controls: []Control{{
			ID:    "ac-1",
			Props: []Property{{Name: "original", Value: "yes"}},
		}},
	}

	alters := []Alter{{
		ControlID: "ac-1",
		Adds: []Addition{{
			Props: []Property{{Name: "fedramp", Value: "required"}},
		}},
	}}

	applyAlters(catalog, alters)
	assert.Len(t, catalog.Controls[0].Props, 2)
	assert.Equal(t, "fedramp", catalog.Controls[0].Props[1].Name)
}

func TestApplyAlters_Remove(t *testing.T) {
	catalog := &Catalog{
		Controls: []Control{{
			ID: "ac-1",
			Parts: []Part{
				{ID: "ac-1_smt", Name: "statement", Prose: "Keep this."},
				{ID: "ac-1_gdn", Name: "guidance", Prose: "Remove this."},
			},
			Props: []Property{
				{Name: "label", Value: "AC-1"},
				{Name: "obsolete", Value: "yes"},
			},
		}},
	}

	alters := []Alter{{
		ControlID: "ac-1",
		Removes: []Remove{
			{ByID: "ac-1_gdn"},
			{ByName: "obsolete"},
		},
	}}

	applyAlters(catalog, alters)
	ctrl := catalog.Controls[0]
	assert.Len(t, ctrl.Parts, 1, "Should have removed guidance part")
	assert.Equal(t, "ac-1_smt", ctrl.Parts[0].ID)
	assert.Len(t, ctrl.Props, 1, "Should have removed obsolete prop")
	assert.Equal(t, "label", ctrl.Props[0].Name)
}

func TestApplyAlters_NonexistentControlIgnored(t *testing.T) {
	catalog := &Catalog{
		Controls: []Control{{
			ID:    "ac-1",
			Title: "AC-1",
		}},
	}

	alters := []Alter{{
		ControlID: "nonexistent",
		Adds: []Addition{{
			Props: []Property{{Name: "new", Value: "prop"}},
		}},
	}}

	// Should not panic or error — just silently skip
	applyAlters(catalog, alters)
	assert.Len(t, catalog.Controls[0].Props, 0)
}

// findPartByID searches parts by ID (helper for tests).
func findPartByID(parts []Part, id string) *Part {
	for i := range parts {
		if parts[i].ID == id {
			return &parts[i]
		}
		if found := findPartByID(parts[i].Parts, id); found != nil {
			return found
		}
	}
	return nil
}

func TestDetectDocumentType_RedHatProfile(t *testing.T) {
	profile := loadFixture(t, "../fixtures/input/profile-redhat-fedramp-high.json")
	docType, err := DetectDocumentType(profile)
	require.NoError(t, err)
	assert.Equal(t, "profile", docType)
}
