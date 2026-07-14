package csafvex

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	validators "github.com/mitre/hdf-libs/hdf-validators/go/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testVersion = "test"

func loadInput(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "fixtures", "input", name))
	require.NoError(t, err)
	return data
}

func TestConvertCSAFVEX_NotAffectedUseCase(t *testing.T) {
	t.Parallel()
	result, err := ConvertCSAFVEXToHDF(loadInput(t, "2022-evd-uc-01-na-001.json"), testVersion)
	require.NoError(t, err)
	require.Len(t, result.Overrides, 1)

	o := result.Overrides[0]
	assert.Equal(t, "CVE-2021-44228", o.RequirementID)
	assert.Equal(t, hdf.FalsePositive, o.Type)
	require.NotNil(t, o.Status)
	assert.Equal(t, hdf.Passed, *o.Status)
	assert.Nil(t, o.Justification, "uc-01-na has no flags; justification should be unset")
	assert.Contains(t, o.Reason, "Class with vulnerable code was removed")
	assert.NotContains(t, o.Reason, "CSAFPID-0001")
	// CSAFPID-0001 resolves through product_tree's vendor/product_name/
	// product_version branch hierarchy → name "ABC", version "4.2".
	require.Len(t, o.AffectedPackages, 1)
	require.NotNil(t, o.AffectedPackages[0].Name)
	require.NotNil(t, o.AffectedPackages[0].Version)
	assert.Equal(t, "ABC", *o.AffectedPackages[0].Name)
	assert.Equal(t, "4.2", *o.AffectedPackages[0].Version)

	body, err := json.Marshal(result)
	require.NoError(t, err)
	v := validators.ValidateAmendments(body)
	require.True(t, v.Valid, "amendments must validate: %s", v.Error())
}

func TestConvertCSAFVEX_FixedUseCaseProducesPoamPinnedToFailed(t *testing.T) {
	t.Parallel()
	result, err := ConvertCSAFVEXToHDF(loadInput(t, "2022-evd-uc-01-f-001.json"), testVersion)
	require.NoError(t, err)
	require.Len(t, result.Overrides, 1)

	o := result.Overrides[0]
	assert.Equal(t, hdf.Poam, o.Type)
	require.NotNil(t, o.Status)
	assert.Equal(t, hdf.Failed, *o.Status, "POA&M from supplier 'fixed' stays failed until consumer re-scans")
	require.Len(t, o.Milestones, 1)
	assert.Equal(t, hdf.Pending, o.Milestones[0].Status)

	body, err := json.Marshal(result)
	require.NoError(t, err)
	v := validators.ValidateAmendments(body)
	require.True(t, v.Valid, "amendments must validate: %s", v.Error())
}

func TestConvertCSAFVEX_SecVexCarriesFlagAsJustification(t *testing.T) {
	t.Parallel()
	result, err := ConvertCSAFVEXToHDF(loadInput(t, "sec-vex-2022-0001.json"), testVersion)
	require.NoError(t, err)
	require.Len(t, result.Overrides, 3, "three CVEs, all known_not_affected")

	for _, o := range result.Overrides {
		assert.Equal(t, hdf.FalsePositive, o.Type)
		require.NotNil(t, o.Justification, "each CVE has a flag with label=component_not_present")
		assert.Equal(t, hdf.ComponentNotPresent, *o.Justification)
		assert.NotEmpty(t, o.Evidence, "vulnerability references should populate evidence[]")
	}

	body, err := json.Marshal(result)
	require.NoError(t, err)
	v := validators.ValidateAmendments(body)
	require.True(t, v.Valid)
}

func TestConvertCSAFVEX_AffectedAndUnderInvestigationProduceError(t *testing.T) {
	t.Parallel()

	_, errAff := ConvertCSAFVEXToHDF(loadInput(t, "2022-evd-uc-01-a-001.json"), testVersion)
	require.Error(t, errAff, "known_affected has no consumer-action payload")
	assert.Contains(t, errAff.Error(), "no actionable statements")

	_, errUI := ConvertCSAFVEXToHDF(loadInput(t, "2022-evd-uc-01-ui-001.json"), testVersion)
	require.Error(t, errUI, "under_investigation has no consumer-action payload")
	assert.Contains(t, errUI.Error(), "no actionable statements")
}

func TestConvertCSAFVEX_RejectsNonVEXProfile(t *testing.T) {
	t.Parallel()
	input := []byte(`{"document":{"category":"csaf_security_advisory","csaf_version":"2.0","publisher":{"category":"vendor","name":"Acme"},"tracking":{"id":"X","status":"final","version":"1","current_release_date":"2026-01-01T00:00:00Z","initial_release_date":"2026-01-01T00:00:00Z"}}}`)
	_, err := ConvertCSAFVEXToHDF(input, testVersion)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "csaf_vex")
}

func TestConvertCSAFVEX_RejectsOversizedInput(t *testing.T) {
	t.Parallel()
	_, err := ConvertCSAFVEXToHDF(make([]byte, 51*1024*1024), testVersion)
	require.Error(t, err)
}

func TestConvertCSAFVEX_RejectsInvalidJSON(t *testing.T) {
	t.Parallel()
	_, err := ConvertCSAFVEXToHDF([]byte("not json"), testVersion)
	require.Error(t, err)
}

func TestConvertCSAFVEX_PublisherNamespaceBuildsAdvisoryURI(t *testing.T) {
	t.Parallel()
	result, err := ConvertCSAFVEXToHDF(loadInput(t, "sec-vex-2022-0001.json"), testVersion)
	require.NoError(t, err)
	require.NotEmpty(t, result.Overrides[0].Evidence)
	assert.Contains(t, result.Overrides[0].Evidence[0].Data, "github.com/secvisogram",
		"first evidence entry is the advisory URI built from publisher.namespace + tracking.id")
}

// --- Ground-truth anchor (see shared/go/anchor.go) ---
// csaf-vex emits one override per actionable status bucket (known_not_affected,
// and fixed/first_fixed) on each CVE-bearing vulnerability. Count those buckets
// independently from the source and assert the emitted override count matches.
func countCsafActionableBuckets(t *testing.T, input []byte) int {
	t.Helper()
	var doc struct {
		Vulnerabilities []struct {
			CVE           string `json:"cve"`
			ProductStatus *struct {
				KnownNotAffected []string `json:"known_not_affected"`
				Fixed            []string `json:"fixed"`
				FirstFixed       []string `json:"first_fixed"`
			} `json:"product_status"`
		} `json:"vulnerabilities"`
	}
	require.NoError(t, json.Unmarshal(input, &doc))
	n := 0
	for _, v := range doc.Vulnerabilities {
		if v.CVE == "" || v.ProductStatus == nil {
			continue
		}
		if len(v.ProductStatus.KnownNotAffected) > 0 {
			n++
		}
		if len(v.ProductStatus.Fixed) > 0 || len(v.ProductStatus.FirstFixed) > 0 {
			n++
		}
	}
	return n
}

func TestConvertCSAFVEX_OverrideAnchor(t *testing.T) {
	t.Parallel()
	input := loadInput(t, "sec-vex-2022-0001.json")
	result, err := ConvertCSAFVEXToHDF(input, testVersion)
	require.NoError(t, err)
	shared.AssertOverrideCount(t, result, countCsafActionableBuckets(t, input),
		"sec-vex-2022-0001.json: one override per actionable status bucket")
}
