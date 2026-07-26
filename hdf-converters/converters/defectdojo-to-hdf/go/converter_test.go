package defectdojo_to_hdf

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

const converterVersion = "0.1.0"

func loadFixture(t *testing.T, name string) []byte {
	t.Helper()
	p := filepath.Join(shared.GetConvertersDir(), "defectdojo-to-hdf", "fixtures", "input", name)
	data, err := os.ReadFile(p)
	require.NoError(t, err)
	return data
}

// requirementByTriage finds the single requirement whose triage tag is set true.
func requirementByTriage(t *testing.T, reqs []hdf.EvaluatedRequirement, tag string) hdf.EvaluatedRequirement {
	t.Helper()
	for _, r := range reqs {
		if v, ok := r.Tags[tag].(bool); ok && v {
			return r
		}
	}
	t.Fatalf("no requirement with %s=true", tag)
	return hdf.EvaluatedRequirement{}
}

func TestConvertDefectDojo_Findings(t *testing.T) {
	result, err := ConvertDefectDojo(loadFixture(t, "findings.json"), converterVersion)
	require.NoError(t, err)
	require.NotNil(t, result)

	require.NotNil(t, result.Generator)
	assert.Equal(t, "defectdojo-to-hdf", result.Generator.Name)

	// All four sample findings came from the "Generic Findings Import" test_type
	// → a single per-scanner baseline.
	require.Len(t, result.Baselines, 1)
	base := result.Baselines[0]
	assert.Equal(t, "DefectDojo: Generic Findings Import", base.Name)
	require.Len(t, base.Requirements, 4)

	// Output must be schema-valid.
	out, err := json.Marshal(result)
	require.NoError(t, err)
	assert.True(t, validators.ValidateResults(out).Valid, "HDF output must validate: %s", validators.ValidateResults(out).Error())
}

func TestConvertDefectDojo_StatusMapping(t *testing.T) {
	result, err := ConvertDefectDojo(loadFixture(t, "findings.json"), converterVersion)
	require.NoError(t, err)
	reqs := result.Baselines[0].Requirements

	// active (untriaged) → failed
	active := requirementByTriage(t, reqs, "defectdojo/active")
	assert.Equal(t, hdf.Failed, active.Results[0].Status)

	// false_p → failed (raw-primary; dismissal rides in the tag, not the status)
	fp := requirementByTriage(t, reqs, "defectdojo/false_p")
	assert.Equal(t, hdf.Failed, fp.Results[0].Status)
	assert.Nil(t, fp.EffectiveStatus, "false positive is not an override")

	// is_mitigated → passed (only when it is not also false_p/risk_accepted)
	// finding 3 in the fixture is mitigated-only.
	var mitigatedOnly *hdf.EvaluatedRequirement
	for i := range reqs {
		r := reqs[i]
		if b, _ := r.Tags["defectdojo/is_mitigated"].(bool); b {
			if fp2, _ := r.Tags["defectdojo/false_p"].(bool); !fp2 {
				mitigatedOnly = &reqs[i]
			}
		}
	}
	require.NotNil(t, mitigatedOnly, "expected a mitigated-only requirement")
	assert.Equal(t, hdf.Passed, mitigatedOnly.Results[0].Status)
}

func TestConvertDefectDojo_RiskAcceptanceWaiverOverride(t *testing.T) {
	result, err := ConvertDefectDojo(loadFixture(t, "findings.json"), converterVersion)
	require.NoError(t, err)
	reqs := result.Baselines[0].Requirements

	ra := requirementByTriage(t, reqs, "defectdojo/risk_accepted")

	// Raw status stays failed; the acceptance is an override, not a rewrite.
	assert.Equal(t, hdf.Failed, ra.Results[0].Status)

	// Effective axis reflects the waiver, fully attributed.
	require.NotNil(t, ra.EffectiveStatus)
	assert.Equal(t, hdf.Passed, *ra.EffectiveStatus)
	require.NotNil(t, ra.Disposition)
	assert.Equal(t, hdf.OverrideTypeWaiver, *ra.Disposition)

	require.Len(t, ra.StatusOverrides, 1)
	ov := ra.StatusOverrides[0]
	assert.Equal(t, hdf.OverrideTypeWaiver, ov.Type)
	require.NotNil(t, ov.Status)
	assert.Equal(t, hdf.Passed, *ov.Status)
	assert.Contains(t, ov.Reason, "WAF virtual patch") // real decision_details, not fabricated
	assert.Equal(t, "defectdojo-user-1", ov.AppliedBy.Identifier)
	assert.Equal(t, hdf.Simple, ov.AppliedBy.Type)
	assert.Equal(t, 2099, ov.ExpiresAt.Year()) // real expiration_date
	assert.False(t, ov.AppliedAt.IsZero())
}

func TestConvertDefectDojo_Empty(t *testing.T) {
	result, err := ConvertDefectDojo(loadFixture(t, "empty.json"), converterVersion)
	require.NoError(t, err)
	require.Len(t, result.Baselines, 1)
	require.Len(t, result.Baselines[0].Requirements, 1)
	req := result.Baselines[0].Requirements[0]
	assert.Equal(t, "defectdojo-no-findings", req.ID)
	assert.Equal(t, hdf.Passed, req.Results[0].Status)

	out, err := json.Marshal(result)
	require.NoError(t, err)
	assert.True(t, validators.ValidateResults(out).Valid)
}

func TestConvertDefectDojo_InvalidAndEmptyInput(t *testing.T) {
	_, err := ConvertDefectDojo([]byte(""), converterVersion)
	assert.Error(t, err)

	_, err = ConvertDefectDojo([]byte("not json"), converterVersion)
	assert.Error(t, err)
}
