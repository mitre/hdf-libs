package testhdf

import (
	"encoding/json"
	"testing"

	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	validators "github.com/mitre/hdf-libs/hdf-validators/go/v3"
	"github.com/stretchr/testify/require"
)

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	require.NoError(t, err)
	return b
}

func TestDocs_SchemaValid(t *testing.T) {
	t.Run("baseline", func(t *testing.T) {
		r := validators.ValidateBaseline(mustJSON(t, BaselineDoc("test-baseline", BaselineReq("AC-1", BaselineImpact(0.5)))))
		require.True(t, r.Valid, r.Error())
	})
	t.Run("amendments", func(t *testing.T) {
		r := validators.ValidateAmendments(mustJSON(t, Amendments("test",
			Override(hdf.OverrideTypeWaiver, "AC-1", OverrideStatus(hdf.Passed), OverrideReason("accepted risk")))))
		require.True(t, r.Valid, r.Error())
	})
	t.Run("system", func(t *testing.T) {
		r := validators.ValidateSystem(mustJSON(t, System("test-system", Component("WebTier", hdf.Application))))
		require.True(t, r.Valid, r.Error())
	})
	t.Run("plan", func(t *testing.T) {
		r := validators.ValidatePlan(mustJSON(t, Plan("test-plan", Assessment("baseline-1"))))
		require.True(t, r.Valid, r.Error())
	})
	t.Run("evidence-package", func(t *testing.T) {
		r := validators.ValidateEvidencePackage(mustJSON(t, EvidencePackage("test-evidence", Content("results.json", hdf.HdfResults))))
		require.True(t, r.Valid, r.Error())
	})
	t.Run("change-event", func(t *testing.T) {
		r := validators.ValidateRequirementChangeEvent(mustJSON(t, ChangeEvent("AC-1")))
		require.True(t, r.Valid, r.Error())
	})
	t.Run("comparison", func(t *testing.T) {
		r := validators.ValidateComparison(mustJSON(t, Comparison(hdf.Temporal)))
		require.True(t, r.Valid, r.Error())
	})
}
