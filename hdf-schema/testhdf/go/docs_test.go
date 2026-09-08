package testhdf

import (
	"encoding/json"
	"os"
	"testing"

	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	validators "github.com/mitre/hdf-libs/hdf-validators/go/v3"
	"github.com/stretchr/testify/require"
)

var overrideTypes = []hdf.OverrideType{
	hdf.OverrideTypeWaiver,
	hdf.Attestation,
	hdf.Poam,
	hdf.Inherited,
	hdf.FalsePositive,
	hdf.RiskAdjustment,
	hdf.OperationalRequirement,
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	require.NoError(t, err)
	return b
}

// Every builder must be schema-valid with no options supplied — the defaults are
// the contract the rest of the repo's tests build on.
func TestDocs_SchemaValid(t *testing.T) {
	t.Run("baseline", func(t *testing.T) {
		r := validators.ValidateBaseline(mustJSON(t, BaselineDoc("test-baseline", BaselineReq("AC-1"))))
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

func TestDocs_SchemaValidWithOptions(t *testing.T) {
	t.Run("baseline", func(t *testing.T) {
		r := validators.ValidateBaseline(mustJSON(t, BaselineDoc("test-baseline", BaselineReq("AC-1", BaselineImpact(0.5)))))
		require.True(t, r.Valid, r.Error())
	})
	t.Run("amendments", func(t *testing.T) {
		r := validators.ValidateAmendments(mustJSON(t, Amendments("test",
			Override(hdf.OverrideTypeWaiver, "AC-1", OverrideStatus(hdf.Passed), OverrideReason("accepted risk")))))
		require.True(t, r.Valid, r.Error())
	})
}

// Every override type must build a schema-valid document with no options: the
// schema's status/impact rule is type-dependent, so a single default cannot
// satisfy operationalRequirement (which forbids both) and the rest at once.
func TestDocs_AmendmentsAreSchemaValid(t *testing.T) {
	for _, ot := range overrideTypes {
		t.Run(string(ot), func(t *testing.T) {
			r := validators.ValidateAmendments(mustJSON(t, Amendments("a", Override(ot, "CVE-2021-44228"))))
			require.True(t, r.Valid, r.Error())
		})
	}
}

// Writes the default-built documents the TS peer's parity test diffs against;
// inert unless that test asks for the dump.
func TestDocs_ParityDump(t *testing.T) {
	out := os.Getenv("TESTHDF_PARITY_DUMP")
	if out == "" {
		t.Skip("TESTHDF_PARITY_DUMP unset")
	}
	docs := map[string]any{
		"results":          Results(Req("X")),
		"baseline":         BaselineDoc("b", BaselineReq("AC-1")),
		"system":           System("s", Component("WebTier", hdf.Application)),
		"plan":             Plan("p", Assessment("baseline-1")),
		"evidence-package": EvidencePackage("e", Content("results.json", hdf.HdfResults)),
		"change-event":     ChangeEvent("AC-1"),
		"comparison":       Comparison(hdf.Temporal),
	}
	for _, ot := range overrideTypes {
		docs["amendments-"+string(ot)] = Amendments("a", Override(ot, "CVE-2021-44228"))
	}
	require.NoError(t, os.WriteFile(out, mustJSON(t, docs), 0o600))
}
