package diff

import (
	"encoding/json"
	"testing"
	"time"

	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const ecRefTime = "2026-07-01T00:00:00Z"

// Pinned cross-language vectors: sha256 of the canonical JSON
// {"status":<resolved>,"impact":<resolved>,"disposition":<type|null>}.
// The TS suite pins the same hex values from the same inputs.
const (
	ecVectorFailedHalf = "704f62b2d0803438ad6b7b9bab45e2c4f350b7344135a2a7f8ef986d98669021" // {"status":"failed","impact":0.5,"disposition":null}
	ecVectorWaivedNA   = "40f165574efcca5a6bf5ff2c113e6d1bc2aea56e4251b70b68bdb2e05d1fef3b" // {"status":"notApplicable","impact":0.7,"disposition":"waiver"}
	ecVectorZeroImpact = "de78ada7d86293d722efc2c30b0bac553303183ec9e784839c3c9a7745472ffc" // {"status":"notApplicable","impact":0,"disposition":null}
	ecVectorPassedHalf = "73908440a3b44d76de559753babfea36987a618b80ee9d26adcf29cb5c7a5217" // {"status":"passed","impact":0.5,"disposition":null}
)

func ecFailingReq() hdf.EvaluatedRequirement {
	return stMakeRequirement(func(r *hdf.EvaluatedRequirement) {
		r.Impact = 0.5
		r.Results = []hdf.RequirementResult{stMakeResult(hdf.Failed)}
	})
}

func TestComputeEffectiveChecksum_KnownVectors(t *testing.T) {
	t.Run("failing requirement, no overrides", func(t *testing.T) {
		cs := ComputeEffectiveChecksum(ecFailingReq(), ecRefTime)
		require.NotNil(t, cs)
		assert.Equal(t, hdf.Sha256, cs.Algorithm)
		assert.Equal(t, ecVectorFailedHalf, cs.Value)
	})

	t.Run("waived requirement carries disposition", func(t *testing.T) {
		req := stMakeRequirement(func(r *hdf.EvaluatedRequirement) {
			r.Results = []hdf.RequirementResult{stMakeResult(hdf.Failed)}
			r.StatusOverrides = []hdf.StatusOverride{stMakeOverride(struct {
				Type      string
				Status    hdf.ResultStatus
				Reason    string
				AppliedAt time.Time
				ExpiresAt time.Time
			}{Type: "waiver", Status: hdf.NotApplicable})}
		})
		cs := ComputeEffectiveChecksum(req, ecRefTime)
		require.NotNil(t, cs)
		assert.Equal(t, ecVectorWaivedNA, cs.Value)
	})

	t.Run("impact zero resolves to notApplicable", func(t *testing.T) {
		req := stMakeRequirement(func(r *hdf.EvaluatedRequirement) {
			r.Impact = 0
			r.Results = []hdf.RequirementResult{stMakeResult(hdf.Passed)}
		})
		cs := ComputeEffectiveChecksum(req, ecRefTime)
		require.NotNil(t, cs)
		assert.Equal(t, ecVectorZeroImpact, cs.Value)
	})
}

func TestComputeEffectiveChecksum_Deterministic(t *testing.T) {
	a := ComputeEffectiveChecksum(ecFailingReq(), ecRefTime)
	b := ComputeEffectiveChecksum(ecFailingReq(), ecRefTime)
	require.NotNil(t, a)
	require.NotNil(t, b)
	assert.Equal(t, a.Value, b.Value)
}

func TestComputeEffectiveChecksum_FlipsOnEffectiveFields(t *testing.T) {
	base := ComputeEffectiveChecksum(ecFailingReq(), ecRefTime).Value

	t.Run("status change flips", func(t *testing.T) {
		req := ecFailingReq()
		req.Results = []hdf.RequirementResult{stMakeResult(hdf.Passed)}
		cs := ComputeEffectiveChecksum(req, ecRefTime)
		assert.Equal(t, ecVectorPassedHalf, cs.Value)
		assert.NotEqual(t, base, cs.Value)
	})

	t.Run("impact override flips", func(t *testing.T) {
		req := ecFailingReq()
		req.StatusOverrides = []hdf.StatusOverride{{
			Type:      hdf.RiskAdjustment,
			Impact:    &hdf.ImpactOverride{Value: 0.2},
			Reason:    "environmental adjustment",
			AppliedBy: hdf.Identity{Identifier: "admin"},
			AppliedAt: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
			ExpiresAt: time.Date(2099, 12, 31, 0, 0, 0, 0, time.UTC),
		}}
		cs := ComputeEffectiveChecksum(req, ecRefTime)
		assert.NotEqual(t, base, cs.Value)
	})

	t.Run("disposition flips even when status unchanged", func(t *testing.T) {
		req := ecFailingReq()
		req.StatusOverrides = []hdf.StatusOverride{stMakeOverride(struct {
			Type      string
			Status    hdf.ResultStatus
			Reason    string
			AppliedAt time.Time
			ExpiresAt time.Time
		}{Type: "waiver", Status: hdf.Failed})}
		cs := ComputeEffectiveChecksum(req, ecRefTime)
		assert.NotEqual(t, base, cs.Value)
	})
}

func TestComputeEffectiveChecksum_StableUnderVolatileFields(t *testing.T) {
	base := ComputeEffectiveChecksum(ecFailingReq(), ecRefTime).Value

	req := ecFailingReq()
	req.Results[0].CodeDesc = "entirely different check description"
	req.Results[0].StartTime = time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC)
	msg := "sshd_config PermitRootLogin is set to yes"
	req.Results[0].Message = &msg
	req.Tags = map[string]any{"severity": "high", "nist": []string{"AC-6"}}
	req.Title = stPtrString("Some new title")

	assert.Equal(t, base, ComputeEffectiveChecksum(req, ecRefTime).Value,
		"checksum must ignore non-effective fields (results detail, tags, title)")
}

func TestComputeEffectiveChecksum_ExpiredOverrideFallsBack(t *testing.T) {
	req := ecFailingReq()
	req.StatusOverrides = []hdf.StatusOverride{stMakeOverride(struct {
		Type      string
		Status    hdf.ResultStatus
		Reason    string
		AppliedAt time.Time
		ExpiresAt time.Time
	}{Type: "waiver", Status: hdf.NotApplicable, ExpiresAt: time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)})}

	cs := ComputeEffectiveChecksum(req, ecRefTime)
	assert.Equal(t, ecVectorFailedHalf, cs.Value,
		"expired override must not govern: status falls back to results, disposition null")
}

func TestComputeEffectiveImpact(t *testing.T) {
	t.Run("base impact when no overrides", func(t *testing.T) {
		assert.InDelta(t, 0.5, ComputeEffectiveImpact(ecFailingReq(), ecRefTime), 1e-9)
	})

	t.Run("non-expired impact override wins", func(t *testing.T) {
		req := ecFailingReq()
		req.StatusOverrides = []hdf.StatusOverride{{
			Type:      hdf.RiskAdjustment,
			Impact:    &hdf.ImpactOverride{Value: 0.2},
			Reason:    "environmental adjustment",
			AppliedBy: hdf.Identity{Identifier: "admin"},
			AppliedAt: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
			ExpiresAt: time.Date(2099, 12, 31, 0, 0, 0, 0, time.UTC),
		}}
		assert.InDelta(t, 0.2, ComputeEffectiveImpact(req, ecRefTime), 1e-9)
	})

	t.Run("expired impact override ignored", func(t *testing.T) {
		req := ecFailingReq()
		req.StatusOverrides = []hdf.StatusOverride{{
			Type:      hdf.RiskAdjustment,
			Impact:    &hdf.ImpactOverride{Value: 0.2},
			Reason:    "environmental adjustment",
			AppliedBy: hdf.Identity{Identifier: "admin"},
			AppliedAt: time.Date(2019, 1, 1, 0, 0, 0, 0, time.UTC),
			ExpiresAt: time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
		}}
		assert.InDelta(t, 0.5, ComputeEffectiveImpact(req, ecRefTime), 1e-9)
	})

	t.Run("stored effectiveImpact honored when no overrides", func(t *testing.T) {
		req := ecFailingReq()
		v := 0.3
		req.EffectiveImpact = &v
		assert.InDelta(t, 0.3, ComputeEffectiveImpact(req, ecRefTime), 1e-9)
	})

	t.Run("most recently applied impact override wins regardless of array order", func(t *testing.T) {
		req := ecFailingReq()
		req.StatusOverrides = []hdf.StatusOverride{
			{
				Type:      hdf.RiskAdjustment,
				Impact:    &hdf.ImpactOverride{Value: 0.4},
				Reason:    "initial adjustment",
				AppliedBy: hdf.Identity{Identifier: "admin"},
				AppliedAt: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
				ExpiresAt: time.Date(2099, 12, 31, 0, 0, 0, 0, time.UTC),
			},
			{
				Type:      hdf.RiskAdjustment,
				Impact:    &hdf.ImpactOverride{Value: 0.1},
				Reason:    "superseding adjustment",
				AppliedBy: hdf.Identity{Identifier: "admin"},
				AppliedAt: time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC),
				ExpiresAt: time.Date(2099, 12, 31, 0, 0, 0, 0, time.UTC),
			},
		}
		assert.InDelta(t, 0.1, ComputeEffectiveImpact(req, ecRefTime), 1e-9)
	})

	t.Run("impact-less newer override does not mask an older impact-bearing one", func(t *testing.T) {
		req := ecFailingReq()
		waived := hdf.NotApplicable
		req.StatusOverrides = []hdf.StatusOverride{
			{
				Type:      hdf.RiskAdjustment,
				Impact:    &hdf.ImpactOverride{Value: 0.2},
				Reason:    "environmental adjustment",
				AppliedBy: hdf.Identity{Identifier: "admin"},
				AppliedAt: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
				ExpiresAt: time.Date(2099, 12, 31, 0, 0, 0, 0, time.UTC),
			},
			{
				Type:      hdf.OverrideTypeWaiver,
				Status:    &waived,
				Reason:    "risk accepted",
				AppliedBy: hdf.Identity{Identifier: "admin"},
				AppliedAt: time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC),
				ExpiresAt: time.Date(2099, 12, 31, 0, 0, 0, 0, time.UTC),
			},
		}
		assert.InDelta(t, 0.2, ComputeEffectiveImpact(req, ecRefTime), 1e-9)
	})
}

func TestComputeDisposition(t *testing.T) {
	t.Run("nil when no overrides", func(t *testing.T) {
		assert.Nil(t, ComputeDisposition(ecFailingReq(), ecRefTime))
	})

	t.Run("governing non-expired override type", func(t *testing.T) {
		req := ecFailingReq()
		req.StatusOverrides = []hdf.StatusOverride{stMakeOverride(struct {
			Type      string
			Status    hdf.ResultStatus
			Reason    string
			AppliedAt time.Time
			ExpiresAt time.Time
		}{Type: "waiver", Status: hdf.NotApplicable})}
		d := ComputeDisposition(req, ecRefTime)
		require.NotNil(t, d)
		assert.Equal(t, hdf.OverrideTypeWaiver, *d)
	})

	t.Run("stored disposition honored when no overrides", func(t *testing.T) {
		req := ecFailingReq()
		d := hdf.FalsePositive
		req.Disposition = &d
		got := ComputeDisposition(req, ecRefTime)
		require.NotNil(t, got)
		assert.Equal(t, hdf.FalsePositive, *got)
	})

	t.Run("nil when all overrides expired", func(t *testing.T) {
		req := ecFailingReq()
		req.StatusOverrides = []hdf.StatusOverride{stMakeOverride(struct {
			Type      string
			Status    hdf.ResultStatus
			Reason    string
			AppliedAt time.Time
			ExpiresAt time.Time
		}{Type: "waiver", Status: hdf.NotApplicable, ExpiresAt: time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)})}
		assert.Nil(t, ComputeDisposition(req, ecRefTime))
	})

	t.Run("most recently applied override type wins regardless of array order", func(t *testing.T) {
		req := ecFailingReq()
		waived := hdf.NotApplicable
		req.StatusOverrides = []hdf.StatusOverride{
			{
				Type:      hdf.OverrideTypeWaiver,
				Status:    &waived,
				Reason:    "risk accepted",
				AppliedBy: hdf.Identity{Identifier: "admin"},
				AppliedAt: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
				ExpiresAt: time.Date(2099, 12, 31, 0, 0, 0, 0, time.UTC),
			},
			{
				Type:      hdf.RiskAdjustment,
				Impact:    &hdf.ImpactOverride{Value: 0.2},
				Reason:    "superseding adjustment",
				AppliedBy: hdf.Identity{Identifier: "admin"},
				AppliedAt: time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC),
				ExpiresAt: time.Date(2099, 12, 31, 0, 0, 0, 0, time.UTC),
			},
		}
		d := ComputeDisposition(req, ecRefTime)
		require.NotNil(t, d)
		assert.Equal(t, hdf.RiskAdjustment, *d)
	})
}

func TestStampEffectiveChecksums(t *testing.T) {
	docJSON := `{
	  "timestamp": "2026-07-01T00:00:00Z",
	  "baselines": [{"requirements": [
	    {"id": "R1", "impact": 0.5, "tags": {}, "descriptions": [],
	     "results": [{"status": "failed", "codeDesc": "t", "startTime": "2025-01-01T00:00:00Z"}]},
	    {"id": "R2", "impact": 0.7, "tags": {}, "descriptions": [],
	     "results": [{"status": "failed", "codeDesc": "t", "startTime": "2025-01-01T00:00:00Z"}],
	     "statusOverrides": [{"type": "waiver", "status": "notApplicable", "reason": "r",
	       "appliedBy": {"identifier": "admin"}, "appliedAt": "2025-01-01T00:00:00Z",
	       "expiresAt": "2099-12-31T00:00:00Z"}]}
	  ]}],
	  "requirements": [
	    {"id": "R3", "impact": 0.5, "tags": {}, "descriptions": [],
	     "results": [{"status": "passed", "codeDesc": "t", "startTime": "2025-01-01T00:00:00Z"}]}
	  ]
	}`
	var doc map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(docJSON), &doc))

	require.NoError(t, StampEffectiveChecksums(doc, "2026-07-01T00:00:00Z"))

	getCS := func(reqs []interface{}, i int) map[string]interface{} {
		req := reqs[i].(map[string]interface{})
		cs, ok := req["effectiveChecksum"].(map[string]interface{})
		require.True(t, ok, "requirement %d must be stamped", i)
		return cs
	}

	baselineReqs := doc["baselines"].([]interface{})[0].(map[string]interface{})["requirements"].([]interface{})
	assert.Equal(t, ecVectorFailedHalf, getCS(baselineReqs, 0)["value"])
	assert.Equal(t, ecVectorWaivedNA, getCS(baselineReqs, 1)["value"])

	topReqs := doc["requirements"].([]interface{})
	assert.Equal(t, ecVectorPassedHalf, getCS(topReqs, 0)["value"])
}

func TestStampEffectiveChecksums_SkipsUntypeableRequirement(t *testing.T) {
	docJSON := `{
	  "timestamp": "2026-07-01T00:00:00Z",
	  "baselines": [{"requirements": [
	    {"id": "BAD", "impact": 0.5, "tags": {}, "descriptions": [],
	     "results": [{"status": "failed", "codeDesc": "t", "startTime": "2025-01-01T00:00:00Z"}],
	     "statusOverrides": [{"type": 123, "status": 456, "expiresAt": "2099-12-31T00:00:00Z"}]},
	    {"id": "GOOD", "impact": 0.5, "tags": {}, "descriptions": [],
	     "results": [{"status": "failed", "codeDesc": "t", "startTime": "2025-01-01T00:00:00Z"}]}
	  ]}]
	}`
	var doc map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(docJSON), &doc))

	require.NoError(t, StampEffectiveChecksums(doc, "2026-07-01T00:00:00Z"),
		"a requirement that cannot be typed must not fail the whole document")

	reqs := doc["baselines"].([]interface{})[0].(map[string]interface{})["requirements"].([]interface{})
	bad := reqs[0].(map[string]interface{})
	good := reqs[1].(map[string]interface{})
	_, badStamped := bad["effectiveChecksum"]
	assert.False(t, badStamped, "untypeable requirement stays unstamped")
	cs, ok := good["effectiveChecksum"].(map[string]interface{})
	require.True(t, ok, "well-formed sibling must still be stamped")
	assert.Equal(t, ecVectorFailedHalf, cs["value"])
}
