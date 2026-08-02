package diff

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"

	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	hdfutil "github.com/mitre/hdf-libs/hdf-utilities/go/v3"
)

// effectiveFields is the canonical hash input for ComputeEffectiveChecksum.
// Field order is the canonical serialization order; both language
// implementations must emit identical bytes.
type effectiveFields struct {
	Status      string  `json:"status"`
	Impact      float64 `json:"impact"`
	Disposition *string `json:"disposition"`
}

// overrideWindows maps schema overrides onto the shared neutral selection
// shape (applied/expiry window only; eligibility is passed separately).
func overrideWindows(overrides []hdf.StatusOverride) []hdfutil.StatusOverrideInput {
	windows := make([]hdfutil.StatusOverrideInput, len(overrides))
	for i := range overrides {
		windows[i] = hdfutil.StatusOverrideInput{
			AppliedAt: overrides[i].AppliedAt,
			ExpiresAt: overrides[i].ExpiresAt,
		}
	}
	return windows
}

// ComputeEffectiveImpact determines the effective impact of a requirement:
// the most recently applied non-expired override carrying an impact value
// wins (the schema's definition of effectiveImpact, selected by the shared
// governing helper); with no overrides, a stored effectiveImpact field is
// honored; otherwise the base impact.
func ComputeEffectiveImpact(req hdf.EvaluatedRequirement, referenceTimestamp string) float64 {
	if len(req.StatusOverrides) > 0 {
		ref := hdfutil.ParseTimestamp(referenceTimestamp)
		carriesImpact := func(i int) bool { return req.StatusOverrides[i].Impact != nil }
		if i := hdfutil.GoverningOverrideIndex(overrideWindows(req.StatusOverrides), carriesImpact, ref); i >= 0 {
			return req.StatusOverrides[i].Impact.Value
		}
		return req.Impact
	}
	if req.EffectiveImpact != nil {
		return *req.EffectiveImpact
	}
	return req.Impact
}

// ComputeDisposition returns the Override_Type of the governing (most
// recently applied non-expired) override, a stored disposition field when no
// overrides are present, or nil when nothing governs.
func ComputeDisposition(req hdf.EvaluatedRequirement, referenceTimestamp string) *hdf.OverrideType {
	if len(req.StatusOverrides) > 0 {
		ref := hdfutil.ParseTimestamp(referenceTimestamp)
		all := func(int) bool { return true }
		if i := hdfutil.GoverningOverrideIndex(overrideWindows(req.StatusOverrides), all, ref); i >= 0 {
			return &req.StatusOverrides[i].Type
		}
		return nil
	}
	return req.Disposition
}

// ComputeEffectiveChecksum hashes the resolved effective posture of a
// requirement: sha256 over the canonical JSON of
// {"status":<resolved>,"impact":<resolved>,"disposition":<type|null>}.
// It flips exactly when the requirement's operative status, impact, or
// disposition changes, and is stable under all other document churn
// (results detail, timestamps, tags). referenceTimestamp anchors override
// expiry — pass the document timestamp, never wall clock, for determinism.
func ComputeEffectiveChecksum(req hdf.EvaluatedRequirement, referenceTimestamp string) *hdf.Checksum {
	fields := effectiveFields{
		Status: ComputeEffectiveStatus(req, referenceTimestamp),
		Impact: ComputeEffectiveImpact(req, referenceTimestamp),
	}
	if d := ComputeDisposition(req, referenceTimestamp); d != nil {
		s := string(*d)
		fields.Disposition = &s
	}

	raw, err := json.Marshal(fields)
	if err != nil {
		return nil
	}
	hash := sha256.Sum256(raw)
	return &hdf.Checksum{
		Algorithm: hdf.Sha256,
		Value:     hex.EncodeToString(hash[:]),
	}
}

// StampEffectiveChecksums sets effectiveChecksum on every requirement of a
// map-decoded hdf-results document (baselines[].requirements and any
// top-level requirements array), leaving all other fields untouched. Used by
// document-rewriting tooling (hdf convert, amendment merge) that operates on
// maps to preserve unknown/extension fields.
func StampEffectiveChecksums(doc map[string]interface{}, referenceTimestamp string) error {
	stampList := func(reqsRaw interface{}) error {
		reqs, ok := reqsRaw.([]interface{})
		if !ok {
			return nil
		}
		for _, rRaw := range reqs {
			reqMap, ok := rRaw.(map[string]interface{})
			if !ok {
				continue
			}
			raw, err := json.Marshal(reqMap)
			if err != nil {
				return err
			}
			var typed hdf.EvaluatedRequirement
			if err := json.Unmarshal(raw, &typed); err != nil {
				// A requirement too malformed to type cannot be hashed; the
				// field is optional, so it stays unstamped rather than
				// failing the whole document (mirrors the merge tooling's
				// tolerance of malformed overrides).
				continue
			}
			cs := ComputeEffectiveChecksum(typed, referenceTimestamp)
			if cs == nil {
				continue
			}
			reqMap["effectiveChecksum"] = map[string]interface{}{
				"algorithm": string(cs.Algorithm),
				"value":     cs.Value,
			}
		}
		return nil
	}

	if baselinesRaw, ok := doc["baselines"].([]interface{}); ok {
		for _, bRaw := range baselinesRaw {
			baseline, ok := bRaw.(map[string]interface{})
			if !ok {
				continue
			}
			if err := stampList(baseline["requirements"]); err != nil {
				return err
			}
		}
	}
	return stampList(doc["requirements"])
}
