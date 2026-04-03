// Package amend provides operations for merging HDF amendments into results.
package amend

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"time"
)

// MergeAmendments applies amendments to an HDF results document.
// It operates on map[string]interface{} to preserve extra fields.
// The original results bytes are not modified; the returned bytes are a new document.
func MergeAmendments(results, amendments []byte) ([]byte, error) {
	var doc map[string]interface{}
	if err := json.Unmarshal(results, &doc); err != nil {
		return nil, fmt.Errorf("failed to parse results JSON: %w", err)
	}

	var amendDoc map[string]interface{}
	if err := json.Unmarshal(amendments, &amendDoc); err != nil {
		return nil, fmt.Errorf("failed to parse amendments JSON: %w", err)
	}

	overridesRaw, ok := amendDoc["overrides"]
	if !ok {
		// No overrides — return results unchanged.
		return json.MarshalIndent(doc, "", "  ")
	}

	overrides, ok := overridesRaw.([]interface{})
	if !ok {
		return nil, fmt.Errorf("amendments overrides field is not an array")
	}

	if len(overrides) == 0 {
		return json.MarshalIndent(doc, "", "  ")
	}

	// Compute previousChecksum from the original results before any modification.
	checksum := computeSHA256(results)

	// Apply each override to matching requirements.
	for _, ovRaw := range overrides {
		ov, ok := ovRaw.(map[string]interface{})
		if !ok {
			continue
		}
		reqID, _ := ov["requirementId"].(string)
		if reqID == "" {
			continue
		}
		baselineRef, _ := ov["baselineRef"].(string)
		applyOverrideToDoc(doc, ov, reqID, baselineRef)
	}

	// Set previousChecksum on the merged output.
	doc["previousChecksum"] = map[string]interface{}{
		"algorithm": "sha256",
		"value":     checksum,
	}

	return json.MarshalIndent(doc, "", "  ")
}

// applyOverrideToDoc finds the matching requirement across all baselines and
// applies the override.
func applyOverrideToDoc(doc, override map[string]interface{}, reqID, baselineRef string) {
	baselinesRaw, ok := doc["baselines"]
	if !ok {
		return
	}
	baselines, ok := baselinesRaw.([]interface{})
	if !ok {
		return
	}

	for _, bRaw := range baselines {
		baseline, ok := bRaw.(map[string]interface{})
		if !ok {
			continue
		}

		// If baselineRef is specified, only apply to that baseline.
		if baselineRef != "" {
			name, _ := baseline["name"].(string)
			if name != baselineRef {
				continue
			}
		}

		requirementsRaw, ok := baseline["requirements"]
		if !ok {
			continue
		}
		requirements, ok := requirementsRaw.([]interface{})
		if !ok {
			continue
		}

		for _, rRaw := range requirements {
			req, ok := rRaw.(map[string]interface{})
			if !ok {
				continue
			}
			id, _ := req["id"].(string)
			if id != reqID {
				continue
			}

			// Set effectiveStatus from the override's status, validating it first.
			if statusRaw, ok := override["status"]; ok {
				validStatuses := map[string]bool{
					"passed": true, "failed": true, "notApplicable": true,
					"notReviewed": true, "error": true,
				}
				status, isString := statusRaw.(string)
				if isString && validStatuses[status] {
					req["effectiveStatus"] = status
				}
			}

			// Build a statusOverride entry from the standalone override fields.
			statusOverride := buildStatusOverride(override)

			// Append to statusOverrides array.
			existing, _ := req["statusOverrides"].([]interface{})
			req["statusOverrides"] = append(existing, statusOverride)
		}
	}
}

// buildStatusOverride creates a statusOverride map from a standalone override.
func buildStatusOverride(override map[string]interface{}) map[string]interface{} {
	so := make(map[string]interface{})

	// Copy relevant fields from the standalone override into the inline format.
	for _, key := range []string{"type", "status", "reason", "appliedAt", "appliedBy", "expiresAt", "evidence", "previousChecksum", "signature"} {
		if v, ok := override[key]; ok {
			so[key] = v
		}
	}

	return so
}

// computeSHA256 returns the hex-encoded SHA-256 checksum of the data.
func computeSHA256(data []byte) string {
	h := sha256.Sum256(data)
	return fmt.Sprintf("%x", h[:])
}

// ParsedOverride holds a parsed standalone override for display purposes.
type ParsedOverride struct {
	RequirementID string  `json:"requirementId"`
	Type          string  `json:"type"`
	Status        string  `json:"status"`
	Reason        string  `json:"reason"`
	ExpiresAt     *string `json:"expiresAt,omitempty"`
	AppliedAt     *string `json:"appliedAt,omitempty"`
	BaselineRef   *string `json:"baselineRef,omitempty"`
}

// ListOverrides parses an amendments document and returns the overrides for display.
func ListOverrides(amendments []byte) (name, systemRef string, overrides []ParsedOverride, err error) {
	var doc map[string]interface{}
	if err := json.Unmarshal(amendments, &doc); err != nil {
		return "", "", nil, fmt.Errorf("failed to parse amendments JSON: %w", err)
	}

	name, _ = doc["name"].(string)
	systemRef, _ = doc["systemRef"].(string)

	overridesRaw, ok := doc["overrides"]
	if !ok {
		return name, systemRef, nil, nil
	}

	ovList, ok := overridesRaw.([]interface{})
	if !ok {
		return "", "", nil, fmt.Errorf("overrides field is not an array")
	}

	parsed := make([]ParsedOverride, 0, len(ovList))
	for _, ovRaw := range ovList {
		ov, ok := ovRaw.(map[string]interface{})
		if !ok {
			continue
		}
		p := ParsedOverride{}
		p.RequirementID, _ = ov["requirementId"].(string)
		p.Type, _ = ov["type"].(string)
		p.Status, _ = ov["status"].(string)
		p.Reason, _ = ov["reason"].(string)
		if v, ok := ov["expiresAt"].(string); ok {
			p.ExpiresAt = &v
		}
		if v, ok := ov["appliedAt"].(string); ok {
			p.AppliedAt = &v
		}
		if v, ok := ov["baselineRef"].(string); ok {
			p.BaselineRef = &v
		}
		parsed = append(parsed, p)
	}

	return name, systemRef, parsed, nil
}

// ChainVerifyResult holds the result of verifying an amendment chain against results.
type ChainVerifyResult struct {
	ExpirationResult *VerifyResult `json:"expiration"`
	ChainValid       bool          `json:"chainValid"`
	ChainMessage     string        `json:"chainMessage,omitempty"`
	MissingReqIDs    []string      `json:"missingRequirementIds,omitempty"`
}

// VerifyChain performs full amendment verification including expiration,
// previousChecksum chain, and requirementId existence.
func VerifyChain(resultsData, amendmentsData []byte) (*ChainVerifyResult, error) {
	// Step 1: Expiration check
	expResult, err := VerifyAmendments(amendmentsData)
	if err != nil {
		return nil, err
	}

	result := &ChainVerifyResult{
		ExpirationResult: expResult,
		ChainValid:       true,
	}

	// Step 2: Check previousChecksum chain
	var amendDoc map[string]interface{}
	if err := json.Unmarshal(amendmentsData, &amendDoc); err != nil {
		return nil, fmt.Errorf("failed to parse amendments: %w", err)
	}

	if prevChecksum, ok := amendDoc["previousChecksum"].(map[string]interface{}); ok {
		expectedValue, _ := prevChecksum["value"].(string)
		if expectedValue != "" {
			hash := sha256.Sum256(resultsData)
			actualValue := fmt.Sprintf("%x", hash)
			if actualValue != expectedValue {
				result.ChainValid = false
				result.ChainMessage = fmt.Sprintf("previousChecksum mismatch: expected %s, got %s", expectedValue, actualValue)
			} else {
				result.ChainMessage = "previousChecksum verified"
			}
		}
	} else {
		result.ChainMessage = "no previousChecksum present (chain not established)"
	}

	// Step 3: Check requirementIds exist in results
	var resultsDoc map[string]interface{}
	if err := json.Unmarshal(resultsData, &resultsDoc); err != nil {
		return nil, fmt.Errorf("failed to parse results: %w", err)
	}

	reqIDs := make(map[string]bool)
	baselines, _ := resultsDoc["baselines"].([]interface{})
	for _, bRaw := range baselines {
		b, ok := bRaw.(map[string]interface{})
		if !ok {
			continue
		}
		reqs, _ := b["requirements"].([]interface{})
		for _, rRaw := range reqs {
			r, ok := rRaw.(map[string]interface{})
			if !ok {
				continue
			}
			if id, ok := r["id"].(string); ok {
				reqIDs[id] = true
			}
		}
	}

	overrides, _ := amendDoc["overrides"].([]interface{})
	for _, ovRaw := range overrides {
		ov, ok := ovRaw.(map[string]interface{})
		if !ok {
			continue
		}
		reqID, ok := ov["requirementId"].(string)
		if !ok {
			continue
		}
		if !reqIDs[reqID] {
			result.MissingReqIDs = append(result.MissingReqIDs, reqID)
		}
	}

	return result, nil
}

// VerifyResult holds the verification status of an amendments document.
type VerifyResult struct {
	TotalOverrides int  `json:"totalOverrides"`
	ValidOverrides int  `json:"validOverrides"`
	ExpiredCount   int  `json:"expiredOverrides"`
	HasErrors      bool `json:"hasErrors"`
}

// VerifyAmendments checks that all overrides have non-expired expiresAt dates.
func VerifyAmendments(amendments []byte) (*VerifyResult, error) {
	var doc map[string]interface{}
	if err := json.Unmarshal(amendments, &doc); err != nil {
		return nil, fmt.Errorf("failed to parse amendments JSON: %w", err)
	}

	overridesRaw, ok := doc["overrides"]
	if !ok {
		return &VerifyResult{}, nil
	}

	ovList, ok := overridesRaw.([]interface{})
	if !ok {
		return nil, fmt.Errorf("overrides field is not an array")
	}

	result := &VerifyResult{
		TotalOverrides: len(ovList),
	}

	now := time.Now()

	for _, ovRaw := range ovList {
		ov, ok := ovRaw.(map[string]interface{})
		if !ok {
			continue
		}

		expiresStr, ok := ov["expiresAt"].(string)
		if !ok {
			// No expiration — count as valid (schema enforces this field).
			result.ValidOverrides++
			continue
		}

		expiresAt, err := time.Parse(time.RFC3339, expiresStr)
		if err != nil {
			result.HasErrors = true
			continue
		}

		if expiresAt.Before(now) {
			result.ExpiredCount++
		} else {
			result.ValidOverrides++
		}
	}

	result.HasErrors = result.HasErrors || result.ExpiredCount > 0

	return result, nil
}
