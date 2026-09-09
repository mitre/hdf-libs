// Package amend provides operations for merging HDF amendments into results.
package amend

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	diff "github.com/mitre/hdf-libs/hdf-diff/go/v3"
	hdfutil "github.com/mitre/hdf-libs/hdf-utilities/go/v3"
	validators "github.com/mitre/hdf-libs/hdf-validators/go/v3"
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

	if err := refuseDraft(amendDoc); err != nil {
		return nil, err
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

	// Re-stamp per-requirement effective checksums: overrides change the
	// effective posture the checksum hashes. Expiry is anchored to the
	// document timestamp for determinism.
	docTimestamp, _ := doc["timestamp"].(string)
	if err := diff.StampEffectiveChecksums(doc, docTimestamp); err != nil {
		return nil, fmt.Errorf("failed to stamp effective checksums: %w", err)
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

			applyOverrideToReq(req, override)
		}
	}
}

// applyOverrideToReq applies a single override to a matched requirement.
func applyOverrideToReq(req, override map[string]interface{}) {
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

	// Set effectiveImpact from the override's impact field.
	if impactObj, ok := override["impact"].(map[string]interface{}); ok {
		if val, ok := impactObj["value"].(float64); ok {
			req["effectiveImpact"] = val
		}
	}

	// Set disposition from the override's type.
	if ovType, ok := override["type"].(string); ok && ovType != "" {
		req["disposition"] = ovType
	}

	// Build a statusOverride entry and append to the array.
	statusOverride := buildStatusOverride(override)
	existing, _ := req["statusOverrides"].([]interface{})
	req["statusOverrides"] = append(existing, statusOverride)
}

// buildStatusOverride creates a statusOverride map from a standalone override.
func buildStatusOverride(override map[string]interface{}) map[string]interface{} {
	so := make(map[string]interface{})

	// Copy relevant fields from the standalone override into the inline format.
	for _, key := range []string{"type", "status", "impact", "reason", "appliedAt", "appliedBy", "expiresAt", "evidence", "previousChecksum", "signature"} {
		if v, ok := override[key]; ok {
			so[key] = v
		}
	}

	return so
}

// computeSHA256 returns the hex-encoded SHA-256 checksum of the data.
func computeSHA256(data []byte) string {
	return hdfutil.SHA256Hex(data)
}

// ParsedOverride holds a parsed standalone override for display purposes.
type ParsedOverride struct {
	RequirementID string   `json:"requirementId"`
	Type          string   `json:"type"`
	Status        string   `json:"status,omitempty"`
	Impact        *float64 `json:"impact,omitempty"`
	Reason        string   `json:"reason"`
	ExpiresAt     *string  `json:"expiresAt,omitempty"`
	AppliedAt     *string  `json:"appliedAt,omitempty"`
	BaselineRef   *string  `json:"baselineRef,omitempty"`
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
		if impactObj, ok := ov["impact"].(map[string]interface{}); ok {
			if val, ok := impactObj["value"].(float64); ok {
				p.Impact = &val
			}
		}
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

// ChainVerifyResult holds the result of verifying an amendments document
// against the results it claims to amend. ChainValid refers to the document's
// own previousChecksum link to that results file, which is a separate signal
// from VerifyResult.Chain (the links between the amendments themselves).
type ChainVerifyResult struct {
	ExpirationResult *VerifyResult `json:"expiration"`
	ChainEstablished bool          `json:"chainEstablished"`
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
			result.ChainEstablished = true
			actualValue := hdfutil.SHA256Hex(resultsData)
			if actualValue != expectedValue {
				result.ChainValid = false
				result.ChainMessage = fmt.Sprintf("previousChecksum mismatch: expected %s, got %s", expectedValue, actualValue)
			} else {
				result.ChainMessage = "previousChecksum matches the results document"
			}
		}
	}
	if !result.ChainEstablished {
		result.ChainMessage = "this document records no checksum of the results it amends"
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

// ChainStatus reports on the previousChecksum links between consecutive
// overrides. Valid is only meaningful when Established: a document that never
// populates previousChecksum has no chain to contradict, which is not a failure.
type ChainStatus struct {
	Established bool     `json:"established"`
	Valid       bool     `json:"valid"`
	Breaks      []string `json:"breaks,omitempty"`
}

// VerifyResult holds the verification status of an amendments document.
// ValidOverrides, ExpiredCount and InvalidCount partition TotalOverrides, so a
// summary built from them can never silently drop an amendment.
type VerifyResult struct {
	TotalOverrides int         `json:"totalOverrides"`
	ValidOverrides int         `json:"validOverrides"`
	ExpiredCount   int         `json:"expiredOverrides"`
	InvalidCount   int         `json:"invalidOverrides"`
	SchemaErrors   []string    `json:"schemaErrors,omitempty"`
	Chain          ChainStatus `json:"chain"`
	HasErrors      bool        `json:"hasErrors"`
}

// VerifyAmendments checks an amendments document three ways: it validates
// against the hdf-amendments schema, classifies every override as valid,
// expired or structurally invalid, and verifies the previousChecksum chain.
func VerifyAmendments(amendments []byte) (*VerifyResult, error) {
	var doc map[string]interface{}
	if err := json.Unmarshal(amendments, &doc); err != nil {
		return nil, fmt.Errorf("failed to parse amendments JSON: %w", err)
	}

	result := &VerifyResult{}

	// Structural validity is delegated to the schema rather than a required-field
	// list kept here, which would drift the moment hdf-amendments changes.
	invalid := make(map[int]bool)
	for _, e := range validators.ValidateAmendments(amendments).Errors {
		result.SchemaErrors = append(result.SchemaErrors, formatSchemaError(e))
		if i, ok := overrideIndex(e.Field); ok {
			invalid[i] = true
		}
	}

	overridesRaw, ok := doc["overrides"]
	if !ok {
		result.HasErrors = len(result.SchemaErrors) > 0
		return result, nil
	}

	ovList, ok := overridesRaw.([]interface{})
	if !ok {
		return nil, fmt.Errorf("overrides field is not an array")
	}

	result.TotalOverrides = len(ovList)
	now := time.Now()

	for i, ovRaw := range ovList {
		ov, isObject := ovRaw.(map[string]interface{})
		if !isObject {
			invalid[i] = true
			continue
		}
		if invalid[i] {
			continue
		}

		// Schema validation normally marks a missing or malformed expiresAt
		// invalid before this point. These two checks are the fallback for when
		// it could not run at all (an unloadable schema yields one unattributed
		// error), so expiry is never silently skipped.
		expiresStr, hasExpiry := ov["expiresAt"].(string)
		if !hasExpiry {
			invalid[i] = true
			continue
		}

		// ParseTimestamp accepts zone-less values as UTC (repo timestamp
		// convention); zero means unparseable.
		expiresAt := hdfutil.ParseTimestamp(expiresStr)
		if expiresAt.IsZero() {
			invalid[i] = true
			continue
		}

		if expiresAt.Before(now) {
			result.ExpiredCount++
		} else {
			result.ValidOverrides++
		}
	}

	result.InvalidCount = len(invalid)
	result.Chain = verifyOverrideChain(ovList)
	result.HasErrors = result.ExpiredCount > 0 || result.InvalidCount > 0 ||
		len(result.SchemaErrors) > 0 || (result.Chain.Established && !result.Chain.Valid)

	return result, nil
}

// FailureSummary names every failing dimension of a verification result, so a
// caller's error message says what to fix rather than only that something is
// wrong. Empty when the document verifies.
func (r *VerifyResult) FailureSummary() string {
	var reasons []string
	if r.ExpiredCount > 0 {
		reasons = append(reasons, fmt.Sprintf("%d expired", r.ExpiredCount))
	}
	if r.InvalidCount > 0 {
		reasons = append(reasons, fmt.Sprintf("%d invalid", r.InvalidCount))
	}
	if len(r.SchemaErrors) > 0 && r.InvalidCount == 0 {
		reasons = append(reasons, "document is invalid")
	}
	if r.Chain.Established && !r.Chain.Valid {
		reasons = append(reasons, "amendment chain is broken")
	}
	return strings.Join(reasons, ", ")
}

// refuseDraft rejects a document still carrying the _draft marker.
func refuseDraft(doc map[string]interface{}) error {
	if draft, _ := doc["_draft"].(bool); draft {
		return fmt.Errorf("amendments document is an incomplete draft: complete the override stubs and remove the \"_draft\" marker before applying")
	}
	return nil
}

// RefuseUnverified returns an error when an amendments document must not be
// applied. Its scope is the document itself — structure, expiry and chain — so
// apply refuses everything a one-argument `hdf amend verify` refuses.
//
// It deliberately does NOT include the results-pair checks the two-argument
// verify adds. An override naming a requirement absent from these particular
// results is normal: one amendments document may cover a fleet and be applied
// per host, and MergeAmendments skips what it does not match.
//
// An expired amendment is refused rather than warned about: applying one
// re-creates the thing amendments exist to replace, a suppression with no end
// date. A broken chain is refused because the document was edited after it was
// written, and a structurally invalid one because it is not an amendments
// document. The remedy in every case is to fix the document, not to bypass this.
func RefuseUnverified(amendments []byte) error {
	var doc map[string]interface{}
	if err := json.Unmarshal(amendments, &doc); err != nil {
		return fmt.Errorf("failed to parse amendments JSON: %w", err)
	}
	// Ahead of the verify verdict: a draft's stubs are deliberately incomplete,
	// so its own remedy is more useful than the schema errors they produce.
	if err := refuseDraft(doc); err != nil {
		return err
	}

	result, err := VerifyAmendments(amendments)
	if err != nil {
		return err
	}
	if !result.HasErrors {
		return nil
	}
	summary := result.FailureSummary()
	if len(result.Chain.Breaks) > 0 {
		summary += " (" + strings.Join(result.Chain.Breaks, "; ") + ")"
	}
	for _, schemaErr := range result.SchemaErrors {
		summary += "\n  " + schemaErr
	}
	return fmt.Errorf("amendments document does not verify: %s", summary)
}

// verifyOverrideChain recomputes each override's checksum and compares it with
// the next override's recorded previousChecksum.
//
// What this proves: no amendment was edited in place after the chain was
// written. What it does not prove: an editor who recomputes every downstream
// link, or who drops trailing amendments, leaves an intact chain. Detecting
// either needs a signature or an externally anchored head.
func verifyOverrideChain(ovList []interface{}) ChainStatus {
	status := ChainStatus{Valid: true}

	for i := 1; i < len(ovList); i++ {
		if _, present := recordedPreviousChecksum(ovList[i]); present {
			status.Established = true
			break
		}
	}
	if !status.Established {
		return status
	}

	for i := 1; i < len(ovList); i++ {
		prev, isObject := ovList[i-1].(map[string]interface{})
		if !isObject {
			continue
		}
		recorded, present := recordedPreviousChecksum(ovList[i])
		switch {
		case !present:
			status.Valid = false
			status.Breaks = append(status.Breaks, fmt.Sprintf(
				"%s: no previousChecksum, but the document establishes a chain", overrideLabel(ovList[i], i)))
		case recorded != ChecksumOverride(prev):
			status.Valid = false
			status.Breaks = append(status.Breaks, fmt.Sprintf(
				"%s: previousChecksum does not match %s", overrideLabel(ovList[i], i), overrideLabel(ovList[i-1], i-1)))
		}
	}

	return status
}

// recordedPreviousChecksum returns the previousChecksum value an override
// carries. A null or malformed value reads as absent; the schema types this
// field as an object, so an explicit null is reported as a structural error
// rather than treated as a broken link.
func recordedPreviousChecksum(ovRaw interface{}) (string, bool) {
	ov, isObject := ovRaw.(map[string]interface{})
	if !isObject {
		return "", false
	}
	checksum, isObject := ov["previousChecksum"].(map[string]interface{})
	if !isObject {
		return "", false
	}
	value, isString := checksum["value"].(string)
	return value, isString && value != ""
}

// overrideLabel names an override for an operator: its position plus the
// requirement it adjudicates.
func overrideLabel(ovRaw interface{}, index int) string {
	label := fmt.Sprintf("override %d", index+1)
	if ov, isObject := ovRaw.(map[string]interface{}); isObject {
		if reqID, _ := ov["requirementId"].(string); reqID != "" {
			return fmt.Sprintf("%s (%s)", label, reqID)
		}
	}
	return label
}

// ChainOverrides stamps previousChecksum across overrides in document order,
// linking each to the one before it and leaving the first unlinked. Every
// authoring route calls this, so whether a document carries tamper-evidence does
// not depend on which command happened to write it.
func ChainOverrides(overrides []map[string]interface{}) error {
	prev := ""
	for i, ov := range overrides {
		if prev == "" {
			delete(ov, "previousChecksum")
		} else {
			ov["previousChecksum"] = map[string]interface{}{"algorithm": "sha256", "value": prev}
		}
		// Fails closed: an unhashable override must abort, not silently leave
		// the rest of the document unchained.
		sum, err := hdfutil.ChecksumJSON(ov)
		if err != nil {
			return fmt.Errorf("chaining override %d: %w", i, err)
		}
		prev = sum
	}
	return nil
}

// ChecksumOverride returns the canonical checksum of an override. This is the
// one definition of the amendment chain's hash: every authoring route writes it
// and `hdf amend verify` recomputes it, so the two cannot drift into a check
// that always passes.
//
// The canonical form lives in hdf-utilities so the converters, which cannot
// depend on hdf-diff, hash identically — see hdfutil.CanonicalJSON for the
// contract and its TypeScript counterpart.
func ChecksumOverride(override map[string]interface{}) string {
	sum, err := hdfutil.ChecksumJSON(override)
	if err != nil {
		return ""
	}
	return sum
}

// overrideIndex extracts N from a schema error field path like "overrides.2" or
// "overrides.2.expiresAt".
func overrideIndex(field string) (int, bool) {
	rest, found := strings.CutPrefix(field, "overrides.")
	if !found {
		return 0, false
	}
	if dot := strings.IndexByte(rest, '.'); dot >= 0 {
		rest = rest[:dot]
	}
	i, err := strconv.Atoi(rest)
	if err != nil {
		return 0, false
	}
	return i, true
}

// formatSchemaError renders one validation error the way ValidationResult does,
// minus the root-path noise.
func formatSchemaError(e validators.ValidationError) string {
	if e.Field == "" || e.Field == "(root)" {
		return e.Description
	}
	return e.Field + ": " + e.Description
}
