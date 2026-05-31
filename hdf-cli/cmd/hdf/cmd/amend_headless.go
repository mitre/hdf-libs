package cmd

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	validators "github.com/mitre/hdf-libs/hdf-validators/go/v3"
)

// validOverrideTypes is the set of Override_Type enum values from the
// hdf-amendments schema. Headless authoring is type-agnostic across all of them.
var validOverrideTypes = map[string]bool{
	"waiver":                 true,
	"attestation":            true,
	"poam":                   true,
	"inherited":              true,
	"falsePositive":          true,
	"riskAdjustment":         true,
	"operationalRequirement": true,
}

// --- Headless create ---

// runAmendCreateHeadless reads a spec (array of override specs, or an envelope
// object with an overrides[] array) from a file or stdin ("-"), fattens each
// spec into a complete Standalone_Override, validates the document against the
// hdf-amendments schema, and writes it.
func runAmendCreateHeadless(specPath, outputPath string) error {
	data, err := readSpecInput(specPath)
	if err != nil {
		return err
	}

	specs, envelope, err := parseSpecInput(data)
	if err != nil {
		return err
	}

	doc, err := buildAmendmentsFromSpecs(specs, envelope, time.Now().UTC())
	if err != nil {
		return err
	}

	output, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to serialize amendments: %w", err)
	}

	if res := validators.ValidateAmendments(output); !res.Valid {
		return fmt.Errorf("generated amendments failed schema validation: %s", res.Error())
	}

	if outputPath == "" {
		fmt.Println(string(output))
		return nil
	}
	if err := os.WriteFile(outputPath, append(output, '\n'), 0o600); err != nil { // #nosec G306 -- CLI writes user-provided path
		return fmt.Errorf("failed to write amendments: %w", err)
	}
	fmt.Fprintf(os.Stderr, "Created %s with %d amendments\n", outputPath, len(specs))
	return nil
}

// readSpecInput reads the spec from a file path, or from stdin when the path is
// "-" or empty.
func readSpecInput(specPath string) ([]byte, error) {
	if specPath == "" || specPath == "-" {
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			return nil, fmt.Errorf("failed to read spec from stdin: %w", err)
		}
		return data, nil
	}
	data, err := os.ReadFile(specPath) // #nosec G304 -- CLI reads user-provided path
	if err != nil {
		return nil, fmt.Errorf("failed to read spec file: %w", err)
	}
	return data, nil
}

// parseSpecInput accepts either a bare JSON array of override specs or an
// envelope object {name, overrides:[...], ...}. It returns the override specs
// and, for the envelope form, the doc-level metadata (minus overrides).
func parseSpecInput(data []byte) (specs []map[string]interface{}, envelope map[string]interface{}, err error) {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return nil, nil, fmt.Errorf("spec is empty")
	}

	if trimmed[0] == '[' {
		if err := json.Unmarshal(trimmed, &specs); err != nil {
			return nil, nil, fmt.Errorf("failed to parse spec array: %w", err)
		}
		if len(specs) == 0 {
			return nil, nil, fmt.Errorf("spec array is empty: provide at least one override")
		}
		return specs, nil, nil
	}

	var obj map[string]interface{}
	if err := json.Unmarshal(trimmed, &obj); err != nil {
		return nil, nil, fmt.Errorf("failed to parse spec object: %w", err)
	}
	ovRaw, ok := obj["overrides"].([]interface{})
	if !ok || len(ovRaw) == 0 {
		return nil, nil, fmt.Errorf("spec object must have a non-empty \"overrides\" array")
	}
	for i, raw := range ovRaw {
		m, ok := raw.(map[string]interface{})
		if !ok {
			return nil, nil, fmt.Errorf("override %d is not an object", i)
		}
		specs = append(specs, m)
	}
	delete(obj, "overrides")
	return specs, obj, nil
}

// fattenOverrideSpec expands a lean override spec into a complete
// Standalone_Override map. It is type-agnostic: per-type logic is limited to
// which default status (if any) satisfies the schema anyOf. Unknown fields
// (evidence, milestones, cvss, componentRef, ...) are carried through verbatim.
func fattenOverrideSpec(spec map[string]interface{}, now time.Time) (map[string]interface{}, error) {
	out := make(map[string]interface{}, len(spec)+2)
	for k, v := range spec {
		out[k] = v
	}

	amendType, _ := out["type"].(string)
	if amendType == "" {
		return nil, fmt.Errorf("override is missing required field \"type\"")
	}
	if !validOverrideTypes[amendType] {
		return nil, fmt.Errorf("invalid override type %q", amendType)
	}
	if reqID, _ := out["requirementId"].(string); reqID == "" {
		return nil, fmt.Errorf("override %q is missing required field \"requirementId\"", amendType)
	}
	if reason, _ := out["reason"].(string); reason == "" {
		return nil, fmt.Errorf("override for %v is missing required field \"reason\"", out["requirementId"])
	}

	if err := normalizeAppliedBy(out); err != nil {
		return nil, err
	}
	normalizeAppliedAt(out, now)
	if err := normalizeExpiresAt(out, now); err != nil {
		return nil, err
	}
	normalizeImpact(out)
	applyDefaultStatus(out, amendType)

	return out, nil
}

// normalizeAppliedBy expands a string appliedBy into an Identity object.
func normalizeAppliedBy(out map[string]interface{}) error {
	raw, present := out["appliedBy"]
	if !present {
		return fmt.Errorf("override for %v is missing required field \"appliedBy\"", out["requirementId"])
	}
	switch v := raw.(type) {
	case string:
		if v == "" {
			return fmt.Errorf("override for %v has an empty \"appliedBy\"", out["requirementId"])
		}
		out["appliedBy"] = map[string]interface{}{
			"type":       identityType(v),
			"identifier": v,
		}
	case map[string]interface{}:
		// Already an Identity object — leave as-is.
	default:
		return fmt.Errorf("override for %v has an invalid \"appliedBy\" (want string or object)", out["requirementId"])
	}
	return nil
}

// normalizeAppliedAt defaults appliedAt to now when absent.
func normalizeAppliedAt(out map[string]interface{}, now time.Time) {
	if s, _ := out["appliedAt"].(string); s == "" {
		out["appliedAt"] = now.Format(time.RFC3339)
	}
}

// normalizeExpiresAt resolves a relative duration or bare date into an absolute
// date-time. A full RFC3339 timestamp is kept verbatim. The now argument is the
// anchor for relative durations (so tests can pin the resolved date).
func normalizeExpiresAt(out map[string]interface{}, now time.Time) error {
	raw, _ := out["expiresAt"].(string)
	if raw == "" {
		return fmt.Errorf("override for %v is missing required field \"expiresAt\"", out["requirementId"])
	}
	if _, err := time.Parse(time.RFC3339, raw); err == nil {
		return nil
	}
	date, err := parseExpiryInput(raw, now)
	if err != nil {
		return fmt.Errorf("override for %v has an invalid \"expiresAt\": %w", out["requirementId"], err)
	}
	out["expiresAt"] = date + "T23:59:59Z"
	return nil
}

// normalizeImpact expands a numeric impact into an Impact_Override object.
func normalizeImpact(out map[string]interface{}) {
	switch v := out["impact"].(type) {
	case float64:
		out["impact"] = map[string]interface{}{"value": v}
	case json.Number:
		f, _ := v.Float64()
		out["impact"] = map[string]interface{}{"value": f}
	}
}

// applyDefaultStatus sets a type-appropriate default status when neither status
// nor impact was supplied, so the schema anyOf (status|impact) is satisfied.
func applyDefaultStatus(out map[string]interface{}, amendType string) {
	if _, hasStatus := out["status"]; hasStatus {
		return
	}
	if _, hasImpact := out["impact"]; hasImpact {
		return
	}
	if s := amendTypeToStatus(amendType); s != "" {
		out["status"] = s
	}
}

// buildAmendmentsFromSpecs fattens each spec, chains previousChecksum across the
// overrides, and assembles a complete hdf-amendments document. Envelope metadata
// (name, description, approvedBy, ...) is preserved; name is derived when absent.
func buildAmendmentsFromSpecs(specs []map[string]interface{}, envelope map[string]interface{}, now time.Time) (map[string]interface{}, error) {
	overrides := make([]map[string]interface{}, 0, len(specs))
	var prevChecksum string
	for i, spec := range specs {
		ov, err := fattenOverrideSpec(spec, now)
		if err != nil {
			return nil, fmt.Errorf("override %d: %w", i, err)
		}
		if prevChecksum != "" {
			ov["previousChecksum"] = map[string]interface{}{
				"algorithm": "sha256",
				"value":     prevChecksum,
			}
		}
		prevChecksum = checksumOverride(ov)
		overrides = append(overrides, ov)
	}

	doc := map[string]interface{}{}
	for k, v := range envelope {
		doc[k] = v
	}
	if _, ok := doc["name"].(string); !ok {
		doc["name"] = deriveAmendmentsName(specs)
	}
	doc["overrides"] = overrides
	return doc, nil
}

// checksumOverride returns the hex SHA-256 of an override's canonical JSON.
func checksumOverride(ov map[string]interface{}) string {
	raw, err := json.Marshal(ov)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// deriveAmendmentsName builds a default document name from the dominant type.
func deriveAmendmentsName(specs []map[string]interface{}) string {
	counts := map[string]int{}
	for _, s := range specs {
		if t, _ := s["type"].(string); t != "" {
			counts[t]++
		}
	}
	dominant := ""
	best := -1
	for _, t := range sortedKeys(counts) {
		if counts[t] > best {
			best = counts[t]
			dominant = t
		}
	}
	if dominant == "" {
		dominant = "amendment"
	}
	return fmt.Sprintf("%ss-%s", dominant, time.Now().Format("2006-01-02"))
}

func sortedKeys(m map[string]int) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// --- Draft ---

// runAmendDraft reads a results file, builds a draft amendments document of
// stubs (one per matching requirement), and writes it. The output is marked
// _draft and is rejected by `hdf amend apply` until completed.
func runAmendDraft(resultsPath, amendType, statusFilter, selectStr, expires, outputPath string) error {
	data, err := os.ReadFile(resultsPath) // #nosec G304 -- CLI reads user-provided path
	if err != nil {
		return fmt.Errorf("failed to read results file: %w", err)
	}
	var doc map[string]interface{}
	if err := json.Unmarshal(data, &doc); err != nil {
		return fmt.Errorf("failed to parse results: %w", err)
	}

	draft, err := buildDraftFromResults(doc, amendType, statusFilter, selectStr, expires, time.Now().UTC())
	if err != nil {
		return err
	}

	count := len(draft["overrides"].([]map[string]interface{}))
	output, err := json.MarshalIndent(draft, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to serialize draft: %w", err)
	}

	if outputPath == "" {
		fmt.Println(string(output))
		return nil
	}
	if err := os.WriteFile(outputPath, append(output, '\n'), 0o600); err != nil { // #nosec G306 -- CLI writes user-provided path
		return fmt.Errorf("failed to write draft: %w", err)
	}
	fmt.Fprintf(os.Stderr, "Wrote draft %s with %d %s stub(s). "+
		"Complete each stub and remove the \"_draft\" marker before applying.\n", outputPath, count, amendType)
	return nil
}

// buildDraftFromResults enumerates candidate requirements from a results doc and
// emits one incomplete override stub per match. The document is marked _draft so
// it cannot be applied until completed. It deliberately bakes in NO scan-specific
// data (e.g. base CVSS) — amendments are reusable org context merged at apply time.
func buildDraftFromResults(doc map[string]interface{}, amendType, statusFilter, selectStr, expires string, now time.Time) (map[string]interface{}, error) {
	if !validOverrideTypes[amendType] {
		return nil, fmt.Errorf("invalid override type %q", amendType)
	}

	resolvedExpiry, err := resolveDraftExpiry(expires, now)
	if err != nil {
		return nil, err
	}

	reqs := extractAllRequirements(doc)
	selectLower := strings.ToLower(strings.TrimSpace(selectStr))

	overrides := make([]map[string]interface{}, 0, len(reqs))
	for _, r := range reqs {
		if statusFilter != "" && r.Status != statusFilter {
			continue
		}
		if selectLower != "" && !matchesSelect(r, selectLower) {
			continue
		}
		overrides = append(overrides, draftStub(r, amendType, resolvedExpiry, now))
	}

	return map[string]interface{}{
		"_draft":    true,
		"name":      fmt.Sprintf("%ss-draft-%s", amendType, now.Format("2006-01-02")),
		"overrides": overrides,
	}, nil
}

// resolveDraftExpiry resolves a relative/absolute expiry, or returns "" when the
// author did not supply one (draft stubs may leave it blank for later editing).
// The now argument anchors relative durations (so tests can pin the resolved date).
func resolveDraftExpiry(expires string, now time.Time) (string, error) {
	if strings.TrimSpace(expires) == "" {
		return "", nil
	}
	if _, err := time.Parse(time.RFC3339, expires); err == nil {
		return expires, nil
	}
	date, err := parseExpiryInput(expires, now)
	if err != nil {
		return "", fmt.Errorf("invalid --expires value: %w", err)
	}
	return date + "T23:59:59Z", nil
}

// matchesSelect reports whether a requirement's id or title contains the
// (already lowercased) select substring.
func matchesSelect(r requirementInfo, selectLower string) bool {
	return strings.Contains(strings.ToLower(r.ID), selectLower) ||
		strings.Contains(strings.ToLower(r.Title), selectLower)
}

// draftStub builds one incomplete override stub for a requirement, pre-filling
// only requirementId/type/appliedAt/expiresAt and leaving type-appropriate
// fields blank for the author (or an enrichment script) to complete.
func draftStub(r requirementInfo, amendType, expiry string, now time.Time) map[string]interface{} {
	stub := map[string]interface{}{
		"type":          amendType,
		"requirementId": r.ID,
		"reason":        "",
		"appliedBy":     map[string]interface{}{"type": "", "identifier": ""},
		"appliedAt":     now.Format(time.RFC3339),
		"expiresAt":     expiry,
		"_label":        fmt.Sprintf("%s [%s]", r.Title, r.Status),
	}
	switch amendType {
	case "riskAdjustment":
		stub["impact"] = map[string]interface{}{"value": 0.0}
	case "poam":
		stub["status"] = ""
		stub["milestones"] = []interface{}{}
	default:
		stub["status"] = ""
	}
	return stub
}
