package shared

import (
	"encoding/json"
	"fmt"
	"time"

	hdfutil "github.com/mitre/hdf-libs/hdf-utilities/go/v3"
)

// EnrichOptions controls optional behavior of the enrich pass. The zero value
// is the informational-only pass (Phase 2 behavior).
type EnrichOptions struct {
	// RecomputeCVSS enables the opt-in E:H CVSS Threat recompute (Phase 5): for a
	// CVE-matched finding with a 3.1 base vector whose STIX object carries an
	// exploitation signal, author an inline riskAdjustment. Off by default.
	RecomputeCVSS bool
	// AsOf is the appliedAt timestamp for authored overrides; expiresAt =
	// AsOf + ReviewHorizon. Zero → time.Now() (injected in tests for determinism).
	AsOf time.Time
	// ReviewHorizon is how long an authored riskAdjustment stays valid before
	// review. Zero → defaultReviewHorizon (90 days).
	ReviewHorizon time.Duration
}

const defaultReviewHorizon = 90 * 24 * time.Hour

// EnrichStix overlays a STIX 2.1 bundle onto an existing HDF results document,
// attaching each STIX object as an inert externalReferences[] entry: a
// CVE-bearing object attaches to the finding whose requirementId is that CVE
// (fanning out to every match), and everything else — non-CVE objects and CVEs
// with no matching finding — attaches to the results root. Each entry carries
// the raw STIX object losslessly in `document`.
//
// The pass is informational only: it authors no overrides and fabricates no
// status/impact (the E:A recompute is a separate, opt-in step). The results
// document is preserved verbatim except for the appended references — it is
// manipulated structurally (not deserialized into typed HDF structs) so every
// pre-existing field, including timestamp strings, round-trips unchanged.
func EnrichStix(resultsInput, bundleInput []byte, opts ...EnrichOptions) ([]byte, error) {
	if err := ValidateJSONSize(resultsInput, "enrich-stix", 0); err != nil {
		return nil, err
	}
	if err := ValidateJSONSize(bundleInput, "enrich-stix", 0); err != nil {
		return nil, err
	}
	if len(resultsInput) == 0 {
		return nil, fmt.Errorf("enrich-stix: empty results input")
	}

	bundle, err := ParseStixBundle(bundleInput)
	if err != nil {
		return nil, err
	}

	var doc map[string]interface{}
	if err := json.Unmarshal(resultsInput, &doc); err != nil {
		return nil, fmt.Errorf("enrich-stix: parsing results: %w", err)
	}

	reqByID := indexRequirementsByID(doc)

	for _, obj := range bundle.Objects {
		matched := false
		for _, cve := range StixObjectCVEs(obj) {
			for _, req := range reqByID[cve] {
				appendExternalReference(req, buildStixRef(obj, "investigate"))
				matched = true
			}
		}
		if !matched {
			appendExternalReference(doc, buildStixRef(obj, "reference"))
		}
	}

	if len(opts) > 0 && opts[0].RecomputeCVSS {
		recomputeExploitation(bundle, reqByID, opts[0])
	}

	return json.MarshalIndent(doc, "", "  ")
}

// indexRequirementsByID maps each finding id to the (mutable) requirement maps
// carrying it. A slice, not a single value, so a CVE shared by findings in
// multiple baselines fans out to every match.
func indexRequirementsByID(doc map[string]interface{}) map[string][]map[string]interface{} {
	index := map[string][]map[string]interface{}{}
	baselines, ok := doc["baselines"].([]interface{})
	if !ok {
		return index
	}
	for _, b := range baselines {
		bm, ok := b.(map[string]interface{})
		if !ok {
			continue
		}
		reqs, ok := bm["requirements"].([]interface{})
		if !ok {
			continue
		}
		for _, r := range reqs {
			rm, ok := r.(map[string]interface{})
			if !ok {
				continue
			}
			if id, ok := rm["id"].(string); ok && id != "" {
				index[id] = append(index[id], rm)
			}
		}
	}
	return index
}

// buildStixRef builds an External_Reference envelope carrying the raw STIX
// object in `document`. rel is "investigate" for a live pivot on a matched
// finding, "reference" for bundle-wide context on the root.
func buildStixRef(obj map[string]interface{}, rel string) map[string]interface{} {
	ref := map[string]interface{}{
		"sourceName": "stix",
		"kind":       "threat-intel",
		"rel":        rel,
		"document":   obj,
	}
	if id := StixObjectID(obj); id != "" {
		ref["externalId"] = id
	} else {
		// No id → satisfy External_Reference's anyOf(externalId/href/description).
		ref["description"] = stixFallbackDescription(obj)
	}
	return ref
}

// stixFallbackDescription derives a human-readable description for a STIX object
// that carries no id, so its reference still satisfies External_Reference's
// anyOf constraint: the object's name when present, else a type-derived label.
func stixFallbackDescription(obj map[string]interface{}) string {
	if name, ok := obj["name"].(string); ok && name != "" {
		return name
	}
	if t, ok := obj["type"].(string); ok && t != "" {
		return "STIX " + t + " object"
	}
	return "STIX object"
}

// appendExternalReference appends a reference to a container's
// externalReferences[] (results root or a requirement), creating it if absent.
func appendExternalReference(container map[string]interface{}, ref map[string]interface{}) {
	existing, _ := container["externalReferences"].([]interface{})
	container["externalReferences"] = append(existing, ref)
}

// recomputeExploitation authors an inline riskAdjustment on each CVE-matched
// finding that (a) has a 3.1 base vector and (b) whose CVE carries a structural
// exploitation signal in the bundle. Applies CVSS Exploit Maturity E:H (the 3.1
// analog of 4.0 E:A) and recomputes the Threat score via the hdf-utilities
// engine. Skips (no fabrication) when a base vector is absent or non-3.1.
func recomputeExploitation(bundle *StixBundle, reqByID map[string][]map[string]interface{}, opt EnrichOptions) {
	appliedAt := opt.AsOf
	if appliedAt.IsZero() {
		appliedAt = time.Now()
	}
	appliedAt = appliedAt.UTC()
	horizon := opt.ReviewHorizon
	if horizon <= 0 {
		horizon = defaultReviewHorizon
	}
	expiresAt := appliedAt.Add(horizon)

	for cve, src := range exploitedCVEs(bundle) {
		for _, req := range reqByID[cve] {
			entry := findBaseVectorEntry(req, cve)
			if entry == nil {
				continue // no base vector → cannot recompute honestly; skip
			}
			baseVector, _ := entry["baseVector"].(string)
			score, err := hdfutil.ComputeCvssScore(baseVector + "/E:H")
			if err != nil {
				continue // non-3.1 (e.g. 4.0) or unparseable → skip, never fabricate
			}
			ov := buildRiskAdjustment(cve, baseVector, score, src, appliedAt, expiresAt)
			existing, _ := req["statusOverrides"].([]interface{})
			req["statusOverrides"] = append(existing, ov)
		}
	}
}

// exploitedCVEs maps each CVE with a structural exploitation signal in the
// bundle to the STIX object that provides it. A vulnerability is exploited if it
// is the sighting_of_ref of a sighting, the target_ref of a targets/exploits
// relationship, or referenced by an indicator/report's object_refs.
func exploitedCVEs(bundle *StixBundle) map[string]map[string]interface{} {
	vulnCVE := map[string]string{}
	for _, o := range bundle.Objects {
		if t, _ := o["type"].(string); t == "vulnerability" {
			for _, cve := range StixObjectCVEs(o) {
				vulnCVE[StixObjectID(o)] = cve
			}
		}
	}
	exploited := map[string]map[string]interface{}{}
	mark := func(vulnID string, src map[string]interface{}) {
		if cve, ok := vulnCVE[vulnID]; ok {
			if _, exists := exploited[cve]; !exists {
				exploited[cve] = src
			}
		}
	}
	for _, o := range bundle.Objects {
		switch t, _ := o["type"].(string); t {
		case "sighting":
			if ref, _ := o["sighting_of_ref"].(string); ref != "" {
				mark(ref, o)
			}
		case "relationship":
			rt, _ := o["relationship_type"].(string)
			if rt == "targets" || rt == "exploits" {
				if tgt, _ := o["target_ref"].(string); tgt != "" {
					mark(tgt, o)
				}
			}
		case "indicator", "report":
			if refs, ok := o["object_refs"].([]interface{}); ok {
				for _, r := range refs {
					if id, _ := r.(string); id != "" {
						mark(id, o)
					}
				}
			}
		}
	}
	return exploited
}

// findBaseVectorEntry returns the finding's cvss[] entry that carries a base
// vector for the given CVE (or a version-agnostic entry with no id), else nil.
func findBaseVectorEntry(req map[string]interface{}, cve string) map[string]interface{} {
	arr, ok := req["cvss"].([]interface{})
	if !ok {
		return nil
	}
	for _, e := range arr {
		m, ok := e.(map[string]interface{})
		if !ok {
			continue
		}
		if bv, _ := m["baseVector"].(string); bv != "" {
			if id, _ := m["id"].(string); id == "" || id == cve {
				return m
			}
		}
	}
	return nil
}

// buildRiskAdjustment builds the inline riskAdjustment Status_Override recording
// the E:H-recomputed CVSS Threat score and citing the STIX exploitation source.
func buildRiskAdjustment(cve, baseVector string, score hdfutil.CvssScore, src map[string]interface{}, appliedAt, expiresAt time.Time) map[string]interface{} {
	return map[string]interface{}{
		"type":   "riskAdjustment",
		"reason": fmt.Sprintf("%s actively exploited per STIX threat intelligence (%s); CVSS Threat recomputed with Exploit Maturity E:H.", cve, StixObjectID(src)),
		"impact": map[string]interface{}{"value": hdfutil.RoundImpact(score.TemporalScore / 10.0)},
		"appliedBy": map[string]interface{}{
			"type":       "other",
			"identifier": "hdf-enrich",
		},
		"appliedAt": appliedAt.Format(time.RFC3339),
		"expiresAt": expiresAt.Format(time.RFC3339),
		"cvss": map[string]interface{}{
			"version":       "3.1",
			"id":            cve,
			"baseVector":    baseVector,
			"baseScore":     score.BaseScore,
			"threatVector":  "E:H",
			"threatScore":   score.TemporalScore,
			"computedScore": score.TemporalScore,
		},
		"externalReferences": []interface{}{buildStixRef(src, "evidence")},
	}
}
