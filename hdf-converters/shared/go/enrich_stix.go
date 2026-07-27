package shared

import (
	"encoding/json"
	"fmt"
)

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
func EnrichStix(resultsInput, bundleInput []byte) ([]byte, error) {
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
	}
	return ref
}

// appendExternalReference appends a reference to a container's
// externalReferences[] (results root or a requirement), creating it if absent.
func appendExternalReference(container map[string]interface{}, ref map[string]interface{}) {
	existing, _ := container["externalReferences"].([]interface{})
	container["externalReferences"] = append(existing, ref)
}
