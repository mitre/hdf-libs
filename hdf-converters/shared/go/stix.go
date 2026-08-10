package shared

import (
	"encoding/json"
	"fmt"
	"strings"
)

// StixBundle is a parsed STIX 2.1 bundle. Objects are kept as raw maps so the
// enrichment pass can carry each one through losslessly (no field normalization).
type StixBundle struct {
	Type    string
	ID      string
	Objects []map[string]interface{}
}

// ParseStixBundle parses and validates a STIX 2.1 bundle. Shared by the enrich
// pass and (in a later phase) the CLI source fingerprint — one implementation,
// no fork.
func ParseStixBundle(input []byte) (*StixBundle, error) {
	if len(input) == 0 {
		return nil, fmt.Errorf("stix: empty input")
	}
	var raw struct {
		Type    string                   `json:"type"`
		ID      string                   `json:"id"`
		Objects []map[string]interface{} `json:"objects"`
	}
	if err := json.Unmarshal(input, &raw); err != nil {
		return nil, fmt.Errorf("stix: parsing bundle: %w", err)
	}
	if raw.Type != "bundle" {
		return nil, fmt.Errorf("stix: not a STIX bundle (type=%q)", raw.Type)
	}
	if raw.Objects == nil {
		return nil, fmt.Errorf("stix: bundle has no objects[]")
	}
	return &StixBundle{Type: raw.Type, ID: raw.ID, Objects: raw.Objects}, nil
}

// DetectStixBundle reports whether the input looks like a STIX 2.1 bundle
// (`{type:"bundle", objects:[…]}`), without erroring. Used by the CLI source
// fingerprint.
func DetectStixBundle(input []byte) bool {
	var probe struct {
		Type    string            `json:"type"`
		Objects []json.RawMessage `json:"objects"`
	}
	if err := json.Unmarshal(input, &probe); err != nil {
		return false
	}
	return probe.Type == "bundle" && probe.Objects != nil
}

// StixObjectID returns a STIX object's id ("" if absent).
func StixObjectID(obj map[string]interface{}) string {
	id, _ := obj["id"].(string)
	return id
}

// StixObjectCVEs returns the CVE ids a STIX object cites via its
// external_references (source_name "cve"). A STIX vulnerability records its CVE
// this way rather than in a native field (STIX 2.1 §4.19).
func StixObjectCVEs(obj map[string]interface{}) []string {
	refs, ok := obj["external_references"].([]interface{})
	if !ok {
		return nil
	}
	var cves []string
	for _, r := range refs {
		ref, ok := r.(map[string]interface{})
		if !ok {
			continue
		}
		if src, _ := ref["source_name"].(string); strings.EqualFold(src, "cve") {
			if id, _ := ref["external_id"].(string); id != "" {
				cves = append(cves, id)
			}
		}
	}
	return cves
}
