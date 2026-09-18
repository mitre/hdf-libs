package hdfparsers

import (
	"encoding/json"
	"fmt"

	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
)

// safTargetDeprecation and safProvenanceDeprecation name the v3-native shape so
// users migrate off the legacy SAF-supplement convention.
const (
	safTargetDeprecation     = "deprecated: top-level 'target' (saf supplement target write) was normalized into components[]; emit a component directly — this compatibility shim will be removed in a future release"
	safProvenanceDeprecation = "deprecated: top-level 'passthrough' was normalized into extensions.passthrough; write provenance under extensions — this compatibility shim will be removed in a future release"
)

// validComponentType reports whether s is a v3 component/target type. Kept in
// sync with the TargetType enum; an unknown type is left for the schema to
// reject rather than guessed into a wrong shape.
func validComponentType(s string) bool {
	switch hdf.TargetType(s) {
	case hdf.AIModel, hdf.Application, hdf.Artifact, hdf.CloudAccount,
		hdf.CloudResource, hdf.ContainerImage, hdf.ContainerInstance,
		hdf.ContainerPlatform, hdf.Database, hdf.Dataset, hdf.Host,
		hdf.Network, hdf.Repository:
		return true
	}
	return false
}

// NormalizeSAFSupplement rewrites the legacy SAF-supplement top-level keys into
// v3-native carriers so a SAF-produced document becomes valid v3 before schema
// validation: `target` → a components[] entry (type validated; id → name and,
// for cloudAccount, accountId; boundary → labels.boundary; merged into a
// matching existing component rather than duplicated); `passthrough` →
// extensions.passthrough. It returns the (possibly rewritten) document plus a
// deprecation warning per rewritten key.
//
// It is deliberately narrow: input that is not JSON, or carries neither legacy
// key, is returned BYTE-IDENTICAL with no warnings. A target whose type is not a
// valid component type is left in place (with a warning) for the schema to
// reject — never guessed. Mirrors hdf-parsers/typescript normalizeSafSupplement.
func NormalizeSAFSupplement(input []byte) ([]byte, []string) {
	var doc map[string]any
	if err := json.Unmarshal(input, &doc); err != nil {
		return input, nil // not a JSON object — let the validator surface it
	}
	_, hasTarget := doc["target"]
	_, hasPassthrough := doc["passthrough"]
	if !hasTarget && !hasPassthrough {
		return input, nil // no legacy keys — byte-identical passthrough
	}

	var warnings []string

	if hasTarget {
		if rewritten := rewriteTarget(doc); rewritten {
			warnings = append(warnings, safTargetDeprecation)
		} else {
			warnings = append(warnings, fmt.Sprintf(
				"%s (target.type is not a recognized component type; left for schema validation)", safTargetDeprecation))
		}
	}

	if hasPassthrough {
		rewritePassthrough(doc)
		warnings = append(warnings, safProvenanceDeprecation)
	}

	out, err := json.Marshal(doc)
	if err != nil {
		return input, nil // unreachable for a map decoded from valid JSON
	}
	return out, warnings
}

// rewriteTarget lifts a legacy top-level `target` object into components[].
// Returns false (leaving `target` in place) when the target is not an object or
// its type is not a valid component type.
func rewriteTarget(doc map[string]any) bool {
	tgt, ok := doc["target"].(map[string]any)
	if !ok {
		return false
	}
	typ, _ := tgt["type"].(string)
	if !validComponentType(typ) {
		return false
	}
	id, _ := tgt["id"].(string)
	boundary, _ := tgt["boundary"].(string)

	comps, _ := doc["components"].([]any)

	// Merge into an existing component with the same name+type rather than
	// duplicating; otherwise append a new one.
	merged := false
	for i := range comps {
		c, ok := comps[i].(map[string]any)
		if !ok {
			continue
		}
		if name, _ := c["name"].(string); name == id {
			if ct, _ := c["type"].(string); ct == typ {
				applyBoundaryLabel(c, boundary)
				merged = true
				break
			}
		}
	}
	if !merged {
		c := map[string]any{"type": typ, "name": id}
		if typ == string(hdf.CloudAccount) {
			c["accountId"] = id
		}
		applyBoundaryLabel(c, boundary)
		comps = append(comps, c)
	}
	doc["components"] = comps
	delete(doc, "target")
	return true
}

// applyBoundaryLabel records the legacy target.boundary as a component label
// (the deferred first-class-field decision — ADR-0015). No-op for an empty
// boundary.
func applyBoundaryLabel(c map[string]any, boundary string) {
	if boundary == "" {
		return
	}
	labels, ok := c["labels"].(map[string]any)
	if !ok {
		labels = map[string]any{}
	}
	if _, exists := labels["boundary"]; !exists {
		labels["boundary"] = boundary
	}
	c["labels"] = labels
}

// rewritePassthrough moves the legacy top-level `passthrough` under
// extensions.passthrough, merging into any existing extensions without
// clobbering other keys.
func rewritePassthrough(doc map[string]any) {
	ext, ok := doc["extensions"].(map[string]any)
	if !ok {
		ext = map[string]any{}
	}
	if _, exists := ext["passthrough"]; !exists {
		ext["passthrough"] = doc["passthrough"]
	}
	doc["extensions"] = ext
	delete(doc, "passthrough")
}
