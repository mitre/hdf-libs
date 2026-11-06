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
// for cloudAccount, accountId, falling back to name; labels and boundary →
// labels; merged into a matching or platform-derived component rather than
// duplicated); `passthrough` →
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
		relocations := rewritePassthrough(doc)
		warnings = append(warnings, safProvenanceDeprecation)
		warnings = append(warnings, relocations...)
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
	// SAF writes `id`; the classic Heimdall/InSpec target carries `name` instead.
	id, _ := tgt["id"].(string)
	if id == "" {
		id, _ = tgt["name"].(string)
	}
	boundary, _ := tgt["boundary"].(string)
	labels := stringLabels(tgt["labels"])

	comps, _ := doc["components"].([]any)

	c := findComponent(comps, id, typ)
	if c == nil {
		if c = platformComponent(comps, typ); c != nil && id != "" {
			c["name"] = id
		}
	}
	if c == nil {
		c = map[string]any{"type": typ, "name": id}
		if typ == string(hdf.CloudAccount) {
			c["accountId"] = id
		}
		comps = append(comps, c)
	}
	applyLabels(c, labels)
	applyBoundaryLabel(c, boundary)
	doc["components"] = comps
	delete(doc, "target")
	return true
}

// findComponent returns the existing component with this name and type, or nil.
func findComponent(comps []any, name, typ string) map[string]any {
	for i := range comps {
		c, ok := comps[i].(map[string]any)
		if !ok {
			continue
		}
		if n, _ := c["name"].(string); n != name {
			continue
		}
		if ct, _ := c["type"].(string); ct == typ {
			return c
		}
	}
	return nil
}

// platformComponent returns the lone component the v2 upgrade derives from an
// InSpec `platform` (no componentId, OS name standing in as the name), which
// describes the same assessed thing as the target. Any other shape is a distinct
// component and is never renamed.
func platformComponent(comps []any, typ string) map[string]any {
	if len(comps) != 1 {
		return nil
	}
	c, ok := comps[0].(map[string]any)
	if !ok {
		return nil
	}
	if _, hasID := c["componentId"]; hasID {
		return nil
	}
	ct, _ := c["type"].(string)
	name, _ := c["name"].(string)
	osName, _ := c["osName"].(string)
	if ct != typ || name == "" || name != osName {
		return nil
	}
	return c
}

// stringLabels keeps the string-valued entries of a legacy target.labels;
// component labels admit only strings.
func stringLabels(v any) map[string]string {
	raw, _ := v.(map[string]any)
	out := map[string]string{}
	for k, val := range raw {
		if s, ok := val.(string); ok {
			out[k] = s
		}
	}
	return out
}

// applyLabels adds target labels to a component without overriding its own.
func applyLabels(c map[string]any, labels map[string]string) {
	if len(labels) == 0 {
		return
	}
	existing, ok := c["labels"].(map[string]any)
	if !ok {
		existing = map[string]any{}
	}
	for k, v := range labels {
		if _, exists := existing[k]; !exists {
			existing[k] = v
		}
	}
	c["labels"] = existing
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
// extensions.passthrough, then relocates any other key the producer left beside
// it into passthrough as well: `extensions` is a closed object, so a sibling it
// does not define makes the document invalid.
func rewritePassthrough(doc map[string]any) []string {
	ext, ok := doc["extensions"].(map[string]any)
	if !ok {
		ext = map[string]any{}
	}
	if _, exists := ext["passthrough"]; !exists {
		ext["passthrough"] = doc["passthrough"]
	}
	doc["extensions"] = ext
	delete(doc, "passthrough")
	return relocateExtensionSiblings(ext)
}

// extensionsDefinedMembers are the only keys `extensions` admits. Anything else
// a producer wrote beside them is exactly what `passthrough` is for.
var extensionsDefinedMembers = map[string]bool{
	"passthrough":        true,
	"rawSourceArtifacts": true,
}

// relocateExtensionSiblings moves undefined `extensions` keys into
// extensions.passthrough, returning a warning per key it could not move.
// Without this, a legacy document carrying something like extensions.audit
// normalizes into a document the closed `extensions` rejects.
func relocateExtensionSiblings(ext map[string]any) []string {
	var warnings []string
	pt, isObject := ext["passthrough"].(map[string]any)
	if _, present := ext["passthrough"]; present && !isObject {
		// passthrough is present but not an object, so nothing can be merged
		// into it. Leave the document alone and let the schema reject it rather
		// than reshape data we cannot place.
		for k := range ext {
			if !extensionsDefinedMembers[k] {
				warnings = append(warnings, fmt.Sprintf(
					"extensions.%s could not be relocated because extensions.passthrough is not an object; `extensions` is closed, so this document will not validate", k))
			}
		}
		return warnings
	}
	for k, v := range ext {
		if extensionsDefinedMembers[k] {
			continue
		}
		if pt == nil {
			pt = map[string]any{}
		}
		if _, clash := pt[k]; clash {
			warnings = append(warnings, fmt.Sprintf(
				"extensions.%s was dropped: `extensions` is closed and extensions.passthrough.%s already holds a value", k, k))
		} else {
			pt[k] = v
			warnings = append(warnings, fmt.Sprintf(
				"extensions.%s was moved into extensions.passthrough.%s; `extensions` accepts only its defined members", k, k))
		}
		delete(ext, k)
	}
	if pt != nil {
		ext["passthrough"] = pt
	}
	return warnings
}
