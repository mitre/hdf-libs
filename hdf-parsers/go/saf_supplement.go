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

// SAFSupplementOption adjusts NormalizeSAFSupplement; none is the plain parse path.
type SAFSupplementOption func(*safSupplementOptions)

type safSupplementOptions struct {
	mergePlatformComponent bool
}

// MergePlatformComponent lets a target absorb the lone component the caller
// built from an InSpec `platform` (no componentId, OS name standing in as the
// name). Only that caller knows where the component came from; on a plain parse
// the same shape is a genuine component and is never renamed.
func MergePlatformComponent() SAFSupplementOption {
	return func(o *safSupplementOptions) { o.mergePlatformComponent = true }
}

// NormalizeSAFSupplement rewrites the legacy SAF-supplement top-level keys into
// v3-native carriers so a SAF-produced document is valid v3 before validation:
// `target` → a components[] entry (type validated; id, or failing that name, →
// name; id alone → accountId for cloudAccount; labels and boundary → labels,
// boundary winning; merged into a same-name component rather than duplicated,
// and only with MergePlatformComponent into the platform-derived one);
// `passthrough` → extensions.passthrough. Returns the (possibly rewritten)
// document plus a deprecation warning per rewritten key. Input that is not JSON
// or carries neither key is returned BYTE-IDENTICAL with no warnings; a target of
// unmapped type is left in place, with a warning, for the schema to reject.
func NormalizeSAFSupplement(input []byte, opts ...SAFSupplementOption) ([]byte, []string) {
	var o safSupplementOptions
	for _, opt := range opts {
		opt(&o)
	}
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
		if reason := rewriteTarget(doc, o.mergePlatformComponent); reason == "" {
			warnings = append(warnings, safTargetDeprecation)
		} else {
			warnings = append(warnings, fmt.Sprintf("%s (%s; left for schema validation)", safTargetDeprecation, reason))
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
// Returns a non-empty reason, leaving `target` in place, when the target cannot
// be placed: it is not an object, its type is not a component type, or it has
// no identity and no component to take it. mergePlatform lets the component the
// v2 upgrade derived from `platform` take it, renaming that component.
func rewriteTarget(doc map[string]any, mergePlatform bool) string {
	const unmappedType = "target.type is not a recognized component type"
	tgt, ok := doc["target"].(map[string]any)
	if !ok {
		return unmappedType
	}
	typ, _ := tgt["type"].(string)
	if !validComponentType(typ) {
		return unmappedType
	}
	// SAF writes `id`; the classic Heimdall/InSpec target carries `name` instead.
	// Only an `id` is a provider identifier; a display name never becomes one.
	id, _ := tgt["id"].(string)
	name := id
	if name == "" {
		name, _ = tgt["name"].(string)
	}
	labels := stringLabels(tgt["labels"])
	// The first-class boundary field is the SAF carrier, so it wins over a
	// `labels.boundary` entry (the deferred first-class-field decision — ADR-0015).
	if boundary, _ := tgt["boundary"].(string); boundary != "" {
		labels["boundary"] = boundary
	}

	comps, _ := doc["components"].([]any)

	c := findComponent(comps, name, typ)
	if c == nil && mergePlatform {
		if c = platformComponent(comps, typ); c != nil && name != "" {
			c["name"] = name
		}
	}
	if c == nil && name == "" {
		return "target carries no id or name and matches no component"
	}
	if c == nil {
		c = map[string]any{"type": typ, "name": name}
		if typ == string(hdf.CloudAccount) && id != "" {
			c["accountId"] = id
		}
		comps = append(comps, c)
	}
	applyLabels(c, labels)
	doc["components"] = comps
	delete(doc, "target")
	return ""
}

// findComponent returns the existing component with this name and type, or nil.
// An empty name is no identity and matches nothing, so a component that lacks a
// name is never joined to a target that lacks one too.
func findComponent(comps []any, name, typ string) map[string]any {
	if name == "" {
		return nil
	}
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
