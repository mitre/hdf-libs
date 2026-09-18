// Merge engine — combine several results documents into one multi-baseline
// results document (ADR-0016). One baseline per input baseline, renamed
// `<tool>/<original>`; per-baseline provenance in labels; each input's root
// provenance kept verbatim under extensions["hdf-merge"]. Union semantics: no
// requirement is deduplicated, re-keyed or dropped. Deterministic for the same
// inputs in the same order. Kept at behavioural parity with the TS peer
// (hdf-engine/src/merge.ts); see merge_test.go / test/merge.test.ts.
package hdfengine

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
)

// MergeSource is one input to Merge: a results document and the name it is
// recorded under (its basename, or a caller-supplied label). Name is recorded
// as the sourceDocument label and in the root provenance; it is never a key.
type MergeSource struct {
	Name string
	Doc  hdf.HDFResults
}

// MergeWarningKind classifies a non-fatal condition Merge reports rather than
// silently resolving.
type MergeWarningKind string

const (
	// WarnDuplicateBaselineName: two merged baselines share a name even after
	// the tool prefix. Both are kept; Indices names every position that
	// collides. Read tools key on position (Match.BaselineIndex), so the
	// document stays correct, but name-keyed consumers (hdf diff, baselineRef)
	// cannot tell them apart.
	WarnDuplicateBaselineName MergeWarningKind = "duplicate-baseline-name"
	// WarnLabelOverwritten: a source baseline already carried one of the
	// provenance labels Merge writes (tool, toolVersion, sourceDocument); the
	// source value was replaced — or, for toolVersion when the new source has
	// no tool version, removed, since a stale version would describe the
	// wrong tool. Label names the key, Indices the merged position.
	WarnLabelOverwritten MergeWarningKind = "label-overwritten"
)

// MergeWarning is one reported condition. Name is the merged baseline name;
// Indices are merged baseline positions; Label is set for label warnings only.
type MergeWarning struct {
	Kind    MergeWarningKind `json:"kind"`
	Name    string           `json:"name,omitempty"`
	Indices []int            `json:"indices,omitempty"`
	Label   string           `json:"label,omitempty"`
}

// Provenance label keys written on every merged baseline (ADR-0016 §3).
const (
	LabelTool           = "tool"
	LabelToolVersion    = "toolVersion"
	LabelSourceDocument = "sourceDocument"
)

// mergeGeneratorName is the root generator.name of a merged document.
const mergeGeneratorName = "hdf-merge"

// mergeExtensionKey is the root extensions key carrying per-source provenance.
const mergeExtensionKey = "hdf-merge"

// Merge combines the sources, in order, into one results document. It returns
// the document, any warnings (never an error for a collision or overwrite), and
// an error only when there is nothing to merge. Inputs are not mutated.
func Merge(sources []MergeSource) (hdf.HDFResults, []MergeWarning, error) {
	if len(sources) == 0 {
		return hdf.HDFResults{}, nil, errors.New("merge: no sources")
	}

	out := hdf.HDFResults{
		Generator: &hdf.Generator{Name: mergeGeneratorName, Version: Version()},
	}
	var warnings []MergeWarning
	var latest *time.Time
	seenComponent := map[string]bool{}
	provenance := make([]any, 0, len(sources))
	positionsByName := map[string][]int{}
	var nameOrder []string

	for i := range sources {
		src := sources[i]
		prefix := toolPrefix(src.Doc, i)
		version := toolVersion(src.Doc)

		for j := range src.Doc.Baselines {
			b := src.Doc.Baselines[j]
			nb := b
			nb.Name = prefix + "/" + b.Name
			pos := len(out.Baselines)

			labels := make(map[string]string, len(b.Labels)+3)
			for k, v := range b.Labels {
				labels[k] = v
			}
			warnings = setLabel(warnings, labels, LabelTool, prefix, nb.Name, pos)
			if version != "" {
				warnings = setLabel(warnings, labels, LabelToolVersion, version, nb.Name, pos)
			} else if _, had := labels[LabelToolVersion]; had {
				delete(labels, LabelToolVersion)
				warnings = append(warnings, MergeWarning{Kind: WarnLabelOverwritten, Name: nb.Name, Indices: []int{pos}, Label: LabelToolVersion})
			}
			warnings = setLabel(warnings, labels, LabelSourceDocument, src.Name, nb.Name, pos)
			nb.Labels = labels

			if _, seen := positionsByName[nb.Name]; !seen {
				nameOrder = append(nameOrder, nb.Name)
			}
			positionsByName[nb.Name] = append(positionsByName[nb.Name], pos)
			out.Baselines = append(out.Baselines, nb)
		}

		for j := range src.Doc.Components {
			c := src.Doc.Components[j]
			if c.ComponentID != nil {
				if seenComponent[*c.ComponentID] {
					continue
				}
				seenComponent[*c.ComponentID] = true
			}
			out.Components = append(out.Components, c)
		}

		if ts := src.Doc.Timestamp; ts != nil && (latest == nil || ts.After(*latest)) {
			t := *ts
			latest = &t
		}

		provenance = append(provenance, sourceProvenance(i, src))
	}

	for _, name := range nameOrder {
		if pos := positionsByName[name]; len(pos) > 1 {
			warnings = append(warnings, MergeWarning{Kind: WarnDuplicateBaselineName, Name: name, Indices: pos})
		}
	}

	out.Timestamp = latest
	out.Extensions = map[string]any{
		mergeExtensionKey: map[string]any{
			"version": Version(),
			"sources": provenance,
		},
	}
	return out, warnings, nil
}

// setLabel writes key=value, warning when the baseline already carried the key.
func setLabel(warnings []MergeWarning, labels map[string]string, key, value, name string, pos int) []MergeWarning {
	if _, had := labels[key]; had {
		warnings = append(warnings, MergeWarning{Kind: WarnLabelOverwritten, Name: name, Indices: []int{pos}, Label: key})
	}
	labels[key] = value
	return warnings
}

// toolPrefix is the `<tool>` of a merged baseline name (ADR-0016 §2): the
// root tool.name lower-cased and trimmed; else generator.name the same way;
// else doc<N>.
func toolPrefix(doc hdf.HDFResults, index int) string {
	if doc.Tool != nil && doc.Tool.Name != nil {
		if s := normalizeName(*doc.Tool.Name); s != "" {
			return s
		}
	}
	if doc.Generator != nil {
		if s := normalizeName(doc.Generator.Name); s != "" {
			return s
		}
	}
	return fmt.Sprintf("doc%d", index)
}

func normalizeName(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}

// toolVersion is the root tool.version, or "" when the source carries none.
func toolVersion(doc hdf.HDFResults) string {
	if doc.Tool != nil && doc.Tool.Version != nil {
		return strings.TrimSpace(*doc.Tool.Version)
	}
	return ""
}

// sourceProvenance is one input's root metadata, verbatim, for
// extensions["hdf-merge"].sources[]: index, name, and — only when the input
// has them — tool, generator, timestamp and runner, each as plain JSON so the
// carrier is the same shape in Go and TS.
func sourceProvenance(index int, src MergeSource) map[string]any {
	entry := map[string]any{"index": index, "name": src.Name}
	if src.Doc.Tool != nil {
		entry["tool"] = asJSONMap(src.Doc.Tool)
	}
	if src.Doc.Generator != nil {
		entry["generator"] = asJSONMap(src.Doc.Generator)
	}
	if src.Doc.Timestamp != nil {
		entry["timestamp"] = src.Doc.Timestamp.Format(time.RFC3339Nano)
	}
	if src.Doc.Runner != nil {
		entry["runner"] = asJSONMap(src.Doc.Runner)
	}
	return entry
}

// asJSONMap round-trips a schema struct through JSON so only the fields it
// actually carries appear (omitempty), exactly as the input serialized them.
func asJSONMap(v any) map[string]any {
	b, err := json.Marshal(v)
	if err != nil {
		return map[string]any{}
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return map[string]any{}
	}
	return m
}
