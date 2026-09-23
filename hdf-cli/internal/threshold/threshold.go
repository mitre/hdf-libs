// Package threshold parses the threshold specifications that gate CI and answer
// compliance questions. Both surfaces that accept a user-authored spec — the
// `hdf validate threshold` command and the MCP compliance tool — must reject a
// spec that does not mean what it appears to mean, so the strictness lives here
// instead of in either caller: fixing one and forgetting the other is exactly
// how a permissive parse survived on one path after being closed on the other.
package threshold

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"

	hdfengine "github.com/mitre/hdf-libs/hdf-engine/go/v3"
	"gopkg.in/yaml.v3"
)

// ErrNoAssertions reports a spec that parsed cleanly but declares no bounds. It
// passes every document, so treating it as success reports a gate that checked
// nothing — the same false green a misspelled key produces, reached
// deliberately rather than by accident.
var ErrNoAssertions = errors.New("threshold asserts nothing: add at least one bound (e.g. a 'failed.total.max' entry)")

// keyVocabulary restates yaml's KnownFields errors, which name the Go type that
// rejected the key, in the spec's own terms. Unmatched wording degrades to the
// raw message, which still names the key and its line.
var keyVocabulary = strings.NewReplacer(
	"not found in type hdfengine.ThresholdConfig", "is not a known threshold category",
	"not found in type hdfengine.ThresholdSeverity", "is not a known severity field",
	"not found in type hdfengine.ThresholdBound", "is not a known bound",
	"not found in type hdfengine.ComplianceBound", "is not a known compliance field",
)

// Spec is one threshold policy together with where it came from. A run may apply
// several, so a violation has to be able to name the policy that produced it.
type Spec struct {
	Config *hdfengine.ThresholdConfig
	Label  string
}

// DecodeAll parses every document in a spec stream into its own policy, rejecting
// any key the schema does not define in ANY of them. Input may be YAML or JSON,
// since YAML is a superset — the MCP tool passes a JSON-marshalled inline object
// through the same path as a YAML file.
//
// Several documents are a CONJUNCTION: each is evaluated separately and the
// violations are unioned. They are returned separately rather than merged
// because merging two documents that bound the same key would need a precedence
// rule nobody asked for, while evaluating both needs none — the stricter bound
// simply fails on its own terms.
//
// source names the origin for labelling: a file path, or a flag name for inline
// input. A stream holding one document takes the bare source as its label; a
// stream holding several takes source#1, source#2, …, 1-based because that is how
// a person counts documents in a file. A separator introducing no document — a
// bare trailing ---, a repeated one, a comment-only tail — is not a policy and
// yields no spec, so nothing an author wrote is invented or discarded.
//
// An empty stream yields no specs. Reporting that as "asserts nothing" belongs to
// the caller, which knows how many other specs the run carries.
func DecodeAll(raw []byte, source string) ([]Spec, error) {
	decoder := yaml.NewDecoder(bytes.NewReader(raw))
	decoder.KnownFields(true)

	var specs []Spec
	for {
		// A pointer target distinguishes a document carrying no content, which
		// decodes to nil, from one that is present but empty (`{}`), which
		// allocates. The second is a policy the author wrote and asserts
		// nothing; the first was never a policy at all.
		var config *hdfengine.ThresholdConfig
		err := decoder.Decode(&config)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("%s: %s", labelAt(source, len(specs)+1), keyVocabulary.Replace(err.Error()))
		}
		if config == nil {
			continue
		}
		specs = append(specs, Spec{Config: config, Label: source})
	}

	// The index is only useful when there is something to disambiguate, so the
	// single-document case — which is nearly every spec — keeps the bare source.
	if len(specs) > 1 {
		for i := range specs {
			specs[i].Label = fmt.Sprintf("%s#%d", source, i+1)
		}
	}
	return specs, nil
}

// labelAt names the nth policy of a stream, 1-based. The index counts POLICIES
// rather than documents, so a file padded with separators does not report its one
// policy as #3. A stream still being read cannot know whether more policies
// follow, so the first takes the bare source; DecodeAll indexes it afterwards if
// others turn up.
func labelAt(source string, n int) string {
	if n <= 1 {
		return source
	}
	return fmt.Sprintf("%s#%d", source, n)
}

// AssertionCount reports how many bounds a spec actually asserts, counting every
// level: a section present but empty (`failed: {}`) asserts as little as an
// empty document.
func AssertionCount(config *hdfengine.ThresholdConfig) int {
	if config == nil {
		return 0
	}
	count := 0
	// A rule is a bound like any other: a spec whose only content is rules
	// asserts plenty, and reporting it as asserting nothing would tell the author
	// to add a bound they already wrote. A rule with neither min nor max asserts
	// nothing, and is counted as nothing.
	for _, rule := range config.Rules {
		if rule.Min != nil {
			count++
		}
		if rule.Max != nil {
			count++
		}
	}
	if config.Compliance != nil {
		if config.Compliance.Min != nil {
			count++
		}
		if config.Compliance.Max != nil {
			count++
		}
	}
	for _, severity := range []*hdfengine.ThresholdSeverity{config.Passed, config.Failed, config.Skipped, config.Error, config.NoImpact} {
		if severity == nil {
			continue
		}
		// Every bound must be listed: one omitted here reports a populated spec
		// as asserting nothing, which reads as the false green this count exists
		// to prevent.
		for _, bound := range []*hdfengine.ThresholdBound{
			severity.Critical, severity.High, severity.Medium, severity.Low,
			severity.Informational, severity.None, severity.Total,
		} {
			if bound == nil {
				continue
			}
			if bound.Min != nil {
				count++
			}
			if bound.Max != nil {
				count++
			}
			count += len(bound.Controls)
		}
	}
	return count
}
