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

// Decode parses a threshold spec, rejecting any key the schema does not define
// and any spec that is not a single YAML document.
// Input may be YAML or JSON, since YAML is a superset — the MCP tool passes a
// JSON-marshalled inline object through the same path as a YAML file. An empty
// input decodes to a zero config rather than erroring; callers reject that via
// AssertionCount, which reports the more useful reason.
func Decode(raw []byte) (*hdfengine.ThresholdConfig, error) {
	var config hdfengine.ThresholdConfig
	decoder := yaml.NewDecoder(bytes.NewReader(raw))
	decoder.KnownFields(true)
	if err := decoder.Decode(&config); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%s", keyVocabulary.Replace(err.Error()))
	}
	if err := rejectSecondDocument(decoder); err != nil {
		return nil, err
	}
	return &config, nil
}

// rejectSecondDocument reports a spec whose stream carries another document with
// content in it. Decode reads exactly one document, so bounds written after a
// `---` were parsed by nobody — KnownFields cannot see them, because strictness
// applies within a document and not across a stream. A separator that introduces
// nothing (a bare trailing `---`, a repeated one, or a comment-only tail) decodes
// to a null scalar and is left alone: it discards nothing an author wrote, and
// rejecting it would break specs that are legal YAML and common in the wild.
func rejectSecondDocument(decoder *yaml.Decoder) error {
	for {
		var doc yaml.Node
		err := decoder.Decode(&doc)
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("%s", keyVocabulary.Replace(err.Error()))
		}
		if documentIsEmpty(&doc) {
			continue
		}
		return fmt.Errorf(
			"a threshold spec must be a single document: the content at line %d follows a '---' separator, "+
				"so it would never be evaluated — merge it into the first document or split it into its own spec",
			doc.Line)
	}
}

// documentIsEmpty reports a document carrying no content. yaml.v3 renders a bare
// separator and a comment-only tail identically: a document node wrapping a
// null-tagged scalar whose value is empty.
func documentIsEmpty(doc *yaml.Node) bool {
	if len(doc.Content) != 1 {
		return len(doc.Content) == 0
	}
	inner := doc.Content[0]
	return inner.Kind == yaml.ScalarNode && inner.Tag == "!!null" && inner.Value == ""
}

// AssertionCount reports how many bounds a spec actually asserts, counting every
// level: a section present but empty (`failed: {}`) asserts as little as an
// empty document.
func AssertionCount(config *hdfengine.ThresholdConfig) int {
	if config == nil {
		return 0
	}
	count := 0
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
