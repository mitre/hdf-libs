// Package matching provides strategies for matching requirements across evaluations.
package matching

import hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"

// MatchPair represents a matched pair of requirements.
type MatchPair struct {
	OldReq     hdf.EvaluatedRequirement
	NewReq     hdf.EvaluatedRequirement
	Strategy   string
	Confidence float64
}

// MatchResult holds the output of a matching operation.
type MatchResult struct {
	Matched      []MatchPair
	UnmatchedOld []hdf.EvaluatedRequirement
	UnmatchedNew []hdf.EvaluatedRequirement
}

// Strategy defines the interface for a matching strategy.
type Strategy interface {
	Name() string
	Match(oldReqs, newReqs []hdf.EvaluatedRequirement) MatchResult
}

// Options configures the matching behavior.
type Options struct {
	Strategy           string
	FallbackStrategies []string
	MappingTable       map[string]string
	MinConfidence      float64
}
