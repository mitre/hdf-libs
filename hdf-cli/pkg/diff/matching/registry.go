package matching

import (
	"fmt"

	hdf "github.com/mitre/hdf-cli/pkg/hdf"
)

// createStrategy creates a strategy instance by name.
func createStrategy(name string, opts Options) (Strategy, error) {
	switch name {
	case "exactId":
		return NewExactIDStrategy(), nil
	case "mappedId":
		mapping := opts.MappingTable
		if mapping == nil {
			mapping = make(map[string]string)
		}
		return NewMappedIDStrategy(mapping), nil
	case "cciMatch":
		return NewCCIMatchStrategy(), nil
	case "fuzzyTitle":
		return NewFuzzyTitleStrategy(opts.MinConfidence), nil
	default:
		return nil, fmt.Errorf("unknown matching strategy: '%s'", name)
	}
}

// MatchRequirements matches requirements between two evaluations using a primary
// strategy and optional fallback strategies. Returns the combined MatchResult.
// If an unknown strategy name is provided, it panics.
//
// Deprecated: Use MatchRequirementsWithError instead, which returns an error
// rather than panicking on invalid strategy names.
func MatchRequirements(oldReqs, newReqs []hdf.EvaluatedRequirement, opts Options) MatchResult {
	result, err := MatchRequirementsWithError(oldReqs, newReqs, opts)
	if err != nil {
		panic(err)
	}
	return result
}

// MatchRequirementsWithError matches requirements between two evaluations using
// a primary strategy and optional fallback strategies. Returns an error if an
// unknown strategy name is provided.
func MatchRequirementsWithError(oldReqs, newReqs []hdf.EvaluatedRequirement, opts Options) (MatchResult, error) {
	primaryName := opts.Strategy
	if primaryName == "" {
		primaryName = "exactId"
	}
	fallbackNames := opts.FallbackStrategies

	// Build all strategy instances up front (validates names).
	allNames := append([]string{primaryName}, fallbackNames...)
	strategies := make([]Strategy, 0, len(allNames))
	for _, name := range allNames {
		s, err := createStrategy(name, opts)
		if err != nil {
			return MatchResult{}, err
		}
		strategies = append(strategies, s)
	}

	// Accumulate all matched pairs
	var allMatched []MatchPair

	// Start with all requirements unmatched
	currentUnmatchedOld := oldReqs
	currentUnmatchedNew := newReqs

	// Apply strategies in order
	for _, strategy := range strategies {
		if len(currentUnmatchedOld) == 0 || len(currentUnmatchedNew) == 0 {
			break
		}

		r := strategy.Match(currentUnmatchedOld, currentUnmatchedNew)

		allMatched = append(allMatched, r.Matched...)
		currentUnmatchedOld = r.UnmatchedOld
		currentUnmatchedNew = r.UnmatchedNew
	}

	return MatchResult{
		Matched:      allMatched,
		UnmatchedOld: currentUnmatchedOld,
		UnmatchedNew: currentUnmatchedNew,
	}, nil
}
