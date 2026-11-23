package matching

import hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"

// MappedIDStrategy matches requirements by translating old IDs through a
// mapping table and then performing exact matching on the translated IDs.
type MappedIDStrategy struct {
	mapping map[string]string
}

// NewMappedIDStrategy creates a new mapped ID matching strategy.
// The mapping maps old requirement IDs to new requirement IDs.
func NewMappedIDStrategy(mapping map[string]string) *MappedIDStrategy {
	if mapping == nil {
		mapping = make(map[string]string)
	}
	return &MappedIDStrategy{mapping: mapping}
}

// Name returns the strategy name.
func (s *MappedIDStrategy) Name() string {
	return "mappedId"
}

// Match matches old requirements against new requirements using the mapping table.
// Only matches requirements whose old ID appears in the mapping table and whose
// mapped new ID exists in the new requirements. Confidence is 0.95.
func (s *MappedIDStrategy) Match(oldReqs, newReqs []hdf.EvaluatedRequirement) MatchResult {
	result := MatchResult{}

	oldByID := buildIDIndex(oldReqs)
	newByID := buildIDIndex(newReqs)

	// As in ExactIDStrategy: document order, one id at a time, occurrences paired
	// among themselves.
	pairedWith := make(map[int]int, len(oldReqs))
	pairedNew := make(map[int]bool, len(newReqs))
	seen := make(map[string]bool, len(oldByID))
	for _, oldReq := range oldReqs {
		oldID := oldReq.ID
		if seen[oldID] {
			continue
		}
		seen[oldID] = true
		mappedNewID, hasMapped := s.mapping[oldID]
		if !hasMapped {
			continue
		}
		// Several old ids may map to one new id, so an occurrence another id already
		// claimed is not offered again, or one entry is matched twice.
		candidates := make([]int, 0, len(newByID[mappedNewID]))
		for _, i := range newByID[mappedNewID] {
			if !pairedNew[i] {
				candidates = append(candidates, i)
			}
		}
		pairs, _, _ := pairOccurrences(oldByID[oldID], candidates, oldReqs, newReqs)
		for _, p := range pairs {
			pairedWith[p[0]] = p[1]
			pairedNew[p[1]] = true
		}
	}

	for i, oldReq := range oldReqs {
		newIdx, ok := pairedWith[i]
		if !ok {
			result.UnmatchedOld = append(result.UnmatchedOld, oldReq)
			continue
		}
		result.Matched = append(result.Matched, MatchPair{
			OldReq:     oldReq,
			NewReq:     newReqs[newIdx],
			Strategy:   "mappedId",
			Confidence: 0.95,
		})
	}

	for i, req := range newReqs {
		if !pairedNew[i] {
			result.UnmatchedNew = append(result.UnmatchedNew, req)
		}
	}

	return result
}
