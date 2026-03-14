package matching

import hdf "github.com/mitre/hdf-cli/pkg/hdf"

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

	// Build a map of new requirements by ID, detecting duplicates.
	newByID := make(map[string]int)
	duplicateNewIDs := make(map[string]bool)
	for i, req := range newReqs {
		id := req.ID
		if duplicateNewIDs[id] {
			continue
		}
		if _, exists := newByID[id]; exists {
			duplicateNewIDs[id] = true
			delete(newByID, id)
		} else {
			newByID[id] = i
		}
	}

	// Build a map of old requirements by ID, detecting duplicates.
	oldByID := make(map[string]int)
	duplicateOldIDs := make(map[string]bool)
	for i, req := range oldReqs {
		id := req.ID
		if duplicateOldIDs[id] {
			continue
		}
		if _, exists := oldByID[id]; exists {
			duplicateOldIDs[id] = true
			delete(oldByID, id)
		} else {
			oldByID[id] = i
		}
	}

	// Track which new reqs have been matched
	matchedNewIDs := make(map[string]bool)

	// Try to match old requirements using the mapping table (skip duplicate old IDs)
	for _, oldReq := range oldReqs {
		oldID := oldReq.ID
		if duplicateOldIDs[oldID] {
			result.UnmatchedOld = append(result.UnmatchedOld, oldReq)
			continue
		}

		mappedNewID, hasMapped := s.mapping[oldID]
		if !hasMapped {
			result.UnmatchedOld = append(result.UnmatchedOld, oldReq)
			continue
		}

		// Skip if the mapped new ID is a duplicate
		if duplicateNewIDs[mappedNewID] {
			result.UnmatchedOld = append(result.UnmatchedOld, oldReq)
			continue
		}

		newIdx, found := newByID[mappedNewID]
		if found && !matchedNewIDs[mappedNewID] {
			result.Matched = append(result.Matched, MatchPair{
				OldReq:     oldReq,
				NewReq:     newReqs[newIdx],
				Strategy:   "mappedId",
				Confidence: 0.95,
			})
			matchedNewIDs[mappedNewID] = true
		} else {
			result.UnmatchedOld = append(result.UnmatchedOld, oldReq)
		}
	}

	// Collect unmatched new requirements (including all duplicates)
	for _, req := range newReqs {
		id := req.ID
		if duplicateNewIDs[id] || !matchedNewIDs[id] {
			result.UnmatchedNew = append(result.UnmatchedNew, req)
		}
	}

	return result
}
