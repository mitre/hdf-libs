package matching

import hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go"

// buildUniqueIDIndex builds a map of requirement ID to slice index, detecting
// duplicates. IDs that appear more than once are removed from byID and added
// to duplicates. This is shared by ExactIDStrategy and MappedIDStrategy.
func buildUniqueIDIndex(reqs []hdf.EvaluatedRequirement) (byID map[string]int, duplicates map[string]bool) {
	byID = make(map[string]int, len(reqs))
	duplicates = make(map[string]bool)

	for i, req := range reqs {
		id := req.ID
		if duplicates[id] {
			continue
		}
		if _, exists := byID[id]; exists {
			duplicates[id] = true
			delete(byID, id)
		} else {
			byID[id] = i
		}
	}

	return byID, duplicates
}
