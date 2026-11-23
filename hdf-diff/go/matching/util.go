package matching

import (
	"encoding/json"

	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
)

// buildIDIndex groups requirement positions by id. A repeated id is legal: the id
// names the requirement, not the finding, so one CVE reported against several
// packages emits several entries. Shared with MappedIDStrategy.
func buildIDIndex(reqs []hdf.EvaluatedRequirement) map[string][]int {
	byID := make(map[string][]int, len(reqs))
	for i, req := range reqs {
		byID[req.ID] = append(byID[req.ID], i)
	}
	return byID
}

// contentKey discriminates occurrences that share an id: code, title and
// affectedPackages, with position as the tie-break in pairOccurrences. results[] is
// excluded because its startTime and runTime vary per run, which would separate two
// runs of the same occurrence.
func contentKey(req hdf.EvaluatedRequirement) string {
	raw, err := json.Marshal(struct {
		Code             *string               `json:"code"`
		Title            *string               `json:"title"`
		AffectedPackages []hdf.AffectedPackage `json:"affectedPackages"`
	}{req.Code, req.Title, req.AffectedPackages})
	if err != nil {
		// No key, so every occurrence of this id falls to the positional tie-break.
		return ""
	}
	return string(raw)
}

// pairOccurrences pairs one id's occurrences by content key, then by document order
// within a key, reporting the surplus on each side. A repeated id was once called
// ambiguous and left wholly unmatched, so a self-comparison reported every occurrence
// absent AND new.
func pairOccurrences(
	oldIdx, newIdx []int,
	oldReqs, newReqs []hdf.EvaluatedRequirement,
) (pairs [][2]int, surplusOld, surplusNew []int) {
	if len(oldIdx) == 1 && len(newIdx) == 1 {
		return [][2]int{{oldIdx[0], newIdx[0]}}, nil, nil
	}

	newByContent := make(map[string][]int, len(newIdx))
	for _, i := range newIdx {
		key := contentKey(newReqs[i])
		newByContent[key] = append(newByContent[key], i)
	}

	taken := make(map[int]bool, len(newIdx))
	var leftover []int
	for _, oi := range oldIdx {
		key := contentKey(oldReqs[oi])
		queue := newByContent[key]
		if len(queue) == 0 {
			leftover = append(leftover, oi)
			continue
		}
		ni := queue[0]
		newByContent[key] = queue[1:]
		taken[ni] = true
		pairs = append(pairs, [2]int{oi, ni})
	}

	// What no content key claimed pairs in document order, settling indistinguishable
	// occurrences.
	var free []int
	for _, i := range newIdx {
		if !taken[i] {
			free = append(free, i)
		}
	}
	n := min(len(leftover), len(free))
	for k := 0; k < n; k++ {
		pairs = append(pairs, [2]int{leftover[k], free[k]})
	}
	return pairs, leftover[n:], free[n:]
}
