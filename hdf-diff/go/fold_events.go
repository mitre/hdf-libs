package diff

import (
	"encoding/json"
	"fmt"
	"sort"
	"time"

	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
)

// FoldResult is the materialization output: a systemDrift comparison built
// from a change-event batch, plus any per-key anomalies detected while
// folding (same warning shape as ApplyChangeEvents).
type FoldResult struct {
	Comparison HdfComparison
	Warnings   []ApplyWarning
}

// eventStateToDiffState maps the event vocabulary onto the comparison
// vocabulary (values are identical; the types differ).
func eventStateToDiffState(s hdf.EventRequirementState) RequirementState {
	return RequirementState(string(s))
}

// eventReasonsToDiffReasons casts the event's producer-subset reasons onto
// the comparison vocabulary (the subset is value-identical by construction,
// test-enforced in hdf-schema).
func eventReasonsToDiffReasons(reasons []hdf.EventChangeReason) []ChangeReason {
	out := make([]ChangeReason, 0, len(reasons))
	for _, r := range reasons {
		out = append(out, ChangeReason(string(r)))
	}
	return out
}

// typedRequirement converts a map-decoded or event-carried requirement to
// the generated type; ok=false when untypeable.
func typedRequirement(v interface{}) (hdf.EvaluatedRequirement, bool) {
	var typed hdf.EvaluatedRequirement
	raw, err := json.Marshal(v)
	if err != nil {
		return typed, false
	}
	if err := json.Unmarshal(raw, &typed); err != nil {
		return typed, false
	}
	return typed, true
}

// nonNilFieldChanges guards the schema's required-array contract (nil
// marshals as null; Requirement_Diff.fieldChanges must be an array).
func nonNilFieldChanges(fc []FieldChange) []FieldChange {
	if fc == nil {
		return []FieldChange{}
	}
	return fc
}

// nonNilDiffs guards the schema's array contract for diff slices.
func nonNilDiffs(d []RequirementDiff) []RequirementDiff {
	if d == nil {
		return []RequirementDiff{}
	}
	return d
}

// FoldChangeEventsIntoComparison materializes a change-event batch into a
// full systemDrift hdf-comparison against the seed document (ADR-0005 §5):
// each winning event lifts into the Requirement_Diff shape the batch engine
// produces — before from the seed, after from the event payload, field
// changes derived by the batch engine's own computeFieldChanges — under the
// same fold contract as ApplyChangeEvents (dedup, last-value-wins by
// sequence, tombstone-aware, warnings never abort). Output is deterministic:
// the comparison timestamp is the latest event occurrence, and seed-side
// override expiry anchors to the seed's own timestamp (falling back to the
// event occurrence when the seed has none) — never the wall clock.
func FoldChangeEventsIntoComparison(seed []byte, events []*hdf.HDFRequirementChangeEvent) (*FoldResult, error) {
	var doc map[string]interface{}
	if err := json.Unmarshal(seed, &doc); err != nil {
		return nil, fmt.Errorf("failed to parse seed results: %w", err)
	}
	docTimestamp, _ := doc["timestamp"].(string)

	byKey, keys := groupEventChains(dedupEvents(events))

	result := &FoldResult{}
	keyWarnFactory := func(id string) func(kind, message string) {
		warned := false
		return func(kind, message string) {
			if !warned {
				warned = true
				result.Warnings = append(result.Warnings, ApplyWarning{RequirementID: id, Kind: kind, Message: message})
			}
		}
	}

	// Baseline names for the Baseline field: seed requirement's own baseline,
	// or the first baseline for keys the seed does not carry.
	firstBaselineName := ""
	baselineByReq := map[string]string{}
	if baselines, ok := doc["baselines"].([]interface{}); ok {
		for i, bRaw := range baselines {
			b, ok := bRaw.(map[string]interface{})
			if !ok {
				continue
			}
			name, _ := b["name"].(string)
			if i == 0 {
				firstBaselineName = name
			}
			reqs, _ := b["requirements"].([]interface{})
			for _, rRaw := range reqs {
				if r, ok := rRaw.(map[string]interface{}); ok {
					if id, _ := r["id"].(string); id != "" {
						recordRequirementBaseline(baselineByReq, id, name)
					}
				}
			}
		}
	}

	var diffs []RequirementDiff
	var maxOccurred time.Time
	systemRef := ""

	for _, id := range keys {
		chain := byKey[id]
		winner := chain[len(chain)-1]
		if systemRef == "" {
			systemRef = winner.SystemRef
		}
		keyWarn := keyWarnFactory(id)

		var seedTyped *hdf.EvaluatedRequirement
		seedReqs, inSeed := seedEntries(doc, id)
		if inSeed {
			seedTyped = &seedReqs[0]
		}

		verifyEventChain(chain, seedReqs, inSeed, keyWarn)

		if winner.Timestamp.After(maxOccurred) {
			maxOccurred = winner.Timestamp
		}
		newTs := winner.Timestamp.UTC().Format(time.RFC3339Nano)
		// Seed-side override expiry needs a deterministic anchor: the seed's
		// own observation time, else the event occurrence — a timestamp-less
		// seed must never fall through to the wall clock.
		seedRef := docTimestamp
		if seedRef == "" {
			seedRef = newTs
		}

		// The requirement's prior posture is the fold over every entry it carried, as
		// the new side is: worst status, highest impact. One entry gives its own.
		oldStatus := ""
		oldImpact := 0.0
		if inSeed {
			if seedFold := FoldEffectiveState(seedReqs, seedRef); seedFold != nil {
				oldStatus = seedFold.EffectiveStatus
			}
			oldImpact = highestImpact(seedReqs)
		}

		if winner.State == hdf.EventRequirementStateAbsent {
			if !inSeed {
				keyWarn("absentUnknown", "absent event for a key not present in the seed")
				continue
			}
			diffs = append(diffs, RequirementDiff{
				ID:                 id,
				Title:              resolveTitle(seedTyped.Title, nil),
				Baseline:           baselineByReq[id],
				State:              StateAbsent,
				OldEffectiveStatus: oldStatus,
				ChangeReasons:      []ChangeReason{},
				OldImpact:          &oldImpact,
				FieldChanges:       []FieldChange{},
				Before:             seedTyped,
				After:              nil,
			})
			continue
		}

		// The event carries every entry of the id. The fold emits ONE requirementDiff per
		// key, so the posture is the folded one and the representative entry is the first.
		afterEntries, tok := typedRequirements(winner.After)
		if !tok {
			keyWarn("chainGap", "winning event carries no typeable after payload")
			continue
		}
		afterTyped := afterEntries[0]
		folded := FoldEffectiveState(afterEntries, newTs)
		if folded == nil {
			keyWarn("chainGap", "winning event's after payload has no resolvable posture")
			continue
		}
		newStatus := folded.EffectiveStatus
		// The impact a requirementDiff carries is the requirement's own, not its
		// effective one — the batch comparison's contract — so the fold takes the
		// highest of them.
		newImpact := highestImpact(afterEntries)

		// Content-bearing chain for a key the seed does not carry: the
		// comparison vocabulary allows a null before only on new, so the
		// entry is coerced to the batch engine's new shape; the chain
		// warning (already emitted by verifyEventChain for anchored chains,
		// or here for unanchored ones) records the anomaly.
		if !inSeed {
			if winner.State != hdf.EventRequirementStateNew {
				keyWarn("chainGap", "non-new chain for a key the seed does not carry; lifted as new")
			}
			diffs = append(diffs, RequirementDiff{
				ID:                 id,
				Title:              resolveTitle(nil, afterTyped.Title),
				Baseline:           firstBaselineName,
				State:              StateNew,
				NewEffectiveStatus: newStatus,
				ChangeReasons:      []ChangeReason{},
				NewImpact:          &newImpact,
				FieldChanges:       []FieldChange{},
				Before:             nil,
				After:              &afterTyped,
			})
			continue
		}

		diffs = append(diffs, RequirementDiff{
			ID:                 id,
			Title:              resolveTitle(seedTyped.Title, afterTyped.Title),
			Baseline:           baselineByReq[id],
			State:              eventStateToDiffState(winner.State),
			OldEffectiveStatus: oldStatus,
			NewEffectiveStatus: newStatus,
			ChangeReasons:      eventReasonsToDiffReasons(winner.ChangeReasons),
			OldImpact:          &oldImpact,
			NewImpact:          &newImpact,
			FieldChanges:       nonNilFieldChanges(computeFieldChanges(*seedTyped, afterTyped, defaultTrackedFields)),
			Before:             seedTyped,
			After:              &afterTyped,
		})
	}

	// Stable, as the TypeScript peer's sort is: a repeated id ties.
	sort.SliceStable(diffs, func(i, j int) bool { return diffs[i].ID < diffs[j].ID })
	if diffs == nil {
		diffs = []RequirementDiff{}
	}

	asOf := docTimestamp
	if !maxOccurred.IsZero() {
		asOf = maxOccurred.UTC().Format(time.RFC3339Nano)
	}
	if asOf == "" {
		return nil, fmt.Errorf("cannot derive a comparison timestamp: no events supplied and the seed document has no timestamp")
	}

	result.Comparison = HdfComparison{
		FormatVersion:    "1.0.0",
		ComparisonMode:   ModeSystemDrift,
		Timestamp:        asOf,
		SystemRef:        systemRef,
		Sources:          buildSources(ModeSystemDrift),
		Matching:         &MatchingConfig{PrimaryStrategy: "exactId"},
		Summary:          ComputeSummary(diffs),
		BaselineDiffs:    []BaselineDiff{},
		RequirementDiffs: diffs,
		Drift:            nonNilDiffs(extractDrift(diffs)),
	}
	return result, nil
}

// highestImpact is the raw impact of the entry that scores highest, which is how the
// fold takes an id's exposure. One entry gives exactly its own impact.
func highestImpact(reqs []hdf.EvaluatedRequirement) float64 {
	highest := 0.0
	for _, req := range reqs {
		if req.Impact > highest {
			highest = req.Impact
		}
	}
	return highest
}

// typedRequirements decodes an event's after[] into typed requirements. It reports
// false on an empty or undecodable payload, which the caller treats as a chain gap.
func typedRequirements(after interface{}) ([]hdf.EvaluatedRequirement, bool) {
	raw, err := json.Marshal(after)
	if err != nil {
		return nil, false
	}
	var entries []hdf.EvaluatedRequirement
	if err := json.Unmarshal(raw, &entries); err != nil || len(entries) == 0 {
		return nil, false
	}
	return entries, true
}
