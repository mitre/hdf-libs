package diff

import (
	"fmt"
	"sort"
	"time"

	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
)

// dedupEvents drops duplicate (source, eventId) deliveries — the fold
// contract's idempotency key (ADR-0005 §4).
func dedupEvents(events []*hdf.HDFRequirementChangeEvent) []*hdf.HDFRequirementChangeEvent {
	seen := map[string]bool{}
	var deduped []*hdf.HDFRequirementChangeEvent
	for _, ev := range events {
		if ev == nil {
			continue
		}
		key := ev.Source + "|" + ev.EventID
		if seen[key] {
			continue
		}
		seen[key] = true
		deduped = append(deduped, ev)
	}
	return deduped
}

// groupEventChains groups events per entity key, each chain ordered by
// sequence (eventId tie-break for determinism under pathological duplicate
// sequences), and returns the keys sorted for deterministic iteration.
func groupEventChains(events []*hdf.HDFRequirementChangeEvent) (map[string][]*hdf.HDFRequirementChangeEvent, []string) {
	byKey := map[string][]*hdf.HDFRequirementChangeEvent{}
	for _, ev := range events {
		byKey[ev.RequirementID] = append(byKey[ev.RequirementID], ev)
	}
	keys := make([]string, 0, len(byKey))
	for k := range byKey {
		keys = append(keys, k)
		sort.Slice(byKey[k], func(i, j int) bool {
			a, b := byKey[k][i], byKey[k][j]
			if a.Sequence != b.Sequence {
				return a.Sequence < b.Sequence
			}
			return a.EventID < b.EventID
		})
	}
	sort.Strings(keys)
	return byKey, keys
}

// verifyEventChain walks a per-key chain's priorChecksum links from the seed
// posture forward, reporting anomalies through keyWarn. Best-effort: expiry
// is anchored to each event's occurrence time. Chains for keys the seed does
// not carry are only anchored when they open with a new-state event;
// unanchored chains are left to the caller's application outcome.
func verifyEventChain(
	chain []*hdf.HDFRequirementChangeEvent,
	seedTyped *hdf.EvaluatedRequirement,
	inSeed bool,
	keyWarn func(kind, message string),
) {
	if len(chain) == 0 {
		return
	}
	if !inSeed && chain[0].State != hdf.EventRequirementStateNew {
		return
	}

	expected := ""
	if seedTyped != nil {
		ref := chain[0].Timestamp.UTC().Format(time.RFC3339Nano)
		if cs := ComputeEffectiveChecksum(*seedTyped, ref); cs != nil {
			expected = cs.Value
		}
	}
	for _, ev := range chain {
		prior := eventPriorValue(ev)
		if ev.State == hdf.EventRequirementStateNew {
			if inSeed {
				keyWarn("newOnExisting", "state new for a key already present in the seed")
			} else if prior != "" {
				keyWarn("chainGap", "new-state event carries a non-null priorChecksum")
			}
		} else if prior != expected {
			keyWarn("chainGap", fmt.Sprintf("priorChecksum %q does not match expected chain state %q", prior, expected))
		}
		expected = eventAfterChecksum(ev)
	}
}
