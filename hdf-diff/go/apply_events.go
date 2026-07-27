package diff

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
)

// ApplyInputs carries the caller-supplied identity for a reassembly run.
// Everything else in the derivation block is computed from the seed bytes
// and the event batch — no wall clock, no RNG.
type ApplyInputs struct {
	// Generator names the reconciling tool: a reconciled document must never
	// masquerade as scanner output.
	Generator hdf.Generator
	// SeedURI locates the seed snapshot for the derivation block; its
	// checksum is computed from the seed bytes.
	SeedURI string
	// Source is the event-stream producer context recorded in the
	// derivation block.
	Source string
}

// ApplyWarning reports a non-fatal anomaly for one entity key. Warnings
// never abort the fold: the key is still applied last-value-wins and the
// warning marks it unverified (ADR-0005 §4 fold contract).
type ApplyWarning struct {
	RequirementID string
	// Kind: chainGap | newOnExisting | absentUnknown | multiBaseline
	Kind    string
	Message string
}

// ApplyResult is the reassembly output: the reconciled result set plus any
// per-key anomalies detected while folding.
type ApplyResult struct {
	Results  []byte
	Warnings []ApplyWarning
}

// eventPriorValue extracts the priorChecksum hex from the event's
// interface{} field ("" when null/absent).
func eventPriorValue(ev *hdf.HDFRequirementChangeEvent) string {
	if m, ok := ev.PriorChecksum.(map[string]interface{}); ok {
		if v, ok := m["value"].(string); ok {
			return v
		}
	}
	return ""
}

// eventAfterChecksum computes the effective checksum of the event's after
// payload, anchored to the event's occurrence time. Returns "" when the
// payload is absent or untypeable (chain verification becomes best-effort).
func eventAfterChecksum(ev *hdf.HDFRequirementChangeEvent) string {
	if ev.After == nil {
		return ""
	}
	raw, err := json.Marshal(ev.After)
	if err != nil {
		return ""
	}
	var typed hdf.EvaluatedRequirement
	if err := json.Unmarshal(raw, &typed); err != nil {
		return ""
	}
	cs := ComputeEffectiveChecksum(typed, ev.Timestamp.UTC().Format(time.RFC3339Nano))
	if cs == nil {
		return ""
	}
	return cs.Value
}

// findRequirement locates a requirement by id across all baselines,
// returning the baseline's requirements slice, the index, and true on hit.
func findRequirement(doc map[string]interface{}, id string) (map[string]interface{}, []interface{}, int, bool) {
	baselines, _ := doc["baselines"].([]interface{})
	for _, bRaw := range baselines {
		b, ok := bRaw.(map[string]interface{})
		if !ok {
			continue
		}
		reqs, _ := b["requirements"].([]interface{})
		for i, rRaw := range reqs {
			r, ok := rRaw.(map[string]interface{})
			if !ok {
				continue
			}
			if rid, _ := r["id"].(string); rid == id {
				return b, reqs, i, true
			}
		}
	}
	return nil, nil, 0, false
}

// ApplyChangeEvents reassembles the current posture from a seed hdf-results
// document plus a batch of requirement-change events (ADR-0005 §§4-7):
// keyed last-value-wins by sequence, idempotent via (source, eventId) dedup,
// tombstone-aware (absent removes), total over the event-state enum.
// Delivery order and duplicates never change the output. The result carries
// the caller's generator and a derivation block (seed pinned by content,
// watermark, count, asOf) so it can never masquerade as scan evidence.
// Chain gaps and anomalies are surfaced as warnings, never as refusal.
func ApplyChangeEvents(seed []byte, events []*hdf.HDFRequirementChangeEvent, in ApplyInputs) (*ApplyResult, error) {
	var doc map[string]interface{}
	if err := json.Unmarshal(seed, &doc); err != nil {
		return nil, fmt.Errorf("failed to parse seed results: %w", err)
	}

	seedHash := sha256.Sum256(seed)
	docTimestamp, _ := doc["timestamp"].(string)

	byKey, keys := groupEventChains(dedupEvents(events))

	result := &ApplyResult{}
	warn := func(id, kind, message string) {
		result.Warnings = append(result.Warnings, ApplyWarning{RequirementID: id, Kind: kind, Message: message})
	}

	var maxSequence int64
	var maxOccurred time.Time
	eventsApplied := 0
	type insertion struct {
		sequence int64
		id       string
		payload  map[string]interface{}
	}
	var insertions []insertion

	for _, id := range keys {
		chain := byKey[id]
		_, _, _, inSeed := findRequirement(doc, id)

		// One warning per key, application anomalies taking priority over
		// chain-link mismatches.
		keyWarned := false
		keyWarn := func(kind, message string) {
			if !keyWarned {
				keyWarned = true
				warn(id, kind, message)
			}
		}

		winner := chain[len(chain)-1]

		// Chain verification (shared with the fold): unanchored chains defer
		// to the application outcome below.
		var seedTyped *hdf.EvaluatedRequirement
		if _, reqs, idx, ok := findRequirement(doc, id); ok {
			if typed, tok := typedRequirement(reqs[idx]); tok {
				seedTyped = &typed
			}
		}
		verifyEventChain(chain, seedTyped, inSeed, keyWarn)
		verifyLinks := inSeed || chain[0].State == hdf.EventRequirementStateNew

		// Apply the winner.
		if winner.Sequence > maxSequence {
			maxSequence = winner.Sequence
		}
		if winner.Timestamp.After(maxOccurred) {
			maxOccurred = winner.Timestamp
		}

		if winner.State == hdf.EventRequirementStateAbsent {
			if b, reqs, idx, ok := findRequirement(doc, id); ok {
				b["requirements"] = append(reqs[:idx], reqs[idx+1:]...)
				eventsApplied++
			} else {
				keyWarn("absentUnknown", "absent event for a key not present in the document")
			}
			continue
		}

		if !verifyLinks {
			keyWarn("chainGap", "non-new chain for a key the seed does not carry")
		}

		raw, err := json.Marshal(winner.After)
		if err != nil {
			keyWarn("chainGap", "winning event payload is not marshalable")
			continue
		}
		var payload map[string]interface{}
		if err := json.Unmarshal(raw, &payload); err != nil || payload == nil {
			keyWarn("chainGap", "winning event carries no applicable after payload")
			continue
		}

		if _, reqs, idx, ok := findRequirement(doc, id); ok {
			reqs[idx] = payload
			eventsApplied++
		} else {
			insertions = append(insertions, insertion{sequence: winner.Sequence, id: id, payload: payload})
		}
	}

	// Deterministic insertion order regardless of delivery order.
	sort.Slice(insertions, func(i, j int) bool {
		if insertions[i].sequence != insertions[j].sequence {
			return insertions[i].sequence < insertions[j].sequence
		}
		return insertions[i].id < insertions[j].id
	})
	if len(insertions) > 0 {
		baselines, _ := doc["baselines"].([]interface{})
		if len(baselines) == 0 {
			return nil, fmt.Errorf("seed document has no baselines to insert new requirements into")
		}
		if len(baselines) > 1 {
			warn(insertions[0].id, "multiBaseline", "seed has multiple baselines; new requirements appended to the first")
		}
		first, ok := baselines[0].(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("seed document baseline is not an object")
		}
		reqs, _ := first["requirements"].([]interface{})
		for _, ins := range insertions {
			reqs = append(reqs, ins.payload)
			eventsApplied++
		}
		first["requirements"] = reqs
	}

	// Lineage: computed from the batch; asOf falls back to the seed's own
	// timestamp for an empty batch.
	asOf := docTimestamp
	if !maxOccurred.IsZero() {
		asOf = maxOccurred.UTC().Format(time.RFC3339Nano)
	}
	if asOf == "" {
		return nil, fmt.Errorf("cannot derive asOf: no events supplied and the seed document has no timestamp")
	}

	genRaw, err := json.Marshal(in.Generator)
	if err != nil {
		return nil, fmt.Errorf("failed to encode generator: %w", err)
	}
	var genMap map[string]interface{}
	if err := json.Unmarshal(genRaw, &genMap); err != nil {
		return nil, fmt.Errorf("failed to encode generator: %w", err)
	}
	doc["generator"] = genMap
	doc["timestamp"] = asOf
	doc["derivation"] = map[string]interface{}{
		"seed": map[string]interface{}{
			"uri": in.SeedURI,
			"checksum": map[string]interface{}{
				"algorithm": "sha256",
				"value":     hex.EncodeToString(seedHash[:]),
			},
		},
		"source":          in.Source,
		"throughSequence": maxSequence,
		"eventsApplied":   eventsApplied,
		"asOf":            asOf,
	}

	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to encode reconciled results: %w", err)
	}
	result.Results = out
	return result, nil
}
