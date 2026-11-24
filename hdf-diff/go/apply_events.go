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
	entries, ok := typedRequirements(ev.After)
	if !ok {
		return ""
	}
	// Folded, because the event's key covers every entry it carries: the chain link has to
	// be the same value FoldEffectiveState gives the seed's entries for that id.
	folded := FoldEffectiveState(entries, ev.Timestamp.UTC().Format(time.RFC3339Nano))
	if folded == nil {
		return ""
	}
	return folded.Checksum.Value
}

// requirementSite is one place an id's entries sit: a baseline and the positions it
// occupies in that baseline's requirements, in document order.
type requirementSite struct {
	baseline map[string]interface{}
	indexes  []int
}

// findRequirementSites locates every entry an id carries, across all baselines. An id
// names the requirement rather than the finding, so it may sit in several positions and
// several baselines, and an event carries all of them; placing one payload on the first
// hit overwrote a real entry's content.
func findRequirementSites(doc map[string]interface{}, id string) []requirementSite {
	var sites []requirementSite
	baselines, _ := doc["baselines"].([]interface{})
	for _, bRaw := range baselines {
		b, ok := bRaw.(map[string]interface{})
		if !ok {
			continue
		}
		reqs, _ := b["requirements"].([]interface{})
		var indexes []int
		for i, rRaw := range reqs {
			r, ok := rRaw.(map[string]interface{})
			if !ok {
				continue
			}
			if rid, _ := r["id"].(string); rid == id {
				indexes = append(indexes, i)
			}
		}
		if len(indexes) > 0 {
			sites = append(sites, requirementSite{baseline: b, indexes: indexes})
		}
	}
	return sites
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
		inSeed := len(findRequirementSites(doc, id)) > 0

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
		seedReqs, _ := seedEntries(doc, id)
		verifyEventChain(chain, seedReqs, inSeed, keyWarn)
		verifyLinks := inSeed || chain[0].State == hdf.EventRequirementStateNew

		// Apply the winner.
		if winner.Sequence > maxSequence {
			maxSequence = winner.Sequence
		}
		if winner.Timestamp.After(maxOccurred) {
			maxOccurred = winner.Timestamp
		}

		if winner.State == hdf.EventRequirementStateAbsent {
			// The requirement left the assessment, so EVERY entry it carried goes: an
			// absent event is about the id, and removing one of several left the rest
			// behind as a requirement that had supposedly disappeared.
			sites := findRequirementSites(doc, id)
			if len(sites) == 0 {
				keyWarn("absentUnknown", "absent event for a key not present in the document")
				continue
			}
			placeEntries(sites, nil)
			eventsApplied++
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
		var payload []map[string]interface{}
		if err := json.Unmarshal(raw, &payload); err != nil || len(payload) == 0 {
			keyWarn("chainGap", "winning event carries no applicable after payload")
			continue
		}

		sites := findRequirementSites(doc, id)
		if len(sites) == 0 {
			for _, entry := range payload {
				insertions = append(insertions, insertion{sequence: winner.Sequence, id: id, payload: entry})
			}
			continue
		}
		// The event carries every entry of the id, so they replace every entry of the id.
		// Only a change in their NUMBER leaves the arrangement undecidable, because the
		// event cannot then say which belongs where; that case is reported, not done
		// silently.
		if siteEntryCount(sites) != len(payload) {
			keyWarn("occurrenceMismatch",
				"the event carries a different number of this id's entries than the seed; "+
					"they are replaced in the first baseline that carries it")
		}
		placeEntries(sites, payload)
		eventsApplied++
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

// placeEntries writes an event's entries over the id's existing entries, because the
// event's list is the whole truth about that id. Both the event's after[] and the sites
// are in document order, so when the event carries as many entries as the seed holds
// each site takes its own share and the seed's arrangement across baselines is
// reproduced exactly. An empty payload removes them all, which is what absent means.
func placeEntries(sites []requirementSite, payload []map[string]interface{}) {
	shares := payloadShares(sites, payload)
	for i, site := range sites {
		reqs, _ := site.baseline["requirements"].([]interface{})
		drop := map[int]bool{}
		for _, j := range site.indexes {
			drop[j] = true
		}
		kept := make([]interface{}, 0, len(reqs)+len(shares[i]))
		written := false
		for j, r := range reqs {
			if !drop[j] {
				kept = append(kept, r)
				continue
			}
			if !written {
				for _, entry := range shares[i] {
					kept = append(kept, entry)
				}
				written = true
			}
		}
		site.baseline["requirements"] = kept
	}
}

// siteEntryCount is how many entries the id holds across every site.
func siteEntryCount(sites []requirementSite) int {
	total := 0
	for _, site := range sites {
		total += len(site.indexes)
	}
	return total
}

// payloadShares splits an event's entries across the sites the id occupies, one share
// each. The shares match the seed's own counts when the number agrees; otherwise the
// arrangement is undecidable and the first site takes everything, which the caller
// reports.
func payloadShares(sites []requirementSite, payload []map[string]interface{}) [][]map[string]interface{} {
	shares := make([][]map[string]interface{}, len(sites))
	if siteEntryCount(sites) != len(payload) {
		shares[0] = payload
		return shares
	}
	offset := 0
	for i, site := range sites {
		shares[i] = payload[offset : offset+len(site.indexes)]
		offset += len(site.indexes)
	}
	return shares
}

// seedEntries returns every entry the id carries in the document that decodes to a
// typed requirement. Presence is a separate question — an entry may be present and not
// decode — so callers that need presence count findRequirementSites instead.
func seedEntries(doc map[string]interface{}, id string) ([]hdf.EvaluatedRequirement, bool) {
	var entries []hdf.EvaluatedRequirement
	for _, site := range findRequirementSites(doc, id) {
		reqs, _ := site.baseline["requirements"].([]interface{})
		for _, i := range site.indexes {
			if typed, ok := typedRequirement(reqs[i]); ok {
				entries = append(entries, typed)
			}
		}
	}
	return entries, len(entries) > 0
}
