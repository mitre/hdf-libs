package hdftosarif

import (
	"sort"
	"time"

	"github.com/mitre/hdf-libs/hdf-converters/v3/shared/go/exportmap"
)

// zeroTime is the reference the shared override helpers take for expiry
// resolution; every HDF exporter passes the zero value.
var zeroTime = time.Time{}

// The objects a carried SARIF property bag can be addressed to. SARIF §3.8.1
// puts a properties bag on every object, so carriage cannot enumerate bag KEYS
// — Appendix D tells producers to name them after the native tool's own fields.
// What it can enumerate is the objects THIS exporter emits, which is what an
// address names.
const (
	onLog        = "log"
	onRun        = "run"
	onDriver     = "driver"
	onConversion = "conversion"
	onRule       = "rule"
	onResult     = "result"
	onLocation   = "location"
)

// address identifies the SARIF object a carried bag belongs to by the HDF
// identities that survive a conversion, never by array position: HDF groups,
// deduplicates and reorders, so /runs/0/results/3 would silently reattach a bag
// to a different finding. Baseline name addresses the run, requirement id the
// rule, and the result's index WITHIN its requirement the individual result.
type address struct {
	On       string
	Baseline string
	RuleID   string
	Ordinal  int
	Index    int
}

// carriedBags holds the SARIF property bags a document retained, keyed by
// address. The entry shape mirrors ADR-0014 §3's oscal-props convention — a flat
// array in source order, each entry naming the object its payload came from —
// widened to a tuple because SARIF nests deeper than OSCAL's three objects.
type carriedBags map[address]map[string]interface{}

func (c carriedBags) find(a address) map[string]interface{} {
	return c[a]
}

// readCarriedBags reads extensions.passthrough.sarif.propertyBags[].
//
// extensions is closed to passthrough and rawSourceArtifacts, so a namespaced
// key inside passthrough is the only place SARIF-specific carriage can live.
// A malformed entry is skipped rather than failing the conversion: carriage is
// bookkeeping, and losing a bag must not cost the document its findings.
func readCarriedBags(doc map[string]interface{}) carriedBags {
	ext, _ := exportmap.AsMap(doc["extensions"])
	passthrough, _ := exportmap.AsMap(ext["passthrough"])
	block, _ := exportmap.AsMap(passthrough["sarif"])
	entries, _ := exportmap.AsSlice(block["propertyBags"])

	bags := carriedBags{}
	for _, raw := range entries {
		entry, ok := exportmap.AsMap(raw)
		if !ok {
			continue
		}
		props, ok := exportmap.AsMap(entry["properties"])
		if !ok || len(props) == 0 {
			continue
		}
		a := address{
			On:       exportmap.GetStr(entry, "on"),
			Baseline: exportmap.GetStr(entry, "baseline"),
			RuleID:   exportmap.GetStr(entry, "ruleId"),
		}
		if v, ok := entry["ordinal"].(float64); ok {
			a.Ordinal = int(v)
		}
		if v, ok := entry["index"].(float64); ok {
			a.Index = int(v)
		}
		bags[a] = props
	}
	return bags
}

// PassthroughSchemaVersion is the version of the extensions.passthrough.sarif.propertyBags
// carriage block this converter reads.
const PassthroughSchemaVersion = 1

// setBag writes an object's properties bag: this exporter's own keys first, then
// the carried ones, skipping any key the exporter already set.
//
// The exporter wins deliberately — verbatim carriage buys bookkeeping fidelity
// and mapping buys semantic fidelity, so a carried value never overwrites one
// this converter derived from an HDF field. Mirrors ADR-0014 §3.4.
func setBag(obj, own, carried map[string]interface{}) {
	if len(own) == 0 && len(carried) == 0 {
		return
	}
	props := map[string]interface{}{}
	for k, v := range own {
		props[k] = v
	}
	for k, v := range carried {
		if k == "tags" {
			continue // merged below; the schema requires the array be distinct
		}
		if _, taken := props[k]; !taken {
			props[k] = v
		}
	}
	if tags := mergeTags(own["tags"], carried["tags"]); len(tags) > 0 {
		props["tags"] = tags
	}
	if len(props) > 0 {
		obj["properties"] = props
	}
}

// mergeTags unions two propertyBag tags arrays. Sorted and deduplicated because
// the schema puts uniqueItems on the array and the two languages must agree on
// the order.
func mergeTags(own, carried interface{}) []interface{} {
	seen := map[string]bool{}
	var tags []string
	for _, side := range []interface{}{own, carried} {
		entries, _ := exportmap.AsSlice(side)
		for _, raw := range entries {
			s, ok := raw.(string)
			if ok && !seen[s] {
				seen[s] = true
				tags = append(tags, s)
			}
		}
	}
	sort.Strings(tags)
	out := make([]interface{}, 0, len(tags))
	for _, t := range tags {
		out = append(out, t)
	}
	return out
}

// remainingExtensions returns the producer data in extensions.passthrough that
// this converter did not consume.
//
// rawSourceArtifacts is dropped deliberately: it holds the bytes the document
// was converted FROM, not data about the findings, and echoing a whole source
// artifact back into the output both multiplies its size and invites a consumer
// to replay those bytes instead of reading the fields this exporter mapped.
func remainingExtensions(doc map[string]interface{}) map[string]interface{} {
	ext, _ := exportmap.AsMap(doc["extensions"])
	passthrough, _ := exportmap.AsMap(ext["passthrough"])
	if len(passthrough) == 0 {
		return nil
	}
	kept := map[string]interface{}{}
	for k, v := range passthrough {
		if k == "sarif" {
			continue // consumed by readCarriedBags and re-emitted onto its objects
		}
		kept[k] = v
	}
	if len(kept) == 0 {
		return nil
	}
	return map[string]interface{}{"passthrough": kept}
}

// baselineExtensions is the baseline-level counterpart: its passthrough only,
// for the same reason rawSourceArtifacts is dropped at document level.
func baselineExtensions(baseline map[string]interface{}) map[string]interface{} {
	ext, _ := exportmap.AsMap(baseline["extensions"])
	passthrough, _ := exportmap.AsMap(ext["passthrough"])
	if len(passthrough) == 0 {
		return nil
	}
	return map[string]interface{}{"passthrough": passthrough}
}

// withoutRawSourceRecord copies a result row without its rawSourceRecord.
//
// The record holds the native finding's own bytes — the converter's input, not
// data about the finding — and this exporter re-derives every SARIF result from
// the mapped HDF fields. Carrying the bytes alongside would roughly double the
// output for a SARIF-sourced document and offer a consumer a byte-replay that
// bypasses the mapping, which is exactly the shortcut that makes a round-trip
// test prove nothing.
func withoutRawSourceRecord(row map[string]interface{}) map[string]interface{} {
	if _, present := row["rawSourceRecord"]; !present {
		return row
	}
	kept := make(map[string]interface{}, len(row))
	for k, v := range row {
		if k != "rawSourceRecord" {
			kept[k] = v
		}
	}
	return kept
}
