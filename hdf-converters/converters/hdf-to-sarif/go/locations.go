package hdftosarif

import (
	"github.com/mitre/hdf-libs/hdf-converters/v3/shared/go/exportmap"
)

// regionIntFields are the SARIF region members HDF can carry through the
// sarif-region tag. They are integers in SARIF; a carried value that is not a
// whole number is dropped rather than coerced.
var regionIntFields = []string{
	"startLine", "startColumn", "endLine", "endColumn",
	"charOffset", "charLength", "byteOffset", "byteLength",
}

// buildLocations maps a requirement's location onto SARIF locations.
//
// HDF Source_Location is {ref, line} and closed, so column and end positions
// come from the documented sarif-region tag when a document carries one, and the
// {ref, line} pair alone otherwise. The locations are requirement-level: HDF
// results[] rows carry no location of their own, so every result of a
// requirement reports at the requirement's location.
func buildLocations(
	req map[string]interface{},
	baselineName, ruleID string,
	carried carriedBags,
	ordinal int,
) []interface{} {
	// A per-result carried location wins. HDF puts sourceLocation on the
	// REQUIREMENT, so without this every result of a rule reports at the first
	// one's location — a rule with ten findings in ten places came back claiming
	// all ten were at the first.
	source, _ := exportmap.AsMap(req["sourceLocation"])
	perRegion := map[string]interface{}{}
	if per := carriedResultLocation(req, ordinal); len(per) > 0 {
		source = per
		perRegion, _ = exportmap.AsMap(per["region"])
	}
	region := buildRegion(req, source, perRegion)
	uri := exportmap.GetStr(source, "ref")
	bag := carried.find(address{On: onLocation, Baseline: baselineName, RuleID: ruleID})

	if uri == "" && len(region) == 0 && len(bag) == 0 {
		return nil
	}

	physical := map[string]interface{}{}
	if uri != "" {
		physical["artifactLocation"] = map[string]interface{}{"uri": EncodeURIReference(uri)}
	}
	if len(region) > 0 {
		physical["region"] = region
	}

	location := map[string]interface{}{}
	if len(physical) > 0 {
		location["physicalLocation"] = physical
	}
	setBag(location, nil, bag)
	if len(location) == 0 {
		return nil
	}
	return []interface{}{location}
}

// buildRegion assembles a SARIF region, in precedence order: the per-result
// carried region, then the requirement-level sarif-region tag, then
// sourceLocation.line for startLine. The per-result region is most specific —
// it is the one the tool reported for THIS finding — so it wins.
func buildRegion(req, source, perResult map[string]interface{}) map[string]interface{} {
	tags, _ := exportmap.AsMap(req["tags"])
	carried, _ := exportmap.AsMap(tags[regionTag])

	region := map[string]interface{}{}
	for _, field := range regionIntFields {
		if v, ok := wholeNumber(perResult[field]); ok {
			region[field] = v
			continue
		}
		if v, ok := wholeNumber(carried[field]); ok {
			region[field] = v
		}
	}
	if _, ok := region["startLine"]; !ok {
		if v, ok := wholeNumber(source["line"]); ok {
			region["startLine"] = v
		}
	}
	exportmap.SetIf(region, "sourceLanguage", exportmap.GetStr(carried, "sourceLanguage"))
	// Per-result snippet first, then the requirement-level sarif-region tag.
	for _, src := range []map[string]interface{}{perResult, carried} {
		snippet, ok := exportmap.AsMap(src["snippet"])
		if !ok {
			continue
		}
		if text := exportmap.GetStr(snippet, "text"); text != "" {
			region["snippet"] = map[string]interface{}{"text": text}
			break
		}
	}
	return region
}

// wholeNumber reports a JSON number that is a positive whole value, which is
// what every SARIF region position is. A fractional or non-positive value is not
// a line or column, so it is dropped rather than truncated into a wrong one.
func wholeNumber(v interface{}) (float64, bool) {
	f, ok := v.(float64)
	if !ok || f <= 0 || f != float64(int64(f)) {
		return 0, false
	}
	return f, true
}

// buildSuppressions maps HDF overrides onto SARIF suppressions.
//
// A suppressions array asserts the finding was suppressed, so it is emitted only
// when an override actually drove a failing verdict non-failing. A riskAdjustment
// or POA&M that leaves the requirement failing is still actionable and is
// carried in the HDF property bag instead of being dressed up as a suppression.
//
// A tags.suppressions written by sarif-to-hdf holds every source suppression
// verbatim, including the rejected and under-review ones and their original
// kind, so it takes priority over anything derived from the overrides.
func buildSuppressions(req map[string]interface{}) []interface{} {
	if carried := carriedSuppressions(req); len(carried) > 0 {
		return carried
	}
	if !exportmap.StatusOf(req).Suppressed {
		return nil
	}
	overrides, _ := exportmap.AsSlice(req["statusOverrides"])
	gov, ok := exportmap.GoverningOverride(overrides, zeroTime)
	if !ok {
		return nil
	}
	suppression := map[string]interface{}{
		// An HDF override is a signed, attributed record in the HDF document,
		// never a marker inside the artifact that was scanned, so "external" is
		// the only value SARIF's definition admits — not a convenience default.
		"kind":   "external",
		"status": "accepted",
	}
	exportmap.SetIf(suppression, "justification", exportmap.GetStr(gov, "reason"))
	// appliedBy/appliedAt/expiresAt/type/signature/previousChecksum and the
	// structured justification have no SARIF suppression field at all.
	suppression["properties"] = map[string]interface{}{hdfBagKey: gov}
	return []interface{}{suppression}
}

// carriedSuppressions rebuilds the suppressions array from the tag sarif-to-hdf
// writes, keeping only the members SARIF's suppression object admits.
func carriedSuppressions(req map[string]interface{}) []interface{} {
	tags, _ := exportmap.AsMap(req["tags"])
	entries, _ := exportmap.AsSlice(tags["suppressions"])
	out := make([]interface{}, 0, len(entries))
	for _, raw := range entries {
		entry, ok := exportmap.AsMap(raw)
		if !ok {
			continue
		}
		kind := exportmap.GetStr(entry, "kind")
		if kind != "inSource" && kind != "external" {
			continue
		}
		suppression := map[string]interface{}{"kind": kind}
		if status := exportmap.GetStr(entry, "status"); suppressionStatuses[status] {
			suppression["status"] = status
		}
		exportmap.SetIf(suppression, "justification", exportmap.GetStr(entry, "justification"))
		out = append(out, suppression)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// suppressionStatuses is the SARIF review-status enum.
var suppressionStatuses = map[string]bool{"accepted": true, "underReview": true, "rejected": true}

// carriedResultLocation reads the location sarif-to-hdf carried for the result at
// this ordinal, shaped like a Source_Location so it drops straight into the
// requirement-level path: {ref, region}. Returns nil when nothing was carried.
func carriedResultLocation(req map[string]interface{}, ordinal int) map[string]interface{} {
	tags, ok := exportmap.AsMap(req["tags"])
	if !ok {
		return nil
	}
	entries, ok := exportmap.AsSlice(tags["sarif-results"])
	if !ok || ordinal < 0 || ordinal >= len(entries) {
		return nil
	}
	entry, ok := exportmap.AsMap(entries[ordinal])
	if !ok {
		return nil
	}
	loc, ok := exportmap.AsMap(entry["location"])
	if !ok || len(loc) == 0 {
		return nil
	}
	return loc
}
