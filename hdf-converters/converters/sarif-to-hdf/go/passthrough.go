package sarif

import (
	"encoding/json"

	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
)

// The objects a carried SARIF property bag can be addressed to. Mirrors
// hdf-to-sarif's own vocabulary exactly: this converter is the producer and that
// one the consumer of the same carriage block, so a value added here without
// being added there would write a bag nothing can restore.
const (
	bagOnLog    = "log"
	bagOnRun    = "run"
	bagOnRule   = "rule"
	bagOnResult = "result"
)

// passthroughSchemaVersion is the version of the
// extensions.passthrough.sarif.propertyBags carriage block this converter WRITES.
// hdf-to-sarif declares the version it reads; the two are the same contract and
// must move together.
const passthroughSchemaVersion = 1

// collectPropertyBags gathers every SARIF property bag in a document into
// carriage entries, addressed by the HDF identities that survive the conversion.
//
// SARIF §3.8.1 puts a properties bag on every object, and Appendix D tells
// producers to name the keys after their own native fields, so the bags cannot be
// enumerated by key and nothing can be mapped from them. Dropping them instead
// loses the producer's own taxonomy — a rule bag carrying ["security", "sql",
// "injection"] came back as this converter's NIST tags and nothing else. So they
// are carried verbatim and addressed, never interpreted.
//
// Addressing is by identity, never array position: HDF groups results by rule and
// reorders them, so /runs/0/results/3 would reattach a bag to a different finding.
// The baseline name addresses the run, the requirement id the rule, and a result's
// index WITHIN its requirement the individual result.
func collectPropertyBags(doc *SarifFile, baselineNames []string, groups [][]bagGroup) []interface{} {
	entries := make([]interface{}, 0)

	if len(doc.Properties) > 0 {
		entries = append(entries, bagEntry(map[string]interface{}{"on": bagOnLog}, doc.Properties))
	}

	for runIdx, run := range doc.Runs {
		baseline := ""
		if runIdx < len(baselineNames) {
			baseline = baselineNames[runIdx]
		}
		if len(run.Properties) > 0 {
			entries = append(entries, bagEntry(map[string]interface{}{
				"on": bagOnRun, "baseline": baseline,
			}, run.Properties))
		}
		if runIdx >= len(groups) {
			continue
		}
		for _, g := range groups[runIdx] {
			if len(g.ruleProps) > 0 {
				entries = append(entries, bagEntry(map[string]interface{}{
					"on": bagOnRule, "baseline": baseline, "ruleId": g.ruleID,
				}, g.ruleProps))
			}
			for ordinal, props := range g.resultProps {
				if len(props) == 0 {
					continue
				}
				entries = append(entries, bagEntry(map[string]interface{}{
					"on": bagOnResult, "baseline": baseline, "ruleId": g.ruleID,
					"ordinal": ordinal,
				}, props))
			}
		}
	}
	return entries
}

// bagGroup is the per-rule slice of a run the collector needs: the requirement id
// the rule became, its own bag, and each of its results' bags in the order the
// requirement carries them, so an ordinal addresses the right one.
type bagGroup struct {
	ruleID      string
	ruleProps   map[string]interface{}
	resultProps []map[string]interface{}
}

func bagEntry(addr map[string]interface{}, props map[string]interface{}) map[string]interface{} {
	addr["properties"] = props
	return addr
}

// attachPropertyBags writes the carriage block onto the document. extensions is
// closed to passthrough and rawSourceArtifacts, so a namespaced key inside
// passthrough is the only place SARIF-specific carriage can live. Absent bags
// leave extensions untouched rather than writing an empty block.
func attachPropertyBags(out *hdf.HDFResults, entries []interface{}) {
	if len(entries) == 0 {
		return
	}
	block := map[string]interface{}{
		"schemaVersion": passthroughSchemaVersion,
		"propertyBags":  entries,
	}
	if out.Extensions == nil {
		out.Extensions = &hdf.Extensions{}
	}
	if out.Extensions.Passthrough == nil {
		out.Extensions.Passthrough = map[string]interface{}{}
	}
	out.Extensions.Passthrough["sarif"] = block
}

// --- Restoring HDF fields SARIF cannot express (owner ruling, option (c)) ---

// restoreUnexpressible merges a carried `hdf` property bag's UNEXPRESSIBLE fields
// into a requirement already built from the SARIF content.
//
// The list is deliberately short. A bag is only present when hdf-to-sarif produced
// the document, it lives in `extensions.passthrough` which the schema leaves
// unconstrained by design, and it is therefore untrusted data used only when it
// happens to be there AND SARIF offers no other way to recover the field.
//
// Anything SARIF DOES express is derived from the SARIF content instead, even when
// the bag also carries it: impact (the security-severity convention), status and
// kind, level, fingerprints, locations and the codeDesc built from them,
// descriptions[default]/[check]/[rationale], nist and cci tags, and a suppression's
// justification and kind. A document round-tripping through here therefore does NOT
// reproduce its original impact where a CVSS score is present, nor a per-result
// codeDesc's column and snippet. Those are ruled, deliberate losses.
//
// A field the mapping already produced is never overwritten, and a bag value that
// does not decode into its typed field is skipped rather than failing the
// conversion — untrusted carriage must not cost a document its findings.
func restoreUnexpressible(req *hdf.EvaluatedRequirement, bag map[string]interface{}) {
	decodeBagField(bag, "cvss", &req.Cvss, len(req.Cvss) > 0)
	decodeBagField(bag, "epss", &req.Epss, req.Epss != nil)
	decodeBagField(bag, "kev", &req.Kev, req.Kev != nil)
	decodeBagField(bag, "affected_packages", &req.AffectedPackages, len(req.AffectedPackages) > 0)
	decodeBagField(bag, "code", &req.Code, req.Code != nil)
	decodeBagField(bag, "refs", &req.Refs, len(req.Refs) > 0)
	// SARIF carries a single helpUri, not a reference array, so a requirement-level
	// externalReferences of any size has no SARIF expression.
	decodeBagField(bag, "external_references", &req.ExternalReferences, len(req.ExternalReferences) > 0)
	decodeBagField(bag, "effective_checksum", &req.EffectiveChecksum, req.EffectiveChecksum != nil)
	decodeBagField(bag, "control_type", &req.ControlType, req.ControlType != nil)
	// verificationMethod and statusOverrides override what the mapping produced,
	// which is the one exception to the rule above, for two different reasons.
	//
	// verificationMethod: the mapping does not DERIVE it from SARIF — SARIF has no
	// field for it. This converter sets a constant `automated` because it is reading
	// scanner output, but the schema defines the field as "how this requirement is
	// intended to be verified" and places it on Requirement_Core, which baseline
	// requirements share and which nothing has assessed. Reading a SARIF file says a
	// check ran; it does not say the requirement is INTENDED to be automated. The
	// schema also says consumers should infer no default when it is omitted. So the
	// constant is an inferred default, not a derived value, and a carried witness to
	// the real one outranks it.
	decodeBagField(bag, "verification_method", &req.VerificationMethod, false)
	// statusOverrides: ONLY the invented fields. SARIF's suppression carries a
	// justification, a kind, a status, a guid, a location and a bag, and this
	// converter derives the override's type, status and reason from them — so those
	// three are SARIF-expressed and stay derived. appliedBy, appliedAt and expiresAt
	// are derived from nothing: the converter invents them (identity "sarif
	// suppression", the conversion time, a default expiry), and the carried values
	// are the document's real ones.
	//
	// Scoped rather than wholesale because disposition and the effective-status
	// rollup are computed from the DERIVED override before this runs. Replacing the
	// whole override left a document whose disposition said waiver while its override
	// said falsePositive.
	restoreInventedOverrideFields(req, bag)
	decodeBagField(bag, "applicability", &req.Applicability, req.Applicability != nil)
	decodeBagField(bag, "evidence", &req.Evidence, len(req.Evidence) > 0)
	decodeBagField(bag, "poams", &req.Poams, len(req.Poams) > 0)
	restoreUnexpressibleDescriptions(req, bag)
}

// decodeBagField decodes one bag value into a typed field, skipping when the
// mapping already set it or when the carried value does not fit the type.
func decodeBagField(bag map[string]interface{}, key string, target interface{}, alreadySet bool) {
	if alreadySet {
		return
	}
	raw, ok := bag[key]
	if !ok {
		return
	}
	encoded, err := json.Marshal(raw)
	if err != nil {
		return
	}
	// Decode failure is silent on purpose: the bag is untrusted, and a malformed
	// entry must cost only itself.
	_ = json.Unmarshal(encoded, target)
}

// restoreUnexpressibleDescriptions restores only labels the SARIF mapping cannot
// produce. "default", "check" and "rationale" all have SARIF carriers and are
// derived; "fix" comes from SARIF fixes[], which hdf-to-sarif does not emit, so a
// fix description reaching SARIF has no way back except the bag.
func restoreUnexpressibleDescriptions(req *hdf.EvaluatedRequirement, bag map[string]interface{}) {
	raw, ok := bag["descriptions"]
	if !ok {
		return
	}
	encoded, err := json.Marshal(raw)
	if err != nil {
		return
	}
	var carried []hdf.Description
	if err := json.Unmarshal(encoded, &carried); err != nil {
		return
	}
	have := map[string]bool{}
	for _, d := range req.Descriptions {
		have[d.Label] = true
	}
	for _, d := range carried {
		if d.Label == "" || have[d.Label] || sarifExpressesDescription[d.Label] {
			continue
		}
		req.Descriptions = append(req.Descriptions, d)
		have[d.Label] = true
	}
}

// The description labels hdf-to-sarif maps onto real SARIF fields, which are
// therefore derived rather than restored.
var sarifExpressesDescription = map[string]bool{
	"default":   true,
	"check":     true,
	"rationale": true,
}

// ruleBag returns the `hdf` property bag a rule carries, or nil. This is the only
// place the importer looks at a bag, and it looks only because hdf-to-sarif put
// HDF data there that SARIF has no field for.
func ruleBag(rule *ReportingDescriptor) map[string]interface{} {
	if rule == nil || len(rule.Properties) == 0 {
		return nil
	}
	bag, _ := rule.Properties[hdfBagKey].(map[string]interface{})
	return bag
}

// hdfBagKey is the single reserved key hdf-to-sarif writes its carriage under.
// Declared here rather than imported so the two converters do not form a build
// cycle; the two constants are one contract and must move together.
const hdfBagKey = "hdf"

// resultBagRow returns the HDF result row hdf-to-sarif carried on one SARIF
// result's own bag, or nil.
func resultBagRow(result SarifResult) map[string]interface{} {
	if len(result.Properties) == 0 {
		return nil
	}
	bag, _ := result.Properties[hdfBagKey].(map[string]interface{})
	if bag == nil {
		return nil
	}
	row, _ := bag["result"].(map[string]interface{})
	return row
}

// restoreUnexpressibleResult fills in the result fields SARIF cannot carry, from the
// row hdf-to-sarif put on this result's own bag.
//
// resource and resourceId are the whole list: codeDesc and status are NOT restored,
// because SARIF expresses position as result locations and verdict as kind, so both
// are derived from the SARIF content under the same rule that governs the
// requirement-level restore. Never overwrites what the mapping produced, and a value
// that does not decode into its typed field is skipped.
func restoreUnexpressibleResult(out *hdf.RequirementResult, row map[string]interface{}) {
	if row == nil {
		return
	}
	decodeBagField(row, "resource", &out.Resource, out.Resource != nil)
	decodeBagField(row, "resourceId", &out.ResourceID, out.ResourceID != nil)
	// startTime is the scan's time, not the conversion's. SARIF has no per-result
	// timestamp and this exporter writes no invocations block, so nothing in the
	// SARIF expresses it and the converter falls back to time.Now() — which silently
	// restamps every finding with the moment it was converted.
	decodeBagField(row, "startTime", &out.StartTime, false)
}

// restoreInventedOverrideFields replaces the identity, application time and expiry
// this converter invented with the carried ones, position by position, leaving the
// type, status and reason it derived from the SARIF suppression untouched.
//
// Positional because an override has no id: the carried list and the derived list
// describe the same suppressions in the same order, one per requirement.
func restoreInventedOverrideFields(req *hdf.EvaluatedRequirement, bag map[string]interface{}) {
	raw, ok := bag["status_overrides"]
	if !ok || len(req.StatusOverrides) == 0 {
		return
	}
	encoded, err := json.Marshal(raw)
	if err != nil {
		return
	}
	var carried []hdf.StatusOverride
	if err := json.Unmarshal(encoded, &carried); err != nil {
		return
	}
	for i := range req.StatusOverrides {
		if i >= len(carried) {
			break
		}
		if carried[i].AppliedBy.Identifier != "" {
			req.StatusOverrides[i].AppliedBy = carried[i].AppliedBy
		}
		if !carried[i].AppliedAt.IsZero() {
			req.StatusOverrides[i].AppliedAt = carried[i].AppliedAt
		}
		req.StatusOverrides[i].ExpiresAt = carried[i].ExpiresAt
	}
}
