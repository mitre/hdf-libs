package sarif

import (
	"encoding/json"
	"reflect"

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
	// Decode into a scratch value and commit only on success. Failure is silent on
	// purpose — the bag is untrusted and a malformed entry must cost only itself — and
	// decoding straight into the field would not achieve that: encoding/json allocates
	// the pointee before it discovers a type mismatch, leaving a non-nil empty value
	// behind instead of the field it found.
	//
	// Undeclared members are IGNORED here, deliberately, and the reason is schema SKEW
	// rather than any type being open: a document built against a newer hdf-schema can
	// carry a member this build has no field for, and rejecting the value over it would
	// turn a partial restore into a total loss, again on every schema addition. A missing
	// REQUIRED member is the shape that actually produces an invalid document, and it is
	// checked where the type is known rather than here, by decodeBaselineArray.
	v := reflect.ValueOf(target)
	if v.Kind() != reflect.Pointer || v.IsNil() {
		return
	}
	scratch := reflect.New(v.Elem().Type())
	if err := json.Unmarshal(encoded, scratch.Interface()); err != nil {
		return
	}
	v.Elem().Set(scratch.Elem())
}

// baselineArrayRequiredKeys is the keys the HDF schema REQUIRES on each element of a
// carried baseline array. Mirrors the TypeScript peer's BASELINE_ARRAY_FIELDS exactly;
// the two are the same rule written twice because neither language can read the other's.
var baselineArrayRequiredKeys = map[string][]string{
	"supports":           nil,
	"depends":            nil,
	"groups":             {"id", "requirements"},
	"inputs":             {"name"},
	"externalReferences": {"sourceName"},
}

// decodeBaselineArray restores a carried array only when every element is an object
// carrying the members the schema requires of it.
//
// This is the check {"bogusKey": 5} needs. A plain decode of it succeeds — undeclared
// members are ignored and absent ones zeroed — and yields a RequirementGroup with no id
// and a nil requirements, which then fails the output schema gate and costs the whole
// conversion. Testing for the required members refuses exactly that, while leaving a
// legitimate element carrying an EXTRA member alone.
func decodeBaselineArray(bag map[string]interface{}, key string, target interface{}, alreadySet bool) {
	if alreadySet {
		return
	}
	raw, ok := bag[key]
	if !ok {
		return
	}
	items, ok := raw.([]interface{})
	if !ok {
		return
	}
	for _, item := range items {
		obj, ok := item.(map[string]interface{})
		if !ok {
			return
		}
		for _, required := range baselineArrayRequiredKeys[key] {
			if _, present := obj[required]; !present {
				return
			}
		}
	}
	decodeBagField(bag, key, target, false)
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

// runBag returns the reserved hdf block a run carries, or nil.
func runBag(run SarifRun) map[string]interface{} {
	if len(run.Properties) == 0 {
		return nil
	}
	bag, _ := run.Properties[hdfBagKey].(map[string]interface{})
	return bag
}

// restoreBaselineFields merges a carried run bag's baseline identity back onto the
// baseline this run converted to.
//
// SARIF's toolComponent describes the SCANNER. A baseline describes the POLICY — what
// was required — so SARIF has no way to say any of these, and ruling (c) therefore
// permits reading them. The exporter carries 23 keys; five are excluded, in three
// groups:
//
//   - name and resultsChecksum are DERIVED, not read. SARIF does express the name, on
//     the driver, and resultsChecksum must be computed over the results actually
//     present or it attests to content this document does not contain.
//   - integrity and originalChecksum are REFUSED. Both are tamper-evidence, and a round
//     trip is a transformation of the thing they cover: Integrity is defined over "the
//     HDF file" and carries an optional signature and signedBy, so restoring it would
//     re-attach a signature to a document nobody signed.
//   - generator is REFUSED because it names the converter that produced THIS file, and
//     this converter produced it. Restoring the upstream one would misattribute the
//     document; the original stays readable in the bag.
//
// title and version are restored OVER what the mapping produced, rather than only when
// absent. The mapping has no baseline to describe, so it writes the SARIF format's own
// name and spec version; where the bag carries the real ones, those invented values are
// not a neutral default but a false claim about the policy.
func restoreBaselineFields(baseline *hdf.EvaluatedBaseline, bag map[string]interface{}) {
	if len(bag) == 0 {
		return
	}
	decodeBagField(bag, "title", &baseline.Title, false)
	decodeBagField(bag, "version", &baseline.Version, false)

	decodeBagField(bag, "summary", &baseline.Summary, baseline.Summary != nil)
	decodeBagField(bag, "description", &baseline.Description, baseline.Description != nil)
	decodeBagField(bag, "maintainer", &baseline.Maintainer, baseline.Maintainer != nil)
	decodeBagField(bag, "copyright", &baseline.Copyright, baseline.Copyright != nil)
	decodeBagField(bag, "copyrightEmail", &baseline.CopyrightEmail, baseline.CopyrightEmail != nil)
	decodeBagField(bag, "license", &baseline.License, baseline.License != nil)
	decodeBagField(bag, "status", &baseline.Status, baseline.Status != nil)
	decodeBagField(bag, "statusMessage", &baseline.StatusMessage, baseline.StatusMessage != nil)
	decodeBagField(bag, "parentBaseline", &baseline.ParentBaseline, baseline.ParentBaseline != nil)
	decodeBagField(bag, "labels", &baseline.Labels, len(baseline.Labels) > 0)
	decodeBaselineArray(bag, "supports", &baseline.Supports, len(baseline.Supports) > 0)
	decodeBaselineArray(bag, "depends", &baseline.Depends, len(baseline.Depends) > 0)
	decodeBaselineArray(bag, "groups", &baseline.Groups, len(baseline.Groups) > 0)
	decodeBaselineArray(bag, "inputs", &baseline.Inputs, len(baseline.Inputs) > 0)
	decodeBaselineArray(bag, "externalReferences", &baseline.ExternalReferences, len(baseline.ExternalReferences) > 0)
	// The baseline's own passthrough — producer data outside the HDF model that belongs
	// to this baseline. SARIF cannot express it either, so it restores like the rest.
	// It does not collide with this converter's own carriage, which is written at the
	// DOCUMENT level rather than the baseline's.
	decodeBagField(bag, "extensions", &baseline.Extensions, baseline.Extensions != nil)
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

// statusExportKinds mirrors hdf-to-sarif's statusKinds: the SARIF kind each HDF status
// is written as. Declared here rather than imported so the two converters do not form a
// build cycle, which is the same reason hdfBagKey is declared twice.
//
// The map is injective — five statuses, five distinct kinds — so a carried status can
// always be checked against the kind that accompanies it.
var statusExportKinds = map[hdf.ResultStatus]string{
	hdf.Passed:        "pass",
	hdf.Failed:        "fail",
	hdf.NotApplicable: "notApplicable",
	hdf.NotReviewed:   "review",
	hdf.Error:         "open",
}

// restoreCarriedStatus takes the status from a carried result row, but only when
// exporting that status would have produced the kind this SARIF actually states.
//
// SARIF cannot express HDF's error: there is no kind meaning "the check threw", so the
// export writes "open" — §3.27.9's state where the tool had insufficient information to
// decide — and an importer reading the kind alone cannot tell that from a tool that
// genuinely reported "open". That is the one distinction the kind cannot carry, and the
// owner's ruling is that the bag may settle it, because HDF cannot reflect every source
// status and deriving it only from what SARIF expresses discards what the source said.
//
// The gate is what keeps this honest. The bag is untrusted carriage, so it may REFINE a
// kind that cannot express the distinction and never overrule one that can: a carried
// "passed" found under kind "open" disagrees with the document it arrived in, and the
// SARIF wins. Same rule tags.kind already follows.
func restoreCarriedStatus(out *hdf.RequirementResult, row map[string]interface{}, kind string) {
	if row == nil {
		return
	}
	raw, ok := row["status"].(string)
	if !ok {
		return
	}
	want, known := statusExportKinds[hdf.ResultStatus(raw)]
	if !known {
		return
	}
	// §3.27.9 defaults an absent kind to "fail".
	if kind == "" {
		kind = "fail"
	}
	if want != kind {
		return
	}
	out.Status = hdf.ResultStatus(raw)
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
