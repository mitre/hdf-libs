package hdftosarif

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"testing"

	sarif "github.com/mitre/hdf-libs/hdf-converters/v3/converters/sarif-to-hdf/go"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The round-trip invariant is defined once, on the epic's evaluation card, and this
// file asserts exactly it. Byte-identity across a format boundary is not achievable
// and is not the target; asking less than the invariant would make the exercise
// decorative, so these helpers deliberately have no tolerance knobs.

const roundTripVersion = "0.0.0"

// sarifFixture reads a committed sarif-to-hdf input fixture. Real producer output,
// never synthesized: the invariant is about real documents surviving the trip.
func sarifFixture(t *testing.T, name string) []byte {
	t.Helper()
	path := filepath.Join("..", "..", "sarif-to-hdf", "fixtures", "input", name)
	raw, err := os.ReadFile(path) // #nosec G304 -- repo-relative fixture
	require.NoError(t, err)
	return raw
}

// sarifToHDFToSarif runs the full trip and returns the original and final logs.
func sarifToHDFToSarif(t *testing.T, name string) (before, after map[string]interface{}) {
	t.Helper()
	in := sarifFixture(t, name)

	hdfDoc, err := sarif.ConvertSarifToHDF(in, roundTripVersion, "")
	require.NoError(t, err, "import leg")
	hdfBytes, err := json.Marshal(hdfDoc)
	require.NoError(t, err)

	out, err := ConvertHDFToSARIF(hdfBytes, roundTripVersion)
	require.NoError(t, err, "export leg")

	require.NoError(t, json.Unmarshal(in, &before))
	require.NoError(t, json.Unmarshal(out, &after))
	return before, after
}

// bagsByObject collects every `properties` bag in a SARIF log, keyed by a stable
// address so the same object can be compared across the trip. Invariant item 7
// requires each bag to come back verbatim ON THE OBJECT IT CAME FROM, so an
// address-insensitive comparison would not be asserting the invariant.
func bagsByObject(log map[string]interface{}) map[string]interface{} {
	out := map[string]interface{}{}
	runs, _ := log["runs"].([]interface{})
	for ri, rawRun := range runs {
		run, _ := rawRun.(map[string]interface{})
		if run == nil {
			continue
		}
		if p, ok := run["properties"]; ok {
			out[key("run", ri)] = p
		}
		tool, _ := run["tool"].(map[string]interface{})
		driver, _ := tool["driver"].(map[string]interface{})
		rules, _ := driver["rules"].([]interface{})
		for _, rawRule := range rules {
			rule, _ := rawRule.(map[string]interface{})
			if rule == nil {
				continue
			}
			if p, ok := rule["properties"]; ok {
				if id, _ := rule["id"].(string); id != "" {
					out[key("rule", ri)+"/"+id] = p
				}
			}
		}
		results, _ := run["results"].([]interface{})
		for si, rawRes := range results {
			res, _ := rawRes.(map[string]interface{})
			if res == nil {
				continue
			}
			if p, ok := res["properties"]; ok {
				out[key("result", ri)+"/"+itoa(si)] = p
			}
		}
	}
	return out
}

func key(kind string, runIdx int) string { return kind + "/" + itoa(runIdx) }

func itoa(i int) string {
	b, _ := json.Marshal(i)
	return string(b)
}

// Invariant item 7: every property bag, verbatim, restored to the object it came
// from. The exporter writes HDF's unmappable data into a reserved `hdf` bag for
// exactly this reason; if the importer does not read bags back, the data is present
// in the document and still lost on the trip.
func TestRoundTrip_SarifToHDFToSarif_PreservesPropertyBags(t *testing.T) {
	for _, fixture := range []string{"sarif_input.sarif", "rich.sarif", "gosec.sarif"} {
		t.Run(fixture, func(t *testing.T) {
			before, after := sarifToHDFToSarif(t, fixture)
			wantBags := bagsByObject(before)
			gotBags := bagsByObject(after)

			for addr, want := range wantBags {
				got, present := gotBags[addr]
				if !assert.True(t, present, "bag at %s did not survive the round trip", addr) {
					continue
				}
				assertBagRestored(t, addr, want, got)
			}
		})
	}
}

// assertBagRestored checks invariant item 7 for one bag: every key the producer
// wrote comes back with the value it had.
//
// It asserts CONTAINMENT, not equality, and that is the invariant's meaning rather
// than a weakening of it. "Restored verbatim" constrains what happens to the
// producer's content; it does not forbid the exporter from adding its own. Two
// additions are by design and documented:
//
//   - the reserved `hdf` key, which is how everything SARIF cannot express is
//     carried, and which has no counterpart in the input;
//   - `tags`, which setBag merges rather than replaces because SARIF's tags is a
//     reserved string array and the schema requires its members be distinct
//     (ADR-0014 section 3.4). The producer's tags must all still be there.
//
// Equality would therefore fail on a correct implementation, and loosening it
// further — to presence of the key alone, say — would let a changed value pass.
func assertBagRestored(t *testing.T, addr string, want, got interface{}) {
	t.Helper()
	wantMap, ok := want.(map[string]interface{})
	if !ok {
		assert.Equal(t, want, got, "bag at %s came back changed", addr)
		return
	}
	gotMap, ok := got.(map[string]interface{})
	if !assert.True(t, ok, "bag at %s is no longer an object", addr) {
		return
	}
	for k, wv := range wantMap {
		gv, present := gotMap[k]
		if !assert.True(t, present, "bag at %s lost key %q", addr, k) {
			continue
		}
		if k == "tags" {
			assertTagsContain(t, addr, wv, gv)
			continue
		}
		assert.Equal(t, wv, gv, "bag at %s changed key %q", addr, k)
	}
}

// assertTagsContain requires every producer tag to survive the merge. A superset is
// allowed; a missing member is not.
func assertTagsContain(t *testing.T, addr string, want, got interface{}) {
	t.Helper()
	wantArr, ok := want.([]interface{})
	if !ok {
		assert.Equal(t, want, got, "bag at %s changed tags", addr)
		return
	}
	gotArr, _ := got.([]interface{})
	have := map[interface{}]bool{}
	for _, v := range gotArr {
		have[v] = true
	}
	for _, v := range wantArr {
		assert.True(t, have[v], "bag at %s lost tag %v from the producer's own taxonomy", addr, v)
	}
}

// --- Invariant items 1-6, SARIF -> HDF -> SARIF ---

// resultsByRule indexes a log's results by rule id, in document order, so the
// invariant can be checked per rule without depending on array position across
// the trip: HDF groups results by rule and the exporter re-emits them grouped.
func resultsByRule(log map[string]interface{}) map[string][]map[string]interface{} {
	out := map[string][]map[string]interface{}{}
	runs, _ := log["runs"].([]interface{})
	for _, rawRun := range runs {
		run, _ := rawRun.(map[string]interface{})
		results, _ := run["results"].([]interface{})
		for _, rawRes := range results {
			res, _ := rawRes.(map[string]interface{})
			if res == nil {
				continue
			}
			id, _ := res["ruleId"].(string)
			out[id] = append(out[id], res)
		}
	}
	return out
}

// Item 1: rule identity and the set of rules REFERENCED. Declared-but-unreferenced
// rules are deliberately outside this — a results document represents findings, not
// a scanner's rule catalog, which is why CodeQL's 149 declared rules become the 13
// its results actually cite.
// One ADDITION is by design and is listed per fixture rather than tolerated
// generally: a run that declared executionSuccessful: false gains a synthesized
// requirement on import, and that requirement exports as a rule of its own. It is the
// converter's, not the tool's, which is what its "<driver>-run-failed" id says.
func TestRoundTrip_SarifToHDFToSarif_PreservesReferencedRuleSet(t *testing.T) {
	for fixture, added := range map[string][]string{
		"sarif_input.sarif": nil,
		"rich.sarif":        nil,
		"gosec.sarif":       nil,
		"spotbugs.sarif":    {"SpotBugs-run-failed"},
	} {
		t.Run(fixture, func(t *testing.T) {
			before, after := sarifToHDFToSarif(t, fixture)
			wantIDs := append(referencedRuleIDs(before), added...)
			sort.Strings(wantIDs)
			gotIDs := referencedRuleIDs(after)
			assert.Equal(t, wantIDs, gotIDs, "the set of referenced rule ids changed")
		})
	}
}

func referencedRuleIDs(log map[string]interface{}) []string {
	seen := map[string]bool{}
	for id := range resultsByRule(log) {
		if id != "" {
			seen[id] = true
		}
	}
	out := make([]string, 0, len(seen))
	for id := range seen {
		out = append(out, id)
	}
	sortStrings(out)
	return out
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

// Items 2 and 3: result count per rule, each result's kind, and each result's
// message text. The RESOLVED level is asserted by its own test below; comparing a
// result's raw `level` field would assert the wrong thing, because §3.27.10 lets a
// level be stated on the result or inherited from the rule and both spellings mean
// the same thing.
func TestRoundTrip_SarifToHDFToSarif_PreservesResultCountKindAndMessage(t *testing.T) {
	for _, fixture := range []string{"sarif_input.sarif", "rich.sarif", "gosec.sarif", "spotbugs.sarif"} {
		t.Run(fixture, func(t *testing.T) {
			before, after := sarifToHDFToSarif(t, fixture)
			wantByRule := resultsByRule(before)
			gotByRule := resultsByRule(after)

			for ruleID, want := range wantByRule {
				got := gotByRule[ruleID]
				if !assert.Len(t, got, len(want), "result count changed for rule %q", ruleID) {
					continue
				}
				for i := range want {
					assert.Equal(t, kindOf(want[i]), kindOf(got[i]),
						"rule %q result %d: kind changed", ruleID, i)
					// An originally-absent or empty message has nothing to preserve, and
					// SARIF REQUIRES result.message, so the exporter must emit something:
					// spotbugs ships results with no message text and the trip supplies
					// codeDesc. Asserting equality there would demand the round trip
					// reproduce an invalid document.
					if wantMsg := messageOf(want[i]); wantMsg != "" {
						assert.Equal(t, wantMsg, messageOf(got[i]),
							"rule %q result %d: message text changed", ruleID, i)
					}
				}
			}
		})
	}
}

// §3.27.9 defaults an absent kind to "fail", so the comparison must normalize or an
// omitted kind would read as a change.
func kindOf(res map[string]interface{}) string {
	if k, _ := res["kind"].(string); k != "" {
		return k
	}
	return "fail"
}

func messageOf(res map[string]interface{}) string {
	msg, _ := res["message"].(map[string]interface{})
	text, _ := msg["text"].(string)
	return text
}

// Item 4: each result's location file URI and startLine. Only the first location is
// compared, and that is the invariant's scope rather than a shortcut: HDF's
// Source_Location is {ref, line} and closed, so a result with several locations has
// one place to put the first and tags["sarif-region"] for the rest. A multi-location
// result is expanded into several HDF results on import, which this exporter cannot
// re-collapse. No committed SARIF fixture carries a multi-location result, so that
// behaviour is untested by absence rather than by decision — said plainly because an
// earlier version of this comment claimed it was a recorded known loss, and it was
// recorded nowhere.
func TestRoundTrip_SarifToHDFToSarif_PreservesFirstLocation(t *testing.T) {
	for _, fixture := range []string{"sarif_input.sarif", "rich.sarif", "gosec.sarif", "spotbugs.sarif"} {
		t.Run(fixture, func(t *testing.T) {
			before, after := sarifToHDFToSarif(t, fixture)
			wantByRule := resultsByRule(before)
			gotByRule := resultsByRule(after)

			for ruleID, want := range wantByRule {
				got := gotByRule[ruleID]
				if len(got) != len(want) {
					continue // count is item 2's failure to report, not this test's
				}
				for i := range want {
					wu, wl := firstLocation(want[i])
					if wu == "" && wl == 0 {
						continue // nothing to preserve
					}
					gu, gl := firstLocation(got[i])
					assert.Equal(t, wu, gu, "rule %q result %d: location uri changed", ruleID, i)
					assert.Equal(t, wl, gl, "rule %q result %d: startLine changed", ruleID, i)
				}
			}
		})
	}
}

func firstLocation(res map[string]interface{}) (uri string, line float64) {
	locs, _ := res["locations"].([]interface{})
	if len(locs) == 0 {
		return "", 0
	}
	loc, _ := locs[0].(map[string]interface{})
	phys, _ := loc["physicalLocation"].(map[string]interface{})
	art, _ := phys["artifactLocation"].(map[string]interface{})
	uri, _ = art["uri"].(string)
	region, _ := phys["region"].(map[string]interface{})
	line, _ = region["startLine"].(float64)
	return uri, line
}

// Item 5: each result's fingerprints and partialFingerprints. These exist for
// cross-run correlation, so losing one silently breaks a consumer's ability to say
// "this is the same finding as last week" — the reason the importer carries them
// addressably rather than only inside the opaque rawSourceRecord.
func TestRoundTrip_SarifToHDFToSarif_PreservesFingerprints(t *testing.T) {
	for _, fixture := range []string{"sarif_input.sarif", "rich.sarif", "spotbugs.sarif"} {
		t.Run(fixture, func(t *testing.T) {
			before, after := sarifToHDFToSarif(t, fixture)
			wantByRule := resultsByRule(before)
			gotByRule := resultsByRule(after)

			for ruleID, want := range wantByRule {
				got := gotByRule[ruleID]
				if len(got) != len(want) {
					continue
				}
				for i := range want {
					for _, field := range []string{"fingerprints", "partialFingerprints"} {
						wf, ok := want[i][field].(map[string]interface{})
						if !ok || len(wf) == 0 {
							continue
						}
						gf, _ := got[i][field].(map[string]interface{})
						for k, v := range wf {
							assert.Equal(t, v, gf[k],
								"rule %q result %d: %s[%q] changed", ruleID, i, field, k)
						}
					}
				}
			}
		})
	}
}

// Item 6: each ACCEPTED suppression's justification and kind. Only accepted ones:
// §3.35.3 makes underReview non-final and rejected a declined request, and the
// importer deliberately converts neither into an HDF override, so neither can come
// back and asserting otherwise would be asserting against a ratified decision.
func TestRoundTrip_SarifToHDFToSarif_PreservesAcceptedSuppressions(t *testing.T) {
	for _, fixture := range []string{"rich.sarif"} {
		t.Run(fixture, func(t *testing.T) {
			before, after := sarifToHDFToSarif(t, fixture)
			wantByRule := resultsByRule(before)
			gotByRule := resultsByRule(after)

			checked := 0
			for ruleID, want := range wantByRule {
				got := gotByRule[ruleID]
				if len(got) != len(want) {
					continue
				}
				for i := range want {
					for _, sup := range acceptedSuppressions(want[i]) {
						checked++
						found := false
						for _, gs := range acceptedSuppressions(got[i]) {
							if gs["justification"] == sup["justification"] && gs["kind"] == sup["kind"] {
								found = true
								break
							}
						}
						assert.True(t, found,
							"rule %q result %d: accepted suppression %v did not survive", ruleID, i, sup)
					}
				}
			}
			// A fixture that exercises nothing would make this test decorative.
			assert.Positive(t, checked, "fixture carries no accepted suppression to assert on")
		})
	}
}

func acceptedSuppressions(res map[string]interface{}) []map[string]interface{} {
	out := []map[string]interface{}{}
	sups, _ := res["suppressions"].([]interface{})
	for _, raw := range sups {
		s, _ := raw.(map[string]interface{})
		if s == nil {
			continue
		}
		// §3.35.3: an absent status means accepted.
		if st, ok := s["status"].(string); ok && st != "accepted" {
			continue
		}
		out = append(out, s)
	}
	return out
}

// --- HDF -> SARIF -> HDF ---

// hdfToSarifToHDF runs the reverse trip over a committed HDF document.
func hdfToSarifToHDF(t *testing.T, name string) (before, after map[string]interface{}) {
	t.Helper()
	path := filepath.Join("..", "fixtures", "input", name)
	raw, err := os.ReadFile(path) // #nosec G304 -- repo-relative fixture
	require.NoError(t, err)

	sarifBytes, err := ConvertHDFToSARIF(raw, roundTripVersion)
	require.NoError(t, err, "export leg")

	back, err := sarif.ConvertSarifToHDF(sarifBytes, roundTripVersion, "")
	require.NoError(t, err, "re-import leg")
	backBytes, err := json.Marshal(back)
	require.NoError(t, err)

	require.NoError(t, json.Unmarshal(raw, &before))
	require.NoError(t, json.Unmarshal(backBytes, &after))
	return before, after
}

// requirementsByID indexes a document's requirements by id. Identity, not position:
// the invariant is about a requirement surviving, and the exporter groups runs by
// baseline so positions move.
func requirementsByID(doc map[string]interface{}) map[string]map[string]interface{} {
	out := map[string]map[string]interface{}{}
	baselines, _ := doc["baselines"].([]interface{})
	for _, rawB := range baselines {
		b, _ := rawB.(map[string]interface{})
		reqs, _ := b["requirements"].([]interface{})
		for _, rawR := range reqs {
			r, _ := rawR.(map[string]interface{})
			if r == nil {
				continue
			}
			id, _ := r["id"].(string)
			out[id] = r
		}
	}
	return out
}

// The reverse invariant, as the owner's ruling leaves it.
//
// q89x0.1 defined it as requirement identity, title, descriptions by label, impact,
// and per-result status and codeDesc. The owner then ruled (option (c)) that a
// carried property bag may be read ONLY for fields SARIF cannot express, because
// the bag is present only when this repo produced the document, lives in an
// intentionally unconstrained part of the schema, and is therefore untrusted.
//
// Three of the invariant's items are consequently unachievable, and are asserted
// below as KNOWN LOSSES rather than quietly dropped:
//
//   - impact, where a CVSS score is present: SARIF expresses severity through the
//     security-severity convention, so re-import recomputes it (0.7 -> 0.86).
//   - descriptions["default"]: SARIF expresses it as the rule's fullDescription and
//     the result's message, so re-import derives it from those.
//   - per-result codeDesc: SARIF expresses position as result locations, and HDF's
//     Source_Location is requirement-scoped and closed, so the column and snippet
//     do not survive.
//
// Asserting the losses, rather than omitting the assertions, is what keeps this a
// regression gate: if a future change makes impact round-trip, or breaks a field
// that survives today, the expected-loss set stops matching and this fails.
func TestRoundTrip_HDFToSarifToHDF_PreservesTheInvariant(t *testing.T) {
	// Per fixture, because impact's fate depends on the document: it is recomputed
	// from security-severity, which the exporter emits only where the requirement
	// carries CVSS. flawfinder has none, so its impact survives; grype-cve does, so
	// its impact is recomputed. That difference is the ruling's shape made visible.
	for fixture, wantLosses := range map[string]map[string]bool{
		"flawfinder.hdf.json": {
			"descriptions[default]": true,
			"results[].codeDesc":    true,
		},
		"grype-cve.hdf.json": {
			"descriptions[default]": true,
			"results[].codeDesc":    true,
			"impact":                true,
		},
	} {
		t.Run(fixture, func(t *testing.T) {
			before, after := hdfToSarifToHDF(t, fixture)
			wantReqs := requirementsByID(before)
			gotReqs := requirementsByID(after)

			losses := map[string]bool{}
			for id, want := range wantReqs {
				got, present := gotReqs[id]
				if !assert.True(t, present, "requirement %q did not survive the round trip", id) {
					continue
				}
				// Preserved, and asserted.
				assert.Equal(t, want["title"], got["title"], "requirement %q: title changed", id)

				gotDescs := descriptionsByLabel(got)
				for label, wantData := range descriptionsByLabel(want) {
					if label == "default" {
						if gotDescs[label] != wantData {
							losses["descriptions[default]"] = true
						}
						continue
					}
					gotData, ok := gotDescs[label]
					if !assert.True(t, ok, "requirement %q: description %q did not survive", id, label) {
						continue
					}
					assert.Equal(t, wantData, gotData, "requirement %q: description %q changed", id, label)
				}

				wantRows := resultRows(want)
				gotRows := resultRows(got)
				if !assert.Len(t, gotRows, len(wantRows), "requirement %q: result count changed", id) {
					continue
				}
				for i := range wantRows {
					assert.Equal(t, wantRows[i]["status"], gotRows[i]["status"],
						"requirement %q result %d: status changed", id, i)
					if wantRows[i]["codeDesc"] != gotRows[i]["codeDesc"] {
						losses["results[].codeDesc"] = true
					}
				}

				if want["impact"] != got["impact"] {
					losses["impact"] = true
				}
			}

			// The ruled losses for THIS fixture, and nothing else. A new entry means
			// something that survived today stopped surviving; a missing one means a
			// loss was fixed and this expectation is stale.
			assert.Equal(t, wantLosses, losses, "the set of known round-trip losses changed")
		})
	}
}

// Fields SARIF cannot express are restored from the carried bag, so they must
// survive even under ruling (c). This is the half of the reverse invariant that IS
// achievable, and it is the half the restore path exists for.
func TestRoundTrip_HDFToSarifToHDF_RestoresWhatSarifCannotExpress(t *testing.T) {
	before, after := hdfToSarifToHDF(t, "grype-cve.hdf.json")
	wantReqs := requirementsByID(before)
	gotReqs := requirementsByID(after)

	checked := 0
	for id, want := range wantReqs {
		got, ok := gotReqs[id]
		if !ok {
			continue
		}
		for _, field := range []string{"cvss", "epss", "refs", "affectedPackages", "code", "effectiveChecksum"} {
			w, present := want[field]
			if !present {
				continue
			}
			checked++
			assert.Equal(t, w, got[field],
				"requirement %q: %s has no SARIF expression and must be restored from the bag", id, field)
		}
	}
	assert.Positive(t, checked, "fixture exercises none of the unexpressible fields")
}

func descriptionsByLabel(req map[string]interface{}) map[string]interface{} {
	out := map[string]interface{}{}
	descs, _ := req["descriptions"].([]interface{})
	for _, raw := range descs {
		d, _ := raw.(map[string]interface{})
		if d == nil {
			continue
		}
		label, _ := d["label"].(string)
		out[label] = d["data"]
	}
	return out
}

func resultRows(req map[string]interface{}) []map[string]interface{} {
	out := []map[string]interface{}{}
	rows, _ := req["results"].([]interface{})
	for _, raw := range rows {
		if r, ok := raw.(map[string]interface{}); ok {
			out = append(out, r)
		}
	}
	return out
}

// Item 2's resolved-level clause. §3.27.10 resolves a level as the result's own
// level, else the rule's defaultConfiguration.level, else "warning" — so the
// comparison is of RESOLVED levels, not of the raw field, and a document that moves
// a level between the two spellings is not a loss.
//
// This exists because the level was the one clause of the invariant with no
// assertion: a rule whose results carried different levels had them collapsed onto
// the requirement's summary severity, and 16 of sarif_input.sarif's results came
// back at a level the tool never reported.
func TestRoundTrip_SarifToHDFToSarif_PreservesResolvedLevel(t *testing.T) {
	for _, fixture := range []string{"sarif_input.sarif", "rich.sarif", "gosec.sarif", "spotbugs.sarif"} {
		t.Run(fixture, func(t *testing.T) {
			before, after := sarifToHDFToSarif(t, fixture)
			wantByRule := resultsByRule(before)
			gotByRule := resultsByRule(after)

			for ruleID, want := range wantByRule {
				got := gotByRule[ruleID]
				if len(got) != len(want) {
					continue // item 2's failure to report
				}
				wantDefault := ruleDefaultLevel(before, ruleID)
				gotDefault := ruleDefaultLevel(after, ruleID)
				for i := range want {
					assert.Equal(t,
						resolvedLevel(want[i], wantDefault),
						resolvedLevel(got[i], gotDefault),
						"rule %q result %d: resolved level changed", ruleID, i)
				}
			}
		})
	}
}

// resolvedLevel applies §3.27.10 to one result.
//
// The rule's defaultConfiguration is consulted ONLY for a failing result. For any
// other kind the section is explicit: if level is absent it defaults to "none", and
// if present its value SHALL be "none". So a passing result resolves to "none" no
// matter what the rule declares, and inheriting the rule default there would make
// this helper disagree with the spec rather than with the converter.
func resolvedLevel(res map[string]interface{}, ruleDefault string) string {
	if kindOf(res) != kindFail {
		return "none"
	}
	if l, _ := res["level"].(string); l != "" {
		return l
	}
	if ruleDefault != "" {
		return ruleDefault
	}
	return "warning"
}

// ruleDefaultLevel is a rule's defaultConfiguration.level, or "".
func ruleDefaultLevel(log map[string]interface{}, ruleID string) string {
	runs, _ := log["runs"].([]interface{})
	for _, rawRun := range runs {
		run, _ := rawRun.(map[string]interface{})
		tool, _ := run["tool"].(map[string]interface{})
		driver, _ := tool["driver"].(map[string]interface{})
		rules, _ := driver["rules"].([]interface{})
		for _, rawRule := range rules {
			rule, _ := rawRule.(map[string]interface{})
			if id, _ := rule["id"].(string); id != ruleID {
				continue
			}
			cfg, _ := rule["defaultConfiguration"].(map[string]interface{})
			level, _ := cfg["level"].(string)
			return level
		}
	}
	return ""
}

// verificationMethod and statusOverrides must survive, and the source values here
// DIFFER from what the importer would otherwise assert — `manual-by-design` against
// its constant `automated`, and a real appliedBy/appliedAt/expiresAt against the
// identity, conversion time and default expiry it invents. A fixture carrying the
// constant's own value cannot see the difference, which is how the restore sat
// unreachable while every test passed.
func TestRoundTrip_HDFToSarifToHDF_RestoresAssertedRatherThanInventedFields(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "fixtures", "input", "grype-cve.hdf.json")) // #nosec G304 -- repo-relative fixture
	require.NoError(t, err)
	var doc map[string]interface{}
	require.NoError(t, json.Unmarshal(raw, &doc))

	baselines, _ := doc["baselines"].([]interface{})
	b, _ := baselines[0].(map[string]interface{})
	reqs, _ := b["requirements"].([]interface{})
	req, _ := reqs[0].(map[string]interface{})
	reqID, _ := req["id"].(string)

	req["verificationMethod"] = "manual-by-design"
	req["statusOverrides"] = []interface{}{map[string]interface{}{
		"type": "waiver", "status": "passed", "reason": "ISSM accepted",
		"appliedBy": map[string]interface{}{"type": "username", "identifier": "jane.doe"},
		"appliedAt": "2026-01-15T00:00:00Z",
		"expiresAt": "2099-12-31T00:00:00Z",
	}}
	mutated, err := json.Marshal(doc)
	require.NoError(t, err)

	sarifBytes, err := ConvertHDFToSARIF(mutated, roundTripVersion)
	require.NoError(t, err)
	back, err := sarif.ConvertSarifToHDF(sarifBytes, roundTripVersion, "")
	require.NoError(t, err)
	backBytes, err := json.Marshal(back)
	require.NoError(t, err)
	var after map[string]interface{}
	require.NoError(t, json.Unmarshal(backBytes, &after))

	got, ok := requirementsByID(after)[reqID]
	require.True(t, ok, "requirement %q did not survive", reqID)

	assert.Equal(t, "manual-by-design", got["verificationMethod"],
		"the importer's constant must not outrank a carried verificationMethod")

	overrides, _ := got["statusOverrides"].([]interface{})
	require.Len(t, overrides, 1)
	ov, _ := overrides[0].(map[string]interface{})
	assert.Equal(t, "2026-01-15T00:00:00Z", ov["appliedAt"], "invented appliedAt replaced the real one")
	assert.Equal(t, "2099-12-31T00:00:00Z", ov["expiresAt"], "invented expiry replaced the real one")
	appliedBy, _ := ov["appliedBy"].(map[string]interface{})
	assert.Equal(t, "jane.doe", appliedBy["identifier"], "invented identity replaced the real one")
}

// region.snippet has no structured HDF home — it reaches codeDesc as prose — so it
// survives only because sarif-to-hdf carries it on the per-result location and this
// exporter reads it back. sarif_input.sarif carries 77 of them; before the carriage
// existed, every one was lost.
func TestRoundTrip_SarifToHDFToSarif_PreservesRegionSnippets(t *testing.T) {
	before, after := sarifToHDFToSarif(t, "sarif_input.sarif")
	count := func(log map[string]interface{}) int {
		n := 0
		runs, _ := log["runs"].([]interface{})
		for _, rawRun := range runs {
			run, _ := rawRun.(map[string]interface{})
			results, _ := run["results"].([]interface{})
			for _, rawRes := range results {
				res, _ := rawRes.(map[string]interface{})
				locs, _ := res["locations"].([]interface{})
				for _, rawLoc := range locs {
					loc, _ := rawLoc.(map[string]interface{})
					phys, _ := loc["physicalLocation"].(map[string]interface{})
					region, _ := phys["region"].(map[string]interface{})
					if _, ok := region["snippet"]; ok {
						n++
					}
				}
			}
		}
		return n
	}
	want := count(before)
	require.Positive(t, want, "fixture carries no snippet to assert on")
	assert.Equal(t, want, count(after), "region snippets did not survive the round trip")
}

// CWE lives in tags["cwe"] on a SARIF-sourced document, not in the first-class cwe
// field, so an exporter reading only the first-class field emitted no CWE tags and
// the importer — which recovers CWE from exactly those tags — rebuilt an empty list.
// The NIST and CCI tags derive from that list, so they degraded with it. All three
// are asserted together because they fail together.
func TestRoundTrip_HDFToSarifToHDF_PreservesCWEAndItsDerivedTags(t *testing.T) {
	before, after := hdfToSarifToHDF(t, "flawfinder.hdf.json")
	gotReqs := requirementsByID(after)
	checked := 0
	for id, want := range requirementsByID(before) {
		got, ok := gotReqs[id]
		if !ok {
			continue
		}
		wantTags, _ := want["tags"].(map[string]interface{})
		gotTags, _ := got["tags"].(map[string]interface{})
		for _, field := range []string{"cwe", "nist", "cci"} {
			w := stringsOf(wantTags[field])
			if len(w) == 0 {
				continue
			}
			checked++
			assert.ElementsMatch(t, w, stringsOf(gotTags[field]),
				"requirement %q: tags.%s changed", id, field)
		}
	}
	assert.Positive(t, checked, "fixture exercises none of the tag families")
}

// stringsOf normalizes a tag value to a comparable slice. Order is not asserted:
// the exporter deduplicates through a set and re-emits sorted, which is a spelling
// difference rather than a loss.
func stringsOf(v interface{}) []string {
	raw, _ := v.([]interface{})
	out := make([]string, 0, len(raw))
	for _, x := range raw {
		if s, ok := x.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// resource and resourceId have no SARIF field at all, so they survive only via the
// row hdf-to-sarif puts on each SARIF result's own bag — carriage that was written
// and never read until the result-level restore existed.
func TestRoundTrip_HDFToSarifToHDF_RestoresResultResourceFields(t *testing.T) {
	before, after := hdfToSarifToHDF(t, "grype-cve.hdf.json")
	gotReqs := requirementsByID(after)
	checked := 0
	for id, want := range requirementsByID(before) {
		got, ok := gotReqs[id]
		if !ok {
			continue
		}
		wantRows := resultRows(want)
		gotRows := resultRows(got)
		if len(wantRows) != len(gotRows) {
			continue
		}
		for i := range wantRows {
			for _, field := range []string{"resource", "resourceId"} {
				w, present := wantRows[i][field]
				if !present {
					continue
				}
				checked++
				assert.Equal(t, w, gotRows[i][field],
					"requirement %q result %d: %s has no SARIF field and must be restored", id, i, field)
			}
		}
	}
	assert.Positive(t, checked, "fixture exercises neither resource nor resourceId")
}

// A failed invocation reaches HDF as a requirement, and that requirement survives the
// trip back out as a SARIF result. The invocations array itself does not.
//
// sarif-to-hdf reads invocations[].executionSuccessful and turns a declared failure
// into a synthesized error requirement — N results where x < N carry error, which is
// how HDF expresses a partly-failed evaluation. The exporter has no source from which
// to rebuild an invocation object, so it emits none rather than inventing one.
//
// Asserting the loss keeps it a regression gate: if a future change does restore
// invocations, this fails and the decision gets made deliberately.
func TestRoundTrip_SarifToHDFToSarif_DoesNotRebuildAFailedInvocation(t *testing.T) {
	before, after := sarifToHDFToSarif(t, "failed-run.sarif")

	beforeRun := before["runs"].([]interface{})[0].(map[string]interface{})
	invs, ok := beforeRun["invocations"].([]interface{})
	require.True(t, ok, "fixture precondition: the input run carries invocations")
	require.Equal(t, false, invs[0].(map[string]interface{})["executionSuccessful"],
		"fixture precondition: the input invocation declares failure")

	afterRun := after["runs"].([]interface{})[0].(map[string]interface{})
	assert.NotContains(t, afterRun, "invocations",
		"the exporter must not synthesize an invocation it cannot source from the document")

	// What does survive: the synthesized requirement, as a result of its own.
	results, _ := afterRun["results"].([]interface{})
	var found bool
	for _, raw := range results {
		r, _ := raw.(map[string]interface{})
		if r != nil && r["ruleId"] == "eslint-run-failed" {
			found = true
		}
	}
	assert.True(t, found, "the run-failed requirement must survive export as a result")

	// And nothing was written to the baseline: a baseline is a policy document.
	block, ok := afterRun["properties"].(map[string]interface{})["hdf"].(map[string]interface{})
	require.True(t, ok, "the run must carry an hdf block")
	assert.NotContains(t, block, "statusMessage",
		"per-run health must not be recorded on the baseline")
}

// The requirement survives a full circle but its STATUS does not. HDF "error" exports
// as SARIF kind "open", and the importer maps "open" back to "failed" — SARIF has no
// kind that means "the check threw", so the two collapse. Pre-existing and documented
// on statusKinds in converter.go; this card only made it reachable from a SARIF input.
// Pinned so that restoring the distinction is a deliberate decision rather than an
// accident.
func TestRoundTrip_SarifToHDFToSarifToHDF_DegradesErrorToFailed(t *testing.T) {
	in := sarifFixture(t, "failed-run.sarif")

	first, err := sarif.ConvertSarifToHDF(in, roundTripVersion, "")
	require.NoError(t, err, "import leg")
	require.Len(t, first.Baselines[0].Requirements, 1)
	require.Equal(t, "eslint-run-failed", first.Baselines[0].Requirements[0].ID)
	require.Equal(t, hdf.Error, first.Baselines[0].Requirements[0].Results[0].Status,
		"precondition: the first import records the failure as an error")

	firstBytes, err := json.Marshal(first)
	require.NoError(t, err)
	sarifBytes, err := ConvertHDFToSARIF(firstBytes, roundTripVersion)
	require.NoError(t, err, "export leg")
	second, err := sarif.ConvertSarifToHDF(sarifBytes, roundTripVersion, "")
	require.NoError(t, err, "re-import leg")

	require.Len(t, second.Baselines[0].Requirements, 1)
	assert.Equal(t, "eslint-run-failed", second.Baselines[0].Requirements[0].ID,
		"the requirement itself survives the full circle")
	assert.Equal(t, hdf.Failed, second.Baselines[0].Requirements[0].Results[0].Status,
		"error degrades to failed on re-import; if that is fixed, revisit this")
}
