package hdftosarif

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

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

// HDF "error" now survives a full circle. SARIF has no kind that means "the check
// threw", so the export maps it to "open" — §3.27.9's state where the tool had
// insufficient information to decide — and an importer reading only the kind cannot tell
// that from a tool that genuinely reported "open". The carried status settles it.
//
// The owner's ruling: the bag MAY carry status, because HDF cannot reflect every source
// status and deriving it only from what SARIF expresses throws away a distinction the
// source document made. The restore is gated so the bag can only REFINE what the kind
// cannot distinguish, never contradict it — a carried status whose own export would have
// produced a different kind is ignored.
func TestRoundTrip_SarifToHDFToSarifToHDF_PreservesErrorStatus(t *testing.T) {
	in := sarifFixture(t, "failed-run.sarif")

	first, err := sarif.ConvertSarifToHDF(in, roundTripVersion, "")
	require.NoError(t, err, "import leg")
	require.Equal(t, hdf.Error, first.Baselines[0].Requirements[0].Results[0].Status,
		"precondition: the first import records the failure as an error")

	firstBytes, err := json.Marshal(first)
	require.NoError(t, err)
	sarifBytes, err := ConvertHDFToSARIF(firstBytes, roundTripVersion)
	require.NoError(t, err, "export leg")

	// The SARIF itself still says "open"; nothing about the export changed.
	var log map[string]interface{}
	require.NoError(t, json.Unmarshal(sarifBytes, &log))
	res := log["runs"].([]interface{})[0].(map[string]interface{})["results"].([]interface{})[0]
	assert.Equal(t, "open", res.(map[string]interface{})["kind"],
		"error still exports as open; the fix is on the read side")

	second, err := sarif.ConvertSarifToHDF(sarifBytes, roundTripVersion, "")
	require.NoError(t, err, "re-import leg")
	require.Len(t, second.Baselines[0].Requirements, 1)
	assert.Equal(t, "eslint-run-failed", second.Baselines[0].Requirements[0].ID)
	assert.Equal(t, hdf.Error, second.Baselines[0].Requirements[0].Results[0].Status,
		"the carried status refines what the kind cannot distinguish")
}

// AC2: a result that was genuinely "open" in the SOURCE SARIF — no carriage behind it —
// must still import as failed. Real scanner output must not start reading as errored
// because this card taught the importer a new trick.
func TestConvertSarif_GenuineOpenKindWithoutCarriageStaysFailed(t *testing.T) {
	input := []byte(`{
		"version": "2.1.0",
		"runs": [{
			"tool": { "driver": { "name": "ExampleAnalyzer", "rules": [{"id": "R1"}] } },
			"results": [{ "ruleId": "R1", "kind": "open", "message": { "text": "undecided" } }]
		}]
	}`)
	out, err := sarif.ConvertSarifToHDF(input, roundTripVersion, "")
	require.NoError(t, err)
	require.Len(t, out.Baselines[0].Requirements, 1)
	assert.Equal(t, hdf.Failed, out.Baselines[0].Requirements[0].Results[0].Status,
		"no carried status, so the kind alone decides, exactly as before")
}

// AC3: a carried status that CONTRADICTS the kind is ignored. The bag is untrusted
// carriage; it may refine a kind that cannot express the distinction, never overrule one
// that can. "passed" exports to kind "pass", so finding it under kind "open" means the
// two disagree and the SARIF wins.
func TestConvertSarif_CarriedStatusContradictingTheKindIsIgnored(t *testing.T) {
	for _, tc := range []struct {
		name, kind, carried string
		want                hdf.ResultStatus
	}{
		{"passed under open", "open", "passed", hdf.Failed},
		{"notApplicable under fail", "fail", "notApplicable", hdf.Failed},
		{"error under pass", "pass", "error", hdf.Passed},
		{"nonsense value under open", "open", "not-a-status", hdf.Failed},
		{"error under open agrees", "open", "error", hdf.Error},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input := []byte(`{
				"version": "2.1.0",
				"runs": [{
					"tool": { "driver": { "name": "ExampleAnalyzer", "rules": [{"id": "R1"}] } },
					"results": [{
						"ruleId": "R1", "kind": "` + tc.kind + `",
						"message": { "text": "m" },
						"properties": { "hdf": { "result": { "status": "` + tc.carried + `" } } }
					}]
				}]
			}`)
			out, err := sarif.ConvertSarifToHDF(input, roundTripVersion, "")
			require.NoError(t, err)
			assert.Equal(t, tc.want, out.Baselines[0].Requirements[0].Results[0].Status)
		})
	}
}

// Baseline-level restore. hdf-to-sarif writes the whole baseline identity into the
// run's hdf block; sarif-to-hdf restores the fields SARIF cannot express, derives the
// two it can, and refuses the two that are tamper-evidence.
//
// The owner's ruling, per field:
//
//	restored    every field describing the POLICY — SARIF's toolComponent describes the
//	            scanner, so it has no way to say any of them
//	derived     name (the driver carries it) and resultsChecksum (recomputed over the
//	            results actually present), which ruling (c) requires come from the SARIF
//	never       integrity and originalChecksum. Both are tamper-evidence, and a round
//	            trip is a transformation: Integrity covers "the HDF file" and can carry
//	            a signature and signedBy, so restoring it would re-attach someone's
//	            signature to a document they never signed.
func TestRoundTrip_HDFToSarifToHDF_RestoresBaselineIdentity(t *testing.T) {
	raw := seededBaselineHDF(t)

	sarifBytes, err := ConvertHDFToSARIF(raw, roundTripVersion)
	require.NoError(t, err, "export leg")
	back, err := sarif.ConvertSarifToHDF(sarifBytes, roundTripVersion, "")
	require.NoError(t, err, "re-import leg")
	got := back.Baselines[0]

	// Restored verbatim: the policy's own description of itself.
	require.NotNil(t, got.Summary)
	assert.Equal(t, "a summary", *got.Summary)
	require.NotNil(t, got.Description)
	assert.Equal(t, "a description", *got.Description)
	require.NotNil(t, got.Maintainer)
	assert.Equal(t, "Team Blue", *got.Maintainer)
	require.NotNil(t, got.Copyright)
	assert.Equal(t, "ACME Corp", *got.Copyright)
	require.NotNil(t, got.CopyrightEmail)
	assert.Equal(t, "sec@example.invalid", *got.CopyrightEmail)
	require.NotNil(t, got.License)
	assert.Equal(t, "Apache-2.0", *got.License)
	require.NotNil(t, got.Status)
	assert.Equal(t, "loaded", *got.Status)
	require.NotNil(t, got.StatusMessage)
	assert.Equal(t, "a status note", *got.StatusMessage)
	require.NotNil(t, got.ParentBaseline)
	assert.Equal(t, "parent-policy", *got.ParentBaseline)
	assert.Equal(t, map[string]string{"team": "blue", "environment": "prod"}, got.Labels)
	require.Len(t, got.Supports, 1)
	require.Len(t, got.Depends, 1)
	require.Len(t, got.Groups, 1)
	require.Len(t, got.Inputs, 1)
	require.Len(t, got.ExternalReferences, 1)

	// Restored over the invented values. Without this the baseline claims the SARIF
	// format's own name and spec version as its own: "Static Analysis Results
	// Interchange Format" and "2.1.0".
	require.NotNil(t, got.Title)
	assert.Equal(t, "ACME Hardening Policy", *got.Title)
	require.NotNil(t, got.Version)
	assert.Equal(t, "9.9.9", *got.Version)

	// Derived from the SARIF, never the bag.
	assert.Equal(t, "Flawfinder", got.Name, "the driver carries the name, so SARIF expresses it")
	require.NotNil(t, got.ResultsChecksum)

	// The baseline's own passthrough is producer data SARIF cannot express, so it
	// restores like the rest.
	require.NotNil(t, got.Extensions)
	encodedExt, err := json.Marshal(got.Extensions)
	require.NoError(t, err)
	assert.Contains(t, string(encodedExt), "policyOwner")

	// Refused. Tamper-evidence does not survive a transformation of the thing it covers.
	assert.Nil(t, got.Integrity,
		"restoring integrity would re-attach a signature to a document nobody signed")
	assert.Nil(t, got.OriginalChecksum,
		"the round trip changes the requirements originalChecksum attests to")

	// Also refused, for a different reason: generator names the converter that produced
	// THIS file, and this converter produced it.
	require.NotNil(t, back.Generator)
	assert.Equal(t, "sarif-to-hdf", back.Generator.Name,
		"restoring the upstream generator would misattribute the document")
}

// A bag that is absent, or whose entries are the wrong shape, must cost only itself.
func TestRoundTrip_HDFToSarifToHDF_BaselineRestoreToleratesAMalformedBag(t *testing.T) {
	raw := seededBaselineHDF(t)
	sarifBytes, err := ConvertHDFToSARIF(raw, roundTripVersion)
	require.NoError(t, err)

	var doc map[string]interface{}
	require.NoError(t, json.Unmarshal(sarifBytes, &doc))
	run := doc["runs"].([]interface{})[0].(map[string]interface{})
	block := run["properties"].(map[string]interface{})[hdfBagKey].(map[string]interface{})
	// Wrong type for a string field, and for a slice field.
	block["license"] = []interface{}{"not", "a", "string"}
	block["groups"] = "not a list"
	block["maintainer"] = "Team Blue"
	mangled, err := json.Marshal(doc)
	require.NoError(t, err)

	back, err := sarif.ConvertSarifToHDF(mangled, roundTripVersion, "")
	require.NoError(t, err, "a malformed bag must not fail the conversion")
	got := back.Baselines[0]
	assert.Nil(t, got.License, "a wrong-typed entry is skipped")
	assert.Empty(t, got.Groups, "a wrong-typed entry is skipped")
	require.NotNil(t, got.Maintainer, "its neighbours still restore")
	assert.Equal(t, "Team Blue", *got.Maintainer)
}

// The adversarial corpus. Every entry is a value the bag could carry that does not fit
// the field it addresses, and the contract is the same for all of them in both
// languages: skip the field, keep its neighbours, and never fail the conversion.
//
// The last one is the subtle case and the reason this table exists. {"bogusKey": 5}
// DECODES without error in Go — encoding/json ignores members the target does not
// declare and zeroes the ones it does not find — so a decode that only checks err
// commits a RequirementGroup with no id and a nil requirements, which then fails the
// output schema gate and costs the whole document. TypeScript has no types at runtime
// and would take the object verbatim, reaching the same invalid output by a different
// route. Both languages reject it now, for the same reason stated differently.
var adversarialBagValues = map[string]interface{}{
	"supports":           []interface{}{1, 2, 3},
	"depends":            []interface{}{"not-an-object"},
	"inputs":             []interface{}{42},
	"externalReferences": []interface{}{"x"},
	"license":            []interface{}{"not", "a", "string"},
	"labels":             map[string]interface{}{"team": 7},
	"groups":             []interface{}{map[string]interface{}{"bogusKey": 5}},
}

func TestRoundTrip_HDFToSarifToHDF_BaselineRestoreSkipsEveryAdversarialValue(t *testing.T) {
	for field, bad := range adversarialBagValues {
		t.Run(field, func(t *testing.T) {
			sarifBytes, err := ConvertHDFToSARIF(seededBaselineHDF(t), roundTripVersion)
			require.NoError(t, err)

			var doc map[string]interface{}
			require.NoError(t, json.Unmarshal(sarifBytes, &doc))
			run := doc["runs"].([]interface{})[0].(map[string]interface{})
			block := run["properties"].(map[string]interface{})[hdfBagKey].(map[string]interface{})
			block[field] = bad
			mangled, err := json.Marshal(doc)
			require.NoError(t, err)

			back, err := sarif.ConvertSarifToHDF(mangled, roundTripVersion, "")
			require.NoError(t, err, "an adversarial bag must never fail the conversion")

			encoded, err := json.Marshal(back.Baselines[0])
			require.NoError(t, err)
			var got map[string]interface{}
			require.NoError(t, json.Unmarshal(encoded, &got))
			assert.NotContains(t, got, field, "the field must be skipped, not taken")

			// Its neighbours are unaffected: one bad entry costs only itself.
			assert.Equal(t, "Team Blue", got["maintainer"])
			assert.Equal(t, "ACME Hardening Policy", got["title"])
		})
	}
}

// Timestamp spellings the carriage must survive, and the regression that made this
// test necessary.
//
// Every one of these is a legitimate RFC3339 value a producer can emit, and Go's
// time.Time normalizes three of the four on the way back out — it trims trailing
// fractional zeros and rewrites a +00:00 offset as Z. A restore guard that asked
// "does the decoded value re-serialize to the carried bytes?" therefore rejected
// correct data: .100Z, .000Z and +00:00 were all dropped, and because
// results[].startTime falls back to the conversion time when nothing restores it, the
// document silently acquired the wrong assessment time rather than merely losing one.
//
// The guard was replaced with a plain scratch decode, which is indifferent to how a
// value is spelled; the member-name test that the adversarial case needs lives in
// decodeBaselineArray, on the five baseline array fields. Three of the four timestamp
// fields below bypass it entirely; the baseline's own externalReferences goes through
// it, where the required-member gate checks sourceName and never looks at addedAt.
// Nothing in the committed corpus carries a trailing-zero millisecond, which is why the
// regression passed every suite.
func TestRoundTrip_HDFToSarifToHDF_RestoresEveryTimestampSpelling(t *testing.T) {
	for _, carried := range []string{
		"2026-10-09T16:04:26.123Z", // no trailing zero — the only spelling the corpus had
		"2026-10-09T16:04:26.100Z", // trailing zero in the fraction
		"2026-10-09T16:04:26.000Z", // zero fraction
		"2026-10-09T16:04:26+00:00",
	} {
		t.Run(carried, func(t *testing.T) {
			raw := seededTimestampHDF(t, carried)
			sarifBytes, err := ConvertHDFToSARIF(raw, roundTripVersion)
			require.NoError(t, err, "export leg")
			back, err := sarif.ConvertSarifToHDF(sarifBytes, roundTripVersion, "")
			require.NoError(t, err, "re-import leg")

			req := back.Baselines[0].Requirements[0]
			want, err := time.Parse(time.RFC3339, carried)
			require.NoError(t, err)

			require.Len(t, req.Results, 1)
			assert.True(t, req.Results[0].StartTime.Equal(want),
				"startTime: want %s, got %s — a dropped restore silently substitutes the conversion time",
				want, req.Results[0].StartTime)
			assert.Len(t, req.Evidence, 1, "evidence must survive, whatever the capturedAt spelling")
			assert.Len(t, req.ExternalReferences, 1, "externalReferences must survive too")
			assert.Len(t, back.Baselines[0].ExternalReferences, 1, "and the baseline's own")
		})
	}
}

// A legitimately null value under an omitempty field. Input.Value is "any JSON value",
// so null is schema-valid, and it does not re-serialize — another shape a
// re-serialization guard rejects and a member-name guard does not.
func TestRoundTrip_HDFToSarifToHDF_RestoresANullInputValue(t *testing.T) {
	raw := seededTimestampHDF(t, "2026-10-09T16:04:26.123Z")
	var doc map[string]interface{}
	require.NoError(t, json.Unmarshal(raw, &doc))
	b := doc["baselines"].([]interface{})[0].(map[string]interface{})
	b["inputs"] = []interface{}{map[string]interface{}{
		"name": "threshold", "type": "Numeric", "value": nil,
	}}
	seeded, err := json.Marshal(doc)
	require.NoError(t, err)

	sarifBytes, err := ConvertHDFToSARIF(seeded, roundTripVersion)
	require.NoError(t, err)
	back, err := sarif.ConvertSarifToHDF(sarifBytes, roundTripVersion, "")
	require.NoError(t, err)
	require.Len(t, back.Baselines[0].Inputs, 1, "a null value must not cost the whole array")
	assert.Equal(t, "threshold", back.Baselines[0].Inputs[0].Name)
}

// seededTimestampHDF puts the same timestamp on every carried time field the restore
// touches: a result's startTime, an evidence item's capturedAt, and an external
// reference's addedAt at both requirement and baseline scope.
func seededTimestampHDF(t *testing.T, stamp string) []byte {
	t.Helper()
	path := filepath.Join("..", "fixtures", "input", "flawfinder.hdf.json")
	raw, err := os.ReadFile(path) // #nosec G304 -- repo-relative fixture
	require.NoError(t, err)

	var doc map[string]interface{}
	require.NoError(t, json.Unmarshal(raw, &doc))
	b := doc["baselines"].([]interface{})[0].(map[string]interface{})
	reqs := b["requirements"].([]interface{})
	b["requirements"] = reqs[:1]
	req := reqs[0].(map[string]interface{})

	results := req["results"].([]interface{})
	req["results"] = results[:1]
	results[0].(map[string]interface{})["startTime"] = stamp

	req["evidence"] = []interface{}{map[string]interface{}{
		"type": "log", "data": "a line", "capturedAt": stamp,
	}}
	ref := []interface{}{map[string]interface{}{
		"sourceName": "ACME", "href": "https://example.invalid/a", "addedAt": stamp,
	}}
	req["externalReferences"] = ref
	b["externalReferences"] = ref

	seeded, err := json.Marshal(doc)
	require.NoError(t, err)
	return seeded
}

// A member this build does not declare must not cost the value it rides on.
//
// This is the SCHEMA SKEW case, and it is why the behaviour matters. A document produced
// against a newer hdf-schema can carry a Reference member this build has no field for —
// External_Reference gained content and encoding exactly that way — and a build must
// still return the refs array it was given. A restore guard that rejected the whole value
// over one unknown member turned a partial restore into a total loss, and would have done
// it again on every schema addition.
//
// The member used here is not legal in a CURRENT document: Reference is closed as of the
// Reference clean-up, so a present-day producer cannot emit it. It stands in for a future
// one, which is the case no amount of validation protects a build from.
//
// What each language does with the unknown member itself differs, and that is accepted
// rather than asserted: Go decodes into a typed struct so it cannot keep a field it has no
// type for, TypeScript assigns the carried value verbatim so it survives. Neither is
// wrong — a build cannot invent storage for an unknown field, and preserving it when you
// can is a kindness to a newer consumer. What must agree, and is asserted in both, is that
// the ARRAY and its declared members are never lost.
func TestRoundTrip_HDFToSarifToHDF_AnUndeclaredMemberDoesNotCostTheValue(t *testing.T) {
	path := filepath.Join("..", "..", "gitlab-to-hdf", "fixtures", "expected", "minimal-dast.json.hdf.json")
	raw, err := os.ReadFile(path) // #nosec G304 -- repo-relative fixture
	require.NoError(t, err)

	var doc map[string]interface{}
	require.NoError(t, json.Unmarshal(raw, &doc))
	b := doc["baselines"].([]interface{})[0].(map[string]interface{})
	req := b["requirements"].([]interface{})[0].(map[string]interface{})
	req["refs"] = []interface{}{map[string]interface{}{
		"ref": "NIST SP 800-53 Rev 5",
		"url": "https://example.invalid/a",
		// Stands in for a member a future schema version adds; not one hdf.Reference
		// declares, and not legal in a current document now that Reference is closed.
		"title": "Security and Privacy Controls",
	}}
	seeded, err := json.Marshal(doc)
	require.NoError(t, err)

	sarifBytes, err := ConvertHDFToSARIF(seeded, roundTripVersion)
	require.NoError(t, err, "export leg")
	back, err := sarif.ConvertSarifToHDF(sarifBytes, roundTripVersion, "")
	require.NoError(t, err, "re-import leg")

	var restored []hdf.Reference
	for _, r := range back.Baselines[0].Requirements {
		if len(r.Refs) > 0 {
			restored = r.Refs
			break
		}
	}
	require.Len(t, restored, 1, "the array must survive; dropping it loses the declared members too")
	require.NotNil(t, restored[0].URL)
	assert.Equal(t, "https://example.invalid/a", *restored[0].URL)
	require.NotNil(t, restored[0].Ref)
}

// A SARIF document with no hdf bag at all keeps the converter's own defaults.
func TestRoundTrip_HDFToSarifToHDF_NoBagKeepsTheInventedDefaults(t *testing.T) {
	in := sarifFixture(t, "gosec.sarif")
	out, err := sarif.ConvertSarifToHDF(in, roundTripVersion, "")
	require.NoError(t, err)
	b := out.Baselines[0]
	require.NotNil(t, b.Title)
	assert.Equal(t, "Static Analysis Results Interchange Format", *b.Title,
		"with nothing carried, the invented title remains the fallback")
	assert.Nil(t, b.License)
	assert.Nil(t, b.Maintainer)
}

// seededBaselineHDF is a real exporter fixture with every baseline field the exporter
// carries set to a distinguishable value, so a field that fails to restore is visible
// rather than merely absent.
func seededBaselineHDF(t *testing.T) []byte {
	t.Helper()
	path := filepath.Join("..", "fixtures", "input", "flawfinder.hdf.json")
	raw, err := os.ReadFile(path) // #nosec G304 -- repo-relative fixture
	require.NoError(t, err)

	var doc map[string]interface{}
	require.NoError(t, json.Unmarshal(raw, &doc))
	// A generator this converter would never stamp, so the refusal assertion cannot
	// pass by coincidence: the fixture's own generator is already sarif-to-hdf.
	doc["generator"] = map[string]interface{}{"name": "grype-to-hdf", "version": "1.2.3"}
	b := doc["baselines"].([]interface{})[0].(map[string]interface{})
	for k, v := range map[string]interface{}{
		"title": "ACME Hardening Policy", "version": "9.9.9",
		"summary": "a summary", "description": "a description",
		"maintainer": "Team Blue", "copyright": "ACME Corp",
		"copyrightEmail": "sec@example.invalid", "license": "Apache-2.0",
		"status": "loaded", "statusMessage": "a status note",
		"parentBaseline": "parent-policy",
		"labels":         map[string]interface{}{"team": "blue", "environment": "prod"},
		"supports":       []interface{}{map[string]interface{}{"platform": "linux"}},
		"depends":        []interface{}{map[string]interface{}{"name": "dep-a"}},
		"groups":         []interface{}{map[string]interface{}{"id": "g1", "title": "Group One", "requirements": []interface{}{"V-1"}}},
		"inputs":         []interface{}{map[string]interface{}{"name": "threshold", "type": "Numeric"}},
		"integrity": map[string]interface{}{
			"algorithm": "sha256", "checksum": strings.Repeat("a", 64),
			"signature": "c2ln", "signedBy": "someone@example.invalid",
		},
		"originalChecksum": map[string]interface{}{
			"algorithm": "sha256", "value": strings.Repeat("b", 64),
		},
		"externalReferences": []interface{}{
			map[string]interface{}{"sourceName": "ACME", "href": "https://example.invalid/policy"},
		},
		"extensions": map[string]interface{}{
			"passthrough": map[string]interface{}{"acme": map[string]interface{}{"policyOwner": "Team Blue"}},
		},
	} {
		b[k] = v
	}
	seeded, err := json.Marshal(doc)
	require.NoError(t, err)
	return seeded
}
