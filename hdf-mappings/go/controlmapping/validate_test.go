package controlmapping

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// The TypeScript peer (test/control-mapping.test.ts) asserts this same table,
// which is what keeps the two validators refusing the same documents.
type validationCase struct {
	Name  string          `json:"name"`
	Codes []string        `json:"codes"`
	Why   string          `json:"why"`
	Doc   json.RawMessage `json:"doc"`
	Raw   *string         `json:"raw"`
}

// document is the bytes to validate: a case carries either a JSON value or, for
// documents no JSON value can express, the literal text.
func (c validationCase) document() []byte {
	if c.Raw != nil {
		return []byte(*c.Raw)
	}
	return c.Doc
}

func loadValidationCases(t *testing.T) []validationCase {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "candidate-validation-cases.json"))
	if err != nil {
		t.Fatalf("shared validation table is unreadable: %v", err)
	}
	var table struct {
		Cases []validationCase `json:"cases"`
	}
	if err := json.Unmarshal(raw, &table); err != nil {
		t.Fatalf("shared validation table is invalid JSON: %v", err)
	}
	if len(table.Cases) == 0 {
		t.Fatal("shared validation table has no cases")
	}
	return table.Cases
}

func faultCodes(faults []Fault) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, f := range faults {
		if !seen[f.Code] {
			seen[f.Code] = true
			out = append(out, f.Code)
		}
	}
	sort.Strings(out)
	return out
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestValidateCandidatesSharedCases(t *testing.T) {
	for _, c := range loadValidationCases(t) {
		t.Run(c.Name, func(t *testing.T) {
			corpus, faults := ValidateCandidates(c.document())

			want := append([]string{}, c.Codes...)
			sort.Strings(want)
			if got := faultCodes(faults); !equalStrings(got, want) {
				t.Errorf("ValidateCandidates faults = %v, want %v (%s)", got, want, c.Why)
			}

			// Ingestion is all-or-nothing per corpus: one fault refuses the
			// whole import, because a partial import leaves adjudication
			// running against an unknown subset.
			if len(c.Codes) == 0 {
				if corpus == nil {
					t.Fatalf("accepted document returned no corpus (%s)", c.Why)
				}
				return
			}
			if corpus != nil {
				t.Errorf("refused document still returned a corpus — import must be all-or-nothing (%s)", c.Why)
			}
		})
	}
}

// Every fault carries a path, so a refusal names the record at fault rather
// than only the fault kind.
func TestFaultsCarryAPath(t *testing.T) {
	for _, c := range loadValidationCases(t) {
		if len(c.Codes) == 0 {
			continue
		}
		t.Run(c.Name, func(t *testing.T) {
			_, faults := ValidateCandidates(c.document())
			for _, f := range faults {
				// A whole-document fault has no member to name; every
				// other fault must point at the record at fault.
				if f.Code == FaultDocumentUnparseable {
					continue
				}
				if f.Path == "" {
					t.Errorf("fault %q carries no path", f.Code)
				}
			}
		})
	}
}

func TestValidateCandidatesRejectsMalformedJSON(t *testing.T) {
	corpus, faults := ValidateCandidates([]byte("{not json"))
	if len(faults) == 0 {
		t.Fatal("malformed JSON produced no faults")
	}
	if corpus != nil {
		t.Error("malformed JSON still returned a corpus")
	}
}

// An accepted corpus preserves what adjudication needs: the scanner and
// catalog it was computed against, and every candidate's score.
func TestAcceptedCorpusPreservesScoredCandidates(t *testing.T) {
	var minimal json.RawMessage
	for _, c := range loadValidationCases(t) {
		if c.Name == "valid-minimal" {
			minimal = c.Doc
		}
	}
	if minimal == nil {
		t.Fatal("shared table has no valid-minimal case")
	}

	corpus, faults := ValidateCandidates(minimal)
	if len(faults) != 0 {
		t.Fatalf("valid-minimal was refused: %v", faults)
	}
	if corpus.Scanner.Name != "kics" || corpus.Scanner.Version != "v2.1.20" {
		t.Errorf("scanner = %+v, want kics v2.1.20", corpus.Scanner)
	}
	if corpus.Catalog.Revision != 5 {
		t.Errorf("catalog revision = %d, want 5", corpus.Catalog.Revision)
	}
	if corpus.Catalog.PinnedCommit == "" {
		t.Error("catalog pinned commit was dropped")
	}

	cands, ok := corpus.Candidates("a1bc27c6-7115-48d8-bf9d-5a7e836845ba")
	if !ok {
		t.Fatal("check id from the accepted corpus is not retrievable")
	}
	if len(cands) != 2 {
		t.Fatalf("got %d candidates, want 2", len(cands))
	}
	if cands[0].Control != "SA-10.4" || cands[0].Score != 1.0 {
		t.Errorf("first candidate = %+v, want SA-10.4 at 1.0", cands[0])
	}
	// The sub-part granularity the CWE table cannot express at all.
	if cands[1].Control != "SA-15 a" {
		t.Errorf("second candidate = %q, want the statement sub-part SA-15 a", cands[1].Control)
	}
}

// A candidate id is carried as upstream spelled it and also in this repo's
// canonical spelling, so adjudication can join on the catalog without every
// consumer re-deriving the translation.
func TestAcceptedCorpusCanonicalisesControlIDs(t *testing.T) {
	var minimal json.RawMessage
	for _, c := range loadValidationCases(t) {
		if c.Name == "valid-minimal" {
			minimal = c.Doc
		}
	}
	corpus, _ := ValidateCandidates(minimal)
	cands, _ := corpus.Candidates("a1bc27c6-7115-48d8-bf9d-5a7e836845ba")
	if cands[0].NormalizedControl != "SA-10 04" {
		t.Errorf("NormalizedControl = %q, want SA-10 04", cands[0].NormalizedControl)
	}
	if cands[1].NormalizedControl != "SA-15 a" {
		t.Errorf("NormalizedControl = %q, want SA-15 a", cands[1].NormalizedControl)
	}
}

// The gate. A scored candidate is a review queue, not a mapping: nothing in
// this package turns one into a tags.nist value, and the refusal is explicit
// so a caller cannot mistake an empty result for "no controls apply".
func TestCandidatesNeverResolveToNIST(t *testing.T) {
	var minimal json.RawMessage
	for _, c := range loadValidationCases(t) {
		if c.Name == "valid-minimal" {
			minimal = c.Doc
		}
	}
	corpus, _ := ValidateCandidates(minimal)

	for _, checkID := range []string{"a1bc27c6-7115-48d8-bf9d-5a7e836845ba", "absent-check"} {
		controls, err := corpus.ResolveNIST(checkID)
		if !errors.Is(err, ErrUnadjudicated) {
			t.Errorf("ResolveNIST(%q) err = %v, want ErrUnadjudicated", checkID, err)
		}
		if len(controls) != 0 {
			t.Errorf("ResolveNIST(%q) returned %v, want no controls", checkID, controls)
		}
	}
}

// The contract document states the shape; the validator enforces it. This
// asserts they agree: every property candidate-schema.json marks required is a
// property whose absence the validator actually refuses. Adding a required
// field to the schema extends this test on its own.
func TestSchemaRequiredFieldsAreEnforced(t *testing.T) {
	raw, err := os.ReadFile("candidate-schema.json")
	if err != nil {
		t.Fatalf("contract schema is unreadable: %v", err)
	}
	var schema map[string]any
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatalf("contract schema is invalid JSON: %v", err)
	}

	var valid json.RawMessage
	for _, c := range loadValidationCases(t) {
		if c.Name == "valid-minimal" {
			valid = c.Doc
		}
	}
	if valid == nil {
		t.Fatal("shared table has no valid-minimal case")
	}

	for _, site := range requiredSites(t, schema) {
		for _, mode := range []struct {
			name    string
			nullify bool
			lost    string
		}{
			{"deleted", false, "without it"},
			{"nulled", true, "with it set to null"},
		} {
			t.Run(site.where+"/"+mode.name, func(t *testing.T) {
				var doc map[string]any
				if err := json.Unmarshal(valid, &doc); err != nil {
					t.Fatalf("valid-minimal is invalid JSON: %v", err)
				}
				site.mutate(doc, mode.nullify)

				mutated, err := json.Marshal(doc)
				if err != nil {
					t.Fatalf("mutated document is unmarshalable: %v", err)
				}
				corpus, faults := ValidateCandidates(mutated)
				if len(faults) == 0 {
					t.Errorf("schema requires %s but the validator accepted a document %s", site.where, mode.lost)
				}
				if corpus != nil {
					t.Errorf("document %s required %s still produced a corpus", mode.lost, site.where)
				}
			})
		}
	}
}

type requiredSite struct {
	where string
	// mutate deletes the property, or sets it to JSON null when nullify is
	// set. Both must be refused: a null read as absence suppresses the
	// property's own missing fault.
	mutate func(doc map[string]any, nullify bool)
}

// drop removes key from parent, or nulls it, so one site covers both mutations.
func drop(parent map[string]any, key string, nullify bool) {
	if nullify {
		parent[key] = nil
		return
	}
	delete(parent, key)
}

// requiredSites reads every "required" list in the contract schema and pairs it
// with the way to delete that property from a document.
func requiredSites(t *testing.T, schema map[string]any) []requiredSite {
	t.Helper()
	props := object(t, schema, "properties")
	checkSchema := object(t, object(t, props, "checks"), "additionalProperties")
	candidateSchema := object(t, object(t, object(t, checkSchema, "properties"), "candidates"), "items")

	var sites []requiredSite
	for _, name := range requiredList(t, schema, "(root)") {
		field := name
		sites = append(sites, requiredSite{"/" + field, func(doc map[string]any, nullify bool) {
			drop(doc, field, nullify)
		}})
	}
	for _, section := range []string{"catalog", "scanner"} {
		part := section
		for _, name := range requiredList(t, object(t, props, part), part) {
			field := name
			sites = append(sites, requiredSite{"/" + part + "/" + field, func(doc map[string]any, nullify bool) {
				if inner, ok := doc[part].(map[string]any); ok {
					drop(inner, field, nullify)
				}
			}})
		}
	}
	for _, name := range requiredList(t, checkSchema, "checks.additionalProperties") {
		field := name
		sites = append(sites, requiredSite{"/checks/*/" + field, func(doc map[string]any, nullify bool) {
			forEachCheck(doc, func(check map[string]any) { drop(check, field, nullify) })
		}})
	}
	for _, name := range requiredList(t, candidateSchema, "candidates.items") {
		field := name
		sites = append(sites, requiredSite{"/checks/*/candidates/*/" + field, func(doc map[string]any, nullify bool) {
			forEachCheck(doc, func(check map[string]any) {
				list, _ := check["candidates"].([]any)
				for _, entry := range list {
					if candidate, ok := entry.(map[string]any); ok {
						drop(candidate, field, nullify)
					}
				}
			})
		}})
	}

	if len(sites) == 0 {
		t.Fatal("contract schema declares no required properties")
	}
	return sites
}

func forEachCheck(doc map[string]any, fn func(check map[string]any)) {
	checks, _ := doc["checks"].(map[string]any)
	for _, entry := range checks {
		if check, ok := entry.(map[string]any); ok {
			fn(check)
		}
	}
}

func object(t *testing.T, parent map[string]any, key string) map[string]any {
	t.Helper()
	child, ok := parent[key].(map[string]any)
	if !ok {
		t.Fatalf("contract schema has no object at %q", key)
	}
	return child
}

func requiredList(t *testing.T, schema map[string]any, where string) []string {
	t.Helper()
	raw, ok := schema["required"].([]any)
	if !ok {
		t.Fatalf("contract schema declares no required list at %s", where)
	}
	out := make([]string, 0, len(raw))
	for _, entry := range raw {
		name, ok := entry.(string)
		if !ok {
			t.Fatalf("required list at %s holds a non-string", where)
		}
		out = append(out, name)
	}
	return out
}

// The gate, as a property of the repo rather than of one function: no converter
// may reach candidate data at all. This is what AC "a candidate is NOT
// reachable by any converter" actually asserts — ResolveNIST refusing is a
// convention, but an import is the thing that would break it, since a caller
// holding a Corpus can read NormalizedControl directly.
func TestNoConverterReachesCandidateData(t *testing.T) {
	converters := filepath.Join("..", "..", "..", "hdf-converters")
	if _, err := os.Stat(converters); err != nil {
		t.Skip("hdf-converters is not present beside this module")
	}

	// Both languages' spellings of this package, plus the entry points a
	// converter would have to name to use it.
	forbidden := []string{
		"hdf-mappings/go/v3/controlmapping",
		"control-mapping/index",
		"validateCandidates",
		"ValidateCandidates",
		"resolveNistFromCandidates",
	}

	var offenders []string
	err := filepath.WalkDir(converters, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if name := entry.Name(); name == "node_modules" || name == "dist" || name == "fixtures" {
				return filepath.SkipDir
			}
			return nil
		}
		switch filepath.Ext(path) {
		case ".go", ".ts":
		default:
			return nil
		}
		body, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		for _, needle := range forbidden {
			if strings.Contains(string(body), needle) {
				offenders = append(offenders, path+" references "+needle)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking hdf-converters: %v", err)
	}
	if len(offenders) > 0 {
		t.Errorf("candidate data must stay unreachable from converters until it is adjudicated:\n  %s",
			strings.Join(offenders, "\n  "))
	}
}

func TestCorpusAccessors(t *testing.T) {
	var minimal json.RawMessage
	for _, c := range loadValidationCases(t) {
		if c.Name == "valid-minimal" {
			minimal = c.Doc
		}
	}
	corpus, faults := ValidateCandidates(minimal)
	if len(faults) != 0 {
		t.Fatalf("valid-minimal was refused: %v", faults)
	}

	const present = "a1bc27c6-7115-48d8-bf9d-5a7e836845ba"
	if got := corpus.CheckIDs(); len(got) != 1 || got[0] != present {
		t.Errorf("CheckIDs() = %v, want [%s]", got, present)
	}

	check, ok := corpus.Check(present)
	if !ok {
		t.Fatal("Check() did not find the id CheckIDs() reported")
	}
	if check.QueryName != "Run Using apt" {
		t.Errorf("QueryName = %q, want %q", check.QueryName, "Run Using apt")
	}
	if len(check.Candidates) != 2 {
		t.Errorf("Check() returned %d candidates, want 2", len(check.Candidates))
	}

	if _, ok := corpus.Check("absent"); ok {
		t.Error("Check() reported an absent id as present")
	}
	if cands, ok := corpus.Candidates("absent"); ok || cands != nil {
		t.Errorf("Candidates(absent) = %v, %v; want nil, false", cands, ok)
	}
}

func TestFaultStringNamesCodePathAndDetail(t *testing.T) {
	got := Fault{FaultScoreRange, "/checks/c/candidates/0/score", "score 2 is outside"}.String()
	want := "candidate_score_range at /checks/c/candidates/0/score: score 2 is outside"
	if got != want {
		t.Errorf("Fault.String() = %q, want %q", got, want)
	}
}

// Everything an adjudicator needs besides the control and its score must
// survive ingestion. Without this, deleting the handling for any of these
// members fails no test.
func TestAcceptedCorpusCarriesAdjudicationFields(t *testing.T) {
	var full json.RawMessage
	for _, c := range loadValidationCases(t) {
		if c.Name == "valid-full" {
			full = c.Doc
		}
	}
	if full == nil {
		t.Fatal("shared table has no valid-full case")
	}
	corpus, faults := ValidateCandidates(full)
	if len(faults) != 0 {
		t.Fatalf("valid-full was refused: %v", faults)
	}

	check, ok := corpus.Check("a1bc27c6-7115-48d8-bf9d-5a7e836845ba")
	if !ok {
		t.Fatal("the real upstream check is not retrievable")
	}
	for _, field := range []struct{ name, got, want string }{
		{"QueryName", check.QueryName, "Run Using apt"},
		{"Platform", check.Platform, "Buildah"},
		{"CWE", check.CWE, "1188"},
		{"Category", check.Category, "Supply-Chain"},
		{"ControlTitle", check.Candidates[0].ControlTitle, "Trusted Generation"},
	} {
		if field.got != field.want {
			t.Errorf("%s = %q, want %q", field.name, field.got, field.want)
		}
	}
	want := []string{"statement", "objective", "guidance"}
	got := check.Candidates[0].MatchedOn
	if len(got) != len(want) {
		t.Fatalf("MatchedOn = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("MatchedOn[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}
